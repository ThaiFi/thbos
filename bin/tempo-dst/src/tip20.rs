// SPDX-License-Identifier: GPL-2.0

//! TIP-20 load and its oracle (E8): a bank-transfer workload over a closed set
//! of holders.
//!
//! `contrib/bedrock-dst/tip20/deploy.yaml` creates [`TOKEN`] through the
//! TIP20Factory before the warm checkpoint and mints its whole supply to
//! [`HOLDERS`] (see [`Ledger::initial`]). Afterwards only transfers among the
//! holders touch it ([`spec`]; fees are paid in pathUSD), so at every block:
//!
//! - **Conservation** ([`check_ledger`]): `totalSupply` is the minted supply
//!   and the holders' balances sum to it.
//! - **One generation** ([`check_block`]): the block's balances are exactly
//!   its parent's plus the `Transfer` logs in the block's receipts. A
//!   partially applied block, or reads that mix two blocks' state, are not
//!   explainable.
//! - **Stable history** ([`Tip20Oracle`] pins): a block's balances, read again
//!   later (after more blocks, persistence of that block, node restarts), are
//!   unchanged while the block is canonical.
//!
//! Every read of one block names it by hash (EIP-1898), so a snapshot is one
//! version of the state or an error, never a mix of two canonical chains.

use std::collections::BTreeMap;

use alloy_primitives::{address, b256, Address, B256, U256};
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{
    oracle::{sweep_depth, Failure, DEEP_DEPTHS, SHALLOW_DEPTHS},
    verdict::{finding, Verdict},
};

pub use crate::common::BlockRef;

/// Created by account 9 with salt 0xb1d (`TIP20Factory.getTokenAddress`).
pub const TOKEN: Address = address!("20c0000000000000000000008a34063c54ebdca3");
/// Dev accounts 1-8 (mnemonic `test ... junk`); account 0 is the trie load's.
pub const HOLDERS: [Address; 8] = [
    address!("70997970c51812dc3a010c7d01b50e0d17dc79c8"),
    address!("3c44cdddb6a900fa2b585dd299e03d12fa4293bc"),
    address!("90f79bf6eb2c4f870365e785982e1f101e93b906"),
    address!("15d34aaf54267db7d7c367839aaf71a00a2c6a65"),
    address!("9965507d1a55bcc2695c58ba16fb37d819b0a4dc"),
    address!("976ea74026e726554db657fa54763abd0c3a0aa9"),
    address!("14dc79964da2c08b23698b3d3cc7ca32193d9955"),
    address!("23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f"),
];
/// Holder `k` (0-based) is minted `(k + 1) * UNIT`.
const UNIT: u128 = 1_000_000_000_000_000_000_000_000;
/// `Transfer(address,address,uint256)`.
const TRANSFER_TOPIC: B256 =
    b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transfer {
    pub from: Address,
    pub to: Address,
    pub amount: U256,
}

impl Transfer {
    /// Decodes a `Transfer` event; `None` for any other log.
    pub fn from_log(topics: &[B256], data: &[u8]) -> Option<Transfer> {
        match topics {
            [t, from, to] if *t == TRANSFER_TOPIC && data.len() == 32 => Some(Transfer {
                from: Address::from_word(*from),
                to: Address::from_word(*to),
                amount: U256::from_be_slice(data),
            }),
            _ => None,
        }
    }
}

/// The token's state at one block: each holder's balance and `totalSupply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    pub balances: BTreeMap<Address, U256>,
    pub supply: U256,
}

impl Ledger {
    /// The state `deploy.yaml` mints.
    pub fn initial() -> Ledger {
        let balances: BTreeMap<_, _> = HOLDERS
            .iter()
            .zip(1u128..)
            .map(|(h, k)| (*h, U256::from(k * UNIT)))
            .collect();
        let supply = balances.values().sum();
        Ledger { balances, supply }
    }

    /// The state after `transfers`. Mints (from zero) and burns (to zero) move
    /// the supply; amounts that leave or enter the holder set otherwise only
    /// move balances. `Err` if a holder would go negative.
    pub fn apply(&self, transfers: &[Transfer]) -> Result<Ledger, String> {
        let mut next = self.clone();
        for t in transfers {
            if t.from == Address::ZERO {
                next.supply = next.supply.saturating_add(t.amount);
            } else if let Some(b) = next.balances.get_mut(&t.from) {
                *b = b
                    .checked_sub(t.amount)
                    .ok_or_else(|| format!("{} spends {} of {b}", t.from, t.amount))?;
            }
            if t.to == Address::ZERO {
                next.supply = next.supply.saturating_sub(t.amount);
            } else if let Some(b) = next.balances.get_mut(&t.to) {
                *b = b.saturating_add(t.amount);
            }
        }
        Ok(next)
    }

    fn sum(&self) -> U256 {
        self.balances
            .values()
            .fold(U256::ZERO, |a, b| a.saturating_add(*b))
    }

    /// Holders whose balance differs from `other`'s, as `holder: ours -> theirs`.
    fn diff(&self, other: &Ledger) -> String {
        let mut out: Vec<String> = self
            .balances
            .iter()
            .filter(|(h, b)| other.balances.get(*h) != Some(*b))
            .map(|(h, b)| format!("{h}: {b} -> {:?}", other.balances.get(h)))
            .collect();
        if self.supply != other.supply {
            out.push(format!("supply: {} -> {}", self.supply, other.supply));
        }
        out.join(", ")
    }
}

/// Conservation at one block: the supply is what was minted, nothing was
/// created or lost among the holders, and no balance exceeds the supply.
pub fn check_ledger(ledger: &Ledger) -> Vec<Failure> {
    let want = Ledger::initial().supply;
    let mut out = Vec::new();
    if ledger.supply != want {
        out.push((
            "E8/tip20-supply-changed".into(),
            format!("totalSupply {}, minted {want}", ledger.supply),
        ));
    }
    if ledger.sum() != ledger.supply {
        out.push((
            "E8/tip20-balances-not-conserved".into(),
            format!(
                "holders sum to {}, totalSupply {}: {:?}",
                ledger.sum(),
                ledger.supply,
                ledger.balances
            ),
        ));
    }
    for (h, b) in &ledger.balances {
        if *b > ledger.supply {
            out.push((
                "E8/tip20-balance-exceeds-supply".into(),
                format!("{h} holds {b}, totalSupply {}", ledger.supply),
            ));
        }
    }
    out
}

/// One block: conservation of `cur`, and `cur` is exactly `prev` (its
/// parent) plus the block's `transfers`.
pub fn check_block(prev: &Ledger, cur: &Ledger, transfers: &[Transfer]) -> Vec<Failure> {
    let mut out = check_ledger(cur);
    match prev.apply(transfers) {
        Ok(want) if want == *cur => {}
        Ok(want) => out.push((
            "E8/tip20-transfers-unexplained".into(),
            format!(
                "{} transfers; expected -> read: {}",
                transfers.len(),
                want.diff(cur)
            ),
        )),
        Err(e) => out.push((
            "E8/tip20-transfers-unexplained".into(),
            format!(
                "{} transfers on the parent's balances: {e}",
                transfers.len()
            ),
        )),
    }
    out
}

/// Node queries for E8; `Err` while the node is unreachable. Block state is
/// named by hash.
pub trait Tip20Chain {
    /// Canonical block `number`; `None` past the head.
    fn block(&mut self, number: u64) -> Result<Option<BlockRef>, String>;
    fn balances(
        &mut self,
        token: Address,
        holders: &[Address],
        block: B256,
    ) -> Result<Vec<U256>, String>;
    fn supply(&mut self, token: Address, block: B256) -> Result<U256, String>;
    /// `Transfer` events of `token` in the block's receipts, in order.
    fn transfers(&mut self, token: Address, block: B256) -> Result<Vec<Transfer>, String>;

    /// [`TOKEN`]'s ledger at `block`.
    fn ledger(&mut self, block: B256) -> Result<Ledger, String> {
        let supply = self.supply(TOKEN, block)?;
        let balances = self.balances(TOKEN, &HOLDERS, block)?;
        Ok(Ledger {
            balances: HOLDERS.iter().copied().zip(balances).collect(),
            supply,
        })
    }
}

/// New blocks checked per tick, newest last; older unchecked ones are skipped.
const BLOCKS_PER_TICK: u64 = 10;
/// Blocks at multiples of this are pinned, besides the run's first block.
const PIN_EVERY: u64 = 25;
/// Recent pins kept besides the first one.
const RECENT_PINS: usize = 3;

#[derive(Debug, Clone)]
struct Pin {
    block: BlockRef,
    ledger: Ledger,
    /// Node restarts before the pin was taken.
    restarts: u64,
    /// Not yet persisted when pinned (newer than the last "Saved range").
    in_memory: bool,
    /// A "Saved range of blocks" covered it since.
    persisted: bool,
}

/// E8 over successive ticks: checks new blocks and a historical depth sweep,
/// and re-reads pinned snapshots.
#[derive(Debug, Default)]
pub struct Tip20Oracle {
    /// The first head seen: the token's deploy is complete there, so older
    /// blocks are not checked.
    floor: Option<u64>,
    /// The newest block checked.
    checked: u64,
    checked_hash: Option<B256>,
    ticks: u64,
    /// The last ledger read, by block hash: usually the next block's parent.
    last: Option<(B256, Ledger)>,
    /// Pins: the run's first checked block, then the most recent.
    pins: Vec<Pin>,
    restarts: u64,
    saved: Option<u64>,
    covered: std::collections::BTreeSet<&'static str>,
}

impl Tip20Oracle {
    /// The node logged "Saved range of blocks" up to `number`.
    pub fn on_saved(&mut self, number: u64) {
        self.saved = Some(number);
        for p in &mut self.pins {
            if p.block.number <= number {
                p.persisted = true;
            }
        }
    }

    pub fn on_restart(&mut self) {
        self.restarts += 1;
    }

    fn cover(&mut self, out: &mut Vec<Verdict>, signature: &'static str, detail: String) {
        if self.covered.insert(signature) {
            out.push(Verdict::Sometimes(true, finding(signature, detail)));
        }
    }

    fn ledger(&mut self, chain: &mut impl Tip20Chain, hash: B256) -> Option<Ledger> {
        match &self.last {
            Some((h, l)) if *h == hash => Some(l.clone()),
            _ => chain.ledger(hash).ok(),
        }
    }

    /// [`check_block`] for canonical block `number`; `None` while the node is
    /// unreachable.
    fn check(
        &mut self,
        chain: &mut impl Tip20Chain,
        number: u64,
    ) -> Option<(BlockRef, Ledger, usize, Vec<Failure>)> {
        let block = chain.block(number).ok()??;
        let prev = self.ledger(chain, block.parent)?;
        let cur = chain.ledger(block.hash).ok()?;
        let transfers = chain.transfers(TOKEN, block.hash).ok()?;
        self.last = Some((block.hash, cur.clone()));
        let failures = check_block(&prev, &cur, &transfers);
        Some((block, cur, transfers.len(), failures))
    }

    pub fn tick(&mut self, chain: &mut impl Tip20Chain, head: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        let floor = *self.floor.get_or_insert(head);
        // Crash recovery rewound the chain: check the rebuilt blocks.
        if head < self.checked {
            self.checked = head.saturating_sub(1);
        } else if let Some(want) = self.checked_hash {
            match chain.block(self.checked) {
                Ok(Some(b)) if b.hash != want => {
                    self.checked = self.checked.saturating_sub(BLOCKS_PER_TICK);
                }
                Ok(_) => {}
                Err(_) => return Vec::new(),
            }
        }
        let first = (self.checked + 1)
            .max(head.saturating_sub(BLOCKS_PER_TICK - 1))
            .max(floor);
        let tick = self.ticks;
        self.ticks += 1;
        let older: Vec<u64> = [SHALLOW_DEPTHS, DEEP_DEPTHS]
            .into_iter()
            .filter_map(|range| head.checked_sub(sweep_depth(range, tick)))
            .filter(|b| *b >= floor && *b < first)
            .collect();
        for number in older.into_iter().chain(first..=head) {
            let Some((block, ledger, transfers, failures)) = self.check(chain, number) else {
                return out;
            };
            let ok = failures.is_empty();
            for (signature, detail) in failures {
                out.push(Verdict::Always(
                    false,
                    finding(
                        &signature,
                        format!("block {number} ({}): {detail}", block.hash),
                    ),
                ));
            }
            if ok {
                self.cover(&mut out, "S/tip20-checked", format!("block {number}"));
                if transfers >= 2 {
                    self.cover(
                        &mut out,
                        "S/tip20-transfers-in-block",
                        format!("block {number}: {transfers} transfers"),
                    );
                }
            }
            if number >= first {
                self.checked = number;
                self.checked_hash = Some(block.hash);
                if ok && (self.pins.is_empty() || number % PIN_EVERY == 0) {
                    self.pin(block, ledger);
                }
            }
        }
        out.extend(self.reread_pins(chain));
        out
    }

    fn pin(&mut self, block: BlockRef, ledger: Ledger) {
        if self.pins.iter().any(|p| p.block == block) {
            return;
        }
        // A rebuilt block replaces its rewound pin.
        self.pins.retain(|p| p.block.number != block.number);
        if self.pins.len() > RECENT_PINS {
            self.pins.remove(1);
        }
        self.pins.push(Pin {
            block,
            ledger,
            restarts: self.restarts,
            in_memory: self.saved.is_none_or(|s| s < block.number),
            persisted: false,
        });
    }

    /// Re-reads every pinned block that is still canonical; a rewound one is
    /// dropped (unfinalized blocks may be rebuilt after a crash; see E3).
    fn reread_pins(&mut self, chain: &mut impl Tip20Chain) -> Vec<Verdict> {
        let mut out = Vec::new();
        let mut keep = Vec::new();
        for pin in std::mem::take(&mut self.pins) {
            match chain.block(pin.block.number) {
                Ok(Some(b)) if b.hash != pin.block.hash => continue,
                Ok(Some(_)) => {}
                // Not rebuilt yet, or the node is unreachable.
                _ => {
                    keep.push(pin);
                    continue;
                }
            }
            if let Ok(now) = chain.ledger(pin.block.hash) {
                let detail = format!("block {} ({})", pin.block.number, pin.block.hash);
                if now != pin.ledger {
                    out.push(Verdict::Always(
                        false,
                        finding(
                            "E8/tip20-snapshot-changed",
                            format!("{detail}: pinned -> now: {}", pin.ledger.diff(&now)),
                        ),
                    ));
                } else {
                    if self.restarts > pin.restarts {
                        self.cover(
                            &mut out,
                            "S/tip20-pinned-read-survived-restart",
                            detail.clone(),
                        );
                    }
                    if pin.in_memory && pin.persisted {
                        self.cover(&mut out, "S/tip20-pinned-read-survived-persistence", detail);
                    }
                }
            }
            keep.push(pin);
        }
        self.pins = keep;
        out
    }
}

/// Per-seed transfer mix.
struct Knobs {
    /// Holders that send (indices into [`HOLDERS`]), at least two.
    senders: Vec<usize>,
    /// Weights of zero, small (< 1000), large (up to 10^20) and overdrawn
    /// (more than the supply: reverts, moves nothing) amounts.
    amounts: [u32; 4],
    /// Chance a transfer is to the sender itself.
    to_self: f64,
}

const KNOB_SALT: u64 = 0x7469_7032_306b_6e62;
const STEP_SALT: u64 = 0x7469_7032_3073_7470;

fn amount(rng: &mut StdRng, weights: &[u32; 4]) -> U256 {
    let mut pick = rng.random_range(0..weights.iter().sum::<u32>());
    let mut class = 0;
    while pick >= weights[class] {
        pick -= weights[class];
        class += 1;
    }
    match class {
        0 => U256::ZERO,
        1 => U256::from(rng.random_range(1..1000u64)),
        2 => U256::from(rng.random_range(1000..=100_000_000_000_000_000_000u128)),
        _ => Ledger::initial().supply + U256::from(rng.random_range(1..=u64::MAX)),
    }
}

/// txgen spec for load generation `generation` (0 at branch start, one more
/// per node restart): `steps` transfers of [`TOKEN`] between holders. Senders
/// are interleaved, so each block carries several concurrent transfers.
pub fn spec(seed: u64, generation: u64, steps: usize) -> String {
    let mut knob_rng = StdRng::seed_from_u64(seed ^ KNOB_SALT);
    let mut senders: Vec<usize> = (0..HOLDERS.len()).collect();
    for i in (1..senders.len()).rev() {
        senders.swap(i, knob_rng.random_range(0..=i));
    }
    senders.truncate(knob_rng.random_range(2..=HOLDERS.len()));
    senders.sort_unstable();
    let knobs = Knobs {
        senders,
        amounts: [
            knob_rng.random_range(0..=1),
            knob_rng.random_range(1..=4),
            knob_rng.random_range(0..=4),
            knob_rng.random_range(0..=1),
        ],
        to_self: [0.0, 0.05, 0.2][knob_rng.random_range(0..3)],
    };
    let mut rng =
        StdRng::seed_from_u64(seed ^ STEP_SALT ^ generation.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let mut out = format!(
        "# Generated by tempo-dst (tip20) for seed {seed}, load generation {generation}.\n\
         # Senders: holders {:?}.\n\
         chain_id: 1337\n\
         accounts:\n  holders:\n    mnemonic: \"test test test test test test test test test test test junk\"\n    range: [1, 9]\n\
         artifacts:\n  TIP20: tip20.abi.json\n\
         templates:\n  transfer:\n    type: tempo\n    from: {{ pool: holders, select: {{ index: 0 }} }}\n    gas_limit: 1000000\n\
         \x20   max_fee_per_gas: 100000000000\n    max_priority_fee_per_gas: 1000000000\n\
         \x20   fee_token: \"0x20c0000000000000000000000000000000000000\"\n\
         \x20   call:\n      to: \"{TOKEN:#x}\"\n      abi: TIP20\n      function: transfer\n      args: []\n\
         sequences:\n",
        knobs.senders
    );
    // One single-step sequence per transfer: txgen sends a sequence's steps
    // one block at a time, and different sequences concurrently. txgen draws
    // `steps` of them (with replacement) and assigns nonces in draw order.
    for i in 0..steps {
        let from = knobs.senders[rng.random_range(0..knobs.senders.len())];
        let to = if rng.random_bool(knobs.to_self) {
            from
        } else {
            let to = rng.random_range(0..HOLDERS.len() - 1);
            to + usize::from(to >= from)
        };
        let amount = amount(&mut rng, &knobs.amounts);
        out.push_str(&format!(
            "  t{i}:\n    steps:\n      - {{ name: x, template: transfer, with: {{ from: {{ pool: holders, select: {{ index: {from} }} }}, call: {{ args: [\"{:#x}\", \"{amount}\"] }} }} }}\n",
            HOLDERS[to]
        ));
    }
    out.push_str("mix:\n");
    for i in 0..steps {
        out.push_str(&format!("  - {{ sequence: t{i}, weight: 1 }}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn t(from: usize, to: usize, amount: u64) -> Transfer {
        Transfer {
            from: HOLDERS[from],
            to: HOLDERS[to],
            amount: U256::from(amount),
        }
    }

    fn sigs(f: &[Failure]) -> Vec<&str> {
        f.iter().map(|(s, _)| s.as_str()).collect()
    }

    #[test]
    fn initial_ledger_matches_deploy() {
        let l = Ledger::initial();
        assert_eq!(l.supply, U256::from(36 * UNIT));
        assert_eq!(l.balances[&HOLDERS[7]], U256::from(8 * UNIT));
        assert!(check_ledger(&l).is_empty());
    }

    #[test]
    fn transfers_explain_the_next_block() {
        let prev = Ledger::initial();
        let xs = [t(0, 1, 5), t(1, 2, 7), t(3, 3, 9)];
        let cur = prev.apply(&xs).unwrap();
        assert_eq!(cur.balances[&HOLDERS[0]], U256::from(UNIT - 5));
        assert_eq!(cur.balances[&HOLDERS[1]], U256::from(2 * UNIT - 2));
        assert_eq!(cur.balances[&HOLDERS[3]], U256::from(4 * UNIT));
        assert!(check_block(&prev, &cur, &xs).is_empty());
    }

    #[test]
    fn partially_applied_block_is_unexplained() {
        let prev = Ledger::initial();
        let xs = [t(0, 1, 5), t(1, 2, 7)];
        // Only the first transfer's effects are visible; still conserved.
        let half = prev.apply(&xs[..1]).unwrap();
        assert_eq!(
            sigs(&check_block(&prev, &half, &xs)),
            ["E8/tip20-transfers-unexplained"]
        );
        // A debit without its credit breaks conservation too.
        let mut torn = prev.clone();
        *torn.balances.get_mut(&HOLDERS[0]).unwrap() -= U256::from(5);
        assert_eq!(
            sigs(&check_block(&prev, &torn, &[])),
            [
                "E8/tip20-balances-not-conserved",
                "E8/tip20-transfers-unexplained"
            ]
        );
    }

    #[test]
    fn overspend_and_supply_changes_are_reported() {
        let prev = Ledger::initial();
        let too_much = [Transfer {
            amount: U256::from(UNIT + 1),
            ..t(0, 1, 0)
        }];
        assert_eq!(
            sigs(&check_block(&prev, &prev, &too_much)),
            ["E8/tip20-transfers-unexplained"]
        );
        let mut minted = prev.clone();
        minted.supply += U256::from(1);
        assert_eq!(
            sigs(&check_ledger(&minted)),
            ["E8/tip20-supply-changed", "E8/tip20-balances-not-conserved"]
        );
        let mut rich = prev.clone();
        rich.balances
            .insert(HOLDERS[0], rich.supply + U256::from(1));
        assert!(sigs(&check_ledger(&rich)).contains(&"E8/tip20-balance-exceeds-supply"));
        // A mint is explained by its log, but still changes the supply.
        let mint = [Transfer {
            from: Address::ZERO,
            ..t(0, 0, 3)
        }];
        let after = prev.apply(&mint).unwrap();
        assert_eq!(
            sigs(&check_block(&prev, &after, &mint)),
            ["E8/tip20-supply-changed"]
        );
    }

    #[test]
    fn decodes_transfer_logs() {
        let word = |a: Address| a.into_word();
        let data = U256::from(42).to_be_bytes::<32>();
        let x = Transfer::from_log(&[TRANSFER_TOPIC, word(HOLDERS[0]), word(HOLDERS[1])], &data);
        assert_eq!(x, Some(t(0, 1, 42)));
        assert_eq!(Transfer::from_log(&[B256::ZERO], &data), None);
    }

    /// Canonical hashes by number; ledgers and transfers by hash. Blocks
    /// built after a rewind get hashes of a new fork.
    #[derive(Default)]
    struct FakeChain {
        canon: Vec<B256>,
        fork: u8,
        ledgers: HashMap<B256, Ledger>,
        transfers: HashMap<B256, Vec<Transfer>>,
        down: bool,
    }

    fn hash(n: u64, fork: u8) -> B256 {
        let mut h = B256::from(U256::from(n));
        h.0[0] = fork + 1;
        h
    }

    impl FakeChain {
        fn new(head: u64) -> FakeChain {
            let mut c = FakeChain::default();
            c.canon.push(hash(0, 0));
            c.ledgers.insert(hash(0, 0), Ledger::initial());
            c.grow(head, |_| vec![]);
            c
        }

        fn head(&self) -> u64 {
            self.canon.len() as u64 - 1
        }

        /// Extends the chain to `head`, block `n` applying `xs(n)`.
        fn grow(&mut self, head: u64, xs: impl Fn(u64) -> Vec<Transfer>) {
            for n in self.head() + 1..=head {
                let prev = self.ledgers[self.canon.last().unwrap()].clone();
                let x = xs(n);
                let h = hash(n, self.fork);
                self.ledgers.insert(h, prev.apply(&x).unwrap());
                self.transfers.insert(h, x);
                self.canon.push(h);
            }
        }

        /// Crash recovery: blocks after `to` are discarded, and later ones are
        /// built on a new fork.
        fn rewind(&mut self, to: u64) {
            self.canon.truncate(to as usize + 1);
            self.fork += 1;
        }
    }

    impl Tip20Chain for FakeChain {
        fn block(&mut self, n: u64) -> Result<Option<BlockRef>, String> {
            if self.down {
                return Err("down".into());
            }
            Ok(self.canon.get(n as usize).map(|h| BlockRef {
                number: n,
                hash: *h,
                parent: self.canon[n.saturating_sub(1) as usize],
            }))
        }
        fn balances(&mut self, _: Address, h: &[Address], b: B256) -> Result<Vec<U256>, String> {
            let l = self.ledgers.get(&b).ok_or("unknown block")?;
            Ok(h.iter().map(|a| l.balances[a]).collect())
        }
        fn supply(&mut self, _: Address, b: B256) -> Result<U256, String> {
            Ok(self.ledgers.get(&b).ok_or("unknown block")?.supply)
        }
        fn transfers(&mut self, _: Address, b: B256) -> Result<Vec<Transfer>, String> {
            Ok(self.transfers.get(&b).cloned().unwrap_or_default())
        }
    }

    fn vsigs(v: &[Verdict]) -> Vec<(bool, &str)> {
        v.iter()
            .map(|v| match v {
                Verdict::Always(ok, f) | Verdict::Sometimes(ok, f) => (*ok, f.signature.as_str()),
            })
            .collect()
    }

    fn busy(n: u64) -> Vec<Transfer> {
        vec![t(n as usize % 8, (n as usize + 1) % 8, n), t(2, 5, 1)]
    }

    #[test]
    fn honest_chain_passes_with_coverage() {
        let mut c = FakeChain::new(10);
        let mut o = Tip20Oracle::default();
        assert_eq!(vsigs(&o.tick(&mut c, 10)), [(true, "S/tip20-checked")]);
        c.grow(14, busy);
        assert_eq!(
            vsigs(&o.tick(&mut c, 14)),
            [(true, "S/tip20-transfers-in-block")]
        );
        c.grow(300, busy);
        for head in (20..=300).step_by(10) {
            let v = o.tick(&mut c, head);
            assert!(!vsigs(&v).iter().any(|(ok, _)| !ok), "{v:?}");
        }
    }

    #[test]
    fn unexplained_block_is_reported() {
        let mut c = FakeChain::new(10);
        let mut o = Tip20Oracle::default();
        o.tick(&mut c, 10);
        c.grow(12, busy);
        // Block 12's receipts lose a transfer that its state applied.
        c.transfers.get_mut(&hash(12, 0)).unwrap().pop();
        let v = o.tick(&mut c, 12);
        assert!(vsigs(&v).contains(&(false, "E8/tip20-transfers-unexplained")));
    }

    #[test]
    fn pinned_snapshot_change_is_reported() {
        let mut c = FakeChain::new(5);
        let mut o = Tip20Oracle::default();
        o.tick(&mut c, 5);
        c.grow(30, busy);
        o.tick(&mut c, 30);
        // Block 5 (the first pin) reads differently later, same hash.
        let l = c.ledgers.get_mut(&hash(5, 0)).unwrap();
        l.balances.insert(HOLDERS[0], U256::ZERO);
        let v = o.tick(&mut c, 30);
        assert!(vsigs(&v).contains(&(false, "E8/tip20-snapshot-changed")));
    }

    #[test]
    fn pins_survive_persistence_and_restart() {
        let mut c = FakeChain::new(5);
        let mut o = Tip20Oracle::default();
        o.on_saved(3);
        o.tick(&mut c, 5);
        c.grow(25, busy);
        o.tick(&mut c, 25);
        // Block 25 is pinned in memory, then persisted.
        o.on_saved(26);
        let v = o.tick(&mut c, 25);
        assert!(vsigs(&v).contains(&(true, "S/tip20-pinned-read-survived-persistence")));
        c.down = true;
        assert!(o.tick(&mut c, 25).is_empty());
        o.on_restart();
        c.down = false;
        let v = o.tick(&mut c, 25);
        assert!(vsigs(&v).contains(&(true, "S/tip20-pinned-read-survived-restart")));
    }

    #[test]
    fn rewound_pins_are_dropped_and_rebuilt_blocks_rechecked() {
        let mut c = FakeChain::new(5);
        let mut o = Tip20Oracle::default();
        o.tick(&mut c, 5);
        c.grow(50, busy);
        o.tick(&mut c, 30);
        o.tick(&mut c, 50);
        assert_eq!(
            o.pins.iter().map(|p| p.block.number).collect::<Vec<_>>(),
            [5, 25, 50]
        );
        // Crash recovery rewinds to 40 and rebuilds past the old head, unseen.
        c.rewind(40);
        c.grow(52, |n| vec![t(4, 6, n)]);
        let v = o.tick(&mut c, 52);
        assert!(!vsigs(&v).iter().any(|(ok, _)| !ok), "{v:?}");
        // The rewound pin of 50 is replaced by the rebuilt block.
        assert_eq!(
            o.pins.iter().map(|p| p.block.number).collect::<Vec<_>>(),
            [5, 25, 50]
        );
        assert!(o
            .pins
            .iter()
            .all(|p| c.canon[p.block.number as usize] == p.block.hash));
        // The rebuilt blocks were checked: a wrong one among them is caught.
        c.rewind(45);
        c.grow(53, |_| vec![]);
        let h = c.canon[48];
        c.ledgers
            .get_mut(&h)
            .unwrap()
            .balances
            .insert(HOLDERS[0], U256::ZERO);
        let v = o.tick(&mut c, 53);
        assert!(
            vsigs(&v).contains(&(false, "E8/tip20-transfers-unexplained")),
            "{v:?}"
        );
    }

    #[test]
    fn spec_is_deterministic_per_seed_and_generation() {
        let a = spec(3, 0, 200);
        assert_eq!(a, spec(3, 0, 200));
        assert_ne!(a, spec(3, 1, 200));
        assert_ne!(a, spec(4, 0, 200));
        assert_eq!(a.matches("template: transfer").count(), 200);
        // Several senders are interleaved.
        let senders: std::collections::BTreeSet<_> = a
            .lines()
            .filter_map(|l| l.split("index: ").nth(1))
            .filter_map(|s| s.split(' ').next())
            .collect();
        assert!(senders.len() >= 2, "{senders:?}");
        assert!(a.contains(&format!("to: \"{TOKEN:#x}\"")));
    }
}
