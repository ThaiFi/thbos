// SPDX-License-Identifier: GPL-2.0

//! Generated storage-trie load: a pure function of the run seed.
//!
//! [`slots`] picks the RawStorage slots a run writes so that their trie paths
//! (`keccak256(bytes32(slot))`) form a random shape: an anchor slot, a stack of
//! slots sharing 1, 2, 3, ... leading nibbles with it (nested branches and
//! extensions), sometimes a pair sharing 7+ nibbles (leaves short enough to be
//! inlined in their parent), and a few unrelated slots. [`spec`] writes a txgen
//! spec of random inserts, updates and deletes over those slots, with values
//! from every encoding class and no-op holds of random length, so changes land
//! at every distance from the node's persistence cycles. Nothing here names a
//! particular bug; per-seed knobs (stack depth, value mix, holds) vary the mix
//! swarm-style.
//!
//! With `trie_contracts=auto`, [`plan`] spreads the load over the first N of
//! the [`POOL`] contracts `trie/deploy-pool.yaml` deploys, written by S of the
//! [`WRITERS`]: each contract gets its own slot shape (a per-contract sub-seed;
//! contract 0 keeps the run seed), each writer one txgen sequence over a
//! subset of the contracts (nonce order, one write per block), and the
//! writers run concurrently, so blocks carry writes to several storage tries.
//! N = 1, S = 1 is exactly the single-contract load ([`spec`]).

use alloy_primitives::{address, keccak256, Address, B256, U256};
use rand::{rngs::StdRng, Rng, SeedableRng};

/// Slots considered: enough keccak paths that 4-nibble stacks always exist
/// and 7-nibble pairs usually do.
const SEARCH: u64 = 1 << 17;
/// Written with zero for no-op holds; never written non-zero.
pub const NOOP_SLOT: u64 = 1 << 40;
/// RawStorage's CREATE address (deployed by `trie/deploy.yaml`).
const CONTRACT: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

/// RawStorage contracts `trie/deploy-pool.yaml` deploys (see [`pool_address`]).
pub const POOL: usize = 16;
/// TrieWriter dev-account indices (mnemonic `test ... junk`): writer 0 is the
/// single-contract load's sender, writers 1-7 are outside every other load's
/// accounts (transfers 0-9, TIP-20 1-9, chain 9). The pool deploy funds them
/// with pathUSD: the dev genesis only funds accounts 0-9.
pub const WRITERS: [u32; 8] = [0, 10, 11, 12, 13, 14, 15, 16];
/// [`WRITERS`]' addresses.
pub(crate) const WRITER_ADDRESSES: [Address; 8] = [
    address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
    address!("Bcd4042DE499D14e55001CcbB24a551F3b954096"),
    address!("71bE63f3384f5fb98995898A86B02Fb2426c5788"),
    address!("FABB0ac9d68B0B445fB7357272Ff202C5651694a"),
    address!("1CBd3b2770909D4e10f157cABC84C7264073C9Ec"),
    address!("dF3e18d64BC6A983f673Ab319CCaE4f1a57C7097"),
    address!("cd3B766CCDd6AE721141F452C550Ca635964ce71"),
    address!("2546BcD3c84621e976D8185a91A922aE77ECEc30"),
];

const SHAPE_SALT: u64 = 0x7472_6965_7368_6170;
const OPS_SALT: u64 = 0x7472_6965_6f70_7300;
const CONTRACT_SALT: u64 = 0x7472_6965_6374_7263;
const WRITER_SALT: u64 = 0x7472_6965_7772_7472;
const BURST_SALT: u64 = 0x7472_6965_6275_7273;
const ASSIGN_SALT: u64 = 0x7472_6965_6173_676e;

/// Pool contract `c`: writer `c mod 8`'s CREATE at nonce `c div 8`, the order
/// `trie/deploy-pool.yaml` deploys them in. TrieContract 0 is dev account 0's
/// nonce-0 CREATE, the single-contract load's address.
pub fn pool_address(c: usize) -> Address {
    WRITER_ADDRESSES[c % WRITERS.len()].create((c / WRITERS.len()) as u64)
}

/// Every pool address, as the pool deploy (`start::deploy`) checks them.
pub fn pool_addresses() -> Vec<String> {
    (0..POOL)
        .map(|c| pool_address(c).to_checksum(None))
        .collect()
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Sub-seed for item `i` (a contract's slot shape, a writer's write stream).
/// Item 0 keeps the run seed, so contract 0 and writer 0 are the
/// single-contract load's.
fn sub_seed(seed: u64, salt: u64, i: usize) -> u64 {
    if i == 0 {
        seed
    } else {
        splitmix64(seed ^ salt ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
    }
}

fn path(slot: u64) -> [u8; 32] {
    keccak256(B256::from(U256::from(slot))).0
}

fn paths() -> Vec<[u8; 32]> {
    (0..SEARCH).map(path).collect()
}

/// Leading nibbles `a` and `b` share.
fn shared_nibbles(a: &[u8; 32], b: &[u8; 32]) -> usize {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        if x != y {
            return 2 * i + usize::from(x >> 4 == y >> 4);
        }
    }
    64
}

/// The run's slots, sorted (contract 0's shape in [`plan`]).
pub fn slots(seed: u64) -> Vec<u64> {
    slots_in(&paths(), seed)
}

/// [`slots`] over precomputed [`paths`].
fn slots_in(paths: &[[u8; 32]], seed: u64) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(seed ^ SHAPE_SALT);
    let anchor = rng.random_range(0..SEARCH);
    let mut out = vec![anchor];
    // Stack: for each level, 1-2 slots sharing exactly `level` nibbles with
    // the anchor, i.e. siblings of the anchor's path at that depth.
    let depth = rng.random_range(1..=5);
    for level in 1..=depth {
        let candidates: Vec<u64> = (0..SEARCH)
            .filter(|s| !out.contains(s))
            .filter(|s| shared_nibbles(&paths[anchor as usize], &paths[*s as usize]) == level)
            .collect();
        for _ in 0..rng.random_range(1..=2) {
            if !candidates.is_empty() {
                let s = candidates[rng.random_range(0..candidates.len())];
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    }
    // Long shared prefix: short leaves, inlined in their parent when small.
    if rng.random_bool(0.5) {
        let mut by_prefix = std::collections::HashMap::new();
        let mut pairs = Vec::new();
        for s in 0..SEARCH {
            let p = &paths[s as usize];
            let key = (u32::from_be_bytes([p[0], p[1], p[2], p[3]])) >> 4;
            if let Some(prev) = by_prefix.insert(key, s) {
                pairs.push((prev, s));
            }
        }
        if !pairs.is_empty() {
            let (a, b) = pairs[rng.random_range(0..pairs.len())];
            for s in [a, b] {
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    }
    for _ in 0..rng.random_range(0..=3) {
        let s = rng.random_range(0..SEARCH);
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out.sort_unstable();
    out
}

/// Per-seed operation mix.
struct Knobs {
    /// Weights of delete, small (< 0x80: inline-sized leaves), u64 and full
    /// 256-bit values.
    values: [u32; 4],
    /// Chance a step is a no-op hold, and the longest hold in steps.
    hold: f64,
    max_hold: usize,
}

fn value(rng: &mut StdRng, knobs: &Knobs) -> String {
    let total: u32 = knobs.values.iter().sum();
    let mut pick = rng.random_range(0..total);
    let mut class = 0;
    while pick >= knobs.values[class] {
        pick -= knobs.values[class];
        class += 1;
    }
    match class {
        0 => "0".into(),
        1 => rng.random_range(1..0x80u64).to_string(),
        2 => rng.random_range(0x80..=u64::MAX).to_string(),
        _ => format!("0x{}", hex(&rng.random::<[u8; 32]>())),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// txgen spec for load generation `generation` (0 at branch start, one more
/// per node restart): `steps` RawStorage writes over `slots`, in one sequence
/// so a single sender keeps them in nonce order. [`TriePlan::writer_spec`] with
/// one contract and one writer.
#[cfg(test)]
pub fn spec(seed: u64, generation: u64, slots: &[u64], steps: usize) -> String {
    render(seed, generation, None, seed, &[(CONTRACT, slots)], steps)
}

/// One contract of a [`TriePlan`]: its address and slot shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieContract {
    pub address: String,
    pub slots: Vec<u64>,
}

/// One writer of a [`TriePlan`]: its dev-account index and the contracts it
/// writes (indices into [`TriePlan::contracts`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieWriter {
    pub account: u32,
    contracts: Vec<usize>,
}

/// A run's multi-contract trie load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriePlan {
    contracts: Vec<TrieContract>,
    writers: Vec<TrieWriter>,
}

/// Salt separating the contracts/senders draw from the seed's other uses.
const DRAW_SALT: u64 = 0x7472_6965_706f_6f6c; // "triepool"

/// `trie_contracts=auto`: the seed's contracts N and senders S, weighted
/// toward a few contracts: 1/8 of seeds write one, 1/2 two to four, 1/4 five
/// to eight, 1/8 nine to sixteen. One contract has one sender; several have
/// 2..=min(N, 8), so blocks carry concurrent writes to different storage
/// tries (`S/multi-contract-block`, required when N >= 2).
pub fn draw(seed: u64) -> (usize, usize) {
    let r = splitmix64(seed ^ DRAW_SALT);
    let (lo, hi) = match r % 8 {
        0 => (1, 1),
        1..=4 => (2, 4),
        5 | 6 => (5, 8),
        _ => (9, POOL as u64),
    };
    let r = splitmix64(r);
    let contracts = lo + r % (hi - lo + 1);
    let senders = if contracts == 1 {
        1
    } else {
        2 + splitmix64(r) % (contracts.min(WRITERS.len() as u64) - 1)
    };
    (contracts as usize, senders as usize)
}

/// The run's contracts (the first `contracts` of the pool, each with its own
/// slot shape) and writers (the first `senders` of [`WRITERS`], at most one
/// per contract). TrieContract `c` is written by writer `c mod S`, so every
/// writer has a contract of its own, and a quarter of the time by one more
/// writer, so some storage tries take two senders' writes in one block.
pub fn plan(seed: u64, contracts: usize, senders: usize) -> TriePlan {
    let n = contracts.clamp(1, POOL);
    let s = senders.clamp(1, WRITERS.len().min(n));
    let paths = paths();
    let contracts = (0..n)
        .map(|c| TrieContract {
            address: if c == 0 {
                CONTRACT.to_string()
            } else {
                pool_address(c).to_checksum(None)
            },
            slots: slots_in(&paths, sub_seed(seed, CONTRACT_SALT, c)),
        })
        .collect();
    let mut rng = StdRng::seed_from_u64(seed ^ ASSIGN_SALT);
    let mut writers: Vec<TrieWriter> = WRITERS[..s]
        .iter()
        .map(|&account| TrieWriter {
            account,
            contracts: Vec::new(),
        })
        .collect();
    for c in 0..n {
        writers[c % s].contracts.push(c);
        if s > 1 && rng.random_bool(0.25) {
            let other = (c % s + rng.random_range(1..s)) % s;
            writers[other].contracts.push(c);
        }
    }
    for w in &mut writers {
        w.contracts.sort_unstable();
    }
    TriePlan { contracts, writers }
}

impl TriePlan {
    /// The number of contracts referenced by the writer assignments.
    pub fn contract_count(&self) -> usize {
        self.contracts.len()
    }

    /// Consumes the plan and returns its contracts in assignment-index order.
    pub fn into_contracts(self) -> Vec<TrieContract> {
        self.contracts
    }

    /// Replaces the first contract's slot shape without changing writer assignments.
    pub fn replace_first_slots(&mut self, slots: Vec<u64>) {
        self.contracts[0].slots = slots;
    }

    /// The immutable writer assignments, in spec-generation order.
    pub fn writers(&self) -> &[TrieWriter] {
        &self.writers
    }

    /// Writer `k`'s burst for load generation `generation` (several writers
    /// only): one write of a fresh full-word value (keccak of the inputs, so
    /// it changes the root whatever the slot held) to a slot of contract
    /// `k`, which is writer `k`'s own. `run-multi.sh` sends every writer's
    /// burst back to back before the interleaved streams, so the first block
    /// of each generation (after branch start and every restart) changes at
    /// least two contracts' storage roots: `S/multi-contract-block` is then
    /// deterministic rather than left to the streams' chance overlap.
    pub fn burst_spec(&self, k: usize, spec_seed: u64, generation: u64) -> String {
        let contract = &self.contracts[k];
        let mut input = Vec::with_capacity(32);
        for x in [spec_seed, generation, k as u64, BURST_SALT] {
            input.extend_from_slice(&x.to_be_bytes());
        }
        let h = keccak256(&input);
        let slot = contract.slots[(h[0] as usize) % contract.slots.len()];
        let value = format!("0x{}", hex(h.as_slice()));
        text(
            spec_seed,
            generation,
            &format!(", writer {k} of {}, burst", self.writers.len()),
            self.writers[k].account,
            &format!("burst{k}"),
            &[(contract.address.as_str(), slot, value)],
        )
    }

    /// Contracts, writers and assignment, as recorded in events.jsonl.
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "contracts": self.contracts.len(),
            "senders": self.writers.len(),
            "addresses": self.contracts.iter().map(|c| &c.address).collect::<Vec<_>>(),
            "writers": self.writers.iter().map(|w| serde_json::json!({
                "account": w.account,
                "contracts": w.contracts,
            })).collect::<Vec<_>>(),
        })
    }

    /// txgen spec for writer `k`'s load generation `generation` with spec
    /// seed `spec_seed` (the run seed unless the generation's inputs say
    /// otherwise): `steps` writes over its contracts, in one sequence from
    /// one sender. With one contract and one writer, exactly [`spec`].
    ///
    /// # Panics
    /// Panics when `k` is outside `0..self.writers().len()`.
    pub fn writer_spec(&self, k: usize, spec_seed: u64, generation: u64, steps: usize) -> String {
        let targets: Vec<(&str, &[u64])> = self.writers[k]
            .contracts
            .iter()
            .map(|&c| {
                let c = &self.contracts[c];
                (c.address.as_str(), c.slots.as_slice())
            })
            .collect();
        let writer =
            (self.writers.len() > 1).then(|| (k, self.writers.len(), self.writers[k].account));
        render(
            spec_seed,
            generation,
            writer,
            sub_seed(spec_seed, WRITER_SALT, k),
            &targets,
            steps,
        )
    }
}

/// One writer's spec. `writer` is `(index, writers, dev account)` with
/// several writers; `None` is the single-writer form (dev account 0,
/// sequence `writes`). `knob_seed` keys the operation mix and write stream.
fn render(
    seed: u64,
    generation: u64,
    writer: Option<(usize, usize, u32)>,
    knob_seed: u64,
    targets: &[(&str, &[u64])],
    steps: usize,
) -> String {
    let mut knob_rng = StdRng::seed_from_u64(knob_seed ^ OPS_SALT);
    let knobs = Knobs {
        values: [
            knob_rng.random_range(1..=4),
            knob_rng.random_range(0..=4),
            knob_rng.random_range(0..=4),
            knob_rng.random_range(0..=4),
        ],
        hold: [0.0, 0.05, 0.2][knob_rng.random_range(0..3)],
        max_hold: [4, 16, 64][knob_rng.random_range(0..3)],
    };
    let mut rng = StdRng::seed_from_u64(
        knob_seed ^ OPS_SALT ^ generation.wrapping_mul(0x9e37_79b9_7f4a_7c15),
    );
    // (target, slot, value); no-op holds write zero to the first target.
    let mut writes: Vec<(usize, u64, String)> = Vec::with_capacity(steps);
    while writes.len() < steps {
        if rng.random_bool(knobs.hold) {
            let n = rng
                .random_range(1..=knobs.max_hold)
                .min(steps - writes.len());
            writes.extend(std::iter::repeat_n((0, NOOP_SLOT, "0".to_string()), n));
        } else {
            // One target draws nothing here: the single-contract stream.
            let t = if targets.len() > 1 {
                rng.random_range(0..targets.len())
            } else {
                0
            };
            let slots = targets[t].1;
            let slot = slots[rng.random_range(0..slots.len())];
            writes.push((t, slot, value(&mut rng, &knobs)));
        }
    }
    let (note, account, sequence) = match writer {
        None => (String::new(), 0, "writes".to_string()),
        Some((k, n, account)) => (
            format!(", writer {k} of {n}"),
            account,
            format!("writes{k}"),
        ),
    };
    let writes: Vec<(&str, u64, String)> = writes
        .into_iter()
        .map(|(t, slot, value)| (targets[t].0, slot, value))
        .collect();
    text(seed, generation, &note, account, &sequence, &writes)
}

/// A spec of `writes` `(to, slot, value)` in one sequence `sequence` from
/// dev account `account`.
fn text(
    seed: u64,
    generation: u64,
    note: &str,
    account: u32,
    sequence: &str,
    writes: &[(&str, u64, String)],
) -> String {
    let mut out = format!(
        "# Generated by tempo-dst (trie_gen) for seed {seed}, load generation {generation}{note}.\n\
         chain_id: 1337\n\
         accounts:\n  trie:\n    mnemonic: \"test test test test test test test test test test test junk\"\n    range: [{account}, {}]\n\
         artifacts:\n  RawStorage:\n    abi: raw-storage.json\n    bytecode: raw-storage.json\n\
         templates:\n  set_slot:\n    type: tempo\n    from: {{ pool: trie, select: {{ index: 0 }} }}\n    gas_limit: 1000000\n\
         \x20   max_fee_per_gas: 100000000000\n    max_priority_fee_per_gas: 1000000000\n\
         \x20   fee_token: \"0x20c0000000000000000000000000000000000000\"\n\
         \x20   call:\n      abi: RawStorage\n      function: set\n      args: []\n\
         sequences:\n  {sequence}:\n    steps:\n",
        account + 1
    );
    for (i, (to, slot, value)) in writes.iter().enumerate() {
        out.push_str(&format!(
            "      - {{ name: w{i}, template: set_slot, with: {{ call: {{ to: \"{to}\", args: [{slot}, \"{value}\"] }} }} }}\n"
        ));
    }
    out.push_str(&format!(
        "mix:\n  - {{ sequence: {sequence}, weight: 1 }}\n"
    ));
    out
}

/// The single-contract spec as it was before [`plan`], to pin [`spec`].
#[cfg(test)]
fn legacy_spec(seed: u64, generation: u64, slots: &[u64], steps: usize) -> String {
    let mut knob_rng = StdRng::seed_from_u64(seed ^ OPS_SALT);
    let knobs = Knobs {
        values: [
            knob_rng.random_range(1..=4),
            knob_rng.random_range(0..=4),
            knob_rng.random_range(0..=4),
            knob_rng.random_range(0..=4),
        ],
        hold: [0.0, 0.05, 0.2][knob_rng.random_range(0..3)],
        max_hold: [4, 16, 64][knob_rng.random_range(0..3)],
    };
    let mut rng =
        StdRng::seed_from_u64(seed ^ OPS_SALT ^ generation.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let mut writes: Vec<(u64, String)> = Vec::with_capacity(steps);
    while writes.len() < steps {
        if rng.random_bool(knobs.hold) {
            let n = rng
                .random_range(1..=knobs.max_hold)
                .min(steps - writes.len());
            writes.extend(std::iter::repeat_n((NOOP_SLOT, "0".to_string()), n));
        } else {
            let slot = slots[rng.random_range(0..slots.len())];
            writes.push((slot, value(&mut rng, &knobs)));
        }
    }
    let mut out = format!(
        "# Generated by tempo-dst (trie_gen) for seed {seed}, load generation {generation}.\n\
         chain_id: 1337\n\
         accounts:\n  trie:\n    mnemonic: \"test test test test test test test test test test test junk\"\n    range: [0, 1]\n\
         artifacts:\n  RawStorage:\n    abi: raw-storage.json\n    bytecode: raw-storage.json\n\
         templates:\n  set_slot:\n    type: tempo\n    from: {{ pool: trie, select: {{ index: 0 }} }}\n    gas_limit: 1000000\n\
         \x20   max_fee_per_gas: 100000000000\n    max_priority_fee_per_gas: 1000000000\n\
         \x20   fee_token: \"0x20c0000000000000000000000000000000000000\"\n\
         \x20   call:\n      abi: RawStorage\n      function: set\n      args: []\n\
         sequences:\n  writes:\n    steps:\n"
    );
    for (i, (slot, value)) in writes.iter().enumerate() {
        out.push_str(&format!(
            "      - {{ name: w{i}, template: set_slot, with: {{ call: {{ to: \"{CONTRACT}\", args: [{slot}, \"{value}\"] }} }} }}\n"
        ));
    }
    out.push_str("mix:\n  - { sequence: writes, weight: 1 }\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_nibbles_counts_half_bytes() {
        let a = [0x12u8; 32];
        let mut b = a;
        b[1] = 0x13;
        assert_eq!(shared_nibbles(&a, &b), 3);
        b[1] = 0x22;
        assert_eq!(shared_nibbles(&a, &b), 2);
        assert_eq!(shared_nibbles(&a, &a), 64);
    }

    #[test]
    fn slots_are_deterministic_and_share_prefixes() {
        for seed in 0..8 {
            let s = slots(seed);
            assert_eq!(s, slots(seed));
            assert!(s.len() >= 2 && s.len() <= 16, "{s:?}");
            // Some pair shares at least one nibble: there is a branch below
            // the root.
            let paths: Vec<_> = s.iter().map(|x| path(*x)).collect();
            let deepest = (0..s.len())
                .flat_map(|i| (i + 1..s.len()).map(move |j| (i, j)))
                .map(|(i, j)| shared_nibbles(&paths[i], &paths[j]))
                .max()
                .unwrap();
            assert!(deepest >= 1, "seed {seed}: {s:?}");
        }
        assert_ne!(slots(1), slots(2));
    }

    #[test]
    fn some_seeds_get_inline_sized_pairs() {
        let deep = (0..16)
            .filter(|seed| {
                let p: Vec<_> = slots(*seed).iter().map(|x| path(*x)).collect();
                (0..p.len()).any(|i| (i + 1..p.len()).any(|j| shared_nibbles(&p[i], &p[j]) >= 7))
            })
            .count();
        assert!(deep > 0);
    }

    #[test]
    fn spec_is_deterministic_per_generation() {
        let s = slots(3);
        let a = spec(3, 0, &s, 50);
        assert_eq!(a, spec(3, 0, &s, 50));
        assert_ne!(a, spec(3, 1, &s, 50));
        assert_eq!(a.matches("template: set_slot").count(), 50);
        assert!(a.contains("sequences:\n  writes:"));
    }

    #[test]
    fn spec_is_unchanged_from_the_single_contract_load() {
        for seed in [0, 3, 17] {
            let s = slots(seed);
            for generation in [0, 2] {
                let want = legacy_spec(seed, generation, &s, 300);
                assert_eq!(spec(seed, generation, &s, 300), want);
                // One contract, one writer: the same spec through the plan.
                let p = plan(seed, 1, 1);
                assert_eq!(p.contracts[0].slots, s);
                assert_eq!(p.writer_spec(0, seed, generation, 300), want);
            }
        }
    }

    #[test]
    fn pool_addresses_are_the_deploys_create_addresses() {
        // `cast compute-address <writer> --nonce <n>`.
        let want = [
            (0, "0x5FbDB2315678afecb367f032d93F642f64180aa3"),
            (1, "0xfbfbfDdd6e35dA57b7B0F9a2C10E34Be70B3A4E9"),
            (7, "0xd0F350b13465B5251bb03E4bbf9Fa1DbC4a378F3"),
            (8, "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"),
            (9, "0x10Aeafac83d48E2f9ac4bAAf94311c45fACe1404"),
            (15, "0xa27bC320252d51EEAA24BCCF6cc003979E485860"),
        ];
        for (c, addr) in want {
            assert_eq!(pool_address(c).to_checksum(None), addr, "contract {c}");
        }
        assert_eq!(pool_addresses()[0], CONTRACT);
        let distinct: std::collections::BTreeSet<_> = pool_addresses().into_iter().collect();
        assert_eq!(distinct.len(), POOL);
        // deploy-pool.yaml deploys exactly these, from these writers.
        let yaml = include_str!("../../../contrib/bedrock-dst/trie/deploy-pool.yaml");
        for c in 0..POOL {
            assert!(yaml.contains(&format!("{{ id: c{c},")), "contract {c}");
        }
        assert!(yaml.contains("range: [10, 17]"));
        assert_eq!(&WRITERS[1..], &[10, 11, 12, 13, 14, 15, 16]);
    }

    #[test]
    fn draw_is_a_stable_weighted_per_seed_choice() {
        let draws: Vec<_> = (0..256).map(draw).collect();
        assert_eq!(draws, (0..256).map(draw).collect::<Vec<_>>());
        // Pinned: a change to the draw changes what auto seeds mean.
        assert_eq!(
            draws[..8],
            [
                (1, 1),
                (4, 4),
                (2, 2),
                (15, 5),
                (1, 1),
                (1, 1),
                (7, 3),
                (5, 2)
            ]
        );
        for &(n, s) in &draws {
            assert!((1..=POOL).contains(&n));
            if n == 1 {
                assert_eq!(s, 1);
            } else {
                assert!((2..=n.min(WRITERS.len())).contains(&s), "{n} {s}");
            }
        }
        assert!(draws.iter().filter(|d| d.0 <= 4).count() > 128);
        for n in [1, 2, 8, 16] {
            assert!(draws.iter().any(|d| d.0 == n), "{n} never drawn");
        }
        assert!(draws.iter().any(|d| d.1 == WRITERS.len()));
    }

    #[test]
    fn plan_assigns_contracts_and_writers_deterministically() {
        for seed in 0..12 {
            for (n, s) in [(1, 1), (2, 2), (5, 3), (16, 8), (9, 1)] {
                let p = plan(seed, n, s);
                assert_eq!(p, plan(seed, n, s));
                assert_eq!(p.contracts.len(), n);
                assert_eq!(p.writers.len(), s);
                let accounts: Vec<u32> = p.writers.iter().map(|w| w.account).collect();
                assert_eq!(accounts, WRITERS[..s]);
                for (c, contract) in p.contracts.iter().enumerate() {
                    assert_eq!(
                        contract.address.to_lowercase(),
                        pool_address(c).to_checksum(None).to_lowercase()
                    );
                    // Every contract is written; its primary writer is c mod S.
                    assert!(p.writers[c % s].contracts.contains(&c));
                }
                for w in &p.writers {
                    assert!(!w.contracts.is_empty());
                    assert!(w.contracts.windows(2).all(|x| x[0] < x[1]));
                }
            }
        }
        // Contracts get their own shapes; contract 0 keeps the run's.
        let p = plan(4, 4, 2);
        assert_eq!(p.contracts[0].slots, slots(4));
        assert_ne!(p.contracts[1].slots, p.contracts[0].slots);
        assert_ne!(p.contracts[2].slots, p.contracts[1].slots);
        // Some contract somewhere is shared by two writers.
        let shared = (0..16).any(|seed| {
            let p = plan(seed, 8, 4);
            (0..8).any(|c| {
                p.writers
                    .iter()
                    .filter(|w| w.contracts.contains(&c))
                    .count()
                    > 1
            })
        });
        assert!(shared);
    }

    #[test]
    fn bursts_write_a_fresh_word_to_each_writers_own_contract() {
        let p = plan(6, 5, 3);
        let mut contracts = std::collections::BTreeSet::new();
        for (k, w) in p.writers.iter().enumerate() {
            let b = p.burst_spec(k, 6, 2);
            assert_eq!(b, p.burst_spec(k, 6, 2));
            assert_ne!(b, p.burst_spec(k, 6, 3), "fresh per generation");
            assert_eq!(b.matches("template: set_slot").count(), 1);
            assert!(b.contains(&format!("range: [{}, {}]", w.account, w.account + 1)));
            assert!(b.contains(&format!("sequences:\n  burst{k}:")));
            let line = b.lines().find(|l| l.contains("to: \"")).unwrap();
            let to = line
                .split("to: \"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            assert_eq!(to, p.contracts[k].address);
            assert!(w.contracts.contains(&k));
            // A full 256-bit value, never zero (a no-op on an empty slot).
            let value = line
                .split(", \"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            assert_eq!(value.len(), 66, "{value}");
            let slot: u64 = line
                .split("args: [")
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            assert!(p.contracts[k].slots.contains(&slot));
            contracts.insert(to.to_string());
        }
        assert_eq!(contracts.len(), 3, "distinct contracts");
    }

    #[test]
    fn writer_specs_send_from_their_own_account_to_their_contracts() {
        let p = plan(6, 5, 3);
        let mut seen = std::collections::BTreeSet::new();
        for (k, w) in p.writers.iter().enumerate() {
            let s = p.writer_spec(k, 6, 0, 200);
            assert_eq!(s, p.writer_spec(k, 6, 0, 200));
            assert_ne!(s, p.writer_spec(k, 6, 1, 200));
            assert!(s.contains(&format!("range: [{}, {}]", w.account, w.account + 1)));
            assert!(s.contains(&format!("sequences:\n  writes{k}:")));
            assert!(s.contains(&format!("sequence: writes{k},")));
            assert_eq!(s.matches("template: set_slot").count(), 200);
            for line in s.lines().filter(|l| l.contains("to: \"")) {
                let to = line
                    .split("to: \"")
                    .nth(1)
                    .unwrap()
                    .split('"')
                    .next()
                    .unwrap();
                let c = p.contracts.iter().position(|c| c.address == to).unwrap();
                assert!(w.contracts.contains(&c), "writer {k} writes {to}");
                seen.insert(c);
            }
        }
        // Between them the writers reach every contract.
        assert_eq!(seen.len(), 5);
    }
}
