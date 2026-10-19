// SPDX-License-Identifier: GPL-2.0

//! E11 durable history (`storage_faults=true`): what the node served about a
//! block before a crash, it serves the same after the cold reopen, if it kept
//! the block.
//!
//! While the node runs, every new canonical block is recorded outside the node
//! (here): its hash, its transaction hashes, and every few blocks a
//! historical account read at it (a sender's nonce and pathUSD balance). At
//! each kill or machine crash the records are frozen; after the restart a
//! sample of them (the newest blocks before the crash, where the volatile
//! suffix lives, plus a stride over older ones) is re-checked:
//!
//! - a block still canonical with its recorded hash must have the same body
//!   (`E11/block-body-changed`), every transaction must resolve to it by hash
//!   (`eth_getTransactionByHash`: `E11/tx-lookup-missing`,
//!   `E11/tx-lookup-wrong-block`) with a receipt in it
//!   (`eth_getTransactionReceipt`: `E11/receipt-missing`,
//!   `E11/receipt-wrong-block`), and the historical reads must equal the
//!   recorded ones (`eth_getTransactionCount`, `eth_call` at the block hash,
//!   and `eth_getProof` verified against the header state root:
//!   `E11/history-account-mismatch`, `E11/history-storage-mismatch`,
//!   `E11/history-proof-invalid`, `E11/history-proof-mismatch`,
//!   `E11/history-read-error`). A block present with holes in its history is
//!   exactly what losing one store's un-synced writes while another persisted
//!   further produces (reth#23603: RocksDB indices behind MDBX);
//! - a block that was rebuilt (the un-synced suffix of unfinalized blocks was
//!   lost: allowed; E3 covers finalized ones) must not leave its transactions
//!   resolving to a block that is no longer canonical (`E11/tx-lookup-stale`).
//!
//! E4 then re-executes the whole chain from the datadir at the end of the run.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, U256};
use serde_json::{json, Value};

use crate::{
    common,
    trie_ref::{self, AccountProof},
    verdict::{finding, Verdict},
};

/// pathUSD, the fee token every load pays in.
pub const PATH_USD: Address =
    alloy_primitives::address!("20c0000000000000000000000000000000000000");
/// Account reads are recorded on every this many blocks with transactions.
const READ_EVERY: u64 = 4;
/// Blocks recorded per tick (the node makes ~5 per second).
const RECORD_PER_TICK: u64 = 25;
/// Re-checked after a crash: the newest blocks, and up to this many older.
const SWEEP_NEWEST: usize = 48;
const SWEEP_OLDER: usize = 32;
/// Swept blocks per tick.
const SWEEP_PER_TICK: usize = 8;
/// Transactions of a rebuilt block checked for stale lookups.
const REBUILT_TXS: usize = 16;

/// A canonical block body and account identities used for durable-history checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTxs {
    pub hash: B256,
    pub state_root: B256,
    pub txs: Vec<B256>,
    pub senders: Vec<Address>,
}

/// `(block hash, block number)` a transaction or receipt lookup resolves to.
pub type Located = Option<(B256, u64)>;

/// Node queries for E11; `Err` while the node is unreachable.
pub trait DurableChain {
    fn block_txs(&mut self, number: u64) -> Result<Option<BlockTxs>, String>;
    /// `eth_getTransactionByHash` for each hash, in one batch; inner `Err`
    /// is a per-call RPC error.
    fn tx_lookups(&mut self, txs: &[B256]) -> Result<Vec<Result<Located, String>>, String>;
    /// `eth_getTransactionReceipt` for each hash, in one batch.
    fn receipt_lookups(&mut self, txs: &[B256]) -> Result<Vec<Result<Located, String>>, String>;
    fn nonce_at(&mut self, account: Address, number: u64) -> Result<u64, String>;
    /// pathUSD `balanceOf(account)` at block `hash`.
    fn balance_at(&mut self, account: Address, hash: B256) -> Result<U256, String>;
    fn account_proof(&mut self, account: Address, number: u64) -> Result<AccountProof, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Reads {
    account: Address,
    nonce: u64,
    balance: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    hash: B256,
    txs: Vec<B256>,
    reads: Option<Reads>,
}

#[derive(Debug)]
struct Sweep {
    /// Frozen at the kill: `(number, record)`, ascending.
    blocks: Vec<(u64, Record)>,
    next: usize,
    /// Head when the kill happened.
    head_at_kill: u64,
}

/// Records canonical history and checks retained blocks after node restarts.
#[derive(Debug, Default)]
pub struct DurableOracle {
    records: BTreeMap<u64, Record>,
    /// Highest block recorded from the current canonical chain.
    recorded: u64,
    sweep: Option<Sweep>,
    down: bool,
    seen_checked: bool,
    seen_rebuilt: bool,
}

/// The newest `SWEEP_NEWEST` blocks and a stride of `SWEEP_OLDER` older ones.
fn sample(records: &BTreeMap<u64, Record>, upto: u64) -> Vec<(u64, Record)> {
    let all: Vec<(u64, Record)> = records
        .range(..=upto)
        .map(|(n, r)| (*n, r.clone()))
        .collect();
    let split = all.len().saturating_sub(SWEEP_NEWEST);
    let (older, newest) = all.split_at(split);
    let stride = older.len().div_ceil(SWEEP_OLDER).max(1);
    older
        .iter()
        .step_by(stride)
        .chain(newest)
        .cloned()
        .collect()
}

fn always(signature: &str, detail: String) -> Verdict {
    Verdict::Always(false, finding(signature, detail))
}

impl DurableOracle {
    /// The node went down (kill, or a machine crash): freeze what it served.
    pub fn on_kill(&mut self) {
        self.down = true;
        if self.recorded > 0 {
            self.sweep = Some(Sweep {
                blocks: sample(&self.records, self.recorded),
                next: 0,
                head_at_kill: self.recorded,
            });
        }
    }

    /// Resumes checking after the node restarts; the frozen crash sample remains pending.
    pub fn on_restart(&mut self) {
        self.down = false;
    }

    /// Checks a recovery sample and records new history; emits failures and coverage.
    pub fn tick(&mut self, chain: &mut impl DurableChain, head: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        if self.down {
            return out;
        }
        self.step_sweep(chain, head, &mut out);
        self.record(chain, head);
        out
    }

    fn step_sweep(&mut self, chain: &mut impl DurableChain, head: u64, out: &mut Vec<Verdict>) {
        let Some(sweep) = self.sweep.as_mut() else {
            return;
        };
        let mut done = 0;
        while done < SWEEP_PER_TICK {
            let Some((n, rec)) = sweep.blocks.get(sweep.next).cloned() else {
                out.push(Verdict::Sometimes(
                    true,
                    finding(
                        "S/durable-sweep-complete",
                        format!(
                            "{} blocks up to {} re-checked",
                            sweep.blocks.len(),
                            sweep.head_at_kill
                        ),
                    ),
                ));
                self.sweep = None;
                return;
            };
            if n > head {
                // Not rebuilt yet; wait for the head.
                return;
            }
            let Ok(Some(block)) = chain.block_txs(n) else {
                return;
            };
            let verdicts = if block.hash == rec.hash {
                check_present(chain, n, &rec, &block)
            } else {
                check_rebuilt(chain, n, &rec)
            };
            let Some(verdicts) = verdicts else {
                // The node went away mid-check: retry this block.
                return;
            };
            if block.hash == rec.hash {
                let clean = verdicts
                    .iter()
                    .all(|v| !matches!(v, Verdict::Always(false, _)));
                if clean && !rec.txs.is_empty() && !self.seen_checked {
                    self.seen_checked = true;
                    out.push(Verdict::Sometimes(
                        true,
                        finding(
                            "S/durable-history-checked",
                            format!("block {n}: {} txs survived the crash intact", rec.txs.len()),
                        ),
                    ));
                }
            } else if !self.seen_rebuilt {
                self.seen_rebuilt = true;
                out.push(Verdict::Sometimes(
                    true,
                    finding(
                        "S/durable-block-rebuilt",
                        format!("block {n}: {} -> {}", rec.hash, block.hash),
                    ),
                ));
            }
            out.extend(verdicts);
            sweep.next += 1;
            done += 1;
        }
    }

    fn record(&mut self, chain: &mut impl DurableChain, head: u64) {
        if head < self.recorded {
            // Rewound by crash recovery: re-record the rebuilt blocks.
            self.recorded = head;
            self.records.split_off(&(head + 1));
        }
        let last = head.min(self.recorded + RECORD_PER_TICK);
        for n in self.recorded + 1..=last {
            let Ok(Some(block)) = chain.block_txs(n) else {
                return;
            };
            let reads = match block.senders.first() {
                Some(&account) if n % READ_EVERY == 0 => {
                    let (Ok(nonce), Ok(balance)) = (
                        chain.nonce_at(account, n),
                        chain.balance_at(account, block.hash),
                    ) else {
                        return;
                    };
                    Some(Reads {
                        account,
                        nonce,
                        balance,
                    })
                }
                _ => None,
            };
            self.records.insert(
                n,
                Record {
                    hash: block.hash,
                    txs: block.txs,
                    reads,
                },
            );
            self.recorded = n;
        }
    }
}

/// E11 for a block that survived with its hash; `None` if the node went away.
fn check_present(
    chain: &mut impl DurableChain,
    n: u64,
    rec: &Record,
    block: &BlockTxs,
) -> Option<Vec<Verdict>> {
    let mut out = Vec::new();
    if block.txs != rec.txs {
        out.push(always(
            "E11/block-body-changed",
            format!(
                "block {n} {}: {} txs recorded, {} served",
                rec.hash,
                rec.txs.len(),
                block.txs.len()
            ),
        ));
    }
    for (rpc, lookups, missing, wrong) in [
        (
            "eth_getTransactionByHash",
            chain.tx_lookups(&rec.txs).ok()?,
            "E11/tx-lookup-missing",
            "E11/tx-lookup-wrong-block",
        ),
        (
            "eth_getTransactionReceipt",
            chain.receipt_lookups(&rec.txs).ok()?,
            "E11/receipt-missing",
            "E11/receipt-wrong-block",
        ),
    ] {
        let mut miss = Vec::new();
        let mut bad = Vec::new();
        let mut errors = Vec::new();
        for (tx, l) in rec.txs.iter().zip(lookups) {
            match l {
                Ok(None) => miss.push(*tx),
                Ok(Some((h, num))) if h != rec.hash || num != n => bad.push((*tx, h, num)),
                Ok(Some(_)) => {}
                Err(e) => errors.push((*tx, e)),
            }
        }
        if let Some(tx) = miss.first() {
            out.push(always(
                missing,
                format!(
                    "block {n} {}: {rpc} returns null for {} of {} txs (first {tx})",
                    rec.hash,
                    miss.len(),
                    rec.txs.len()
                ),
            ));
        }
        if let Some((tx, h, num)) = bad.first() {
            out.push(always(
                wrong,
                format!(
                    "block {n} {}: {rpc} puts {} txs elsewhere (first {tx} in block {num} {h})",
                    rec.hash,
                    bad.len()
                ),
            ));
        }
        if let Some((tx, e)) = errors.first() {
            out.push(always(
                "E11/history-read-error",
                format!("block {n}: {rpc}({tx}): {e}"),
            ));
        }
    }
    if let Some(r) = &rec.reads {
        match chain.nonce_at(r.account, n) {
            Ok(nonce) if nonce != r.nonce => out.push(always(
                "E11/history-account-mismatch",
                format!(
                    "block {n}: nonce of {} was {}, now {nonce}",
                    r.account, r.nonce
                ),
            )),
            Ok(_) => {}
            Err(e) => out.push(always(
                "E11/history-read-error",
                format!("block {n}: eth_getTransactionCount({}): {e}", r.account),
            )),
        }
        match chain.balance_at(r.account, rec.hash) {
            Ok(b) if b != r.balance => out.push(always(
                "E11/history-storage-mismatch",
                format!(
                    "block {n}: pathUSD balance of {} was {}, now {b}",
                    r.account, r.balance
                ),
            )),
            Ok(_) => {}
            Err(e) => out.push(always(
                "E11/history-read-error",
                format!("block {n}: balanceOf({}): {e}", r.account),
            )),
        }
        // Outside --rpc.eth-proof-window the node refuses: not a finding.
        if let Ok(p) = chain.account_proof(r.account, n) {
            if let Err(e) = trie_ref::verify(&p, block.state_root) {
                out.push(always(
                    "E11/history-proof-invalid",
                    format!("block {n}: proof of {}: {e:?}", r.account),
                ));
            } else if p.nonce.to::<u64>() != r.nonce {
                out.push(always(
                    "E11/history-proof-mismatch",
                    format!(
                        "block {n}: proven nonce of {} is {}, recorded {}",
                        r.account, p.nonce, r.nonce
                    ),
                ));
            }
        }
    }
    Some(out)
}

/// E11 for a block that was rebuilt: its old transactions resolve nowhere,
/// or to a canonical block.
fn check_rebuilt(chain: &mut impl DurableChain, n: u64, rec: &Record) -> Option<Vec<Verdict>> {
    let txs = &rec.txs[..rec.txs.len().min(REBUILT_TXS)];
    let mut out = Vec::new();
    for (tx, l) in txs.iter().zip(chain.tx_lookups(txs).ok()?) {
        match l {
            Ok(Some((h, num))) => {
                let canonical = chain.block_txs(num).ok()?.map(|b| b.hash);
                if canonical != Some(h) {
                    out.push(always(
                    "E11/tx-lookup-stale",
                    format!(
                        "tx {tx} of rebuilt block {n} ({}) resolves to block {num} {h}, canonical {canonical:?}",
                        rec.hash
                    ),
                ));
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => out.push(always(
                "E11/history-read-error",
                format!("tx {tx} of rebuilt block {n}: {e}"),
            )),
        }
    }
    Some(out)
}

/// The node over RPC.
pub struct RpcDurable;

fn located(v: &Value) -> Result<Located, String> {
    if v.is_null() {
        return Ok(None);
    }
    let hash: B256 = serde_json::from_value(v["blockHash"].clone())
        .map_err(|e| format!("bad blockHash: {e}: {v}"))?;
    let number: alloy_primitives::U64 = serde_json::from_value(v["blockNumber"].clone())
        .map_err(|e| format!("bad blockNumber: {e}: {v}"))?;
    Ok(Some((hash, number.to())))
}

fn lookups(method: &str, txs: &[B256]) -> Result<Vec<Result<Located, String>>, String> {
    let calls: Vec<(&str, Value)> = txs.iter().map(|t| (method, json!([t]))).collect();
    Ok(common::rpc_batch(&calls)?
        .into_iter()
        .map(|r| r.and_then(|v| located(&v)))
        .collect())
}

impl DurableChain for RpcDurable {
    fn block_txs(&mut self, number: u64) -> Result<Option<BlockTxs>, String> {
        let b = common::rpc(
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), true]),
        )?;
        if b.is_null() {
            return Ok(None);
        }
        let field = |v: &Value, name: &str| -> Result<B256, String> {
            serde_json::from_value(v[name].clone()).map_err(|e| format!("bad {name}: {e}"))
        };
        let txs = b["transactions"].as_array().cloned().unwrap_or_default();
        Ok(Some(BlockTxs {
            hash: field(&b, "hash")?,
            state_root: field(&b, "stateRoot")?,
            txs: txs
                .iter()
                .map(|t| field(t, "hash"))
                .collect::<Result<_, _>>()?,
            senders: txs
                .iter()
                .filter_map(|t| serde_json::from_value(t["from"].clone()).ok())
                .collect(),
        }))
    }
    fn tx_lookups(&mut self, txs: &[B256]) -> Result<Vec<Result<Located, String>>, String> {
        lookups("eth_getTransactionByHash", txs)
    }
    fn receipt_lookups(&mut self, txs: &[B256]) -> Result<Vec<Result<Located, String>>, String> {
        lookups("eth_getTransactionReceipt", txs)
    }
    fn nonce_at(&mut self, account: Address, number: u64) -> Result<u64, String> {
        let v = common::rpc(
            "eth_getTransactionCount",
            json!([account, format!("0x{number:x}")]),
        )?;
        serde_json::from_value::<alloy_primitives::U64>(v.clone())
            .map(|n| n.to())
            .map_err(|e| format!("bad nonce: {e}: {v}"))
    }
    fn balance_at(&mut self, account: Address, hash: B256) -> Result<U256, String> {
        // balanceOf(address)
        let mut data = vec![0x70, 0xa0, 0x82, 0x31];
        data.extend_from_slice(account.into_word().as_slice());
        let out = common::calls_at(&[(PATH_USD, data)], hash)?;
        (out[0].len() == 32)
            .then(|| U256::from_be_slice(&out[0]))
            .ok_or_else(|| format!("balanceOf returned {} bytes", out[0].len()))
    }
    fn account_proof(&mut self, account: Address, number: u64) -> Result<AccountProof, String> {
        common::proof(&account.to_string(), &[], number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A node whose canonical chain and indices the tests edit directly.
    #[derive(Default)]
    struct Fake {
        blocks: BTreeMap<u64, BlockTxs>,
        tx_index: HashMap<B256, (B256, u64)>,
        receipts: HashMap<B256, (B256, u64)>,
        nonces: HashMap<u64, u64>,
        down: bool,
    }

    fn h(x: u64) -> B256 {
        B256::from(U256::from(x))
    }

    const SENDER: Address = Address::repeat_byte(0x11);

    impl Fake {
        fn head(&self) -> u64 {
            *self.blocks.keys().last().unwrap_or(&0)
        }
        /// Appends block `n` (salt changes the hash) with two txs, indexed.
        fn push(&mut self, n: u64, salt: u64) {
            let hash = h(n * 1000 + salt);
            let txs = vec![
                h(n * 1_000_000 + salt * 10 + 1),
                h(n * 1_000_000 + salt * 10 + 2),
            ];
            for t in &txs {
                self.tx_index.insert(*t, (hash, n));
                self.receipts.insert(*t, (hash, n));
            }
            self.nonces.insert(n, n * 2);
            self.blocks.insert(
                n,
                BlockTxs {
                    hash,
                    state_root: B256::ZERO,
                    txs,
                    senders: vec![SENDER],
                },
            );
        }
        /// An honest unwind: blocks past `keep` and their indices go.
        fn truncate(&mut self, keep: u64) {
            for (_, b) in self.blocks.split_off(&(keep + 1)) {
                for t in b.txs {
                    self.tx_index.remove(&t);
                    self.receipts.remove(&t);
                }
            }
        }
    }

    impl DurableChain for Fake {
        fn block_txs(&mut self, n: u64) -> Result<Option<BlockTxs>, String> {
            if self.down {
                return Err("down".into());
            }
            Ok(self.blocks.get(&n).cloned())
        }
        fn tx_lookups(&mut self, txs: &[B256]) -> Result<Vec<Result<Located, String>>, String> {
            Ok(txs
                .iter()
                .map(|t| Ok(self.tx_index.get(t).copied()))
                .collect())
        }
        fn receipt_lookups(
            &mut self,
            txs: &[B256],
        ) -> Result<Vec<Result<Located, String>>, String> {
            Ok(txs
                .iter()
                .map(|t| Ok(self.receipts.get(t).copied()))
                .collect())
        }
        fn nonce_at(&mut self, _: Address, n: u64) -> Result<u64, String> {
            self.nonces
                .get(&n)
                .copied()
                .ok_or_else(|| "no state".into())
        }
        fn balance_at(&mut self, _: Address, _: B256) -> Result<U256, String> {
            Ok(U256::from(7))
        }
        fn account_proof(&mut self, _: Address, _: u64) -> Result<AccountProof, String> {
            Err("outside proof window".into())
        }
    }

    fn sigs(v: &[Verdict]) -> Vec<(bool, String)> {
        v.iter()
            .map(|v| match v {
                Verdict::Always(ok, f) => (*ok, f.signature.clone()),
                Verdict::Sometimes(ok, f) => (*ok, format!("~{}", f.signature)),
            })
            .collect()
    }

    fn run_until_swept(o: &mut DurableOracle, c: &mut Fake) -> Vec<(bool, String)> {
        let mut all = Vec::new();
        for _ in 0..50 {
            let head = c.head();
            all.extend(sigs(&o.tick(c, head)));
        }
        all
    }

    /// 40 blocks, recorded; then a crash that loses blocks 31..=40, which
    /// the node rebuilds with different hashes.
    fn crashed_chain() -> (DurableOracle, Fake) {
        let mut c = Fake::default();
        let mut o = DurableOracle::default();
        for n in 1..=40 {
            c.push(n, 0);
        }
        for _ in 0..3 {
            o.tick(&mut c, 40);
        }
        o.on_kill();
        c.truncate(30);
        for n in 31..=40 {
            c.push(n, 1);
        }
        o.on_restart();
        (o, c)
    }

    #[test]
    fn honest_recovery_passes_with_coverage() {
        let (mut o, mut c) = crashed_chain();
        let all = run_until_swept(&mut o, &mut c);
        assert!(all.iter().all(|(ok, _)| *ok), "{all:?}");
        for s in [
            "~S/durable-history-checked",
            "~S/durable-block-rebuilt",
            "~S/durable-sweep-complete",
        ] {
            assert!(all.contains(&(true, s.into())), "{s}: {all:?}");
        }
    }

    #[test]
    fn lost_tx_index_entries_in_a_kept_block_are_holes() {
        let (mut o, mut c) = crashed_chain();
        // RocksDB lost its newest writes while MDBX kept blocks 25..=30.
        for n in 25..=30 {
            for t in c.blocks[&n].txs.clone() {
                c.tx_index.remove(&t);
            }
        }
        let all = run_until_swept(&mut o, &mut c);
        assert!(
            all.contains(&(false, "E11/tx-lookup-missing".into())),
            "{all:?}"
        );
        assert!(!all.iter().any(|(_, s)| s == "E11/receipt-missing"));
    }

    #[test]
    fn changed_history_reads_are_reported() {
        let (mut o, mut c) = crashed_chain();
        c.nonces.insert(28, 999);
        let all = run_until_swept(&mut o, &mut c);
        assert!(
            all.contains(&(false, "E11/history-account-mismatch".into())),
            "{all:?}"
        );
    }

    #[test]
    fn stale_lookups_of_rebuilt_blocks_are_reported() {
        let (mut o, mut c) = crashed_chain();
        // A lost block's tx still resolves to its old, replaced hash.
        let old_tx = h(35 * 1_000_000 + 1);
        c.tx_index.insert(old_tx, (h(35 * 1000), 35));
        let all = run_until_swept(&mut o, &mut c);
        assert!(
            all.contains(&(false, "E11/tx-lookup-stale".into())),
            "{all:?}"
        );
    }

    #[test]
    fn sweep_waits_for_the_head_and_for_the_node() {
        let (mut o, mut c) = crashed_chain();
        c.truncate(20);
        c.down = true;
        assert!(o.tick(&mut c, 20).is_empty());
        c.down = false;
        let v = sigs(&o.tick(&mut c, 20));
        assert!(!v.iter().any(|(_, s)| s.contains("sweep-complete")));
        for n in 21..=40 {
            c.push(n, 2);
        }
        let all = run_until_swept(&mut o, &mut c);
        assert!(all.iter().all(|(ok, _)| *ok), "{all:?}");
        assert!(all.contains(&(true, "~S/durable-sweep-complete".into())));
    }

    #[test]
    fn sample_keeps_the_newest_blocks_and_strides_older_ones() {
        let records: BTreeMap<u64, Record> = (1..=500)
            .map(|n| {
                (
                    n,
                    Record {
                        hash: h(n),
                        txs: vec![],
                        reads: None,
                    },
                )
            })
            .collect();
        let s = sample(&records, 400);
        assert!(s.len() <= SWEEP_NEWEST + SWEEP_OLDER);
        assert_eq!(s.last().unwrap().0, 400);
        let n: Vec<u64> = s.iter().map(|(n, _)| *n).collect();
        assert!(n.windows(2).all(|w| w[0] < w[1]));
        assert!((353..=400).all(|b| n.contains(&b)));
        assert_eq!(n[0], 1);
    }
}
