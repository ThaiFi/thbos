// SPDX-License-Identifier: GPL-2.0

//! Strand A: the generic valid-state-root invariant (`verify_state_root`).
//!
//! For every new canonical block, on every node (the dev node and each
//! validator), independently recompute the affected state from scratch and
//! assert it is consistent with the block's header `stateRoot`. This catches
//! ANY path that produces a block whose state root does not match the true
//! post-execution state — the class behind bedrock #16/#62 and reth#27679 —
//! even on a lone, self-accepting producer, because the oracle's ground truth
//! is an independent recompute ([`crate::trie_ref`]), never the node's own trie.
//!
//! Per block, for the touched set — the block's transaction senders and
//! recipients, any contracts its receipts created, the generic workload's
//! mutator contract, and the known finalize-time system writers (pathUSD, the
//! fee token written every block; extend [`SYSTEM_WRITERS`] with the
//! CurrentCommittee contract / deployed precompiles when their addresses are
//! known here) — it queries, by block hash (EIP-1898, `requireCanonical`, so a
//! reorg makes a read fail rather than answer for another block):
//!
//! - For the workload contract, whose complete written-slot candidate set is
//!   known ([`crate::statemix_gen::written_slots`] for statemix — the per-seed
//!   pool AND the per-generation bulk-write range — or a trie contract's slots):
//!   a (chunked) `eth_getProof` over the candidate set discovers which slots are
//!   live (non-zero) at the block and the node's `storageHash`; the live slots'
//!   values are then re-read independently with `eth_getStorageAt` (not from the
//!   proof), and the storage root rebuilt from scratch from them
//!   ([`trie_ref::storage_root`]) must equal `storageHash`
//!   (`E6/state-root-recomputed`, detail `storage-root-mismatch`). The recompute
//!   builds the root itself, so a wrong storage root embedded in the header
//!   `stateRoot` is caught even when the producer's own proof is internally
//!   consistent with it. Reading the full candidate set (not just the pool) is
//!   what makes the recompute match a block captured mid-bulk-write instead of
//!   false-positiving on an empty-pool read.
//! - For every touched account: the `eth_getProof` response must verify against
//!   the block's header `stateRoot` ([`trie_ref::verify`]) — the account proof,
//!   then each storage proof under `storageHash` (detail `account-proof-invalid`
//!   / `storage-proof-invalid`). This catches a node serving state inconsistent
//!   with the root it advertises (the historical-after-crash class).
//!
//! [`StateRootOracle`] is a pure state machine over the [`RootView`] trait; the
//! guest drives it from [`crate::oracle::run`] / [`crate::cluster_live`]. It is
//! deliberately self-contained so a build-differential strand (Strand D) can be
//! added beside it, reusing the same workload tx set, without refactoring.

use alloy_primitives::{Address, B256, U256};
use serde_json::{json, Value};

use crate::{
    common,
    trie_ref::{self, AccountProof, ProofError},
    verdict::{finding, Verdict},
};

/// Known finalize-time / system state writers always kept in scope, so a
/// finalize-time write is proof-checked at every block even when no transaction
/// names it. pathUSD is the fee token, written every block with transactions.
pub const SYSTEM_WRITERS: [Address; 1] = [alloy_primitives::address!(
    "20c0000000000000000000000000000000000000"
)];

/// Blocks checked per tick, newest-ward; bounds RPC per tick.
const BLOCKS_PER_TICK: u64 = 6;
/// On the first tick, how far below the head to start, so a run that enables the
/// oracle mid-stream checks recent blocks without replaying from genesis.
const BACKLOG: u64 = 8;
/// Touched accounts proof-checked per block (bounds RPC on busy blocks).
const MAX_TOUCHED: usize = 24;
/// Candidate slots per `eth_getProof` request: the statemix candidate set spans
/// the whole bulk-write range, so the proof that discovers the live slots is
/// fetched in bounded chunks rather than one huge request.
const PROOF_CHUNK: usize = 256;

/// One block's view for the invariant: its identity and the accounts it touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTouched {
    pub number: u64,
    pub hash: String,
    pub parent: String,
    pub state_root: B256,
    /// Transaction senders/recipients and receipt-created contracts.
    pub touched: Vec<Address>,
}

/// Per-node reads the invariant needs, by block hash where it reads state.
/// `Err` while the node is unreachable, `Ok(None)` past the head.
pub trait RootView {
    fn head(&mut self) -> Result<u64, String>;
    /// Canonical block `number`: its identity and touched accounts.
    fn block(&mut self, number: u64) -> Result<Option<BlockTouched>, String>;
    /// `eth_getProof` of `address`/`slots` at block `hash` (EIP-1898).
    fn proof_at(
        &mut self,
        address: Address,
        slots: &[u64],
        hash: &str,
    ) -> Result<AccountProof, String>;
    /// `eth_getStorageAt` of `slots` of `address` at block `hash` (EIP-1898).
    fn storage_at(
        &mut self,
        address: Address,
        slots: &[u64],
        hash: &str,
    ) -> Result<trie_ref::Storage, String>;
}

/// The generic valid-state-root oracle over one node (see the module docs).
#[derive(Debug)]
pub struct StateRootOracle {
    /// The generic workload's contract and the slots it writes, if any, for the
    /// independent storage-root recompute.
    workload: Option<(Address, Vec<u64>)>,
    /// Highest block fully checked.
    checked: u64,
    started: bool,
    /// Coverage emitted once.
    recompute_seen: bool,
    verify_seen: bool,
}

impl StateRootOracle {
    /// A fresh oracle. `workload` is the generic workload's `(contract, slots)`
    /// for the independent storage-root recompute (`None` with no such load; the
    /// account-proof verification still runs for the touched set).
    pub fn new(workload: Option<(Address, Vec<u64>)>) -> StateRootOracle {
        StateRootOracle {
            workload,
            checked: 0,
            started: false,
            recompute_seen: false,
            verify_seen: false,
        }
    }

    /// Re-check the rebuilt blocks after a rewind (head below the last checked
    /// block), as the trie oracle does.
    fn rewound(&mut self, head: u64) {
        if head < self.checked {
            self.checked = head.saturating_sub(1);
        }
    }

    /// One step: check every not-yet-checked block up to `head`, bounded per
    /// tick. `None` from `view.block` (node unreachable / past head) ends the
    /// tick without advancing, so the block is retried.
    pub fn tick(&mut self, view: &mut impl RootView, head: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        if !self.started {
            self.checked = head.saturating_sub(BACKLOG);
            self.started = true;
        }
        self.rewound(head);
        let up_to = head.min(self.checked + BLOCKS_PER_TICK);
        while self.checked < up_to {
            let b = self.checked + 1;
            match view.block(b) {
                // Only advance when the block was fully checked; a transient
                // RPC error mid-check leaves it to be retried next tick.
                Ok(Some(block)) if block.number == b => {
                    if self.check_block(view, &block, &mut out) {
                        self.checked = b;
                    } else {
                        break;
                    }
                }
                // Not served yet, or unreachable: retry this block next tick.
                _ => break,
            }
        }
        out
    }

    /// The touched set for one block: its own touched accounts, the workload
    /// contract, and the system writers, de-duplicated, capped.
    fn touched_set(&self, block: &BlockTouched) -> Vec<Address> {
        let mut out: Vec<Address> = Vec::new();
        let mut push = |a: Address| {
            if !out.contains(&a) {
                out.push(a);
            }
        };
        if let Some((c, _)) = &self.workload {
            push(*c);
        }
        for a in SYSTEM_WRITERS {
            push(a);
        }
        for a in &block.touched {
            push(*a);
        }
        out.truncate(MAX_TOUCHED);
        out
    }

    /// Checks one block: the workload storage-root recompute, then the touched
    /// set's account proofs, all against the block's header state root. Returns
    /// `false` when a read failed transiently (the node is down, or the block
    /// left the proof window), so the caller retries the block rather than
    /// skipping it.
    fn check_block(
        &mut self,
        view: &mut impl RootView,
        block: &BlockTouched,
        out: &mut Vec<Verdict>,
    ) -> bool {
        let hash = &block.hash;
        let root = block.state_root;
        let mut failed = false;

        // The independent storage-root recompute on the workload contract.
        if let Some((contract, slots)) = self.workload.clone() {
            if !slots.is_empty() {
                // A (chunked) eth_getProof over the whole candidate set discovers
                // which slots are live (non-zero) at this block and the node's
                // storageHash, and proves them (report_verify below). The live
                // slots' values are then re-read independently via
                // eth_getStorageAt, so the from-scratch root is not built from
                // the node's trie proof.
                let mut storage_hash: Option<B256> = None;
                let mut live: Vec<u64> = Vec::new();
                let mut proofs: Vec<AccountProof> = Vec::new();
                for chunk in slots.chunks(PROOF_CHUNK) {
                    let proof = match view.proof_at(contract, chunk, hash) {
                        Ok(p) => p,
                        // Node unreachable / block out of window: retry.
                        Err(_) => return false,
                    };
                    storage_hash = Some(proof.storage_hash);
                    for sp in &proof.storage_proof {
                        if !sp.value.is_zero() {
                            live.push(sp.key.saturating_to::<u64>());
                        }
                    }
                    proofs.push(proof);
                }
                live.sort_unstable();
                live.dedup();
                let storage = match view.storage_at(contract, &live, hash) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let reference = trie_ref::storage_root(&storage);
                // Some(_): every chunk set it. Empty candidate set is excluded above.
                let node_hash = storage_hash.unwrap_or_default();
                if reference != node_hash {
                    failed = true;
                    out.push(Verdict::Always(
                        false,
                        finding(
                            "E6/state-root-recomputed",
                            format!(
                                "block {} ({hash}): storage-root-mismatch for {contract}: recomputed {reference}, node storageHash {node_hash}; live slots {live:?}",
                                block.number
                            ),
                        ),
                    ));
                } else if !self.recompute_seen {
                    self.recompute_seen = true;
                    out.push(Verdict::Sometimes(
                        true,
                        finding(
                            "S/state-root-recomputed-checked",
                            format!(
                                "block {}: storage root of {contract} rebuilt from scratch matches the header state root",
                                block.number
                            ),
                        ),
                    ));
                }
                // Prove every candidate slot (live and absent) against storageHash,
                // so a node hiding a live slot is caught too.
                for proof in &proofs {
                    failed |= report_verify(proof, root, block.number, hash, Some(contract), out);
                }
            }
        }

        // Every touched account's proof must verify against the header root.
        for address in self.touched_set(block) {
            // The workload contract (with slots) was already checked above.
            if self
                .workload
                .as_ref()
                .is_some_and(|(c, slots)| *c == address && !slots.is_empty())
            {
                continue;
            }
            let proof = match view.proof_at(address, &[], hash) {
                Ok(p) => p,
                // Transient read failure: retry the whole block next tick.
                Err(_) => return false,
            };
            failed |= report_verify(&proof, root, block.number, hash, None, out);
        }

        if !failed {
            out.push(Verdict::Always(
                true,
                finding("E6/state-root-recomputed", String::new()),
            ));
            if !self.verify_seen {
                self.verify_seen = true;
                out.push(Verdict::Sometimes(
                    true,
                    finding(
                        "S/state-root-verified",
                        format!(
                            "block {}: touched-set proofs verify against the header state root",
                            block.number
                        ),
                    ),
                ));
            }
        }
        true
    }
}

/// Verifies one proof against `root`; pushes `E6/state-root-recomputed` on
/// failure. Returns whether it failed.
fn report_verify(
    proof: &AccountProof,
    root: B256,
    number: u64,
    hash: &str,
    contract: Option<Address>,
    out: &mut Vec<Verdict>,
) -> bool {
    let who = contract
        .map(|c| format!("{c}"))
        .unwrap_or_else(|| format!("{}", proof.address));
    match trie_ref::verify(proof, root) {
        Ok(()) => false,
        Err(ProofError::Account(e)) => {
            out.push(Verdict::Always(
                false,
                finding(
                    "E6/state-root-recomputed",
                    format!(
                        "block {number} ({hash}): account-proof-invalid for {who} against header state root {root}: {e}"
                    ),
                ),
            ));
            true
        }
        Err(ProofError::Storage { slot, error }) => {
            out.push(Verdict::Always(
                false,
                finding(
                    "E6/state-root-recomputed",
                    format!(
                        "block {number} ({hash}): storage-proof-invalid for {who}, slot {slot}, storageHash {}: {error}",
                        proof.storage_hash
                    ),
                ),
            ));
            true
        }
    }
}

/// The live per-node view over RPC: `None` targets the dev node, `Some(url)` a
/// specific validator. Reads state by block hash (EIP-1898), as the historical
/// oracles do.
pub struct RpcRoot(pub Option<&'static str>);

impl RpcRoot {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        match self.0 {
            Some(url) => common::with_rpc_url(url, || common::rpc(method, params)),
            None => common::rpc(method, params),
        }
    }
}

fn hex(n: u64) -> String {
    format!("0x{n:x}")
}

/// `{"blockHash": h, "requireCanonical": true}` — a reorg fails the read.
fn at(hash: &str) -> Value {
    json!({"blockHash": hash, "requireCanonical": true})
}

impl RootView for RpcRoot {
    fn head(&mut self) -> Result<u64, String> {
        let head = self.call("eth_blockNumber", json!([]))?;
        head.as_str()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .ok_or_else(|| format!("bad eth_blockNumber: {head}"))
    }

    fn block(&mut self, number: u64) -> Result<Option<BlockTouched>, String> {
        let b = self.call("eth_getBlockByNumber", json!([hex(number), true]))?;
        if b.is_null() {
            return Ok(None);
        }
        let hash = b["hash"].as_str().unwrap_or_default().to_lowercase();
        let parent = b["parentHash"].as_str().unwrap_or_default().to_lowercase();
        let state_root: B256 = serde_json::from_value(b["stateRoot"].clone())
            .map_err(|e| format!("bad stateRoot: {e}: {b}"))?;
        let mut touched: Vec<Address> = Vec::new();
        if let Some(txs) = b["transactions"].as_array() {
            for tx in txs {
                for k in ["from", "to"] {
                    if let Some(a) = tx
                        .get(k)
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse().ok())
                    {
                        if !touched.contains(&a) {
                            touched.push(a);
                        }
                    }
                }
            }
            // Receipt-created contracts (top-level CREATE txs).
            if txs.iter().any(|tx| tx.get("to").is_none_or(Value::is_null)) {
                if let Ok(receipts) = self.call("eth_getBlockReceipts", json!([hash])) {
                    if let Some(rs) = receipts.as_array() {
                        for r in rs {
                            if let Some(a) = r
                                .get("contractAddress")
                                .and_then(Value::as_str)
                                .and_then(|s| s.parse().ok())
                            {
                                if !touched.contains(&a) {
                                    touched.push(a);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(Some(BlockTouched {
            number,
            hash,
            parent,
            state_root,
            touched,
        }))
    }

    fn proof_at(
        &mut self,
        address: Address,
        slots: &[u64],
        hash: &str,
    ) -> Result<AccountProof, String> {
        let keys: Vec<String> = slots.iter().map(|s| format!("0x{s:x}")).collect();
        let proof = self.call("eth_getProof", json!([address, keys, at(hash)]))?;
        serde_json::from_value(proof.clone()).map_err(|e| format!("bad eth_getProof: {e}: {proof}"))
    }

    fn storage_at(
        &mut self,
        address: Address,
        slots: &[u64],
        hash: &str,
    ) -> Result<trie_ref::Storage, String> {
        slots
            .iter()
            .map(|slot| {
                let v = self.call(
                    "eth_getStorageAt",
                    json!([address, format!("0x{slot:x}"), at(hash)]),
                )?;
                Ok((
                    *slot,
                    serde_json::from_value::<U256>(v).map_err(|e| e.to_string())?,
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie_ref::tests::honest_state;
    use std::collections::BTreeMap;

    const ADDR: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
    const SLOTS: &[u64] = &[0, 1, 7];

    /// A node serving one block's state from honest proofs, with optional
    /// tampering so the oracle must report a wrong root.
    struct FakeView {
        head: u64,
        hash: String,
        state_root: B256,
        proof: AccountProof,
        storage: trie_ref::Storage,
        touched: Vec<Address>,
        /// A value the node *reports* via eth_getStorageAt that differs from
        /// what its trie (proof) actually holds: the recompute then differs
        /// from the node's storageHash.
        storage_lies: bool,
    }

    impl FakeView {
        /// An honest node: the proof verifies and the storage recompute matches.
        fn honest() -> FakeView {
            let pairs: Vec<(u64, u64)> = vec![(0, 5), (1, 9), (7, 0)];
            let (state_root, mut proofs) = honest_state(&[(ADDR, &pairs, SLOTS)]);
            let proof = proofs.remove(0);
            let storage: trie_ref::Storage =
                pairs.iter().map(|(s, v)| (*s, U256::from(*v))).collect();
            FakeView {
                head: 10,
                hash: "0xaa".to_string() + &"0".repeat(62),
                state_root,
                proof,
                storage,
                touched: vec![ADDR.parse().unwrap()],
                storage_lies: false,
            }
        }
    }

    impl RootView for FakeView {
        fn head(&mut self) -> Result<u64, String> {
            Ok(self.head)
        }
        fn block(&mut self, number: u64) -> Result<Option<BlockTouched>, String> {
            Ok(Some(BlockTouched {
                number,
                hash: self.hash.clone(),
                parent: "0x00".into(),
                state_root: self.state_root,
                touched: self.touched.clone(),
            }))
        }
        fn proof_at(
            &mut self,
            _address: Address,
            _slots: &[u64],
            _hash: &str,
        ) -> Result<AccountProof, String> {
            Ok(self.proof.clone())
        }
        fn storage_at(
            &mut self,
            _address: Address,
            slots: &[u64],
            _hash: &str,
        ) -> Result<trie_ref::Storage, String> {
            if self.storage_lies {
                // Claim a different value than the trie proves, so the
                // recomputed storage root no longer matches storageHash.
                Ok(slots.iter().map(|s| (*s, U256::from(0xdead_u64))).collect())
            } else {
                Ok(self.storage.clone())
            }
        }
    }

    fn failures(v: &[Verdict]) -> Vec<&Verdict> {
        v.iter()
            .filter(|x| matches!(x, Verdict::Always(false, _)))
            .collect()
    }

    #[test]
    fn a_correct_root_passes() {
        let mut view = FakeView::honest();
        let mut oracle = StateRootOracle::new(Some((ADDR.parse().unwrap(), SLOTS.to_vec())));
        let out = oracle.tick(&mut view, 10);
        assert!(failures(&out).is_empty(), "{out:?}");
        // The independent recompute and the touched-set verification both ran.
        assert!(out
            .iter()
            .any(|v| matches!(v, Verdict::Sometimes(_, f) if f.signature == "S/state-root-recomputed-checked")));
        assert!(out.iter().any(
            |v| matches!(v, Verdict::Always(true, f) if f.signature == "E6/state-root-recomputed")
        ));
    }

    #[test]
    fn a_planted_wrong_root_is_reported() {
        // The node's reported slot values do not match its trie: the storage
        // root rebuilt from the values differs from the node's storageHash.
        let mut view = FakeView::honest();
        view.storage_lies = true;
        let mut oracle = StateRootOracle::new(Some((ADDR.parse().unwrap(), SLOTS.to_vec())));
        let out = oracle.tick(&mut view, 10);
        let fails = failures(&out);
        assert!(!fails.is_empty(), "expected a reported wrong root");
        assert!(fails.iter().any(|v| matches!(
            v,
            Verdict::Always(false, f)
                if f.signature == "E6/state-root-recomputed" && f.detail.contains("storage-root-mismatch")
        )));
    }

    #[test]
    fn a_proof_that_does_not_verify_is_reported() {
        // The proof is for one state root but the header claims another.
        let mut view = FakeView::honest();
        view.state_root = B256::ZERO;
        let mut oracle = StateRootOracle::new(Some((ADDR.parse().unwrap(), SLOTS.to_vec())));
        let out = oracle.tick(&mut view, 10);
        assert!(failures(&out).iter().any(|v| matches!(
            v,
            Verdict::Always(false, f)
                if f.signature == "E6/state-root-recomputed" && f.detail.contains("account-proof-invalid")
        )), "{out:?}");
    }

    #[test]
    fn it_advances_and_is_deterministic() {
        let mut view = FakeView::honest();
        let mut oracle = StateRootOracle::new(Some((ADDR.parse().unwrap(), SLOTS.to_vec())));
        // First tick starts near the head (BACKLOG) and checks a bounded number.
        let _ = oracle.tick(&mut view, 10);
        let checked_first = oracle.checked;
        assert!(checked_first <= 10);
        // Repeated ticks reach the head and stop (no blocks past it).
        for _ in 0..5 {
            oracle.tick(&mut view, 10);
        }
        assert_eq!(oracle.checked, 10);
        let _ = BTreeMap::<u64, u64>::new();
    }

    /// A node whose contract holds `storage`, answering `eth_getProof` for the
    /// exact slots requested (so a candidate set that misses a live slot proves
    /// it absent, as the real node would) and `eth_getStorageAt` from `storage`,
    /// optionally lying about one slot.
    struct PoolView {
        state_root: B256,
        storage: Vec<(u64, u64)>,
        /// `eth_getStorageAt` returns this (slot, wrong value) in place of the truth.
        tamper: Option<(u64, u64)>,
    }

    impl PoolView {
        fn new(storage: Vec<(u64, u64)>) -> PoolView {
            // Account-trie root is a function of the (constant) storageHash, so
            // it is the same for any proven-slot set.
            let (state_root, _) = honest_state(&[(ADDR, &storage, &[])]);
            PoolView {
                state_root,
                storage,
                tamper: None,
            }
        }
    }

    impl RootView for PoolView {
        fn head(&mut self) -> Result<u64, String> {
            Ok(10)
        }
        fn block(&mut self, number: u64) -> Result<Option<BlockTouched>, String> {
            Ok(Some(BlockTouched {
                number,
                hash: "0xbb".to_string() + &"0".repeat(62),
                parent: "0x00".into(),
                state_root: self.state_root,
                touched: vec![ADDR.parse().unwrap()],
            }))
        }
        fn proof_at(
            &mut self,
            _address: Address,
            slots: &[u64],
            _hash: &str,
        ) -> Result<AccountProof, String> {
            let (_, mut proofs) = honest_state(&[(ADDR, &self.storage, slots)]);
            Ok(proofs.remove(0))
        }
        fn storage_at(
            &mut self,
            _address: Address,
            slots: &[u64],
            _hash: &str,
        ) -> Result<trie_ref::Storage, String> {
            Ok(slots
                .iter()
                .map(|s| {
                    let v = match self.tamper {
                        Some((ts, tv)) if ts == *s => tv,
                        _ => self
                            .storage
                            .iter()
                            .find(|(k, _)| k == s)
                            .map_or(0, |(_, v)| *v),
                    };
                    (*s, U256::from(v))
                })
                .collect())
        }
    }

    #[test]
    fn recompute_matches_a_bulk_range_slot_outside_the_pool() {
        // The statemix regression: the only live slot is a bulk-write slot (512),
        // outside the per-seed pool. A naive pool that misses it reads an empty
        // pool and false-positives on the empty storage root; the complete
        // candidate set (statemix_gen::written_slots) reads it and matches.
        let storage = vec![(512u64, 7u64)];

        let mut naive = PoolView::new(storage.clone());
        let mut naive_oracle = StateRootOracle::new(Some((ADDR.parse().unwrap(), vec![0, 1, 2])));
        let out = naive_oracle.tick(&mut naive, 10);
        assert!(
            failures(&out).iter().any(|v| matches!(v,
                Verdict::Always(false, f) if f.detail.contains("storage-root-mismatch"))),
            "a pool missing the live slot should false-positive: {out:?}"
        );

        let mut view = PoolView::new(storage);
        let candidate = crate::statemix_gen::written_slots(0);
        assert!(
            candidate.contains(&512),
            "candidate set covers the bulk range"
        );
        let mut oracle = StateRootOracle::new(Some((ADDR.parse().unwrap(), candidate)));
        let out = oracle.tick(&mut view, 10);
        assert!(
            failures(&out).is_empty(),
            "the complete candidate set should match the node's root: {out:?}"
        );
        assert!(out.iter().any(|v| matches!(v,
            Verdict::Sometimes(_, f) if f.signature == "S/state-root-recomputed-checked")));
    }

    #[test]
    fn recompute_catches_a_planted_wrong_value_at_a_bulk_slot() {
        // With the complete candidate set the recompute still catches a genuine
        // wrong root: the node reports a slot value its trie does not hold.
        let mut view = PoolView::new(vec![(512u64, 7u64)]);
        view.tamper = Some((512, 0xdead));
        let candidate = crate::statemix_gen::written_slots(0);
        let mut oracle = StateRootOracle::new(Some((ADDR.parse().unwrap(), candidate)));
        let out = oracle.tick(&mut view, 10);
        assert!(
            failures(&out).iter().any(|v| matches!(v,
                Verdict::Always(false, f)
                    if f.signature == "E6/state-root-recomputed" && f.detail.contains("storage-root-mismatch"))),
            "a planted wrong value must be reported: {out:?}"
        );
    }
}
