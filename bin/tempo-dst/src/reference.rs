// SPDX-License-Identifier: GPL-2.0

//! E7: a reference node as a differential oracle.
//!
//! With `reference=true`, a second Tempo node (`tempo-ref`, RPC on 8547) follows
//! the primary: it fetches each block from the primary's RPC (reth's debug
//! consensus client) and re-executes it on reth's simplest engine paths (no
//! prewarming or caches, synchronous state root, no state masking), backfilling
//! from the primary over p2p when it missed blocks. It is never crashed or
//! thread-fuzzed. Checks:
//!
//! - `E7/reference-<pattern>`, `E7/reference-rejected`: the reference logs a
//!   failure (E1's patterns, plus its own block rejections) for a block the
//!   primary produced.
//! - `E7/reference-stalled`: its head stays more than [`MAX_LAG`] blocks behind
//!   the primary's for `liveness_secs` while the primary is up.
//! - `E7/state-root-differs`, `E7/block-hash-differs`: at the highest block
//!   both have, the nodes disagree for longer than `liveness_secs` (a primary
//!   crash may rebuild unfinalized blocks, which the reference then reorgs to),
//!   or serve the same header hash with different state roots.
//! - `E7/proof-differs` (trie load): on blocks both nodes agree on, the
//!   RawStorage contract's `eth_getProof` storage hash and proven values,
//!   `eth_getMultiProof` storage hash, and `eth_getStorageAt` values match.
//!   Checks new common blocks plus E5/E6's depth sweep; with several
//!   contracts, every contract at the newest common block and one,
//!   round-robin, at each other block (`oracle::trie_targets`).
//!
//! [`Reference`] is a pure state machine over two [`Node`]s; [`start`] wires
//! it to the guest.

use std::sync::mpsc;

use alloy_primitives::B256;

use crate::{
    common::{self, Config, DstEvent, TrieConfig, NODE_CONTAINER, REFERENCE_CONTAINER},
    oracle::{
        contract_note, sweep_depth, trie_targets, Chain, Failure, RpcChain, DEEP_DEPTHS,
        SHALLOW_DEPTHS, TRIE_BLOCKS_PER_TICK,
    },
    trie_ref::{self, AccountProof},
    verdict::{finding, strip_ansi, Finding, Verdict, LOG_PATTERNS},
};

/// Blocks the reference may trail the primary by before E7/reference-stalled
/// starts timing (about 6 s of 200 ms blocks).
pub const MAX_LAG: u64 = 32;

/// Reference-only rejection messages (reth 42fa3c5): the engine's invalid
/// `newPayload` and the pipeline's backfill validation failures.
const REJECTED: &[&str] = &[
    "Invalid block error on new payload",
    "Stage encountered a validation error",
    "Stage encountered an execution error",
];

/// E7 for one reference log line: E1's patterns, renamed `E7/reference-*`,
/// then the reference's own rejections. ERROR-level lines alone are not
/// findings: the debug consensus client logs poll errors while the primary is
/// down.
pub fn scan_line(line: &str) -> Option<Finding> {
    let line = strip_ansi(line);
    let detail: String = line.chars().take(400).collect();
    let signature = if let Some((sig, _)) = LOG_PATTERNS.iter().find(|(_, p)| line.contains(p)) {
        format!("E7/reference-{}", sig.trim_start_matches("E1/"))
    } else if REJECTED.iter().any(|p| line.contains(p)) {
        "E7/reference-rejected".into()
    } else {
        return None;
    };
    Some(Finding { signature, detail })
}

/// What E7 asks each node; `Err` while it is unreachable.
pub trait Node {
    fn head(&mut self) -> Result<u64, String>;
    fn hash(&mut self, number: u64) -> Result<Option<String>, String>;
    fn state_root(&mut self, block: u64) -> Result<B256, String>;
    fn storage(
        &mut self,
        address: &str,
        slots: &[u64],
        block: u64,
    ) -> Result<trie_ref::Storage, String>;
    fn proof(&mut self, address: &str, slots: &[u64], block: u64) -> Result<AccountProof, String>;
    fn multiproof(
        &mut self,
        address: &str,
        slots: &[u64],
        block: u64,
    ) -> Result<AccountProof, String>;
}

impl<C: Chain> Node for C {
    fn head(&mut self) -> Result<u64, String> {
        Chain::head(self)
    }
    fn hash(&mut self, number: u64) -> Result<Option<String>, String> {
        Chain::hash(self, number)
    }
    fn state_root(&mut self, block: u64) -> Result<B256, String> {
        Chain::state_root(self, block)
    }
    fn storage(&mut self, a: &str, s: &[u64], block: u64) -> Result<trie_ref::Storage, String> {
        Chain::storage(self, a, s, block)
    }
    fn proof(&mut self, a: &str, s: &[u64], block: u64) -> Result<AccountProof, String> {
        Chain::proof(self, a, s, block)
    }
    fn multiproof(&mut self, a: &str, s: &[u64], block: u64) -> Result<AccountProof, String> {
        Chain::multiproof(self, a, s, block)
    }
}

/// One node's answers for the trie contract at one block.
struct TrieView {
    proof: AccountProof,
    multiproof: AccountProof,
    storage: trie_ref::Storage,
}

fn trie_view(node: &mut impl Node, trie: &TrieConfig, block: u64) -> Option<TrieView> {
    Some(TrieView {
        proof: node.proof(&trie.address, &trie.slots, block).ok()?,
        multiproof: node.multiproof(&trie.address, &trie.slots, block).ok()?,
        storage: node.storage(&trie.address, &trie.slots, block).ok()?,
    })
}

/// E7/proof-differs for one block both nodes agree on; `None` while either
/// cannot answer (e.g. the block left a proof window).
fn compare_trie_block(
    primary: &mut impl Node,
    reference: &mut impl Node,
    trie: &TrieConfig,
    block: u64,
) -> Option<Vec<Failure>> {
    let p = trie_view(primary, trie, block)?;
    let r = trie_view(reference, trie, block)?;
    let mut failures = Vec::new();
    let mut differ = |what: &str, primary: String, reference: String| {
        if primary != reference {
            failures.push((
                "E7/proof-differs".to_string(),
                format!("{what}: primary {primary}, reference {reference}"),
            ));
        }
    };
    differ(
        "eth_getProof storageHash",
        p.proof.storage_hash.to_string(),
        r.proof.storage_hash.to_string(),
    );
    let proven = |a: &AccountProof| {
        let v: Vec<_> = a.storage_proof.iter().map(|s| (s.key, s.value)).collect();
        format!("{v:?}")
    };
    differ("eth_getProof values", proven(&p.proof), proven(&r.proof));
    differ(
        "eth_getMultiProof storageHash",
        p.multiproof.storage_hash.to_string(),
        r.multiproof.storage_hash.to_string(),
    );
    differ(
        "eth_getStorageAt",
        format!("{:?}", p.storage),
        format!("{:?}", r.storage),
    );
    Some(failures)
}

#[derive(Debug)]
pub struct Reference {
    liveness_ns: u64,
    /// Contracts compared (see `trie_targets`).
    tries: Vec<TrieConfig>,
    /// Round-robin cursor over `tries` for blocks below the newest.
    trie_cursor: usize,
    /// Primary killed and not yet restarted.
    primary_down: bool,
    primary_head: Option<u64>,
    /// Primary head at the last kill, until the reference follows past it.
    head_at_kill: Option<u64>,
    /// Since when the reference has trailed by more than [`MAX_LAG`].
    behind_since: Option<u64>,
    stall_reported: bool,
    /// Since when the nodes disagree at their highest common block.
    diverged_since: Option<u64>,
    diverge_reported: bool,
    /// Last common block whose trie answers were compared.
    compared: u64,
    ticks: u64,
    seen_compared: bool,
    seen_synced: bool,
}

impl Reference {
    /// Creates a fresh reference comparison oracle for the configured contracts.
    pub fn new(liveness_secs: u64, tries: Vec<TrieConfig>) -> Reference {
        Reference {
            liveness_ns: liveness_secs * 1_000_000_000,
            tries,
            trie_cursor: 0,
            primary_down: false,
            primary_head: None,
            head_at_kill: None,
            behind_since: None,
            stall_reported: false,
            diverged_since: None,
            diverge_reported: false,
            compared: 0,
            ticks: 0,
            seen_compared: false,
            seen_synced: false,
        }
    }

    /// Supplies a single test contract before any checks run.
    #[cfg(test)]
    fn with_trie(self, trie: Option<TrieConfig>) -> Reference {
        self.with_tries(trie.into_iter().collect())
    }

    /// Supplies test fixtures before any checks run.
    #[cfg(test)]
    fn with_tries(mut self, tries: Vec<TrieConfig>) -> Reference {
        self.tries = tries;
        self
    }

    pub fn on_log(&mut self, line: &str) -> Vec<Verdict> {
        scan_line(line)
            .map(|f| vec![Verdict::Always(false, f)])
            .unwrap_or_default()
    }

    /// Nemesis kills, graceful stops and pauses of the primary, and its
    /// restarts and resumes. Timers restart with the primary: the reference
    /// cannot follow while its source is down or frozen (it keeps running
    /// and polling, so its follow and catch-up paths are exercised).
    pub fn on_event(&mut self, ev: &DstEvent) {
        if ev.source != "nemesis" || ev.container.as_deref() != Some(NODE_CONTAINER) {
            return;
        }
        match ev.kind.as_str() {
            "kill" | "down" | "stop" | "pause" => {
                self.primary_down = true;
                self.head_at_kill = self.primary_head;
            }
            "restart" | "resume" => {
                self.primary_down = false;
                self.behind_since = None;
                self.stall_reported = false;
                self.diverged_since = None;
                self.diverge_reported = false;
            }
            _ => {}
        }
    }

    fn sometimes(&mut self, signature: &str, detail: String) -> Verdict {
        Verdict::Sometimes(true, finding(signature, detail))
    }

    pub fn tick(
        &mut self,
        primary: &mut impl Node,
        reference: &mut impl Node,
        now_ns: u64,
    ) -> Vec<Verdict> {
        let mut out = Vec::new();
        if self.primary_down {
            return out;
        }
        let Ok(ph) = primary.head() else {
            return out;
        };
        self.primary_head = Some(ph);
        let rh = reference.head().ok();

        // Stall: too far behind for too long (an unreachable reference counts).
        if rh.is_none_or(|r| ph > r + MAX_LAG) {
            let since = *self.behind_since.get_or_insert(now_ns);
            if !self.stall_reported && now_ns.saturating_sub(since) > self.liveness_ns {
                self.stall_reported = true;
                out.push(Verdict::Always(
                    false,
                    finding(
                        "E7/reference-stalled",
                        format!(
                            "reference head {rh:?}, primary head {ph}: more than {MAX_LAG} blocks behind for {}s",
                            self.liveness_ns / 1_000_000_000
                        ),
                    ),
                ));
            }
        } else {
            self.behind_since = None;
            self.stall_reported = false;
        }

        let Some(rh) = rh else {
            return out;
        };
        let common = rh.min(ph);
        if common == 0 {
            return out;
        }
        let (Ok(p_hash), Ok(r_hash), Ok(p_root), Ok(r_root)) = (
            primary.hash(common),
            reference.hash(common),
            primary.state_root(common),
            reference.state_root(common),
        ) else {
            return out;
        };
        let lower = |h: Option<String>| h.map(|h| h.to_lowercase());
        let (p_hash, r_hash) = (lower(p_hash), lower(r_hash));
        if p_hash.is_none() || p_hash != r_hash {
            // Normal right after a primary crash: it may rebuild unfinalized
            // blocks, and the reference has to reorg onto them.
            let since = *self.diverged_since.get_or_insert(now_ns);
            if !self.diverge_reported && now_ns.saturating_sub(since) > self.liveness_ns {
                self.diverge_reported = true;
                let signature = if p_root != r_root {
                    "E7/state-root-differs"
                } else {
                    "E7/block-hash-differs"
                };
                out.push(Verdict::Always(
                    false,
                    finding(
                        signature,
                        format!(
                            "block {common} for {}s: primary {p_hash:?} root {p_root}, reference {r_hash:?} root {r_root}",
                            self.liveness_ns / 1_000_000_000
                        ),
                    ),
                ));
            }
            return out;
        }
        self.diverged_since = None;
        self.diverge_reported = false;
        if p_root != r_root {
            out.push(Verdict::Always(
                false,
                finding(
                    "E7/state-root-differs",
                    format!("block {common} hash {p_hash:?}: primary root {p_root}, reference root {r_root}"),
                ),
            ));
        }
        if !self.seen_compared {
            self.seen_compared = true;
            out.push(self.sometimes("S/reference-compared", format!("block {common}")));
        }
        if rh >= ph && !self.seen_synced {
            self.seen_synced = true;
            out.push(self.sometimes("S/reference-synced", format!("head {rh}")));
        }
        if let Some(k) = self.head_at_kill.filter(|k| rh <= ph && rh > *k) {
            self.head_at_kill = None;
            out.push(self.sometimes(
                "S/reference-followed-restart",
                format!("reference head {rh} passed the primary's pre-kill head {k}"),
            ));
        }
        out.extend(self.compare_trie(primary, reference, common));
        out
    }

    /// E7/proof-differs for new blocks up to `common` (both nodes have the
    /// same block there, hence the same chain below it), plus a shallow and a
    /// deep older block as in E5/E6.
    fn compare_trie(
        &mut self,
        primary: &mut impl Node,
        reference: &mut impl Node,
        common: u64,
    ) -> Vec<Verdict> {
        let mut out = Vec::new();
        if self.tries.is_empty() {
            return out;
        }
        let tries = self.tries.clone();
        if common < self.compared {
            self.compared = common.saturating_sub(1);
        }
        let first = (self.compared + 1).max(common.saturating_sub(TRIE_BLOCKS_PER_TICK - 1));
        let tick = self.ticks;
        self.ticks += 1;
        let older: Vec<u64> = [SHALLOW_DEPTHS, DEEP_DEPTHS]
            .into_iter()
            .filter_map(|range| common.checked_sub(sweep_depth(range, tick)))
            .filter(|b| *b > 0 && *b < first)
            .collect();
        'blocks: for block in older.into_iter().chain(first..=common) {
            for c in trie_targets(tries.len(), block, common, &mut self.trie_cursor) {
                let Some(failures) = compare_trie_block(primary, reference, &tries[c], block)
                else {
                    // Deep blocks can leave a node's proof window; new ones retry.
                    if block >= first {
                        return out;
                    }
                    continue 'blocks;
                };
                for (signature, detail) in failures {
                    out.push(Verdict::Always(
                        false,
                        finding(
                            &signature,
                            format!("block {block}: {}{detail}", contract_note(&tries, c)),
                        ),
                    ));
                }
            }
            if block >= first {
                self.compared = block;
            }
        }
        out
    }
}

/// The reference node's RPC, as a [`Node`].
struct ReferenceChain;

impl Node for ReferenceChain {
    fn head(&mut self) -> Result<u64, String> {
        common::with_rpc_url(common::REFERENCE_RPC_URL, common::head_number)
    }
    fn hash(&mut self, number: u64) -> Result<Option<String>, String> {
        common::with_rpc_url(common::REFERENCE_RPC_URL, || common::block_hash(number))
    }
    fn state_root(&mut self, block: u64) -> Result<B256, String> {
        common::with_rpc_url(common::REFERENCE_RPC_URL, || common::state_root(block))
    }
    fn storage(&mut self, a: &str, s: &[u64], block: u64) -> Result<trie_ref::Storage, String> {
        common::with_rpc_url(common::REFERENCE_RPC_URL, || {
            common::storage_at(a, s, block)
        })
    }
    fn proof(&mut self, a: &str, s: &[u64], block: u64) -> Result<AccountProof, String> {
        common::with_rpc_url(common::REFERENCE_RPC_URL, || common::proof(a, s, block))
    }
    fn multiproof(&mut self, a: &str, s: &[u64], block: u64) -> Result<AccountProof, String> {
        common::with_rpc_url(common::REFERENCE_RPC_URL, || {
            common::multiproof(a, s, block)
        })
    }
}

/// E7 inside the online oracle's loop.
pub struct Online {
    oracle: Reference,
    logs: mpsc::Receiver<String>,
}

/// Starts following the reference's log; `None` unless the run has one.
pub fn start(cfg: &Config) -> Option<Online> {
    if !cfg.reference {
        return None;
    }
    let (tx, logs) = mpsc::channel();
    std::thread::spawn(move || crate::oracle::follow_logs(REFERENCE_CONTAINER, tx));
    Some(Online {
        oracle: Reference::new(cfg.liveness_secs, cfg.tries()),
        logs,
    })
}

impl Online {
    /// One oracle tick: reference log lines, new events, then the RPC checks.
    pub fn step(&mut self, events: &[DstEvent], now_ns: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        for line in self.logs.try_iter() {
            out.extend(self.oracle.on_log(&line));
        }
        for ev in events {
            self.oracle.on_event(ev);
        }
        out.extend(self.oracle.tick(&mut RpcChain, &mut ReferenceChain, now_ns));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use serde_json::Value;
    use std::collections::HashMap;

    const S: u64 = 1_000_000_000;
    const ADDR: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
    const SLOTS: [u64; 2] = [544, 646];

    /// A node as E7 sees it: a chain of `(hash, state root)` by number, and
    /// RawStorage contents per block.
    #[derive(Default, Clone)]
    struct FakeNode {
        up: bool,
        blocks: Vec<(String, B256)>,
        storage: HashMap<u64, Vec<(u64, u64)>>,
        /// eth_getMultiProof answers that differ from eth_getProof's.
        multiproofs: HashMap<u64, AccountProof>,
        /// (address, block) of each eth_getStorageAt batch.
        reads: Vec<(String, u64)>,
    }

    impl FakeNode {
        /// Blocks `1..=n` of fork `fork`.
        fn chain(n: u64, fork: &str) -> FakeNode {
            let mut f = FakeNode {
                up: true,
                ..Default::default()
            };
            f.extend(n, fork);
            f
        }
        fn extend(&mut self, to: u64, fork: &str) {
            for b in self.blocks.len() as u64 + 1..=to {
                self.blocks
                    .push((format!("0x{fork}{b}"), B256::with_last_byte(b as u8)));
            }
        }
        fn truncate(&mut self, n: u64) {
            self.blocks.truncate(n as usize);
        }
        fn values(&self, block: u64) -> Vec<(u64, u64)> {
            self.storage.get(&block).cloned().unwrap_or_default()
        }
    }

    impl Node for FakeNode {
        fn head(&mut self) -> Result<u64, String> {
            self.up
                .then_some(self.blocks.len() as u64)
                .ok_or_else(|| "down".into())
        }
        fn hash(&mut self, n: u64) -> Result<Option<String>, String> {
            Ok(n.checked_sub(1)
                .and_then(|i| self.blocks.get(i as usize))
                .map(|b| b.0.clone()))
        }
        fn state_root(&mut self, n: u64) -> Result<B256, String> {
            n.checked_sub(1)
                .and_then(|i| self.blocks.get(i as usize))
                .map(|b| b.1)
                .ok_or_else(|| "no block".into())
        }
        fn storage(&mut self, a: &str, s: &[u64], b: u64) -> Result<trie_ref::Storage, String> {
            self.reads.push((a.to_string(), b));
            let set = self.values(b);
            Ok(s.iter()
                .map(|s| {
                    let v = set.iter().find(|(k, _)| k == s).map_or(0, |(_, v)| *v);
                    (*s, U256::from(v))
                })
                .collect())
        }
        fn proof(&mut self, _: &str, s: &[u64], b: u64) -> Result<AccountProof, String> {
            if b as usize > self.blocks.len() {
                return Err("no block".into());
            }
            Ok(trie_ref::tests::honest_proof(ADDR, &self.values(b), s).1)
        }
        fn multiproof(&mut self, a: &str, s: &[u64], b: u64) -> Result<AccountProof, String> {
            match self.multiproofs.get(&b) {
                Some(p) => Ok(p.clone()),
                None => self.proof(a, s, b),
            }
        }
    }

    fn ev(kind: &str) -> DstEvent {
        DstEvent {
            source: "nemesis".into(),
            kind: kind.into(),
            container: Some(NODE_CONTAINER.into()),
            guest_time_ns: 0,
            detail: Value::Null,
        }
    }

    fn sigs(v: &[Verdict]) -> Vec<(bool, &str)> {
        v.iter()
            .map(|v| match v {
                Verdict::Always(ok, f) | Verdict::Sometimes(ok, f) => (*ok, f.signature.as_str()),
            })
            .collect()
    }

    fn failures(v: &[Verdict]) -> Vec<&str> {
        sigs(v)
            .into_iter()
            .filter(|(ok, _)| !ok)
            .map(|(_, s)| s)
            .collect()
    }

    fn trie_reference() -> Reference {
        Reference::new(10, Vec::new()).with_trie(Some(TrieConfig {
            address: ADDR.into(),
            slots: SLOTS.to_vec(),
            ..Default::default()
        }))
    }

    #[test]
    fn scans_reference_logs_as_e7() {
        let bad = "WARN consensus::engine: Bad block with hash invalid_ancestor=0x1";
        assert_eq!(scan_line(bad).unwrap().signature, "E7/reference-bad-block");
        let root = "WARN engine::tree: Invalid block error on new payload invalid_number=7 validation_err=mismatched block state root";
        assert_eq!(
            scan_line(root).unwrap().signature,
            "E7/reference-state-root-mismatch"
        );
        let rejected = "WARN engine::tree: Invalid block error on new payload invalid_number=7 validation_err=gas";
        assert_eq!(
            scan_line(rejected).unwrap().signature,
            "E7/reference-rejected"
        );
        // The debug consensus client while the primary is down.
        let poll = "ERROR alloy_rpc_client::poller: failed to poll err=error sending request";
        assert_eq!(scan_line(poll), None);
    }

    #[test]
    fn synced_reference_is_compared_and_covered() {
        let mut o = Reference::new(10, Vec::new());
        let mut p = FakeNode::chain(20, "a");
        let mut r = FakeNode::chain(20, "a");
        assert_eq!(
            sigs(&o.tick(&mut p, &mut r, S)),
            [(true, "S/reference-compared"), (true, "S/reference-synced")]
        );
        p.extend(25, "a");
        r.extend(24, "a");
        assert!(o.tick(&mut p, &mut r, 2 * S).is_empty());
    }

    #[test]
    fn lagging_reference_stalls_once_per_episode() {
        let mut o = Reference::new(10, Vec::new());
        let mut p = FakeNode::chain(100, "a");
        let mut r = FakeNode::chain(50, "a");
        assert!(failures(&o.tick(&mut p, &mut r, S)).is_empty());
        assert!(failures(&o.tick(&mut p, &mut r, 5 * S)).is_empty());
        assert_eq!(
            failures(&o.tick(&mut p, &mut r, 12 * S)),
            ["E7/reference-stalled"]
        );
        assert!(failures(&o.tick(&mut p, &mut r, 30 * S)).is_empty());
        // Catching up within MAX_LAG ends the episode.
        r.extend(100 - MAX_LAG, "a");
        assert!(failures(&o.tick(&mut p, &mut r, 31 * S)).is_empty());
        r.up = false;
        o.tick(&mut p, &mut r, 32 * S);
        assert_eq!(
            failures(&o.tick(&mut p, &mut r, 43 * S)),
            ["E7/reference-stalled"]
        );
    }

    #[test]
    fn primary_downtime_is_not_a_stall() {
        let mut o = Reference::new(10, Vec::new());
        let mut p = FakeNode::chain(100, "a");
        let mut r = FakeNode::chain(100, "a");
        o.tick(&mut p, &mut r, S);
        o.on_event(&ev("kill"));
        p.up = false;
        assert!(o.tick(&mut p, &mut r, 50 * S).is_empty());
        o.on_event(&ev("restart"));
        p.up = true;
        p.extend(200, "a");
        // The restart restarts the clock.
        assert!(failures(&o.tick(&mut p, &mut r, 51 * S)).is_empty());
        r.extend(200, "a");
        assert_eq!(
            sigs(&o.tick(&mut p, &mut r, 55 * S)),
            [(true, "S/reference-followed-restart")]
        );
    }

    #[test]
    fn primary_pause_is_not_a_stall() {
        let mut o = Reference::new(10, Vec::new());
        let mut p = FakeNode::chain(100, "a");
        let mut r = FakeNode::chain(70, "a");
        // Already behind when the primary freezes.
        assert!(failures(&o.tick(&mut p, &mut r, S)).is_empty());
        o.on_event(&ev("pause"));
        assert!(o.tick(&mut p, &mut r, 30 * S).is_empty());
        o.on_event(&ev("resume"));
        // The resume restarts the clock.
        assert!(failures(&o.tick(&mut p, &mut r, 31 * S)).is_empty());
        p.extend(105, "a");
        r.extend(105, "a");
        let v = o.tick(&mut p, &mut r, 33 * S);
        assert!(failures(&v).is_empty());
        assert!(sigs(&v).contains(&(true, "S/reference-followed-restart")));
        // A reference that never catches up after the resume still stalls.
        o.on_event(&ev("pause"));
        o.on_event(&ev("resume"));
        p.extend(200, "a");
        o.tick(&mut p, &mut r, 40 * S);
        assert_eq!(
            failures(&o.tick(&mut p, &mut r, 51 * S)),
            ["E7/reference-stalled"]
        );
    }

    #[test]
    fn reorg_after_primary_restart_is_tolerated() {
        // The primary unwinds 95..100 on restart and rebuilds them; the
        // reference still has the old blocks until it reorgs.
        let mut o = Reference::new(10, Vec::new());
        let mut p = FakeNode::chain(100, "a");
        let mut r = FakeNode::chain(100, "a");
        o.tick(&mut p, &mut r, S);
        o.on_event(&ev("kill"));
        o.on_event(&ev("restart"));
        p.truncate(94);
        p.extend(98, "b");
        assert!(failures(&o.tick(&mut p, &mut r, 2 * S)).is_empty());
        p.extend(102, "b");
        assert!(failures(&o.tick(&mut p, &mut r, 8 * S)).is_empty());
        r.truncate(94);
        r.extend(102, "b");
        assert_eq!(
            sigs(&o.tick(&mut p, &mut r, 11 * S)),
            [(true, "S/reference-followed-restart")]
        );
    }

    #[test]
    fn persistent_divergence_is_reported() {
        let mut o = Reference::new(10, Vec::new());
        let mut p = FakeNode::chain(50, "a");
        let mut r = FakeNode::chain(50, "a");
        o.tick(&mut p, &mut r, S);
        // The reference sticks to its own block 51 (e.g. it rejected the
        // primary's), with the same state root: only the hash differs.
        p.extend(60, "a");
        r.extend(51, "x");
        r.blocks[50].1 = p.blocks[50].1;
        assert!(failures(&o.tick(&mut p, &mut r, 2 * S)).is_empty());
        assert_eq!(
            failures(&o.tick(&mut p, &mut r, 13 * S)),
            ["E7/block-hash-differs"]
        );
        assert!(failures(&o.tick(&mut p, &mut r, 30 * S)).is_empty());

        let mut o = Reference::new(10, Vec::new());
        r.blocks[50].1 = B256::repeat_byte(9);
        o.tick(&mut p, &mut r, S);
        assert_eq!(
            failures(&o.tick(&mut p, &mut r, 12 * S)),
            ["E7/state-root-differs"]
        );
    }

    #[test]
    fn same_header_different_state_root_fails_at_once() {
        let mut o = Reference::new(10, Vec::new());
        let mut p = FakeNode::chain(5, "a");
        let mut r = FakeNode::chain(5, "a");
        r.blocks[4].1 = B256::repeat_byte(7);
        assert!(failures(&o.tick(&mut p, &mut r, S)).contains(&"E7/state-root-differs"));
    }

    #[test]
    fn agreeing_tries_pass() {
        let mut o = trie_reference();
        let mut p = FakeNode::chain(3, "a");
        p.storage.insert(2, vec![(544, 1)]);
        p.storage.insert(3, vec![(544, 1), (646, 2)]);
        let mut r = p.clone();
        assert!(failures(&o.tick(&mut p, &mut r, S)).is_empty());
    }

    #[test]
    fn differing_storage_is_reported_on_every_rpc() {
        let mut o = trie_reference();
        let mut p = FakeNode::chain(3, "a");
        p.storage.insert(3, vec![(544, 1)]);
        let mut r = p.clone();
        r.storage.insert(3, vec![(544, 1), (646, 1)]);
        let v = o.tick(&mut p, &mut r, S);
        let details: Vec<_> = v
            .iter()
            .filter_map(|v| match v {
                Verdict::Always(false, f) => Some(f.detail.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(failures(&v), ["E7/proof-differs"; 4], "{details:?}");
        for what in [
            "eth_getProof storageHash",
            "eth_getProof values",
            "eth_getMultiProof storageHash",
            "eth_getStorageAt",
        ] {
            assert!(
                details
                    .iter()
                    .any(|d| d.starts_with(&format!("block 3: {what}"))),
                "{details:?}"
            );
        }
    }

    #[test]
    fn multiproof_only_difference_is_reported() {
        let mut o = trie_reference();
        let mut p = FakeNode::chain(2, "a");
        p.storage.insert(2, vec![(544, 1)]);
        let mut r = p.clone();
        let (_, other) = trie_ref::tests::honest_proof(ADDR, &[(646, 1)], &SLOTS);
        r.multiproofs.insert(2, other);
        let v = o.tick(&mut p, &mut r, S);
        assert_eq!(failures(&v), ["E7/proof-differs"]);
        assert!(
            matches!(&v[..], [.., Verdict::Always(false, f)] if f.detail.contains("eth_getMultiProof")),
            "{v:?}"
        );
    }

    #[test]
    fn proofs_are_compared_only_on_agreed_blocks_and_swept() {
        let mut o = trie_reference();
        let mut p = FakeNode::chain(300, "a");
        // Every older block differs on the reference.
        let mut r = p.clone();
        for b in 1..=290 {
            r.storage.insert(b, vec![(646, 1)]);
        }
        let mut bad = std::collections::BTreeSet::new();
        for t in 0..300u64 {
            for v in o.tick(&mut p, &mut r, (t + 1) * S) {
                if let Verdict::Always(false, f) = v {
                    bad.insert(f.detail.split(':').next().unwrap().to_string());
                }
            }
        }
        // As in E5/E6: the deep and shallow sweeps cover blocks 50..=290.
        assert_eq!(bad.len(), 241, "{bad:?}");

        // A diverged reference compares no proofs.
        let mut o = trie_reference();
        let mut r = FakeNode::chain(300, "x");
        r.storage.insert(300, vec![(646, 1)]);
        assert!(!failures(&o.tick(&mut p, &mut r, S)).contains(&"E7/proof-differs"));
    }

    #[test]
    fn every_contract_is_compared_at_the_newest_common_block() {
        let addrs = [
            ADDR,
            "0xfbfbfddd6e35da57b7b0f9a2c10e34be70b3a4e9",
            "0x72bb9c7ffbe2ed234e53bc64862dda6d9fff333b",
        ];
        let mut o = Reference::new(10, Vec::new()).with_tries(
            addrs
                .iter()
                .map(|a| TrieConfig {
                    address: a.to_string(),
                    slots: SLOTS.to_vec(),
                    ..Default::default()
                })
                .collect(),
        );
        let mut p = FakeNode::chain(300, "a");
        let mut r = p.clone();
        assert!(failures(&o.tick(&mut p, &mut r, S)).is_empty());
        for node in [&p, &r] {
            let at_head = node.reads.iter().filter(|(_, b)| *b == 300).count();
            assert_eq!(at_head, addrs.len());
            // 9 new blocks below the head and one swept deep block: one
            // contract each, round-robin.
            assert_eq!(node.reads.len(), addrs.len() + 10);
            for a in addrs {
                assert!(node.reads.iter().any(|(x, b)| x == a && *b < 300));
            }
        }
        // A difference in the newest block names the contract it was read for.
        p.extend(301, "a");
        r.extend(301, "a");
        r.storage.insert(301, vec![(646, 1)]);
        let v = o.tick(&mut p, &mut r, 2 * S);
        let details: Vec<_> = v
            .iter()
            .filter_map(|v| match v {
                Verdict::Always(false, f) => Some(f.detail.clone()),
                _ => None,
            })
            .collect();
        for a in addrs {
            assert!(
                details.iter().any(|d| d.contains(&format!("contract {a}"))),
                "{details:?}"
            );
        }
    }
}
