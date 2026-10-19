// SPDX-License-Identifier: GPL-2.0

//! Online oracles over the node's log stream, the DST event stream, and RPC:
//!
//! - E1 log scanner: panics, consensus mismatches, trie-update differences,
//!   engine/persistence failures, and ERROR-level lines.
//! - E2 liveness: the head advances within `liveness_secs` while the node is up
//!   and not paused or CPU-throttled by the nemesis; the clock restarts when
//!   such a window ends, so a node that does not recover still fails.
//! - E5 storage trie: a RawStorage contract's storage root (`eth_getProof`)
//!   equals a root rebuilt from scratch from its slot values, at every block.
//! - E6 proofs: that `eth_getProof` response verifies against the block's
//!   state root, and proves the values `eth_getStorageAt` returns (see
//!   `trie_ref`).
//! - E8 TIP-20 ledger: holders' balances conserve the supply and are explained
//!   by each block's Transfer logs; pinned snapshots read the same later (see
//!   `tip20`).
//! - E3 durability: the block the node reported finalized before a kill keeps
//!   its hash after the restart, and the head returns to it. Unfinalized blocks
//!   may be rebuilt: reth's crash recovery unwinds to its persisted state-trie
//!   frontier, which can trail the "Saved range of blocks" frontier.
//! - E9 chain of blocks: a ChainOfBlocks contract's hash chain, rebuilt from
//!   receipts, matches its state at every block and survives restarts (see
//!   `cob`).
//! - E7 reference node: see `reference`.
//! - E11 durable history (`storage_faults=true`): see `durable`.
//!
//! [`Oracle`] is a pure state machine; [`run`] feeds it from the guest.

use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use alloy_primitives::{Address, B256, U256};
use bedrock_assertions::Condition;

use crate::{
    cob::CobOracle,
    common::{self, CobConfig, Config, DstEvent, TrieConfig, NODE_CONTAINER},
    tip20::{self, BlockRef, Ledger, Tip20Chain, Tip20Oracle, Transfer},
    trie_ref::{self, AccountProof, ProofError},
    verdict::{finding, strip_ansi, Finding, Verdict, LOG_PATTERNS},
    witness::{self, WitnessRpc},
};

const SAVED_BLOCKS: &str = "Saved range of blocks";

/// E1: the failing signature for one log line, if any.
pub fn scan_line(line: &str) -> Option<Finding> {
    let line = strip_ansi(line);
    let detail: String = line.chars().take(400).collect();
    if let Some((sig, _)) = LOG_PATTERNS.iter().find(|(_, p)| line.contains(p)) {
        return Some(Finding {
            signature: sig.to_string(),
            detail,
        });
    }
    // reth's default format: "<ts>  ERROR <spans>: <target>: <message>
    // <fields>", where spans (`name{fields}:name{..}`) may be absent.
    let rest = line.split_once(" ERROR ")?.1;
    let target = rest
        .split(": ")
        .find(|part| !part.contains('{') && !part.contains('}'))
        .unwrap_or("")
        .trim();
    Some(Finding {
        signature: format!("E1/error-log/{target}"),
        detail,
    })
}

/// Parses `last=NumHash { number: N, hash: 0x.. }` from a "Saved range of
/// blocks" line. Block data up to `last` is committed, but the state trie may
/// lag it, so a crash can still unwind these blocks (see E3).
pub fn parse_saved(line: &str) -> Option<(u64, String)> {
    let line = strip_ansi(line);
    if !line.contains(SAVED_BLOCKS) {
        return None;
    }
    let last = line.split_once("last=")?.1;
    let number = last.split_once("number: ")?.1;
    let digits: String = number.chars().take_while(char::is_ascii_digit).collect();
    let hash = last.split_once("hash: ")?.1;
    let hash: String = hash
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    Some((digits.parse().ok()?, hash.to_lowercase()))
}

/// Node queries; `Err` while the node is unreachable.
pub trait Chain: Tip20Chain {
    fn head(&mut self) -> Result<u64, String>;
    fn hash(&mut self, number: u64) -> Result<Option<String>, String>;
    fn finalized(&mut self) -> Result<Option<(u64, String)>, String>;
    fn storage(
        &mut self,
        address: &str,
        slots: &[u64],
        block: u64,
    ) -> Result<trie_ref::Storage, String>;
    /// `eth_getProof` (reth's legacy proof path).
    fn proof(&mut self, address: &str, slots: &[u64], block: u64) -> Result<AccountProof, String>;
    /// `eth_getMultiProof` (reth's proof v2 path).
    fn multiproof(
        &mut self,
        address: &str,
        slots: &[u64],
        block: u64,
    ) -> Result<AccountProof, String>;
    fn state_root(&mut self, block: u64) -> Result<B256, String>;
    fn tx_count(&mut self, block: u64) -> Result<u64, String>;
    /// `debug_executionWitness` (E6/witness-*). Defaults to "unavailable" so a
    /// node (or test chain) without it is simply skipped, not failed.
    fn execution_witness(&mut self, _block: u64) -> WitnessRpc {
        WitnessRpc::Unavailable
    }
    /// `eth_getStorageAt` for a full 32-byte slot (E9's mapping slots).
    fn storage_word(&mut self, _address: &str, _slot: B256, _block: u64) -> Result<B256, String> {
        Err("storage_word unsupported".into())
    }
    /// `eth_getLogs` of `address` with first topic `topic` in `from..=to`.
    fn logs(
        &mut self,
        _address: &str,
        _topic: B256,
        _from: u64,
        _to: u64,
    ) -> Result<Vec<common::Log>, String> {
        Err("logs unsupported".into())
    }
}

/// Blocks E5/E6 check per tick, newest last; older unchecked blocks are skipped.
pub(crate) const TRIE_BLOCKS_PER_TICK: u64 = 10;

/// E5/E6 also re-check two older blocks each tick, at depths that sweep these
/// ranges: shallow blocks straddle the persisted state-trie frontier (state
/// masking keeps it behind the persisted block tip); deep ones are served from
/// the persisted trie with the newer blocks reverted in an overlay. Needs
/// `--rpc.eth-proof-window` above the deep range.
pub(crate) const SHALLOW_DEPTHS: (u64, u64) = (2, 48);
pub(crate) const DEEP_DEPTHS: (u64, u64) = (49, 250);

/// The `tick`th depth in `lo..=hi`; a stride coprime to the range length
/// visits every depth once per cycle.
pub(crate) fn sweep_depth((lo, hi): (u64, u64), tick: u64) -> u64 {
    let len = hi - lo + 1;
    let stride = (1..len)
        .rev()
        .find(|s| gcd(*s, len) == 1 && *s < len / 2 + 1)
        .unwrap_or(1);
    lo + tick.wrapping_mul(stride) % len
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// `(signature, detail)`.
pub(crate) type Failure = (String, String);

/// Contracts (indices into `n` of them) E5/E6/E7 check at `block` when
/// `newest` is the newest block of the tick: every contract at `newest`, one
/// at any other block (new blocks below the newest, and the swept older
/// ones), taken round-robin from `cursor`. RPC cost per tick is then about
/// `n + TRIE_BLOCKS_PER_TICK + 1` contract checks instead of `n` times
/// that; every contract is still checked at every tick's newest block, and
/// it gets every `n`th older block, so each contract's depth sweep covers its
/// ranges about `n` times slower. One contract is checked at every block.
pub(crate) fn trie_targets(n: usize, block: u64, newest: u64, cursor: &mut usize) -> Vec<usize> {
    if block == newest || n <= 1 {
        return (0..n).collect();
    }
    let c = *cursor % n;
    *cursor = cursor.wrapping_add(1);
    vec![c]
}

/// `contract <address>, ` in failure details when there are several
/// contracts; empty with one (the single-contract load's details).
pub(crate) fn contract_note(tries: &[TrieConfig], c: usize) -> String {
    if tries.len() > 1 {
        format!("contract {}, ", tries[c].address)
    } else {
        String::new()
    }
}

/// One contract's E5/E6 result at one block.
struct TrieCheck {
    /// Slots with non-zero values.
    live: Vec<u64>,
    failures: Vec<Failure>,
    /// The node's storage root (`eth_getProof`).
    storage_hash: B256,
}

/// E5 and E6 for one block: the contract's live slots, and failures as
/// `(signature, detail)`; `None` while the node is unreachable.
///
/// Both proof RPCs are checked, `eth_getProof` and reth's `eth_getMultiProof`
/// (signatures `E5/multiproof-*`, `E6/multiproof-*`): they build proofs on
/// different code paths. An `eth_getProof` without storage targets is checked
/// too (`E5/untargeted-*`, `E6/untargeted-*`): targets make the node recompute
/// their paths, which can mask a stale node elsewhere in the trie.
fn check_trie_block(chain: &mut impl Chain, trie: &TrieConfig, block: u64) -> Option<TrieCheck> {
    let storage = chain.storage(&trie.address, &trie.slots, block).ok()?;
    let state_root = chain.state_root(block).ok()?;
    let proofs = [
        ("", chain.proof(&trie.address, &trie.slots, block).ok()?),
        (
            "multiproof-",
            chain.multiproof(&trie.address, &trie.slots, block).ok()?,
        ),
        ("untargeted-", chain.proof(&trie.address, &[], block).ok()?),
    ];
    let live = storage
        .iter()
        .filter(|(_, v)| !v.is_zero())
        .map(|(s, _)| *s)
        .collect();
    let reference = trie_ref::storage_root(&storage);
    let read: Vec<(U256, U256)> = storage.iter().map(|(s, v)| (U256::from(*s), *v)).collect();
    let mut failures = Vec::new();
    for (rpc, proof) in &proofs {
        let mut fail = |oracle: &str, kind: &str, detail: String| {
            failures.push((format!("{oracle}/{rpc}{kind}"), detail));
        };
        if reference != proof.storage_hash {
            fail(
                "E5",
                "storage-root-mismatch",
                format!("reference {reference}, node {}", proof.storage_hash),
            );
        }
        match trie_ref::verify(proof, state_root) {
            Ok(()) => {}
            Err(ProofError::Account(e)) => fail(
                "E6",
                "account-proof-invalid",
                format!(
                    "state root {state_root}, storage hash {}: {e}",
                    proof.storage_hash
                ),
            ),
            Err(ProofError::Storage { slot, error }) => fail(
                "E6",
                "storage-proof-invalid",
                format!("slot {slot}, storage hash {}: {error}", proof.storage_hash),
            ),
        }
        let proven: Vec<(U256, U256)> = proof
            .storage_proof
            .iter()
            .map(|p| (p.key, p.value))
            .collect();
        if !(rpc.starts_with("untargeted") && proven.is_empty()) && proven != read {
            fail(
                "E6",
                "proof-value-mismatch",
                format!("proven {proven:?}, eth_getStorageAt {read:?}"),
            );
        }
    }
    Some(TrieCheck {
        live,
        failures,
        storage_hash: proofs[0].1.storage_hash,
    })
}

#[derive(Debug)]
pub struct Oracle {
    /// E2 head-stall and E3 reach-finalized budget; `None` disables both
    /// (the cluster judges liveness with E16 instead).
    liveness_ns: Option<u64>,
    /// Latest "Saved range of blocks" frontier.
    saved: Option<(u64, String)>,
    /// Latest finalized block seen while the node was up.
    finalized: Option<(u64, String)>,
    /// Head and when it last advanced.
    head: Option<u64>,
    progress_ns: u64,
    stall_reported: bool,
    /// Node killed and not yet restarted.
    down: bool,
    /// Finalized block captured at the last kill, awaiting verification.
    pending_finalized: Option<(u64, String)>,
    /// Saved frontier captured at the last kill, for the rewind coverage signal.
    pending_saved: Option<(u64, String)>,
    /// Head when the last kill happened, for the recovery coverage signal.
    head_at_kill: Option<u64>,
    restart_ns: u64,
    /// Contracts checked by E5/E6 (see [`Oracle::check_trie`]), and the last
    /// block checked.
    tries: Vec<TrieConfig>,
    trie_checked: u64,
    /// Round-robin cursor over `tries` for blocks below the newest.
    trie_cursor: usize,
    trie_seen_multi: bool,
    /// Last block `check_multi` compared with its parent.
    multi_checked: u64,
    trie_seen_all: bool,
    /// Contract checks so far, per contract (logged to oracle.log).
    trie_counts: Vec<u64>,
    trie_seen_full: bool,
    trie_seen_check: bool,
    /// `check_trie` calls, which advance the depth sweep.
    trie_ticks: u64,
    /// `debug_executionWitness` is absent (method not found): latched after the
    /// first `S/execution-witness-unsupported`, so it is not retried.
    witness_unsupported: bool,
    /// `S/execution-witness-verified` emitted once.
    witness_verified: bool,
    /// `S/execution-witness-empty` emitted once.
    witness_empty: bool,
    /// A block produced during the run included a transaction.
    load_seen: bool,
    /// E8, with the TIP-20 load.
    tip20: Option<Tip20Oracle>,
    /// E9 over the chain-of-blocks contract.
    cob: Option<CobOracle>,
    /// Inside a storage-fault window (until the restart that ends it): the
    /// node may fail when a torn write crashes its file system, so E1 findings are
    /// coverage, not failures.
    storage_window: bool,
    storage_fault_seen: bool,
    /// Frozen by a nemesis pause (until its resume): no checks, like downtime.
    paused: bool,
    /// Head at the last pause, until the head passes it after the resume.
    head_at_pause: Option<u64>,
    /// Inside a nemesis CPU throttle: E2 is excused, other checks run.
    throttled: bool,
    /// Head at the last throttle's end, until the head passes it.
    head_at_throttle_end: Option<u64>,
    /// The node is down for (or restarted from) a graceful stop.
    graceful: bool,
}

impl Oracle {
    /// A fresh online oracle at guest time `now_ns`, for the configured
    /// contracts and liveness budget (`liveness_secs` as in
    /// [`Oracle::liveness_ns`]).
    pub fn new(liveness_secs: Option<u64>, now_ns: u64, tries: Vec<TrieConfig>) -> Oracle {
        Oracle {
            liveness_ns: liveness_secs.map(|s| s * 1_000_000_000),
            saved: None,
            finalized: None,
            head: None,
            progress_ns: now_ns,
            stall_reported: false,
            down: false,
            pending_finalized: None,
            pending_saved: None,
            head_at_kill: None,
            restart_ns: now_ns,
            tries,
            trie_checked: 0,
            trie_cursor: 0,
            trie_seen_multi: false,
            multi_checked: 0,
            trie_seen_all: false,
            trie_counts: Vec::new(),
            trie_seen_full: false,
            trie_seen_check: false,
            trie_ticks: 0,
            witness_unsupported: false,
            witness_verified: false,
            witness_empty: false,
            load_seen: false,
            tip20: None,
            cob: None,
            storage_window: false,
            storage_fault_seen: false,
            paused: false,
            head_at_pause: None,
            throttled: false,
            head_at_throttle_end: None,
            graceful: false,
        }
    }

    /// A pause or throttle ended: liveness is judged afresh from now.
    fn restart_liveness_clock(&mut self, now_ns: u64) {
        self.progress_ns = now_ns;
        self.stall_reported = false;
    }

    /// A storage-fault window opens (see [`Oracle::storage_window`]). Called
    /// before the tick's log lines are scanned when the tick's events open
    /// one, so the node's reaction to the fault is excused.
    pub fn open_storage_window(&mut self) {
        self.storage_window = true;
    }

    pub fn with_tip20(mut self, enabled: bool) -> Oracle {
        self.tip20 = enabled.then(Tip20Oracle::default);
        self
    }

    pub fn with_cob(mut self, cob: Option<CobConfig>) -> Oracle {
        self.cob = cob.map(|c| CobOracle::new(&c.address));
        self
    }

    /// Supplies a single test contract before any checks run.
    #[cfg(test)]
    fn with_trie(self, trie: Option<TrieConfig>) -> Oracle {
        self.with_tries(trie.into_iter().collect())
    }

    /// Supplies test fixtures before any checks run.
    #[cfg(test)]
    fn with_tries(mut self, tries: Vec<TrieConfig>) -> Oracle {
        self.tries = tries;
        self
    }

    /// E5 and E6 for blocks after the last checked one, up to `head`, plus a
    /// shallow and a deep older block (see [`SHALLOW_DEPTHS`]). A rewind
    /// (head below the last checked block) re-checks the rebuilt blocks.
    ///
    /// With several contracts (see [`trie_targets`]), `head` is checked for
    /// every contract and each other block for one, round-robin; see
    /// [`Oracle::check_multi`] for `S/multi-contract-block`.
    fn check_trie(&mut self, chain: &mut impl Chain, head: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        if self.tries.is_empty() {
            return out;
        }
        let tries = self.tries.clone();
        self.trie_counts.resize(tries.len(), 0);
        if head < self.trie_checked {
            self.trie_checked = head.saturating_sub(1);
        }
        let first = (self.trie_checked + 1).max(head.saturating_sub(TRIE_BLOCKS_PER_TICK - 1));
        let tick = self.trie_ticks;
        self.trie_ticks += 1;
        let older: Vec<u64> = [SHALLOW_DEPTHS, DEEP_DEPTHS]
            .into_iter()
            .filter_map(|range| head.checked_sub(sweep_depth(range, tick)))
            .filter(|b| *b > 0 && *b < first)
            .collect();
        for block in older.into_iter().chain(first..=head) {
            let mut roots = Vec::new();
            let targets = trie_targets(tries.len(), block, head, &mut self.trie_cursor);
            for &c in &targets {
                let trie = &tries[c];
                let Some(checked) = check_trie_block(chain, trie, block) else {
                    return out;
                };
                roots.push(checked.storage_hash);
                self.trie_counts[c] += 1;
                if checked.failures.is_empty() && !self.trie_seen_check {
                    self.trie_seen_check = true;
                    out.push(Verdict::Sometimes(
                        true,
                        finding("S/trie-checked", String::new()),
                    ));
                }
                let live = &checked.live;
                for (signature, detail) in checked.failures {
                    out.push(Verdict::Always(
                        false,
                        finding(
                            &signature,
                            format!(
                                "block {block}: {}live slots {live:?}, {detail}",
                                contract_note(&tries, c)
                            ),
                        ),
                    ));
                }
                if live.len() == trie.slots.len() && !self.trie_seen_full {
                    self.trie_seen_full = true;
                    out.push(Verdict::Sometimes(
                        true,
                        finding("S/trie-all-slots-live", format!("block {block}")),
                    ));
                }
            }
            out.extend(self.check_witness(chain, &tries, block, &targets));
            if block == head && tries.len() > 1 && !self.trie_seen_all {
                self.trie_seen_all = true;
                out.push(Verdict::Sometimes(
                    true,
                    finding(
                        "S/trie-all-contracts-checked",
                        format!("block {head}: {} contracts", tries.len()),
                    ),
                ));
            }
            if block >= first {
                self.trie_checked = block;
            }
        }
        out.extend(self.check_multi(chain, head));
        if tick.is_multiple_of(30) {
            eprintln!(
                "trie: tick {tick} head {head}: checks per contract {:?}",
                self.trie_counts
            );
        }
        out
    }

    /// `S/multi-contract-block`: until seen, every new block's contract
    /// roots (untargeted `eth_getProof`) against its parent's, so the first
    /// block of a load generation (the writers' burst) is not missed between
    /// ticks. About N proofs per new block, only until it is seen.
    fn check_multi(&mut self, chain: &mut impl Chain, head: u64) -> Vec<Verdict> {
        if self.tries.len() < 2 || self.trie_seen_multi {
            return Vec::new();
        }
        if head < self.multi_checked {
            self.multi_checked = head.saturating_sub(1);
        }
        let first = (self.multi_checked + 1)
            .max(head.saturating_sub(TRIE_BLOCKS_PER_TICK - 1))
            .max(2);
        let tries = self.tries.clone();
        let roots = |chain: &mut _, block| -> Option<Vec<B256>> {
            tries
                .iter()
                .map(|t| {
                    Chain::proof(chain, &t.address, &[], block)
                        .ok()
                        .map(|p| p.storage_hash)
                })
                .collect()
        };
        // Reused only within the tick: a rewind may rebuild a block.
        let mut prev: Option<(u64, Vec<B256>)> = None;
        for block in first..=head {
            let parent = match prev.take() {
                Some((n, r)) if n + 1 == block => r,
                _ => match roots(chain, block - 1) {
                    Some(r) => r,
                    None => return Vec::new(),
                },
            };
            let Some(cur) = roots(chain, block) else {
                return Vec::new();
            };
            let changed: Vec<&str> = tries
                .iter()
                .zip(parent.iter().zip(&cur))
                .filter(|(_, (a, b))| a != b)
                .map(|(t, _)| t.address.as_str())
                .collect();
            self.multi_checked = block;
            if changed.len() >= 2 {
                self.trie_seen_multi = true;
                return vec![Verdict::Sometimes(
                    true,
                    finding(
                        "S/multi-contract-block",
                        format!("block {block}: contracts {changed:?}"),
                    ),
                )];
            }
            prev = Some((block, cur));
        }
        Vec::new()
    }

    /// E6/witness-*: `debug_executionWitness` at `block` proves the sampled
    /// contracts' pre-execution (parent-block) accounts and slots against the
    /// parent state root, independently of `eth_getProof` (see [`crate::witness`]).
    ///
    /// Capability-gated: a node whose debug namespace is off records
    /// `S/execution-witness-unsupported` once and is not retried, so a run
    /// against such a node is explained rather than failed. `targets` and their
    /// slots are the same deterministic sample the E5/E6 path uses.
    fn check_witness(
        &mut self,
        chain: &mut impl Chain,
        tries: &[TrieConfig],
        block: u64,
        targets: &[usize],
    ) -> Vec<Verdict> {
        let mut out = Vec::new();
        if block == 0 || self.witness_unsupported || targets.is_empty() {
            return out;
        }
        let witness = match chain.execution_witness(block) {
            WitnessRpc::Ok(w) => w,
            WitnessRpc::Unsupported => {
                self.witness_unsupported = true;
                out.push(Verdict::Sometimes(
                    true,
                    finding(
                        "S/execution-witness-unsupported",
                        format!("debug_executionWitness unavailable at block {block}"),
                    ),
                ));
                return out;
            }
            WitnessRpc::Unavailable => return out,
        };
        if witness.state.is_empty() {
            if !self.witness_empty {
                self.witness_empty = true;
                out.push(Verdict::Sometimes(
                    true,
                    finding("S/execution-witness-empty", format!("block {block}")),
                ));
            }
            return out;
        }
        // The witness proves the pre-execution state, so it is anchored at the
        // parent block's state root.
        let Ok(parent_root) = chain.state_root(block - 1) else {
            return out;
        };
        let nodes = witness::node_map(&witness);
        // Check A: the parent state root node is present.
        if !nodes.contains_key(&parent_root) {
            out.push(Verdict::Always(
                false,
                finding(
                    "E6/witness-root-missing",
                    format!(
                        "block {block}: parent state root {parent_root} absent from witness ({} nodes)",
                        nodes.len()
                    ),
                ),
            ));
            return out;
        }
        let codes = witness::code_hashes(&witness);
        for &c in targets {
            let trie = &tries[c];
            // Ground truth: the node's own proof at the parent block.
            let Ok(parent_proof) = chain.proof(&trie.address, &trie.slots, block - 1) else {
                continue;
            };
            let report = witness::check_account(&nodes, parent_root, &parent_proof, &codes);
            if report.verified && !self.witness_verified {
                self.witness_verified = true;
                out.push(Verdict::Sometimes(
                    true,
                    finding(
                        "S/execution-witness-verified",
                        format!(
                            "block {block}: {}account proven from witness",
                            contract_note(tries, c)
                        ),
                    ),
                ));
            }
            for (signature, detail) in report.failures {
                out.push(Verdict::Always(
                    false,
                    finding(
                        &signature,
                        format!("block {block}: {}{detail}", contract_note(tries, c)),
                    ),
                ));
            }
        }
        out
    }

    pub fn on_log(&mut self, line: &str) -> Vec<Verdict> {
        if let Some(saved) = parse_saved(line) {
            if let Some(t) = &mut self.tip20 {
                t.on_saved(saved.0);
            }
            self.saved = Some(saved);
            return Vec::new();
        }
        let Some(f) = scan_line(line) else {
            return Vec::new();
        };
        if self.storage_window {
            if self.storage_fault_seen {
                return Vec::new();
            }
            self.storage_fault_seen = true;
            return vec![Verdict::Sometimes(
                true,
                finding(
                    "S/storage-fault-surfaced",
                    format!("{}: {}", f.signature, f.detail),
                ),
            )];
        }
        vec![Verdict::Always(false, f)]
    }

    pub fn on_event(&mut self, ev: &DstEvent, now_ns: u64) -> Vec<Verdict> {
        if ev.source != "nemesis" || ev.container.as_deref() != Some(NODE_CONTAINER) {
            return Vec::new();
        }
        match ev.kind.as_str() {
            "storage-fault" => {
                self.storage_window = true;
                Vec::new()
            }
            "pause" => {
                self.paused = true;
                self.head_at_pause = Some(self.head.unwrap_or(0));
                Vec::new()
            }
            "resume" => {
                self.paused = false;
                self.restart_liveness_clock(now_ns);
                Vec::new()
            }
            "throttle" => {
                self.throttled = true;
                Vec::new()
            }
            "throttle-end" => {
                self.throttled = false;
                self.head_at_throttle_end = Some(self.head.unwrap_or(0));
                self.restart_liveness_clock(now_ns);
                Vec::new()
            }
            // "down": the node had already stopped (fail-stop in a
            // storage-fault window) when the nemesis crashed the machine.
            // "stop": a graceful stop, restarted like a kill.
            "kill" | "down" | "stop" => {
                self.down = true;
                self.graceful = ev.kind == "stop";
                if let Some(cob) = self.cob.as_mut() {
                    cob.on_kill();
                }
                self.pending_finalized = self.finalized.clone();
                self.pending_saved = self.saved.clone();
                self.head_at_kill = self.head;
                let signature = if self.graceful {
                    "S/graceful-stop"
                } else {
                    "S/kill"
                };
                vec![Verdict::Sometimes(
                    true,
                    finding(
                        signature,
                        format!("finalized={:?} saved={:?}", self.finalized, self.saved),
                    ),
                )]
            }
            "restart" => {
                self.down = false;
                self.storage_window = false;
                if let Some(t) = &mut self.tip20 {
                    t.on_restart();
                }
                if let Some(cob) = self.cob.as_mut() {
                    cob.on_restart();
                }
                self.restart_ns = now_ns;
                self.progress_ns = now_ns;
                self.stall_reported = false;
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    pub fn tick(&mut self, chain: &mut impl Chain, now_ns: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        if self.down || self.paused {
            return out;
        }
        if let Ok(head) = chain.head() {
            if self.head.is_some_and(|h| head > h)
                && !self.load_seen
                && chain.tx_count(head).is_ok_and(|n| n > 0)
            {
                self.load_seen = true;
                out.push(Verdict::Sometimes(
                    true,
                    finding("S/load-included", format!("block {head}")),
                ));
            }
            if self.head.is_none_or(|h| head > h) {
                self.progress_ns = now_ns;
                self.stall_reported = false;
                if let Some(k) = self.head_at_kill {
                    if head > k {
                        self.head_at_kill = None;
                        out.push(Verdict::Sometimes(
                            true,
                            finding(
                                "S/recovered",
                                format!("head {head} passed pre-kill head {k}"),
                            ),
                        ));
                        if std::mem::take(&mut self.graceful) {
                            out.push(Verdict::Sometimes(
                                true,
                                finding(
                                    "S/graceful-restart",
                                    format!("head {head} passed pre-stop head {k}"),
                                ),
                            ));
                        }
                    }
                }
                if let Some(p) = self.head_at_pause.filter(|p| head > *p) {
                    self.head_at_pause = None;
                    out.push(Verdict::Sometimes(
                        true,
                        finding(
                            "S/paused-recovered",
                            format!("head {head} passed pre-pause head {p}"),
                        ),
                    ));
                }
                if let Some(t) = self.head_at_throttle_end.filter(|t| head > *t) {
                    self.head_at_throttle_end = None;
                    out.push(Verdict::Sometimes(
                        true,
                        finding(
                            "S/throttled-recovered",
                            format!("head {head} passed head {t} at the throttle's end"),
                        ),
                    ));
                }
            }
            self.head = Some(head);
            out.extend(self.check_trie(chain, head));
            if let Some(t) = &mut self.tip20 {
                out.extend(t.tick(chain, head));
            }
            if let Some(cob) = self.cob.as_mut() {
                out.extend(cob.tick(chain, head));
            }
            if let Ok(Some(f)) = chain.finalized() {
                self.finalized = Some(f);
            }
            if let Some((n, want)) = self.pending_finalized.clone() {
                if head >= n {
                    if let Ok(got) = chain.hash(n) {
                        let ok = got.as_deref().map(str::to_lowercase).as_deref() == Some(&want);
                        out.push(Verdict::Always(
                            ok,
                            finding(
                                "E3/finalized-block-changed",
                                format!("block {n}: finalized {want}, after restart {got:?}"),
                            ),
                        ));
                        self.pending_finalized = None;
                    }
                }
            }
            if let Some((n, want)) = self.pending_saved.clone() {
                if head >= n {
                    if let Ok(got) = chain.hash(n) {
                        let rewound =
                            got.as_deref().map(str::to_lowercase).as_deref() != Some(&want);
                        out.push(Verdict::Sometimes(
                            rewound,
                            finding(
                                "S/rewound-unfinalized",
                                format!("saved block {n}: {want} -> {got:?}"),
                            ),
                        ));
                        self.pending_saved = None;
                    }
                }
            }
        }
        if let Some((n, _)) = &self.pending_finalized {
            if self
                .liveness_ns
                .is_some_and(|l| now_ns.saturating_sub(self.restart_ns) > l)
            {
                out.push(Verdict::Always(
                    false,
                    finding(
                        "E3/head-below-finalized",
                        format!(
                            "head {:?} never reached finalized block {n} after restart",
                            self.head
                        ),
                    ),
                ));
                self.pending_finalized = None;
            }
        }
        let stalled = self
            .liveness_ns
            .filter(|l| now_ns.saturating_sub(self.progress_ns) > *l);
        if let Some(liveness_ns) = stalled.filter(|_| !self.stall_reported && !self.throttled) {
            self.stall_reported = true;
            out.push(Verdict::Always(
                false,
                finding(
                    "E2/head-stalled",
                    format!(
                        "head {:?} did not advance for {}s",
                        self.head,
                        liveness_ns / 1_000_000_000
                    ),
                ),
            ));
        }
        out
    }
}

pub(crate) struct RpcChain;

impl Chain for RpcChain {
    fn head(&mut self) -> Result<u64, String> {
        common::head_number()
    }
    fn hash(&mut self, number: u64) -> Result<Option<String>, String> {
        common::block_hash(number)
    }
    fn finalized(&mut self) -> Result<Option<(u64, String)>, String> {
        common::finalized_block()
    }
    fn storage(
        &mut self,
        address: &str,
        slots: &[u64],
        block: u64,
    ) -> Result<trie_ref::Storage, String> {
        common::storage_at(address, slots, block)
    }
    fn proof(&mut self, address: &str, slots: &[u64], block: u64) -> Result<AccountProof, String> {
        common::proof(address, slots, block)
    }
    fn multiproof(
        &mut self,
        address: &str,
        slots: &[u64],
        block: u64,
    ) -> Result<AccountProof, String> {
        common::multiproof(address, slots, block)
    }
    fn state_root(&mut self, block: u64) -> Result<B256, String> {
        common::state_root(block)
    }
    fn tx_count(&mut self, block: u64) -> Result<u64, String> {
        common::tx_count(block)
    }
    fn execution_witness(&mut self, block: u64) -> WitnessRpc {
        common::execution_witness(block)
    }
    fn storage_word(&mut self, address: &str, slot: B256, block: u64) -> Result<B256, String> {
        common::storage_word(address, slot, block)
    }
    fn logs(
        &mut self,
        address: &str,
        topic: B256,
        from: u64,
        to: u64,
    ) -> Result<Vec<common::Log>, String> {
        common::logs(address, topic, from, to)
    }
}

fn word(out: &[u8]) -> Result<U256, String> {
    (out.len() == 32)
        .then(|| U256::from_be_slice(out))
        .ok_or_else(|| format!("expected one word, got {} bytes", out.len()))
}

fn balance_of(token: Address, holder: &Address) -> (Address, Vec<u8>) {
    // balanceOf(address)
    let mut data = vec![0x70, 0xa0, 0x82, 0x31];
    data.extend_from_slice(holder.into_word().as_slice());
    (token, data)
}

fn total_supply(token: Address) -> (Address, Vec<u8>) {
    (token, vec![0x18, 0x16, 0x0d, 0xdd])
}

impl Tip20Chain for RpcChain {
    fn block(&mut self, number: u64) -> Result<Option<BlockRef>, String> {
        Ok(common::block_ref(number)?.map(|(hash, parent)| BlockRef {
            number,
            hash,
            parent,
        }))
    }
    fn balances(
        &mut self,
        token: Address,
        holders: &[Address],
        block: B256,
    ) -> Result<Vec<U256>, String> {
        let calls: Vec<_> = holders.iter().map(|h| balance_of(token, h)).collect();
        common::calls_at(&calls, block)?
            .iter()
            .map(|r| word(r))
            .collect()
    }
    fn supply(&mut self, token: Address, block: B256) -> Result<U256, String> {
        word(&common::calls_at(&[total_supply(token)], block)?[0])
    }
    fn transfers(&mut self, token: Address, block: B256) -> Result<Vec<Transfer>, String> {
        Ok(common::block_logs(block)?
            .iter()
            .filter(|l| l.address == token)
            .filter_map(|l| Transfer::from_log(&l.topics, &l.data))
            .collect())
    }
    /// One batch: the supply and every balance at once.
    fn ledger(&mut self, block: B256) -> Result<Ledger, String> {
        let calls: Vec<_> = std::iter::once(total_supply(tip20::TOKEN))
            .chain(tip20::HOLDERS.iter().map(|h| balance_of(tip20::TOKEN, h)))
            .collect();
        let words = common::calls_at(&calls, block)?
            .iter()
            .map(|r| word(r))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Ledger {
            supply: words[0],
            balances: tip20::HOLDERS
                .iter()
                .copied()
                .zip(words[1..].iter().copied())
                .collect(),
        })
    }
}

pub(crate) fn record(verdicts: Vec<Verdict>) {
    for v in verdicts {
        match v {
            Verdict::Always(ok, f) => {
                common::assert_always(Condition::Bool(ok), "oracle", &f.signature, &f.detail)
            }
            Verdict::Sometimes(ok, f) => {
                common::assert_sometimes(Condition::Bool(ok), "oracle", &f.signature, &f.detail)
            }
        }
    }
}

/// Follows a container's output across restarts; journald keeps one stream
/// per container name.
pub(crate) fn follow_logs(container: &str, tx: mpsc::Sender<String>) {
    let child = Command::new("journalctl")
        .args(["-f", "-o", "cat", "--no-tail"])
        .arg(format!("CONTAINER_NAME={container}"))
        .stdout(Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        eprintln!("cannot spawn journalctl");
        return;
    };
    let stdout = child.stdout.take().expect("piped stdout");
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if tx.send(line).is_err() {
            break;
        }
    }
}

pub fn run() {
    let cfg = Config::load();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || follow_timestamped_logs(NODE_CONTAINER, tx));
    let mut oracle = Oracle::new(
        Some(cfg.liveness_secs),
        common::guest_time_ns(),
        cfg.tries(),
    )
    .with_tip20(cfg.tip20)
    .with_cob(cfg.cob.clone());
    let mut reference = crate::reference::start(&cfg);
    let mut follower = cfg
        .zones
        .then(|| crate::follower::FollowerOracle::new(cfg.liveness_secs, common::guest_time_ns()));
    // E3h, the historical-state-across-restart oracle (`historical=true`):
    // against the dev node itself. E7h needs a second node and so runs only in
    // the cluster path (see `cluster_live::run_oracle`).
    let mut across = cfg.historical.then(|| {
        crate::historical::AcrossRestart::new(cfg.seed, crate::historical::Targets::of(&cfg))
    });
    // Strand A: the generic valid-state-root invariant (`verify_state_root`),
    // against the dev node itself.
    let mut state_root = cfg
        .verify_state_root
        .then(|| crate::state_root::StateRootOracle::new(cfg.state_root_workload()));
    let mut durable = cfg
        .nemesis
        .storage_faults
        .then(crate::durable::DurableOracle::default);
    let mut zones = cfg.zones.then(|| {
        let (tx, rx) = mpsc::channel();
        let zone_nodes: &[&'static str] = if cfg.zone_cluster() {
            &["zone-0", "zone-1", "zone-2"]
        } else {
            &[crate::zones::ZONE_CONTAINER]
        };
        let logged = zone_nodes.iter().copied().chain([
            crate::zones::PROVER_CONTAINER,
            crate::zones::LOAD_CONTAINER,
            crate::zones::POLICY_CONTAINER,
        ]);
        for c in logged {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let (ctx, crx) = mpsc::channel();
                std::thread::spawn(move || follow_logs(c, ctx));
                for line in crx {
                    if tx.send((c, line)).is_err() {
                        break;
                    }
                }
            });
        }
        (
            crate::zones::ZonesOracle::new(cfg.liveness_secs, common::guest_time_ns()),
            crate::zones_live::RpcZones::new(crate::zones::ZoneEndpoints::of(&cfg)),
            rx,
        )
    });
    // E12's cluster checks (`E12/zones-cluster-*`) over the sequencers.
    let mut cluster = cfg.zone_cluster().then(|| {
        (
            crate::zones_cluster::ClusterOracle::new(
                cfg.zone_sequencers as usize,
                cfg.liveness_secs,
                common::guest_time_ns(),
            ),
            crate::zones_cluster::RpcCluster,
        )
    });
    let (upstream_tx, upstream_rx) = mpsc::channel();
    if cfg.zones {
        for v in crate::cluster::ValidatorId::all() {
            let tx = upstream_tx.clone();
            std::thread::spawn(move || follow_logs(v.container(), tx));
        }
    }
    let mut chain = RpcChain;
    let mut seen_events = 0;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = common::guest_time_ns();
        let mut out = Vec::new();
        let events = common::read_events();
        let new_events = events.get(seen_events..).unwrap_or_default();
        if new_events
            .iter()
            .any(|e| e.source == "nemesis" && e.kind == "storage-fault")
        {
            oracle.open_storage_window();
        }
        if let Some(f) = follower.as_mut() {
            for ev in new_events {
                out.extend(f.on_event(ev, now));
            }
        }
        for (at_ns, line) in rx.try_iter() {
            if let Some(f) = follower.as_mut() {
                out.extend(f.on_log_at(at_ns, &line));
            }
            if let (Some(a), Some(s)) = (across.as_mut(), parse_saved(&line)) {
                a.on_saved(s);
            }
            out.extend(oracle.on_log(&line));
        }
        for ev in new_events {
            out.extend(oracle.on_event(ev, now));
            if let Some(a) = across.as_mut() {
                a.on_event(ev);
            }
            if let Some(d) = durable.as_mut() {
                if ev.source == "nemesis" && ev.container.as_deref() == Some(NODE_CONTAINER) {
                    match ev.kind.as_str() {
                        "kill" | "down" | "stop" => d.on_kill(),
                        "restart" => d.on_restart(),
                        _ => {}
                    }
                }
            }
        }
        for line in upstream_rx.try_iter() {
            if let Some(finding) = scan_line(&line) {
                out.push(Verdict::Always(false, finding));
            }
        }
        seen_events = events.len();
        out.extend(oracle.tick(&mut chain, now));
        if let Some(f) = follower.as_mut() {
            out.extend(crate::follower::step(f, now));
        }
        if let Some(a) = across.as_mut() {
            out.extend(a.tick(&mut crate::historical::RpcHist(None), now));
        }
        if let Some(sr) = state_root.as_mut() {
            let mut view = crate::state_root::RpcRoot(None);
            if let Ok(head) = crate::state_root::RootView::head(&mut view) {
                out.extend(sr.tick(&mut view, head));
            }
        }
        if let Some(d) = durable.as_mut() {
            if let Ok(head) = common::head_number() {
                out.extend(d.tick(&mut crate::durable::RpcDurable, head));
            }
        }
        if let Some((z, zchain, zrx)) = zones.as_mut() {
            for ev in new_events {
                z.on_event(ev, now);
            }
            for (container, line) in zrx.try_iter() {
                out.extend(match container {
                    crate::zones::PROVER_CONTAINER => {
                        let mut v = z.on_prover_line(&line);
                        v.extend(z.on_mutation_line(&line));
                        v.extend(z.on_l1fault_line(&line));
                        v
                    }
                    crate::zones::LOAD_CONTAINER => z.on_load_line(&line),
                    crate::zones::POLICY_CONTAINER => z.on_policy_line(&line),
                    _ => crate::zones::scan_zone_line(&line),
                });
            }
            out.extend(z.tick(zchain, now));
        }
        if let Some((c, rpc)) = cluster.as_mut() {
            for ev in new_events {
                c.on_event(ev, now);
            }
            out.extend(c.tick(rpc, now));
        }
        if let Some(r) = reference.as_mut() {
            out.extend(r.step(new_events, now));
        }
        record(out);
    }
}

/// Preserve journald's guest monotonic time so snapshot recovery ignores
/// queued lines from the previous process incarnation.
pub(crate) fn follow_timestamped_logs(container: &str, tx: mpsc::Sender<(u64, String)>) {
    let child = Command::new("journalctl")
        .args(["-f", "-o", "json", "--no-tail"])
        .arg(format!("CONTAINER_NAME={container}"))
        .stdout(Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        eprintln!("cannot spawn journalctl");
        return;
    };
    let stdout = child.stdout.take().expect("piped stdout");
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if journal_line(&line).is_some_and(|line| tx.send(line).is_err()) {
            break;
        }
    }
}

fn journal_line(line: &str) -> Option<(u64, String)> {
    let entry: serde_json::Value = serde_json::from_str(line).ok()?;
    let at = entry["__MONOTONIC_TIMESTAMP"]
        .as_str()?
        .parse::<u64>()
        .ok()?;
    Some((at.checked_mul(1000)?, entry["MESSAGE"].as_str()?.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const S: u64 = 1_000_000_000;

    #[derive(Default)]
    struct FakeChain {
        head: Option<u64>,
        finalized: Option<u64>,
        hashes: std::collections::HashMap<u64, String>,
        /// Per-block RawStorage values (slot -> value) that eth_getStorageAt
        /// returns, and the (state root, eth_getProof) the node serves.
        trie_storage: std::collections::HashMap<u64, Vec<(u64, u64)>>,
        trie_proofs: std::collections::HashMap<u64, (B256, AccountProof)>,
        tx_counts: std::collections::HashMap<u64, u64>,
        /// eth_getMultiProof responses that differ from eth_getProof's.
        multiproofs: std::collections::HashMap<u64, AccountProof>,
        /// Per-block `debug_executionWitness` responses; absent blocks are
        /// "unavailable" (skipped).
        witness: std::collections::HashMap<u64, WitnessRpc>,
    }

    /// E8 is exercised in `tip20`'s tests; here the token is never readable.
    impl Tip20Chain for FakeChain {
        fn block(&mut self, _: u64) -> Result<Option<BlockRef>, String> {
            Ok(None)
        }
        fn balances(&mut self, _: Address, _: &[Address], _: B256) -> Result<Vec<U256>, String> {
            Err("no token".into())
        }
        fn supply(&mut self, _: Address, _: B256) -> Result<U256, String> {
            Err("no token".into())
        }
        fn transfers(&mut self, _: Address, _: B256) -> Result<Vec<Transfer>, String> {
            Err("no token".into())
        }
    }

    impl Chain for FakeChain {
        fn head(&mut self) -> Result<u64, String> {
            self.head.ok_or_else(|| "down".into())
        }
        fn hash(&mut self, n: u64) -> Result<Option<String>, String> {
            Ok(self.hashes.get(&n).cloned())
        }
        fn finalized(&mut self) -> Result<Option<(u64, String)>, String> {
            Ok(self
                .finalized
                .map(|n| (n, self.hashes.get(&n).cloned().unwrap_or_default())))
        }
        fn storage(
            &mut self,
            _address: &str,
            slots: &[u64],
            block: u64,
        ) -> Result<trie_ref::Storage, String> {
            let set = self.trie_storage.get(&block).cloned().unwrap_or_default();
            Ok(slots
                .iter()
                .map(|s| {
                    let v = set.iter().find(|(k, _)| k == s).map_or(0, |(_, v)| *v);
                    (*s, U256::from(v))
                })
                .collect())
        }
        fn proof(&mut self, _: &str, slots: &[u64], block: u64) -> Result<AccountProof, String> {
            let mut p = self
                .trie_proofs
                .get(&block)
                .map(|(_, p)| p.clone())
                .ok_or("no proof")?;
            if slots.is_empty() {
                p.storage_proof.clear();
            }
            Ok(p)
        }
        fn multiproof(&mut self, a: &str, s: &[u64], block: u64) -> Result<AccountProof, String> {
            match self.multiproofs.get(&block) {
                Some(p) => Ok(p.clone()),
                None => self.proof(a, s, block),
            }
        }
        fn state_root(&mut self, block: u64) -> Result<B256, String> {
            self.trie_proofs
                .get(&block)
                .map(|(r, _)| *r)
                .ok_or_else(|| "no block".into())
        }
        fn tx_count(&mut self, block: u64) -> Result<u64, String> {
            Ok(self.tx_counts.get(&block).copied().unwrap_or(0))
        }
        fn execution_witness(&mut self, block: u64) -> WitnessRpc {
            self.witness
                .get(&block)
                .cloned()
                .unwrap_or(WitnessRpc::Unavailable)
        }
    }

    const TRIE_ADDRESS: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
    const TRIE_SLOTS: [u64; 2] = [544, 646];

    fn trie_oracle() -> Oracle {
        Oracle::new(Some(60), 0, Vec::new()).with_trie(Some(TrieConfig {
            address: TRIE_ADDRESS.into(),
            slots: TRIE_SLOTS.to_vec(),
            ..Default::default()
        }))
    }

    /// Serve `storage` at `block` from both eth_getStorageAt and an honest
    /// node's eth_getProof.
    fn set_block(c: &mut FakeChain, block: u64, storage: &[(u64, u64)]) {
        c.trie_storage.insert(block, storage.to_vec());
        c.trie_proofs.insert(
            block,
            trie_ref::tests::honest_proof(TRIE_ADDRESS, storage, &TRIE_SLOTS),
        );
    }

    fn trie_chain(blocks: &[(u64, &[(u64, u64)])]) -> FakeChain {
        let mut c = FakeChain::default();
        for (b, storage) in blocks {
            set_block(&mut c, *b, storage);
        }
        c
    }

    #[test]
    fn included_load_is_covered_once() {
        let mut o = Oracle::new(Some(60), 0, Vec::new());
        let mut c = FakeChain {
            head: Some(10),
            ..Default::default()
        };
        // The head at the first tick predates the run.
        c.tx_counts.insert(10, 1);
        assert!(sigs(&o.tick(&mut c, S)).is_empty());
        c.head = Some(11);
        assert!(sigs(&o.tick(&mut c, 2 * S)).is_empty());
        c.head = Some(12);
        c.tx_counts.insert(12, 3);
        assert_eq!(sigs(&o.tick(&mut c, 3 * S)), [(true, "S/load-included")]);
        c.head = Some(13);
        c.tx_counts.insert(13, 3);
        assert!(sigs(&o.tick(&mut c, 4 * S)).is_empty());
    }

    #[test]
    fn honest_trie_blocks_pass() {
        let mut o = trie_oracle();
        let mut c = trie_chain(&[(1, &[]), (2, &[(544, 1)]), (3, &[(544, 1), (646, 1)])]);
        c.head = Some(3);
        assert_eq!(
            sigs(&o.tick(&mut c, S)),
            [(true, "S/trie-checked"), (true, "S/trie-all-slots-live")]
        );
    }

    /// A `debug_executionWitness` response holding every node of an honest
    /// proof of the trie contract over `storage` (the parent-block state).
    fn honest_witness_rpc(storage: &[(u64, u64)]) -> WitnessRpc {
        let (_, proof) = trie_ref::tests::honest_proof(TRIE_ADDRESS, storage, &TRIE_SLOTS);
        let mut state: Vec<alloy_primitives::Bytes> = proof.account_proof.clone();
        for sp in &proof.storage_proof {
            state.extend(sp.proof.iter().cloned());
        }
        WitnessRpc::Ok(crate::witness::ExecutionWitness {
            state,
            codes: vec![alloy_primitives::Bytes::from_static(b"code")],
            ..Default::default()
        })
    }

    #[test]
    fn witness_verifies_and_is_covered() {
        let mut o = trie_oracle();
        // Blocks 1 (parent) and 2; the witness at block 2 proves block 1's state.
        let mut c = trie_chain(&[(1, &[(544, 1)]), (2, &[(544, 1)])]);
        c.witness.insert(2, honest_witness_rpc(&[(544, 1)]));
        c.head = Some(2);
        let t = o.tick(&mut c, S);
        let v = sigs(&t);
        assert!(v.contains(&(true, "S/execution-witness-verified")), "{v:?}");
        assert!(!v.iter().any(|(_, s)| s.starts_with("E6/witness")), "{v:?}");
    }

    #[test]
    fn witness_unsupported_is_covered_once() {
        let mut o = trie_oracle();
        let mut c = trie_chain(&[(1, &[(544, 1)]), (2, &[(544, 1)]), (3, &[(544, 1)])]);
        c.witness.insert(1, WitnessRpc::Unsupported);
        c.witness.insert(2, WitnessRpc::Unsupported);
        c.head = Some(2);
        let t = o.tick(&mut c, S);
        let v = sigs(&t);
        assert_eq!(
            v.iter()
                .filter(|(_, s)| *s == "S/execution-witness-unsupported")
                .count(),
            1,
            "{v:?}"
        );
        // Latched: later ticks do not retry the capability probe.
        c.witness.insert(3, WitnessRpc::Unsupported);
        c.head = Some(3);
        let t = o.tick(&mut c, 2 * S);
        let v = sigs(&t);
        assert!(
            !v.iter()
                .any(|(_, s)| *s == "S/execution-witness-unsupported"),
            "{v:?}"
        );
    }

    #[test]
    fn witness_root_missing_is_reported() {
        let mut o = trie_oracle();
        let mut c = trie_chain(&[(1, &[(544, 1)]), (2, &[(544, 1)])]);
        // A witness whose state does not include the parent state root.
        c.witness.insert(
            2,
            WitnessRpc::Ok(crate::witness::ExecutionWitness {
                state: vec![alloy_primitives::Bytes::from_static(&[0x80])],
                ..Default::default()
            }),
        );
        c.head = Some(2);
        let t = o.tick(&mut c, S);
        let v = sigs(&t);
        assert!(v.contains(&(false, "E6/witness-root-missing")), "{v:?}");
    }

    #[test]
    fn storage_root_mismatch_is_reported() {
        let mut o = trie_oracle();
        // The node's trie (and proofs) hold A only, but slot B reads 1.
        let mut c = trie_chain(&[(1, &[(544, 1)])]);
        c.trie_storage.insert(1, vec![(544, 1), (646, 1)]);
        c.head = Some(1);
        let v = o.tick(&mut c, S);
        let v = sigs(&v);
        assert!(v.contains(&(false, "E5/storage-root-mismatch")), "{v:?}");
        assert!(v.contains(&(false, "E6/proof-value-mismatch")), "{v:?}");
    }

    #[test]
    fn invalid_proofs_are_reported() {
        let mut o = trie_oracle();
        let mut c = trie_chain(&[(1, &[(544, 1)]), (2, &[(544, 1), (646, 1)])]);
        // Block 1: the header's state root does not commit to the account.
        c.trie_proofs.get_mut(&1).unwrap().0 = B256::repeat_byte(1);
        // Block 2: a storage proof is missing its leaf.
        c.trie_proofs.get_mut(&2).unwrap().1.storage_proof[0]
            .proof
            .pop();
        c.head = Some(2);
        let v = o.tick(&mut c, S);
        let v = sigs(&v);
        assert!(v.contains(&(false, "E6/account-proof-invalid")), "{v:?}");
        assert!(v.contains(&(false, "E6/storage-proof-invalid")), "{v:?}");
        assert!(!v.contains(&(false, "E5/storage-root-mismatch")), "{v:?}");
    }

    #[test]
    fn multiproof_failures_are_reported_separately() {
        let mut o = trie_oracle();
        let mut c = trie_chain(&[(1, &[(544, 1)])]);
        // proof v2 serves a proof of B's storage instead.
        let (_, other) = trie_ref::tests::honest_proof(TRIE_ADDRESS, &[(646, 1)], &TRIE_SLOTS);
        c.multiproofs.insert(1, other);
        c.head = Some(1);
        let v = o.tick(&mut c, S);
        let v = sigs(&v);
        assert!(
            v.contains(&(false, "E5/multiproof-storage-root-mismatch")),
            "{v:?}"
        );
        assert!(
            v.contains(&(false, "E6/multiproof-account-proof-invalid")),
            "{v:?}"
        );
        assert!(
            v.contains(&(false, "E6/multiproof-proof-value-mismatch")),
            "{v:?}"
        );
        assert!(
            !v.iter()
                .any(|(_, s)| !s.contains("multiproof") && s.starts_with('E')),
            "{v:?}"
        );
    }

    #[test]
    fn depth_sweep_visits_every_depth() {
        for range in [SHALLOW_DEPTHS, DEEP_DEPTHS] {
            let len = range.1 - range.0 + 1;
            let seen: std::collections::BTreeSet<u64> =
                (0..len).map(|t| sweep_depth(range, t)).collect();
            assert_eq!(seen.len() as u64, len);
            assert_eq!(seen.first(), Some(&range.0));
            assert_eq!(seen.last(), Some(&range.1));
        }
    }

    #[test]
    fn older_blocks_are_rechecked_across_depths() {
        let mut o = trie_oracle();
        let mut c = FakeChain::default();
        for b in 1..=300 {
            set_block(&mut c, b, &[(544, 1)]);
        }
        // The node serves every older block wrong.
        for b in 1..=290 {
            c.trie_storage.insert(b, vec![(544, 1), (646, 1)]);
        }
        let mut bad = std::collections::BTreeSet::new();
        for t in 0..300u64 {
            c.head = Some(300);
            for v in o.tick(&mut c, (t + 1) * S) {
                if let Verdict::Always(false, f) = v {
                    if f.signature.starts_with("E5") {
                        bad.insert(f.detail.split(':').next().unwrap().to_string());
                    }
                }
            }
        }
        // Both sweeps reached their whole depth range: deep 250..=49 is
        // blocks 50..=251, shallow 48..=10 (the wrong ones) is 252..=290.
        let blocks = bad.iter().filter(|d| d.starts_with("block ")).count();
        assert_eq!(blocks, 241, "{bad:?}");
        assert!(
            bad.contains("block 50") && bad.contains("block 290"),
            "{bad:?}"
        );
    }

    const MULTI: [&str; 3] = [
        "0x5fbdb2315678afecb367f032d93f642f64180aa3",
        "0xfbfbfddd6e35da57b7b0f9a2c10e34be70b3a4e9",
        "0x72bb9c7ffbe2ed234e53bc64862dda6d9fff333b",
    ];

    /// An honest node holding several RawStorage contracts in one state.
    #[derive(Default)]
    struct MultiChain {
        head: u64,
        /// Per block, each contract's (slot, value)s.
        blocks: std::collections::HashMap<u64, Vec<Vec<(u64, u64)>>>,
        /// Contract whose eth_getStorageAt reads slot 646 as 1 everywhere.
        lie: Option<usize>,
        /// (address, block) of every eth_getStorageAt batch: one per check.
        reads: Vec<(String, u64)>,
    }

    impl MultiChain {
        fn state(&self, block: u64) -> Result<(B256, Vec<AccountProof>), String> {
            let storage = self.blocks.get(&block).ok_or("no block")?;
            let contracts: Vec<_> = MULTI
                .iter()
                .zip(storage)
                .map(|(a, s)| (*a, s.as_slice(), &TRIE_SLOTS[..]))
                .collect();
            Ok(trie_ref::tests::honest_state(&contracts))
        }
        fn index(address: &str) -> usize {
            MULTI.iter().position(|a| *a == address).unwrap()
        }
    }

    impl Tip20Chain for MultiChain {
        fn block(&mut self, _: u64) -> Result<Option<BlockRef>, String> {
            Ok(None)
        }
        fn balances(&mut self, _: Address, _: &[Address], _: B256) -> Result<Vec<U256>, String> {
            Err("no token".into())
        }
        fn supply(&mut self, _: Address, _: B256) -> Result<U256, String> {
            Err("no token".into())
        }
        fn transfers(&mut self, _: Address, _: B256) -> Result<Vec<Transfer>, String> {
            Err("no token".into())
        }
    }

    impl Chain for MultiChain {
        fn head(&mut self) -> Result<u64, String> {
            Ok(self.head)
        }
        fn hash(&mut self, n: u64) -> Result<Option<String>, String> {
            Ok(Some(format!("0x{n}")))
        }
        fn finalized(&mut self) -> Result<Option<(u64, String)>, String> {
            Ok(None)
        }
        fn storage(
            &mut self,
            a: &str,
            slots: &[u64],
            block: u64,
        ) -> Result<trie_ref::Storage, String> {
            self.reads.push((a.to_string(), block));
            let c = Self::index(a);
            let mut set = self.blocks.get(&block).ok_or("no block")?[c].clone();
            if self.lie == Some(c) {
                set.push((646, 1));
            }
            Ok(slots
                .iter()
                .map(|s| {
                    let v = set.iter().find(|(k, _)| k == s).map_or(0, |(_, v)| *v);
                    (*s, U256::from(v))
                })
                .collect())
        }
        fn proof(&mut self, a: &str, slots: &[u64], block: u64) -> Result<AccountProof, String> {
            let mut p = self.state(block)?.1.remove(Self::index(a));
            if slots.is_empty() {
                p.storage_proof.clear();
            }
            Ok(p)
        }
        fn multiproof(&mut self, a: &str, s: &[u64], block: u64) -> Result<AccountProof, String> {
            self.proof(a, s, block)
        }
        fn state_root(&mut self, block: u64) -> Result<B256, String> {
            Ok(self.state(block)?.0)
        }
        fn tx_count(&mut self, _: u64) -> Result<u64, String> {
            Ok(0)
        }
    }

    fn multi_oracle() -> Oracle {
        Oracle::new(Some(60), 0, Vec::new()).with_tries(
            MULTI
                .iter()
                .map(|a| TrieConfig {
                    address: a.to_string(),
                    slots: TRIE_SLOTS.to_vec(),
                    ..Default::default()
                })
                .collect(),
        )
    }

    /// Blocks `1..=n`, where contract `c` holds slot 544 = c + 1 from block
    /// `c + 2` on.
    fn multi_chain(n: u64) -> MultiChain {
        let mut c = MultiChain {
            head: n,
            ..Default::default()
        };
        for b in 1..=n {
            let storage = (0..MULTI.len() as u64)
                .map(|i| {
                    if b >= i + 2 {
                        vec![(544, i + 1)]
                    } else {
                        vec![]
                    }
                })
                .collect();
            c.blocks.insert(b, storage);
        }
        c
    }

    #[test]
    fn every_contract_is_checked_at_the_newest_block_and_rotated_below() {
        let mut o = multi_oracle();
        let mut c = multi_chain(300);
        let v = o.tick(&mut c, S);
        assert!(failures(&v).is_empty(), "{:?}", sigs(&v));
        // The newest block: every contract.
        let at_head: Vec<_> = c.reads.iter().filter(|(_, b)| *b == 300).collect();
        assert_eq!(at_head.len(), MULTI.len());
        // 9 more new blocks and the deep swept block (the shallow one, 298,
        // is new): one contract each, so the tick costs 3 + 10 checks, not
        // 3 * 11.
        assert_eq!(c.reads.len(), MULTI.len() + 9 + 1);
        let below: Vec<_> = c.reads.iter().filter(|(_, b)| *b < 300).collect();
        for a in MULTI {
            assert!(below.iter().any(|(x, _)| x == a), "{a} never rotated in");
        }
        // Later ticks stay bounded and keep every contract at the head.
        for t in 2..40u64 {
            c.head += 1;
            let n = c.head;
            let prev = c.blocks[&(n - 1)].clone();
            c.blocks.insert(n, prev);
            c.reads.clear();
            assert!(failures(&o.tick(&mut c, t * S)).is_empty());
            assert!(c.reads.len() <= MULTI.len() + 2, "{:?}", c.reads);
            assert_eq!(c.reads.iter().filter(|(_, b)| *b == n).count(), MULTI.len());
        }
    }

    #[test]
    fn a_wrong_contract_is_reported_with_its_address() {
        let mut o = multi_oracle();
        let mut c = multi_chain(5);
        c.lie = Some(2);
        let v = o.tick(&mut c, S);
        let bad: Vec<_> = v
            .iter()
            .filter_map(|v| match v {
                Verdict::Always(false, f) => Some(f),
                _ => None,
            })
            .collect();
        assert!(bad
            .iter()
            .any(|f| f.signature == "E5/storage-root-mismatch"));
        for f in &bad {
            assert!(
                f.detail.contains(&format!("contract {}", MULTI[2])),
                "{f:?}"
            );
        }
    }

    #[test]
    fn a_block_changing_two_contracts_is_covered() {
        let mut o = multi_oracle();
        let mut c = multi_chain(3);
        // Block 3 changes contract 1 only (contract 0 changed at block 2).
        let v = o.tick(&mut c, S);
        assert!(!sigs(&v).contains(&(true, "S/multi-contract-block")));
        // Block 4 changes contracts 0 and 2.
        let mut b4 = c.blocks[&3].clone();
        b4[0] = vec![(544, 9)];
        b4[2] = vec![(646, 3)];
        c.blocks.insert(4, b4);
        c.head = 4;
        let v = o.tick(&mut c, 2 * S);
        assert!(
            sigs(&v).contains(&(true, "S/multi-contract-block")),
            "{:?}",
            sigs(&v)
        );
        // Covered once.
        c.head = 4;
        assert!(!sigs(&o.tick(&mut c, 3 * S)).contains(&(true, "S/multi-contract-block")));
    }

    #[test]
    fn a_two_contract_block_below_the_head_is_covered() {
        let mut o = multi_oracle();
        let mut c = multi_chain(3);
        assert!(!sigs(&o.tick(&mut c, S)).contains(&(true, "S/multi-contract-block")));
        // Between ticks: block 4 changes contracts 0 and 1 (a burst), blocks
        // 5-6 change nothing; the next tick's head is 6.
        let mut b4 = c.blocks[&3].clone();
        b4[0] = vec![(544, 7)];
        b4[1] = vec![(646, 7)];
        for b in 4..=6 {
            c.blocks.insert(b, b4.clone());
        }
        c.head = 6;
        let v = o.tick(&mut c, 2 * S);
        assert!(
            sigs(&v).contains(&(true, "S/multi-contract-block")),
            "{:?}",
            sigs(&v)
        );
    }

    #[test]
    fn rewound_blocks_are_rechecked() {
        let mut o = trie_oracle();
        let mut c = trie_chain(&[(1, &[]), (2, &[(544, 1)])]);
        c.head = Some(2);
        o.tick(&mut c, S);
        // Crash recovery rewinds to block 1 and rebuilds block 2 with B
        // written, but the node's trie misses the write.
        c.trie_storage.insert(2, vec![(544, 1), (646, 1)]);
        c.head = Some(1);
        o.tick(&mut c, 2 * S);
        c.head = Some(2);
        assert!(sigs(&o.tick(&mut c, 3 * S)).contains(&(false, "E5/storage-root-mismatch")));
    }

    /// The shape of the native run's second crash: block data saved through
    /// 318, finalized at 269, head 330 at the kill.
    fn chain_before_kill() -> FakeChain {
        let mut c = FakeChain {
            head: Some(330),
            finalized: Some(269),
            ..Default::default()
        };
        c.hashes.insert(269, "0xf1".into());
        c.hashes.insert(318, "0x318a".into());
        c
    }

    const SAVED_318: &str = "DEBUG engine::persistence: Saved range of blocks first=Some(NumHash { number: 308, hash: 0x1 }) last=NumHash { number: 318, hash: 0x318a }";

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

    const SAVED: &str = "2026-10-07T00:00:00.000000Z DEBUG engine::persistence: Saved range of blocks first=Some(NumHash { number: 5, hash: 0xaa }) last=NumHash { number: 7, hash: 0xBEEF01 }";

    #[test]
    fn parses_saved_range() {
        assert_eq!(parse_saved(SAVED), Some((7, "0xbeef01".into())));
        assert_eq!(
            parse_saved("Saving range of blocks last=NumHash { number: 9, hash: 0x1 }"),
            None
        );
    }

    #[test]
    fn parses_saved_range_with_ansi() {
        let colored = SAVED.replace("DEBUG", "\x1b[34mDEBUG\x1b[0m");
        assert_eq!(parse_saved(&colored), Some((7, "0xbeef01".into())));
    }

    #[test]
    fn scans_known_patterns_and_errors() {
        let panic = "thread 'tokio-runtime-worker' panicked at crates/trie/sparse/src/lib.rs:10:5:";
        assert_eq!(scan_line(panic).unwrap().signature, "E1/panic");
        let diff = "WARN engine::tree: Difference in account trie updates path=0x1";
        assert_eq!(scan_line(diff).unwrap().signature, "E1/trie-diff-account");
        let err = "2026-10-07T00:00:00Z ERROR engine::tree: something odd";
        assert_eq!(
            scan_line(err).unwrap().signature,
            "E1/error-log/engine::tree"
        );
        assert_eq!(scan_line("INFO reth::cli: Status connected_peers=0"), None);
        let spanned = "2024-01-01T00:06:23Z ERROR start_next_execution_task{current.head_height=270}:set_execution_task{task_type=\"verify\"}: tempo_consensus::executor::actor: failed";
        assert_eq!(
            scan_line(spanned).unwrap().signature,
            "E1/error-log/tempo_consensus::executor::actor"
        );
    }

    #[test]
    fn saved_line_is_not_a_finding() {
        let mut o = Oracle::new(Some(60), 0, Vec::new());
        assert!(o.on_log(SAVED).is_empty());
    }

    #[test]
    fn storage_error_windows_excuse_e1_until_restart() {
        let mut o = Oracle::new(Some(60), 0, Vec::new());
        o.on_event(&ev("storage-fault"), S);
        let panic = "thread 'persistence' panicked at crates/x.rs: Input/output error";
        assert_eq!(sigs(&o.on_log(panic)), [(true, "S/storage-fault-surfaced")]);
        assert!(o.on_log(panic).is_empty());
        o.on_event(&ev("down"), 2 * S);
        o.on_event(&ev("restart"), 3 * S);
        assert_eq!(sigs(&o.on_log(panic)), [(false, "E1/panic")]);
    }

    #[test]
    fn rewinding_unfinalized_blocks_is_coverage_not_failure() {
        // reth unwinds to its state-trie frontier (308) and rebuilds 309..318.
        let mut o = Oracle::new(Some(60), 0, Vec::new());
        let mut c = chain_before_kill();
        o.on_log(SAVED_318);
        o.tick(&mut c, S);
        assert_eq!(sigs(&o.on_event(&ev("kill"), 2 * S)), [(true, "S/kill")]);
        c.head = None;
        assert!(o.tick(&mut c, 3 * S).is_empty());
        o.on_event(&ev("restart"), 4 * S);
        c.head = Some(308);
        assert_eq!(
            sigs(&o.tick(&mut c, 5 * S)),
            [(true, "E3/finalized-block-changed")]
        );
        c.hashes.insert(318, "0x318b".into());
        c.head = Some(320);
        assert_eq!(
            sigs(&o.tick(&mut c, 6 * S)),
            [(true, "S/rewound-unfinalized")]
        );
        c.head = Some(331);
        assert_eq!(sigs(&o.tick(&mut c, 7 * S)), [(true, "S/recovered")]);
    }

    #[test]
    fn durability_fails_when_finalized_block_changes() {
        let mut o = Oracle::new(Some(60), 0, Vec::new());
        let mut c = chain_before_kill();
        o.tick(&mut c, S);
        o.on_event(&ev("kill"), 2 * S);
        o.on_event(&ev("restart"), 3 * S);
        c.hashes.insert(269, "0xother".into());
        assert!(sigs(&o.tick(&mut c, 4 * S)).contains(&(false, "E3/finalized-block-changed")));
    }

    #[test]
    fn durability_fails_when_head_never_reaches_finalized() {
        let mut o = Oracle::new(Some(10), 0, Vec::new());
        let mut c = chain_before_kill();
        o.tick(&mut c, S);
        o.on_event(&ev("kill"), 2 * S);
        o.on_event(&ev("restart"), 3 * S);
        c.head = Some(200);
        assert!(!sigs(&o.tick(&mut c, 4 * S))
            .iter()
            .any(|(_, s)| s.starts_with("E3/")));
        let v = o.tick(&mut c, 14 * S);
        assert!(sigs(&v).contains(&(false, "E3/head-below-finalized")));
    }

    #[test]
    fn no_finalized_block_means_nothing_to_check() {
        let mut o = Oracle::new(Some(10), 0, Vec::new());
        let mut c = FakeChain {
            head: Some(5),
            ..Default::default()
        };
        o.tick(&mut c, S);
        o.on_event(&ev("kill"), 2 * S);
        o.on_event(&ev("restart"), 3 * S);
        assert!(!sigs(&o.tick(&mut c, 20 * S))
            .iter()
            .any(|(_, s)| s.starts_with("E3/")));
    }

    #[test]
    fn liveness_fails_once_per_stall_and_ignores_downtime() {
        let mut o = Oracle::new(Some(10), 0, Vec::new());
        let mut c = FakeChain {
            head: Some(1),
            ..Default::default()
        };
        o.tick(&mut c, S);
        assert!(o.tick(&mut c, 5 * S).is_empty());
        assert_eq!(sigs(&o.tick(&mut c, 12 * S)), [(false, "E2/head-stalled")]);
        assert!(o.tick(&mut c, 30 * S).is_empty());
        c.head = Some(2);
        assert!(o.tick(&mut c, 31 * S).is_empty());
        o.on_event(&ev("kill"), 32 * S);
        assert!(o.tick(&mut c, 100 * S).is_empty());
        o.on_event(&ev("restart"), 100 * S);
        assert!(o.tick(&mut c, 105 * S).is_empty());
        assert_eq!(sigs(&o.tick(&mut c, 111 * S)), [(false, "E2/head-stalled")]);
    }

    #[test]
    fn pause_excuses_liveness_until_resume_then_judges_afresh() {
        let mut o = Oracle::new(Some(10), 0, Vec::new());
        let mut c = FakeChain {
            head: Some(5),
            ..Default::default()
        };
        o.tick(&mut c, S);
        o.on_event(&ev("pause"), 2 * S);
        // Frozen: RPC fails or hangs, the head stands still; no E2.
        c.head = None;
        assert!(o.tick(&mut c, 30 * S).is_empty());
        c.head = Some(5);
        o.on_event(&ev("resume"), 30 * S);
        assert!(o.tick(&mut c, 35 * S).is_empty());
        c.head = Some(6);
        assert_eq!(
            sigs(&o.tick(&mut c, 36 * S)),
            [(true, "S/paused-recovered")]
        );
        // A node that does not recover within liveness_secs of the resume
        // still fails.
        o.on_event(&ev("pause"), 37 * S);
        o.on_event(&ev("resume"), 50 * S);
        assert!(o.tick(&mut c, 59 * S).is_empty());
        assert_eq!(sigs(&o.tick(&mut c, 61 * S)), [(false, "E2/head-stalled")]);
    }

    #[test]
    fn throttle_excuses_liveness_but_keeps_checking() {
        // liveness_secs = 60.
        let mut o = trie_oracle();
        let mut c = trie_chain(&[(1, &[(544, 1)])]);
        c.head = Some(1);
        o.tick(&mut c, S);
        o.on_event(&ev("throttle"), 2 * S);
        // A stall inside the window is excused...
        assert!(failures_of(&o.tick(&mut c, 90 * S)).is_empty());
        // ...but the other oracles still run: a bad block is reported.
        c.trie_storage.insert(2, vec![(544, 1), (646, 1)]);
        c.trie_proofs.insert(
            2,
            trie_ref::tests::honest_proof(TRIE_ADDRESS, &[(544, 1)], &TRIE_SLOTS),
        );
        c.head = Some(2);
        assert!(failures_of(&o.tick(&mut c, 91 * S)).contains(&"E5/storage-root-mismatch"));
        o.on_event(&ev("throttle-end"), 95 * S);
        set_block(&mut c, 3, &[(544, 1)]);
        c.head = Some(3);
        assert!(sigs(&o.tick(&mut c, 96 * S)).contains(&(true, "S/throttled-recovered")));
        // Stalled for liveness_secs after the window: E2.
        o.on_event(&ev("throttle"), 97 * S);
        o.on_event(&ev("throttle-end"), 110 * S);
        assert!(failures_of(&o.tick(&mut c, 169 * S)).is_empty());
        assert_eq!(failures_of(&o.tick(&mut c, 171 * S)), ["E2/head-stalled"]);
    }

    #[test]
    fn graceful_stop_is_downtime_and_its_restart_is_covered() {
        let mut o = Oracle::new(Some(10), 0, Vec::new());
        let mut c = chain_before_kill();
        o.tick(&mut c, S);
        assert_eq!(
            sigs(&o.on_event(&ev("stop"), 2 * S)),
            [(true, "S/graceful-stop")]
        );
        c.head = None;
        assert!(o.tick(&mut c, 40 * S).is_empty());
        o.on_event(&ev("restart"), 41 * S);
        c.head = Some(331);
        let v = o.tick(&mut c, 42 * S);
        let v = sigs(&v);
        assert!(v.contains(&(true, "S/recovered")), "{v:?}");
        assert!(v.contains(&(true, "S/graceful-restart")), "{v:?}");
        // The finalized block still has to survive the stop (E3).
        assert!(v.contains(&(true, "E3/finalized-block-changed")), "{v:?}");
        // A later kill's recovery is not a graceful restart.
        o.on_event(&ev("kill"), 43 * S);
        o.on_event(&ev("restart"), 44 * S);
        c.head = Some(332);
        assert!(!sigs(&o.tick(&mut c, 45 * S)).contains(&(true, "S/graceful-restart")));
    }

    fn failures_of(v: &[Verdict]) -> Vec<&str> {
        sigs(v)
            .into_iter()
            .filter(|(ok, _)| !ok)
            .map(|(_, s)| s)
            .collect()
    }
    #[test]
    fn journal_log_timestamp_uses_guest_monotonic_time() {
        assert_eq!(
            journal_line(r#"{"__MONOTONIC_TIMESTAMP":"123","MESSAGE":"Executed block"}"#),
            Some((123000, "Executed block".into()))
        );
        assert_eq!(journal_line(r#"{"MESSAGE":"Executed block"}"#), None);
    }
}
