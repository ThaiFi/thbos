// SPDX-License-Identifier: GPL-2.0

//! Consensus oracles for the multi-validator cluster (`validators=4`),
//! E13-E18, as a pure state machine ([`ConsensusOracle`]) over a
//! [`ClusterView`] of every validator and the nemesis' kill/restart events:
//!
//! - E13 safety: every validator's finalized blocks agree (same hash at a
//!   height: `finalized-conflict`), link (each one's parent is the block
//!   finalized below it: `finalized-not-prefix`), and never change on the
//!   node that served them (`finalized-reverted`), across restarts too.
//! - E14 durability: a restarted validator still has every finalization and
//!   finalized block it served before the crash (its own pre-crash reads; a
//!   node legitimately lacks certificates for heights it finalized while
//!   catching up, so it is never compared against its peers for that), its
//!   finalized height never goes back within one process
//!   (`finalized-height-regressed`), and certificates agree.
//! - E15 reopen: a restarted validator answers RPC within the catch-up
//!   budget, and logs no consensus-storage error while recovering.
//! - E16 liveness: the cluster's finalized height advances while at most
//!   [`FAULT_BUDGET`] validators are down (`stalled`), an up validator
//!   catches up (`node-stuck`), the full mesh re-forms (`mesh-timeout`);
//!   budgets scale with the cooldown ([`LivenessBudget`]).
//! - E17: no validator blocks a peer (all are honest): a `block!` warning,
//!   a `..._tracker_directory_blocked{peer}` series, or rising
//!   `..._handshakes_blocked_total`.
//! - E18: no DKG ceremony fails.
//!
//! Coverage (Sometimes): `S/mesh-formed`, `S/epoch-transition`,
//! `S/nullification`, `S/leader-skip`, `S/resolver-fetch`,
//! `S/archive-sparse`, `S/validator-caught-up`, `S/finalized-during-fault`,
//! `S/full-restart-recovered`.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::B256;

use crate::{
    cluster::{EngineProfile, LivenessBudget, ValidatorId, FAULT_BUDGET, VALIDATORS},
    common::{DstEvent, TrieConfig},
    trie_ref::{self, AccountProof},
    verdict::{finding, Verdict},
};

/// A finalized block as one validator serves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedBlock {
    pub number: u64,
    pub hash: B256,
    pub parent: B256,
}

/// `consensus_getFinalization({"height": N})` from one validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizationRead {
    /// The node has the certificate (hex) of the block `digest`.
    Present {
        epoch: u64,
        view: u64,
        digest: B256,
        certificate: String,
    },
    /// The node answered that it lacks the certificate or the block (503,
    /// with what is missing).
    Missing(String),
}

/// The consensus metrics the oracles read (`:8002/metrics`), summed over
/// their labels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeMetrics {
    pub finalized_height: Option<u64>,
    pub epoch: Option<u64>,
    /// `consensus_network_tracker_directory_connected{peer}` series.
    pub connected_peers: usize,
    /// Peers with a `consensus_network_tracker_directory_blocked{peer}`.
    pub blocked_peers: Vec<String>,
    pub handshakes_blocked: u64,
    pub dkg_successes: u64,
    pub dkg_failures: u64,
    pub nullifications: u64,
    /// Views timed out because the leader did not propose in time.
    pub leader_timeouts: u64,
    /// Successful p2p resolver fetches (missing blocks/certificates).
    pub resolver_fetches: u64,
}

/// Timeout reasons that mean the view's leader was skipped.
const LEADER_SKIP_REASONS: [&str; 3] = ["LeaderTimeout", "MissingProposal", "LeaderNullify"];

/// Parses the Prometheus text exposition into [`NodeMetrics`].
pub fn parse_metrics(text: &str) -> NodeMetrics {
    let mut m = NodeMetrics::default();
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some((series, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let (name, labels) = series.split_once('{').unwrap_or((series, ""));
        let value: f64 = value.parse().unwrap_or(0.0);
        let int = value.max(0.0) as u64;
        let label = |key: &str| {
            labels
                .split(',')
                .find_map(|kv| kv.trim_end_matches('}').strip_prefix(&format!("{key}=\"")))
                .map(|v| v.trim_end_matches('"').to_string())
        };
        match name {
            "consensus_engine_marshal_finalized_height" => m.finalized_height = Some(int),
            "consensus_engine_epoch_manager_latest_epoch" => m.epoch = Some(int),
            "consensus_network_tracker_directory_connected" => m.connected_peers += 1,
            "consensus_network_tracker_directory_blocked" => {
                m.blocked_peers.push(label("peer").unwrap_or_default())
            }
            "consensus_network_listener_handshakes_blocked_total" => m.handshakes_blocked += int,
            "consensus_engine_dkg_manager_ceremony_successes_total" => m.dkg_successes += int,
            "consensus_engine_dkg_manager_ceremony_failures_total" => m.dkg_failures += int,
            "consensus_engine_epoch_manager_simplex_voter_state_nullifications_total" => {
                m.nullifications += int
            }
            "consensus_engine_epoch_manager_simplex_voter_state_timeouts_total"
                if label("reason").is_some_and(|r| LEADER_SKIP_REASONS.contains(&r.as_str())) =>
            {
                m.leader_timeouts += int
            }
            "consensus_engine_p2p_resolver_fetch_total"
                if label("status").as_deref() == Some("Success") =>
            {
                m.resolver_fetches += int
            }
            _ => {}
        }
    }
    m
}

/// Messages of commonware's `block!` (a `WARN` naming the `peer=` it
/// blocks), at the pinned commonware (2026.9.0).
const BLOCK_MESSAGES: &[&str] = &[
    "invalid signature",
    "epoch mismatch",
    "decoding error",
    "conflicting notarize",
    "conflicting finalize",
    "conflicting nullify",
    "unknown participant",
    "shard sent by non-participant",
    "shard equivocation",
    "received invalid message",
    "nullify signer mismatch",
    "nullify after finalize",
    "notarize signer mismatch",
    "finalize signer mismatch",
    "finalize after nullify",
    "invalid shard received",
    "invalid assigned shard received",
    "invalid message",
    "invalid certificate",
    "invalid ack signature",
    "blocking equivocator",
    "ack decode failed",
];

/// Words of commonware-storage errors (journal, archive, freezer, metadata
/// replay and checksums) that, at ERROR level on a recovering validator,
/// mean its consensus storage did not reopen cleanly.
const STORAGE_ERROR_WORDS: &[&str] = &[
    "journal", "archive", "freezer", "metadata", "checksum", "corrupt", "replay", "rewind",
];

/// Every validator's view the oracles need; `Err` while it is unreachable.
pub trait ClusterView {
    /// `eth_getBlockByNumber("finalized")` as `(number, hash)`.
    fn finalized(&mut self, v: ValidatorId) -> Result<Option<(u64, B256)>, String>;
    /// Canonical block `number`; `None` past the node's head.
    fn block(&mut self, v: ValidatorId, number: u64) -> Result<Option<FinalizedBlock>, String>;
    fn finalization(&mut self, v: ValidatorId, height: u64) -> Result<FinalizationRead, String>;
    fn metrics(&mut self, v: ValidatorId) -> Result<NodeMetrics, String>;
}

/// Blocks scanned per validator per tick; a node further behind catches up
/// over several ticks.
const SCAN_PER_TICK: u64 = 16;
/// How far below its first finalized height a validator's scan starts.
const SCAN_BACKLOG: u64 = 32;
/// Pre-crash finalizations kept per validator, newest first.
const READS_KEPT: usize = 64;
/// Pre-crash finalizations re-read after a restart.
const REREADS: usize = 8;
/// Blocks a validator may trail the cluster's finalized height before it
/// counts as behind (E16/node-stuck).
const BEHIND_BLOCKS: u64 = 5;
/// Recent heights whose certificates are kept for comparison.
const CERTIFICATES_KEPT: usize = 256;
/// Metrics are read every this many ticks.
const METRICS_EVERY: u64 = 3;

#[derive(Debug, Default)]
struct NodeState {
    /// Not killed (or restarted since).
    up: bool,
    /// Inside an impairment window (see [`ConsensusOracle::on_event`]).
    impaired: bool,
    /// Last restart, until the node answered RPC (E15).
    restarted_ns: Option<u64>,
    reopen_reported: bool,
    finalized: Option<u64>,
    /// Highest height scanned since the last restart.
    scanned: Option<u64>,
    /// Finalized blocks as this node served them, across restarts.
    own: BTreeMap<u64, B256>,
    /// Finalizations this node served (height -> digest), newest kept.
    reads: BTreeMap<u64, B256>,
    /// Pre-crash reads still to re-check after the last restart.
    rereads: Vec<(u64, B256)>,
    /// The cluster's finalized height at the last restart, until reached.
    catch_up_target: Option<u64>,
    /// The node's first finalized height after the last restart: heights
    /// above it, up to the target, it finalized while catching up.
    restart_floor: Option<u64>,
    sparse_probed: bool,
    behind_since_ns: Option<u64>,
    stuck_reported: bool,
    metrics: Option<NodeMetrics>,
    blocked_reported: BTreeSet<String>,
}

/// E13-E18 over the cluster (see the module docs).
#[derive(Debug)]
pub struct ConsensusOracle {
    mesh_ns: u64,
    stall_ns: u64,
    catch_up_ns: u64,
    nodes: Vec<NodeState>,
    /// Finalized hash at each height, with the validator that served it first.
    canonical: BTreeMap<u64, (B256, ValidatorId)>,
    /// The first certificate read at each recent height: `(digest,
    /// certificate, validator)`.
    certificates: BTreeMap<u64, (B256, String, ValidatorId)>,
    /// Highest finalized height any validator served.
    cluster_max: u64,
    progress_ns: u64,
    stall_reported: bool,
    /// The cluster's finalized height when every validator was down.
    all_down_max: Option<u64>,
    /// Since when the full mesh is due; `None` while it holds.
    mesh_due_since_ns: Option<u64>,
    mesh_reported: bool,
    /// Coverage signatures already reported.
    covered: BTreeSet<&'static str>,
    ticks: u64,
}

fn always(ok: bool, sig: &str, detail: String) -> Verdict {
    Verdict::Always(ok, finding(sig, detail))
}

impl ConsensusOracle {
    /// A fresh oracle at guest time `now_ns` with `budget`.
    pub fn new(budget: LivenessBudget, now_ns: u64) -> ConsensusOracle {
        let s = 1_000_000_000;
        ConsensusOracle {
            mesh_ns: budget.mesh_secs * s,
            stall_ns: budget.stall_secs * s,
            catch_up_ns: budget.catch_up_secs * s,
            nodes: (0..VALIDATORS)
                .map(|_| NodeState {
                    up: true,
                    ..NodeState::default()
                })
                .collect(),
            canonical: BTreeMap::new(),
            certificates: BTreeMap::new(),
            cluster_max: 0,
            progress_ns: now_ns,
            stall_reported: false,
            all_down_max: None,
            mesh_due_since_ns: Some(now_ns),
            mesh_reported: false,
            covered: BTreeSet::new(),
            ticks: 0,
        }
    }

    fn cover(&mut self, sig: &'static str, detail: String, out: &mut Vec<Verdict>) {
        if self.covered.insert(sig) {
            out.push(Verdict::Sometimes(true, finding(sig, detail)));
        }
    }

    /// Validators killed and not restarted.
    fn killed(&self) -> usize {
        self.nodes.iter().filter(|n| !n.up).count()
    }

    /// Validators counted against the fault budget: killed, or inside an
    /// impairment window (e.g. a network fault) while running.
    fn down(&self) -> usize {
        self.nodes.iter().filter(|n| !n.up || n.impaired).count()
    }

    /// Applies a nemesis event: a validator's `kill` or `restart`
    /// (container `v<i>`), or an `impair`/`heal` window over `targets`
    /// (validator numbers): impaired validators keep being checked for
    /// safety but count against the fault budget, and a heal restarts the
    /// liveness clocks like a restart does.
    pub fn on_event(&mut self, ev: &DstEvent, now_ns: u64) -> Vec<Verdict> {
        if ev.source != "nemesis" {
            return Vec::new();
        }
        if let kind @ ("impair" | "heal") = ev.kind.as_str() {
            let targets: Vec<ValidatorId> =
                serde_json::from_value(ev.detail["targets"].clone()).unwrap_or_default();
            for t in targets {
                self.nodes[t.index()].impaired = kind == "impair";
            }
            if kind == "heal" {
                self.mesh_due_since_ns = Some(now_ns);
                self.mesh_reported = false;
                if self.down() <= FAULT_BUDGET {
                    self.progress_ns = self.progress_ns.max(now_ns);
                }
                for n in &mut self.nodes {
                    n.behind_since_ns = None;
                }
            }
            return Vec::new();
        }
        let Some(v) = ev.container.as_deref().and_then(ValidatorId::of_container) else {
            return Vec::new();
        };
        let cluster_max = self.cluster_max;
        let n = &mut self.nodes[v.index()];
        match ev.kind.as_str() {
            "kill" => {
                n.up = false;
                // Its newest reads, the evidence a restart must keep.
                n.rereads = n
                    .reads
                    .iter()
                    .rev()
                    .take(REREADS)
                    .map(|(h, d)| (*h, *d))
                    .collect();
                if self.killed() == self.nodes.len() {
                    self.all_down_max = Some(cluster_max);
                }
            }
            "restart" => {
                n.up = true;
                n.restarted_ns = Some(now_ns);
                n.reopen_reported = false;
                n.finalized = None;
                n.scanned = None;
                n.catch_up_target = Some(cluster_max);
                n.restart_floor = None;
                n.sparse_probed = false;
                n.behind_since_ns = None;
                n.stuck_reported = false;
                n.metrics = None;
                self.mesh_due_since_ns = Some(now_ns);
                self.mesh_reported = false;
                if self.down() <= FAULT_BUDGET {
                    // The stall clock restarts once liveness is due again.
                    self.progress_ns = self.progress_ns.max(now_ns);
                }
            }
            _ => {}
        }
        Vec::new()
    }

    /// E17 and E15 for one log line of validator `v`.
    pub fn on_log(&mut self, v: ValidatorId, line: &str) -> Vec<Verdict> {
        let mut out = Vec::new();
        let detail = || format!("{v}: {}", line.chars().take(400).collect::<String>());
        if line.contains(" WARN ")
            && line.contains("peer=")
            && BLOCK_MESSAGES.iter().any(|m| line.contains(m))
        {
            out.push(always(false, "E17/honest-peer-blocked", detail()));
        }
        let n = &self.nodes[v.index()];
        let recovering = n.catch_up_target.is_some();
        let lower = line.to_lowercase();
        if recovering
            && line.contains(" ERROR ")
            && STORAGE_ERROR_WORDS.iter().any(|w| lower.contains(w))
        {
            out.push(always(false, "E15/consensus-storage-error", detail()));
        }
        out
    }

    /// Records block `b` served by `v` as finalized: E13.
    fn record_block(&mut self, v: ValidatorId, b: FinalizedBlock, out: &mut Vec<Verdict>) {
        let h = b.number;
        let n = &mut self.nodes[v.index()];
        if let Some(prev) = n.own.insert(h, b.hash) {
            if prev != b.hash {
                out.push(always(
                    false,
                    "E13/finalized-reverted",
                    format!("{v}: finalized block {h} was {prev}, now {}", b.hash),
                ));
            }
        }
        match self.canonical.get(&h) {
            Some((hash, first)) if *hash != b.hash => out.push(always(
                false,
                "E13/finalized-conflict",
                format!(
                    "height {h}: {first} finalized {hash}, {v} finalized {}",
                    b.hash
                ),
            )),
            Some(_) => {}
            None => {
                self.canonical.insert(h, (b.hash, v));
            }
        }
        if let Some((parent, first)) = h.checked_sub(1).and_then(|p| self.canonical.get(&p)) {
            if *parent != b.parent {
                out.push(always(
                    false,
                    "E13/finalized-not-prefix",
                    format!(
                        "{v}: block {h} {} has parent {}, but {first} finalized {} at {}",
                        b.hash,
                        b.parent,
                        parent,
                        h - 1
                    ),
                ));
            }
        }
    }

    /// One validator's step; whether it answered.
    fn tick_node(
        &mut self,
        view: &mut impl ClusterView,
        v: ValidatorId,
        now_ns: u64,
        out: &mut Vec<Verdict>,
    ) -> bool {
        let i = v.index();
        let fin = match view.finalized(v) {
            Ok(f) => f,
            Err(e) => {
                let n = &mut self.nodes[i];
                if let Some(t) = n.restarted_ns {
                    if !n.reopen_reported && now_ns.saturating_sub(t) > self.catch_up_ns {
                        n.reopen_reported = true;
                        out.push(always(
                            false,
                            "E15/reopen-failed",
                            format!(
                                "{v} not answering {}s after its restart: {e}",
                                self.catch_up_ns / 1_000_000_000
                            ),
                        ));
                    }
                }
                return false;
            }
        };
        if self.nodes[i].restarted_ns.take().is_some() {
            out.push(always(true, "E15/reopen-failed", String::new()));
        }
        let Some((f, hash)) = fin else {
            return true;
        };
        if let Some((want, first)) = self.canonical.get(&f) {
            if *want != hash {
                out.push(always(
                    false,
                    "E13/finalized-conflict",
                    format!("height {f}: {first} finalized {want}, {v} reports finalized {hash}"),
                ));
            }
        }
        let n = &mut self.nodes[i];
        if let Some(prev) = n.finalized.filter(|p| f < *p) {
            // Same blocks, lower height: the node's finalized tag went back
            // (e.g. it reported a checkpoint from before a crash its chain
            // no longer reaches); a different block is E13's.
            out.push(always(
                false,
                "E14/finalized-height-regressed",
                format!("{v}: finalized height went from {prev} back to {f} within one process"),
            ));
        } else if n.finalized.is_some() {
            out.push(always(
                true,
                "E14/finalized-height-regressed",
                String::new(),
            ));
        }
        n.finalized = Some(f);
        n.restart_floor.get_or_insert(f);
        let start = n
            .scanned
            .map_or(f.saturating_sub(SCAN_BACKLOG), |s| s + 1)
            .max(1);
        let mut scanned = 0;
        for h in start..=f.min(start + SCAN_PER_TICK - 1) {
            match view.block(v, h) {
                Ok(Some(b)) if b.number == h => {
                    self.record_block(v, b, out);
                    self.nodes[i].scanned = Some(h);
                    scanned += 1;
                }
                _ => break,
            }
        }
        if scanned > 0 {
            for sig in [
                "E13/finalized-conflict",
                "E13/finalized-not-prefix",
                "E13/finalized-reverted",
            ] {
                if !out
                    .iter()
                    .any(|o| matches!(o, Verdict::Always(false, x) if x.signature == sig))
                {
                    out.push(always(true, sig, String::new()));
                }
            }
        }
        // The newest finalization, evidence for E14 if the node crashes.
        if let Ok(FinalizationRead::Present {
            digest,
            certificate,
            ..
        }) = view.finalization(v, f)
        {
            self.check_certificate(v, f, digest, certificate, out);
            let n = &mut self.nodes[i];
            n.reads.insert(f, digest);
            while n.reads.len() > READS_KEPT {
                n.reads.pop_first();
            }
        }
        self.check_rereads(view, v, f, out);
        self.check_catch_up(view, v, f, now_ns, out);
        true
    }

    /// The finalization `v` serves at height `h` certifies the block `v`
    /// finalized there (E13), and its certificate equals every other
    /// validator's for that height (E14: the certificate is a threshold BLS
    /// signature, unique per message, so honest nodes hold the same bytes).
    fn check_certificate(
        &mut self,
        v: ValidatorId,
        h: u64,
        digest: B256,
        certificate: String,
        out: &mut Vec<Verdict>,
    ) {
        if let Some(own) = self.nodes[v.index()].own.get(&h) {
            if *own != digest {
                out.push(always(
                    false,
                    "E13/finalized-conflict",
                    format!(
                        "{v}: finalization {h} certifies {digest}, its finalized block is {own}"
                    ),
                ));
            }
        }
        match self.certificates.get(&h) {
            Some((d, cert, first)) if *d == digest => out.push(always(
                *cert == certificate,
                "E14/certificate-invalid",
                format!("height {h} ({digest}): {first} certificate {cert}, {v} certificate {certificate}"),
            )),
            Some(_) => {} // a digest conflict: E13 reports it
            None => {
                self.certificates.insert(h, (digest, certificate, v));
                while self.certificates.len() > CERTIFICATES_KEPT {
                    self.certificates.pop_first();
                }
            }
        }
    }

    /// E14 (and E13 reverts) for the pre-crash reads of a restarted `v`,
    /// once it has finalized past them.
    fn check_rereads(
        &mut self,
        view: &mut impl ClusterView,
        v: ValidatorId,
        f: u64,
        out: &mut Vec<Verdict>,
    ) {
        let pending = std::mem::take(&mut self.nodes[v.index()].rereads);
        let mut keep = Vec::new();
        for (h, digest) in pending {
            if h > f || !self.nodes[v.index()].up {
                keep.push((h, digest));
                continue;
            }
            let read = view.finalization(v, h);
            let block = view.block(v, h);
            let (Ok(read), Ok(block)) = (read, block) else {
                keep.push((h, digest));
                continue;
            };
            match read {
                FinalizationRead::Present { digest: d, .. } => {
                    out.push(always(
                        d == digest,
                        "E13/finalized-reverted",
                        format!("{v}: finalization {h} was {digest} before the crash, now {d}"),
                    ));
                    out.push(always(true, "E14/finalization-lost", String::new()));
                }
                FinalizationRead::Missing(what) => out.push(always(
                    false,
                    "E14/finalization-lost",
                    format!("{v}: finalization {h} ({digest}) served before the crash is missing after it ({what})"),
                )),
            }
            let want = self.nodes[v.index()].own.get(&h).copied();
            match block {
                Some(b) => {
                    out.push(always(true, "E14/finalized-block-lost", String::new()));
                    if let Some(want) = want {
                        out.push(always(
                            b.hash == want,
                            "E13/finalized-reverted",
                            format!("{v}: finalized block {h} was {want} before the crash, now {}", b.hash),
                        ));
                    }
                }
                None => out.push(always(
                    false,
                    "E14/finalized-block-lost",
                    format!("{v}: finalized block {h} ({want:?}) missing after the crash, finalized height {f}"),
                )),
            }
        }
        self.nodes[v.index()].rereads = keep;
    }

    /// S/validator-caught-up, S/archive-sparse and E16/node-stuck for `v`.
    fn check_catch_up(
        &mut self,
        view: &mut impl ClusterView,
        v: ValidatorId,
        f: u64,
        now_ns: u64,
        out: &mut Vec<Verdict>,
    ) {
        let over_budget = self.down() > FAULT_BUDGET;
        let cluster_max = self.cluster_max.max(f);
        let n = &mut self.nodes[v.index()];
        if let Some(target) = n.catch_up_target {
            if f >= target {
                n.catch_up_target = None;
                self.cover(
                    "S/validator-caught-up",
                    format!("{v} reached {target} after its restart"),
                    out,
                );
            }
        }
        let n = &mut self.nodes[v.index()];
        if n.catch_up_target.is_none() && !n.sparse_probed {
            if let Some(floor) = n.restart_floor.filter(|fl| *fl + 1 < f) {
                n.sparse_probed = true;
                // A height it finalized while catching up: it may lack the
                // certificate (sparse archive), which is fine.
                let probe = floor + (f - floor) / 2;
                if let Ok(FinalizationRead::Missing(what)) = view.finalization(v, probe) {
                    self.cover(
                        "S/archive-sparse",
                        format!("{v}: no certificate for {probe} ({what}) after catching up"),
                        out,
                    );
                }
            }
        }
        let n = &mut self.nodes[v.index()];
        if over_budget || f + BEHIND_BLOCKS >= cluster_max {
            n.behind_since_ns = None;
            if f + BEHIND_BLOCKS >= cluster_max {
                n.stuck_reported = false;
            }
            return;
        }
        let since = *n.behind_since_ns.get_or_insert(now_ns);
        if !n.stuck_reported && now_ns.saturating_sub(since) > self.catch_up_ns {
            n.stuck_reported = true;
            out.push(always(
                false,
                "E16/node-stuck",
                format!(
                    "{v} at finalized {f}, cluster at {cluster_max}, for {}s",
                    self.catch_up_ns / 1_000_000_000
                ),
            ));
        }
    }

    /// Metrics-driven checks for every up validator: E17, E18, the mesh and
    /// counter coverage.
    fn tick_metrics(&mut self, view: &mut impl ClusterView, now_ns: u64, out: &mut Vec<Verdict>) {
        let mut meshed = 0;
        for v in ValidatorId::all() {
            if !self.nodes[v.index()].up {
                continue;
            }
            let Ok(m) = view.metrics(v) else { continue };
            if m.connected_peers + 1 >= usize::from(VALIDATORS) {
                meshed += 1;
            }
            let prev = self.nodes[v.index()].metrics.replace(m.clone());
            for peer in &m.blocked_peers {
                if self.nodes[v.index()].blocked_reported.insert(peer.clone()) {
                    out.push(always(
                        false,
                        "E17/honest-peer-blocked",
                        format!("{v} blocked peer {peer} (tracker_directory_blocked)"),
                    ));
                }
            }
            let Some(prev) = prev else { continue };
            // Counters only grow within one process.
            let grew = |a: u64, b: u64| b > a;
            if grew(prev.handshakes_blocked, m.handshakes_blocked) {
                out.push(always(
                    false,
                    "E17/honest-peer-blocked",
                    format!(
                        "{v}: handshakes_blocked_total {} -> {}",
                        prev.handshakes_blocked, m.handshakes_blocked
                    ),
                ));
            } else if m.blocked_peers.is_empty() {
                out.push(always(true, "E17/honest-peer-blocked", String::new()));
            }
            if grew(prev.dkg_failures, m.dkg_failures) {
                out.push(always(
                    false,
                    "E18/dkg-failed",
                    format!(
                        "{v}: ceremony failures {} -> {} (epoch {:?})",
                        prev.dkg_failures, m.dkg_failures, m.epoch
                    ),
                ));
            } else if grew(prev.dkg_successes, m.dkg_successes) {
                out.push(always(true, "E18/dkg-failed", String::new()));
            }
            if prev.epoch.zip(m.epoch).is_some_and(|(a, b)| b > a) {
                self.cover(
                    "S/epoch-transition",
                    format!("{v}: epoch {:?} -> {:?}", prev.epoch, m.epoch),
                    out,
                );
            }
            if grew(prev.nullifications, m.nullifications) {
                self.cover(
                    "S/nullification",
                    format!("{v}: {} nullifications", m.nullifications),
                    out,
                );
            }
            if grew(prev.leader_timeouts, m.leader_timeouts) {
                self.cover(
                    "S/leader-skip",
                    format!("{v}: {} leader timeouts", m.leader_timeouts),
                    out,
                );
            }
            if grew(prev.resolver_fetches, m.resolver_fetches) {
                self.cover(
                    "S/resolver-fetch",
                    format!("{v}: {} resolver fetches", m.resolver_fetches),
                    out,
                );
            }
        }
        if self.down() > 0 {
            return;
        }
        if meshed == usize::from(VALIDATORS) {
            if self.mesh_due_since_ns.take().is_some() {
                self.cover(
                    "S/mesh-formed",
                    "every validator connected to every other".into(),
                    out,
                );
                out.push(always(true, "E16/mesh-timeout", String::new()));
            }
        } else if let Some(since) = self.mesh_due_since_ns {
            if !self.mesh_reported && now_ns.saturating_sub(since) > self.mesh_ns {
                self.mesh_reported = true;
                out.push(always(
                    false,
                    "E16/mesh-timeout",
                    format!(
                        "{meshed}/{VALIDATORS} validators fully connected {}s after the last restart",
                        self.mesh_ns / 1_000_000_000
                    ),
                ));
            }
        }
    }

    /// One oracle step at guest time `now_ns`.
    pub fn tick(&mut self, view: &mut impl ClusterView, now_ns: u64) -> Vec<Verdict> {
        self.tick_with_events(view, now_ns, &mut Vec::new)
    }

    /// [`tick`](Self::tick), applying the events `fresh` returns (those
    /// logged since its last call) right before each validator's reads. A
    /// tick makes many RPCs and can outlast a kill and restart: with one
    /// events snapshot per tick, a read answered by the new process would
    /// be charged to the old one (seen as a finalized height going back
    /// within one process). The nemesis logs a kill before issuing it, so a
    /// read made after `fresh` has no kill pending was answered by the
    /// incarnation the oracle knows.
    pub fn tick_with_events(
        &mut self,
        view: &mut impl ClusterView,
        now_ns: u64,
        fresh: &mut dyn FnMut() -> Vec<DstEvent>,
    ) -> Vec<Verdict> {
        let mut out = Vec::new();
        self.ticks += 1;
        for v in ValidatorId::all() {
            for ev in fresh() {
                out.extend(self.on_event(&ev, now_ns));
            }
            if self.nodes[v.index()].up {
                self.tick_node(view, v, now_ns, &mut out);
            }
        }
        let max = self
            .nodes
            .iter()
            .filter_map(|n| n.finalized)
            .max()
            .unwrap_or(0);
        if max > self.cluster_max {
            self.cluster_max = max;
            self.progress_ns = now_ns;
            self.stall_reported = false;
            if self.down() > 0 {
                self.cover(
                    "S/finalized-during-fault",
                    format!("finalized {max} with {} validator(s) down", self.down()),
                    &mut out,
                );
            }
            if let Some(m) = self.all_down_max.filter(|m| max > *m) {
                self.all_down_max = None;
                self.cover(
                    "S/full-restart-recovered",
                    format!("finalized {max} past {m} after every validator was down"),
                    &mut out,
                );
            }
        }
        if self.down() > FAULT_BUDGET {
            self.progress_ns = now_ns;
        } else if !self.stall_reported && now_ns.saturating_sub(self.progress_ns) > self.stall_ns {
            self.stall_reported = true;
            out.push(always(
                false,
                "E16/stalled",
                format!(
                    "finalized height {} did not advance for {}s with {} validator(s) down",
                    self.cluster_max,
                    self.stall_ns / 1_000_000_000,
                    self.down()
                ),
            ));
        }
        if self.ticks % METRICS_EVERY == 1 {
            self.tick_metrics(view, now_ns, &mut out);
        }
        out
    }
}

// ---- E13 cross-validator execution differential (`validator_engine_diff`) ----

/// Per-validator execution reads the differential oracle needs; `Err` while a
/// validator is unreachable (e.g. killed), `Ok(None)` past its head.
pub trait ExecView {
    /// Canonical block `number` on `v`: `(hash, header stateRoot)`.
    fn header(&mut self, v: ValidatorId, number: u64) -> Result<Option<(B256, B256)>, String>;
    /// `eth_getProof` of `address`/`slots` at `number` on `v`.
    fn proof(
        &mut self,
        v: ValidatorId,
        address: &str,
        slots: &[u64],
        number: u64,
    ) -> Result<AccountProof, String>;
}

/// Blocks the differential checks per tick (newest first is not needed; it
/// sweeps forward from the last checked block). Bounds the RPC per tick.
const EXEC_DIFF_PER_TICK: u64 = 4;
/// On the first tick, how far below the cluster's agreed height to start, so
/// the differential checks recent blocks without replaying from genesis.
const EXEC_DIFF_BACKLOG: u64 = 16;

/// E13 cross-validator execution differential: at every block the validators
/// AGREE on (same finalized/canonical hash — E13 safety already checks the
/// agreement), their EXECUTION must match too. For each such block it compares,
/// across the agreeing validators, the header state root
/// (`E13/validator-state-root-differs`) and, on the same deterministic
/// `(address, slots)` sample E5/E6 use, the `eth_getProof` response: each proof
/// must verify against that validator's state root and prove the same values as
/// its peers (`E13/validator-proof-differs`). Running the validators on
/// different [`EngineProfile`]s (the `validator_engine_diff` feature) turns this
/// into the sparse-trie-vs-simple-engine differential the old E7 dev-node
/// reference provided — the #16-class detector — on real consensus nodes.
///
/// Deterministic: validators are iterated in [`ValidatorId::all`] order, the
/// sample is drawn from the seed (the `tries` passed in are
/// `Config::tries()`), and it sweeps forward over block numbers with no
/// wall-clock input.
#[derive(Debug)]
pub struct ExecDiffOracle {
    /// Each validator's engine profile (index order; `profiles[i]` is
    /// `v<i+1>`). Used only to report which engines diverged and to gate the
    /// coverage on at least two distinct profiles being compared.
    profiles: Vec<EngineProfile>,
    /// The `(address, slots)` sample, the same E5/E6 check (`Config::tries()`).
    tries: Vec<TrieConfig>,
    /// Highest block fully compared.
    checked: u64,
    started: bool,
    covered: bool,
}

fn exec_always(ok: bool, sig: &str, detail: String) -> Verdict {
    Verdict::Always(ok, finding(sig, detail))
}

impl ExecDiffOracle {
    /// A fresh differential over `profiles` (one per validator) and the
    /// `(address, slots)` sample `tries`.
    pub fn new(profiles: Vec<EngineProfile>, tries: Vec<TrieConfig>) -> ExecDiffOracle {
        ExecDiffOracle {
            profiles,
            tries,
            checked: 0,
            started: false,
            covered: false,
        }
    }

    /// The profile of validator `v`, if known.
    fn profile(&self, v: ValidatorId) -> Option<EngineProfile> {
        self.profiles.get(v.index()).copied()
    }

    /// One step: compare execution across the agreeing validators for every
    /// not-yet-checked block up to `target` (the cluster's agreed finalized
    /// height — a height every answering validator has), bounded per tick.
    pub fn tick(&mut self, view: &mut impl ExecView, target: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        if self.profiles.len() < 2 {
            return out;
        }
        if !self.started {
            // Start near the agreed height, not at genesis.
            self.checked = target.saturating_sub(EXEC_DIFF_BACKLOG);
            self.started = true;
        }
        let up_to = target.min(self.checked + EXEC_DIFF_PER_TICK);
        while self.checked < up_to {
            let b = self.checked + 1;
            self.check_block(view, b, &mut out);
            self.checked = b;
        }
        out
    }

    /// Compares block `b` across the validators that finalized the same hash.
    fn check_block(&mut self, view: &mut impl ExecView, b: u64, out: &mut Vec<Verdict>) {
        // Group the validators by the block hash they serve (agreement).
        let mut groups: BTreeMap<B256, Vec<(ValidatorId, B256)>> = BTreeMap::new();
        for v in ValidatorId::all() {
            if let Ok(Some((hash, root))) = view.header(v, b) {
                groups.entry(hash).or_default().push((v, root));
            }
        }
        for (hash, group) in &groups {
            if group.len() < 2 {
                continue;
            }
            self.check_group(view, b, *hash, group, out);
        }
    }

    /// Compares execution within one agreeing group (`>= 2` validators, same
    /// block hash `hash`): the header state root, then each proof.
    fn check_group(
        &mut self,
        view: &mut impl ExecView,
        b: u64,
        hash: B256,
        group: &[(ValidatorId, B256)],
        out: &mut Vec<Verdict>,
    ) {
        let (ref_v, ref_root) = group[0];
        let mut root_ok = true;
        // Same block hash implies the same header state root; a mismatch means
        // a validator served a header inconsistent with the one it finalized.
        for &(v, root) in &group[1..] {
            if root != ref_root {
                root_ok = false;
                out.push(exec_always(
                    false,
                    "E13/validator-state-root-differs",
                    format!(
                        "block {b} {hash}: {ref_v} ({}) state root {ref_root}, {v} ({}) state root {root}",
                        self.profile_name(ref_v),
                        self.profile_name(v),
                    ),
                ));
            }
        }
        if root_ok {
            out.push(exec_always(
                true,
                "E13/validator-state-root-differs",
                String::new(),
            ));
        }
        let mut proof_ok = true;
        let mut compared = false;
        for trie in &self.tries {
            // The reference validator's proof for this contract.
            let reference = match view.proof(ref_v, &trie.address, &trie.slots, b) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Err(e) = trie_ref::verify(&reference, ref_root) {
                proof_ok = false;
                out.push(exec_always(
                    false,
                    "E13/validator-proof-differs",
                    format!(
                        "block {b} {hash}, {}{ref_v} ({}): proof does not verify against its state root {ref_root}: {e:?}",
                        self.contract_note(trie),
                        self.profile_name(ref_v),
                    ),
                ));
            }
            for &(v, root) in &group[1..] {
                let proof = match view.proof(v, &trie.address, &trie.slots, b) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                compared = true;
                if let Err(e) = trie_ref::verify(&proof, root) {
                    proof_ok = false;
                    out.push(exec_always(
                        false,
                        "E13/validator-proof-differs",
                        format!(
                            "block {b} {hash}, {}{v} ({}): proof does not verify against its state root {root}: {e:?}",
                            self.contract_note(trie),
                            self.profile_name(v),
                        ),
                    ));
                }
                if let Some(diff) = proof_diff(&reference, &proof) {
                    proof_ok = false;
                    out.push(exec_always(
                        false,
                        "E13/validator-proof-differs",
                        format!(
                            "block {b} {hash}, {}{ref_v} ({}) vs {v} ({}): {diff}",
                            self.contract_note(trie),
                            self.profile_name(ref_v),
                            self.profile_name(v),
                        ),
                    ));
                }
            }
        }
        if proof_ok && compared {
            out.push(exec_always(
                true,
                "E13/validator-proof-differs",
                String::new(),
            ));
        }
        // Coverage: a block was compared across validators running at least two
        // distinct engine profiles.
        if !self.covered {
            let distinct: BTreeSet<EngineProfile> =
                group.iter().filter_map(|&(v, _)| self.profile(v)).collect();
            if distinct.len() >= 2 {
                self.covered = true;
                let profiles: Vec<String> = distinct
                    .iter()
                    .map(|p| format!("{p:?}[{}]", p.flags().join(" ")))
                    .collect();
                out.push(Verdict::Sometimes(
                    true,
                    finding(
                        "S/validator-engine-diff-checked",
                        format!(
                            "block {b}: execution compared across {} validators running {}",
                            group.len(),
                            profiles.join(", ")
                        ),
                    ),
                ));
            }
        }
    }

    fn profile_name(&self, v: ValidatorId) -> String {
        self.profile(v)
            .map(|p| format!("{p:?}"))
            .unwrap_or_else(|| "?".into())
    }

    fn contract_note(&self, trie: &TrieConfig) -> String {
        if self.tries.len() > 1 {
            format!("contract {}, ", trie.address)
        } else {
            String::new()
        }
    }
}

/// How two proofs of the same `(address, slots)` at the same block differ in
/// their proven state, if at all (the storage root, or a slot's proven value).
fn proof_diff(a: &AccountProof, b: &AccountProof) -> Option<String> {
    if a.storage_hash != b.storage_hash {
        return Some(format!(
            "storage hash {} vs {}",
            a.storage_hash, b.storage_hash
        ));
    }
    for (pa, pb) in a.storage_proof.iter().zip(&b.storage_proof) {
        if pa.key == pb.key && pa.value != pb.value {
            return Some(format!(
                "slot {} proven {} vs {}",
                pa.key, pa.value, pb.value
            ));
        }
    }
    None
}

// ---- Strand C: cross-node same-height state-root probe (`verify_state_root`) ----

/// Heights the same-height probe checks per tick.
const SAME_HEIGHT_PER_TICK: u64 = 4;
/// How far below the lowest head to probe, so the block is settled on every
/// validator and transient tip disagreement is not a finding.
const SAME_HEIGHT_LAG: u64 = 2;
/// First-tick backlog below the settled height.
const SAME_HEIGHT_BACKLOG: u64 = 8;

/// Strand C: at a height every validator has settled on (the lowest head minus
/// a small lag), the validators' canonical blocks must share one state root. A
/// producer that self-accepts a block with a wrong state root diverges from its
/// honest peers at that height, so this reports it promptly
/// (`E13/same-height-state-root-differs`) instead of only as an E16 liveness
/// stall. It reuses the engine-diff per-validator [`ExecView`] plumbing.
///
/// Distinct from [`ExecDiffOracle`], which compares only validators that already
/// AGREE on the block hash: this compares across the full set at the same
/// height, so a hash/root fork is the signal it looks for, not a precondition.
#[derive(Debug)]
pub struct SameHeightOracle {
    /// Per-validator engine profiles (index order), for the report; may be empty.
    profiles: Vec<EngineProfile>,
    /// Highest height probed.
    checked: u64,
    started: bool,
    covered: bool,
}

impl SameHeightOracle {
    pub fn new(profiles: Vec<EngineProfile>) -> SameHeightOracle {
        SameHeightOracle {
            profiles,
            checked: 0,
            started: false,
            covered: false,
        }
    }

    fn profile_name(&self, v: ValidatorId) -> String {
        self.profiles
            .get(v.index())
            .map(|p| format!("{p:?}"))
            .unwrap_or_else(|| "?".into())
    }

    /// One step: probe every not-yet-checked settled height up to `min_head`
    /// minus the lag, bounded per tick.
    pub fn tick(&mut self, view: &mut impl ExecView, min_head: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        let settled = min_head.saturating_sub(SAME_HEIGHT_LAG);
        if settled == 0 {
            return out;
        }
        if !self.started {
            self.checked = settled.saturating_sub(SAME_HEIGHT_BACKLOG);
            self.started = true;
        }
        if settled < self.checked {
            self.checked = settled.saturating_sub(1);
        }
        let up_to = settled.min(self.checked + SAME_HEIGHT_PER_TICK);
        while self.checked < up_to {
            let b = self.checked + 1;
            self.check_block(view, b, &mut out);
            self.checked = b;
        }
        out
    }

    /// Compares every answering validator's canonical block at height `b`.
    fn check_block(&mut self, view: &mut impl ExecView, b: u64, out: &mut Vec<Verdict>) {
        // (validator, block hash, state root).
        let mut seen: Vec<(ValidatorId, B256, B256)> = Vec::new();
        for v in ValidatorId::all() {
            if let Ok(Some((hash, root))) = view.header(v, b) {
                seen.push((v, hash, root));
            }
        }
        if seen.len() < 2 {
            return;
        }
        let (ref_v, _, ref_root) = seen[0];
        let mut ok = true;
        for &(v, hash, root) in &seen[1..] {
            if root != ref_root {
                ok = false;
                out.push(exec_always(
                    false,
                    "E13/same-height-state-root-differs",
                    format!(
                        "height {b}: {ref_v} ({}) state root {ref_root}, {v} ({}) state root {root} (hash {hash})",
                        self.profile_name(ref_v),
                        self.profile_name(v),
                    ),
                ));
            }
        }
        if ok {
            out.push(exec_always(
                true,
                "E13/same-height-state-root-differs",
                String::new(),
            ));
            if !self.covered {
                self.covered = true;
                out.push(Verdict::Sometimes(
                    true,
                    finding(
                        "S/same-height-root-checked",
                        format!("height {b}: {} validators share one state root", seen.len()),
                    ),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::Cooldown;
    use serde_json::Value;
    use std::collections::HashMap;

    const S: u64 = 1_000_000_000;

    fn h(n: u64, fork: u8) -> B256 {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_be_bytes());
        b[31] = fork;
        B256::from(b)
    }

    /// Each validator serves a chain up to its finalized height; fork 0 is
    /// the honest chain.
    #[derive(Default)]
    struct FakeCluster {
        finalized: HashMap<u8, u64>,
        fork: HashMap<(u8, u64), u8>,
        down: BTreeSet<u8>,
        missing_certs: BTreeSet<(u8, u64)>,
        metrics: HashMap<u8, NodeMetrics>,
    }

    impl FakeCluster {
        fn all_at(f: u64) -> Self {
            let mut c = FakeCluster::default();
            for v in 1..=4 {
                c.finalized.insert(v, f);
                c.metrics.insert(v, meshed());
            }
            c
        }
        fn hash(&self, v: u8, n: u64) -> B256 {
            h(n, self.fork.get(&(v, n)).copied().unwrap_or(0))
        }
    }

    fn meshed() -> NodeMetrics {
        NodeMetrics {
            connected_peers: 3,
            ..NodeMetrics::default()
        }
    }

    impl ClusterView for FakeCluster {
        fn finalized(&mut self, v: ValidatorId) -> Result<Option<(u64, B256)>, String> {
            let id = u8::from(v);
            if self.down.contains(&id) {
                return Err("down".into());
            }
            Ok(self.finalized.get(&id).map(|f| (*f, self.hash(id, *f))))
        }
        fn block(&mut self, v: ValidatorId, n: u64) -> Result<Option<FinalizedBlock>, String> {
            let id = u8::from(v);
            if self.down.contains(&id) {
                return Err("down".into());
            }
            Ok((n <= self.finalized[&id]).then(|| FinalizedBlock {
                number: n,
                hash: self.hash(id, n),
                parent: self.hash(id, n.saturating_sub(1)),
            }))
        }
        fn finalization(&mut self, v: ValidatorId, n: u64) -> Result<FinalizationRead, String> {
            let id = u8::from(v);
            if self.down.contains(&id) {
                return Err("down".into());
            }
            if self.missing_certs.contains(&(id, n)) || n > self.finalized[&id] {
                return Ok(FinalizationRead::Missing("certificate".into()));
            }
            Ok(FinalizationRead::Present {
                epoch: 0,
                view: n,
                digest: self.hash(id, n),
                certificate: format!("cert-{}", self.hash(id, n)),
            })
        }
        fn metrics(&mut self, v: ValidatorId) -> Result<NodeMetrics, String> {
            let id = u8::from(v);
            if self.down.contains(&id) {
                return Err("down".into());
            }
            Ok(self.metrics[&id].clone())
        }
    }

    fn ev(kind: &str, v: u8) -> DstEvent {
        DstEvent {
            source: "nemesis".into(),
            kind: kind.into(),
            container: Some(format!("v{v}")),
            guest_time_ns: 0,
            detail: Value::Null,
        }
    }

    fn fails(out: &[Verdict]) -> Vec<&str> {
        out.iter()
            .filter_map(|v| match v {
                Verdict::Always(false, f) => Some(f.signature.as_str()),
                _ => None,
            })
            .collect()
    }

    fn covered(out: &[Verdict]) -> Vec<&str> {
        out.iter()
            .filter_map(|v| match v {
                Verdict::Sometimes(true, f) => Some(f.signature.as_str()),
                _ => None,
            })
            .collect()
    }

    fn oracle() -> ConsensusOracle {
        ConsensusOracle::new(Cooldown::Fast.budget(), 0)
    }

    /// Runs ticks 1 s apart from `from` while `step` advances the cluster.
    fn run(
        o: &mut ConsensusOracle,
        c: &mut FakeCluster,
        from: u64,
        secs: u64,
        mut step: impl FnMut(&mut FakeCluster),
    ) -> Vec<Verdict> {
        let mut out = Vec::new();
        for t in from..from + secs {
            step(c);
            out.extend(o.tick(c, t * S));
        }
        out
    }

    fn advance(c: &mut FakeCluster) {
        for v in 1..=4u8 {
            if !c.down.contains(&v) {
                *c.finalized.get_mut(&v).unwrap() += 1;
            }
        }
    }

    #[test]
    fn honest_cluster_passes_and_forms_the_mesh() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(10);
        let out = run(&mut o, &mut c, 1, 30, advance);
        assert!(fails(&out).is_empty(), "{:?}", fails(&out));
        assert_eq!(covered(&out), ["S/mesh-formed"]);
    }

    #[test]
    fn a_conflicting_finalized_block_is_reported() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(10);
        c.fork.insert((3, 9), 1);
        let out = o.tick(&mut c, S);
        let f = fails(&out);
        assert!(f.contains(&"E13/finalized-conflict"), "{f:?}");
        // v3's block 10 links to its own 9, not the canonical one.
        assert!(f.contains(&"E13/finalized-not-prefix"), "{f:?}");
    }

    #[test]
    fn a_reverted_finalized_block_is_reported_across_a_restart() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(20);
        run(&mut o, &mut c, 1, 3, |_| {});
        o.on_event(&ev("kill", 2), 4 * S);
        c.down.insert(2);
        run(&mut o, &mut c, 4, 1, advance);
        c.down.remove(&2);
        o.on_event(&ev("restart", 2), 5 * S);
        // After the restart v2 serves another block 19 (and certificate).
        c.fork.insert((2, 19), 7);
        let out = run(&mut o, &mut c, 6, 3, advance);
        assert!(
            fails(&out).contains(&"E13/finalized-reverted"),
            "{:?}",
            fails(&out)
        );
    }

    #[test]
    fn lost_finalizations_are_judged_against_the_nodes_own_reads() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(20);
        run(&mut o, &mut c, 1, 5, advance); // v1..v4 read 21..25
        o.on_event(&ev("kill", 1), 6 * S);
        c.down.insert(1);
        run(&mut o, &mut c, 6, 5, advance);
        // After the restart v1 lacks a certificate it served before (24)...
        c.missing_certs.insert((1, 24));
        // ...and one for a height it never read (a peer's: fine).
        c.missing_certs.insert((1, 27));
        c.down.remove(&1);
        o.on_event(&ev("restart", 1), 11 * S);
        let out = run(&mut o, &mut c, 11, 5, advance);
        let f = fails(&out);
        assert_eq!(f, ["E14/finalization-lost"], "{f:?}");
        assert!(covered(&out).contains(&"S/validator-caught-up"));
    }

    #[test]
    fn liveness_is_excused_beyond_the_fault_budget_only() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(10);
        run(&mut o, &mut c, 1, 3, advance);
        // Two validators down: the chain may stall as long as they are.
        for v in [1, 2] {
            o.on_event(&ev("kill", v), 4 * S);
            c.down.insert(v);
        }
        let out = run(&mut o, &mut c, 4, 200, |_| {});
        assert!(fails(&out).is_empty(), "{:?}", fails(&out));
        o.on_event(&ev("restart", 1), 204 * S);
        c.down.remove(&1);
        // One down, within the budget: a stall past 60 s is a failure.
        let out = run(&mut o, &mut c, 205, 70, |_| {});
        let f = fails(&out);
        assert!(f.contains(&"E16/stalled"), "{f:?}");
    }

    #[test]
    fn finalizing_with_one_validator_down_is_covered_and_its_lag_judged() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(10);
        run(&mut o, &mut c, 1, 3, advance);
        o.on_event(&ev("kill", 4), 4 * S);
        c.down.insert(4);
        let out = run(&mut o, &mut c, 4, 5, advance);
        assert!(covered(&out).contains(&"S/finalized-during-fault"));
        c.down.remove(&4);
        o.on_event(&ev("restart", 4), 9 * S);
        // v4 comes back but never finalizes again.
        let out = run(&mut o, &mut c, 9, 100, |c| {
            for v in 1..=3u8 {
                *c.finalized.get_mut(&v).unwrap() += 1;
            }
        });
        let f = fails(&out);
        assert!(f.contains(&"E16/node-stuck"), "{f:?}");
        assert!(!f.contains(&"E16/stalled"), "{f:?}");
    }

    #[test]
    fn whole_cluster_restart_recovery_is_covered() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(10);
        run(&mut o, &mut c, 1, 3, advance);
        for v in 1..=4 {
            o.on_event(&ev("kill", v), 4 * S);
            c.down.insert(v);
        }
        run(&mut o, &mut c, 4, 3, |_| {});
        for v in 1..=4 {
            c.down.remove(&v);
            o.on_event(&ev("restart", v), 7 * S);
        }
        let out = run(&mut o, &mut c, 7, 5, advance);
        assert!(
            covered(&out).contains(&"S/full-restart-recovered"),
            "{out:?}"
        );
        assert!(fails(&out).is_empty(), "{:?}", fails(&out));
    }

    #[test]
    fn unreachable_restarted_node_fails_reopen() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(10);
        o.tick(&mut c, S);
        o.on_event(&ev("kill", 3), 2 * S);
        o.on_event(&ev("restart", 3), 3 * S);
        c.down.insert(3);
        let out = run(&mut o, &mut c, 3, 100, advance);
        assert!(
            fails(&out).contains(&"E15/reopen-failed"),
            "{:?}",
            fails(&out)
        );
    }

    #[test]
    fn mesh_must_reform_after_a_restart() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(10);
        run(&mut o, &mut c, 1, 4, advance);
        o.on_event(&ev("kill", 2), 5 * S);
        o.on_event(&ev("restart", 2), 6 * S);
        c.metrics.get_mut(&2).unwrap().connected_peers = 1;
        let out = run(&mut o, &mut c, 6, 70, advance);
        assert!(
            fails(&out).contains(&"E16/mesh-timeout"),
            "{:?}",
            fails(&out)
        );
    }

    #[test]
    fn blocked_peers_and_failed_ceremonies_are_reported() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(10);
        run(&mut o, &mut c, 1, 4, advance);
        let m = c.metrics.get_mut(&1).unwrap();
        m.blocked_peers.push("ab".into());
        m.dkg_failures = 1;
        m.epoch = Some(1);
        let out = run(&mut o, &mut c, 5, 4, advance);
        let f = fails(&out);
        assert!(
            f.contains(&"E17/honest-peer-blocked") && f.contains(&"E18/dkg-failed"),
            "{f:?}"
        );
        let line = "2026-10-09T06:49:11Z  WARN commonware_consensus::simplex: blocking equivocator peer=ee1a";
        let v1 = ValidatorId::new(1).unwrap();
        assert_eq!(fails(&o.on_log(v1, line)), ["E17/honest-peer-blocked"]);
        let resolver = "2026-10-09T06:49:11Z  WARN commonware_resolver::p2p::engine: serve send failed peer=7f id=24";
        assert!(o.on_log(v1, resolver).is_empty());
    }

    #[test]
    fn impairment_windows_count_against_the_fault_budget() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(10);
        run(&mut o, &mut c, 1, 3, advance);
        let window = |kind: &str, targets: &[u8]| DstEvent {
            source: "nemesis".into(),
            kind: kind.into(),
            container: None,
            guest_time_ns: 0,
            detail: serde_json::json!({ "targets": targets }),
        };
        // A 2|2 partition: no quorum, the stall is excused.
        o.on_event(&window("impair", &[1, 2]), 4 * S);
        let out = run(&mut o, &mut c, 4, 120, |_| {});
        assert!(fails(&out).is_empty(), "{:?}", fails(&out));
        // Healed: liveness is due again, from the heal.
        o.on_event(&window("heal", &[1, 2]), 124 * S);
        let out = run(&mut o, &mut c, 124, 50, |_| {});
        assert!(fails(&out).is_empty(), "{:?}", fails(&out));
        let out = run(&mut o, &mut c, 174, 20, |_| {});
        assert!(fails(&out).contains(&"E16/stalled"), "{:?}", fails(&out));
    }

    /// The shape of tempo-dst roll1/seed-1: right after a SIGKILL restart a
    /// validator's RPC reports its pre-crash finalized checkpoint (156),
    /// then the height consensus replays from (132).
    #[test]
    fn a_finalized_height_going_back_after_a_restart_is_reported() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(30);
        run(&mut o, &mut c, 1, 3, |_| {});
        o.on_event(&ev("kill", 4), 4 * S);
        c.down.insert(4);
        run(&mut o, &mut c, 4, 2, |_| {});
        c.down.remove(&4);
        o.on_event(&ev("restart", 4), 6 * S);
        let out = run(&mut o, &mut c, 6, 1, |_| {});
        assert!(fails(&out).is_empty(), "{:?}", fails(&out));
        c.finalized.insert(4, 25);
        let out = run(&mut o, &mut c, 7, 1, |_| {});
        assert_eq!(fails(&out), ["E14/finalized-height-regressed"]);
    }

    /// The shape of roll1/seed-1: v4 is killed and restarted while a tick
    /// is still reading v1..v3, and its new process (finalized 132, below
    /// the old one's 156) answers v4's reads. Applying events per validator
    /// attributes that read to the new incarnation.
    #[test]
    fn a_restart_during_a_tick_is_applied_before_the_nodes_reads() {
        let mut o = oracle();
        let mut c = FakeCluster::all_at(156);
        run(&mut o, &mut c, 1, 3, |_| {});
        c.finalized.insert(4, 132);
        let mut pending = vec![ev("kill", 4), ev("restart", 4)];
        let mut fresh = || std::mem::take(&mut pending);
        let out = o.tick_with_events(&mut c, 4 * S, &mut fresh);
        assert!(fails(&out).is_empty(), "{:?}", fails(&out));
        // With the events only after the tick, the same read is a regression.
        let mut stale = oracle();
        let mut c = FakeCluster::all_at(156);
        run(&mut stale, &mut c, 1, 3, |_| {});
        c.finalized.insert(4, 132);
        let out = stale.tick(&mut c, 4 * S);
        assert_eq!(fails(&out), ["E14/finalized-height-regressed"]);
    }

    #[test]
    fn parses_the_consensus_metrics() {
        let text = r#"# HELP x
consensus_engine_marshal_finalized_height 884
consensus_engine_epoch_manager_latest_epoch 4
consensus_network_tracker_directory_connected{peer="ee1a"} 1791529020533
consensus_network_tracker_directory_connected{peer="0c22"} 1791529041012
consensus_network_tracker_directory_blocked{peer="7f7f"} 1791529041012
consensus_network_listener_handshakes_blocked_total 2
consensus_engine_dkg_manager_ceremony_failures_total 0
consensus_engine_dkg_manager_ceremony_successes_total 4
consensus_engine_epoch_manager_simplex_voter_state_nullifications_total{epoch="4",leader="ab"} 3
consensus_engine_epoch_manager_simplex_voter_state_timeouts_total{epoch="4",leader="ab",reason="LeaderTimeout"} 2
consensus_engine_epoch_manager_simplex_voter_state_timeouts_total{epoch="4",leader="ab",reason="Retry"} 9
consensus_engine_p2p_resolver_fetch_total{status="Success"} 15
consensus_engine_p2p_resolver_fetch_total{status="Failure"} 6
"#;
        let m = parse_metrics(text);
        assert_eq!(m.finalized_height, Some(884));
        assert_eq!(m.epoch, Some(4));
        assert_eq!(m.connected_peers, 2);
        assert_eq!(m.blocked_peers, ["7f7f"]);
        assert_eq!(
            (m.handshakes_blocked, m.dkg_successes, m.dkg_failures),
            (2, 4, 0)
        );
        assert_eq!(
            (m.nullifications, m.leader_timeouts, m.resolver_fetches),
            (3, 2, 15)
        );
    }

    // ---- ExecDiffOracle (E13 cross-validator execution differential) ----

    const DIFF_ADDR: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
    const DIFF_SLOTS: [u64; 4] = [544, 646, 131, 0];

    /// Per-validator `(hash, state_root, proof)`; a validator absent here is
    /// "down" (its reads error). `header`/`proof` ignore the block number (the
    /// fake serves the same finalized state at every checked block).
    #[derive(Default)]
    struct FakeExec {
        nodes: HashMap<u8, (B256, B256, AccountProof)>,
    }

    impl FakeExec {
        /// A validator serving block hash `hash`, state root `root` and the
        /// proof built from `storage` (its own slot values).
        fn set(&mut self, v: u8, hash: B256, root: B256, storage: &[(u64, u64)]) {
            let (_proof_root, proof) =
                crate::trie_ref::tests::honest_proof(DIFF_ADDR, storage, &DIFF_SLOTS);
            self.nodes.insert(v, (hash, root, proof));
        }
    }

    impl ExecView for FakeExec {
        fn header(&mut self, v: ValidatorId, _n: u64) -> Result<Option<(B256, B256)>, String> {
            match self.nodes.get(&u8::from(v)) {
                Some((hash, root, _)) => Ok(Some((*hash, *root))),
                None => Err("down".into()),
            }
        }
        fn proof(
            &mut self,
            v: ValidatorId,
            _address: &str,
            _slots: &[u64],
            _n: u64,
        ) -> Result<AccountProof, String> {
            match self.nodes.get(&u8::from(v)) {
                Some((_, _, p)) => Ok(p.clone()),
                None => Err("down".into()),
            }
        }
    }

    fn diff_tries() -> Vec<TrieConfig> {
        vec![TrieConfig {
            address: DIFF_ADDR.into(),
            slots: DIFF_SLOTS.to_vec(),
            ..TrieConfig::default()
        }]
    }

    fn diff_oracle() -> ExecDiffOracle {
        // v1 Optimized, v2 Simple, v3 Compare, v4 Race: four distinct profiles.
        let profiles = crate::cluster::engine_profiles(4, {
            let mut s = 1u64;
            move |n| {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                s % n
            }
        });
        ExecDiffOracle::new(profiles, diff_tries())
    }

    #[test]
    fn same_height_probe_passes_when_validators_share_a_root() {
        let storage = [(544, 1), (646, 1), (131, 1), (0, 1)];
        let (root, _) = crate::trie_ref::tests::honest_proof(DIFF_ADDR, &storage, &DIFF_SLOTS);
        let mut view = FakeExec::default();
        for v in 1..=4 {
            view.set(v, h(100, 0), root, &storage);
        }
        let mut o = SameHeightOracle::new(vec![]);
        // min_head 100: probes up to 100 - LAG.
        let out = o.tick(&mut view, 100);
        assert!(fails(&out).is_empty(), "{:?}", fails(&out));
        assert!(
            covered(&out).contains(&"S/same-height-root-checked"),
            "{out:?}"
        );
    }

    #[test]
    fn same_height_probe_catches_a_producer_only_wrong_root() {
        // Three honest validators share a root; one (a producer) self-accepted a
        // block with a different state root at the same height.
        let honest = [(544, 1), (646, 1), (131, 1), (0, 1)];
        let (root, _) = crate::trie_ref::tests::honest_proof(DIFF_ADDR, &honest, &DIFF_SLOTS);
        let wrong = [(544, 2), (646, 1), (131, 1), (0, 1)];
        let (wrong_root, _) = crate::trie_ref::tests::honest_proof(DIFF_ADDR, &wrong, &DIFF_SLOTS);
        assert_ne!(root, wrong_root);
        let mut view = FakeExec::default();
        view.set(1, h(100, 1), wrong_root, &wrong);
        for v in 2..=4 {
            view.set(v, h(100, 0), root, &honest);
        }
        let mut o = SameHeightOracle::new(vec![]);
        let out = o.tick(&mut view, 100);
        assert!(
            fails(&out).contains(&"E13/same-height-state-root-differs"),
            "{out:?}"
        );
    }

    #[test]
    fn agreeing_validators_with_matching_execution_pass_and_are_covered() {
        // Every validator: same block hash, same state root, same storage.
        let storage = [(544, 1), (646, 1), (131, 1), (0, 1)];
        let (root, _) = crate::trie_ref::tests::honest_proof(DIFF_ADDR, &storage, &DIFF_SLOTS);
        let mut view = FakeExec::default();
        for v in 1..=4 {
            view.set(v, h(100, 0), root, &storage);
        }
        let mut o = diff_oracle();
        let out = o.tick(&mut view, 100);
        assert!(fails(&out).is_empty(), "{:?}", fails(&out));
        assert!(
            covered(&out).contains(&"S/validator-engine-diff-checked"),
            "{out:?}"
        );
        // The checks ran and recorded their passes.
        assert!(out.iter().any(
            |v| matches!(v, Verdict::Always(true, f) if f.signature == "E13/validator-proof-differs")
        ));
    }

    #[test]
    fn agreeing_on_hash_but_differing_on_state_root_is_reported() {
        let storage = [(544, 1)];
        let (root, _) = crate::trie_ref::tests::honest_proof(DIFF_ADDR, &storage, &DIFF_SLOTS);
        let mut view = FakeExec::default();
        // All four finalize the same block hash...
        for v in 1..=4 {
            view.set(v, h(50, 0), root, &storage);
        }
        // ...but v3 reports a different header state root.
        let (other_root, other) =
            crate::trie_ref::tests::honest_proof(DIFF_ADDR, &[(544, 9)], &DIFF_SLOTS);
        view.nodes.insert(3, (h(50, 0), other_root, other));
        let mut o = diff_oracle();
        let out = o.tick(&mut view, 50);
        assert!(
            fails(&out).contains(&"E13/validator-state-root-differs"),
            "{:?}",
            fails(&out)
        );
    }

    #[test]
    fn agreeing_on_hash_but_differing_on_a_proof_is_reported() {
        // v1..v4 report the same block hash and state root, but v2 serves a
        // proof built from a different storage (its state DB diverged): the
        // proof does not verify against the shared root / proves other values.
        let storage = [(544, 1), (646, 1)];
        let (root, _) = crate::trie_ref::tests::honest_proof(DIFF_ADDR, &storage, &DIFF_SLOTS);
        let mut view = FakeExec::default();
        for v in 1..=4 {
            view.set(v, h(70, 0), root, &storage);
        }
        // v2's proof is for a different storage, but it reports the shared root.
        let (_bad_root, bad) =
            crate::trie_ref::tests::honest_proof(DIFF_ADDR, &[(544, 2), (646, 1)], &DIFF_SLOTS);
        view.nodes.insert(2, (h(70, 0), root, bad));
        let mut o = diff_oracle();
        let out = o.tick(&mut view, 70);
        assert!(
            fails(&out).contains(&"E13/validator-proof-differs"),
            "{:?}",
            fails(&out)
        );
    }

    #[test]
    fn fewer_than_two_profiles_or_answering_validators_is_a_noop() {
        // Only one profile: nothing to diff.
        let mut o = ExecDiffOracle::new(vec![EngineProfile::Optimized], diff_tries());
        assert!(o.tick(&mut FakeExec::default(), 100).is_empty());
        // Two profiles but only one validator answers: no comparison.
        let storage = [(544, 1)];
        let (root, _) = crate::trie_ref::tests::honest_proof(DIFF_ADDR, &storage, &DIFF_SLOTS);
        let mut view = FakeExec::default();
        view.set(1, h(10, 0), root, &storage);
        let mut o = diff_oracle();
        let out = o.tick(&mut view, 100);
        assert!(
            fails(&out).is_empty() && covered(&out).is_empty(),
            "{out:?}"
        );
    }
}
