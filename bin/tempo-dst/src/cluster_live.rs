// SPDX-License-Identifier: GPL-2.0

//! The cluster (`validators=4`) in the guest: its RPC/metrics view, the
//! online oracle loop and the fault nemesis.
//!
//! - [`run_oracle`] (`tempo-dst oracle` with a cluster config): E1 over
//!   every validator's log, E13-E18 ([`ConsensusOracle`]), and the load's
//!   oracles (E5/E6/E8/E9, `S/load-included`; [`Oracle`] without its
//!   single-node liveness) against the validator the current load
//!   generation sends to, so successive generations check several nodes.
//! - [`run_nemesis`] (`tempo-dst nemesis` with a cluster config): executes
//!   the planner's [`ClusterFault`] plan: wait for its trigger, SIGKILL its
//!   targets (and, for a machine crash, crash their storage:
//!   `node_storage`), restart them, start the next load generation.

use std::{
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use alloy_primitives::B256;
use serde_json::{json, Value};

use crate::{
    cluster::{ClusterFault, Crash, FaultTrigger, RestartOrder, ValidatorId},
    common::{self, Config, DstEvent, NODE_CONTAINER},
    consensus::{
        parse_metrics, ClusterView, ConsensusOracle, ExecDiffOracle, ExecView, FinalizationRead,
        FinalizedBlock, NodeMetrics, SameHeightOracle,
    },
    historical::{AcrossRestart, Differential, RpcHist, Targets},
    node_storage,
    oracle::{self, Oracle, RpcChain},
    state_root::{RootView, RpcRoot, StateRootOracle},
    trie_ref::AccountProof,
    verdict::{finding, Verdict},
};

/// `eth_getBlockByNumber("finalized")` number of `v`.
pub fn finalized_height(v: ValidatorId) -> Result<Option<u64>, String> {
    common::with_rpc_url(v.rpc_url(), common::finalized_block).map(|f| f.map(|(n, _)| n))
}

/// `v`'s consensus metrics.
pub fn metrics(v: ValidatorId) -> Result<NodeMetrics, String> {
    let text = ureq::get(v.metrics_url())
        .timeout(Duration::from_secs(5))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    Ok(parse_metrics(&text))
}

/// The live cluster over RPC and Prometheus.
pub struct RpcCluster;

impl ClusterView for RpcCluster {
    fn finalized(&mut self, v: ValidatorId) -> Result<Option<(u64, B256)>, String> {
        let f = common::with_rpc_url(v.rpc_url(), common::finalized_block)?;
        f.map(|(n, hash)| {
            hash.parse::<B256>()
                .map(|h| (n, h))
                .map_err(|e| format!("bad finalized hash {hash}: {e}"))
        })
        .transpose()
    }

    fn block(&mut self, v: ValidatorId, number: u64) -> Result<Option<FinalizedBlock>, String> {
        let b = common::with_rpc_url(v.rpc_url(), || common::block_ref(number))?;
        Ok(b.map(|(hash, parent)| FinalizedBlock {
            number,
            hash,
            parent,
        }))
    }

    fn finalization(&mut self, v: ValidatorId, height: u64) -> Result<FinalizationRead, String> {
        let r = common::with_rpc_url(v.rpc_url(), || {
            common::rpc("consensus_getFinalization", json!([{ "height": height }]))
        });
        match r {
            Ok(r) => {
                let field = |k: &str| r.get(k).cloned().unwrap_or(Value::Null);
                Ok(FinalizationRead::Present {
                    epoch: field("epoch").as_u64().unwrap_or(0),
                    view: field("view").as_u64().unwrap_or(0),
                    digest: serde_json::from_value(field("digest"))
                        .map_err(|e| format!("bad finalization digest: {e}"))?,
                    certificate: field("certificate").as_str().unwrap_or("").to_string(),
                })
            }
            // A JSON-RPC error object: 503 names what is missing.
            Err(e) => match serde_json::from_str::<Value>(&e) {
                Ok(err) if err["code"] == 503 => Ok(FinalizationRead::Missing(
                    err["data"].as_str().unwrap_or("").to_string(),
                )),
                _ => Err(e),
            },
        }
    }

    fn metrics(&mut self, v: ValidatorId) -> Result<NodeMetrics, String> {
        metrics(v)
    }
}

/// A DKG dealer rejecting an ACK it already holds: after a restart or a
/// healed partition a player can deliver the same ACK again; the dealer
/// rejects it before storing anything (`Dealer::receive_ack`: "already
/// received an ack", tempo crates/consensus/src/dkg/manager/actor/state.rs)
/// and `handle_network_msg` logs the rejection at ERROR. The ceremony is
/// unaffected (E18 watches its failures), so this exact line is coverage,
/// not an E1 failure.
fn is_duplicate_dkg_ack(line: &str) -> bool {
    line.contains("tempo_consensus::dkg::manager::actor")
        && line.contains("failed to process ACK, already received an ack from")
}

/// E1 for one log line of `v` (detail prefixed with the validator).
fn scan_log(v: ValidatorId, line: &str) -> Option<Verdict> {
    if is_duplicate_dkg_ack(line) {
        return Some(Verdict::Sometimes(
            true,
            finding(
                "S/dkg-duplicate-ack-rejected",
                format!("{v}: {}", line.chars().take(400).collect::<String>()),
            ),
        ));
    }
    oracle::scan_line(line).map(|mut f| {
        f.detail = format!("{v}: {}", f.detail);
        Verdict::Always(false, f)
    })
}

/// `H/storage-layer-enoent` for a line of `v` reporting a commonware blob
/// operation on an open file failing with ENOENT while the datadirs are on a
/// storage layer. Blob resize and sync go through the file descriptor
/// (`File::set_len`, `sync_all`), and `ftruncate(2)`/`fsync(2)` do no path
/// lookup, so a kernel file system cannot return ENOENT for them; under FUSE
/// the daemon resolves the inode back to a path, and that resolution is
/// where it comes from. Such a failure is the harness's storage layer
/// (LazyFS), not the node: flagged so it is triaged as one.
fn scan_storage_layer(v: ValidatorId, line: &str, storage: bool) -> Option<Verdict> {
    let enoent = line.contains("kind: NotFound")
        && (line.contains("BlobResizeFailed") || line.contains("BlobSyncFailed"));
    (storage && enoent).then(|| {
        Verdict::Always(
            false,
            finding(
                "H/storage-layer-enoent",
                format!("{v}: {}", line.chars().take(400).collect::<String>()),
            ),
        )
    })
}

/// Reads the events logged since its last call.
#[derive(Default)]
struct EventCursor {
    seen: usize,
}

impl EventCursor {
    fn take_new(&mut self) -> Vec<DstEvent> {
        let events = common::read_events();
        let new = events.get(self.seen..).unwrap_or_default().to_vec();
        self.seen = events.len();
        new
    }
}

/// The same event as the dev-node [`Oracle`] knows it (container `tempo`).
fn as_node_event(kind: &str, guest_time_ns: u64) -> DstEvent {
    DstEvent {
        source: "nemesis".into(),
        kind: kind.into(),
        container: Some(NODE_CONTAINER.into()),
        guest_time_ns,
        detail: Value::Null,
    }
}

/// `tempo-dst oracle` for a cluster config: see the module docs.
pub fn run_oracle(cfg: &Config) {
    let Some(cluster) = cfg.cluster.clone() else {
        return;
    };
    let logs: Vec<(ValidatorId, mpsc::Receiver<String>)> = ValidatorId::all()
        .map(|v| {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || oracle::follow_logs(v.container(), tx));
            (v, rx)
        })
        .collect();
    let now = common::guest_time_ns();
    let mut consensus = ConsensusOracle::new(cluster.cooldown.budget(), now);
    // The cross-validator execution differential, when the per-validator engine
    // profiles are set (`validator_engine_diff`). Same (address, slots) sample
    // as the load's E5/E6 oracle.
    let mut exec_diff = cluster
        .engine_diff()
        .then(|| ExecDiffOracle::new(cluster.engine_profiles.clone(), cfg.tries()));
    // Strand A per validator and Strand C across the cluster
    // (`verify_state_root`): the generic valid-state-root invariant on every
    // node, and the cross-node same-height probe.
    let workload = cfg.state_root_workload();
    let mut state_root: Vec<(ValidatorId, StateRootOracle)> = if cfg.verify_state_root {
        ValidatorId::all()
            .map(|v| (v, StateRootOracle::new(workload.clone())))
            .collect()
    } else {
        Vec::new()
    };
    let mut same_height = cfg
        .verify_state_root
        .then(|| SameHeightOracle::new(cluster.engine_profiles.clone()));
    let mut load = Oracle::new(None, now, cfg.tries())
        .with_tip20(cfg.tip20)
        .with_cob(cfg.cob.clone());
    // The historical-RPC oracles (`historical=true`): E3h per validator and
    // E7h across the first two.
    let mut historical = cfg.historical.then(|| Historical::new(cfg));
    let mut target = cluster.load_target(0);
    // The load oracle's node is down until the next generation starts.
    let mut target_down = false;
    let mut cursor = EventCursor::default();
    let mut late_events = Vec::new();
    // The certified L1 follower's catch-up oracle (the tempo#8263 detector),
    // when a follower is attached (`follower=true`). Its logs are timestamped so
    // the gate ignores the previous incarnation's queued lines on rejoin.
    let mut follower = cfg
        .follower
        .then(|| crate::follower::FollowerOracle::new(cfg.liveness_secs, now));
    let (follower_tx, follower_rx) = mpsc::channel();
    if cfg.follower {
        std::thread::spawn(move || oracle::follow_timestamped_logs(NODE_CONTAINER, follower_tx));
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = common::guest_time_ns();
        let mut out = Vec::new();
        if let Some(f) = follower.as_mut() {
            for (at_ns, line) in follower_rx.try_iter() {
                out.extend(f.on_log_at(at_ns, &line));
            }
        }
        for (v, rx) in &logs {
            for line in rx.try_iter() {
                if let Some(saved) = oracle::parse_saved(&line) {
                    if let Some(h) = historical.as_mut() {
                        h.on_saved(*v, saved);
                    }
                    if *v == target {
                        out.extend(load.on_log(&line));
                    }
                    continue;
                }
                out.extend(scan_log(*v, &line));
                out.extend(scan_storage_layer(*v, &line, cluster.storage.is_some()));
                out.extend(consensus.on_log(*v, &line));
            }
        }
        let mut new_events = cursor.take_new();
        for ev in &new_events {
            out.extend(consensus.on_event(ev, now));
        }
        // The consensus oracle takes events again right before each
        // validator's reads (see `ConsensusOracle::tick_with_events`); the
        // load oracle follows them after.
        out.extend(consensus.tick_with_events(&mut RpcCluster, now, &mut || {
            let fresh = cursor.take_new();
            late_events.extend(fresh.iter().cloned());
            fresh
        }));
        new_events.append(&mut late_events);
        if let Some(f) = follower.as_mut() {
            for ev in &new_events {
                out.extend(f.on_event(ev, now));
            }
        }
        for ev in &new_events {
            let validator = ev.container.as_deref().and_then(ValidatorId::of_container);
            match (ev.source.as_str(), ev.kind.as_str()) {
                ("nemesis", "kill") if validator == Some(target) && !target_down => {
                    target_down = true;
                    out.extend(load.on_event(&as_node_event("kill", now), now));
                }
                ("load", "generation") => {
                    let next = ev.detail["target"]
                        .as_str()
                        .and_then(ValidatorId::of_container)
                        .unwrap_or(target);
                    // A new node, or the same one back: the load oracle
                    // sees a restart (its pins and chain are re-checked
                    // there).
                    if next != target || target_down {
                        if !target_down {
                            out.extend(load.on_event(&as_node_event("kill", now), now));
                        }
                        target = next;
                        target_down = false;
                        out.extend(load.on_event(&as_node_event("restart", now), now));
                    }
                }
                _ => {}
            }
        }
        // E3h/E7h see each validator's own kills and restarts.
        if let Some(h) = historical.as_mut() {
            for ev in &new_events {
                if ev.source != "nemesis" {
                    continue;
                }
                if let Some(v) = ev.container.as_deref().and_then(ValidatorId::of_container) {
                    if matches!(
                        ev.kind.as_str(),
                        "kill" | "down" | "stop" | "restart" | "resume" | "pause"
                    ) {
                        h.on_event(v, &ev.kind, now);
                    }
                }
            }
        }
        if !target_down {
            out.extend(common::with_rpc_url(target.rpc_url(), || {
                load.tick(&mut RpcChain, now)
            }));
        }
        if let Some(exec_diff) = exec_diff.as_mut() {
            if let Some(agreed) = cluster_agreed_finalized() {
                out.extend(exec_diff.tick(&mut RpcExec, agreed));
            }
        }
        if let Some(f) = follower.as_mut() {
            out.extend(crate::follower::step(f, now));
        }
        for (v, sr) in &mut state_root {
            let mut view = RpcRoot(Some(v.rpc_url()));
            if let Ok(head) = RootView::head(&mut view) {
                out.extend(sr.tick(&mut view, head));
            }
        }
        if let Some(sh) = same_height.as_mut() {
            if let Some(min_head) = cluster_min_head() {
                out.extend(sh.tick(&mut RpcExec, min_head));
            }
        }
        if let Some(h) = historical.as_mut() {
            out.extend(h.tick(now));
        }
        oracle::record(out);
    }
}

/// The live cluster's per-validator execution view (RPC) for the E13
/// cross-validator execution differential.
pub struct RpcExec;

impl ExecView for RpcExec {
    fn header(&mut self, v: ValidatorId, number: u64) -> Result<Option<(B256, B256)>, String> {
        common::with_rpc_url(v.rpc_url(), || common::block_state(number))
    }

    fn proof(
        &mut self,
        v: ValidatorId,
        address: &str,
        slots: &[u64],
        number: u64,
    ) -> Result<AccountProof, String> {
        common::with_rpc_url(v.rpc_url(), || common::proof(address, slots, number))
    }
}

/// The cluster's agreed finalized height: the lowest any validator answers, so
/// every answering validator has the block. `None` unless at least two answer
/// (a differential needs two validators to compare).
fn cluster_agreed_finalized() -> Option<u64> {
    let heights: Vec<u64> = ValidatorId::all()
        .filter_map(|v| finalized_height(v).ok().flatten())
        .collect();
    (heights.len() >= 2).then(|| heights.into_iter().min().unwrap())
}

/// The lowest canonical head any validator answers, so every answering
/// validator has a block at that height (Strand C's settled probe point).
/// `None` unless at least two answer.
fn cluster_min_head() -> Option<u64> {
    let heads: Vec<u64> = ValidatorId::all()
        .filter_map(|v| common::with_rpc_url(v.rpc_url(), common::head_number).ok())
        .collect();
    (heads.len() >= 2).then(|| heads.into_iter().min().unwrap())
}

/// The historical-RPC oracles over the live cluster (`historical=true`; see
/// `historical`): E3h for every validator (each node against itself across its
/// own kills and restarts, the core trie/historical-state-after-crash lead)
/// and E7h across the first two validators at the block they agree on. With
/// `validator_engine_diff`, validators 1 and 2 are the Optimized/Simple engine
/// pair, so E7h is the historical cross-engine differential.
struct Historical {
    across: Vec<(ValidatorId, AcrossRestart)>,
    diff: Option<Differential>,
    /// E7h's primary and reference validators.
    pair: (ValidatorId, ValidatorId),
}

impl Historical {
    fn new(cfg: &Config) -> Historical {
        let across = ValidatorId::all()
            .map(|v| (v, AcrossRestart::new(cfg.seed, Targets::of(cfg))))
            .collect();
        // E7h needs two nodes that agree on a block.
        let (diff, pair) = match (ValidatorId::new(1), ValidatorId::new(2)) {
            (Some(p), Some(r)) => {
                // With validator_engine_diff the pair runs different engine
                // profiles (Optimized vs Simple); engine-dependent methods are
                // then not a differential.
                let cross_engine = cfg
                    .cluster
                    .as_ref()
                    .map(|c| &c.engine_profiles)
                    .is_some_and(|p| p.len() > 1 && p[0] != p[1]);
                let diff = Differential::new(cfg.seed, Targets::of(cfg)).cross_engine(cross_engine);
                (Some(diff), (p, r))
            }
            _ => (
                None,
                (ValidatorId::new(1).unwrap(), ValidatorId::new(1).unwrap()),
            ),
        };
        Historical { across, diff, pair }
    }

    /// A validator's "Saved range of blocks" watermark.
    fn on_saved(&mut self, v: ValidatorId, saved: (u64, String)) {
        if let Some((_, a)) = self.across.iter_mut().find(|(id, _)| *id == v) {
            a.on_saved(saved.clone());
        }
        if v == self.pair.0 {
            if let Some(d) = self.diff.as_mut() {
                d.on_saved(saved);
            }
        }
    }

    /// A nemesis event for validator `v`, as E3h (and E7h for its primary) sees
    /// its own node (translated to the `NODE_CONTAINER` the oracles expect).
    fn on_event(&mut self, v: ValidatorId, kind: &str, now: u64) {
        let ev = as_node_event(kind, now);
        if let Some((_, a)) = self.across.iter_mut().find(|(id, _)| *id == v) {
            a.on_event(&ev);
        }
        if v == self.pair.0 {
            if let Some(d) = self.diff.as_mut() {
                d.on_event(&ev);
            }
        }
    }

    fn tick(&mut self, now: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        // E3h: each validator against itself. `RpcHist(Some(url))` reads that
        // validator over RPC.
        for (v, a) in self.across.iter_mut() {
            out.extend(a.tick(&mut RpcHist(Some(v.rpc_url())), now));
        }
        // E7h: the pair at the block they agree on (their lower finalized
        // height), compared below it.
        if let Some(d) = self.diff.as_mut() {
            let (p, r) = self.pair;
            if let Some((common, max_head)) = e7h_common(p, r) {
                out.extend(d.tick(
                    &mut RpcHist(Some(p.rpc_url())),
                    &mut RpcHist(Some(r.rpc_url())),
                    common,
                    max_head,
                    now,
                ));
            }
        }
        out
    }
}

/// E7h's agreed block and the pair's higher head: the newest block both
/// validators hold with the same hash (near their heads, so the unwind window
/// around a crash — unfinalized blocks a restart may re-derive — is below it,
/// not just finalized history), and the higher of the two heads (for the proof
/// window). Heads can differ by a block or two between the two validators, so
/// it steps down from the lower head to the newest they agree on. `None` until
/// both answer and agree somewhere.
fn e7h_common(primary: ValidatorId, reference: ValidatorId) -> Option<((u64, String), u64)> {
    let ph = common::with_rpc_url(primary.rpc_url(), common::head_number).ok()?;
    let rh = common::with_rpc_url(reference.rpc_url(), common::head_number).ok()?;
    let max_head = ph.max(rh);
    let top = ph.min(rh);
    for n in (top.saturating_sub(16)..=top).rev() {
        if n == 0 {
            continue;
        }
        let p = common::with_rpc_url(primary.rpc_url(), || common::block_ref(n))
            .ok()
            .flatten();
        let r = common::with_rpc_url(reference.rpc_url(), || common::block_ref(n))
            .ok()
            .flatten();
        if let (Some((ph_hash, _)), Some((rh_hash, _))) = (p, r) {
            if ph_hash == rh_hash {
                return Some(((n, format!("{ph_hash:#x}")), max_head));
            }
        }
    }
    None
}

fn podman(args: &[&str]) -> bool {
    match Command::new("podman")
        .args(args)
        .stdout(Stdio::null())
        .status()
    {
        Ok(s) => s.success(),
        Err(e) => {
            eprintln!("podman {args:?}: {e}");
            false
        }
    }
}

/// Sleeps until guest time `ns` (returns at once if it has passed).
fn sleep_until(ns: u64) {
    let now = common::guest_time_ns();
    if ns > now {
        std::thread::sleep(Duration::from_nanos(ns - now));
    }
}

/// The cluster's finalized height: the highest any validator answers.
fn cluster_finalized() -> Option<u64> {
    ValidatorId::all()
        .filter_map(|v| finalized_height(v).ok().flatten())
        .max()
}

/// Waits for `fault`'s trigger (polling every 100 ms) until its deadline,
/// from guest time `from_ns`; returns what fired it and the cluster's
/// finalized height then.
fn wait_trigger(fault: &ClusterFault, from_ns: u64) -> (&'static str, Option<u64>) {
    let deadline = from_ns + fault.deadline_secs * 1_000_000_000;
    let start = cluster_finalized();
    let fired = |cur: u64, prev: u64| fault.trigger.fired(start.unwrap_or(0), prev, cur);
    if matches!(fault.trigger, FaultTrigger::Now) {
        return ("now", start);
    }
    let mut prev = start;
    loop {
        if common::guest_time_ns() >= deadline {
            return ("deadline", prev);
        }
        std::thread::sleep(Duration::from_millis(100));
        let cur = cluster_finalized();
        if let (Some(c), Some(p)) = (cur, prev) {
            if fired(c, p) {
                return ("trigger", cur);
            }
        }
        if cur.is_some() {
            prev = cur;
        }
    }
}

/// SIGKILLs `targets` together (one podman call; fault `index`), logged
/// first so the monitor and oracles never see an unexplained death, and
/// waits until they have stopped (podman start fails before).
fn kill(targets: &[ValidatorId], index: usize) {
    for v in targets {
        common::emit_event(
            "nemesis",
            "kill",
            Some(v.container()),
            json!({"index": index}),
        );
    }
    let names: Vec<&str> = targets.iter().map(|v| v.container()).collect();
    if !podman(&[&["kill", "-s", "KILL"][..], &names].concat()) {
        eprintln!("nemesis: podman kill {names:?} failed");
    }
    podman(&[&["wait"][..], &names].concat());
}

/// Starts `targets` together (one podman call) after fault `index`.
fn restart(targets: &[ValidatorId], index: usize) {
    let names: Vec<&str> = targets.iter().map(|v| v.container()).collect();
    let started = podman(&[&["start"][..], &names].concat());
    for v in targets {
        common::emit_event(
            "nemesis",
            "restart",
            Some(v.container()),
            json!({"index": index, "started": started}),
        );
    }
}

/// With a machine crash, crashes the storage of each (dead) target, logged
/// as `storage-crash` events with LazyFS's counters; a crash that fails is a
/// harness failure (`H/storage-crash-failed`), not silently a process crash.
fn crash_storage(targets: &[ValidatorId], crash: Crash, index: usize) {
    let Crash::Machine { discard } = crash else {
        return;
    };
    for v in targets {
        let result = node_storage::machine_crash(*v, discard);
        common::assert_always(
            bedrock_assertions::Condition::Bool(result.is_ok()),
            "nemesis",
            "H/storage-crash-failed",
            &format!("{v}: {:?}", result.as_ref().err()),
        );
        if let Ok(stats) = &result {
            common::assert_sometimes(
                bedrock_assertions::Condition::Bool(stats.discarded()),
                "nemesis",
                "S/machine-crash-discarded",
                &format!("{v}: {stats:?}"),
            );
        }
        common::emit_event(
            "nemesis",
            "storage-crash",
            Some(v.container()),
            json!({
                "index": index,
                "discard": discard,
                "stats": result.as_ref().ok(),
                "error": result.err(),
            }),
        );
    }
}

/// `tempo-dst nemesis` for a cluster config: see the module docs.
pub fn run_nemesis(cfg: &Config) {
    let Some(cluster) = cfg.cluster.as_ref() else {
        return;
    };
    common::emit_event(
        "nemesis",
        "plan",
        None,
        json!({ "cluster_faults": cluster.faults }),
    );
    // The certified follower's offline-window plan runs on its own schedule,
    // alongside the validators' faults: it drives the `tempo` follower behind
    // and lets it catch up (the tempo#8263 class), independent of the cluster.
    if let Some(plan) = cfg.follower_plan.clone() {
        std::thread::spawn(move || crate::follower::run_plan(&plan));
    }
    let start = common::guest_time_ns();
    for (i, f) in cluster.faults.iter().enumerate() {
        let from = start + f.not_before_secs * 1_000_000_000;
        sleep_until(from);
        let (fired_by, height) = wait_trigger(f, from);
        common::emit_event(
            "nemesis",
            "fault",
            None,
            json!({
                "index": i,
                "fired_by": fired_by,
                "finalized": height,
                "targets": f.targets,
            }),
        );
        let down = Duration::from_millis(f.down_ms);
        if let Some(imp) = &f.impair {
            crate::cluster_net::impair(i, &imp.impairment);
            std::thread::sleep(Duration::from_millis(imp.lead_ms));
        }
        match f.order {
            RestartOrder::Together => {
                kill(&f.targets, i);
                crash_storage(&f.targets, f.crash, i);
                std::thread::sleep(down);
                restart(&f.targets, i);
                if let Some(imp) = &f.impair {
                    crate::cluster_net::reapply(i, &imp.impairment, &f.targets);
                }
            }
            RestartOrder::Rolling { gap_ms } => {
                for (k, v) in f.targets.iter().enumerate() {
                    if k > 0 {
                        std::thread::sleep(Duration::from_millis(gap_ms));
                    }
                    kill(&[*v], i);
                    crash_storage(&[*v], f.crash, i);
                    std::thread::sleep(down);
                    restart(&[*v], i);
                    if let Some(imp) = &f.impair {
                        crate::cluster_net::reapply(i, &imp.impairment, &[*v]);
                    }
                }
            }
        }
        if let Some(imp) = &f.impair {
            std::thread::sleep(Duration::from_millis(imp.hold_ms));
            crate::cluster_net::heal(i, &imp.impairment);
        }
        if let Err(e) = crate::start::restart_load(cfg, i as u64 + 1) {
            eprintln!("nemesis: restarting load: {e}");
        }
    }
}

/// `tempo-dst cluster-watch <secs>`: E13-E18 against a live cluster for
/// `secs` seconds outside Bedrock (validators at their genesis IPs), printing
/// every failure and coverage signal. Node restarts are not known here.
pub fn watch(secs: u64) {
    let start = common::guest_time_ns();
    let mut consensus = ConsensusOracle::new(crate::cluster::Cooldown::Fast.budget(), start);
    while common::guest_time_ns() < start + secs * 1_000_000_000 {
        std::thread::sleep(Duration::from_secs(1));
        for v in consensus.tick(&mut RpcCluster, common::guest_time_ns()) {
            match v {
                Verdict::Always(true, _) => {}
                other => println!("{other:?}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rejected_duplicate_dkg_ack_is_coverage_not_a_failure() {
        let v = ValidatorId::new(2).unwrap();
        let dup = "2024-01-01T00:03:17.829212Z ERROR run_dkg_loop{epoch=1}:handle_network_msg{epoch=1 from=7f7f bytes=65}: tempo_consensus::dkg::manager::actor: error=[failed to process ACK, already received an ack from `7f7f`]";
        assert!(
            matches!(scan_log(v, dup), Some(Verdict::Sometimes(true, ref f)) if f.signature == "S/dkg-duplicate-ack-rejected")
        );
        // Any other DKG error is still E1.
        let other = "2024-01-01T00:03:17Z ERROR run_dkg_loop{epoch=1}:handle_network_msg{epoch=1}: tempo_consensus::dkg::manager::actor: error=[failed to process dealing]";
        assert!(
            matches!(scan_log(v, other), Some(Verdict::Always(false, ref f)) if f.signature == "E1/error-log/tempo_consensus::dkg::manager::actor")
        );
    }

    #[test]
    fn fd_enoent_on_a_storage_layer_is_flagged_as_the_harness() {
        let v = ValidatorId::new(1).unwrap();
        let line = "ERROR commonware_runtime::utils::handle: task panicked err=\"unable to append to journal: Runtime(BlobResizeFailed(\\\"engine_epoch_manager_consensus_epoch_1\\\", \\\"0000000000000009\\\", Os { code: 2, kind: NotFound, message: \\\"No such file or directory\\\" }))\"";
        let v1 = scan_storage_layer(v, line, true);
        assert!(
            matches!(v1, Some(Verdict::Always(false, ref f)) if f.signature == "H/storage-layer-enoent")
        );
        // Without a storage layer it is the node's (E1 reports it).
        assert!(scan_storage_layer(v, line, false).is_none());
        assert!(scan_storage_layer(v, "BlobResizeFailed(.. kind: StorageFull ..)", true).is_none());
    }
}
