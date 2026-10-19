// SPDX-License-Identifier: GPL-2.0

//! Crash nemesis: SIGKILLs the node container and restarts it at times drawn
//! from Bedrock-controlled randomness.
//!
//! With storage faults (`storage_faults`, the datadir on LazyFS; see
//! `storage`), each fault is also drawn from the same randomness:
//!
//! - a process kill (SIGKILL; the page cache, so every write, survives);
//! - a machine crash: un-synced writes discarded (all, or a seed-chosen
//!   subset of blocks and sizes), then a cold reopen;
//! - a torn write (LazyFS's `torn-op`/`torn-seq` on a drawn datadir file),
//!   armed for a window that ends in a machine crash. If it fires, LazyFS
//!   persists part of the write and crashes itself under the running node:
//!   the node's death and E1 log findings are excused until the restart.
//!
//! With process faults (`process_faults`), each fault may also be:
//!
//! - a pause: `podman pause` (cgroup freezer) for 1-20 s, then `podman
//!   unpause`. The node keeps its memory; peers, RPC clients and the E7
//!   reference see it vanish and come back;
//! - a CPU throttle: 10-30% of a CPU for 5-30 s (`process::throttle`);
//! - a graceful stop: `podman stop -t <10-30 s>`, then a start. Falling back
//!   to SIGKILL is a finding (`E4/stop-timeout`).
//!
//! Without either flag no fault is drawn, so the plan (and every seed's
//! meaning) is as before; storage-fault seeds keep theirs without
//! `process_faults`.

use std::{fs, io, process::Command, time::Duration};

use bedrock_assertions::Condition;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    common::{
        self, Config, DstEvent, LoadGeneration, NemesisConfig, ScheduledFault, CONFIG_PATH,
        NODE_CONTAINER,
    },
    netfault::{self, NetFault},
    process, storage,
    storage::{Discard, Torn, TornFile},
    topology,
};

pub use crate::common::Fault;
use crate::planner::kill_target;

/// Guest seconds after nemesis start before the first kill may land.
pub(crate) const WARMUP_SECS: u64 = 5;
/// Longest the node stays down before restart.
pub(crate) const MAX_DOWN_SECS: u64 = 3;
/// Torn-write windows last 2 to this many seconds.
pub(crate) const MAX_TORN_WINDOW_SECS: u64 = 10;
/// A torn `torn-op` splits a write into 2 to this many parts.
const MAX_TORN_PARTS: u64 = 4;
/// A `torn-seq` keeps a subset of the first this many writes of a run.
const TORN_SEQ_WRITES: u64 = 4;
/// Pause windows (seconds).
const PAUSE_SECS: (u64, u64) = (1, 20);
/// CPU throttles: percent of one CPU, window seconds.
const THROTTLE_PCT: (u64, u64) = (10, 30);
pub(crate) const THROTTLE_SECS: (u64, u64) = (5, 30);
/// Graceful-stop timeouts (`podman stop -t`, seconds).
const STOP_TIMEOUT_SECS: (u64, u64) = (10, 30);

fn draw_discard(draw: &mut impl FnMut(u64, u64) -> u64) -> Discard {
    if draw(0, 1) == 0 {
        Discard::All
    } else {
        Discard::Subset {
            seed: draw(0, u64::MAX),
            keep_permille: draw(0, 1000) as u32,
        }
    }
}

/// Fault families as drawn: one entry per share (machine crashes twice).
const FAMILIES: [&str; 4] = ["kill", "crash", "crash", "torn"];
/// Process fault families (`process_faults`), one share each.
const PROCESS_FAMILIES: [&str; 4] = ["kill", "pause", "throttle", "stop"];

/// Whether `kind` names a storage fault family (`storage_fault_kinds`).
pub fn is_family(kind: &str) -> bool {
    FAMILIES.contains(&kind)
}

/// `all` restricted to `kinds` (all if empty or if nothing matches).
fn restrict(all: &[&'static str], kinds: &[String]) -> Vec<&'static str> {
    let table: Vec<&str> = all
        .iter()
        .copied()
        .filter(|f| kinds.is_empty() || kinds.iter().any(|k| k == f))
        .collect();
    if table.is_empty() {
        all.to_vec()
    } else {
        table
    }
}

/// The draw table for the families in `kinds` (all if empty).
fn families(kinds: &[String]) -> Vec<&'static str> {
    restrict(&FAMILIES, kinds)
}

/// The family draw table of `cfg`; `None` when only process kills are
/// planned (no family draw, as before fault families existed). With both
/// flags the storage table owns `kill`, and the process families are
/// appended.
pub fn draw_table(cfg: &NemesisConfig) -> Option<Vec<&'static str>> {
    let mut table = Vec::new();
    if cfg.storage_faults {
        table = families(&cfg.storage_fault_kinds);
    }
    if cfg.process_faults {
        let process = restrict(&PROCESS_FAMILIES, &cfg.process_fault_kinds);
        let own_kill = cfg.storage_faults;
        table.extend(process.into_iter().filter(|f| !(own_kill && *f == "kill")));
    }
    (!table.is_empty()).then_some(table)
}

/// One fault drawn from `table`.
pub fn draw_fault(table: &[&str], draw: &mut impl FnMut(u64, u64) -> u64) -> Fault {
    match table[draw(0, table.len() as u64 - 1) as usize] {
        "kill" => Fault::ProcessKill,
        "crash" => Fault::MachineCrash {
            discard: draw_discard(draw),
        },
        "pause" => Fault::Pause {
            pause_secs: draw(PAUSE_SECS.0, PAUSE_SECS.1),
        },
        "throttle" => Fault::Throttle {
            quota_pct: draw(THROTTLE_PCT.0, THROTTLE_PCT.1) as u32,
            window_secs: draw(THROTTLE_SECS.0, THROTTLE_SECS.1),
        },
        "stop" => Fault::GracefulStop {
            timeout_secs: draw(STOP_TIMEOUT_SECS.0, STOP_TIMEOUT_SECS.1),
        },
        _ => Fault::TornWrite {
            torn: draw_torn(draw),
            window_secs: draw(2, MAX_TORN_WINDOW_SECS),
        },
    }
}

/// A torn write: a file, then `torn-op` (a write split into parts, a strict
/// non-empty subset persisted, at its 1st-20th write) or `torn-seq` (a
/// non-empty subset of a run's first writes persisted, in its 1st-3rd run).
fn draw_torn(draw: &mut impl FnMut(u64, u64) -> u64) -> Torn {
    let file = TornFile::ALL[draw(0, TornFile::ALL.len() as u64 - 1) as usize];
    if draw(0, 1) == 0 {
        let parts = draw(2, MAX_TORN_PARTS);
        Torn::Op {
            file,
            parts: parts as u32,
            persist: draw(1, (1 << parts) - 2) as u32,
            occurrence: draw(1, 20) as u32,
        }
    } else {
        Torn::Seq {
            file,
            persist: draw(1, (1 << TORN_SEQ_WRITES) - 1) as u32,
            occurrence: draw(1, 3) as u32,
        }
    }
}

/// `lo..=hi` from a raw 64-bit draw (the whole range when it spans every
/// `u64`).
pub fn in_range(x: u64, lo: u64, hi: u64) -> u64 {
    match hi.wrapping_sub(lo).wrapping_add(1) {
        0 => x,
        span => lo + x % span,
    }
}

/// Fault schedule for one run. Faults are at least `min_gap_secs` apart and all
/// fit within `run_secs`, leaving the last gap for recovery.
pub fn plan(
    cfg: &NemesisConfig,
    run_secs: u64,
    mut draw: impl FnMut(u64, u64) -> u64,
) -> Vec<ScheduledFault> {
    let mut faults = Vec::new();
    if !cfg.enabled {
        return faults;
    }
    let gap = u64::from(cfg.min_gap_secs.max(1));
    let table = draw_table(cfg);
    let mut t = WARMUP_SECS;
    for _ in 0..cfg.max_faults {
        let at = t + draw(0, gap);
        let down = draw(0, MAX_DOWN_SECS);
        let fault = match &table {
            Some(table) => draw_fault(table, &mut draw),
            None => Fault::ProcessKill,
        };
        let k = ScheduledFault {
            at_secs: at,
            down_secs: down,
            fault,
        };
        // Leave a full gap after the restart so liveness can be judged.
        if k.end_secs() + gap > run_secs {
            break;
        }
        faults.push(k);
        t = k.end_secs() + gap;
    }
    faults
}

fn podman(args: &[&str]) -> bool {
    match Command::new("podman").args(args).status() {
        Ok(s) => s.success(),
        Err(e) => {
            eprintln!("podman {args:?}: {e}");
            false
        }
    }
}

/// The run's kills: `nemesis.plan` from the config when given (driver-made
/// decisions, `replay --scenario`), else [`plan`]. Draws either way, so the
/// guest consumes the same Bedrock randomness with or without a plan.
pub fn faults_for(cfg: &Config, draw: impl FnMut(u64, u64) -> u64) -> Vec<ScheduledFault> {
    let drawn = plan(&cfg.nemesis, cfg.run_secs, draw);
    match &cfg.nemesis_plan {
        Some(explicit) => explicit.clone(),
        None => drawn,
    }
}

/// The run's network faults (with `network`): `network_plan` from the
/// config when given, else [`crate::planner::net_plan`] around the fault
/// plan's windows (from a fault's start to its restart or end). Like
/// [`faults_for`], draws either way.
pub fn network_for(
    cfg: &Config,
    kills: &[ScheduledFault],
    draw: impl FnMut(u64, u64) -> u64,
) -> Vec<NetFault> {
    let Some(net) = cfg.network.as_ref() else {
        return Vec::new();
    };
    let windows: Vec<(u64, u64)> = kills
        .iter()
        .map(|k| (k.at_secs, k.end_secs() - k.at_secs))
        .collect();
    let drawn = crate::planner::net_plan(
        net,
        cfg.run_secs,
        &windows,
        netfault::NET_WARMUP_SECS,
        net.max_faults,
        draw,
    );
    cfg.network_plan.clone().unwrap_or(drawn)
}

fn emit_network_plan(faults: &[NetFault], resumed: bool) {
    let mut detail = netfault::plan_detail(faults);
    if resumed {
        detail["resumed"] = json!(true);
    }
    common::emit_event("network", "plan", None, detail);
}

/// Plan entries (kills and the other fault families) and network faults in
/// time order, from plan entry `skip_kills` and network fault `skip_faults`
/// on, on the clock that started at `start_ns`.
fn run_timeline(
    cfg: &Config,
    kills: &[ScheduledFault],
    faults: &[NetFault],
    start_ns: u64,
    skip_kills: usize,
    skip_faults: usize,
) {
    let secs = |s: u64| start_ns + s * 1_000_000_000;
    let mut steps: Vec<(u64, bool, usize)> = kills
        .iter()
        .enumerate()
        .skip(skip_kills)
        .map(|(i, k)| (k.at_secs, true, i))
        .chain(
            faults
                .iter()
                .enumerate()
                .skip(skip_faults)
                .map(|(j, f)| (f.at_secs, false, j)),
        )
        .collect();
    steps.sort();
    let net = cfg.network.clone().unwrap_or_default();
    for (at, is_kill, i) in steps {
        if is_kill {
            sleep_until(secs(at));
            let k = &kills[i];
            execute(cfg, i, k, || sleep_until(secs(k.end_secs())));
        } else {
            let mut wl = net_workload(cfg);
            if let Err(e) = netfault::run(i, &faults[i], &net, start_ns, wl.as_mut()) {
                network_fault_failed(i, &e);
            }
        }
    }
}

/// The workload side of the network nemesis (roles, hooks, excuses).
fn net_workload(cfg: &Config) -> Box<dyn netfault::NetWorkload> {
    if cfg.zone_cluster() {
        Box::new(crate::zones_cluster::ZonesNet::new())
    } else {
        Box::new(netfault::Plain)
    }
}

/// A network fault that could not be applied or healed: the harness did
/// not do what the plan says, so the run is reported, not trusted.
fn network_fault_failed(index: usize, error: &str) {
    eprintln!("nemesis: network fault {index}: {error}");
    common::assert_always(
        bedrock_assertions::Condition::Bool(false),
        "network",
        "D/network-fault-failed",
        &format!("fault {index}: {error}"),
    );
}

/// `tempo-dst nemesis [--resume]`.
pub fn run(resume: bool) {
    let cfg = Config::load();
    if resume {
        return run_resumed(&cfg);
    }
    let faults = faults_for(&cfg, |lo, hi| rand::random_range(lo..=hi));
    let net_faults = network_for(&cfg, &faults, |lo, hi| rand::random_range(lo..=hi));
    let start_ns = common::guest_time_ns();
    emit_plan(&cfg, &faults, false);
    if cfg.network.is_some() {
        emit_network_plan(&net_faults, false);
        if !net_faults.is_empty() {
            return run_timeline(&cfg, &faults, &net_faults, start_ns, 0, 0);
        }
    }
    let mut elapsed = 0;
    for (i, k) in faults.iter().enumerate() {
        std::thread::sleep(Duration::from_secs(k.at_secs.saturating_sub(elapsed)));
        let started_ns = common::guest_time_ns();
        execute(&cfg, i, k, || {
            std::thread::sleep(Duration::from_secs(k.down_secs))
        });
        // Process faults take as long as they take (a stop may finish
        // before its timeout); the next fault is timed from the actual end.
        elapsed = if k.fault.keeps_running() || matches!(k.fault, Fault::GracefulStop { .. }) {
            k.at_secs + (common::guest_time_ns() - started_ns) / 1_000_000_000
        } else {
            k.end_secs()
        };
    }
}

/// Carries out plan entry `i`, from its start: the fault's window (if any),
/// the kill, the machine crash (if any), the downtime (`down`), and the
/// restart. A pause or throttle only runs its window; a graceful stop is
/// followed by its own drawn downtime.
/// The single node this nemesis acts on, from the topology (the cluster has
/// its own nemesis in `cluster_live`, so here it is always the dev node).
fn node_container(cfg: &Config) -> String {
    topology::topology(cfg).primary().name.clone()
}

fn execute(cfg: &Config, i: usize, k: &ScheduledFault, down: impl FnOnce()) {
    let node = node_container(cfg);
    let node = node.as_str();
    if k.fault.keeps_running() {
        return process_window(i, &k.fault, node);
    }
    if let Fault::GracefulStop { timeout_secs } = k.fault {
        return graceful_restart(cfg, i, k, timeout_secs, node);
    }
    open_window(i, &k.fault, node);
    // A node that already died (under a torn write that fired, its file
    // system gone) is "down", not killed.
    let torn = matches!(k.fault, Fault::TornWrite { .. });
    let running = !torn
        || storage::node_running().unwrap_or_else(|e| {
            // Unknown: kill it anyway (a no-op on a dead container).
            harness_failure("H/node-inspect-failed", &e);
            true
        });
    let target = target_of(cfg, i, k);
    let killed = kill(i, k, target, running);
    if let Some(discard) = k.fault.discard() {
        crash_machine(i, discard, torn, node);
    }
    down();
    restart(cfg, i, target, killed);
    if torn {
        common::emit_event(
            "nemesis",
            "storage-fault-end",
            Some(node),
            json!({"index": i}),
        );
    }
}

fn harness_failure(signature: &str, detail: &str) {
    eprintln!("nemesis: {signature}: {detail}");
    common::assert_always(Condition::Bool(false), "nemesis", signature, detail);
}

/// Opens the fault's window (a torn write) and waits it out.
fn open_window(i: usize, fault: &Fault, node: &str) {
    if let Fault::TornWrite { torn, window_secs } = *fault {
        // Before arming: if it fires, the node loses its file system, and
        // that death and its log lines are excused until the restart.
        common::emit_event(
            "nemesis",
            "storage-fault",
            Some(node),
            json!({"index": i, "fault": fault}),
        );
        if let Err(e) = storage::arm_torn(torn) {
            harness_failure("H/lazyfs-unavailable", &e);
        }
        std::thread::sleep(Duration::from_secs(window_secs));
    }
}

/// A pause or CPU throttle: the node is never killed. Events bracket the
/// window (logged before acting, so the oracles excuse the freeze from its
/// start); the closing one is always logged, so excusal always ends.
fn process_window(i: usize, fault: &Fault, node: &str) {
    match *fault {
        Fault::Pause { pause_secs } => {
            common::emit_event(
                "nemesis",
                "pause",
                Some(node),
                json!({"index": i, "fault": fault}),
            );
            let paused = podman(&["pause", node]);
            if !paused {
                harness_failure("H/pause-failed", "podman pause");
            }
            std::thread::sleep(Duration::from_secs(pause_secs));
            resume(i, paused, node);
        }
        Fault::Throttle {
            quota_pct,
            window_secs,
        } => {
            common::emit_event(
                "nemesis",
                "throttle",
                Some(node),
                json!({"index": i, "fault": fault}),
            );
            let detail = match process::throttle(node, quota_pct, window_secs) {
                Ok(applied) => json!({"index": i, "applied": applied}),
                Err(e) => {
                    harness_failure("H/throttle-failed", &e);
                    json!({"index": i, "error": e})
                }
            };
            common::emit_event("nemesis", "throttle-end", Some(node), detail);
        }
        _ => {}
    }
}

/// Ends pause `i`: `podman unpause` (if the pause took), then the `resume`
/// event.
fn resume(i: usize, paused: bool, node: &str) {
    let resumed = !paused || podman(&["unpause", node]);
    if !resumed {
        harness_failure("H/pause-failed", "podman unpause");
    }
    common::emit_event(
        "nemesis",
        "resume",
        Some(node),
        json!({"index": i, "paused": paused, "resumed": resumed}),
    );
}

/// A graceful stop mid-run, then a start after the downtime. Not falling
/// back to SIGKILL within the drawn timeout is the node's job: E4/stop-timeout.
fn graceful_restart(cfg: &Config, i: usize, k: &ScheduledFault, timeout_secs: u64, node: &str) {
    // Before stopping: workload-monitor excuses the death (a clean exit, or
    // the SIGKILL fallback that E4/stop-timeout reports), and the oracles
    // treat the node as down.
    common::emit_event(
        "nemesis",
        "stop",
        Some(node),
        json!({"index": i, "fault": k.fault}),
    );
    let stop = process::graceful_stop(node, timeout_secs);
    common::assert_always(
        Condition::Bool(stop.judge().is_ok()),
        "nemesis",
        "E4/stop-timeout",
        &stop.detail(),
    );
    common::emit_event(
        "nemesis",
        "stopped",
        Some(node),
        json!({"index": i, "stop": stop}),
    );
    let _ = podman(&["wait", node]);
    std::thread::sleep(Duration::from_secs(k.down_secs));
    restart(cfg, i, node, false);
}

/// Power loss under the stopped node (see `storage::machine_crash`).
fn crash_machine(i: usize, discard: Discard, torn_armed: bool, node: &str) {
    match storage::machine_crash(discard, torn_armed) {
        Ok(stats) => {
            common::emit_event(
                "nemesis",
                "storage-crash",
                Some(node),
                json!({"index": i, "stats": stats}),
            );
            common::assert_sometimes(
                Condition::Bool(stats.discarded()),
                "nemesis",
                "S/storage-discarded",
                &serde_json::to_string(&stats).unwrap_or_default(),
            );
            if stats.undo_errors > 0 {
                harness_failure(
                    "H/lazyfs-crash-failed",
                    &serde_json::to_string(&stats).unwrap_or_default(),
                );
            }
        }
        Err(e) => harness_failure("H/lazyfs-unavailable", &e),
    }
}

fn emit_plan(cfg: &Config, faults: &[ScheduledFault], resumed: bool) {
    let mut detail = json!({ "kills": faults });
    if cfg.zones {
        for (i, (k, entry)) in faults
            .iter()
            .zip(detail["kills"].as_array_mut().into_iter().flatten())
            .enumerate()
        {
            entry["target"] = json!(target_of(cfg, i, k));
        }
    }
    if resumed {
        detail["resumed"] = json!(true);
    }
    common::emit_event("nemesis", "plan", Some(&node_container(cfg)), detail);
}

/// The container plan entry `i` acts on: with the zones load a process kill
/// may target the zone or its prover ([`kill_target`]); every other fault
/// family acts on the node.
fn target_of(cfg: &Config, i: usize, k: &ScheduledFault) -> &'static str {
    if k.fault.is_process_kill() {
        kill_target(cfg, i)
    } else {
        NODE_CONTAINER
    }
}

/// SIGKILLs `target` (entry `i` of the plan) if `running` and waits until
/// it has stopped; whether the kill reached it.
fn kill(i: usize, k: &ScheduledFault, target: &str, running: bool) -> bool {
    // Record before killing so the monitor and oracles never see an
    // unexplained death.
    let mut detail = json!({"index": i});
    if !k.fault.is_process_kill() {
        detail["fault"] = json!(k.fault);
    }
    let kind = if running { "kill" } else { "down" };
    common::emit_event("nemesis", kind, Some(target), detail);
    let killed = running && podman(&["kill", "-s", "KILL", target]);
    // podman start fails until the container has fully stopped.
    let _ = podman(&["wait", target]);
    killed
}

/// Restarts kill `i`'s target and starts the next load generation.
fn restart(cfg: &Config, i: usize, target: &str, killed: bool) {
    if cfg.zones && target == NODE_CONTAINER {
        if let Err(error) = crate::follower::restore() {
            harness_failure("H/follower-snapshot-restore-failed", &error.to_string());
            return;
        }
    }
    let started = podman(&["start", target]);
    common::emit_event(
        "nemesis",
        "restart",
        Some(target),
        json!({"index": i, "killed": killed, "started": started}),
    );
    if let Err(e) = crate::start::restart_load(cfg, i as u64 + 1) {
        eprintln!("nemesis: restarting load: {e}");
    }
}

/// Sleeps until guest time `ns` (returns at once if it has passed).
fn sleep_until(ns: u64) {
    let now = common::guest_time_ns();
    if ns > now {
        std::thread::sleep(Duration::from_nanos(ns - now));
    }
}

/// What the nemesis has done so far in this branch, from the event log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Progress {
    /// Guest time of the first `plan` event: what kill times count from.
    pub start_ns: Option<u64>,
    /// The latest plan.
    pub plan: Vec<ScheduledFault>,
    /// Plan entries started (a kill, a fail-stopped node's crash, a stop, a
    /// pause or a throttle) and finished (restart, resume, throttle end).
    pub faults: usize,
    pub restarts: usize,
    /// Restarts (of the node, or with the zones load the zone or prover a
    /// kill targeted), and the plan index of the last one: each starts a
    /// load generation (pauses and throttles do not).
    pub node_restarts: usize,
    pub last_restart: Option<usize>,
    /// Load generations started, in order.
    pub generations: Vec<LoadGeneration>,
    /// The latest network plan, and its faults started and ended.
    pub net_plan: Vec<NetFault>,
    pub net_started: usize,
    pub net_ended: usize,
}

impl Progress {
    pub fn of(events: &[DstEvent]) -> Self {
        let mut p = Progress::default();
        for ev in events {
            let node = ev.container.as_deref() == Some(NODE_CONTAINER);
            // Planned kills carry their index; load reloads do not. With the
            // zones load a planned kill may target the zone or its prover.
            let planned = ev.detail.get("index").is_some();
            match (ev.source.as_str(), ev.kind.as_str()) {
                ("nemesis", "plan") if node => {
                    p.start_ns.get_or_insert(ev.guest_time_ns);
                    p.plan = serde_json::from_value(ev.detail["kills"].clone()).unwrap_or_default();
                }
                ("network", "plan") => {
                    p.net_plan =
                        serde_json::from_value(ev.detail["faults"].clone()).unwrap_or_default();
                }
                ("network", "fault-start") => p.net_started += 1,
                ("network", "fault-end") => p.net_ended += 1,
                ("nemesis", "kill" | "down" | "stop" | "pause" | "throttle") if planned => {
                    p.faults += 1
                }
                ("nemesis", "restart") if planned => {
                    p.restarts += 1;
                    p.node_restarts += 1;
                    p.last_restart = ev.detail["index"].as_u64().map(|i| i as usize);
                }
                ("nemesis", "resume" | "throttle-end") if planned => p.restarts += 1,
                ("load", "generation") => {
                    if let Ok(g) = serde_json::from_value(ev.detail.clone()) {
                        p.generations.push(g);
                    }
                }
                _ => {}
            }
        }
        p
    }

    /// Between faults: the nemesis has started, and no kill waits for its
    /// restart nor (with a load) a restart for its load generation.
    pub fn quiescent(&self, load: bool) -> bool {
        self.start_ns.is_some()
            && self.faults == self.restarts
            && self.net_started == self.net_ended
            && (!load || self.generations.len() > self.node_restarts)
    }
}

/// A re-decided future for a running branch (`tempo-dst redecide`): the
/// whole kill plan and load generations as the driver would have them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Redecision {
    pub nemesis_plan: Vec<ScheduledFault>,
    #[serde(default)]
    pub generations: Vec<LoadGeneration>,
    /// With the network nemesis: the whole network fault plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_plan: Option<Vec<NetFault>>,
}

/// The plan and generations to continue with: what already happened stays
/// (the guest knows exactly which kills fired; the driver only estimates
/// it), the rest comes from `r`, minus kills that would land in the past
/// (`now_secs` after nemesis start) or before the previous restart.
pub fn merge(p: &Progress, r: &Redecision, now_secs: u64) -> Redecision {
    let mut plan: Vec<ScheduledFault> = p.plan.iter().take(p.faults).copied().collect();
    let mut free = plan.last().map_or(0, ScheduledFault::end_secs);
    for k in r.nemesis_plan.iter().skip(plan.len()) {
        if k.at_secs >= free && k.at_secs >= now_secs {
            plan.push(*k);
            free = k.end_secs();
        }
    }
    let mut generations = p.generations.clone();
    generations.extend(r.generations.iter().skip(generations.len()).copied());
    // Faults that started stay; proposed ones after them and after now join.
    let network_plan = r.network_plan.as_ref().map(|proposed| {
        let mut faults: Vec<NetFault> = p.net_plan.iter().take(p.net_started).cloned().collect();
        let mut free = faults.last().map_or(0, NetFault::end_secs);
        for f in proposed.iter().skip(faults.len()) {
            if f.at_secs >= free && f.at_secs >= now_secs {
                faults.push(f.clone());
                free = f.end_secs();
            }
        }
        faults
    });
    Redecision {
        nemesis_plan: plan,
        generations,
        network_plan,
    }
}

/// `tempo-dst redecide '<json>'`: replaces the not-yet-applied part of the
/// kill plan and load generations of a running branch (`bedrock-dst branch
/// --vary decisions`). Waits until the nemesis is between faults, stops it,
/// writes the merged plan into the config and starts `tempo-dst nemesis
/// --resume`, which continues on the original's clock. Prints the merged
/// [`Redecision`].
pub fn redecide(json: &str) -> io::Result<()> {
    let r: Redecision =
        serde_json::from_str(json).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut cfg = Config::load();
    let load = cfg.load.count > 0;
    // Let an in-flight kill or reload finish (bounded by its downtime and
    // podman); one still in flight after this is finished by --resume.
    for _ in 0..120 {
        if Progress::of(&common::read_events()).quiescent(load) {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    common::stop_subcommands(&["nemesis"])?;
    let p = Progress::of(&common::read_events());
    let start = p.start_ns.unwrap_or_else(common::guest_time_ns);
    let now_secs = common::guest_time_ns().saturating_sub(start) / 1_000_000_000;
    let merged = merge(&p, &r, now_secs);
    cfg.nemesis_plan = Some(merged.nemesis_plan.clone());
    cfg.load.generations = merged.generations.clone();
    if merged.network_plan.is_some() {
        cfg.network_plan = merged.network_plan.clone();
    }
    cfg.validate().map_err(io::Error::other)?;
    fs::write(
        CONFIG_PATH,
        serde_json::to_string(&cfg).map_err(io::Error::other)?,
    )?;
    common::emit_event(
        "nemesis",
        "redecide",
        Some(NODE_CONTAINER),
        json!({
            "kills_done": p.faults,
            "restarts_done": p.restarts,
            "at_secs": now_secs,
            "plan": merged.nemesis_plan,
            "generations": merged.generations,
            "network_plan": merged.network_plan,
            "faults_done": p.net_started,
        }),
    );
    crate::start::spawn_detached_with("nemesis", &["--resume"], true)?;
    println!(
        "{}",
        serde_json::to_string(&merged).map_err(io::Error::other)?
    );
    Ok(())
}

/// `tempo-dst nemesis --resume`: continues a nemesis stopped by
/// [`redecide`] with the config's (merged) plan, on the original's clock: a
/// kill whose restart did not happen is finished first, then the remaining
/// kills fire at their times after the original nemesis start.
fn run_resumed(cfg: &Config) {
    let node = node_container(cfg);
    let node = node.as_str();
    let p = Progress::of(&common::read_events());
    let start = p.start_ns.unwrap_or_else(common::guest_time_ns);
    let faults: Vec<ScheduledFault> = cfg.nemesis_plan.iter().flatten().copied().collect();
    emit_plan(cfg, &faults, true);
    let net_faults = cfg.network_plan.clone().unwrap_or_default();
    if cfg.network.is_some() {
        emit_network_plan(&net_faults, true);
    }
    let secs = |s: u64| start + s * 1_000_000_000;
    if p.net_started > p.net_ended {
        // Stopped inside a network fault: heal it at its end.
        let j = p.net_started - 1;
        if let Some(f) = net_faults.get(j) {
            sleep_until(secs(f.end_secs()));
        }
        let topo = cfg.network.clone().unwrap_or_default().topology;
        let healed = netfault::heal(&topo);
        common::emit_event(
            "network",
            "fault-end",
            None,
            json!({"index": j, "resumed": true, "error": healed.as_ref().err()}),
        );
        if let Err(e) = healed {
            network_fault_failed(j, &e);
        }
    }
    let in_flight = p
        .faults
        .checked_sub(1)
        .and_then(|i| faults.get(i))
        .map(|k| k.fault);
    if p.faults > p.restarts && in_flight.is_some_and(|f| f.keeps_running()) {
        // Stopped inside a pause or throttle: end it now.
        let i = p.faults - 1;
        if matches!(in_flight, Some(Fault::Pause { .. })) {
            resume(i, true, node);
        } else {
            let detail = match process::release(node) {
                Ok(()) => json!({"index": i, "resumed": true}),
                Err(e) => json!({"index": i, "resumed": true, "error": e}),
            };
            common::emit_event("nemesis", "throttle-end", Some(node), detail);
        }
    } else if p.faults > p.restarts {
        // Stopped between a kill (or stop) and its restart (the kill may
        // not have reached podman yet). A storage window closes with the
        // restart; a machine crash not yet done is skipped, except under a
        // torn write: it may have fired (LazyFS gone) and is still armed, so
        // the window ends in a crash that discards everything.
        let i = p.faults - 1;
        let target = faults
            .get(i)
            .map_or(NODE_CONTAINER, |k| target_of(cfg, i, k));
        let killed = podman(&["kill", "-s", "KILL", target]);
        let _ = podman(&["wait", target]);
        if let Some(k) = faults.get(i) {
            sleep_until(secs(k.end_secs()));
        }
        let torn = faults
            .get(i)
            .is_some_and(|k| matches!(k.fault, Fault::TornWrite { .. }));
        if torn {
            crash_machine(i, Discard::All, true, node);
        }
        restart(cfg, i, target, killed);
        if torn {
            common::emit_event(
                "nemesis",
                "storage-fault-end",
                Some(node),
                json!({"index": i}),
            );
        }
    } else if cfg.load.count > 0 && p.node_restarts > 0 && p.generations.len() <= p.node_restarts {
        // Stopped while restarting the load after the last restart (plan
        // entry `i` starts generation `i + 1`).
        let generation = p.last_restart.map_or(p.node_restarts, |i| i + 1);
        if let Err(e) = crate::start::restart_load(cfg, generation as u64) {
            eprintln!("nemesis: restarting load: {e}");
        }
    }
    if !net_faults.is_empty() {
        return run_timeline(cfg, &faults, &net_faults, start, p.faults, p.net_started);
    }
    for (i, k) in faults.iter().enumerate().skip(p.faults) {
        sleep_until(secs(k.at_secs));
        execute(cfg, i, k, || sleep_until(secs(k.end_secs())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn cfg(max_faults: u32, min_gap_secs: u32) -> NemesisConfig {
        NemesisConfig {
            enabled: true,
            max_faults,
            min_gap_secs,
            ..NemesisConfig::default()
        }
    }

    fn process(kinds: &[&str]) -> NemesisConfig {
        NemesisConfig {
            process_faults: true,
            process_fault_kinds: kinds.iter().map(|k| k.to_string()).collect(),
            ..cfg(200, 1)
        }
    }

    fn lcg() -> impl FnMut(u64, u64) -> u64 {
        let mut x = 0u64;
        move |lo, hi| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            in_range(x >> 11, lo, hi)
        }
    }

    #[test]
    fn disabled_plans_nothing() {
        let c = NemesisConfig {
            enabled: false,
            ..cfg(3, 10)
        };
        assert!(plan(&c, 1000, |lo, _| lo).is_empty());
    }

    #[test]
    fn kills_respect_gap_and_fit_the_run() {
        let mut x = 0u64;
        let faults = plan(&cfg(10, 20), 200, |lo, hi| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            lo + x % (hi - lo + 1)
        });
        assert!(!faults.is_empty());
        assert!(faults[0].at_secs >= WARMUP_SECS);
        for w in faults.windows(2) {
            assert!(w[1].at_secs >= w[0].at_secs + w[0].down_secs + 20);
        }
        for k in &faults {
            assert!(k.down_secs <= MAX_DOWN_SECS);
            assert!(k.at_secs + k.down_secs + 20 <= 200);
        }
    }

    #[test]
    fn max_kills_caps_the_plan() {
        assert_eq!(plan(&cfg(2, 1), 10_000, |lo, _| lo).len(), 2);
    }

    fn ev(source: &str, kind: &str, container: Option<&str>, t: u64, detail: Value) -> DstEvent {
        DstEvent {
            source: source.into(),
            kind: kind.into(),
            container: container.map(Into::into),
            guest_time_ns: t,
            detail,
        }
    }

    fn pk(at_secs: u64, down_secs: u64) -> ScheduledFault {
        ScheduledFault {
            at_secs,
            down_secs,
            fault: Fault::ProcessKill,
        }
    }

    fn lg(txgen_seed: u64, spec_seed: u64) -> LoadGeneration {
        LoadGeneration {
            txgen_seed,
            spec_seed,
        }
    }

    /// A branch 20 s in: plan [10+2, 40+1], the first kill and restart done.
    fn progress_at_20s() -> Progress {
        let node = Some(NODE_CONTAINER);
        let gen =
            |g: u64| json!({"generation": g, "txgen_seed": 99 + g, "spec_seed": 7, "steps": 5});
        Progress::of(&[
            ev("load", "generation", Some("txgen"), 900, gen(0)),
            ev(
                "nemesis",
                "plan",
                node,
                1_000,
                json!({"kills": [{"at_secs": 10, "down_secs": 2}, {"at_secs": 40, "down_secs": 1}]}),
            ),
            ev("nemesis", "kill", node, 11_000, json!({"index": 0})),
            // The load reload is logged as a txgen kill: not a node kill.
            ev("nemesis", "kill", Some("txgen"), 13_100, json!({})),
            ev("nemesis", "restart", node, 13_000, json!({"index": 0})),
            ev("load", "generation", Some("txgen"), 13_200, gen(1)),
            ev("assertion", "first-failure", None, 15_000, json!({})),
        ])
    }

    #[test]
    fn progress_counts_node_faults_and_generations() {
        let p = progress_at_20s();
        assert_eq!(p.start_ns, Some(1_000));
        assert_eq!(p.plan, [pk(10, 2), pk(40, 1)]);
        assert_eq!((p.faults, p.restarts), (1, 1));
        assert_eq!(p.generations, [lg(99, 7), lg(100, 7)]);
        assert!(p.quiescent(true));
        // A kill without its restart, or a restart before its generation,
        // is in flight.
        let mut mid = p.clone();
        mid.faults = 2;
        assert!(!mid.quiescent(false));
        let mut reload = p.clone();
        reload.generations.pop();
        assert!(!reload.quiescent(true) && reload.quiescent(false));
        assert!(!Progress::default().quiescent(false));
    }

    #[test]
    fn redecision_keeps_what_already_happened() {
        let p = progress_at_20s();
        // The driver proposes a new plan whose first kill differs from the
        // one that fired: the fired one stays, and a proposed kill in the
        // past is dropped.
        let r = Redecision {
            nemesis_plan: vec![pk(11, 3), pk(19, 0), pk(25, 2), pk(26, 0), pk(60, 1)],
            generations: vec![lg(1, 1), lg(2, 2), lg(3, 3), lg(4, 4)],
            network_plan: None,
        };
        let m = merge(&p, &r, 20);
        // Index 0 fired (kept as fired); 19 is in the past; 26 overlaps 25+2.
        assert_eq!(m.nemesis_plan, [pk(10, 2), pk(25, 2), pk(60, 1)]);
        // Generations 0 and 1 started; the rest are the proposal's.
        assert_eq!(m.generations, [lg(99, 7), lg(100, 7), lg(3, 3), lg(4, 4)]);
        // A proposal shorter than what happened keeps what happened.
        let none = merge(&p, &Redecision::default(), 20);
        assert_eq!(none.nemesis_plan, [pk(10, 2)]);
        assert_eq!(none.generations.len(), 2);
    }

    #[test]
    fn zones_kills_rotate_over_l1_zone_and_prover() {
        let mut c = Config {
            seed: 4,
            ..Config::default()
        };
        assert_eq!(kill_target(&c, 0), NODE_CONTAINER);
        assert_eq!(kill_target(&c, 5), NODE_CONTAINER);
        c.zones = true;
        let t: Vec<_> = (0..3).map(|i| kill_target(&c, i)).collect();
        assert_eq!(t, ["tempo", "zone", "zone-prover"]);
        // Progress counts planned kills of any target, not load reloads.
        let p = Progress::of(&[
            ev(
                "nemesis",
                "plan",
                Some(NODE_CONTAINER),
                1,
                json!({"kills": []}),
            ),
            ev("nemesis", "kill", Some("zone"), 2, json!({"index": 0})),
            ev(
                "nemesis",
                "kill",
                Some("zones-load"),
                3,
                json!({"reason": "reload"}),
            ),
            ev("nemesis", "restart", Some("zone"), 4, json!({"index": 0})),
        ]);
        assert_eq!((p.faults, p.restarts), (1, 1));
    }

    fn fault(at_secs: u64, dur_secs: u64) -> NetFault {
        NetFault {
            at_secs,
            dur_secs,
            family: netfault::NetFaultKind::LinkCut,
            steps: vec![],
        }
    }

    #[test]
    fn network_faults_count_as_progress_and_merge_like_kills() {
        let plan = vec![fault(15, 10), fault(60, 10)];
        let mut events = vec![
            ev(
                "nemesis",
                "plan",
                Some(NODE_CONTAINER),
                1,
                json!({"kills": []}),
            ),
            ev("network", "plan", None, 1, json!({"faults": plan})),
            ev("network", "fault-start", None, 2, json!({"index": 0})),
        ];
        let p = Progress::of(&events);
        assert_eq!((p.net_started, p.net_ended), (1, 0));
        assert_eq!(p.net_plan, plan);
        // Inside a fault the nemesis is not between faults.
        assert!(!p.quiescent(false));
        events.push(ev("network", "fault-end", None, 3, json!({"index": 0})));
        let p = Progress::of(&events);
        assert!(p.quiescent(false));
        // A re-drawn proposal keeps the started fault and drops one in the past.
        let r = Redecision {
            nemesis_plan: vec![],
            generations: vec![],
            network_plan: Some(vec![fault(16, 5), fault(20, 5), fault(40, 10)]),
        };
        let m = merge(&p, &r, 30);
        assert_eq!(m.network_plan.unwrap(), [fault(15, 10), fault(40, 10)]);
        // Without the network nemesis nothing is added.
        let none = merge(&p, &Redecision::default(), 30);
        assert!(none.network_plan.is_none());
    }

    #[test]
    fn explicit_network_plans_win_but_still_draw() {
        let net = netfault::NetworkConfig {
            enabled: true,
            kinds: netfault::NetFaultKind::GENERIC.to_vec(),
            max_faults: 3,
            min_gap_secs: 30,
            topology: netfault::NetTopology {
                nodes: (0..3)
                    .map(|i| netfault::NetNode {
                        name: format!("n{i}"),
                        ip: std::net::Ipv4Addr::new(10, 0, 0, 2 + i),
                    })
                    .collect(),
                ..netfault::NetTopology::default()
            },
        };
        let c = Config {
            run_secs: 300,
            network: Some(net),
            network_plan: Some(vec![fault(50, 10)]),
            ..Config::default()
        };
        let mut draws = 0;
        let faults = network_for(&c, &[], |lo, _| {
            draws += 1;
            lo
        });
        assert_eq!(faults, [fault(50, 10)]);
        let mut plain = 0;
        let derived = Config {
            network_plan: None,
            ..c.clone()
        };
        let drawn = network_for(&derived, &[], |lo, _| {
            plain += 1;
            lo
        });
        assert_eq!(draws, plain);
        assert!(!drawn.is_empty());
        // No network nemesis: no faults, no draws.
        let mut none = 0;
        assert!(network_for(&Config::default(), &[], |lo, _| {
            none += 1;
            lo
        })
        .is_empty());
        assert_eq!(none, 0);
    }

    #[test]
    fn plan_is_a_function_of_the_draws() {
        let a = plan(&cfg(5, 15), 300, |lo, hi| (lo + hi) / 2);
        let b = plan(&cfg(5, 15), 300, |lo, hi| (lo + hi) / 2);
        assert_eq!(a, b);
    }

    #[test]
    fn without_storage_faults_the_draws_are_unchanged() {
        // Exactly two draws per kill, as before storage faults existed.
        let mut n = 0;
        let faults = plan(&cfg(3, 20), 1000, |lo, _| {
            n += 1;
            lo
        });
        assert_eq!(faults.len(), 3);
        assert_eq!(n, 6);
        // And the plan event reads as before.
        assert_eq!(
            serde_json::to_string(&faults[0]).unwrap(),
            r#"{"at_secs":5,"down_secs":0}"#
        );
    }

    #[test]
    fn storage_faults_draw_every_family_and_fit_windows() {
        let c = NemesisConfig {
            storage_faults: true,
            ..cfg(200, 1)
        };
        let faults = plan(&c, 1_000_000, lcg());
        assert_eq!(faults.len(), 200);
        let has = |f: fn(&Fault) -> bool| faults.iter().any(|k| f(&k.fault));
        assert!(has(|f| matches!(f, Fault::ProcessKill)));
        assert!(has(|f| matches!(
            f,
            Fault::MachineCrash {
                discard: Discard::All
            }
        )));
        assert!(has(|f| matches!(
            f,
            Fault::MachineCrash {
                discard: Discard::Subset { .. }
            }
        )));
        let torn: Vec<Torn> = faults
            .iter()
            .filter_map(|k| match k.fault {
                Fault::TornWrite { torn, .. } => Some(torn),
                _ => None,
            })
            .collect();
        for file in TornFile::ALL {
            assert!(torn.iter().any(|t| match *t {
                Torn::Op { file: f, .. } | Torn::Seq { file: f, .. } => f == file,
            }));
        }
        assert!(torn.iter().any(|t| matches!(t, Torn::Op { .. })));
        assert!(torn.iter().any(|t| matches!(t, Torn::Seq { .. })));
        // A torn-op persists a strict, non-empty subset of its parts.
        assert!(torn.iter().all(|t| match *t {
            Torn::Op { parts, persist, .. } =>
                (2..=4).contains(&parts) && persist > 0 && persist < (1 << parts) - 1,
            Torn::Seq { persist, .. } => persist > 0 && persist < 16,
        }));
        for w in faults.windows(2) {
            assert!(w[1].at_secs > w[0].end_secs());
        }
        assert_eq!(faults, plan(&c, 1_000_000, lcg()));
        // Restricting the families draws only those.
        let crash_only = NemesisConfig {
            storage_fault_kinds: vec!["crash".into()],
            ..c.clone()
        };
        assert!(plan(&crash_only, 1_000_000, lcg())
            .iter()
            .all(|k| matches!(k.fault, Fault::MachineCrash { .. })));
        // Plans round-trip through config.json and the plan event.
        let text = serde_json::to_string(&faults).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<ScheduledFault>>(&text).unwrap(),
            faults
        );
        let v =
            serde_json::to_value(faults[1..].iter().find(|k| !k.fault.is_process_kill())).unwrap();
        assert!(v["fault"]["kind"].is_string());
    }

    #[test]
    fn merge_and_validate_respect_fault_windows() {
        let window = ScheduledFault {
            at_secs: 10,
            down_secs: 1,
            fault: Fault::TornWrite {
                torn: Torn::Seq {
                    file: TornFile::Mdbx,
                    persist: 1,
                    occurrence: 1,
                },
                window_secs: 8,
            },
        };
        assert_eq!(window.end_secs(), 19);
        let p = Progress {
            start_ns: Some(0),
            plan: vec![window],
            faults: 1,
            restarts: 1,
            ..Progress::default()
        };
        // 15 s lands inside the fired fault's window: dropped.
        let r = Redecision {
            nemesis_plan: vec![window, pk(15, 0), pk(19, 0)],
            generations: vec![],
            network_plan: None,
        };
        assert_eq!(merge(&p, &r, 12).nemesis_plan, [window, pk(19, 0)]);
        let cfg = Config {
            nemesis_plan: Some(vec![window, pk(18, 0)]),
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn process_faults_draw_every_family_within_bounds() {
        let faults = plan(&process(&[]), 1_000_000, lcg());
        assert_eq!(faults.len(), 200);
        let has = |f: fn(&Fault) -> bool| faults.iter().any(|k| f(&k.fault));
        assert!(has(|f| matches!(f, Fault::ProcessKill)));
        assert!(has(|f| matches!(f, Fault::Pause { .. })));
        assert!(has(|f| matches!(f, Fault::Throttle { .. })));
        assert!(has(|f| matches!(f, Fault::GracefulStop { .. })));
        for k in &faults {
            match k.fault {
                Fault::Pause { pause_secs } => {
                    assert!((PAUSE_SECS.0..=PAUSE_SECS.1).contains(&pause_secs))
                }
                Fault::Throttle {
                    quota_pct,
                    window_secs,
                } => {
                    assert!((10..=30).contains(&quota_pct));
                    assert!((THROTTLE_SECS.0..=THROTTLE_SECS.1).contains(&window_secs));
                }
                Fault::GracefulStop { timeout_secs } => {
                    assert!((STOP_TIMEOUT_SECS.0..=STOP_TIMEOUT_SECS.1).contains(&timeout_secs))
                }
                Fault::ProcessKill => {}
                f => panic!("storage fault without storage_faults: {f:?}"),
            }
            // Process faults are never storage crashes.
            assert_eq!(k.fault.discard(), None);
        }
        // Each fault (window included) ends before the next begins.
        for w in faults.windows(2) {
            let end = w[0].at_secs + w[0].fault.window_secs() + w[0].down_secs;
            assert!(w[1].at_secs > end);
        }
        // A function of the draws.
        assert_eq!(faults, plan(&process(&[]), 1_000_000, lcg()));
        let v = serde_json::to_value(
            faults
                .iter()
                .find(|k| matches!(k.fault, Fault::GracefulStop { .. }))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(v["fault"]["kind"], "graceful-stop");
    }

    #[test]
    fn process_fault_draws_are_exact() {
        // Per fault: the time, the downtime, the family, then its parameters.
        let mut script = vec![
            3, 1, 1, 7, // pause (family 1) for 7 s
            0, 2, 2, 20, 9, // throttle at 20% for 9 s
            4, 0, 3, 25, // stop with a 25 s timeout
            1, 3, 0, // kill
        ]
        .into_iter();
        let c = NemesisConfig {
            min_gap_secs: 10,
            ..process(&[])
        };
        let faults = plan(&c, 1000, |lo, hi| {
            let v = script.next().unwrap_or(lo);
            assert!((lo..=hi).contains(&v), "{v} not in {lo}..={hi}");
            v
        });
        let kinds = faults.iter().take(4).map(|k| k.fault).collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                Fault::Pause { pause_secs: 7 },
                Fault::Throttle {
                    quota_pct: 20,
                    window_secs: 9
                },
                Fault::GracefulStop { timeout_secs: 25 },
                Fault::ProcessKill,
            ]
        );
        assert_eq!(faults[0].at_secs, WARMUP_SECS + 3);
        // The next fault's draw starts a gap after the pause's end.
        assert_eq!(faults[1].at_secs, WARMUP_SECS + 3 + 7 + 1 + 10);
    }

    #[test]
    fn process_fault_kinds_restrict_and_combine_with_storage() {
        for (kind, is) in [
            (
                "pause",
                (|f: &Fault| matches!(f, Fault::Pause { .. })) as fn(&Fault) -> bool,
            ),
            ("throttle", |f| matches!(f, Fault::Throttle { .. })),
            ("stop", |f| matches!(f, Fault::GracefulStop { .. })),
        ] {
            let faults = plan(&process(&[kind]), 100_000, lcg());
            assert!(!faults.is_empty());
            assert!(faults.iter().all(|k| is(&k.fault)), "{kind}");
        }
        // Unknown kinds fall back to every family.
        assert_eq!(draw_table(&process(&["nope"])).unwrap(), PROCESS_FAMILIES);
        // With storage faults, the storage table keeps its own kill share.
        let both = NemesisConfig {
            storage_faults: true,
            ..process(&[])
        };
        assert_eq!(
            draw_table(&both).unwrap(),
            ["kill", "crash", "crash", "torn", "pause", "throttle", "stop"]
        );
        // Without the flag, storage seeds keep their table (and meaning).
        let storage = NemesisConfig {
            storage_faults: true,
            ..cfg(3, 20)
        };
        assert_eq!(draw_table(&storage).unwrap(), FAMILIES);
        assert_eq!(draw_table(&cfg(3, 20)), None);
    }

    #[test]
    fn progress_counts_pauses_as_entries_but_not_restarts() {
        let node = Some(NODE_CONTAINER);
        let gen =
            |g: u64| json!({"generation": g, "txgen_seed": 99 + g, "spec_seed": 7, "steps": 5});
        let mut evs = vec![
            ev("load", "generation", Some("txgen"), 900, gen(0)),
            ev("nemesis", "plan", node, 1_000, json!({"kills": []})),
            ev("nemesis", "pause", node, 2_000, json!({"index": 0})),
        ];
        // Inside the pause: in flight.
        assert!(!Progress::of(&evs).quiescent(true));
        evs.push(ev("nemesis", "resume", node, 3_000, json!({"index": 0})));
        let p = Progress::of(&evs);
        assert_eq!((p.faults, p.restarts, p.node_restarts), (1, 1, 0));
        // A pause starts no load generation.
        assert!(p.quiescent(true));
        evs.push(ev("nemesis", "stop", node, 4_000, json!({"index": 1})));
        evs.push(ev("nemesis", "restart", node, 5_000, json!({"index": 1})));
        let p = Progress::of(&evs);
        assert_eq!((p.faults, p.node_restarts, p.last_restart), (2, 1, Some(1)));
        // Its restart's generation (2: plan entry 1 + 1) is still due.
        assert!(!p.quiescent(true));
        evs.push(ev("load", "generation", Some("txgen"), 6_000, gen(2)));
        assert!(Progress::of(&evs).quiescent(true));
    }
}
