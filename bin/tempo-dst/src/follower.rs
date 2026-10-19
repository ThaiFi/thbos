// SPDX-License-Identifier: GPL-2.0

//! A certified L1 consensus follower driven behind and made to catch up: the
//! generic detector for the tempo#8263 class ("canonicalize follower catch-up
//! after syncing forkchoice").
//!
//! A follower that falls behind the certified consensus and catches up sends a
//! forkchoice ahead of execution; reth answers `SYNCING`, and the buggy path
//! stalls canonicalization and persistence. The invariant: after any rejoin
//! (snapshot restore, a kill-and-hold, a pause, a healed partition) a `SYNCING`
//! forkchoice must resolve to execution, canonicalization, advancing
//! persistence and a canonical history matching the validators' finalized
//! chain — never a stall.
//!
//! The follower is the `tempo` container ([`NODE_CONTAINER`]) in two topologies:
//!
//! - zones: it is the primary, with four independent upstream validators
//!   ([`crate::topology::zones_topology`]); the kill plan restores its snapshot;
//! - the generic consensus cluster (`validators=N consensus=true follower=true`):
//!   it is an extra node alongside `v1..vN` under any load, driven behind by the
//!   scheduled [`FollowerFault`] plan ([`crate::cluster_live::run_nemesis`]).
//!
//! The catch-up oracle ([`FollowerOracle`]) is trigger-agnostic: it arms on any
//! rejoin of its container and asserts the invariant, so it works for every
//! trigger and load, and could watch a validator that fell behind as well.

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    common::{self, DstEvent, NODE_CONTAINER},
    oracle::parse_saved,
    verdict::{finding, Verdict},
};

const SNAPSHOT: &str = "/bedrock/follower-snapshot";
const MARKER: &str = "/bedrock/follower-snapshot-height";
const S: u64 = 1_000_000_000;

/// A scheduled follower offline-window fault: the follower is driven behind the
/// certified consensus and must catch up (the tempo#8263 class). Every field is
/// a pure function of the run seed, so a replay drives the same windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FollowerFault {
    /// Guest seconds after the follower nemesis starts to open the window.
    pub at_secs: u64,
    /// How the follower is taken offline (the gap depth).
    pub trigger: FollowerTrigger,
}

/// The offline-window triggers, in increasing gap depth. All of them funnel
/// into the same trigger-agnostic catch-up oracle on rejoin. The gap must cross
/// the follower's persistence/finality frontier so the rejoin forkchoice points
/// at a head it has not executed yet — the exact `SYNCING` #8263 path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FollowerTrigger {
    /// Restore the clean pre-warm datadir, then restart: the deepest gap and
    /// the strongest trigger (the snapshot predates the persisted tip).
    SnapshotRestore,
    /// SIGKILL and hold the follower down `down_secs` before restart. Sized
    /// past the persistence frontier so the rejoin forkchoice is ahead of
    /// execution.
    KillHold { down_secs: u64 },
    /// `podman pause` the follower for `secs`, then unpause: a softer gap that
    /// still outruns persistence.
    Pause { secs: u64 },
}

impl FollowerTrigger {
    /// How long the window keeps the follower offline, for scheduling the gap
    /// to the next window.
    pub fn down_secs(self) -> u64 {
        match self {
            FollowerTrigger::SnapshotRestore => 0,
            FollowerTrigger::KillHold { down_secs } => down_secs,
            FollowerTrigger::Pause { secs } => secs,
        }
    }
}

pub fn snapshot_exists() -> bool {
    Path::new(MARKER).is_file()
}

fn data_dir() -> io::Result<PathBuf> {
    let output = Command::new("podman")
        .args([
            "inspect",
            NODE_CONTAINER,
            "--format",
            "{{range .Mounts}}{{if eq .Destination \"/data\"}}{{.Source}}{{end}}{{end}}",
        ])
        .output()?;
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    if !output.status.success() || !path.is_absolute() || !path.is_dir() {
        return Err(io::Error::other("follower has no /data volume"));
    }
    Ok(path)
}

fn podman(args: &[&str]) -> io::Result<()> {
    if !Command::new("podman").args(args).status()?.success() {
        return Err(io::Error::other(format!(
            "podman {} failed",
            args.join(" ")
        )));
    }
    Ok(())
}

fn copy(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    if !Command::new("cp")
        .arg("-a")
        .arg(from.join("."))
        .arg(to)
        .status()?
        .success()
    {
        return Err(io::Error::other("copying follower snapshot failed"));
    }
    Ok(())
}

pub fn snapshot() -> io::Result<()> {
    let source = data_dir()?;
    let height = common::head_number().map_err(io::Error::other)?;
    // No live MDBX or consensus journal copy: shut the process down first.
    podman(&["stop", "-t", "120", NODE_CONTAINER])?;
    let result = (|| {
        if Path::new(SNAPSHOT).exists() {
            fs::remove_dir_all(SNAPSHOT)?;
        }
        copy(&source, Path::new(SNAPSHOT))?;
        fs::write(MARKER, height.to_string())
    })();
    // Even a failed copy must not strand the warmup's follower.
    podman(&["start", NODE_CONTAINER])?;
    result
}

pub fn restore() -> io::Result<()> {
    let running = Command::new("podman")
        .args(["inspect", NODE_CONTAINER, "--format", "{{.State.Running}}"])
        .output()?;
    if !running.status.success() || String::from_utf8_lossy(&running.stdout).trim() != "false" {
        return Err(io::Error::other("refusing to restore a running follower"));
    }
    let height = fs::read_to_string(MARKER)?
        .trim()
        .parse::<u64>()
        .map_err(io::Error::other)?;
    if !Path::new(SNAPSHOT).is_dir() {
        return Err(io::Error::other("follower snapshot missing"));
    }
    let dest = data_dir()?;
    for entry in fs::read_dir(&dest)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    copy(Path::new(SNAPSHOT), &dest)?;
    common::emit_event(
        "follower",
        "snapshot-restored",
        Some(NODE_CONTAINER),
        json!({"height": height}),
    );
    Ok(())
}

/// Carries out follower fault `index`: it drives the follower behind and emits
/// the nemesis events the catch-up oracle arms on. Used by the cluster nemesis
/// ([`crate::cluster_live::run_nemesis`]); zones drives the snapshot restore
/// through its kill plan instead ([`crate::nemesis`]).
pub fn apply(index: usize, fault: &FollowerFault) {
    match fault.trigger {
        FollowerTrigger::SnapshotRestore => snapshot_restore(index),
        FollowerTrigger::KillHold { down_secs } => kill_hold(index, down_secs),
        FollowerTrigger::Pause { secs } => pause(index, secs),
    }
}

fn emit(kind: &str, index: usize, extra: serde_json::Value) {
    let mut detail = json!({"index": index});
    if let (Some(a), Some(b)) = (detail.as_object_mut(), extra.as_object()) {
        a.extend(b.clone());
    }
    common::emit_event("nemesis", kind, Some(NODE_CONTAINER), detail);
}

/// Stop the follower, swap in the clean pre-warm datadir, restart it.
fn snapshot_restore(index: usize) {
    emit("kill", index, json!({"trigger": "snapshot_restore"}));
    if let Err(e) = podman(&["stop", "-t", "120", NODE_CONTAINER]) {
        eprintln!("follower nemesis: stop before restore: {e}");
    }
    if let Err(e) = restore() {
        common::assert_always(
            bedrock_assertions::Condition::Bool(false),
            "nemesis",
            "H/follower-snapshot-restore-failed",
            &e.to_string(),
        );
    }
    let started = podman(&["start", NODE_CONTAINER]).is_ok();
    emit("restart", index, json!({"started": started}));
}

/// SIGKILL the follower and hold it down `down_secs` before restart.
fn kill_hold(index: usize, down_secs: u64) {
    emit(
        "kill",
        index,
        json!({"trigger": "kill_hold", "down_secs": down_secs}),
    );
    if let Err(e) = podman(&["kill", "-s", "KILL", NODE_CONTAINER]) {
        eprintln!("follower nemesis: kill: {e}");
    }
    let _ = Command::new("podman")
        .args(["wait", NODE_CONTAINER])
        .status();
    std::thread::sleep(std::time::Duration::from_secs(down_secs));
    let started = podman(&["start", NODE_CONTAINER]).is_ok();
    emit("restart", index, json!({"started": started}));
}

/// Pause the follower `secs`, then unpause: it falls behind without dying.
fn pause(index: usize, secs: u64) {
    emit("pause", index, json!({"trigger": "pause", "secs": secs}));
    if let Err(e) = podman(&["pause", NODE_CONTAINER]) {
        eprintln!("follower nemesis: pause: {e}");
    }
    std::thread::sleep(std::time::Duration::from_secs(secs));
    let resumed = podman(&["unpause", NODE_CONTAINER]).is_ok();
    emit("resume", index, json!({"resumed": resumed}));
}

/// Runs a follower fault plan from the current guest time: wait for each
/// window's `at_secs`, apply it, let the follower catch up before the next.
pub fn run_plan(plan: &[FollowerFault]) {
    let start = common::guest_time_ns();
    common::emit_event(
        "nemesis",
        "follower-plan",
        Some(NODE_CONTAINER),
        json!({ "follower_faults": plan }),
    );
    for (i, f) in plan.iter().enumerate() {
        let at = start + f.at_secs * S;
        let now = common::guest_time_ns();
        if at > now {
            std::thread::sleep(std::time::Duration::from_nanos(at - now));
        }
        apply(i, f);
    }
}

/// State sampled after the follower has rejoined. The target is fixed to
/// upstream finality at rejoin, so a continuously advancing network cannot
/// move the recovery goalposts.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    pub upstream: u64,
    pub head: u64,
    pub finalized: u64,
    pub same_hash: bool,
}

/// The trigger-agnostic catch-up oracle for one follower container. It arms on
/// any rejoin and asserts the tempo#8263 invariant within a liveness bound.
#[derive(Debug)]
pub struct FollowerOracle {
    /// The container it watches (the follower is always `tempo`, but the
    /// invariant applies to any node that fell behind and rejoined).
    container: &'static str,
    liveness_ns: u64,
    down: bool,
    /// A catch-up window is open (the follower rejoined and must reconverge).
    armed: bool,
    /// Guest time the current window opened; logs before it are the previous
    /// incarnation's and do not count.
    armed_at: u64,
    target: Option<u64>,
    deadline: Option<u64>,
    last_progress: u64,
    head: u64,
    saved: u64,
    saved_before: u64,
    syncing: bool,
    executed: bool,
    reported: bool,
}

impl FollowerOracle {
    pub fn new(liveness_secs: u64, now: u64) -> Self {
        Self::for_container(NODE_CONTAINER, liveness_secs, now)
    }

    pub fn for_container(container: &'static str, liveness_secs: u64, now: u64) -> Self {
        Self {
            container,
            liveness_ns: liveness_secs * S,
            down: false,
            armed: false,
            armed_at: 0,
            target: None,
            deadline: None,
            last_progress: now,
            head: 0,
            saved: 0,
            saved_before: 0,
            syncing: false,
            executed: false,
            reported: false,
        }
    }

    /// Opens a fresh catch-up window at `at` (a rejoin). `reset_persistence`
    /// for a snapshot restore, whose datadir predates the persisted tip, so the
    /// watermark the run must pass is the previous incarnation's, not 0.
    fn arm(&mut self, at: u64, reset_persistence: bool) {
        self.armed = true;
        self.armed_at = at;
        self.down = false;
        self.target = None;
        self.deadline = Some(at + self.liveness_ns);
        self.last_progress = at;
        self.head = 0;
        if reset_persistence {
            self.saved_before = self.saved;
            self.saved = 0;
        } else {
            self.saved_before = self.saved;
        }
        self.syncing = false;
        self.executed = false;
        self.reported = false;
    }

    pub fn on_event(&mut self, ev: &DstEvent, now: u64) -> Vec<Verdict> {
        if ev.container.as_deref() != Some(self.container) {
            return Vec::new();
        }
        match (ev.source.as_str(), ev.kind.as_str()) {
            // A snapshot restore is the rejoin itself (the follower is started
            // right after it): arm, resetting the persistence baseline.
            ("follower", "snapshot-restored") => {
                self.arm(ev.guest_time_ns.max(now), true);
                return vec![Verdict::Sometimes(
                    true,
                    finding("S/follower-snapshot-restored", ev.detail.to_string()),
                )];
            }
            ("nemesis", "kill" | "down" | "stop" | "pause" | "partition") => self.down = true,
            // Any rejoin after a down window arms the catch-up check. A restart
            // right after a snapshot restore is already armed above; re-arming
            // would wrongly clear the reset persistence baseline, so skip it.
            ("nemesis", "restart" | "resume" | "heal") if self.down => {
                self.arm(now, false);
            }
            _ => {}
        }
        Vec::new()
    }

    pub fn on_log_at(&mut self, at_ns: u64, line: &str) -> Vec<Verdict> {
        if at_ns < self.armed_at {
            return Vec::new();
        }
        self.on_log(line)
    }

    fn on_log(&mut self, line: &str) -> Vec<Verdict> {
        if !self.armed {
            return Vec::new();
        }
        if let Some((saved, _)) = parse_saved(line) {
            self.saved = self.saved.max(saved);
        }
        if self.reported {
            return Vec::new();
        }
        if !self.syncing
            && line.contains("execution layer reported FCU status")
            && line.to_ascii_uppercase().contains("SYNCING")
        {
            self.syncing = true;
            return vec![Verdict::Sometimes(
                true,
                finding("S/follower-syncing-observed", line.into()),
            )];
        }
        if self.syncing && !self.executed && line.contains("Executed block") {
            self.executed = true;
            return vec![Verdict::Sometimes(
                true,
                finding("S/follower-executed-after-syncing", line.into()),
            )];
        }
        Vec::new()
    }

    pub fn tick(&mut self, sample: Option<Sample>, now: u64) -> Vec<Verdict> {
        if !self.armed || self.down || self.reported {
            return Vec::new();
        }
        if let Some(s) = sample {
            let target = *self.target.get_or_insert(s.upstream);
            if s.head > self.head {
                self.head = s.head;
                self.last_progress = now;
            }
            let caught_up = s.head >= target && s.finalized >= target;
            if caught_up && !s.same_hash {
                self.reported = true;
                return vec![Verdict::Always(
                    false,
                    finding(
                        "E/follower-canonical-diverged",
                        format!("target={target}, head={}", s.head),
                    ),
                )];
            }
            // Head and finality reconverged on the right hashes: persistence
            // must pass the previous incarnation's watermark too (the snapshot
            // can be much older than that watermark). A head that caught up but
            // persistence that never advances is the #8263 persistence stall.
            if caught_up && s.same_hash {
                if self.saved > self.saved_before {
                    self.reported = true;
                    return vec![Verdict::Sometimes(
                        true,
                        finding(
                            "S/follower-caught-up",
                            format!(
                                "head={}, finalized={}, target={target}, saved={}",
                                s.head, s.finalized, self.saved
                            ),
                        ),
                    )];
                }
                if self.deadline.is_some_and(|deadline| now > deadline) {
                    self.reported = true;
                    return vec![Verdict::Always(
                        false,
                        finding(
                            "E/follower-persistence-stalled",
                            format!(
                                "head={}, finalized={}, target={target}, saved={}, previous_saved={}",
                                s.head, s.finalized, self.saved, self.saved_before
                            ),
                        ),
                    )];
                }
                return Vec::new();
            }
        }
        // Still behind: execution can take longer than one budget, but the head
        // must keep advancing; a stuck RPC past the deadline is judged too.
        if self.deadline.is_some_and(|deadline| now > deadline)
            && now.saturating_sub(self.last_progress) > self.liveness_ns
        {
            self.reported = true;
            return vec![Verdict::Always(
                false,
                finding(
                    "E/follower-catch-up-stalled",
                    format!(
                        "target={:?}, head={}, saved={}, previous_saved={}, syncing={}",
                        self.target, self.head, self.saved, self.saved_before, self.syncing
                    ),
                ),
            )];
        }
        Vec::new()
    }
}

pub fn sample(target: Option<u64>) -> Option<Sample> {
    let upstream = common::with_rpc_url(
        crate::cluster::ValidatorId::new(1)?.rpc_url(),
        common::finalized_block,
    )
    .ok()??
    .0;
    let head = common::head_number().ok()?;
    let finalized = common::finalized_block().ok()??.0;
    let compare = target.unwrap_or(upstream).min(head);
    let hash = common::block_ref(compare).ok()??.0;
    let upstream_hash =
        common::with_rpc_url(crate::cluster::ValidatorId::new(1)?.rpc_url(), || {
            common::block_ref(compare)
        })
        .ok()??
        .0;
    Some(Sample {
        upstream,
        head,
        finalized,
        same_hash: hash == upstream_hash,
    })
}

pub fn step(oracle: &mut FollowerOracle, now: u64) -> Vec<Verdict> {
    oracle.tick(sample(oracle.target), now)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(source: &str, kind: &str) -> DstEvent {
        DstEvent {
            source: source.into(),
            kind: kind.into(),
            container: Some(NODE_CONTAINER.into()),
            guest_time_ns: 0,
            detail: json!({"height": 10}),
        }
    }

    fn signature(verdict: &Verdict) -> &str {
        match verdict {
            Verdict::Always(_, f) | Verdict::Sometimes(_, f) => &f.signature,
        }
    }

    /// A follower recovering from a snapshot restore (the deepest gap).
    fn recovering() -> FollowerOracle {
        let mut oracle = FollowerOracle::new(60, 0);
        oracle.on_event(&event("nemesis", "kill"), 0);
        oracle.on_event(&event("follower", "snapshot-restored"), 0);
        oracle
    }

    #[test]
    fn syncing_then_execution_without_catch_up_stalls() {
        let mut oracle = recovering();
        assert_eq!(
            signature(
                &oracle.on_log("execution layer reported FCU status payload_status=SYNCING")[0]
            ),
            "S/follower-syncing-observed"
        );
        let sample = Sample {
            upstream: 100,
            head: 10,
            finalized: 10,
            same_hash: true,
        };
        assert!(oracle.tick(Some(sample), 2 * S).is_empty());
        let result = oracle.tick(Some(sample), 63 * S);
        assert_eq!(signature(&result[0]), "E/follower-catch-up-stalled");
    }

    #[test]
    fn matching_head_requires_finality_hash_and_persistence() {
        let mut oracle = recovering();
        let sample = Sample {
            upstream: 100,
            head: 100,
            finalized: 100,
            same_hash: true,
        };
        assert!(oracle.tick(Some(sample), 2 * S).is_empty());
        oracle.on_log("Saved range of blocks last=NumHash { number: 100, hash: 0x1 }");
        let result = oracle.tick(Some(sample), 3 * S);
        assert_eq!(signature(&result[0]), "S/follower-caught-up");
        // The target is fixed at the first post-rejoin sample.
        assert_eq!(oracle.target, Some(100));
    }

    #[test]
    fn head_caught_up_but_persistence_never_advances_is_the_persistence_stall() {
        let mut oracle = recovering();
        // The previous incarnation persisted to 100; the restored snapshot is
        // older, so the watermark to pass is 100.
        oracle.on_log("Saved range of blocks last=NumHash { number: 100, hash: 0x1 }");
        oracle.on_event(&event("nemesis", "kill"), S);
        oracle.on_event(&event("follower", "snapshot-restored"), S);
        let sample = Sample {
            upstream: 120,
            head: 120,
            finalized: 120,
            same_hash: true,
        };
        assert!(oracle.tick(Some(sample), 2 * S).is_empty());
        // Head and finality reconverge, but persistence stays at the old
        // watermark: the stall the fix prevents.
        oracle.on_log("Saved range of blocks last=NumHash { number: 90, hash: 0x1 }");
        let result = oracle.tick(Some(sample), 70 * S);
        assert_eq!(signature(&result[0]), "E/follower-persistence-stalled");
    }

    #[test]
    fn divergent_canonical_hash_fails_even_when_heights_match() {
        let mut oracle = recovering();
        let sample = Sample {
            upstream: 100,
            head: 100,
            finalized: 100,
            same_hash: false,
        };
        assert_eq!(
            signature(&oracle.tick(Some(sample), 2 * S)[0]),
            "E/follower-canonical-diverged"
        );
    }

    #[test]
    fn a_kill_and_hold_rejoin_arms_the_same_catch_up_check() {
        // No snapshot restore: a plain kill-and-hold window must still arm.
        let mut oracle = FollowerOracle::new(60, 0);
        oracle.on_log("Saved range of blocks last=NumHash { number: 50, hash: 0x1 }");
        oracle.on_event(&event("nemesis", "kill"), S);
        oracle.on_event(&event("nemesis", "restart"), 10 * S);
        assert_eq!(
            signature(
                &oracle.on_log("execution layer reported FCU status payload_status=SYNCING")[0]
            ),
            "S/follower-syncing-observed"
        );
        let sample = Sample {
            upstream: 100,
            head: 100,
            finalized: 100,
            same_hash: true,
        };
        // Persistence must pass the pre-kill watermark (50).
        oracle.on_log("Saved range of blocks last=NumHash { number: 100, hash: 0x1 }");
        assert_eq!(
            signature(&oracle.tick(Some(sample), 11 * S)[0]),
            "S/follower-caught-up"
        );
    }

    #[test]
    fn a_pause_and_resume_window_arms_the_check() {
        let mut oracle = FollowerOracle::new(60, 0);
        oracle.on_event(&event("nemesis", "pause"), S);
        oracle.on_event(&event("nemesis", "resume"), 5 * S);
        let sample = Sample {
            upstream: 100,
            head: 10,
            finalized: 10,
            same_hash: true,
        };
        assert!(oracle.tick(Some(sample), 6 * S).is_empty());
        assert_eq!(
            signature(&oracle.tick(Some(sample), 70 * S)[0]),
            "E/follower-catch-up-stalled"
        );
    }

    #[test]
    fn rpc_outage_expires_and_fault_time_is_excused() {
        let mut oracle = recovering();
        oracle.on_event(&event("nemesis", "kill"), 2 * S);
        assert!(oracle.tick(None, 100 * S).is_empty());
        oracle.on_event(&event("nemesis", "restart"), 100 * S);
        assert!(oracle.tick(None, 150 * S).is_empty());
        assert_eq!(
            signature(&oracle.tick(None, 161 * S)[0]),
            "E/follower-catch-up-stalled"
        );
    }

    #[test]
    fn syncing_coverage_must_belong_to_an_armed_window() {
        let mut oracle = FollowerOracle::new(60, 0);
        let line = "execution layer reported FCU status payload_status=SYNCING";
        assert!(oracle.on_log(line).is_empty());
        oracle.on_event(&event("nemesis", "kill"), S);
        oracle.on_event(&event("follower", "snapshot-restored"), S);
        assert_eq!(
            signature(&oracle.on_log(line)[0]),
            "S/follower-syncing-observed"
        );
        assert_eq!(
            signature(&oracle.on_log("engine::tree::payload_validator: Executed block")[0]),
            "S/follower-executed-after-syncing"
        );
    }

    #[test]
    fn restored_snapshot_cannot_reuse_the_previous_persistence_watermark() {
        let mut oracle = recovering();
        oracle.on_log("Saved range of blocks last=NumHash { number: 100, hash: 0x1 }");
        oracle.on_event(&event("nemesis", "kill"), 3 * S);
        oracle.on_event(&event("follower", "snapshot-restored"), 3 * S);
        oracle.on_log("Saved range of blocks last=NumHash { number: 90, hash: 0x1 }");
        let sample = Sample {
            upstream: 120,
            head: 120,
            finalized: 120,
            same_hash: true,
        };
        assert!(oracle.tick(Some(sample), 5 * S).is_empty());
        oracle.on_log("Saved range of blocks last=NumHash { number: 121, hash: 0x1 }");
        assert_eq!(
            signature(&oracle.tick(Some(sample), 6 * S)[0]),
            "S/follower-caught-up"
        );
    }

    #[test]
    fn queued_logs_from_before_the_window_cannot_claim_trigger_coverage() {
        let mut oracle = FollowerOracle::new(60, 0);
        oracle.on_event(&event("nemesis", "kill"), 0);
        let mut restored = event("follower", "snapshot-restored");
        restored.guest_time_ns = 10 * S;
        oracle.on_event(&restored, 10 * S);
        let line = "execution layer reported FCU status payload_status=SYNCING";
        assert!(oracle.on_log_at(9 * S, line).is_empty());
        assert_eq!(
            signature(&oracle.on_log_at(11 * S, line)[0]),
            "S/follower-syncing-observed"
        );
    }

    #[test]
    fn normal_following_after_recovery_cannot_supply_missing_trigger_coverage() {
        let mut oracle = recovering();
        oracle.on_log("Saved range of blocks last=NumHash { number: 100, hash: 0x1 }");
        let sample = Sample {
            upstream: 100,
            head: 100,
            finalized: 100,
            same_hash: true,
        };
        assert_eq!(
            signature(&oracle.tick(Some(sample), 2 * S)[0]),
            "S/follower-caught-up"
        );
        assert!(oracle
            .on_log("execution layer reported FCU status payload_status=SYNCING")
            .is_empty());
    }

    #[test]
    fn events_for_another_container_are_ignored() {
        let mut oracle = FollowerOracle::for_container("v2", 60, 0);
        // A tempo rejoin does not arm a v2 oracle.
        oracle.on_event(&event("nemesis", "kill"), 0);
        oracle.on_event(&event("follower", "snapshot-restored"), 0);
        assert!(!oracle.armed);
    }

    #[test]
    fn trigger_down_secs_sizes_the_gap() {
        assert_eq!(FollowerTrigger::SnapshotRestore.down_secs(), 0);
        assert_eq!(FollowerTrigger::KillHold { down_secs: 30 }.down_secs(), 30);
        assert_eq!(FollowerTrigger::Pause { secs: 25 }.down_secs(), 25);
    }
}
