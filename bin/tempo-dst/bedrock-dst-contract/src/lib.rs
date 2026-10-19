// SPDX-License-Identifier: GPL-2.0

//! The bedrock-dst workload contract: the typed requests and responses of
//! each hook a workload implements for the generic DST driver.
//!
//! A workload is a guest command (`--workload-cmd`, e.g. `tempo-dst`) and a
//! host-side planner binary (`--workload-planner`; it may be the same
//! static binary). The driver runs:
//!
//! | hook | where | input | output |
//! |------|-------|-------|--------|
//! | `parse-args -` | host | [`ArgsRequest`] (stdin) | the workload's `Args` |
//! | `warmup '<json>'` | guest, every 5 virtual s until ready | [`WarmupRequest`] | [`WarmupStatus`] (last stdout line) |
//! | `config -` | host | [`PlanRequest`] (stdin) | [`Plan`] |
//! | `start '<config>'` | guest, once per branch | `Plan::config` | exit 0 |
//! | `<action>` | guest, mid-run (branches) | `Plan::action` | anything; exit 0 |
//! | `finalize` | guest, at the end | - | the run's assertions in `/bedrock/out/assertions.jsonl` |
//! | `observe -` | host | [`ObserveRequest`] (stdin) | [`Observation`] |
//!
//! Host hooks are pure functions of their input, so the same campaign and
//! seed always plan the same run, and run on the host so planning never
//! perturbs guest time. The workload-specific payloads (`Args`, the guest
//! config `C`, the decisions `D`, the swarm record `S`) are type parameters:
//! the workload instantiates them with its own types, the driver with opaque
//! JSON it stores and passes back verbatim.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

/// A coverage signature (an assertion message up to its first `": "`), e.g.
/// `S/load-included`. A required signature that no `Sometimes` record
/// satisfies fails the run as `C/missing/<signature>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature(pub String);

impl From<&str> for Signature {
    fn from(s: &str) -> Self {
        Signature(s.into())
    }
}

/// Finite, nonnegative virtual seconds since a run's `start` hook.
/// Values must be below the `u64` seconds boundary.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct VirtSecs(f64);

impl VirtSecs {
    /// Rejects negative, nonfinite, or out-of-range seconds.
    pub fn new(seconds: f64) -> Result<Self, &'static str> {
        if seconds.is_finite() && seconds >= 0.0 && seconds < u64::MAX as f64 {
            Ok(Self(seconds))
        } else {
            Err("virtual seconds must be finite, nonnegative, and below u64::MAX")
        }
    }

    /// The validated virtual seconds.
    pub fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for VirtSecs {
    type Error = &'static str;

    fn try_from(seconds: f64) -> Result<Self, Self::Error> {
        Self::new(seconds)
    }
}

impl From<VirtSecs> for f64 {
    fn from(seconds: VirtSecs) -> Self {
        seconds.get()
    }
}

/// Forced preemption of one seed, drawn and applied by the driver
/// (`Branch::set_preempt`): period in guest instructions (0 = off) and the
/// jitter seed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preempt {
    pub period: u64,
    pub seed: u64,
}

/// The generic campaign fields a workload may need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignInfo {
    /// Virtual seconds each seed runs before `finalize`.
    pub run_secs: u64,
    /// Readiness threshold for `warmup` (e.g. a node's head block).
    pub warm_blocks: u64,
    /// Virtual seconds the driver allows for boot plus warmup.
    pub warm_timeout_secs: u64,
    /// The campaign's seeds: `[seed_start, seed_start + seeds)`.
    pub seed_start: u64,
    pub seeds: u64,
}

impl Default for CampaignInfo {
    fn default() -> Self {
        Self {
            run_secs: 180,
            warm_blocks: 10,
            warm_timeout_secs: 900,
            seed_start: 0,
            seeds: 1,
        }
    }
}

/// `parse-args`: the campaign's `--workload-config` file and
/// `--workload-arg KEY=VALUE` pairs (applied over the file, in order). The
/// workload answers with its typed `Args`, rejecting unknown keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgsRequest {
    pub config_file: Option<String>,
    pub args: Vec<String>,
}

/// `warmup`. The warm prefix is shared by every seed of a campaign and
/// rebuilt by every replay of one of them, so the request (which the guest
/// executes, as a command line) carries nothing that differs between them:
/// in particular not the seed range.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WarmupRequest<A> {
    pub warmup: WarmupInfo,
    pub args: A,
}

/// The campaign fields `warmup` may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmupInfo {
    pub run_secs: u64,
    pub warm_blocks: u64,
    pub warm_timeout_secs: u64,
}

/// `warmup`'s answer: the driver checkpoints once `ready`; `detail` is
/// logged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmupStatus {
    pub ready: bool,
    #[serde(default)]
    pub detail: String,
}

/// Keep the decisions a recorded run applied before `after`, re-draw the
/// rest from `seed` (`bedrock-dst branch --vary decisions|both`).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Redraw {
    pub after: VirtSecs,
    pub seed: u64,
}

/// `config`: plan seed `seed` of the campaign, or (with `decisions`) the
/// recorded decisions of a run, without deriving anything from the seed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanRequest<A, D> {
    pub campaign: CampaignInfo,
    pub args: A,
    pub seed: u64,
    /// The driver's preemption draw for `seed` (ignored with `decisions`:
    /// the recorded one stands).
    pub preempt: Preempt,
    /// Test hook (`BEDROCK_DST_DERIVATION_SALT`): perturbs the derivation,
    /// so seeds mean other runs (recorded decisions must not care).
    pub derivation_salt: Option<u64>,
    /// Recorded decisions (a scenario.json).
    pub decisions: Option<D>,
    /// With `decisions`: re-draw what was not applied by a moment.
    pub redraw: Option<Redraw>,
    /// Serve the run's randomness from this seed instead of the recorded
    /// one (a branch's fresh stream), recorded in the decisions.
    pub rng_seed: Option<u64>,
    /// With `decisions`: the same plan without these host decisions (ids of
    /// [`Plan::host_decisions`]), delivered from the start (minimization).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drop: Option<Vec<u32>>,
}

/// One droppable semantic decision of a plan (a nemesis kill, a fault
/// window, a load generation): what a minimizer may remove. Typed data, not
/// a command: the planner applies a drop by planning again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostDecision {
    /// Stable within the plan.
    pub id: u32,
    /// The workload's name for its kind, e.g. `kill`.
    pub kind: String,
    /// Virtual seconds after `start` it applies at.
    pub at_secs: VirtSecs,
    #[serde(default)]
    pub detail: String,
}

/// The generic parameters of a planned run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunParams<S> {
    pub seed: u64,
    /// Seed of Bedrock's RDRAND/getrandom stream for the branch.
    pub rng_seed: u64,
    pub run_secs: u64,
    pub preempt: Preempt,
    /// The swarm record (every feature that shapes the run), copied into
    /// verdict.json and summary.json so failures can be grouped by feature.
    pub swarm: S,
}

/// A workload hook and its optional single argument, passed as literal text.
/// The driver owns shell quoting; planners must not add shell syntax.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestAction {
    /// The hook name, for example `redecide`.
    pub hook: String,
    /// The exact argument to deliver to the hook.
    pub argument: Option<String>,
}

/// `config`'s answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plan<C, D, S> {
    /// The guest config: the argument of the `start` hook, and config.json.
    pub config: C,
    /// Every decision of the run, by value: scenario.json.
    pub decisions: D,
    pub run: RunParams<S>,
    /// Coverage the run must reach.
    pub required: Vec<Signature>,
    /// Delivering `decisions` again reproduces `config` byte for byte, so a
    /// scenario replay must reproduce the run.
    pub replays_exactly: bool,
    /// With `redraw`: the guest command (after the workload command) the
    /// driver issues at the moment.
    #[serde(default)]
    pub action: Option<GuestAction>,
    /// Log lines for the driver to print.
    #[serde(default)]
    pub notes: Vec<String>,
    /// The plan's droppable decisions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_decisions: Vec<HostDecision>,
}

/// `observe`: fold a finished run's events (`events_path`, the collected
/// events.jsonl) into its decisions; with `original`, compare the decisions
/// with the run a replay reproduces.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObserveRequest<D> {
    pub decisions: D,
    pub original: Option<D>,
    pub events_path: String,
}

/// A moment of a run worth branching from, at a guest time of its events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Moment {
    pub guest_time_ns: i64,
    pub what: String,
}

/// `observe`'s answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation<D> {
    /// The decisions with what the run reported (scenario.json).
    pub decisions: D,
    /// Where the run's decisions differ from `original`'s.
    pub decision_diff: Vec<String>,
    /// Moments worth branching from (`bedrock-dst moments`).
    pub moments: Vec<Moment>,
    /// Guest time of the run's first event, which the `start` hook emits:
    /// maps moments to virtual time.
    pub events_origin_ns: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtypes_are_transparent() {
        let s =
            serde_json::to_string(&(Signature::from("S/x"), VirtSecs::new(1.5).unwrap())).unwrap();
        assert_eq!(s, r#"["S/x",1.5]"#);
        let st: WarmupStatus = serde_json::from_str(r#"{"ready": true}"#).unwrap();
        assert!(st.ready && st.detail.is_empty());
        for invalid in [-1.0, f64::NAN, f64::INFINITY, u64::MAX as f64] {
            assert!(VirtSecs::new(invalid).is_err());
        }
        assert!(serde_json::from_str::<VirtSecs>("-1").is_err());
    }
}
