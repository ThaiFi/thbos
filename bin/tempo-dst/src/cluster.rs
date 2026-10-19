// SPDX-License-Identifier: GPL-2.0

//! The multi-validator cluster: its fixed topology, its
//! compose-time variants, and its fault plan.
//!
//! Commonware validators on a podman bridge, one IP each,
//! from a genesis generated at build time (contrib/bedrock-dst/validators):
//! validator `i` (1-based) is container `v<i>` at `10.89.77.(10+i)`, consensus
//! p2p on 8000, execution p2p on 8001, consensus metrics on 8002, RPC on
//! 8545. The IPs are part of the genesis, so they are constants here.
//!
//! The fault plan ([`ClusterFault`]) is always made by the planner on the
//! host and delivered in config.json: the guest only executes it
//! (`cluster_nemesis`). This module is plain data (no planner, guest or I/O
//! dependencies), shared by the planner, the scenario and the guest config.

use serde::{Deserialize, Serialize};

// Validators in the generated genesis.
include!(concat!(env!("OUT_DIR"), "/cluster_nodes.rs"));
/// Byzantine fault budget of the cluster: liveness is expected while at most
/// this many validators are faulted.
pub const FAULT_BUDGET: usize = ((VALIDATORS - 1) / 3) as usize;
/// Blocks per epoch in the generated genesis (`--epoch-length`, see
/// validators/build.sh). Epoch `e` starts at height `e * EPOCH_LENGTH`.
pub const EPOCH_LENGTH: u64 = 100;
/// Commonware consensus p2p port of every validator: network impairments
/// are scoped to it, so execution p2p (8001) and the oracles' RPC (8545)
/// are never faulted.
pub const CONSENSUS_PORT: u16 = 8000;

/// One validator, 1-based like its container name (`ValidatorId(2)` is `v2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct ValidatorId(u8);

impl ValidatorId {
    /// Every validator, in order.
    pub fn all() -> impl Iterator<Item = ValidatorId> {
        (1..=VALIDATORS).map(ValidatorId)
    }

    /// Validator `n` (1-based); `None` outside the cluster.
    pub fn new(n: u8) -> Option<ValidatorId> {
        (1..=VALIDATORS).contains(&n).then_some(ValidatorId(n))
    }

    /// Its position in `0..VALIDATORS`.
    pub fn index(self) -> usize {
        usize::from(self.0 - 1)
    }

    /// Its container name.
    pub fn container(self) -> &'static str {
        CONTAINERS[self.index()]
    }

    /// Its JSON-RPC endpoint.
    pub fn rpc_url(self) -> &'static str {
        RPC_URLS[self.index()]
    }

    /// Its consensus Prometheus endpoint.
    pub fn metrics_url(self) -> &'static str {
        METRICS_URLS[self.index()]
    }

    /// Its address on the cluster bridge (fixed by the genesis).
    pub fn ip(self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(10, 89, 77, 11 + self.0 - 1)
    }

    /// The validator whose container is `name`.
    pub fn of_container(name: &str) -> Option<ValidatorId> {
        ValidatorId::all().find(|v| v.container() == name)
    }
}

impl TryFrom<u8> for ValidatorId {
    type Error = String;
    fn try_from(n: u8) -> Result<Self, String> {
        ValidatorId::new(n).ok_or_else(|| format!("validator {n} not in 1..={VALIDATORS}"))
    }
}

impl From<ValidatorId> for u8 {
    fn from(v: ValidatorId) -> u8 {
        v.0
    }
}

impl std::fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.container())
    }
}

/// Commonware's per-peer connection cooldown
/// (`--consensus.connection-per-peer-min-period`), a compose-time variant.
/// It bounds how fast a restarted validator rejoins the mesh, so the
/// liveness budgets scale with it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cooldown {
    /// 1 s: a full mesh forms in 4-10 s.
    #[default]
    #[serde(rename = "1s")]
    Fast,
    /// Tempo's default (60 s): a full mesh takes 95-123 s.
    #[serde(rename = "default")]
    Default,
}

/// Consensus timeouts, a compose-time variant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Timeouts {
    /// Relaxed for Bedrock's instruction-count clock: 1 s target block time,
    /// 3 s wait for a proposal, 5 s for notarizations, one consensus worker
    /// thread; leader skip at Tempo's default.
    #[default]
    Tuned,
    /// Tempo's defaults.
    Prod,
}

/// A per-validator reth execution-engine profile: a set of `--engine.*`
/// (and, for [`EngineProfile::Simple`], cache/prewarm) flags that pick how
/// the validator computes block execution and state roots. Running different
/// profiles across the validators turns the consensus cluster into an N-way
/// deterministic execution differential: validators that finalize the same
/// block (same hash) must still compute the same state, so a divergence on a
/// state root or a proof between two engines is a finding
/// (`consensus::ExecDiffOracle`, the #16-class detector).
///
/// Every flag here exists in the Tempo build: `compose.yaml`'s validators run
/// `--engine.state-root-task-compare-updates` and the reference node runs the
/// `Simple` set; `--engine.state-root-task-timeout` and
/// `--engine.disable-sparse-trie-cache-pruning` are the reth-reorg `Race`/`NoPrune`
/// modes (`reth_plan::StateRoot`). Run.sh substitutes a validator's flags from
/// its profile (keep the python map in sync with [`EngineProfile::flags`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineProfile {
    /// The sparse-trie state-root task with the self-comparison against the
    /// sequential root — today's cluster default
    /// (`--engine.state-root-task-compare-updates`). Always assigned to the
    /// first validator when the differential is on, so it is a guaranteed
    /// member of the `{Optimized, Simple}` pair.
    Optimized,
    /// The simple sequential engine: the sequential state root with
    /// prewarming, the precompile cache, the in-memory state cache and state
    /// masking all off — the paths the old E7 dev-node reference used. Always
    /// assigned to the second validator when the differential is on.
    Simple,
    /// The self-comparing sparse-trie task run without the in-memory state
    /// cache, so its trie reads hit the persisted path (reth-reorg's `Compare`
    /// mode, under a stricter cache config).
    Compare,
    /// The sparse-trie task raced by the sequential fallback almost at once
    /// (`--engine.state-root-task-timeout 1ms`; reth-reorg's `Race` mode).
    Race,
    /// The sparse-trie task with cache pruning disabled
    /// (`--engine.disable-sparse-trie-cache-pruning`; reth-reorg's `NoPrune`
    /// mode).
    NoPrune,
}

impl EngineProfile {
    /// Every profile, in assignment index order (the order
    /// [`engine_profiles`] draws from).
    pub const ALL: [EngineProfile; 5] = [
        EngineProfile::Optimized,
        EngineProfile::Simple,
        EngineProfile::Compare,
        EngineProfile::Race,
        EngineProfile::NoPrune,
    ];

    /// The `--engine.*` (and cache/prewarm) flags this profile adds to a
    /// validator's `tempo node` command, in place of the default
    /// `--engine.state-root-task-compare-updates`. Keep in sync with run.sh's
    /// `engine_profile_flags` python map.
    pub fn flags(self) -> &'static [&'static str] {
        match self {
            EngineProfile::Optimized => &["--engine.state-root-task-compare-updates"],
            EngineProfile::Simple => &[
                "--engine.state-root-fallback",
                "--engine.disable-prewarming",
                "--engine.disable-precompile-cache",
                "--engine.disable-state-cache",
                "--engine.num-state-masking-blocks",
                "0",
            ],
            EngineProfile::Compare => &[
                "--engine.state-root-task-compare-updates",
                "--engine.disable-state-cache",
            ],
            EngineProfile::Race => &["--engine.state-root-task-timeout", "1ms"],
            EngineProfile::NoPrune => &["--engine.disable-sparse-trie-cache-pruning"],
        }
    }
}

/// Assigns an [`EngineProfile`] to each of `count` validators (index order,
/// `out[i]` is validator `v<i+1>`), drawing from `draw` (a host PRNG of the
/// campaign seed; `draw(n)` is uniform in `0..n`). A pure function of the
/// draw, so the planner and run.sh produce the same assignment and a replay
/// is byte-identical.
///
/// The first validator is always [`EngineProfile::Optimized`] and the second
/// always [`EngineProfile::Simple`], so the sparse-trie-vs-simple divergence
/// is always exercised (the `{Optimized, Simple}` guarantee); the rest are
/// drawn from [`EngineProfile::ALL`]. `draw` is called only for validators
/// past the first two.
pub fn engine_profiles(count: u8, mut draw: impl FnMut(u64) -> u64) -> Vec<EngineProfile> {
    (0..count)
        .map(|i| match i {
            0 => EngineProfile::Optimized,
            1 => EngineProfile::Simple,
            _ => EngineProfile::ALL[draw(EngineProfile::ALL.len() as u64) as usize],
        })
        .collect()
}

/// Seconds of virtual time the liveness oracles allow, given the cooldown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessBudget {
    /// E16/mesh-timeout: a full mesh forms within this after the last
    /// restart (or the branch start).
    pub mesh_secs: u64,
    /// E16/stalled: the cluster's finalized height advances within this
    /// while at most [`FAULT_BUDGET`] validators are down.
    pub stall_secs: u64,
    /// E16/node-stuck: an up validator reaches the cluster's finalized
    /// height within this; E15/reopen-failed: a restarted validator answers
    /// RPC within it.
    pub catch_up_secs: u64,
}

impl Cooldown {
    /// The liveness budget for this cooldown.
    pub fn budget(self) -> LivenessBudget {
        match self {
            Cooldown::Fast => LivenessBudget {
                mesh_secs: 60,
                stall_secs: 60,
                catch_up_secs: 90,
            },
            Cooldown::Default => LivenessBudget {
                mesh_secs: 200,
                stall_secs: 180,
                catch_up_secs: 200,
            },
        }
    }
}

/// The family of faults a seed's plan draws from (a swarm feature).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultFamily {
    /// One validator at a time, down up to 3 s.
    Single,
    /// One validator at a time, back in under a second.
    Quick,
    /// Two or three validators together; small clusters may stall until they
    /// are back.
    Simultaneous,
    /// Every validator in turn, each restarted before the next goes down.
    Rolling,
    /// The whole cluster at once (SIGKILL of every node; with a storage
    /// layer, each fault is a process or a machine crash).
    WholeCluster,
    /// Every validator's machine crashes at once: a whole-cluster power
    /// loss (needs a storage layer).
    PowerLoss,
    /// One validator restarted in under a second while another's consensus
    /// traffic to it is delayed 0.5-5 s (a restarted node backfilling from a
    /// slow peer; needs `network_faults`).
    DelayedPeer,
    /// The validators split on the consensus port across an
    /// epoch boundary (the DKG reshare), one of them crashed while
    /// partitioned, then healed (needs `network_faults`).
    PartitionHeal,
}

impl FaultFamily {
    /// The families a per-seed draw picks from, in index order; with a
    /// storage layer, power loss too; with network faults, the network
    /// families after those (so seeds without them draw as before).
    pub fn drawable(storage: Option<StorageLayer>, network: bool) -> Vec<FaultFamily> {
        let mut out = vec![FaultFamily::Single, FaultFamily::Quick];
        if VALIDATORS > 1 {
            out.push(FaultFamily::Simultaneous);
        }
        out.extend([FaultFamily::Rolling, FaultFamily::WholeCluster]);
        if storage.is_some() {
            out.push(FaultFamily::PowerLoss);
        }
        if network {
            out.extend([FaultFamily::DelayedPeer, FaultFamily::PartitionHeal]);
        }
        out
    }

    /// Whether the family's faults carry a network impairment.
    pub fn is_network(self) -> bool {
        matches!(self, FaultFamily::DelayedPeer | FaultFamily::PartitionHeal)
    }
}

/// The layer under each validator's datadir that can lose un-synced writes
/// in a machine crash (`storage=`; see `node_storage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageLayer {
    /// LazyFS, one instance per validator.
    Lazyfs,
}

/// Which un-synced writes a machine crash discards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum Discard {
    /// Every un-synced write is lost.
    All,
    /// Each un-synced block (and each file's un-synced size) survives with
    /// probability `keep_permille / 1000`.
    Subset { seed: u64, keep_permille: u32 },
}

/// What a fault does to each target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Crash {
    /// SIGKILL the node: its data volume and the page cache survive.
    #[default]
    Process,
    /// SIGKILL the node, then crash its storage: un-synced writes are
    /// discarded per `discard` (needs a storage layer).
    Machine { discard: Discard },
}

/// When a planned fault fires, after its `not_before_secs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "on", rename_all = "kebab-case")]
pub enum FaultTrigger {
    /// At once.
    Now,
    /// When the cluster's finalized height next grows by at least `min_jump`
    /// between two polls (100 ms apart): 1 lands the fault while a
    /// finalization is being processed, 2+ during a catch-up burst.
    Finalization { min_jump: u64 },
    /// When the cluster's finalized height reaches the next epoch boundary
    /// (a multiple of [`EPOCH_LENGTH`]) plus `offset` blocks.
    EpochBoundary { offset: i64 },
}

impl FaultTrigger {
    /// Whether the trigger fires at a poll that saw the cluster's finalized
    /// height go from `prev` to `cur`, `start` being the height when the
    /// trigger began to be watched.
    pub fn fired(self, start: u64, prev: u64, cur: u64) -> bool {
        match self {
            FaultTrigger::Now => true,
            FaultTrigger::Finalization { min_jump } => cur >= prev + min_jump,
            FaultTrigger::EpochBoundary { offset } => {
                let boundary = (start / EPOCH_LENGTH + 1) * EPOCH_LENGTH;
                cur as i64 >= boundary as i64 + offset
            }
        }
    }
}

/// How the targets of a fault go down and come back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum RestartOrder {
    /// All targets killed together, restarted together `down_ms` later.
    Together,
    /// One target at a time: killed, restarted `down_ms` later, then
    /// `gap_ms` before the next.
    Rolling { gap_ms: u64 },
}

/// A cluster seed's swarm features (recorded in the swarm record).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterSwarm {
    pub cooldown: Cooldown,
    /// The fault family of the seed's plan (`None`: no faults).
    pub faults: Option<FaultFamily>,
    pub timeouts: Timeouts,
    /// The per-validator engine-profile differential is on (the validators
    /// run different [`EngineProfile`]s; the assignment is in
    /// [`ClusterConfig::engine_profiles`]). Omitted when off, so existing
    /// swarm records are unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub engine_diff: bool,
}

/// A network impairment of the consensus traffic ([`CONSENSUS_PORT`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Impairment {
    /// What `from` sends `to` is delayed by `latency_ms`, plus up to
    /// `jitter_ms` (netem on `from`'s egress).
    Delay {
        from: ValidatorId,
        to: ValidatorId,
        latency_ms: u32,
        jitter_ms: u32,
    },
    /// No consensus traffic crosses between the sides (blocked in both
    /// directions on every node, so it holds while one side's node
    /// restarts).
    Partition { sides: Vec<Vec<ValidatorId>> },
}

impl Impairment {
    /// The validators it counts against the fault budget: the delayed
    /// sender, or a partition's first side (the minority, or one half).
    pub fn impaired(&self) -> Vec<ValidatorId> {
        match self {
            Impairment::Delay { from, .. } => vec![*from],
            Impairment::Partition { sides } => sides.first().cloned().unwrap_or_default(),
        }
    }
}

/// A network impairment held around a fault: applied `lead_ms` before its
/// targets go down, kept `hold_ms` after they are back, then healed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Impair {
    pub impairment: Impairment,
    pub lead_ms: u64,
    pub hold_ms: u64,
}

/// One entry of a cluster fault plan: crash `targets` (`crash`) and restart
/// them. Entries run in order; each starts a new load generation once its
/// targets are back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterFault {
    /// Seconds after nemesis start before the trigger is watched.
    pub not_before_secs: u64,
    pub trigger: FaultTrigger,
    /// Seconds after `not_before_secs` at which the fault fires anyway when
    /// its trigger never came (e.g. a stalled cluster).
    pub deadline_secs: u64,
    pub targets: Vec<ValidatorId>,
    pub order: RestartOrder,
    #[serde(default)]
    pub crash: Crash,
    /// Milliseconds each target stays down.
    pub down_ms: u64,
    /// A network impairment around the crash (network families only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impair: Option<Impair>,
}

impl ClusterFault {
    /// Upper bound on the virtual seconds from the trigger to the last
    /// target's restart (podman's own time excluded).
    pub fn duration_secs(&self) -> u64 {
        let n = self.targets.len() as u64;
        let ms = match self.order {
            RestartOrder::Together => self.down_ms,
            RestartOrder::Rolling { gap_ms } => n * self.down_ms + n.saturating_sub(1) * gap_ms,
        };
        let held = self.impair.as_ref().map_or(0, |i| i.lead_ms + i.hold_ms);
        (ms + held).div_ceil(1000)
    }
}

/// `/bedrock/in/config.json` `cluster`: the multi-validator run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub cooldown: Cooldown,
    pub timeouts: Timeouts,
    /// The fault plan (empty: no faults).
    pub faults: Vec<ClusterFault>,
    /// The storage layer under each datadir (machine crashes), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageLayer>,
    /// The engine profile each validator runs (index order; `engine_profiles[i]`
    /// is `v<i+1>`), when the per-validator engine differential is on. Empty
    /// (omitted) when off: every validator then keeps today's default flags,
    /// so existing configs are byte-identical. Drawn by the planner
    /// ([`engine_profiles`]) and replicated by run.sh for the compose file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engine_profiles: Vec<EngineProfile>,
    /// The validator load generation 0 sends to; generation `g` sends to
    /// the `g`-th validator after it, so each restart moves the load (and
    /// the load's oracles, E5/E6/E8/E9) to another node.
    pub first_load_target: ValidatorId,
}

impl ClusterConfig {
    /// The validator load generation `generation` sends to.
    pub fn load_target(&self, generation: u64) -> ValidatorId {
        let n = u64::from(VALIDATORS);
        let i = (self.first_load_target.index() as u64 + generation % n) % n;
        ValidatorId(i as u8 + 1)
    }

    /// Whether the per-validator engine differential is on.
    pub fn engine_diff(&self) -> bool {
        !self.engine_profiles.is_empty()
    }

    /// Rejects a plan whose targets repeat within one fault or that is
    /// empty-targeted, or a machine crash without a storage layer.
    pub fn validate(&self) -> Result<(), String> {
        if self.engine_diff() && self.engine_profiles.len() != usize::from(VALIDATORS) {
            return Err(format!(
                "engine_profiles has {} entries, expected one per validator ({VALIDATORS})",
                self.engine_profiles.len()
            ));
        }
        for (i, f) in self.faults.iter().enumerate() {
            if matches!(f.crash, Crash::Machine { .. }) && self.storage.is_none() {
                return Err(format!(
                    "cluster fault {i}: a machine crash needs a storage layer"
                ));
            }
            let mut seen = std::collections::BTreeSet::new();
            if f.targets.is_empty() || !f.targets.iter().all(|t| seen.insert(*t)) {
                return Err(format!("cluster fault {i}: targets {:?}", f.targets));
            }
            match f.impair.as_ref().map(|x| &x.impairment) {
                Some(Impairment::Delay { from, to, .. }) if from == to => {
                    return Err(format!("cluster fault {i}: {from} delays itself"));
                }
                Some(Impairment::Partition { sides }) => {
                    let mut seen = std::collections::BTreeSet::new();
                    if sides.len() < 2
                        || sides.iter().any(Vec::is_empty)
                        || !sides.iter().flatten().all(|v| seen.insert(*v))
                    {
                        return Err(format!("cluster fault {i}: partition {sides:?}"));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Bounds of a drawn plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanBounds {
    pub run_secs: u64,
    pub max_faults: u32,
    /// Seconds between one fault's last restart and the next fault's
    /// `not_before_secs` (and before the end of the run): recovery time.
    pub min_gap_secs: u64,
    pub storage: Option<StorageLayer>,
}

/// Seconds after nemesis start before the first fault may land.
pub const FIRST_FAULT_SECS: u64 = 10;

/// Draws a fault plan of `family` within `bounds`; `draw(lo, hi)` returns a
/// uniform value in `lo..=hi` (a host PRNG of the seed).
pub fn plan(
    family: FaultFamily,
    bounds: PlanBounds,
    mut draw: impl FnMut(u64, u64) -> u64,
) -> Vec<ClusterFault> {
    let mut faults = Vec::new();
    let gap = bounds.min_gap_secs.max(1);
    let mut t = FIRST_FAULT_SECS;
    for _ in 0..bounds.max_faults {
        let not_before_secs = t + draw(0, gap / 2);
        let (trigger, deadline_secs) = match draw(0, 3) {
            0 => (FaultTrigger::Now, 0),
            1 => (FaultTrigger::Finalization { min_jump: 1 }, 20),
            2 => (FaultTrigger::Finalization { min_jump: 2 }, 30),
            _ => (
                FaultTrigger::EpochBoundary {
                    offset: draw(0, 4) as i64 - 2,
                },
                // An epoch is ~EPOCH_LENGTH blocks at ~1 block/s.
                EPOCH_LENGTH + 30,
            ),
        };
        let mut validators: Vec<ValidatorId> = ValidatorId::all().collect();
        // Fisher-Yates over the draw.
        for i in (1..validators.len()).rev() {
            validators.swap(i, draw(0, i as u64) as usize);
        }
        let (targets, order, down_ms) = match family {
            FaultFamily::Single => (1, RestartOrder::Together, draw(0, 3000)),
            FaultFamily::Quick => (1, RestartOrder::Together, draw(0, 900)),
            FaultFamily::Simultaneous => (
                draw(2, u64::from(VALIDATORS.min(3))) as usize,
                RestartOrder::Together,
                draw(0, 3000),
            ),
            FaultFamily::Rolling => (
                validators.len(),
                RestartOrder::Rolling {
                    gap_ms: draw(0, 20_000),
                },
                draw(0, 3000),
            ),
            FaultFamily::WholeCluster | FaultFamily::PowerLoss => {
                (validators.len(), RestartOrder::Together, draw(0, 5000))
            }
            FaultFamily::DelayedPeer => (1, RestartOrder::Together, draw(0, 900)),
            FaultFamily::PartitionHeal => (1, RestartOrder::Together, draw(0, 3000)),
        };
        // Drawn from the shuffle before it is cut to the targets (the
        // network families only, so other plans draw as before).
        let impair = match family {
            FaultFamily::DelayedPeer => Some(Impair {
                impairment: Impairment::Delay {
                    from: validators[1],
                    to: validators[0],
                    latency_ms: draw(500, 5000) as u32,
                    jitter_ms: draw(0, 500) as u32,
                },
                lead_ms: draw(1000, 5000),
                hold_ms: draw(10_000, 30_000),
            }),
            FaultFamily::PartitionHeal => {
                let k = draw(1, u64::from(VALIDATORS / 2)) as usize;
                Some(Impair {
                    impairment: Impairment::Partition {
                        sides: vec![validators[..k].to_vec(), validators[k..].to_vec()],
                    },
                    lead_ms: draw(5000, 15_000),
                    hold_ms: draw(15_000, 45_000),
                })
            }
            _ => None,
        };
        // A partition straddles the next epoch boundary (the DKG reshare).
        let (trigger, deadline_secs) = match family {
            FaultFamily::PartitionHeal => (
                FaultTrigger::EpochBoundary {
                    offset: -(draw(1, 5) as i64),
                },
                EPOCH_LENGTH + 30,
            ),
            _ => (trigger, deadline_secs),
        };
        validators.truncate(targets);
        let machine = |draw: &mut dyn FnMut(u64, u64) -> u64| Crash::Machine {
            discard: match draw(0, 1) {
                0 => Discard::All,
                _ => Discard::Subset {
                    seed: draw(0, u64::from(u32::MAX)),
                    keep_permille: draw(0, 1000) as u32,
                },
            },
        };
        let crash = match (family, bounds.storage) {
            (FaultFamily::PowerLoss, _) => machine(&mut draw),
            (_, Some(_)) if draw(0, 1) == 1 => machine(&mut draw),
            _ => Crash::Process,
        };
        let fault = ClusterFault {
            not_before_secs,
            trigger,
            deadline_secs,
            targets: validators,
            order,
            crash,
            down_ms,
            impair,
        };
        let end = not_before_secs + deadline_secs + fault.duration_secs();
        if end + gap > bounds.run_secs {
            break;
        }
        t = end + gap;
        faults.push(fault);
    }
    faults
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg(mut x: u64) -> impl FnMut(u64, u64) -> u64 {
        move |lo, hi| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            lo + (x >> 11) % (hi - lo + 1)
        }
    }

    #[test]
    fn validator_ids_map_to_the_genesis_topology() {
        let v: Vec<_> = ValidatorId::all().collect();
        assert_eq!(v.len(), 4);
        assert_eq!(v[2].container(), "v3");
        assert_eq!(v[2].rpc_url(), "http://10.89.77.13:8545");
        assert_eq!(v[3].metrics_url(), "http://10.89.77.14:8002/metrics");
        assert_eq!(ValidatorId::of_container("v2"), ValidatorId::new(2));
        assert_eq!(ValidatorId::of_container("tempo"), None);
        assert!(ValidatorId::new(0).is_none() && ValidatorId::new(5).is_none());
        assert_eq!(serde_json::to_string(&v[0]).unwrap(), "1");
        assert!(serde_json::from_str::<ValidatorId>("9").is_err());
    }

    #[test]
    fn variants_parse_by_their_argument_names() {
        assert_eq!(
            serde_json::from_str::<Cooldown>(r#""1s""#).unwrap(),
            Cooldown::Fast
        );
        assert_eq!(
            serde_json::from_str::<Cooldown>(r#""default""#).unwrap(),
            Cooldown::Default
        );
        assert_eq!(
            serde_json::from_str::<Timeouts>(r#""prod""#).unwrap(),
            Timeouts::Prod
        );
        assert!(Cooldown::Default.budget().mesh_secs > 123);
    }

    #[test]
    fn load_rotates_over_every_validator() {
        let c = ClusterConfig {
            cooldown: Cooldown::Fast,
            timeouts: Timeouts::Tuned,
            storage: None,
            faults: vec![],
            engine_profiles: Vec::new(),
            first_load_target: ValidatorId::new(3).unwrap(),
        };
        let t: Vec<u8> = (0..5).map(|g| c.load_target(g).into()).collect();
        assert_eq!(t, [3, 4, 1, 2, 3]);
    }

    #[test]
    fn plans_fit_the_run_and_respect_the_gap() {
        for family in FaultFamily::drawable(Some(StorageLayer::Lazyfs), true) {
            for seed in 0..64 {
                let b = PlanBounds {
                    run_secs: 300,
                    max_faults: 3,
                    min_gap_secs: 40,
                    storage: (family == FaultFamily::PowerLoss).then_some(StorageLayer::Lazyfs),
                };
                let p = plan(family, b, lcg(seed));
                let mut free = 0;
                for f in &p {
                    assert!(f.not_before_secs >= free.max(FIRST_FAULT_SECS), "{p:?}");
                    let end = f.not_before_secs + f.deadline_secs + f.duration_secs();
                    assert!(end + 40 <= 300, "{p:?}");
                    free = end + 40;
                    let n = f.targets.len();
                    match family {
                        FaultFamily::Single
                        | FaultFamily::Quick
                        | FaultFamily::DelayedPeer
                        | FaultFamily::PartitionHeal => assert_eq!(n, 1),
                        FaultFamily::Simultaneous => assert!((2..=3).contains(&n)),
                        _ => assert_eq!(n, 4),
                    }
                    if matches!(family, FaultFamily::Quick | FaultFamily::DelayedPeer) {
                        assert!(f.down_ms < 1000);
                    }
                    assert_eq!(f.impair.is_some(), family.is_network(), "{p:?}");
                    match f.impair.as_ref().map(|i| &i.impairment) {
                        Some(Impairment::Delay {
                            from,
                            to,
                            latency_ms,
                            ..
                        }) => {
                            assert_eq!(*to, f.targets[0]);
                            assert_ne!(from, to);
                            assert!((500..=5000).contains(latency_ms));
                        }
                        Some(Impairment::Partition { sides }) => {
                            assert!(
                                sides[0].contains(&f.targets[0]),
                                "crash inside the partition"
                            );
                            assert!((1..=2).contains(&sides[0].len()));
                            assert_eq!(sides[0].len() + sides[1].len(), 4);
                            assert!(
                                matches!(f.trigger, FaultTrigger::EpochBoundary { offset } if offset < 0)
                            );
                        }
                        None => {}
                    }
                    if family == FaultFamily::PowerLoss {
                        assert!(matches!(f.crash, Crash::Machine { .. }));
                    }
                }
                let c = ClusterConfig {
                    cooldown: Cooldown::Fast,
                    timeouts: Timeouts::Tuned,
                    storage: Some(StorageLayer::Lazyfs),
                    faults: p,
                    engine_profiles: Vec::new(),
                    first_load_target: ValidatorId::new(1).unwrap(),
                };
                c.validate().unwrap();
            }
            // Some seed of every family gets a fault.
            assert!((0..64).any(|s| !plan(
                family,
                PlanBounds {
                    run_secs: 300,
                    max_faults: 3,
                    min_gap_secs: 40,
                    storage: Some(StorageLayer::Lazyfs),
                },
                lcg(s)
            )
            .is_empty()));
        }
    }

    #[test]
    fn network_families_only_extend_the_draw() {
        // Without network faults the drawable families (and so every seed's
        // draw) are unchanged; with them, the network families come last.
        assert_eq!(FaultFamily::drawable(None, false).len(), 5);
        assert_eq!(
            FaultFamily::drawable(Some(StorageLayer::Lazyfs), false).len(),
            6
        );
        let with = FaultFamily::drawable(None, true);
        assert_eq!(&with[..5], &FaultFamily::drawable(None, false)[..]);
        assert_eq!(
            &with[5..],
            &[FaultFamily::DelayedPeer, FaultFamily::PartitionHeal]
        );
        // An impairment is serialized only when present.
        let p = plan(
            FaultFamily::Single,
            PlanBounds {
                run_secs: 300,
                max_faults: 1,
                min_gap_secs: 40,
                storage: None,
            },
            lcg(1),
        );
        assert!(!serde_json::to_string(&p).unwrap().contains("impair"));
    }

    #[test]
    fn impairments_are_validated() {
        let v = |n| ValidatorId::new(n).unwrap();
        let fault = |impairment| ClusterFault {
            not_before_secs: 0,
            trigger: FaultTrigger::Now,
            deadline_secs: 0,
            targets: vec![v(1)],
            order: RestartOrder::Together,
            crash: Crash::Process,
            down_ms: 0,
            impair: Some(Impair {
                impairment,
                lead_ms: 1000,
                hold_ms: 2000,
            }),
        };
        let cfg = |f| ClusterConfig {
            cooldown: Cooldown::Fast,
            timeouts: Timeouts::Tuned,
            storage: None,
            faults: vec![f],
            engine_profiles: Vec::new(),
            first_load_target: v(1),
        };
        let delay = |from, to| Impairment::Delay {
            from: v(from),
            to: v(to),
            latency_ms: 500,
            jitter_ms: 0,
        };
        assert!(cfg(fault(delay(2, 1))).validate().is_ok());
        assert!(cfg(fault(delay(1, 1))).validate().is_err());
        let part = |sides: Vec<Vec<u8>>| Impairment::Partition {
            sides: sides
                .into_iter()
                .map(|s| s.into_iter().map(v).collect())
                .collect(),
        };
        assert!(cfg(fault(part(vec![vec![1], vec![2, 3, 4]])))
            .validate()
            .is_ok());
        assert!(cfg(fault(part(vec![vec![1, 2], vec![2, 3]])))
            .validate()
            .is_err());
        assert!(cfg(fault(part(vec![vec![1, 2, 3, 4]]))).validate().is_err());
        assert_eq!(
            part(vec![vec![1, 2], vec![3, 4]]).impaired(),
            vec![v(1), v(2)]
        );
        assert_eq!(delay(3, 1).impaired(), vec![v(3)]);
        // Lead and hold count toward the fault's duration.
        assert_eq!(fault(delay(2, 1)).duration_secs(), 3);
    }

    #[test]
    fn duration_and_serialization() {
        let f = |targets: &[u8], order| ClusterFault {
            not_before_secs: 0,
            trigger: FaultTrigger::Now,
            deadline_secs: 0,
            targets: targets
                .iter()
                .map(|t| ValidatorId::new(*t).unwrap())
                .collect(),
            order,
            crash: Crash::Process,
            down_ms: 1500,
            impair: None,
        };
        let rolling = f(&[1, 2, 3, 4], RestartOrder::Rolling { gap_ms: 1000 });
        assert_eq!(rolling.duration_secs(), 9);
        let json = serde_json::to_string(&rolling).unwrap();
        assert!(
            json.contains(r#""order":{"mode":"rolling","gap_ms":1000}"#),
            "{json}"
        );
        assert_eq!(
            serde_json::from_str::<ClusterFault>(&json).unwrap(),
            rolling
        );
        let bad = ClusterConfig {
            cooldown: Cooldown::Fast,
            timeouts: Timeouts::Tuned,
            storage: None,
            faults: vec![f(&[1, 1], RestartOrder::Together)],
            engine_profiles: Vec::new(),
            first_load_target: ValidatorId::new(1).unwrap(),
        };
        assert!(bad.validate().is_err());
        let mut machine = f(&[2], RestartOrder::Together);
        machine.crash = Crash::Machine {
            discard: Discard::Subset {
                seed: 7,
                keep_permille: 500,
            },
        };
        let json = serde_json::to_string(&machine).unwrap();
        assert!(
            json.contains(r#""crash":{"kind":"machine","discard":{"mode":"subset","seed":7,"keep_permille":500}}"#),
            "{json}"
        );
        let no_layer = ClusterConfig {
            faults: vec![machine],
            ..bad
        };
        assert!(no_layer.validate().is_err());
    }

    /// A splitmix64-seeded draw matching the planner's and run.sh's.
    fn engine_draw(seed: u64) -> impl FnMut(u64) -> u64 {
        fn splitmix64(mut x: u64) -> u64 {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            x ^ (x >> 31)
        }
        let mut state = splitmix64(seed ^ 0x656e_6769_6e65_6431); // ENGINE_SALT
        move |n| {
            state = splitmix64(state);
            state % n
        }
    }

    #[test]
    fn engine_profiles_are_deterministic_and_guarantee_optimized_and_simple() {
        for count in 2..=20u8 {
            for seed in 0..32u64 {
                let a = engine_profiles(count, engine_draw(seed));
                // A pure function of the seed: a replay is byte-identical.
                let b = engine_profiles(count, engine_draw(seed));
                assert_eq!(a, b, "count {count} seed {seed}");
                assert_eq!(a.len(), usize::from(count));
                // The {Optimized, Simple} pair is always present, at v1/v2.
                assert_eq!(a[0], EngineProfile::Optimized);
                assert_eq!(a[1], EngineProfile::Simple);
                assert!(a.contains(&EngineProfile::Optimized));
                assert!(a.contains(&EngineProfile::Simple));
                // Every assigned profile is one of the known ones.
                assert!(a.iter().all(|p| EngineProfile::ALL.contains(p)));
            }
        }
        // Different seeds vary the tail assignment (count 4, so v3/v4 drawn).
        let seeds: std::collections::BTreeSet<_> = (0..64u64)
            .map(|s| engine_profiles(4, engine_draw(s)))
            .collect();
        assert!(seeds.len() > 1, "the draw should vary across seeds");
    }

    #[test]
    fn engine_profile_flags_are_real_and_distinct() {
        // Every profile contributes at least one flag, and no two profiles map
        // to the same flag set (so distinct labels mean distinct engines).
        let mut seen = std::collections::BTreeSet::new();
        for p in EngineProfile::ALL {
            let f = p.flags();
            assert!(!f.is_empty(), "{p:?} has no flags");
            assert!(f
                .iter()
                .all(|a| a.starts_with("--engine.") || !a.starts_with("--")));
            assert!(
                seen.insert(f.to_vec()),
                "{p:?} flags duplicate another profile"
            );
        }
        // Optimized is exactly today's default (so the off path is unchanged).
        assert_eq!(
            EngineProfile::Optimized.flags(),
            ["--engine.state-root-task-compare-updates"]
        );
    }

    #[test]
    fn engine_profiles_validate_against_the_validator_count() {
        let mut cfg = ClusterConfig {
            cooldown: Cooldown::Fast,
            timeouts: Timeouts::Tuned,
            storage: None,
            faults: vec![],
            engine_profiles: Vec::new(),
            first_load_target: ValidatorId::new(1).unwrap(),
        };
        // Off: valid, engine_diff() false, serialized without engine_profiles.
        assert!(cfg.validate().is_ok() && !cfg.engine_diff());
        assert!(!serde_json::to_string(&cfg)
            .unwrap()
            .contains("engine_profiles"));
        // On: one per validator.
        cfg.engine_profiles = engine_profiles(VALIDATORS, engine_draw(1));
        assert!(cfg.validate().is_ok() && cfg.engine_diff());
        // A wrong length is rejected.
        cfg.engine_profiles.pop();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn triggers_fire_on_finalization_and_epoch_boundaries() {
        let fin = |min_jump| FaultTrigger::Finalization { min_jump };
        assert!(!fin(1).fired(10, 10, 10));
        assert!(fin(1).fired(10, 10, 11));
        assert!(!fin(2).fired(10, 10, 11) && fin(2).fired(10, 11, 13));
        let epoch = |offset| FaultTrigger::EpochBoundary { offset };
        // Watched from height 130: the boundary is 200.
        assert!(!epoch(0).fired(130, 198, 199) && epoch(0).fired(130, 199, 200));
        assert!(epoch(-2).fired(130, 197, 198) && !epoch(2).fired(130, 200, 201));
        // From exactly a boundary, the next one.
        assert!(!epoch(0).fired(200, 200, 201));
        assert!(FaultTrigger::Now.fired(0, 0, 0));
    }
}
