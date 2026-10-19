// SPDX-License-Identifier: GPL-2.0

//! The workload planner: the host side of the bedrock-dst workload contract
//! (`bedrock-dst-contract`), for the Tempo workload.
//!
//! `bedrock-dst` runs this binary on the host as `--workload-planner` (never
//! in the guest, so planning cannot perturb guest time):
//!
//! ```text
//! tempo-dst parse-args -  # ArgsRequest            -> TempoArgs
//! tempo-dst config -      # PlanRequest            -> Plan<Config, scenario, Swarm>
//! tempo-dst observe -     # ObserveRequest         -> Observation<scenario>
//! ```
//!
//! (requests on stdin, one JSON answer on stdout). All are pure functions of
//! their input: the same campaign, arguments, seed and derivation salt give
//! byte-identical output. Everything Tempo-specific about a campaign lives
//! here: the load kinds, their images, contracts and rates, the nemesis kill
//! plan, the per-generation load seeds, the guest config, the decisions a
//! branch re-draws, and the coverage a seed must reach. See
//! contrib/bedrock-dst/README.md ("Workload contract").

use std::collections::BTreeMap;

use bedrock_dst_contract::{
    ArgsRequest, CampaignInfo, GuestAction, HostDecision, Moment, Observation, ObserveRequest,
    Plan, PlanRequest, Preempt, RunParams, Signature, VirtSecs,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::{
    campaign::{Load, Swarm, TrieContracts, TrieShape},
    cluster::{
        self, ClusterConfig, ClusterSwarm, Cooldown, FaultFamily, PlanBounds, StorageLayer,
        Timeouts, ValidatorId,
    },
    common::{CobConfig, Config, LoadConfig, NemesisConfig, TrieConfig, DEFAULT_STOP_TIMEOUT_SECS},
    nemesis::{self, MAX_DOWN_SECS, MAX_TORN_WINDOW_SECS, WARMUP_SECS},
    netfault::{self, NetTopology, NetworkConfig},
    scenario::{
        self, Decisions, Generation, LoadScenario, NemesisScenario, NetworkScenario, Observed,
        Scenario, ScheduledFault,
    },
};

/// Salt of the planner-made nemesis plan (`decisions=explicit`).
const NEMESIS_SALT: u64 = 0x6e65_6d65_7369_7331; // "nemesis1"
/// Salt of a branch's re-drawn decisions.
const BRANCH_DECISION_SALT: u64 = 0x6272_616e_6368_6431; // "branchd1"
/// Salt of the planner-made network fault plan (`decisions=explicit`).
const NETWORK_SALT: u64 = 0x6e65_7477_6f72_6b31; // "network1"
/// Salt of a branch's re-drawn network faults.
const BRANCH_NETWORK_SALT: u64 = 0x6272_616e_6368_6e31; // "branchn1"
/// Salt of a cluster seed's fault family, plan and first load target.
const CLUSTER_SALT: u64 = 0x636c_7573_7465_7231; // "cluster1"
/// Salt of the per-validator engine-profile assignment. Keep in sync with
/// run.sh's `ENGINE_SALT` python constant.
const ENGINE_SALT: u64 = 0x656e_6769_6e65_6431; // "engined1"
/// Salt of the certified follower's offline-window fault plan.
const FOLLOWER_SALT: u64 = 0x666f_6c6c_6f77_6572; // "follower"

/// Trie load image (contrib/bedrock-dst/trie).
pub const TRIE_IMAGE: &str = "bedrock/tempo-dst-trie:latest";
/// RawStorage deployed by trie/deploy.yaml during warmup: dev account 0's
/// first transaction on a fresh chain (CREATE address of nonce 0).
pub const TRIE_CONTRACT: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
/// TIP-20 load image (contrib/bedrock-dst/tip20); its token is created and
/// minted during warmup.
pub const TIP20_IMAGE: &str = "bedrock/tempo-dst-tip20:latest";
/// Chain-of-blocks load image (contrib/bedrock-dst/chain).
pub const CHAIN_IMAGE: &str = "bedrock/tempo-dst-chain:latest";
/// ChainOfBlocks deployed by chain/deploy.yaml during warmup: dev account 9's
/// first transaction.
pub const CHAIN_CONTRACT: &str = "0x700b6a60ce7eaaea56f065753d8dcb9653dbad35";
/// Generic state-mutation load image (contrib/bedrock-dst/statemix).
pub const STATEMIX_IMAGE: &str = "bedrock/tempo-dst-statemix:latest";
/// Mutator deployed by statemix/deploy.yaml during warmup: dev account 0's
/// first transaction on a fresh chain (the slot-0 CREATE address).
pub const STATEMIX_CONTRACT: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
/// Zones load image (contrib/bedrock-dst/zones): zone sequencer, prover and
/// driver. The zone itself is provisioned during warmup (`warmup.rs`).
pub const ZONES_IMAGE: &str = crate::zones::IMAGE;
/// Containers the zones load's nemesis kills rotate over.
pub const ZONES_KILL_TARGETS: [&str; 3] = [
    crate::common::NODE_CONTAINER,
    crate::zones::ZONE_CONTAINER,
    crate::zones::PROVER_CONTAINER,
];
/// ... and with the multi-sequencer zone.
pub const CLUSTER_KILL_TARGETS: [&str; 5] = [
    crate::common::NODE_CONTAINER,
    "zone-0",
    "zone-1",
    "zone-2",
    crate::zones::PROVER_CONTAINER,
];
/// Nemesis warmup before the first kill plus its longest downtime.
const NEMESIS_SLACK_SECS: u64 = WARMUP_SECS + MAX_DOWN_SECS;
/// The longest fault window before a storage-fault crash.
const STORAGE_WINDOW_SLACK_SECS: u64 = MAX_TORN_WINDOW_SECS;

fn is_default_max_faults(n: &u32) -> bool {
    *n == 3
}

fn is_default_net_gap(n: &u32) -> bool {
    *n == 30
}

fn is_one(n: &u8) -> bool {
    *n == 1
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    *t == T::default()
}

/// The Tempo workload's arguments (the contract's `Args`; `bedrock-dst
/// campaign --workload-arg key=value`, e.g. `load=trie`). Unknown keys are rejected; [`Default`] supplies the standard campaign settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TempoArgs {
    /// txgen's transaction-generation seed, shared by every seed so seeds
    /// vary faults and schedules over a fixed workload.
    pub workload_seed: u64,
    /// Maximum scheduled faults, including faults that leave the node alive.
    #[serde(rename = "max_kills")]
    pub max_faults: u32,
    pub min_gap_secs: u32,
    /// Disable the crash nemesis.
    pub no_nemesis: bool,
    /// E2 head-stall budget.
    pub liveness_secs: u64,
    /// Transfers for the `transfers` load (0 disables load).
    pub txgen_count: u64,
    pub txgen_tps: u64,
    pub load: Load,
    /// Trie load rate; ~5 tx/s puts about one step in each 200 ms block.
    /// Per sender with `trie_contracts=auto`.
    pub trie_tps: u64,
    /// `1` (default; old seeds keep meaning the same runs) or `auto`
    /// (contract pool, per-seed contracts and senders; changes the warmup).
    #[serde(skip_serializing_if = "TrieContracts::is_one")]
    pub trie_contracts: TrieContracts,
    /// TIP-20 load rate; ~50 tx/s puts about ten transfers in each block.
    pub tip20_tps: u64,
    /// Chain load rate; ~10 tx/s puts about two appends in each block.
    pub chain_tps: u64,
    /// `load=statemix` rate; ~10 tx/s puts about two mutations in each block.
    /// Skipped at its default so other loads' serialized args are unchanged.
    #[serde(skip_serializing_if = "is_default_statemix_tps")]
    pub statemix_tps: u64,
    /// Run the E7 reference node (compose service `tempo-ref`; run.sh keeps
    /// it in the compose file only with this flag).
    pub reference: bool,
    /// Who makes the nemesis plan and per-generation load seeds: always
    /// `explicit` (derived here from the plan seed and delivered in
    /// config.json). `guest` (drawn from guest getrandom) was removed: the
    /// planner owns every semantic decision, so a fork can re-draw or drop
    /// them as typed host decisions, and guest randomness is left to the
    /// guest's own consumers. Runs recorded with `guest` replay by tape only.
    pub decisions: Decisions,
    /// Put the node's datadir on LazyFS (a FUSE layer that keeps un-synced
    /// writes volatile) during warmup, and let the nemesis draw machine
    /// crashes (discarding all or a subset of un-synced writes) and torn
    /// writes besides process kills; adds the E11 durable-history oracle.
    /// (The new fields are left out of the serialized arguments while at
    /// their defaults.)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub storage_faults: bool,
    /// With `storage_faults`: draw only these families (`kill`, `crash`,
    /// `torn`; a JSON list or `crash,torn`); all when empty. Other names are
    /// rejected.
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "storage_kinds"
    )]
    pub storage_fault_kinds: Vec<String>,
    /// Let the nemesis also draw process-level faults: pause/resume (`podman
    /// pause`, 1-20 s), CPU throttling (10-30% of a CPU for 5-30 s) and
    /// graceful stop/start (`podman stop -t 10-30`; a SIGKILL fallback is
    /// `E4/stop-timeout`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub process_faults: bool,
    /// With `process_faults`: draw only these families (`kill`, `pause`,
    /// `throttle`, `stop`; a JSON list or `pause,stop`); all when empty.
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "kinds")]
    pub process_fault_kinds: Vec<String>,
    /// `podman stop -t` for finalize's graceful stops (`E4/graceful-stop`,
    /// `E7/reference-graceful-stop`).
    #[serde(skip_serializing_if = "is_default_stop_timeout")]
    pub finalize_stop_timeout_secs: u64,
    /// With load=zones, enable the witness-fault family: the prover mutates
    /// each settled batch's witness and checks the SPF rejects it (nothing
    /// invalid is submitted to L1). Omitted when false, so existing
    /// `workload_args` are unchanged.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub zones_witness_faults: bool,
    /// With load=zones, enable the L1-fault family: the prover rebuilds each
    /// batch's witness through a byzantine L1 proxy (wrong state) and checks
    /// it is rejected. Omitted when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub zones_l1_faults: bool,
    /// With load=zones, enable the TIP-403 policy family: a driver changes
    /// pathUSD's transfer policy and sends allowed/forbidden zone transfers.
    /// Omitted when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub zones_policy: bool,
    /// `load=zones`: sequencers in the zone, 1 (one `tempo-zone dev`
    /// sequencer) or 3 (multi-sequencer, 2-of-3 settlement; run.sh keeps
    /// compose.yaml's `# >>> zones-multi` services).
    #[serde(skip_serializing_if = "crate::campaign::single")]
    pub zone_sequencers: u32,
    /// Enable network faults. With a load that has a network topology
    /// (zones): the network nemesis — link cuts, partitions, resets,
    /// per-link netem and the load's families. With the cluster
    /// (`validators=4`): the network families (`delayed-peer`,
    /// `partition-heal`) — consensus-port delays and partitions held around
    /// a crash (cluster_net.rs).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub network_faults: bool,
    /// Families it draws from; empty means the load's defaults.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_fault_kinds: Vec<NetFaultKind>,
    #[serde(skip_serializing_if = "is_default_max_faults")]
    pub max_network_faults: u32,
    #[serde(skip_serializing_if = "is_default_net_gap")]
    pub network_min_gap_secs: u32,
    /// Number of validators. With one validator, `consensus=true` selects
    /// a real consensus node instead of the default dev node.
    #[serde(skip_serializing_if = "is_one")]
    pub validators: u8,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub consensus: bool,
    /// Cluster only: commonware's peer connection cooldown (compose-time).
    #[serde(skip_serializing_if = "is_default")]
    pub cooldown: Cooldown,
    /// Cluster only: consensus timeouts (compose-time).
    #[serde(skip_serializing_if = "is_default")]
    pub timeouts: Timeouts,
    /// Cluster only: the fault family of every seed; absent, each seed
    /// draws one. `max_kills` bounds the faults per seed, `min_gap_secs`
    /// (at least the cooldown's mesh budget) separates them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faults: Option<FaultFamily>,
    /// Cluster only: the storage layer under each validator's datadir, for
    /// machine crashes and power loss (`lazyfs`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageLayer>,
    /// Cluster only: run each validator on a different reth engine profile
    /// (`cluster::EngineProfile`) so the consensus cluster is an N-way
    /// execution differential (sparse-trie task vs the simple engine and the
    /// other state-root modes; `E13/validator-state-root-differs`,
    /// `E13/validator-proof-differs`). The `{Optimized, Simple}` pair is always
    /// present. Needs at least two validators. Omitted (off) by default, so
    /// every validator keeps today's flags and existing goldens are unchanged.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub validator_engine_diff: bool,
    /// Attach one independent certified L1 consensus follower (`tempo`) to the
    /// consensus cluster (`validators=N consensus=true`) under any load: the
    /// generic tempo#8263 catch-up detector. The planner draws its
    /// offline-window fault plan ([`crate::follower`]) from the seed. Off by
    /// default and incompatible with the dev node, so existing goldens are
    /// unchanged. Accepts `follower=true` and `certified_follower=true`.
    #[serde(
        default,
        alias = "certified_follower",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub follower: bool,
    /// Run the historical-RPC oracles (`historical`): E3h (a node serves the
    /// same answers about an old block across a kill/restart, the core
    /// trie/historical-state-after-crash lead) on every run, and, with the
    /// consensus cluster, E7h (the cross-validator historical differential at
    /// the agreed block). Omitted (off) by default, so existing goldens are
    /// unchanged. See `historical`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub historical: bool,
    /// Run the generic valid-state-root invariant (Strand A): for every new
    /// canonical block, on every node, recompute the affected state from scratch
    /// and assert consistency with the header state root (see
    /// [`crate::state_root`]). Auto-on with `load=statemix`. Omitted (off) by
    /// default, so existing goldens are unchanged.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub verify_state_root: bool,
}

fn is_default_stop_timeout(t: &u64) -> bool {
    *t == DEFAULT_STOP_TIMEOUT_SECS
}

/// The default `statemix_tps` (kept in sync with [`TempoArgs::default`]).
fn is_default_statemix_tps(n: &u64) -> bool {
    *n == 10
}

impl Default for TempoArgs {
    fn default() -> Self {
        Self {
            workload_seed: 99,
            max_faults: 3,
            min_gap_secs: 30,
            no_nemesis: false,
            liveness_secs: 60,
            txgen_count: 20_000,
            txgen_tps: 100,
            load: Load::Transfers,
            trie_tps: 5,
            trie_contracts: TrieContracts::One,
            tip20_tps: 50,
            chain_tps: 10,
            statemix_tps: 10,
            reference: false,
            decisions: Decisions::Explicit,
            storage_faults: false,
            storage_fault_kinds: Vec::new(),
            process_faults: false,
            process_fault_kinds: Vec::new(),
            finalize_stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
            zones_witness_faults: false,
            zones_l1_faults: false,
            zones_policy: false,
            zone_sequencers: 1,
            network_faults: false,
            network_fault_kinds: Vec::new(),
            max_network_faults: 3,
            network_min_gap_secs: 30,
            validators: 1,
            consensus: false,
            cooldown: Cooldown::default(),
            timeouts: Timeouts::default(),
            faults: None,
            storage: None,
            validator_engine_diff: false,
            follower: false,
            historical: false,
            verify_state_root: false,
        }
    }
}

/// A list of family names: a JSON list, or one comma-separated string
/// (`--workload-arg process_fault_kinds=pause,stop`).
fn kinds<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Kinds {
        List(Vec<String>),
        Csv(String),
    }
    Ok(match Kinds::deserialize(d)? {
        Kinds::List(l) => l,
        Kinds::Csv(s) => s
            .split(',')
            .filter(|k| !k.is_empty())
            .map(Into::into)
            .collect(),
    })
}

/// [`kinds`] for `storage_fault_kinds`, rejecting names that are not storage
/// fault families (`crash,torn`).
fn storage_kinds<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let kinds = kinds(d)?;
    if let Some(k) = kinds.iter().find(|k| !nemesis::is_family(k)) {
        return Err(serde::de::Error::custom(format!(
            "unknown storage fault kind {k:?} (kill, crash, torn)"
        )));
    }
    Ok(kinds)
}

impl TempoArgs {
    pub fn cluster(&self) -> bool {
        self.load != Load::Zones && (self.validators > 1 || self.consensus)
    }

    /// Whether a certified L1 follower runs: the generic cluster follower
    /// (`follower=true`) or the zones follower (its own topology).
    pub fn follower_on(&self) -> bool {
        self.follower || self.load == Load::Zones
    }

    /// Rejects combinations the workload cannot run.
    pub fn validate(&self) -> Result<(), String> {
        if self.load == Load::Zones
            && (self.validators != 1 || self.consensus || self.reference || self.storage.is_some())
        {
            return Err("load=zones owns four upstream validators and a certified follower; omit validators, consensus, reference and storage".into());
        }
        if self.follower && (self.load == Load::Zones || !self.cluster()) {
            return Err(
                "follower=true attaches a certified follower to validators=N consensus=true; it is implied by zones, not combined with it"
                    .into(),
            );
        }
        if !matches!(self.zone_sequencers, 0 | 1 | 3) {
            return Err(format!(
                "zone_sequencers={}: want 1 or 3",
                self.zone_sequencers
            ));
        }
        if self.zone_sequencers == 3 && self.load != Load::Zones {
            return Err("zone_sequencers=3 needs load=zones".into());
        }
        if self.validators == 1
            && (self.faults == Some(FaultFamily::Simultaneous)
                || self.faults.is_some_and(FaultFamily::is_network))
        {
            return Err("that fault family needs at least two validators".into());
        }
        if self.network_faults && self.validators == 1 && network_topology(self).is_none() {
            return Err(
                "network_faults=true needs at least two validators or a load with a network topology (load=zones zone_sequencers=3)"
                    .into(),
            );
        }
        if self.validator_engine_diff && self.validators < 2 {
            return Err("validator_engine_diff=true needs at least two validators".into());
        }
        Ok(())
    }

    /// The network nemesis' config, when on.
    pub fn network(&self) -> Option<NetworkConfig> {
        let topology = network_topology(self).filter(|_| self.network_faults)?;
        Some(NetworkConfig {
            enabled: true,
            kinds: if self.network_fault_kinds.is_empty() {
                default_net_kinds(self)
            } else {
                self.network_fault_kinds.clone()
            },
            max_faults: self.max_network_faults,
            min_gap_secs: self.network_min_gap_secs,
            topology,
        })
    }
}

// ---- network nemesis plan entries (one canonical fault type) ----

/// A network fault family (`network_fault_kinds`). The generic families
/// draw over the topology's nodes by name; the others are a workload's
/// (they draw role-based steps, resolved when the fault starts).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetFaultKind {
    /// Symmetric partition of the nodes, 1|n-1 up to an even split, on the
    /// topology's fault ports.
    Partition,
    /// The same, but only the first side loses what it sends.
    OneWayPartition,
    /// One node's link to another, cut (reset or silently dropped).
    LinkCut,
    /// Established connections between the nodes reset at drawn offsets.
    LinkReset,
    /// Delay/jitter/loss/rate on one node's links to some peers (asymmetric).
    LinkNetem,
    // Multi-sequencer zones (`zones_cluster::draw_family`), after zones'
    // network-chaos e2e tests (PRs #1261, #1278).
    /// Every sequencer's L1 link cut (reset or silently dropped).
    L1CutAll,
    /// Both followers' L1 links.
    L1CutFollowers,
    /// The leader's L1 link.
    L1CutLeader,
    /// One follower's L1 link.
    L1CutFollower,
    /// Established L1 connections reset at drawn offsets.
    L1Resets,
    /// Netem on the L1 links of all, the leader or one follower.
    L1Netem,
    /// Leadership handed to a follower while the other is cut off.
    HandoffFollowerCut,
    /// ... while the incoming leader and the other follower are cut off.
    HandoffIncomingIsolated,
    /// ... and the outgoing leader is cut off before the activation.
    HandoffOutgoingIsolated,
    /// ... while the incoming leader has no P2P links.
    HandoffIncomingP2pIsolated,
    /// ... under 400 ms P2P and 500 ms L1 latency.
    HandoffLatency,
    /// ... under P2P loss and jitter.
    HandoffLoss,
}

impl NetFaultKind {
    /// The generic families.
    pub const GENERIC: [NetFaultKind; 5] = [
        NetFaultKind::Partition,
        NetFaultKind::OneWayPartition,
        NetFaultKind::LinkCut,
        NetFaultKind::LinkReset,
        NetFaultKind::LinkNetem,
    ];

    /// The `kebab-case` name (as in `network_fault_kinds` and coverage).
    pub fn name(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    }
}

/// How a cut link fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CutMode {
    /// TCP RST: established connections die, new ones are refused.
    Reset,
    /// Silently dropped (a stall): connections hang until timeouts.
    Drop,
}

/// `tc netem` parameters of a degraded link.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetemShape {
    pub latency_ms: u32,
    /// Uniform extra delay up to this.
    pub jitter_ms: u32,
    pub loss_permille: u32,
    /// Bandwidth cap; 0 is none.
    pub rate_kbps: u32,
}

/// A node of the topology, by name or by a role the workload resolves when
/// the fault starts (`all` is every node).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NodeRef {
    Node {
        node: String,
    },
    Role {
        role: String,
        #[serde(default)]
        pick: u32,
    },
}

/// The other end of a faulted link: a node, or a named endpoint of the
/// topology (e.g. the proxy in front of a host-network service).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Peer {
    Node(NodeRef),
    Endpoint { endpoint: String },
}

/// What one step of a network fault does. `ports` scopes it (empty: all,
/// or an endpoint's own ports).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum NetAction {
    /// Every link between nodes of different sides (pairwise for more than
    /// two sides); `one_way`: only what the first side sends.
    Partition {
        sides: Vec<Vec<NodeRef>>,
        ports: Vec<u16>,
        one_way: bool,
        mode: CutMode,
    },
    /// The links of each `from` node to each peer.
    Cut {
        from: Vec<NodeRef>,
        to: Vec<Peer>,
        ports: Vec<u16>,
        mode: CutMode,
    },
    /// Established connections of each `from` node to each peer reset at
    /// each offset (seconds after the step); listeners stay up.
    Reset {
        from: Vec<NodeRef>,
        to: Vec<Peer>,
        ports: Vec<u16>,
        at_offsets: Vec<u64>,
    },
    /// What each `from` node sends to each peer is degraded.
    Netem {
        from: Vec<NodeRef>,
        to: Vec<Peer>,
        ports: Vec<u16>,
        shape: NetemShape,
    },
    /// Zones: `zone_setLeader(target)` through the leader's (else a
    /// follower's) operator RPC.
    SetLeader { target: NodeRef },
}

/// A step of a fault, `after_secs` into it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetStep {
    pub after_secs: u64,
    pub action: NetAction,
}

/// One planned network fault: its steps from `at_secs` after the nemesis
/// started; everything is healed at `at_secs + dur_secs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetFault {
    pub at_secs: u64,
    pub dur_secs: u64,
    pub family: NetFaultKind,
    pub steps: Vec<NetStep>,
}

impl NetFault {
    pub fn end_secs(&self) -> u64 {
        self.at_secs + self.dur_secs
    }
}

/// The network topology of the campaign's load, if it has one the network
/// nemesis can fault.
pub fn network_topology(wa: &TempoArgs) -> Option<NetTopology> {
    (wa.load == Load::Zones && wa.zone_sequencers == 3).then(crate::zones_cluster::topology)
}

/// The families drawn when `network_fault_kinds` is empty.
pub fn default_net_kinds(wa: &TempoArgs) -> Vec<NetFaultKind> {
    let mut kinds = NetFaultKind::GENERIC.to_vec();
    if wa.load == Load::Zones {
        kinds.extend(crate::zones_cluster::FAMILIES);
    }
    kinds
}

/// The steps of a `kind` fault lasting `dur_secs` over `topo`.
pub fn draw_fault_steps(
    kind: NetFaultKind,
    topo: &NetTopology,
    dur_secs: u64,
    draw: &mut dyn FnMut(u64, u64) -> u64,
) -> Vec<NetStep> {
    netfault::draw_generic(kind, topo, dur_secs, draw)
        .or_else(|| crate::zones_cluster::draw_family(kind, dur_secs, draw))
        .unwrap_or_default()
}

/// The network fault plan of `cfg` from `from_secs` on: the guest's
/// (`nemesis::network_for`) and the planner's (explicit decisions, branch
/// re-draws) share it.
pub fn net_plan(
    cfg: &NetworkConfig,
    run_secs: u64,
    kills: &[(u64, u64)],
    from_secs: u64,
    count: u32,
    draw: impl FnMut(u64, u64) -> u64,
) -> Vec<NetFault> {
    let topo = cfg.topology.clone();
    netfault::plan_from(
        cfg,
        run_secs,
        kills,
        from_secs,
        count,
        draw,
        |kind, dur, d| draw_fault_steps(kind, &topo, dur, d),
    )
}

/// This planner's instance of the contract types.
pub type TempoPlanRequest = PlanRequest<TempoArgs, Scenario>;
/// Decisions go out as pretty JSON, so the driver's scenario.json (which
/// it writes verbatim) stays readable.
pub type TempoPlan = Plan<Config, Box<RawValue>, Swarm>;

/// Deterministically mixes a seed into a pseudorandom word (SplitMix64).
pub fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// `s` as pretty JSON.
fn pretty<T: Serialize>(s: &T) -> Result<Box<RawValue>, String> {
    let text = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    RawValue::from_string(text).map_err(|e| e.to_string())
}

/// `tempo-dst parse-args`: `--workload-config` (a JSON object of
/// [`TempoArgs`] fields) with each `KEY=VALUE` over it. A value is taken as
/// JSON when it parses as JSON (`2`, `true`, `[1]`), else as a string
/// (`trie`); [`TempoArgs`] then checks every key and type.
pub fn parse_args(req: &ArgsRequest) -> Result<TempoArgs, String> {
    let mut fields: BTreeMap<String, Box<RawValue>> = match &req.config_file {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            serde_json::from_str(&text).map_err(|e| format!("{path}: want a JSON object: {e}"))?
        }
        None => BTreeMap::new(),
    };
    for kv in &req.args {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| format!("workload arg {kv:?}: want KEY=VALUE"))?;
        let value = match RawValue::from_string(v.to_string()) {
            Ok(json) => json,
            Err(_) => serde_json::value::to_raw_value(v).map_err(|e| e.to_string())?,
        };
        fields.insert(k.to_string(), value);
    }
    let text = serde_json::to_string(&fields).map_err(|e| e.to_string())?;
    let args: TempoArgs = serde_json::from_str(&text).map_err(|e| format!("workload args: {e}"))?;
    args.validate()?;
    check_explicit(&args)?;
    Ok(args)
}

/// `decisions=guest` was removed (see [`TempoArgs::decisions`]).
fn check_explicit(wa: &TempoArgs) -> Result<(), String> {
    if wa.decisions == Decisions::Guest {
        return Err(
            "decisions=guest was removed: the planner makes every decision \
                    (decisions=explicit); runs recorded with it replay by tape only"
                .into(),
        );
    }
    Ok(())
}

/// The guest network planner (`netfault::plan`) for `decisions=explicit`,
/// drawn from a host PRNG of the seed, around the kills of `kills`.
pub fn network_plan_for(
    cfg: &NetworkConfig,
    run_secs: u64,
    kills: &[ScheduledFault],
    seed: u64,
    salt: u64,
) -> Vec<NetFault> {
    let mut state = splitmix64(seed ^ salt);
    let draw = |lo: u64, hi: u64| {
        state = splitmix64(state);
        lo + state % (hi - lo + 1)
    };
    net_plan(
        cfg,
        run_secs,
        &kill_windows(kills),
        netfault::NET_WARMUP_SECS,
        cfg.max_faults,
        draw,
    )
}

fn kill_windows(kills: &[ScheduledFault]) -> Vec<(u64, u64)> {
    kills
        .iter()
        .map(|k| (k.at_secs, k.end_secs() - k.at_secs))
        .collect()
}

/// The guest nemesis planner (`nemesis::plan`) for `decisions=explicit`,
/// drawn from a host PRNG of the seed instead of guest randomness.
pub fn nemesis_plan_for(
    wa: &TempoArgs,
    run_secs: u64,
    seed: u64,
    salt: u64,
) -> Vec<ScheduledFault> {
    let mut state = splitmix64(seed ^ salt);
    let draw = |lo: u64, hi: u64| {
        state = splitmix64(state);
        nemesis::in_range(state, lo, hi)
    };
    nemesis::plan(&nemesis_config(wa), run_secs, draw)
}

/// The guest nemesis config of `wa`.
fn nemesis_config(wa: &TempoArgs) -> NemesisConfig {
    NemesisConfig {
        enabled: !wa.no_nemesis,
        max_faults: wa.max_faults,
        min_gap_secs: wa.min_gap_secs,
        process_fault_kinds: wa.process_fault_kinds.clone(),
        process_faults: wa.process_faults,
        storage_fault_kinds: wa.storage_fault_kinds.clone(),
        storage_faults: wa.storage_faults,
    }
}

/// The guest nemesis config of scenario `s`.
fn scenario_nemesis_config(s: &Scenario) -> NemesisConfig {
    NemesisConfig {
        enabled: s.nemesis.enabled,
        max_faults: s.nemesis.max_faults,
        min_gap_secs: s.nemesis.min_gap_secs,
        process_fault_kinds: s.nemesis.process_fault_kinds.clone(),
        process_faults: s.nemesis.process_faults,
        storage_fault_kinds: s.nemesis.storage_fault_kinds.clone(),
        storage_faults: s.nemesis.storage_faults,
    }
}

/// The cluster of a `validators=4` seed and its swarm record: the fault
/// family (fixed by the arguments, else drawn per seed), plan and first load
/// target, all from a host PRNG of the seed. Always planner-made, whatever
/// `decisions` says.
pub fn cluster_for(
    wa: &TempoArgs,
    run_secs: u64,
    seed: u64,
    salt: u64,
) -> (ClusterConfig, ClusterSwarm) {
    let mut state = splitmix64(seed ^ CLUSTER_SALT ^ salt);
    let mut draw = |lo: u64, hi: u64| {
        state = splitmix64(state);
        lo + state % (hi - lo + 1)
    };
    let first = draw(1, u64::from(cluster::VALIDATORS)) as u8;
    let families = FaultFamily::drawable(wa.storage, wa.network_faults && wa.validators > 1);
    let family = wa
        .faults
        .unwrap_or_else(|| families[draw(0, families.len() as u64 - 1) as usize]);
    let faults = if wa.no_nemesis {
        Vec::new()
    } else {
        cluster::plan(
            family,
            PlanBounds {
                run_secs,
                max_faults: wa.max_faults,
                min_gap_secs: u64::from(wa.min_gap_secs).max(wa.cooldown.budget().mesh_secs),
                storage: wa.storage,
            },
            draw,
        )
    };
    // The per-validator engine assignment is a pure function of the
    // campaign-fixed workload seed (the validators boot once, before the shared
    // warm checkpoint, so their flags cannot vary per run seed; drawing from
    // the workload seed keeps the planner, run.sh's compose and a replay in
    // agreement). run.sh replicates this draw in python.
    let engine_profiles = if wa.validator_engine_diff {
        let mut estate = splitmix64(wa.workload_seed ^ ENGINE_SALT);
        cluster::engine_profiles(cluster::VALIDATORS, |n| {
            estate = splitmix64(estate);
            estate % n
        })
    } else {
        Vec::new()
    };
    let config = ClusterConfig {
        cooldown: wa.cooldown,
        timeouts: wa.timeouts,
        storage: wa.storage,
        faults,
        engine_profiles,
        first_load_target: ValidatorId::new(first).expect("drawn in 1..=VALIDATORS"),
    };
    let swarm = ClusterSwarm {
        cooldown: wa.cooldown,
        faults: (!wa.no_nemesis).then_some(family),
        timeouts: wa.timeouts,
        engine_diff: wa.validator_engine_diff,
    };
    (config, swarm)
}

/// Seconds after the follower nemesis starts before the first window.
const FOLLOWER_FIRST_SECS: u64 = 15;
/// Most follower offline-windows in one run (each needs time to catch up).
const FOLLOWER_MAX_WINDOWS: usize = 3;

/// The certified follower's offline-window fault plan for a seed, pure from the
/// seed so a replay drives the same windows ([`crate::follower`]). The first
/// window is always a snapshot restore (the deepest gap and strongest #8263
/// trigger); later windows draw among the triggers. Each gap crosses the
/// persistence frontier, and the windows are spaced by the liveness budget so
/// one catches up before the next.
pub fn follower_plan_for(
    wa: &TempoArgs,
    run_secs: u64,
    seed: u64,
    salt: u64,
) -> Vec<crate::follower::FollowerFault> {
    use crate::follower::{FollowerFault, FollowerTrigger};
    if wa.no_nemesis {
        return Vec::new();
    }
    let mut state = splitmix64(seed ^ FOLLOWER_SALT ^ salt);
    let mut draw = |lo: u64, hi: u64| {
        state = splitmix64(state);
        lo + state % (hi - lo + 1)
    };
    // The catch-up budget between windows: the liveness bound plus slack.
    let gap = wa.liveness_secs.max(30) + 30;
    let mut faults = Vec::new();
    let mut t = FOLLOWER_FIRST_SECS;
    for i in 0..FOLLOWER_MAX_WINDOWS {
        // Leave room for the last window to catch up before finalize.
        if t + gap > run_secs {
            break;
        }
        let trigger = if i == 0 {
            FollowerTrigger::SnapshotRestore
        } else {
            match draw(0, 2) {
                0 => FollowerTrigger::SnapshotRestore,
                1 => FollowerTrigger::KillHold {
                    down_secs: draw(20, 45),
                },
                _ => FollowerTrigger::Pause { secs: draw(20, 45) },
            }
        };
        let at_secs = t + draw(0, 5);
        faults.push(FollowerFault { at_secs, trigger });
        t = at_secs + trigger.down_secs() + gap;
    }
    faults
}

/// `(count, tps, image)` of the campaign's load.
fn load_params(wa: &TempoArgs, run_secs: u64) -> (u64, u64, Option<&'static str>) {
    // Generated loads get enough steps to outlast the run.
    let steps = |tps| (run_secs + 60) * tps;
    match wa.load {
        Load::Transfers => (wa.txgen_count, wa.txgen_tps, None),
        Load::Trie => (steps(wa.trie_tps), wa.trie_tps, Some(TRIE_IMAGE)),
        Load::Tip20 => (steps(wa.tip20_tps), wa.tip20_tps, Some(TIP20_IMAGE)),
        Load::Chain => (steps(wa.chain_tps), wa.chain_tps, Some(CHAIN_IMAGE)),
        Load::StateMix => (
            steps(wa.statemix_tps),
            wa.statemix_tps,
            Some(STATEMIX_IMAGE),
        ),
        // The driver paces itself (one action at a time, each to settlement).
        Load::Zones => (1, 1, Some(ZONES_IMAGE)),
    }
}

/// The container nemesis kill `index` targets: the node, or with the zones
/// load the node, the zone sequencer and the zone prover in turn from an
/// offset of the run seed after a mandatory first follower slot. A scenario
/// replay or a re-drawn plan targets the same containers and the guest draws no
/// extra randomness.
pub fn kill_target(cfg: &Config, index: usize) -> &'static str {
    if !cfg.zones {
        return crate::common::NODE_CONTAINER;
    }
    let targets = if cfg.zone_cluster() {
        &CLUSTER_KILL_TARGETS[..]
    } else {
        &ZONES_KILL_TARGETS[..]
    };
    let slot = index % targets.len();
    if slot == 0 {
        targets[0]
    } else {
        let others = targets.len() - 1;
        targets[1 + ((cfg.seed % others as u64) as usize + slot - 1) % others]
    }
}

/// Every decision of `seed`'s run. With `decisions=guest` the nemesis plan
/// and load seeds are left to the guest (filled in by `observe`).
pub fn scenario_for(
    c: &CampaignInfo,
    wa: &TempoArgs,
    seed: u64,
    preempt: Preempt,
    salt: Option<u64>,
) -> Scenario {
    let (count, tps, image) = load_params(wa, c.run_secs);
    let explicit = wa.decisions == Decisions::Explicit;
    let nemesis_salt = NEMESIS_SALT ^ salt.unwrap_or(0);
    let (cluster, cluster_swarm) = match wa
        .cluster()
        .then(|| cluster_for(wa, c.run_secs, seed, salt.unwrap_or(0)))
    {
        Some((config, swarm)) => (Some(config), Some(swarm)),
        None => (None, None),
    };
    // The generic certified follower's offline-window plan, always planner-made
    // (like the cluster plan). Zones drive their follower through the kill plan,
    // so they keep no separate follower plan here.
    let follower = (wa.follower && cluster.is_some())
        .then(|| follower_plan_for(wa, c.run_secs, seed, salt.unwrap_or(0)));
    // The cluster runs its own fault plan; the dev node's kill plan is empty.
    let plan = if cluster.is_some() {
        explicit.then(Vec::new)
    } else {
        explicit.then(|| nemesis_plan_for(wa, c.run_secs, seed, nemesis_salt))
    };
    // One generation at start plus one per restart, each as the guest would
    // derive it (so explicit decisions do not change the load).
    let generations = match &plan {
        Some(plan) => (0..=plan.len() as u64)
            .map(|g| Generation {
                txgen_seed: wa.workload_seed + g,
                spec_seed: seed,
            })
            .collect(),
        _ => Vec::new(),
    };
    let network = wa.network().map(|config| NetworkScenario {
        plan: plan.as_ref().map(|kills| {
            network_plan_for(
                &config,
                c.run_secs,
                kills,
                seed,
                NETWORK_SALT ^ salt.unwrap_or(0),
            )
        }),
        config,
    });
    let mut meaning = scenario::meaning();
    if network.is_some() || !crate::campaign::single(&wa.zone_sequencers) {
        meaning.extend(scenario::network_meaning());
    }
    Scenario {
        version: if wa.load == Load::Zones {
            scenario::ZONES_SCENARIO_VERSION
        } else {
            scenario::SCENARIO_VERSION
        },
        decisions: wa.decisions,
        seed,
        rng_seed: seed,
        swarm: Swarm {
            cluster: cluster_swarm,
            follower: wa.follower,
            load: wa.load,
            nemesis: !wa.no_nemesis,
            // The zones/generic network nemesis (`swarm.network`); the
            // cluster's network faults are recorded in its fault family.
            network: network.is_some(),
            preempt,
            process_faults: wa.process_faults,
            reference: wa.reference,
            storage_faults: wa.storage_faults,
            zone_sequencers: wa.zone_sequencers,
            trie: (wa.load == Load::Trie && wa.trie_contracts == TrieContracts::Auto).then(|| {
                let (contracts, senders) = crate::trie_gen::draw(seed);
                TrieShape { contracts, senders }
            }),
        },
        cluster,
        follower,
        run_secs: c.run_secs,
        liveness_secs: wa.liveness_secs,
        zones_witness_faults: wa.zones_witness_faults,
        zones_l1_faults: wa.zones_l1_faults,
        zones_policy: wa.zones_policy,
        historical: wa.historical,
        // The generic valid-state-root invariant: explicit, or auto-on with the
        // generic state-mutation workload.
        verify_state_root: wa.verify_state_root || wa.load == Load::StateMix,
        nemesis: NemesisScenario {
            enabled: !wa.no_nemesis,
            max_faults: wa.max_faults,
            min_gap_secs: wa.min_gap_secs,
            plan,
            storage_faults: wa.storage_faults,
            storage_fault_kinds: wa.storage_fault_kinds.clone(),
            process_faults: wa.process_faults,
            process_fault_kinds: wa.process_fault_kinds.clone(),
        },
        finalize_stop_timeout_secs: wa.finalize_stop_timeout_secs,
        load: LoadScenario {
            kind: wa.load,
            count,
            tps,
            image: image.map(Into::into),
            workload_seed: wa.workload_seed,
            draw_spec_seeds: false,
            generations,
            zone_sequencers: wa.zone_sequencers,
        },
        network,
        observed: Observed::default(),
        meaning,
    }
}

/// The guest's `/bedrock/in/config.json` for scenario `s`. `deliver`: pass
/// the nemesis plan and per-generation load inputs explicitly (planner-made
/// decisions, scenario replays); otherwise the guest derives them.
pub fn guest_config(s: &Scenario, deliver: bool) -> Config {
    let kind = s.load.kind;
    Config {
        cluster: s.cluster.clone(),
        cob: (kind == Load::Chain).then(|| CobConfig {
            address: CHAIN_CONTRACT.into(),
        }),
        finalize_stop_timeout_secs: s.finalize_stop_timeout_secs,
        follower: s.swarm.follower,
        follower_plan: s.follower.clone(),
        liveness_secs: s.liveness_secs,
        load: LoadConfig {
            count: s.load.count,
            draw_spec_seeds: s.load.draw_spec_seeds,
            generations: if deliver {
                s.load.generations.clone()
            } else {
                Vec::new()
            },
            image: s.load.image.clone().unwrap_or_default(),
            seed: s.load.workload_seed,
            spec: String::new(),
            tps: s.load.tps,
        },
        nemesis: scenario_nemesis_config(s),
        nemesis_plan: s.nemesis.plan.clone().filter(|_| deliver),
        network: s.network.as_ref().map(|n| n.config.clone()),
        network_plan: s
            .network
            .as_ref()
            .and_then(|n| n.plan.clone())
            .filter(|_| deliver),
        reference: s.swarm.reference,
        run_secs: s.run_secs,
        seed: s.seed,
        swarm: Some(s.swarm),
        tip20: kind == Load::Tip20,
        trie: (kind == Load::Trie).then(|| TrieConfig {
            address: TRIE_CONTRACT.into(),
            contracts: s.swarm.trie.map_or(0, |t| t.contracts),
            senders: s.swarm.trie.map_or(0, |t| t.senders),
            ..TrieConfig::default()
        }),
        statemix: kind == Load::StateMix,
        verify_state_root: s.verify_state_root,
        workload_seed: s.load.workload_seed,
        zones: kind == Load::Zones,
        zones_witness_faults: kind == Load::Zones && s.zones_witness_faults,
        zones_l1_faults: kind == Load::Zones && s.zones_l1_faults,
        zones_policy: kind == Load::Zones && s.zones_policy,
        historical: s.historical,
        zone_sequencers: if kind == Load::Zones && !crate::campaign::single(&s.load.zone_sequencers)
        {
            s.load.zone_sequencers
        } else {
            0
        },
    }
}

/// Whether every run of `s` has at least one kill and its restart: the first
/// kill lands by warmup + one gap, and needs its downtime plus a full gap
/// after it for recovery (see `nemesis::plan`). Never with process faults:
/// a plan may be all pauses and throttles, which restart nothing.
fn kills_planned(s: &Scenario) -> bool {
    if let Some(c) = &s.cluster {
        return !c.faults.is_empty();
    }
    if s.nemesis.process_faults {
        return false;
    }
    let slack = NEMESIS_SLACK_SECS
        + if s.nemesis.storage_faults {
            STORAGE_WINDOW_SLACK_SECS
        } else {
            0
        };
    s.nemesis.enabled
        && s.nemesis.max_faults > 0
        && s.run_secs >= 2 * u64::from(s.nemesis.min_gap_secs.max(1)) + slack
}

/// Coverage every run of `s` must reach (see bedrock-dst's `verdict`): the
/// load landed, and its oracle checked it. With the trie load, its checks
/// ran. With the TIP-20 load: blocks carried several transfers, and a
/// snapshot pinned while in memory read the same after it was persisted and,
/// when the plan guarantees a kill, after a restart. With the chain load, an
/// append made during the run was checked against state and, when the run
/// kills the node, the chain grew past its pre-kill length after a restart.
/// With the zones load, a batch submitted during the run was replayed by the
/// prover, a deposit was credited, a withdrawal paid out on L1, solvency
/// checked with zone supply, and (with a kill planned) a batch landed after
/// a restart. With `reference`, the reference node caught up and was
/// compared. With storage faults and a kill, E11 re-checked a block that
/// survived a crash.
pub fn required(s: &Scenario) -> Vec<Signature> {
    let mut required = match s.load.kind {
        Load::Transfers if s.load.count == 0 => vec![],
        Load::Transfers => vec!["S/load-included"],
        Load::Trie => vec!["S/load-included", "S/trie-checked"],
        Load::Tip20 => {
            let mut r = vec![
                "S/load-included",
                "S/tip20-checked",
                "S/tip20-transfers-in-block",
                "S/tip20-pinned-read-survived-persistence",
            ];
            if kills_planned(s) {
                r.push("S/tip20-pinned-read-survived-restart");
            }
            r
        }
        Load::Chain if kills_planned(s) => vec![
            "S/load-included",
            "S/chain-appended",
            "S/chain-survived-restart",
        ],
        Load::Chain => vec!["S/load-included", "S/chain-appended"],
        // The valid-state-root coverage is added below (keyed off
        // verify_state_root, which is auto-on for this load).
        Load::StateMix => vec!["S/load-included"],
        Load::Zones => {
            let mut r = vec![
                "S/load-included",
                "S/zones-batch-submitted",
                "S/zones-batch-proven",
                "S/zones-deposit-credited",
                "S/zones-withdrawal-finalized",
                "S/zones-solvency-checked",
            ];
            if kills_planned(s) {
                r.push("S/zones-batch-after-restart");
                r.extend([
                    "S/follower-snapshot-restored",
                    "S/follower-syncing-observed",
                    "S/follower-executed-after-syncing",
                    "S/follower-caught-up",
                ]);
            }
            if s.zones_witness_faults {
                r.push("S/zones-witness-mutated");
                r.push("S/zones-mutated-witness-rejected");
            }
            if s.zones_l1_faults {
                r.push("S/zones-l1-response-faulted");
                r.push("S/zones-l1-fault-detected");
            }
            if s.zones_policy {
                r.push("S/zones-policy-changed");
                r.push("S/zones-transfer-allowed");
                r.push("S/zones-transfer-rejected");
            }
            r
        }
    };
    // Several trie contracts (two or more senders): a block changed two
    // contracts' storage.
    if s.load.kind == Load::Trie && s.swarm.trie.is_some_and(|t| t.contracts >= 2) {
        required.push("S/multi-contract-block");
    }
    if s.swarm.reference {
        required.extend(["S/reference-compared", "S/reference-synced"]);
    }
    if s.nemesis.storage_faults && kills_planned(s) {
        required.push("S/durable-history-checked");
    }
    if let Some(c) = &s.cluster {
        required.push("S/mesh-formed");
        if kills_planned(s) {
            required.push("S/validator-caught-up");
        }
        if c.faults.iter().any(|f| f.impair.is_some()) {
            required.extend(["S/net-impairment-applied", "S/net-impairment-healed"]);
        }
        if c.engine_diff() {
            // The cross-validator execution differential compared at least one
            // block across validators running different engine profiles.
            required.push("S/validator-engine-diff-checked");
        }
        // The generic certified follower, driven behind by its offline-window
        // plan: the tempo#8263 catch-up invariant must be exercised (the
        // snapshot restored, a SYNCING forkchoice seen, and the follower caught
        // back up to the validators' finalized chain).
        if s.follower.as_ref().is_some_and(|p| !p.is_empty()) {
            required.extend([
                "S/follower-snapshot-restored",
                "S/follower-syncing-observed",
                "S/follower-caught-up",
            ]);
        }
    }
    let mut required: Vec<String> = required.into_iter().map(String::from).collect();
    // The historical-RPC oracles: with a kill planned, E3h re-reads a block it
    // recorded before the kill, which any restart exercises, so it is required.
    // E7h's `S/historical-after-unwind` (a block below the agreed point whose
    // hash changed, re-derived after a crash) is a best-effort signal, not
    // required: in the deterministic cluster a BFT-agreed block is re-derived
    // identically, so it rarely fires; the oracle still emits it when it does.
    if s.historical && kills_planned(s) {
        required.push("S/historical-reread-after-restart".into());
    }
    // The generic valid-state-root invariant (Strand A): every run verifies a
    // block's touched-set proofs against its header state root; with a workload
    // whose slots are known (statemix or trie), it also rebuilds a storage root
    // from scratch. With the cluster, the same-height probe (Strand C) runs.
    if s.verify_state_root {
        required.push("S/state-root-verified".into());
        if matches!(s.load.kind, Load::StateMix | Load::Trie) {
            required.push("S/state-root-recomputed-checked".into());
        }
        if s.cluster.is_some() {
            required.push("S/same-height-root-checked".into());
        }
    }
    if s.load.kind == Load::Zones && !crate::campaign::single(&s.load.zone_sequencers) {
        required.extend(["S/cluster-converged", "S/cluster-blocks-checked"].map(String::from));
    }
    let cluster = s.load.kind == Load::Zones && !crate::campaign::single(&s.load.zone_sequencers);
    if let Some(plan) = s.network.as_ref().and_then(|n| n.plan.as_ref()) {
        for f in plan {
            let mut sigs = network_coverage(f);
            if cluster {
                // What E12 (zones and cluster checks) must see each family do.
                sigs.extend(
                    crate::zones_cluster::required_effects(f.family)
                        .iter()
                        .map(|s| s.to_string()),
                );
            }
            for sig in sigs {
                if !required.contains(&sig) {
                    required.push(sig);
                }
            }
        }
    }
    required
        .into_iter()
        .map(|s| Signature::from(s.as_str()))
        .collect()
}

/// The coverage a planned network fault must produce: that it ran, and the
/// effect zones' tests assert for its family.
pub fn network_coverage(f: &NetFault) -> Vec<String> {
    let mut out = vec![format!("S/net-fault-{}", f.family.name())];
    // What the nemesis itself observes; the load's oracles add theirs.
    let reset = f
        .steps
        .iter()
        .any(|s| matches!(s.action, NetAction::Reset { .. }));
    let netem = f
        .steps
        .iter()
        .any(|s| matches!(s.action, NetAction::Netem { .. }));
    if reset {
        out.push("S/net-connections-reset".into());
    }
    if netem {
        out.push("S/net-netem-applied".into());
    }
    out
}

/// A branch's decisions: the parent's up to the moment, re-drawn after it;
/// the argument of `tempo-dst redecide`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedrawnDecisions {
    pub nemesis_plan: Vec<ScheduledFault>,
    pub generations: Vec<Generation>,
    /// With the network nemesis: its faults, those started before the
    /// moment kept (omitted without it, so other commands are unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_plan: Option<Vec<NetFault>>,
    /// How many of each come from the parent.
    #[serde(skip)]
    /// Scheduled faults retained before the branch moment.
    #[serde(rename = "kept_kills")]
    pub kept_faults: usize,
    #[serde(skip)]
    pub kept_generations: usize,
    /// Network faults retained before the branch moment.
    #[serde(skip)]
    pub kept_net_faults: usize,
}

/// Re-draws the decisions of `parent` not yet applied `t_secs` after its
/// nemesis started: kills that fired before stay, as do the load generations
/// started before (generation 0, and one per restart done); the rest of the
/// plan is drawn like the guest planner would, starting after the moment,
/// from `seed`, with fresh txgen and spec seeds for the later generations.
/// The guest has the last word on what already happened
/// (`tempo-dst redecide` keeps every kill that fired).
pub fn redraw_decisions(parent: &Scenario, t_secs: f64, seed: u64) -> RedrawnDecisions {
    let plan0 = parent.nemesis.plan.clone().unwrap_or_default();
    let mut plan: Vec<ScheduledFault> = plan0
        .iter()
        .take_while(|k| (k.at_secs as f64) < t_secs)
        .copied()
        .collect();
    let kept_faults = plan.len();
    let restarted = plan
        .iter()
        .filter(|k| (k.end_secs() as f64) < t_secs)
        .count();
    let mut state = splitmix64(seed ^ BRANCH_DECISION_SALT);
    let mut next = || {
        state = splitmix64(state);
        state
    };
    let n = &parent.nemesis;
    if n.enabled {
        let gap = u64::from(n.min_gap_secs.max(1));
        let after = (t_secs.ceil() as u64).saturating_add(1);
        // Fault families are drawn like the guest's; none without them.
        let table = nemesis::draw_table(&scenario_nemesis_config(parent));
        let mut t = plan
            .last()
            .map_or(WARMUP_SECS, |k| k.end_secs() + gap)
            .max(after);
        while plan.len() < n.max_faults as usize {
            let at = t.saturating_add(next() % (gap + 1));
            let down = next() % (MAX_DOWN_SECS + 1);
            let fault = match &table {
                Some(table) => {
                    nemesis::draw_fault(table, &mut |lo, hi| nemesis::in_range(next(), lo, hi))
                }
                None => nemesis::Fault::ProcessKill,
            };
            let k = ScheduledFault {
                at_secs: at,
                down_secs: down,
                fault,
            };
            if k.end_secs().saturating_add(gap) > parent.run_secs {
                break;
            }
            plan.push(k);
            t = k.end_secs() + gap;
        }
    }
    let gens0 = &parent.load.generations;
    let kept_generations = if gens0.is_empty() {
        0
    } else {
        gens0.len().min(1 + restarted)
    };
    let mut generations = gens0[..kept_generations].to_vec();
    if !gens0.is_empty() {
        for _ in kept_generations..=plan.len() {
            generations.push(Generation {
                txgen_seed: next() >> 32,
                spec_seed: next(),
            });
        }
    }
    // Network faults: drawn from their own stream, so the kill plan and
    // generations above are what they were without the network nemesis.
    let mut kept_net_faults = 0;
    let network_plan = parent.network.as_ref().map(|n| {
        let plan0 = n.plan.clone().unwrap_or_default();
        let mut faults: Vec<NetFault> = plan0
            .iter()
            .take_while(|f| (f.at_secs as f64) < t_secs)
            .cloned()
            .collect();
        kept_net_faults = faults.len();
        let mut state = splitmix64(seed ^ BRANCH_NETWORK_SALT);
        let draw = |lo: u64, hi: u64| {
            state = splitmix64(state);
            lo + state % (hi - lo + 1)
        };
        let gap = u64::from(n.config.min_gap_secs.max(1));
        let from = faults
            .last()
            .map_or(netfault::NET_WARMUP_SECS, |f| f.end_secs() + gap)
            .max(t_secs.ceil() as u64 + 1);
        let left = n.config.max_faults.saturating_sub(faults.len() as u32);
        faults.extend(net_plan(
            &n.config,
            parent.run_secs,
            &kill_windows(&plan),
            from,
            left,
            draw,
        ));
        faults
    });
    RedrawnDecisions {
        nemesis_plan: plan,
        generations,
        network_plan,
        kept_faults,
        kept_generations,
        kept_net_faults,
    }
}

/// The droppable decisions of `s`: its kills (ids are plan indices).
pub fn host_decisions(s: &Scenario) -> Vec<HostDecision> {
    s.nemesis
        .plan
        .iter()
        .flatten()
        .enumerate()
        .map(|(i, f)| HostDecision {
            id: i as u32,
            // The fault family, as the canonical `Fault` names it.
            kind: serde_json::to_value(f.fault)
                .ok()
                .and_then(|v| v["kind"].as_str().map(String::from))
                .unwrap_or_else(|| "process-kill".into()),
            at_secs: VirtSecs::new(f.at_secs as f64).unwrap_or(VirtSecs::new(0.0).unwrap()),
            detail: format!("down {} s", f.down_secs),
        })
        .collect()
}

/// `s` without scheduled faults `ids`, and without the load generation each
/// dropped fault that restarts the node would have started.
pub fn drop_faults(s: &Scenario, ids: &[u32]) -> Scenario {
    let mut out = s.clone();
    let plan = s.nemesis.plan.clone().unwrap_or_default();
    out.nemesis.plan = Some(
        plan.iter()
            .enumerate()
            .filter(|(i, _)| !ids.contains(&(*i as u32)))
            .map(|(_, f)| *f)
            .collect(),
    );
    if !s.load.generations.is_empty() {
        // Generation 0 at start, then one per restarting fault, in order.
        let mut keep = vec![true];
        for (i, f) in plan.iter().enumerate() {
            if !f.fault.keeps_running() {
                keep.push(!ids.contains(&(i as u32)));
            }
        }
        out.load.generations = s
            .load
            .generations
            .iter()
            .enumerate()
            .filter(|(g, _)| keep.get(*g).copied().unwrap_or(true))
            .map(|(_, g)| *g)
            .collect();
    }
    out
}

/// The plan of `req` with the decisions as a typed scenario.
pub fn plan(req: &TempoPlanRequest) -> Result<Plan<Config, Scenario, Swarm>, String> {
    req.args.validate()?;
    if req.args.load == Load::Zones && cluster::VALIDATORS != 4 {
        return Err("load=zones requires a planner built with TEMPO_DST_VALIDATORS=4".into());
    }
    if req.args.cluster() && req.args.validators != cluster::VALIDATORS {
        return Err(format!(
            "validators={}: the generated genesis has {}",
            req.args.validators,
            cluster::VALIDATORS
        ));
    }
    if req.args.cluster() && req.args.reference {
        return Err("reference=true needs the dev node (validators=1, consensus=false)".into());
    }
    if req.args.validator_engine_diff && req.args.validators < 2 {
        return Err("validator_engine_diff=true needs at least two validators".into());
    }
    if req.args.validators == 1
        && (req.args.faults == Some(FaultFamily::Simultaneous)
            || req.args.faults.is_some_and(FaultFamily::is_network))
    {
        return Err("that fault family needs at least two validators".into());
    }
    if req.args.faults == Some(FaultFamily::PowerLoss) && req.args.storage.is_none() {
        return Err("faults=power-loss needs a storage layer (storage=lazyfs)".into());
    }
    if req.args.network_faults && req.args.validators == 1 && network_topology(&req.args).is_none()
    {
        return Err(
            "network_faults=true needs at least two validators or a load with a network topology (load=zones zone_sequencers=3)"
                .into(),
        );
    }
    if req.args.faults.is_some_and(FaultFamily::is_network) && !req.args.network_faults {
        return Err("a network fault family needs network_faults=true".into());
    }
    if req.decisions.as_ref().is_some_and(|s| {
        s.load.kind == Load::Zones && s.version != scenario::ZONES_SCENARIO_VERSION
    }) {
        return Err(
            "zones scenario predates the certified L1 cutover; record a new campaign".into(),
        );
    }
    let mut notes = Vec::new();
    let mut action = None;
    if let Some(ids) = &req.drop {
        let recorded = req
            .decisions
            .as_ref()
            .ok_or("drop needs recorded decisions")?;
        let s = drop_faults(recorded, ids);
        notes.push(format!("faults {ids:?} dropped"));
        let config = guest_config(&s, true);
        return Ok(Plan {
            config,
            required: required(&s),
            replays_exactly: s.replays_exactly(),
            run: RunParams {
                seed: s.seed,
                rng_seed: s.rng_seed,
                run_secs: s.run_secs,
                preempt: s.swarm.preempt,
                swarm: s.swarm,
            },
            host_decisions: host_decisions(&s),
            decisions: s,
            action: None,
            notes,
        });
    }
    let (mut s, config) = match (&req.decisions, req.redraw) {
        (None, Some(_)) => return Err("redraw needs the parent's decisions".into()),
        (None, None) => {
            check_explicit(&req.args)?;
            let s = scenario_for(
                &req.campaign,
                &req.args,
                req.seed,
                req.preempt,
                req.derivation_salt,
            );
            let deliver = s.decisions == Decisions::Explicit;
            let config = guest_config(&s, deliver);
            (s, config)
        }
        // Recorded decisions: delivered as they are, nothing derived.
        (Some(recorded), None) => (recorded.clone(), guest_config(recorded, true)),
        (Some(parent), Some(_)) if parent.cluster.is_some() => {
            return Err(
                "re-drawing a cluster fault plan (branch --vary decisions) is not supported yet"
                    .into(),
            );
        }
        (Some(parent), Some(r)) => {
            let d = redraw_decisions(parent, r.after.get(), r.seed);
            notes.push(format!(
                "decisions after the moment re-drawn: kills {:?} (kept {}), generations {:?} \
                 (kept {})",
                d.nemesis_plan, d.kept_faults, d.generations, d.kept_generations
            ));
            if let Some(faults) = &d.network_plan {
                notes.push(format!(
                    "network faults after the moment re-drawn: {faults:?} (kept {})",
                    d.kept_net_faults
                ));
            }
            if Some(&d.nemesis_plan) == parent.nemesis.plan.as_ref()
                && d.generations == parent.load.generations
                && d.network_plan.as_ref() == parent.network.as_ref().and_then(|n| n.plan.as_ref())
            {
                notes.push(
                    "nothing is left to re-draw after this moment (the next kill would not \
                     fit the run); only the randomness varies"
                        .into(),
                );
            }
            action = Some(GuestAction {
                hook: "redecide".into(),
                argument: Some(serde_json::to_string(&d).map_err(|e| e.to_string())?),
            });
            // What the guest applied, read back from its events.
            let mut s = parent.clone();
            s.nemesis.plan = None;
            s.load.generations.clear();
            if let Some(n) = s.network.as_mut() {
                n.plan = None;
            }
            (s, guest_config(parent, true))
        }
    };
    if let Some(rng) = req.rng_seed {
        s.rng_seed = rng;
    }
    Ok(Plan {
        host_decisions: host_decisions(&s),
        config,
        required: required(&s),
        replays_exactly: s.replays_exactly(),
        run: RunParams {
            seed: s.seed,
            rng_seed: s.rng_seed,
            run_secs: s.run_secs,
            preempt: s.swarm.preempt,
            swarm: s.swarm,
        },
        decisions: s,
        action,
        notes,
    })
}

/// `tempo-dst config`.
pub fn config(req: &TempoPlanRequest) -> Result<TempoPlan, String> {
    let p = plan(req)?;
    Ok(Plan {
        decisions: pretty(&p.decisions)?,
        config: p.config,
        run: p.run,
        required: p.required,
        replays_exactly: p.replays_exactly,
        action: p.action,
        notes: p.notes,
        host_decisions: p.host_decisions,
    })
}

/// Moments of a run from its events: nemesis kills and restarts, load
/// generations, re-decisions, each Always signature's first failure, 5 s
/// before it, and its last pass before it.
pub fn moments(events: &[crate::common::DstEvent]) -> Vec<Moment> {
    let mut out = Vec::new();
    for e in events {
        let ns = e.guest_time_ns as i64;
        let d = &e.detail;
        // Planned kills carry their index (load reloads do not); with the
        // zones load they may target the zone or its prover. Cluster faults
        // also carry an index but target a validator (the `validator` arms).
        let planned = d.get("index").is_some();
        let target = match e.container.as_deref() {
            Some(c) if c != crate::common::NODE_CONTAINER => format!(" ({c})"),
            _ => String::new(),
        };
        let validator = e.container.as_deref().and_then(ValidatorId::of_container);
        let mut push = |ns: i64, what: String| {
            out.push(Moment {
                guest_time_ns: ns,
                what,
            })
        };
        match (e.source.as_str(), e.kind.as_str()) {
            ("nemesis", "kill") if planned && validator.is_none() => {
                push(ns, format!("nemesis kill #{}{target}", d["index"]));
            }
            ("nemesis", "restart") if planned && validator.is_none() => {
                push(ns, format!("nemesis restart #{}{target}", d["index"]));
            }
            ("nemesis", "kill") if validator.is_some() => {
                push(
                    ns,
                    format!(
                        "cluster fault #{} kills {}",
                        d["index"],
                        e.container.as_deref().unwrap_or("?")
                    ),
                );
            }
            ("nemesis", "restart") if validator.is_some() => {
                push(
                    ns,
                    format!(
                        "cluster fault #{} restarts {}",
                        d["index"],
                        e.container.as_deref().unwrap_or("?")
                    ),
                );
            }
            ("nemesis", "redecide") => push(ns, "decisions re-drawn (branch)".into()),
            ("load", "generation") if d["generation"].as_u64() != Some(0) => {
                push(ns, format!("load generation {}", d["generation"]));
            }
            ("assertion", "first-failure") => {
                let sig = d["signature"].as_str().unwrap_or("?");
                push(ns, format!("first failure: {sig}"));
                push(
                    ns - 5_000_000_000,
                    format!("5 s before first failure: {sig}"),
                );
                if let Some(p) = d["last_pass_ns"].as_u64() {
                    push(p as i64, format!("last pass before failure: {sig}"));
                }
            }
            _ => {}
        }
    }
    out
}

/// The events of an events.jsonl (unparsable lines skipped).
fn parse_events(text: &str) -> Vec<crate::common::DstEvent> {
    text.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// `observe` with the decisions as a typed scenario.
pub fn observe_typed(req: &ObserveRequest<Scenario>, events: &str) -> Observation<Scenario> {
    let mut s = req.decisions.clone();
    s.record_observed(Observed::from_events(events));
    let decision_diff = req
        .original
        .as_ref()
        .map(|o| o.decision_diff(&s))
        .unwrap_or_default();
    let evs = parse_events(events);
    Observation {
        decisions: s,
        decision_diff,
        moments: moments(&evs),
        events_origin_ns: evs.first().map(|e| e.guest_time_ns),
    }
}

/// `tempo-dst observe`.
pub fn observe(req: &ObserveRequest<Scenario>) -> Result<Observation<Box<RawValue>>, String> {
    // A run that stopped under the driver has no events.
    let events = std::fs::read_to_string(&req.events_path).unwrap_or_default();
    let o = observe_typed(req, &events);
    Ok(Observation {
        decisions: pretty(&o.decisions)?,
        decision_diff: o.decision_diff,
        moments: o.moments,
        events_origin_ns: o.events_origin_ns,
    })
}

/// Reads a request: inline JSON, or `-` for stdin.
pub fn request<T: serde::de::DeserializeOwned>(arg: &str) -> Result<T, String> {
    let text = if arg == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).map_err(|e| e.to_string())?;
        s
    } else {
        arg.to_string()
    };
    serde_json::from_str(&text).map_err(|e| format!("bad request: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bedrock_dst_contract::{Redraw as RedrawReq, VirtSecs};
    use serde_json::{json, Value};
    use std::collections::BTreeSet;

    // Tests read the golden file, which is arbitrary JSON: `Value` here only.
    fn golden() -> Value {
        serde_json::from_str(include_str!("../testdata/planner-golden.json")).unwrap()
    }

    fn with_meaning(mut v: Value, meaning: &Value) -> Value {
        v["meaning"] = meaning.clone();
        v
    }

    /// Golden cases of a removed mode: `decisions=guest` (the nemesis plan
    /// drawn in the guest) or `spec_seeds_from_getrandom`. The planner now
    /// refuses to plan them live; what they recorded still replays.
    fn removed_mode(case: &Value) -> bool {
        case["workload_args"]["decisions"] == "guest"
            || case["workload_args"]["spec_seeds_from_getrandom"] == true
    }

    fn request_of(case: &Value) -> TempoPlanRequest {
        let mut args = case["workload_args"].clone();
        args.as_object_mut()
            .unwrap()
            .remove("spec_seeds_from_getrandom");
        PlanRequest {
            campaign: CampaignInfo {
                run_secs: case["campaign"]["run_secs"].as_u64().unwrap(),
                warm_blocks: case["campaign"]["warm_blocks"].as_u64().unwrap(),
                ..CampaignInfo::default()
            },
            args: serde_json::from_value(args).unwrap(),
            seed: case["seed"].as_u64().unwrap(),
            preempt: serde_json::from_value(case["preempt"].clone()).unwrap(),
            derivation_salt: case["derivation_salt"].as_u64(),
            decisions: None,
            redraw: None,
            rng_seed: None,
            drop: None,
        }
    }

    fn recorded(s: Scenario) -> TempoPlanRequest {
        PlanRequest {
            campaign: CampaignInfo::default(),
            args: TempoArgs::default(),
            seed: 0,
            preempt: Preempt::default(),
            derivation_salt: None,
            decisions: Some(s),
            redraw: None,
            rng_seed: None,
            drop: None,
        }
    }

    fn value<T: Serialize>(t: &T) -> Value {
        serde_json::to_value(t).unwrap()
    }

    /// The planner produces exactly what bedrock-dst produced before the
    /// workload contract (testdata generated from that driver): config.json
    /// bytes, scenario decisions and required coverage, live, after
    /// observing a run, on a scenario replay, and for re-drawn branches.
    /// Cases of a removed mode ([`removed_mode`]) are refused live and keep
    /// only their replay and re-draw checks.
    fn action_command(action: &GuestAction) -> (String, Value) {
        (
            action.hook.clone(),
            serde_json::from_str(action.argument.as_deref().unwrap()).unwrap(),
        )
    }

    fn recorded_action(command: &str) -> (String, Value) {
        let command = command.strip_prefix("tempo-dst ").unwrap();
        let (hook, argument) = command.split_once(" '").unwrap();
        (
            hook.into(),
            serde_json::from_str(argument.strip_suffix('\'').unwrap()).unwrap(),
        )
    }

    #[test]
    fn planner_matches_the_pre_contract_driver() {
        let g = golden();
        assert!(g["cases"].as_array().unwrap().len() > 100);
        check_golden(&g);
    }

    /// The fault modes' cases (`storage_faults`, ...): snapshots of this
    /// planner, made by [`regenerate_fault_golden`], in the same shape.
    #[test]
    fn fault_modes_match_their_golden_cases() {
        let g: Value =
            serde_json::from_str(include_str!("../testdata/planner-golden-faults.json")).unwrap();
        assert!(!g["cases"].as_array().unwrap().is_empty());
        assert_eq!(g["meaning"], golden()["meaning"]);
        check_golden(&g);
    }

    /// The fault-mode cases: (workload arguments, run_secs).
    fn fault_mode_args() -> Vec<(Value, u64)> {
        let mut out = Vec::new();
        for decisions in ["guest", "explicit"] {
            for extra in [
                json!({"load": "trie"}),
                json!({"load": "trie", "reference": true}),
                json!({"load": "transfers", "storage_fault_kinds": ["crash", "torn"]}),
                json!({"load": "tip20"}),
                json!({"load": "chain"}),
            ] {
                let mut w = json!({"decisions": decisions, "storage_faults": true});
                w.as_object_mut()
                    .unwrap()
                    .extend(extra.as_object().unwrap().clone());
                out.push((w, 180));
            }
        }
        out.push((json!({"load": "chain", "storage_faults": true}), 60));
        // Process faults (appended: the storage cases above stay as they
        // were made).
        for decisions in ["guest", "explicit"] {
            for extra in [
                json!({"load": "trie"}),
                json!({"load": "trie", "reference": true}),
                json!({"load": "chain", "process_fault_kinds": ["pause", "stop"]}),
                json!({"load": "tip20", "storage_faults": true}),
                json!({"load": "transfers", "finalize_stop_timeout_secs": 0}),
            ] {
                let mut w = json!({"decisions": decisions, "process_faults": true});
                w.as_object_mut()
                    .unwrap()
                    .extend(extra.as_object().unwrap().clone());
                out.push((w, 180));
            }
        }
        out
    }

    /// A case's name: its `bedrock-dst campaign` arguments.
    fn case_label(wargs: &Value, run_secs: u64) -> Vec<String> {
        let mut out = Vec::new();
        for (k, v) in wargs.as_object().unwrap() {
            let v = match v {
                Value::String(s) => s.clone(),
                Value::Array(a) => a
                    .iter()
                    .map(|x| x.as_str().unwrap().to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                v => v.to_string(),
            };
            out.extend(["--workload-arg".to_string(), format!("{k}={v}")]);
        }
        if run_secs != 180 {
            out.extend(["--run-secs".to_string(), run_secs.to_string()]);
        }
        out
    }

    /// Writes testdata/planner-golden-faults.json from the current planner:
    /// `TEMPO_DST_REGENERATE_GOLDEN=1 cargo test regenerate_fault_golden --
    /// --ignored`. Only for new fault modes: a change to an existing case's
    /// output is a change of meaning, to be justified.
    #[test]
    #[ignore]
    fn regenerate_fault_golden() {
        if std::env::var_os("TEMPO_DST_REGENERATE_GOLDEN").is_none() {
            return;
        }
        let mut cases = Vec::new();
        for (wargs, run_secs) in fault_mode_args() {
            let args = case_label(&wargs, run_secs);
            for seed in 0..3u64 {
                let wa: TempoArgs = serde_json::from_value(wargs.clone()).unwrap();
                let preempt = if seed == 1 {
                    Preempt {
                        period: 200_000,
                        seed: 77,
                    }
                } else {
                    Preempt::default()
                };
                let campaign =
                    json!({"run_secs": run_secs, "seed_start": 0, "seeds": 3, "warm_blocks": 10});
                let mut case = json!({
                    "args": args,
                    "campaign": campaign,
                    "derivation_salt": null,
                    "preempt": preempt,
                    "seed": seed,
                    "workload_args": value(&wa),
                });
                let out = config(&request_of(&case)).unwrap();
                let decisions: Scenario = serde_json::from_str(out.decisions.get()).unwrap();
                // The guest's events: its plan (as if drawn in the guest)
                // and the first load generation.
                let guest_plan = decisions
                    .nemesis
                    .plan
                    .clone()
                    .unwrap_or_else(|| nemesis_plan_for(&wa, run_secs, seed, 0x0067_7565_7374));
                let events = [
                    json!({"source": "nemesis", "kind": "plan", "container": "tempo",
                           "guest_time_ns": 1, "detail": {"kills": guest_plan}}),
                    json!({"source": "load", "kind": "generation", "container": "txgen",
                           "guest_time_ns": 2, "detail": {"generation": 0,
                           "txgen_seed": 99, "spec_seed": seed, "steps": 10, "kind": "x",
                           "spec_keccak": "0xab0", "slots": null}}),
                ]
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n");
                let obs = observe_typed(
                    &ObserveRequest {
                        decisions: decisions.clone(),
                        original: None,
                        events_path: String::new(),
                    },
                    &events,
                );
                let mut observed = value(&obs.decisions);
                observed.as_object_mut().unwrap().remove("meaning");
                let mut live_decisions = value(&decisions);
                live_decisions.as_object_mut().unwrap().remove("meaning");
                case["live"] = json!({
                    "config": serde_json::to_string(&out.config).unwrap(),
                    "decisions": live_decisions,
                    "required": out.required,
                });
                case["events"] = json!(events);
                case["observed"] = observed;
                let replay = plan(&recorded(obs.decisions.clone())).unwrap();
                case["replay"] = json!({
                    "config": serde_json::to_string(&replay.config).unwrap(),
                    "required": replay.required,
                    "replays_exactly": replay.replays_exactly,
                });
                let mut redraws = Vec::new();
                for (t_secs, rseed) in [(20.0, seed + 11), (75.5, seed + 12)] {
                    let mut req = recorded(obs.decisions.clone());
                    req.redraw = Some(RedrawReq {
                        after: VirtSecs::new(t_secs).unwrap(),
                        seed: rseed,
                    });
                    let b = plan(&req).unwrap();
                    let action = b.action.as_ref().unwrap();
                    redraws.push(json!({
                        "t_secs": t_secs,
                        "seed": rseed,
                        // The form `recorded_action` reads.
                        "command": format!(
                            "tempo-dst {} '{}'",
                            action.hook,
                            action.argument.as_deref().unwrap()
                        ),
                        "required": b.required,
                    }));
                }
                case["redraws"] = json!(redraws);
                cases.push(case);
            }
        }
        let g = json!({"meaning": golden()["meaning"], "cases": cases});
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/planner-golden-faults.json"
        );
        std::fs::write(path, golden_text(&g)).unwrap();
    }

    /// A golden file as text, one case per line like planner-golden.json, so
    /// a changed case is a one-line diff.
    fn golden_text(g: &Value) -> String {
        let cases = g["cases"].as_array().unwrap();
        let lines: Vec<String> = cases.iter().map(|c| c.to_string()).collect();
        format!(
            "{{\"meaning\":{},\"cases\":[\n{}\n]}}\n",
            g["meaning"],
            lines.join(",\n")
        )
    }

    /// Checks every case of a golden file (see
    /// [`planner_matches_the_pre_contract_driver`]).
    fn check_golden(g: &Value) {
        let cases = g["cases"].as_array().unwrap();
        // Cases of the removed modes keep only their replay checks; every
        // golden file still has live (explicit) ones.
        let live_cases = cases.iter().filter(|c| !removed_mode(c)).count();
        assert!(live_cases > 0 && live_cases < cases.len(), "{live_cases}");
        for case in cases {
            // Cases with the network nemesis or the zone cluster carry their
            // own field documentation; the rest share the file's.
            let meaning = case.get("meaning").unwrap_or(&g["meaning"]);
            let name = format!("{} seed {}", case["args"], case["seed"]);
            let observed = with_meaning(case["observed"].clone(), meaning);
            if removed_mode(case) {
                if case["workload_args"]["decisions"] == "guest" {
                    let err = config(&request_of(case)).unwrap_err();
                    assert!(err.contains("decisions=guest was removed"), "{name}");
                }
            } else {
                // Live: derived from the seed.
                let out = config(&request_of(case)).unwrap();
                let live = &case["live"];
                assert_eq!(
                    serde_json::to_string(&out.config).unwrap(),
                    live["config"].as_str().unwrap(),
                    "{name}: config"
                );
                let decisions: Scenario = serde_json::from_str(out.decisions.get()).unwrap();
                assert_eq!(
                    value(&decisions),
                    with_meaning(live["decisions"].clone(), meaning),
                    "{name}: decisions"
                );
                assert_eq!(value(&out.required), live["required"], "{name}: required");
                assert_eq!(out.run.preempt, decisions.swarm.preempt);
                assert_eq!(
                    (out.run.seed, out.run.rng_seed, out.run.run_secs),
                    (decisions.seed, decisions.rng_seed, decisions.run_secs)
                );

                // Observing the run's events.
                let obs = observe_typed(
                    &ObserveRequest {
                        decisions: decisions.clone(),
                        original: None,
                        events_path: String::new(),
                    },
                    case["events"].as_str().unwrap(),
                );
                assert_eq!(value(&obs.decisions), observed, "{name}: observed");
            }

            // Scenario replay: the recorded decisions, nothing derived.
            let rec: Scenario = serde_json::from_value(observed.clone()).unwrap();
            let replay = plan(&recorded(rec.clone())).unwrap();
            let r = &case["replay"];
            assert_eq!(
                serde_json::to_string(&replay.config).unwrap(),
                r["config"].as_str().unwrap(),
                "{name}: replay config"
            );
            assert_eq!(value(&replay.required), r["required"], "{name}");
            assert_eq!(json!(replay.replays_exactly), r["replays_exactly"]);
            assert_eq!(value(&replay.decisions), observed);

            // Branch re-draws.
            for rd in case["redraws"].as_array().unwrap() {
                let mut req = recorded(rec.clone());
                req.redraw = Some(RedrawReq {
                    after: VirtSecs::new(rd["t_secs"].as_f64().unwrap()).unwrap(),
                    seed: rd["seed"].as_u64().unwrap(),
                });
                let b = plan(&req).unwrap();
                assert_eq!(
                    action_command(b.action.as_ref().unwrap()),
                    recorded_action(rd["command"].as_str().unwrap()),
                    "{name}: redraw"
                );
                assert_eq!(value(&b.required), rd["required"], "{name}");
                let mut want = rec.clone();
                want.nemesis.plan = None;
                want.load.generations.clear();
                if let Some(n) = want.network.as_mut() {
                    n.plan = None;
                }
                assert_eq!(b.decisions, want);
            }
        }
    }

    /// The golden cases of the multi-sequencer zone and the network
    /// nemesis, one JSON line each, in the file's format (decisions without
    /// `meaning`, which each case carries). Appended to the golden file once
    /// (`cargo test -p tempo-dst print_network_golden_cases -- --ignored
    /// --nocapture`); the main golden test then pins them.
    #[test]
    #[ignore]
    fn print_network_golden_cases() {
        let arg_sets: &[(&[&str], u64)] = &[
            (
                &["load=zones", "zone_sequencers=3", "decisions=explicit"],
                180,
            ),
            (
                &[
                    "load=zones",
                    "zone_sequencers=3",
                    "network_faults=true",
                    "decisions=explicit",
                ],
                180,
            ),
            (
                &[
                    "load=zones",
                    "zone_sequencers=3",
                    "network_faults=true",
                    "decisions=explicit",
                ],
                300,
            ),
            (
                &["load=zones", "zone_sequencers=3", "network_faults=true"],
                240,
            ),
            (
                &[
                    "load=zones",
                    "zone_sequencers=3",
                    "network_faults=true",
                    "network_fault_kinds=[\"handoff-latency\",\"l1-cut-leader\"]",
                    "max_network_faults=2",
                    "network_min_gap_secs=40",
                    "decisions=explicit",
                ],
                300,
            ),
            (
                &[
                    "load=zones",
                    "zone_sequencers=3",
                    "network_faults=true",
                    "network_fault_kinds=[\"partition\",\"one-way-partition\",\"link-netem\"]",
                    "no_nemesis=true",
                    "decisions=explicit",
                ],
                240,
            ),
        ];
        for (args, run_secs) in arg_sets {
            let wa = parse_args(&ArgsRequest {
                config_file: None,
                args: args.iter().map(|s| s.to_string()).collect(),
            })
            .unwrap();
            for seed in 0..3u64 {
                let campaign = CampaignInfo {
                    run_secs: *run_secs,
                    warm_blocks: 10,
                    ..CampaignInfo::default()
                };
                let preempt = Preempt {
                    period: 200_000,
                    seed: splitmix64(seed),
                };
                let req = PlanRequest {
                    campaign,
                    args: wa.clone(),
                    seed,
                    preempt,
                    derivation_salt: None,
                    decisions: None,
                    redraw: None,
                    rng_seed: None,
                    drop: None,
                };
                let out = config(&req).unwrap();
                let decisions: Scenario = serde_json::from_str(out.decisions.get()).unwrap();
                // What the guest would report: its plans and generations.
                let kills = decisions.nemesis.plan.clone().unwrap_or_else(|| {
                    vec![ScheduledFault {
                        at_secs: 9,
                        down_secs: 2,
                        ..Default::default()
                    }]
                });
                let faults = decisions.network.as_ref().map(|n| {
                    n.plan.clone().unwrap_or_else(|| {
                        let mut x = seed;
                        net_plan(
                            &n.config,
                            *run_secs,
                            &kill_windows(&kills),
                            netfault::NET_WARMUP_SECS,
                            n.config.max_faults,
                            |lo, hi| {
                                x = splitmix64(x);
                                lo + x % (hi - lo + 1)
                            },
                        )
                    })
                });
                let mut events = vec![
                    json!({"source": "nemesis", "kind": "plan", "container": "tempo",
                    "guest_time_ns": 1, "detail": {"kills": kills}}),
                ];
                if let Some(f) = &faults {
                    events.push(
                        json!({"source": "network", "kind": "plan", "container": null,
                        "guest_time_ns": 1, "detail": {"faults": f}}),
                    );
                }
                for g in 0..=kills.len() as u64 {
                    events.push(json!({"source": "load", "kind": "generation", "container": "zones-load",
                        "guest_time_ns": 2 + g, "detail": {"generation": g, "kind": "x", "pid": 70 + g,
                        "slots": null, "spec_keccak": format!("0xab{g}"), "spec_seed": g,
                        "steps": 10, "txgen_seed": 99 + g}}));
                }
                let events: String = events.iter().map(|e| format!("{e}\n")).collect();
                let obs = observe_typed(
                    &ObserveRequest {
                        decisions: decisions.clone(),
                        original: None,
                        events_path: String::new(),
                    },
                    &events,
                );
                let rec = obs.decisions.clone();
                let replay = plan(&recorded(rec.clone())).unwrap();
                let redraws: Vec<Value> = [(25.5, 7u64), (100.0, 8)]
                    .iter()
                    .map(|&(t, s)| {
                        let mut r = recorded(rec.clone());
                        r.redraw = Some(RedrawReq {
                            after: VirtSecs::new(t).unwrap(),
                            seed: s,
                        });
                        let b = plan(&r).unwrap();
                        let a = b.action.unwrap();
                        json!({"t_secs": t, "seed": s,
                            "command": format!("tempo-dst {} '{}'", a.hook, a.argument.unwrap()),
                            "required": b.required})
                    })
                    .collect();
                let strip = |s: &Scenario| {
                    let mut v = value(s);
                    v.as_object_mut().unwrap().remove("meaning");
                    v
                };
                let case = json!({
                    "args": args,
                    "campaign": {"run_secs": run_secs, "seed_start": 0, "seeds": 1, "warm_blocks": 10},
                    "derivation_salt": null,
                    "events": events,
                    "live": {"config": serde_json::to_string(&out.config).unwrap(),
                             "decisions": strip(&decisions), "required": out.required},
                    "meaning": decisions.meaning,
                    "observed": strip(&obs.decisions),
                    "preempt": preempt,
                    "redraws": redraws,
                    "replay": {"config": serde_json::to_string(&replay.config).unwrap(),
                               "required": replay.required, "replays_exactly": replay.replays_exactly},
                    "seed": seed,
                    "workload_args": wa,
                });
                println!("GOLDEN {case}");
            }
        }
    }

    /// Prints golden cases for `trie_contracts=auto` (one compact JSON line
    /// each), made from the single-contract trie cases' campaigns, events
    /// and re-draw points; appended to testdata/planner-golden.json so the
    /// golden test pins the multi-contract planning too:
    /// `cargo test -p tempo-dst trie_contracts_golden_cases -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn trie_contracts_golden_cases() {
        let g = golden();
        let strip = |mut v: Value| {
            v.as_object_mut().unwrap().remove("meaning");
            v
        };
        for case in g["cases"].as_array().unwrap() {
            let args = case["args"].as_array().unwrap();
            let base = [json!("--load"), json!("trie"), json!("--decisions")];
            if args.len() != 4 || args[..3] != base {
                continue;
            }
            // Re-seeded so the cases draw several contracts (seeds 0 and 5
            // draw one); the guest seed-0 case is also kept as is.
            let explicit = args[3] == "explicit";
            let seeds: &[u64] = match (explicit, case["seed"].as_u64().unwrap()) {
                (false, 0) => &[0, 1],
                (false, _) => &[3],
                (true, 0) => &[2],
                (true, _) => &[6],
            };
            for &seed in seeds {
                let mut c = case.clone();
                c["seed"] = json!(seed);
                c["args"]
                    .as_array_mut()
                    .unwrap()
                    .extend([json!("--trie-contracts"), json!("auto")]);
                c["workload_args"]["trie_contracts"] = json!("auto");
                let out = config(&request_of(&c)).unwrap();
                let decisions: Scenario = serde_json::from_str(out.decisions.get()).unwrap();
                c["live"] = json!({
                    "config": serde_json::to_string(&out.config).unwrap(),
                    "decisions": strip(value(&decisions)),
                    "required": value(&out.required),
                });
                let obs = observe_typed(
                    &ObserveRequest {
                        decisions: decisions.clone(),
                        original: None,
                        events_path: String::new(),
                    },
                    c["events"].as_str().unwrap(),
                );
                c["observed"] = strip(value(&obs.decisions));
                let rec = obs.decisions;
                let replay = plan(&recorded(rec.clone())).unwrap();
                c["replay"] = json!({
                    "config": serde_json::to_string(&replay.config).unwrap(),
                    "required": value(&replay.required),
                    "replays_exactly": replay.replays_exactly,
                });
                for rd in c["redraws"].as_array_mut().unwrap() {
                    let mut req = recorded(rec.clone());
                    req.redraw = Some(RedrawReq {
                        after: VirtSecs::new(rd["t_secs"].as_f64().unwrap()).unwrap(),
                        seed: rd["seed"].as_u64().unwrap(),
                    });
                    let b = plan(&req).unwrap();
                    rd["command"] = json!(action_command(b.action.as_ref().unwrap()));
                    rd["required"] = value(&b.required);
                }
                println!("GOLDEN {}", serde_json::to_string(&c).unwrap());
            }
        }
    }

    /// The `trie_contracts=auto` golden cases: the planner draws contracts
    /// and senders per seed, records them in the swarm, delivers them in the
    /// trie config, and requires `S/multi-contract-block` with two or more.
    #[test]
    fn trie_contracts_auto_is_planned_per_seed() {
        let g = golden();
        let auto: Vec<_> = g["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["workload_args"]["trie_contracts"] == "auto")
            .collect();
        assert!(auto.len() >= 4, "{}", auto.len());
        for c in auto {
            let seed = c["seed"].as_u64().unwrap();
            let (n, s) = crate::trie_gen::draw(seed);
            let shape = &c["live"]["decisions"]["swarm"]["trie"];
            assert_eq!(
                (shape["contracts"].as_u64(), shape["senders"].as_u64()),
                (Some(n as u64), Some(s as u64))
            );
            let cfg: Value = serde_json::from_str(c["live"]["config"].as_str().unwrap()).unwrap();
            assert_eq!(cfg["trie"]["contracts"], n);
            assert_eq!(cfg["trie"]["senders"], s);
            let multi = c["live"]["required"]
                .as_array()
                .unwrap()
                .contains(&json!("S/multi-contract-block"));
            assert_eq!(multi, n >= 2, "seed {seed}");
        }
        // The args parse from the run.sh form, and 1 stays the default.
        let parse = |args: &[&str]| {
            parse_args(&ArgsRequest {
                config_file: None,
                args: args.iter().map(|s| s.to_string()).collect(),
            })
        };
        assert_eq!(
            parse(&["trie_contracts=auto"]).unwrap().trie_contracts,
            TrieContracts::Auto
        );
        assert_eq!(
            parse(&["trie_contracts=1"]).unwrap().trie_contracts,
            TrieContracts::One
        );
        assert!(parse(&["trie_contracts=2"]).is_err());
        assert!(value(&TempoArgs::default()).get("trie_contracts").is_none());
    }

    #[test]
    fn workload_args_parse_typed_and_reject_unknown_keys() {
        let g = golden();
        let case = g["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["args"] == json!([]))
            .unwrap()
            .clone();
        // No arguments: the historical defaults, except that the planner
        // makes every decision (and the getrandom spec seeds are gone).
        let defaults = parse_args(&ArgsRequest::default()).unwrap();
        let mut want = case["workload_args"].clone();
        want["decisions"] = json!("explicit");
        want.as_object_mut()
            .unwrap()
            .remove("spec_seeds_from_getrandom");
        assert_eq!(value(&defaults), want);
        let a = parse_args(&ArgsRequest {
            config_file: None,
            args: vec![
                "load=trie".into(),
                "reference=true".into(),
                "max_kills=1".into(),
                "decisions=explicit".into(),
            ],
        })
        .unwrap();
        assert_eq!(a.load, Load::Trie);
        assert!(a.reference);
        assert_eq!(a.max_faults, 1);
        assert_eq!(a.decisions, Decisions::Explicit);
        let err = |args: &[&str]| {
            parse_args(&ArgsRequest {
                config_file: None,
                args: args.iter().map(|s| s.to_string()).collect(),
            })
            .unwrap_err()
        };
        assert!(err(&["lod=trie"]).contains("unknown field `lod`"));
        assert!(err(&["load=tree"]).contains("unknown variant"));
        assert!(err(&["max_kills=many"]).contains("invalid type"));
        assert!(err(&["load"]).contains("KEY=VALUE"));
        assert!(err(&["decisions=guest"]).contains("was removed"));
        assert!(err(&["spec_seeds_from_getrandom=true"]).contains("unknown field"));
        // A config file, with arguments over it.
        let dir = std::env::temp_dir().join(format!("tempo-dst-args-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("w.json");
        std::fs::write(&f, r#"{"load": "tip20", "tip20_tps": 7}"#).unwrap();
        let a = parse_args(&ArgsRequest {
            config_file: Some(f.to_string_lossy().into()),
            args: vec!["tip20_tps=9".into()],
        })
        .unwrap();
        assert_eq!((a.load, a.tip20_tps), (Load::Tip20, 9));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn storage_fault_args_parse_and_reach_the_guest() {
        let parse = |args: &[&str]| {
            parse_args(&ArgsRequest {
                config_file: None,
                args: args.iter().map(|s| s.to_string()).collect(),
            })
            .unwrap()
        };
        let a = parse(&["storage_faults=true", "storage_fault_kinds=crash,torn"]);
        assert!(a.storage_faults);
        assert_eq!(a.storage_fault_kinds, ["crash", "torn"]);
        let b = parse(&[r#"storage_fault_kinds=["torn"]"#]);
        assert_eq!(b.storage_fault_kinds, ["torn"]);
        assert!(parse_args(&ArgsRequest {
            config_file: None,
            args: vec!["storage_fault_kinds=crash,slow".into()],
        })
        .is_err());
        let c = parse(&[
            "process_faults=true",
            "process_fault_kinds=pause,stop",
            "finalize_stop_timeout_secs=0",
        ]);
        assert!(c.process_faults);
        assert_eq!(c.process_fault_kinds, ["pause", "stop"]);
        assert_eq!(c.finalize_stop_timeout_secs, 0);
        // A plan that may be all pauses guarantees no restart.
        let mut chain = recorded(crate::scenario::tests::sample());
        chain.decisions = None;
        chain.args = TempoArgs {
            load: Load::Chain,
            ..c
        };
        let p = plan(&chain).unwrap();
        assert!(!p.required.iter().any(|s| s.0 == "S/chain-survived-restart"));
        assert_eq!(p.config.finalize_stop_timeout_secs, 0);
        // Off: the serialized arguments are the historical ones.
        assert!(!value(&TempoArgs::default())
            .as_object()
            .unwrap()
            .contains_key("storage_faults"));
        // Explicit decisions carry the drawn families into config.json, and
        // a replay delivers them as recorded.
        let mut req = recorded(crate::scenario::tests::sample());
        req.decisions = None;
        req.args = TempoArgs {
            decisions: Decisions::Explicit,
            ..a
        };
        let p = plan(&req).unwrap();
        let faults = p.config.nemesis_plan.clone().unwrap();
        assert!(faults.iter().all(|k| matches!(
            k.fault,
            nemesis::Fault::MachineCrash { .. } | nemesis::Fault::TornWrite { .. }
        )));
        assert!(p.config.nemesis.storage_faults);
        assert!(p
            .required
            .iter()
            .any(|s| s.0 == "S/durable-history-checked"));
        let replay = plan(&recorded(p.decisions)).unwrap();
        assert_eq!(replay.config.nemesis_plan.unwrap(), faults);
    }

    #[test]
    fn scenario_replay_ignores_a_changed_derivation() {
        let mut req = recorded(crate::scenario::tests::sample());
        req.decisions = None;
        req.seed = 6;
        req.args = TempoArgs {
            decisions: Decisions::Explicit,
            load: Load::Chain,
            ..Default::default()
        };
        // The original run: decisions derived, delivered, written out.
        let original = config(&req).unwrap();
        let delivered = serde_json::to_string(&original.config).unwrap();
        let file = original.decisions.get().to_string();

        // Later, the seed-to-decision derivation changes: re-deriving the
        // seed gives another run...
        let changed = TempoPlanRequest {
            derivation_salt: Some(0xbeef),
            ..req.clone()
        };
        let rederived = plan(&changed).unwrap();
        let orig: Scenario = serde_json::from_str(&file).unwrap();
        assert_ne!(rederived.decisions.nemesis.plan, orig.nemesis.plan);
        assert_ne!(serde_json::to_string(&rederived.config).unwrap(), delivered);
        // ...but the recorded decisions deliver exactly the original config,
        // without deriving anything (even under the changed derivation).
        let replayed = plan(&TempoPlanRequest {
            decisions: Some(orig),
            ..changed
        })
        .unwrap();
        assert_eq!(serde_json::to_string(&replayed.config).unwrap(), delivered);
        assert!(replayed.replays_exactly);

        // A guest-made scenario (recorded before decisions=guest was
        // removed) replays its observed plan explicitly...
        let guest = TempoPlanRequest {
            args: TempoArgs {
                load: Load::Chain,
                decisions: Decisions::Guest,
                ..Default::default()
            },
            ..req.clone()
        };
        assert!(plan(&guest).is_err());
        let mut recorded_guest = scenario_for(&guest.campaign, &guest.args, 6, req.preempt, None);
        assert!(recorded_guest.nemesis.plan.is_none());
        recorded_guest.decisions = Decisions::Guest;
        let events = r#"{"source":"nemesis","kind":"plan","container":"tempo","guest_time_ns":1,"detail":{"kills":[{"at_secs":20,"down_secs":1}]}}"#;
        let obs = observe_typed(
            &ObserveRequest {
                decisions: recorded_guest,
                original: None,
                events_path: String::new(),
            },
            events,
        );
        let replay = plan(&recorded(obs.decisions)).unwrap();
        assert_eq!(replay.config.nemesis_plan.unwrap()[0].at_secs, 20);
        assert!(!replay.replays_exactly);
        // A branch's fresh randomness is recorded in its decisions.
        let mut b = recorded(crate::scenario::tests::sample());
        b.rng_seed = Some(77);
        let p = plan(&b).unwrap();
        assert_eq!((p.run.rng_seed, p.decisions.rng_seed), (77, 77));
    }

    #[test]
    fn explicit_decisions_follow_the_guest_planner() {
        let wa = TempoArgs {
            decisions: Decisions::Explicit,
            load: Load::Trie,
            ..Default::default()
        };
        // Pinned, so a change to the derivation is noticed.
        let p = nemesis_plan_for(&wa, 180, 0, NEMESIS_SALT);
        assert_eq!(
            p.iter()
                .map(|k| (k.at_secs, k.down_secs))
                .collect::<Vec<_>>(),
            [(28, 3), (86, 0), (146, 3)]
        );
        for seed in 0..32 {
            let plan = nemesis_plan_for(&wa, 180, seed, NEMESIS_SALT);
            assert!(!plan.is_empty() && plan.len() <= 3, "{plan:?}");
            assert!(plan[0].at_secs >= WARMUP_SECS);
            for w in plan.windows(2) {
                assert!(w[1].at_secs >= w[0].at_secs + w[0].down_secs + 30);
            }
        }
        let quiet = TempoArgs {
            no_nemesis: true,
            ..wa
        };
        assert!(nemesis_plan_for(&quiet, 180, 0, NEMESIS_SALT).is_empty());
    }

    #[test]
    fn redraw_keeps_decisions_before_the_moment() {
        let mut p = crate::scenario::tests::sample();
        p.run_secs = 90;
        p.nemesis.min_gap_secs = 20;
        p.nemesis.plan = Some(vec![
            ScheduledFault {
                at_secs: 10,
                down_secs: 2,
                ..Default::default()
            },
            ScheduledFault {
                at_secs: 40,
                down_secs: 1,
                ..Default::default()
            },
        ]);
        p.load.generations = (0..3)
            .map(|g| Generation {
                txgen_seed: 99 + g,
                spec_seed: 3,
            })
            .collect();
        let plan0 = p.nemesis.plan.clone().unwrap();
        // 20 s in: kill 0 fired and restarted, so it and generations 0 and
        // 1 stay; everything after is re-drawn.
        let r = redraw_decisions(&p, 20.0, 1);
        assert_eq!((r.kept_faults, r.kept_generations), (1, 2));
        assert_eq!(r.nemesis_plan[0], plan0[0]);
        assert_eq!(r.generations[..2], p.load.generations[..2]);
        assert_eq!(r.generations.len(), r.nemesis_plan.len() + 1);
        for w in r.nemesis_plan.windows(2) {
            assert!(w[1].at_secs >= w[0].at_secs + w[0].down_secs + 20, "{r:?}");
        }
        for k in &r.nemesis_plan[1..] {
            assert!(k.at_secs > 20 && k.down_secs <= MAX_DOWN_SECS);
            assert!(k.at_secs + k.down_secs + 20 <= p.run_secs);
        }
        assert_eq!(redraw_decisions(&p, 20.0, 1), r);
        let others: BTreeSet<_> = (0..16)
            .map(|s| format!("{:?}", redraw_decisions(&p, 20.0, s).generations))
            .collect();
        assert!(others.len() > 8);
        let mid = redraw_decisions(&p, 11.0, 1);
        assert_eq!((mid.kept_faults, mid.kept_generations), (1, 1));
        let early = redraw_decisions(&p, 3.0, 2);
        assert_eq!((early.kept_faults, early.kept_generations), (0, 1));
        assert!(early.nemesis_plan.iter().all(|k| k.at_secs > 3));
        // After the last kill: nothing left to re-draw, and the planner says so.
        let late = redraw_decisions(&p, 80.0, 3);
        assert_eq!(late.nemesis_plan, plan0);
        assert_eq!(late.generations, p.load.generations);
        let mut req = recorded(p.clone());
        req.redraw = Some(RedrawReq {
            after: VirtSecs::new(80.0).unwrap(),
            seed: 3,
        });
        let out = plan(&req).unwrap();
        assert!(out.notes.iter().any(|n| n.contains("nothing is left")));
        assert_eq!(out.action.as_ref().unwrap().hook, "redecide");
        assert!(out.action.unwrap().argument.unwrap().starts_with('{'));
        let mut quiet = p.clone();
        quiet.nemesis.enabled = false;
        quiet.nemesis.plan = Some(vec![]);
        quiet.load.generations.clear();
        let q = redraw_decisions(&quiet, 20.0, 4);
        assert!(q.nemesis_plan.is_empty() && q.generations.is_empty());
        // A redraw without the parent is an error.
        req.decisions = None;
        assert!(plan(&req).is_err());
    }

    #[test]
    fn observe_reports_decision_diffs_and_moments() {
        let s = crate::scenario::tests::sample();
        let s_ns = 1_000_000_000u64;
        let events = [
            format!(r#"{{"source":"load","kind":"generation","container":"txgen","guest_time_ns":{},"detail":{{"generation":0,"txgen_seed":99,"spec_seed":3,"steps":1}}}}"#, 1000 * s_ns),
            format!(r#"{{"source":"nemesis","kind":"plan","container":"tempo","guest_time_ns":{},"detail":{{"kills":[{{"at_secs":10,"down_secs":2}}]}}}}"#, 1000 * s_ns),
            format!(r#"{{"source":"nemesis","kind":"kill","container":"tempo","guest_time_ns":{},"detail":{{"index":0}}}}"#, 1010 * s_ns),
            format!(r#"{{"source":"nemesis","kind":"kill","container":"txgen","guest_time_ns":{},"detail":{{}}}}"#, 1012 * s_ns),
            format!(r#"{{"source":"nemesis","kind":"restart","container":"tempo","guest_time_ns":{},"detail":{{"index":0}}}}"#, 1012 * s_ns),
            format!(r#"{{"source":"load","kind":"generation","container":"txgen","guest_time_ns":{},"detail":{{"generation":1,"txgen_seed":100,"spec_seed":3,"steps":1}}}}"#, 1013 * s_ns),
            format!(r#"{{"source":"assertion","kind":"first-failure","guest_time_ns":{},"detail":{{"signature":"E5/storage-root-mismatch","last_pass_ns":{}}}}}"#, 1030 * s_ns, 1029 * s_ns),
        ]
        .join("\n");
        let req = |original| ObserveRequest {
            decisions: s.clone(),
            original,
            events_path: String::new(),
        };
        let out = observe_typed(&req(None), &events);
        let what: Vec<_> = out.moments.iter().map(|m| m.what.as_str()).collect();
        assert_eq!(
            what,
            [
                "nemesis kill #0",
                "nemesis restart #0",
                "load generation 1",
                "first failure: E5/storage-root-mismatch",
                "5 s before first failure: E5/storage-root-mismatch",
                "last pass before failure: E5/storage-root-mismatch",
            ]
        );
        assert_eq!(out.moments[0].guest_time_ns, 1010 * s_ns as i64);
        assert_eq!(out.moments[4].guest_time_ns, 1025 * s_ns as i64);
        assert_eq!(out.events_origin_ns, Some(1000 * s_ns));
        assert!(out.decision_diff.is_empty());
        // A replay that saw another plan differs from its original.
        let replay = observe_typed(
            &req(Some(out.decisions.clone())),
            &events.replace(r#""at_secs":10"#, r#""at_secs":11"#),
        );
        assert_eq!(replay.decision_diff.len(), 1, "{:?}", replay.decision_diff);
        assert!(replay.decision_diff[0].starts_with("nemesis plan"));
    }

    fn cluster_args(extra: &[&str]) -> Result<TempoArgs, String> {
        let mut args = vec!["load=zones", "zone_sequencers=3"];
        args.extend(extra);
        parse_args(&ArgsRequest {
            config_file: None,
            args: args.into_iter().map(String::from).collect(),
        })
    }

    #[test]
    fn network_faults_need_the_cluster() {
        let err = |args: &[&str]| {
            parse_args(&ArgsRequest {
                config_file: None,
                args: args.iter().map(|s| s.to_string()).collect(),
            })
            .unwrap_err()
        };
        assert!(err(&["network_faults=true"]).contains("zone_sequencers=3"));
        assert!(err(&["load=zones", "network_faults=true"]).contains("zone_sequencers=3"));
        assert!(err(&["zone_sequencers=3"]).contains("load=zones"));
        assert!(err(&["load=zones", "zone_sequencers=2"]).contains("want 1 or 3"));
        assert!(err(&[
            "load=zones",
            "zone_sequencers=3",
            "network_fault_kinds=[\"flood\"]"
        ])
        .contains("unknown variant"));
        let a =
            cluster_args(&["network_faults=true", "network_fault_kinds=[\"partition\"]"]).unwrap();
        assert_eq!(a.network().unwrap().kinds, [NetFaultKind::Partition]);
        assert_eq!(
            cluster_args(&["network_faults=true"])
                .unwrap()
                .network()
                .unwrap()
                .kinds,
            default_net_kinds(&cluster_args(&[]).unwrap())
        );
    }

    fn cluster_plan(extra: &[&str], run_secs: u64, seed: u64) -> Plan<Config, Scenario, Swarm> {
        plan(&PlanRequest {
            campaign: CampaignInfo {
                run_secs,
                ..CampaignInfo::default()
            },
            args: cluster_args(extra).unwrap(),
            seed,
            preempt: Preempt::default(),
            derivation_salt: None,
            decisions: None,
            redraw: None,
            rng_seed: None,
            drop: None,
        })
        .unwrap()
    }

    #[test]
    fn one_validator_runs_consensus() {
        if cluster::VALIDATORS != 1 {
            return;
        }
        let args = TempoArgs {
            consensus: true,
            no_nemesis: true,
            ..TempoArgs::default()
        };
        let p = plan(&PlanRequest {
            campaign: CampaignInfo::default(),
            args: args.clone(),
            seed: 0,
            preempt: Preempt::default(),
            derivation_salt: None,
            decisions: None,
            redraw: None,
            rng_seed: None,
            drop: None,
        })
        .unwrap();
        assert!(p.config.cluster.is_some());
        assert_eq!(
            crate::topology::Topology::from_args(&args)
                .validators()
                .count(),
            1
        );
        assert!(!FaultFamily::drawable(None, false).contains(&FaultFamily::Simultaneous));
    }

    #[test]
    fn explicit_network_plans_avoid_kills_and_require_their_coverage() {
        for seed in 0..16 {
            let p = cluster_plan(&["network_faults=true", "decisions=explicit"], 300, seed);
            let kills = p.decisions.nemesis.plan.clone().unwrap();
            let faults = p.decisions.network.as_ref().unwrap().plan.clone().unwrap();
            assert_eq!(p.config.network_plan.as_ref(), Some(&faults));
            assert!(p.config.zone_cluster());
            for f in &faults {
                for k in &kills {
                    assert!(
                        f.end_secs() + netfault::KILL_MARGIN_BEFORE_SECS <= k.at_secs
                            || f.at_secs
                                >= k.at_secs + k.down_secs + netfault::KILL_MARGIN_AFTER_SECS
                    );
                }
                for sig in network_coverage(f) {
                    assert!(p.required.iter().any(|r| r.0.as_str() == sig), "{sig}");
                }
            }
            assert!(p
                .required
                .iter()
                .any(|r| r.0.as_str() == "S/cluster-converged"));
            // Kills rotate over the L1, the three sequencers and the prover.
            let targets: BTreeSet<_> = (0..5).map(|i| kill_target(&p.config, i)).collect();
            assert_eq!(targets.len(), 5);
        }
        // decisions=guest was removed (explicit-only): `parse_args` rejects it
        // and `plan` errors on it (see the recorded-guest replay test), so the
        // planner always delivers the network plan explicitly above.
    }

    #[test]
    fn redraws_keep_started_network_faults_and_redraw_the_rest() {
        let p = cluster_plan(&["network_faults=true", "decisions=explicit"], 400, 2);
        let parent = p.decisions;
        let faults = parent.network.as_ref().unwrap().plan.clone().unwrap();
        assert!(faults.len() >= 2, "{faults:?}");
        let t = faults[0].at_secs as f64 + 1.0;
        let r = redraw_decisions(&parent, t, 5);
        let got = r.network_plan.clone().unwrap();
        assert_eq!(r.kept_net_faults, 1);
        assert_eq!(got[0], faults[0]);
        netfault::validate(&got).unwrap();
        for f in &got[1..] {
            assert!(f.at_secs as f64 > t);
        }
        assert_eq!(redraw_decisions(&parent, t, 5), r);
        assert_ne!(redraw_decisions(&parent, t, 6).network_plan, r.network_plan);
        // The redecide argument carries it; without the network nemesis it
        // is absent.
        let mut req = recorded(parent.clone());
        req.redraw = Some(RedrawReq {
            after: VirtSecs::new(t).unwrap(),
            seed: 5,
        });
        let b = plan(&req).unwrap();
        assert!(b.action.unwrap().argument.unwrap().contains("network_plan"));
        let mut quiet = parent.clone();
        quiet.network = None;
        assert!(redraw_decisions(&quiet, t, 5).network_plan.is_none());
    }

    #[test]
    fn dropping_kills_replans_without_them() {
        let mut p = crate::scenario::tests::sample();
        use crate::common::Fault;
        p.nemesis.plan = Some(vec![
            ScheduledFault {
                at_secs: 10,
                down_secs: 2,
                fault: Fault::ProcessKill,
            },
            // Keeps the node running: no restart, no load generation.
            ScheduledFault {
                at_secs: 25,
                down_secs: 0,
                fault: Fault::Pause { pause_secs: 5 },
            },
            ScheduledFault {
                at_secs: 40,
                down_secs: 1,
                fault: Fault::ProcessKill,
            },
        ]);
        p.load.generations = (0..3)
            .map(|g| Generation {
                txgen_seed: 99 + g,
                spec_seed: 3,
            })
            .collect();
        let hd = host_decisions(&p);
        assert_eq!(hd.len(), 3);
        assert_eq!(
            (hd[2].id, hd[2].kind.as_str(), hd[2].at_secs.get()),
            (2, "process-kill", 40.0)
        );
        assert_eq!(hd[1].kind, "pause");
        // Dropping the pause leaves every generation.
        assert_eq!(drop_faults(&p, &[1]).load.generations, p.load.generations);
        let mut req = recorded(p.clone());
        req.drop = Some(vec![0]);
        let out = plan(&req).unwrap();
        let kills = out.config.nemesis_plan.as_ref().unwrap();
        assert_eq!(kills.len(), 2);
        assert_eq!(kills[1].at_secs, 40);
        // Generation 1 (after kill 0's restart) goes with it.
        assert_eq!(
            out.decisions
                .load
                .generations
                .iter()
                .map(|g| g.txgen_seed)
                .collect::<Vec<_>>(),
            [99, 101]
        );
        assert_eq!(out.host_decisions.len(), 2);
        // Live plans list their kills too.
        let mut live = recorded(p);
        live.decisions = None;
        live.args.load = Load::Trie;
        let lp = plan(&live).unwrap();
        assert_eq!(
            lp.host_decisions.len(),
            lp.decisions.nemesis.plan.as_ref().unwrap().len()
        );
        req.decisions = None;
        assert!(plan(&req).is_err());
    }

    #[test]
    fn configs_never_contain_a_single_quote() {
        // `tempo-dst start '<config>'` relies on it.
        for load in [Load::Transfers, Load::Trie, Load::Tip20, Load::Chain] {
            let mut req = recorded(crate::scenario::tests::sample());
            req.decisions = None;
            req.args = TempoArgs {
                load,
                reference: true,
                ..Default::default()
            };
            let out = config(&req).unwrap();
            assert!(!serde_json::to_string(&out.config).unwrap().contains('\''));
        }
    }

    /// The cluster planner's configs, swarm records and required coverage,
    /// pinned one case per line (`TEMPO_DST_UPDATE_GOLDEN=1` rewrites).
    #[test]
    fn cluster_plans_match_their_golden() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/planner-golden-cluster.ndjson"
        );
        let mut lines = Vec::new();
        let families = [
            "",
            "faults=single",
            "faults=quick",
            "faults=simultaneous",
            "faults=rolling",
            "faults=whole-cluster",
            "storage=lazyfs",
            "faults=power-loss storage=lazyfs",
            "network_faults=true",
            "faults=delayed-peer network_faults=true",
            "faults=partition-heal network_faults=true",
        ];
        for family in families {
            for extra in [
                "load=transfers",
                "load=trie cooldown=default timeouts=prod",
                "no_nemesis=true load=chain",
            ] {
                for seed in 0..3 {
                    let args: Vec<String> = ["validators=4"]
                        .into_iter()
                        .chain(family.split(' '))
                        .chain(extra.split(' '))
                        .filter(|a| !a.is_empty())
                        .map(String::from)
                        .collect();
                    let mut req = recorded(crate::scenario::tests::sample());
                    req.decisions = None;
                    req.seed = seed;
                    req.campaign.run_secs = 300;
                    req.args = parse_args(&ArgsRequest {
                        config_file: None,
                        args: args.clone(),
                    })
                    .unwrap();
                    let out = config(&req).unwrap();
                    lines.push(
                        serde_json::to_string(&json!({
                            "args": args,
                            "seed": seed,
                            "config": out.config,
                            "required": out.required,
                            "swarm": out.run.swarm,
                        }))
                        .unwrap(),
                    );
                }
            }
        }
        // The certified L1 follower (`follower=true`) attached to the cluster
        // under several loads: its deterministic offline-window plan and the
        // tempo#8263 coverage, pinned and replayable across any load.
        for extra in [
            "load=transfers follower=true",
            "load=trie follower=true",
            "load=tip20 follower=true",
            "load=chain follower=true",
            "load=trie follower=true faults=rolling",
        ] {
            for seed in 0..3 {
                let args: Vec<String> = ["validators=4", "consensus=true"]
                    .into_iter()
                    .chain(extra.split(' '))
                    .filter(|a| !a.is_empty())
                    .map(String::from)
                    .collect();
                let mut req = recorded(crate::scenario::tests::sample());
                req.decisions = None;
                req.seed = seed;
                req.campaign.run_secs = 300;
                req.args = parse_args(&ArgsRequest {
                    config_file: None,
                    args: args.clone(),
                })
                .unwrap();
                let out = config(&req).unwrap();
                lines.push(
                    serde_json::to_string(&json!({
                        "args": args,
                        "seed": seed,
                        "config": out.config,
                        "required": out.required,
                        "swarm": out.run.swarm,
                    }))
                    .unwrap(),
                );
            }
        }
        let text = lines.join("\n") + "\n";
        if std::env::var_os("TEMPO_DST_UPDATE_GOLDEN").is_some() {
            std::fs::write(path, &text).unwrap();
        }
        let want = std::fs::read_to_string(path).unwrap();
        for (got, want) in text.lines().zip(want.lines()) {
            assert_eq!(got, want);
        }
        assert_eq!(text.lines().count(), want.lines().count());
        // The cluster plan replays from its decisions.
        let mut req = recorded(crate::scenario::tests::sample());
        req.decisions = None;
        req.args = parse_args(&ArgsRequest {
            config_file: None,
            args: vec!["validators=4".into()],
        })
        .unwrap();
        let live = plan(&req).unwrap();
        let replay = plan(&recorded(live.decisions.clone())).unwrap();
        assert_eq!(replay.config.cluster, live.config.cluster);
        assert!(live.required.iter().any(|r| r.0 == "S/mesh-formed"));
        // Re-drawing a cluster plan, the reference node and other cluster
        // sizes are refused.
        let mut branch = recorded(live.decisions);
        branch.redraw = Some(RedrawReq {
            after: VirtSecs::new(20.0).unwrap(),
            seed: 1,
        });
        assert!(plan(&branch).is_err());
        req.args.reference = true;
        assert!(plan(&req).is_err());
        req.args.reference = false;
        req.args.faults = Some(FaultFamily::PowerLoss);
        assert!(plan(&req).is_err());
        req.args.faults = None;
        req.args.validators = 3;
        assert!(plan(&req).is_err());
        // The certified follower's offline-window plan is a pure function of
        // the seed and replays byte-identically from its decisions.
        let mut follow = recorded(crate::scenario::tests::sample());
        follow.decisions = None;
        follow.campaign.run_secs = 300;
        follow.args = parse_args(&ArgsRequest {
            config_file: None,
            args: vec![
                "validators=4".into(),
                "consensus=true".into(),
                "follower=true".into(),
                "load=trie".into(),
            ],
        })
        .unwrap();
        let live = plan(&follow).unwrap();
        let plan_a = live.config.follower_plan.clone().unwrap();
        assert!(
            !plan_a.is_empty(),
            "a follower run draws at least one window"
        );
        assert_eq!(
            plan_a[0].trigger,
            crate::follower::FollowerTrigger::SnapshotRestore,
            "the first, deepest window is always a snapshot restore"
        );
        assert!(
            live.required
                .iter()
                .any(|r| r.0 == "S/follower-snapshot-restored")
                && live.required.iter().any(|r| r.0 == "S/follower-caught-up")
                && live
                    .required
                    .iter()
                    .any(|r| r.0 == "S/follower-syncing-observed"),
            "the #8263 catch-up coverage is required when a follower runs"
        );
        let replay = plan(&recorded(live.decisions.clone())).unwrap();
        assert_eq!(replay.config.follower_plan, live.config.follower_plan);
        assert_eq!(replay.config, live.config);
        // Same seed, same plan; a different seed draws a different one.
        let again = plan(&follow).unwrap();
        assert_eq!(again.config.follower_plan, live.config.follower_plan);
        follow.seed = 7;
        let other = plan(&follow).unwrap();
        assert_ne!(other.config.follower_plan, live.config.follower_plan);
    }

    /// The per-validator engine differential (`validator_engine_diff=true`):
    /// its configs, swarm records and required coverage, pinned one case per
    /// line (`TEMPO_DST_UPDATE_GOLDEN=1` rewrites). The off cases stay in
    /// `planner-golden-cluster.ndjson`, byte-identical.
    #[test]
    fn cluster_engine_diff_plans_match_their_golden() {
        // Only meaningful at the default genesis size (two or more validators).
        if cluster::VALIDATORS < 2 {
            return;
        }
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/planner-golden-engine-diff.ndjson"
        );
        let mut lines = Vec::new();
        for extra in [
            "load=transfers",
            "load=trie",
            "faults=whole-cluster load=transfers",
            "no_nemesis=true load=chain",
        ] {
            for seed in 0..3 {
                let args: Vec<String> = ["validators=4", "validator_engine_diff=true"]
                    .into_iter()
                    .chain(extra.split(' '))
                    .filter(|a| !a.is_empty())
                    .map(String::from)
                    .collect();
                let mut req = recorded(crate::scenario::tests::sample());
                req.decisions = None;
                req.seed = seed;
                req.campaign.run_secs = 300;
                req.args = parse_args(&ArgsRequest {
                    config_file: None,
                    args: args.clone(),
                })
                .unwrap();
                let out = config(&req).unwrap();
                let cluster = out.config.cluster.as_ref().unwrap();
                // The feature is on: one profile per validator, and the
                // {Optimized, Simple} pair is always present.
                assert!(cluster.engine_diff());
                assert_eq!(
                    cluster.engine_profiles.len(),
                    usize::from(cluster::VALIDATORS)
                );
                assert_eq!(
                    cluster.engine_profiles[0],
                    cluster::EngineProfile::Optimized
                );
                assert_eq!(cluster.engine_profiles[1], cluster::EngineProfile::Simple);
                // Its coverage is required.
                assert!(out
                    .required
                    .iter()
                    .any(|r| r.0 == "S/validator-engine-diff-checked"));
                assert!(out.run.swarm.cluster.unwrap().engine_diff);
                lines.push(
                    serde_json::to_string(&json!({
                        "args": args,
                        "seed": seed,
                        "config": out.config,
                        "required": out.required,
                        "swarm": out.run.swarm,
                    }))
                    .unwrap(),
                );
            }
        }
        let text = lines.join("\n") + "\n";
        if std::env::var_os("TEMPO_DST_UPDATE_GOLDEN").is_some() {
            std::fs::write(path, &text).unwrap();
        }
        let want = std::fs::read_to_string(path).unwrap();
        for (got, want) in text.lines().zip(want.lines()) {
            assert_eq!(got, want);
        }
        assert_eq!(text.lines().count(), want.lines().count());
        // The assignment is a pure function of the workload seed: every run
        // seed of a campaign gets the same profiles, and a replay matches.
        let mut req = recorded(crate::scenario::tests::sample());
        req.decisions = None;
        req.args = parse_args(&ArgsRequest {
            config_file: None,
            args: vec!["validators=4".into(), "validator_engine_diff=true".into()],
        })
        .unwrap();
        let a = plan(&req).unwrap();
        let mut req2 = recorded(crate::scenario::tests::sample());
        req2.decisions = None;
        req2.seed = 7;
        req2.args = req.args.clone();
        let b = plan(&req2).unwrap();
        assert_eq!(
            a.config.cluster.unwrap().engine_profiles,
            b.config.cluster.unwrap().engine_profiles
        );
        // validator_engine_diff with one validator is rejected.
        let bad = parse_args(&ArgsRequest {
            config_file: None,
            args: vec!["validator_engine_diff=true".into()],
        });
        assert!(bad.is_err() || bad.unwrap().validate().is_err());
    }
    #[test]
    fn zones_rejects_the_old_dev_reference_and_generic_cluster_switches() {
        for option in [
            "reference=true",
            "validators=4",
            "consensus=true",
            "storage=lazyfs",
        ] {
            assert!(
                parse_args(&ArgsRequest {
                    config_file: None,
                    args: vec!["load=zones".into(), option.into()]
                })
                .is_err(),
                "{option}"
            );
        }
        let args = parse_args(&ArgsRequest {
            config_file: None,
            args: vec!["load=zones".into()],
        })
        .unwrap();
        assert!(!args.cluster());
        let cfg = Config {
            zones: true,
            seed: 4,
            ..Default::default()
        };
        assert_eq!(kill_target(&cfg, 0), crate::common::NODE_CONTAINER);
        assert_eq!(kill_target(&cfg, 1), crate::zones::ZONE_CONTAINER);
        assert_eq!(kill_target(&cfg, 2), crate::zones::PROVER_CONTAINER);
    }
    #[test]
    fn old_zones_scenarios_are_not_reinterpreted_as_certified_runs() {
        let args = TempoArgs {
            load: Load::Zones,
            ..Default::default()
        };
        let campaign = CampaignInfo {
            run_secs: 180,
            seed_start: 0,
            seeds: 1,
            warm_blocks: 10,
            ..Default::default()
        };
        let mut s = scenario_for(&campaign, &args, 0, Preempt::default(), None);
        assert_eq!(s.version, scenario::ZONES_SCENARIO_VERSION);
        s.version = scenario::SCENARIO_VERSION;
        let mut request = recorded(s);
        request.args = args;
        assert!(plan(&request).is_err());
    }

    /// The historical-RPC oracles (`historical=true`): its configs, swarm
    /// records and required coverage, pinned one case per line
    /// (`TEMPO_DST_UPDATE_GOLDEN=1` rewrites). The off cases stay in the other
    /// goldens, byte-identical, because `historical` is omitted when false.
    #[test]
    fn historical_plans_match_their_golden() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/planner-golden-historical.ndjson"
        );
        // Single-node (dev node) and cluster cases; a storage-fault case so the
        // after-unwind coverage is required.
        let cases: &[&[&str]] = &[
            &["historical=true", "load=trie"],
            &["historical=true", "storage_faults=true", "load=trie"],
            &["historical=true", "storage_faults=true", "load=transfers"],
            &["validators=4", "historical=true", "load=trie"],
            &[
                "validators=4",
                "historical=true",
                "validator_engine_diff=true",
                "load=trie",
            ],
            &[
                "validators=4",
                "historical=true",
                "faults=power-loss",
                "storage=lazyfs",
                "load=trie",
            ],
            &[
                "validators=4",
                "historical=true",
                "no_nemesis=true",
                "load=chain",
            ],
        ];
        let mut lines = Vec::new();
        for case in cases {
            // The cluster cases need the default genesis size.
            if case.contains(&"validators=4") && cluster::VALIDATORS != 4 {
                continue;
            }
            for seed in 0..3 {
                let args: Vec<String> = case.iter().map(|s| s.to_string()).collect();
                let mut req = recorded(crate::scenario::tests::sample());
                req.decisions = None;
                req.seed = seed;
                req.campaign.run_secs = 300;
                req.args = parse_args(&ArgsRequest {
                    config_file: None,
                    args: args.clone(),
                })
                .unwrap();
                let out = config(&req).unwrap();
                // The feature is on in the config the guest reads.
                assert!(out.config.historical, "{args:?}: config.historical");
                // E3h's restart coverage is required whenever a kill is planned.
                let required: BTreeSet<&str> = out.required.iter().map(|r| r.0.as_str()).collect();
                if !args.contains(&"no_nemesis=true".to_string()) {
                    assert!(
                        required.contains("S/historical-reread-after-restart"),
                        "{args:?}: {required:?}"
                    );
                }
                lines.push(
                    serde_json::to_string(&json!({
                        "args": args,
                        "seed": seed,
                        "config": out.config,
                        "required": out.required,
                        "swarm": out.run.swarm,
                    }))
                    .unwrap(),
                );
            }
        }
        let text = lines.join("\n") + "\n";
        if std::env::var_os("TEMPO_DST_UPDATE_GOLDEN").is_some() {
            std::fs::write(path, &text).unwrap();
        }
        let want = std::fs::read_to_string(path).unwrap();
        for (got, want) in text.lines().zip(want.lines()) {
            assert_eq!(got, want);
        }
        assert_eq!(text.lines().count(), want.lines().count());
    }

    /// The generic valid-state-root invariant and statemix workload
    /// (`verify_state_root`, `load=statemix`): configs, swarm records and
    /// required coverage, pinned one case per line (`TEMPO_DST_UPDATE_GOLDEN=1`
    /// rewrites). The off cases stay in the other goldens, byte-identical,
    /// because `statemix`/`verify_state_root` are omitted when false.
    #[test]
    fn statemix_plans_match_their_golden() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/planner-golden-statemix.ndjson"
        );
        // Single-node statemix (verify_state_root auto-on), statemix with a
        // kill, the invariant on the trie load, and cluster cases with the
        // same-height probe and the engine differential.
        let cases: &[&[&str]] = &[
            &["load=statemix"],
            &["load=statemix", "storage_faults=true"],
            &["verify_state_root=true", "load=trie"],
            &["validators=4", "load=statemix"],
            &[
                "validators=4",
                "load=statemix",
                "validator_engine_diff=true",
            ],
        ];
        let mut lines = Vec::new();
        for case in cases {
            if case.contains(&"validators=4") && cluster::VALIDATORS != 4 {
                continue;
            }
            for seed in 0..3 {
                let args: Vec<String> = case.iter().map(|s| s.to_string()).collect();
                let mut req = recorded(crate::scenario::tests::sample());
                req.decisions = None;
                req.seed = seed;
                req.campaign.run_secs = 300;
                req.args = parse_args(&ArgsRequest {
                    config_file: None,
                    args: args.clone(),
                })
                .unwrap();
                let out = config(&req).unwrap();
                // The invariant is on in the config the guest reads.
                assert!(out.config.verify_state_root, "{args:?}: verify_state_root");
                let required: BTreeSet<&str> = out.required.iter().map(|r| r.0.as_str()).collect();
                assert!(
                    required.contains("S/state-root-verified"),
                    "{args:?}: {required:?}"
                );
                if args.iter().any(|a| a.contains("statemix"))
                    || args.contains(&"load=trie".to_string())
                {
                    assert!(
                        required.contains("S/state-root-recomputed-checked"),
                        "{args:?}: {required:?}"
                    );
                }
                if args.contains(&"validators=4".to_string()) {
                    assert!(
                        required.contains("S/same-height-root-checked"),
                        "{args:?}: {required:?}"
                    );
                } else {
                    assert!(out.config.statemix || args.contains(&"load=trie".to_string()));
                }
                lines.push(
                    serde_json::to_string(&json!({
                        "args": args,
                        "seed": seed,
                        "config": out.config,
                        "required": out.required,
                        "swarm": out.run.swarm,
                    }))
                    .unwrap(),
                );
            }
        }
        let text = lines.join("\n") + "\n";
        if std::env::var_os("TEMPO_DST_UPDATE_GOLDEN").is_some() {
            std::fs::write(path, &text).unwrap();
        }
        let want = std::fs::read_to_string(path).unwrap();
        for (got, want) in text.lines().zip(want.lines()) {
            assert_eq!(got, want);
        }
        assert_eq!(text.lines().count(), want.lines().count());
    }
}
