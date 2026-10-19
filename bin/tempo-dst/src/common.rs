// SPDX-License-Identifier: GPL-2.0

//! Shared plumbing: run config, the assertion and event sinks, guest time, and
//! node RPC.
//!
//! Everything here must stay deterministic under Bedrock: time comes from the
//! guest's emulated clock, and randomness (`rand`, seeded via getrandom) from
//! Bedrock's controlled getrandom stream.

use std::{
    cell::Cell, collections::BTreeMap, fs::OpenOptions, io::Write, process::Command, time::Duration,
};

use alloy_primitives::{Address, Bytes, B256};
use bedrock_assertions::{Assertion, Condition, Location};
use nix::time::{clock_gettime, ClockId};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::storage::{Discard, Torn};

pub const NODE_CONTAINER: &str = "tempo";
const RPC_URL: &str = "http://127.0.0.1:8545";
/// Overrides [`RPC_URL`], for running checks against a node outside Bedrock.
const RPC_URL_ENV: &str = "TEMPO_DST_RPC";
/// E7 reference node (compose service `tempo-ref`, `reference=true`).
pub const REFERENCE_CONTAINER: &str = "tempo-ref";
pub const REFERENCE_RPC_URL: &str = "http://127.0.0.1:8547";
pub const CONFIG_PATH: &str = "/bedrock/in/config.json";
pub const EVENTS_PATH: &str = "/bedrock/events.jsonl";
pub const OUT_DIR: &str = "/bedrock/out";

/// Fields in alphabetical order (see [`LoadConfig`]); the fault fields are
/// left out while off, so configs without them are unchanged.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct NemesisConfig {
    pub enabled: bool,
    /// Maximum scheduled faults, including faults that leave the node alive.
    #[serde(rename = "max_kills")]
    pub max_faults: u32,
    pub min_gap_secs: u32,
    /// Process fault families to draw from (`kill`, `pause`, `throttle`,
    /// `stop`); empty means all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_fault_kinds: Vec<String>,
    /// Draw process-level faults too: pause/resume (cgroup freezer), CPU
    /// throttling, and graceful stop/start (see `nemesis`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub process_faults: bool,
    /// Fault families the storage nemesis draws from (`kill`, `crash`,
    /// `error`, `slow`); empty means all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_fault_kinds: Vec<String>,
    /// The datadir is on LazyFS (`storage`): draw machine crashes, storage
    /// errors and slow syncs too, and run E11.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub storage_faults: bool,
}

/// What one planned nemesis fault does (see `nemesis`). Serialized with a
/// `kind` tag; a plain process kill is left out of plans, events and
/// scenarios, which therefore read as they did before fault families.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Fault {
    /// SIGKILL; the page cache, so every write, survives.
    #[default]
    ProcessKill,
    /// Power loss: un-synced writes discarded, then a cold reopen.
    MachineCrash { discard: Discard },
    /// A torn write armed for `window_secs`: if it fires, LazyFS keeps part
    /// of a write (or of a run of writes) and crashes itself; at the window's
    /// end the machine crashes either way (every other un-synced write lost).
    TornWrite { torn: Torn, window_secs: u64 },
    /// Frozen for `pause_secs`, then resumed; never killed or restarted.
    Pause { pause_secs: u64 },
    /// Held to `quota_pct` of a CPU for `window_secs`; never restarted.
    Throttle { quota_pct: u32, window_secs: u64 },
    /// `podman stop -t timeout_secs`, then started after the downtime.
    GracefulStop { timeout_secs: u64 },
}

impl Fault {
    /// Whether this fault is the ordinary SIGKILL case, without storage or process windows.
    pub fn is_process_kill(&self) -> bool {
        *self == Fault::ProcessKill
    }

    /// Seconds between the fault's start and the crash; for process faults,
    /// the longest the fault lasts (a graceful stop: its timeout).
    pub fn window_secs(&self) -> u64 {
        match self {
            Fault::ProcessKill | Fault::MachineCrash { .. } => 0,
            Fault::TornWrite { window_secs, .. } | Fault::Throttle { window_secs, .. } => {
                *window_secs
            }
            Fault::Pause { pause_secs } => *pause_secs,
            Fault::GracefulStop { timeout_secs } => *timeout_secs,
        }
    }

    /// Whether the node keeps running through the fault (no kill, no
    /// restart, no new load generation).
    pub fn keeps_running(&self) -> bool {
        matches!(self, Fault::Pause { .. } | Fault::Throttle { .. })
    }

    /// The machine crash that ends the fault, if any.
    pub fn discard(&self) -> Option<Discard> {
        match self {
            Fault::ProcessKill
            | Fault::Pause { .. }
            | Fault::Throttle { .. }
            | Fault::GracefulStop { .. } => None,
            Fault::MachineCrash { discard } => Some(*discard),
            Fault::TornWrite { .. } => Some(Discard::All),
        }
    }
}

/// One fault of an explicit [`Config::nemesis_plan`], as the nemesis logs it
/// in its `plan` event.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScheduledFault {
    /// Seconds after nemesis start the fault begins; the node goes down
    /// `fault.window_secs()` later.
    pub at_secs: u64,
    pub down_secs: u64,
    #[serde(default, skip_serializing_if = "Fault::is_process_kill")]
    pub fault: Fault,
}

impl ScheduledFault {
    /// Seconds after nemesis start the node is restarted.
    pub fn end_secs(&self) -> u64 {
        self.at_secs + self.fault.window_secs() + self.down_secs
    }
}

impl Default for NemesisConfig {
    fn default() -> Self {
        NemesisConfig {
            enabled: true,
            max_faults: 3,
            min_gap_secs: 20,
            process_fault_kinds: Vec::new(),
            process_faults: false,
            storage_fault_kinds: Vec::new(),
            storage_faults: false,
        }
    }
}

/// txgen load container; `count == 0` disables it.
///
/// Fields serialize in alphabetical order for stable config bytes.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct LoadConfig {
    pub count: u64,
    /// A derived generation draws its spec seed from getrandom (Bedrock's
    /// controlled stream, so it is on the input tape) instead of using the
    /// run seed. See [`Config::draw_load_generation`].
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub draw_spec_seeds: bool,
    /// Explicit per-generation inputs, indexed by load generation (0 at
    /// branch start, one more per node restart). A generation past the end
    /// is derived ([`Config::load_generation`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub generations: Vec<LoadGeneration>,
    /// Load image; empty means the plain txgen image.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub image: String,
    pub seed: u64,
    /// txgen spec inside the image; empty means the image's default.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub spec: String,
    pub tps: u64,
}

/// The inputs of one load generation: everything its txgen run and generated
/// spec (`trie_gen`, `tip20`, `cob_gen`) are a function of, besides the
/// load's count and the trie slots.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct LoadGeneration {
    /// Seed of the generated spec (the run seed when derived).
    pub spec_seed: u64,
    /// `TXGEN_SEED` (txgen's own transaction randomness).
    pub txgen_seed: u64,
}

/// A RawStorage contract whose storage root E5 checks against an
/// independent reference at every block.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct TrieConfig {
    pub address: String,
    /// Generated loads only (`trie_contracts=auto`): pool contracts
    /// written (`trie_gen::plan`; the first is `address`), as the planner
    /// drew them (`trie_gen::draw`). 0 (absent) means the single-contract
    /// load.
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub contracts: usize,
    /// The load spec comes from `trie_gen` over explicit `slots` (a
    /// scenario's recorded slots), instead of `load.spec`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub generated: bool,
    /// Slots the oracles read and prove. Empty: generated from the run seed
    /// (`trie_gen::slots`), along with the load spec.
    /// Writers of the planned contracts (0: one).
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub senders: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub slots: Vec<u64>,
}

fn is_zero_usize(n: &usize) -> bool {
    *n == 0
}

impl TrieConfig {
    /// Whether the load spec (and, without explicit slots, the slots) come
    /// from `trie_gen`.
    pub fn generated(&self) -> bool {
        self.generated || self.slots.is_empty()
    }
}

/// A ChainOfBlocks contract whose hash chain E9 checks (see `cob`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CobConfig {
    pub address: String,
}

impl Config {
    /// The trie config with generated slots filled in.
    pub fn trie(&self) -> Option<TrieConfig> {
        let mut trie = self.trie.clone()?;
        if trie.slots.is_empty() {
            trie.slots = crate::trie_gen::slots(self.seed);
        }
        Some(trie)
    }

    /// The generated trie load's contracts and writers; `None` without a
    /// trie load or with explicit slots.
    pub fn trie_plan(&self) -> Option<crate::trie_gen::TriePlan> {
        self.trie.as_ref().filter(|t| t.generated())?;
        let trie = self.trie()?;
        let mut plan = crate::trie_gen::plan(self.seed, trie.contracts.max(1), trie.senders.max(1));
        // Contract 0 is the configured contract, with its (possibly a
        // scenario's recorded) slots.
        plan.replace_first_slots(trie.slots);
        Some(plan)
    }

    /// Whether the trie load writes the contract pool (`trie_contracts=auto`).
    pub fn trie_pool(&self) -> bool {
        self.trie
            .as_ref()
            .is_some_and(|t| t.generated() && t.contracts > 0)
    }

    /// The contracts E5/E6/E7 check, with generated slots filled in: one
    /// per planned contract (the first at the configured address), or the
    /// configured one with explicit slots.
    pub fn tries(&self) -> Vec<TrieConfig> {
        let Some(trie) = self.trie() else {
            return Vec::new();
        };
        let Some(plan) = self.trie_plan().filter(|p| p.contract_count() > 1) else {
            return vec![trie];
        };
        plan.into_contracts()
            .into_iter()
            .enumerate()
            .map(|(c, contract)| TrieConfig {
                address: if c == 0 {
                    trie.address.clone()
                } else {
                    contract.address
                },
                slots: contract.slots,
                ..Default::default()
            })
            .collect()
    }

    /// The generic valid-state-root oracle's workload contract and the slots it
    /// writes, for the independent storage-root recompute (Strand A): the
    /// statemix Mutator (`statemix_gen::written_slots` — the complete candidate
    /// set, including the per-generation bulk-write range, not just the per-seed
    /// pool), else the first trie contract, else none. `None` when
    /// `verify_state_root` is off. The oracle still verifies the touched-set
    /// proofs without a workload.
    pub fn state_root_workload(&self) -> Option<(alloy_primitives::Address, Vec<u64>)> {
        if !self.verify_state_root {
            return None;
        }
        if self.statemix {
            let addr = crate::statemix_gen::CONTRACT.parse().ok()?;
            return Some((addr, crate::statemix_gen::written_slots(self.seed)));
        }
        let trie = self.tries().into_iter().next()?;
        let addr = trie.address.parse().ok()?;
        Some((addr, trie.slots))
    }

    /// Load generation `generation`'s inputs: explicit in
    /// `load.generations`, else derived from the run (txgen seed
    /// `load.seed + generation`, spec seed the run seed).
    pub fn load_generation(&self, generation: u64) -> LoadGeneration {
        usize::try_from(generation)
            .ok()
            .and_then(|g| self.load.generations.get(g).copied())
            .unwrap_or(LoadGeneration {
                txgen_seed: self.load.seed + generation,
                spec_seed: self.seed,
            })
    }

    /// [`load_generation`](Self::load_generation) for the generation being
    /// started: with `load.draw_spec_seeds`, a derived generation's spec seed
    /// is drawn now from getrandom (served by Bedrock and recorded on the
    /// input tape under this process's pid). Call once per generation.
    pub fn draw_load_generation(&self, generation: u64) -> LoadGeneration {
        let mut inputs = self.load_generation(generation);
        let explicit = usize::try_from(generation).is_ok_and(|g| g < self.load.generations.len());
        if self.load.draw_spec_seeds && !explicit {
            let mut buf = [0u8; 8];
            let read = std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf));
            match read {
                Ok(()) => inputs.spec_seed = u64::from_le_bytes(buf),
                Err(e) => eprintln!("draw spec seed: {e}; using the run seed"),
            }
        }
        inputs
    }
}

/// `/bedrock/in/config.json`: the run config the planner makes and the
/// `start` hook installs (the contract's guest config).
/// Fields are in alphabetical order (see [`LoadConfig`]).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Config {
    /// The four-validator cluster in place of the dev-mode node
    /// (`validators=4`): its variants and fault plan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<crate::cluster::ClusterConfig>,
    /// Chain-of-blocks load and E9.
    pub cob: Option<CobConfig>,
    /// `podman stop -t` for finalize's graceful stops (E4, E7); left out at
    /// the default.
    #[serde(skip_serializing_if = "is_default_stop_timeout")]
    pub finalize_stop_timeout_secs: u64,
    /// A certified L1 consensus follower runs alongside the validators
    /// (`follower=true` on `validators=N consensus=true`): the generic
    /// detector for the tempo#8263 catch-up class. Omitted when off, so other
    /// configs are unchanged. Zones always run a follower through their own
    /// topology (signalled by `zones`), so this stays false there.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub follower: bool,
    /// The follower's offline-window fault plan (`crate::follower`), made by
    /// the planner and executed by the cluster nemesis. Omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follower_plan: Option<Vec<crate::follower::FollowerFault>>,
    /// Guest seconds the head may stall before liveness fails.
    pub liveness_secs: u64,
    pub load: LoadConfig,
    pub nemesis: NemesisConfig,
    /// Explicit kill schedule (planner-made decisions, `bedrock-dst replay
    /// --scenario`). Absent: drawn from Bedrock-controlled randomness
    /// (`nemesis::plan`) per `nemesis`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nemesis_plan: Option<Vec<ScheduledFault>>,
    /// Network nemesis (`network_faults=true`). Omitted when off, so other
    /// configs are unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<crate::netfault::NetworkConfig>,
    /// Explicit network fault plan (planner-made decisions, scenario
    /// replays). Absent: drawn in the guest after the kill plan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_plan: Option<Vec<crate::netfault::NetFault>>,
    /// The E7 reference node runs (compose service `tempo-ref`).
    pub reference: bool,
    /// Virtual seconds the branch runs before finalize.
    pub run_secs: u64,
    /// The branch's seed (the driver's `--seeds` index).
    pub seed: u64,
    /// The run's swarm record (driver-side choices such as preemption),
    /// recorded so the run is self-describing; the guest ignores it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swarm: Option<crate::campaign::Swarm>,
    /// TIP-20 load (`tip20::spec`) and its E8 oracle.
    pub tip20: bool,
    pub trie: Option<TrieConfig>,
    /// The campaign's txgen seed (as `load.seed`); informational.
    pub workload_seed: u64,
    /// Zones load (`load=zones`): zone sequencer and prover services,
    /// txgen's zone-backing driver, and E12. Omitted when false, so other
    /// loads' configs are unchanged.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub zones: bool,
    /// Zones witness-fault family: the prover mutates each batch's witness and
    /// checks the SPF rejects it. Omitted when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub zones_witness_faults: bool,
    /// Zones L1-fault family: the prover rebuilds each batch's witness through
    /// a byzantine L1 proxy and checks it rejects falsified L1 state. Omitted
    /// when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub zones_l1_faults: bool,
    /// Zones TIP-403 policy family: a driver changes pathUSD's policy on L1 and
    /// sends allowed and forbidden zone transfers; E12 checks enforcement and
    /// conservation. Omitted when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub zones_policy: bool,
    /// With `zones`: the multi-sequencer cluster's size (`zone_sequencers`,
    /// 3), else 0 (the single sequencer). Omitted when 0.
    #[serde(skip_serializing_if = "is_zero")]
    pub zone_sequencers: u32,
    /// Run the historical-RPC oracles (`historical=true`): E3h (what the node
    /// served about an old block before a kill, it serves identically after
    /// the restart) on every run, and, with two or more validators, E7h (the
    /// cross-validator historical differential). Omitted when false, so other
    /// loads' configs are unchanged. See `historical`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub historical: bool,
    /// Generic state-mutation load (`load=statemix`): the Mutator contract and
    /// its generated mutation spec. Omitted when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub statemix: bool,
    /// Generic valid-state-root invariant (`verify_state_root`, Strand A):
    /// per-block, per-node, recompute the affected state from scratch and assert
    /// consistency with the header state root (`crate::state_root`). Auto-on with
    /// `load=statemix`. Omitted when false, so other loads' configs are unchanged.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub verify_state_root: bool,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Finalize's graceful-stop timeout unless configured.
pub const DEFAULT_STOP_TIMEOUT_SECS: u64 = 120;

fn is_default_stop_timeout(t: &u64) -> bool {
    *t == DEFAULT_STOP_TIMEOUT_SECS
}

impl Default for Config {
    fn default() -> Self {
        Config {
            cluster: None,
            cob: None,
            finalize_stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
            follower: false,
            follower_plan: None,
            liveness_secs: 60,
            load: LoadConfig::default(),
            nemesis: NemesisConfig::default(),
            nemesis_plan: None,
            network: None,
            network_plan: None,
            reference: false,
            run_secs: 120,
            seed: 0,
            swarm: None,
            tip20: false,
            trie: None,
            workload_seed: 0,
            zones: false,
            zones_witness_faults: false,
            zones_l1_faults: false,
            zones_policy: false,
            zone_sequencers: 0,
            historical: false,
            statemix: false,
            verify_state_root: false,
        }
    }
}

impl Config {
    /// Whether this is the multi-sequencer zone cluster.
    pub fn zone_cluster(&self) -> bool {
        self.zones && self.zone_sequencers > 1
    }

    pub fn load() -> Config {
        match std::fs::read_to_string(CONFIG_PATH) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| panic!("bad {CONFIG_PATH}: {e}")),
            Err(_) => Config::default(),
        }
    }

    /// The RPC endpoint load generation `generation` sends to: a validator
    /// (rotating per generation) in a cluster, else `None` (the dev node).
    pub fn load_rpc_url(&self, generation: u64) -> Option<&'static str> {
        self.cluster
            .as_ref()
            .map(|c| c.load_target(generation).rpc_url())
    }

    /// Rejects an explicit nemesis plan whose kills overlap or go backwards
    /// (the nemesis sleeps from one restart to the next kill), and an
    /// inconsistent cluster plan.
    pub fn validate(&self) -> Result<(), String> {
        if self.zones
            && (self.cluster.is_some() || self.reference || crate::cluster::VALIDATORS != 4)
        {
            return Err(
                "zones uses its own certified L1 topology; cluster and reference are incompatible"
                    .into(),
            );
        }
        if self.follower && (self.cluster.is_none() || self.zones) {
            return Err(
                "a generic certified follower needs the consensus cluster and is implied by zones"
                    .into(),
            );
        }
        if self.follower_plan.is_some() && !self.follower {
            return Err("a follower plan needs follower=true".into());
        }
        if let Some(c) = &self.cluster {
            c.validate()?;
        }
        let mut free = 0;
        for (i, k) in self.nemesis_plan.iter().flatten().enumerate() {
            if k.at_secs < free {
                return Err(format!(
                    "nemesis_plan[{i}] at {}s is before the previous restart at {free}s",
                    k.at_secs
                ));
            }
            free = k.end_secs();
        }
        crate::netfault::validate(self.network_plan.as_deref().unwrap_or_default())
    }
}

/// SIGKILLs every other running `tempo-dst <sub>` for `sub` in `subs`
/// (matched on argv, so a shell whose command line merely names them is
/// spared) and waits until they are gone.
pub fn stop_subcommands(subs: &[&str]) -> std::io::Result<()> {
    let me = std::process::id();
    let pids: Vec<u32> = std::fs::read_dir("/proc")?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| pid != me)
        .filter(|pid| {
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
            args.len() >= 2
                && args[0].ends_with(b"tempo-dst")
                && subs.iter().any(|s| args[1] == s.as_bytes())
        })
        .collect();
    for pid in &pids {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(*pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    for pid in &pids {
        for _ in 0..200 {
            // Gone, or a zombie waiting for init.
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let zombie = stat
                .rsplit(')')
                .next()
                .is_some_and(|s| s.trim_start().starts_with('Z'));
            if stat.is_empty() || zombie {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(())
}

/// Guest `CLOCK_MONOTONIC` in nanoseconds, derived from Bedrock's emulated TSC.
pub fn guest_time_ns() -> u64 {
    let t = clock_gettime(ClockId::CLOCK_MONOTONIC).expect("clock_gettime");
    t.tv_sec() as u64 * 1_000_000_000 + t.tv_nsec() as u64
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DstEvent {
    pub source: String,
    pub kind: String,
    pub container: Option<String>,
    pub guest_time_ns: u64,
    #[serde(default)]
    pub detail: Value,
}

fn append_line(path: &str, line: &str) {
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            let _ = f.write_all(format!("{line}\n").as_bytes());
        }
        Err(e) => eprintln!("cannot append to {path}: {e}"),
    }
}

pub fn emit_event(source: &str, kind: &str, container: Option<&str>, detail: Value) {
    let event = DstEvent {
        source: source.into(),
        kind: kind.into(),
        container: container.map(Into::into),
        guest_time_ns: guest_time_ns(),
        detail,
    };
    append_line(EVENTS_PATH, &serde_json::to_string(&event).unwrap());
}

pub fn read_events() -> Vec<DstEvent> {
    std::fs::read_to_string(EVENTS_PATH)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Records an assertion. `signature` is a stable id the driver dedups by; it
/// prefixes the message.
pub fn assert_always(cond: Condition, component: &str, signature: &str, detail: &str) {
    note_always(cond.evaluate(), component, signature, detail);
    write_assertion(
        component,
        Assertion::always(cond, message(signature, detail), location(component)),
    );
}

pub fn assert_sometimes(cond: Condition, component: &str, signature: &str, detail: &str) {
    write_assertion(
        component,
        Assertion::sometimes(cond, message(signature, detail), location(component)),
    );
}

/// Per Always signature in this process: guest time of its last pass, and
/// whether it has failed.
static ALWAYS_SEEN: std::sync::Mutex<BTreeMap<String, (Option<u64>, bool)>> =
    std::sync::Mutex::new(BTreeMap::new());

/// Emits an `assertion`/`first-failure` event the first time an Always
/// signature fails in this process, with the guest time of its last pass
/// (if it ever passed): when it went wrong, for picking a moment to branch
/// from (`bedrock-dst moments`). Assertion timestamps are wall-clock times;
/// this event records monotonic guest time for a precise branch moment.
fn note_always(ok: bool, component: &str, signature: &str, detail: &str) {
    let mut seen = ALWAYS_SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let entry = seen.entry(signature.to_string()).or_default();
    if ok {
        entry.0 = Some(guest_time_ns());
        return;
    }
    if entry.1 {
        return;
    }
    entry.1 = true;
    let last_pass_ns = entry.0;
    drop(seen);
    let detail: String = detail.chars().take(200).collect();
    emit_event(
        "assertion",
        "first-failure",
        None,
        json!({
            "signature": signature,
            "component": component,
            "detail": detail,
            "last_pass_ns": last_pass_ns,
        }),
    );
}

fn location(component: &str) -> Location {
    Location::new(format!("tempo-dst/{component}"), 0, 0)
}

fn message(signature: &str, detail: &str) -> String {
    if detail.is_empty() {
        signature.to_string()
    } else {
        format!("{signature}: {detail}")
    }
}

fn write_assertion(component: &str, a: Assertion) {
    let path = format!("{}/tempo-dst-{component}.jsonl", crate::assertions::DIR);
    append_line(&path, &serde_json::to_string(&a).unwrap());
}

thread_local! {
    /// `None`: the primary node ([`RPC_URL`], or `TEMPO_DST_RPC`).
    static RPC_TARGET: Cell<Option<&'static str>> = const { Cell::new(None) };
}

/// Runs `f` with this thread's node queries sent to `url` instead of the
/// primary node (E7 asks the reference node the same questions).
pub fn with_rpc_url<T>(url: &'static str, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<&'static str>);
    impl Drop for Restore {
        fn drop(&mut self) {
            RPC_TARGET.set(self.0);
        }
    }
    let _restore = Restore(RPC_TARGET.replace(Some(url)));
    f()
}

/// This thread's node RPC endpoint (see [`with_rpc_url`]).
fn rpc_url() -> String {
    match RPC_TARGET.get() {
        Some(url) => url.into(),
        None => std::env::var(RPC_URL_ENV).unwrap_or_else(|_| RPC_URL.into()),
    }
}

pub(crate) fn rpc(method: &str, params: Value) -> Result<Value, String> {
    rpc_at(&rpc_url(), method, params, Duration::from_secs(10))
}

/// One JSON-RPC call to `url` (any node: the L1, a zone sequencer).
pub(crate) fn rpc_at(
    url: &str,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<Value, String> {
    let resp: Value = ureq::post(url)
        .timeout(timeout)
        .send_json(json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    match resp.get("error") {
        Some(err) => Err(err.to_string()),
        None => resp
            .get("result")
            .cloned()
            .ok_or_else(|| "no result".into()),
    }
}

/// One JSON-RPC batch: each call's result, or its error. `Err` when the
/// request itself fails (e.g. the node is down).
pub fn rpc_batch(calls: &[(&str, Value)]) -> Result<Vec<Result<Value, String>>, String> {
    if calls.is_empty() {
        return Ok(Vec::new());
    }
    let batch: Vec<Value> = calls
        .iter()
        .enumerate()
        .map(|(id, (method, params))| {
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        })
        .collect();
    let resp: Vec<Value> = ureq::post(&rpc_url())
        .timeout(Duration::from_secs(20))
        .send_json(Value::Array(batch))
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    let mut out = vec![Err("missing batch response".to_string()); calls.len()];
    for r in resp {
        let Some(id) = r["id"]
            .as_u64()
            .map(|i| i as usize)
            .filter(|i| *i < out.len())
        else {
            return Err(format!("bad batch response: {r}"));
        };
        out[id] = match r.get("error") {
            Some(e) => Err(e.to_string()),
            None => Ok(r.get("result").cloned().unwrap_or(Value::Null)),
        };
    }
    Ok(out)
}

pub fn head_number() -> Result<u64, String> {
    let head = rpc("eth_blockNumber", json!([]))?;
    head.as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .ok_or_else(|| format!("bad eth_blockNumber: {head}"))
}

/// The node's finalized block as `(number, hash)`; `None` before any.
pub fn finalized_block() -> Result<Option<(u64, String)>, String> {
    let block = rpc("eth_getBlockByNumber", json!(["finalized", false]))?;
    if block.is_null() {
        return Ok(None);
    }
    let number = block
        .get("number")
        .and_then(Value::as_str)
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .ok_or_else(|| format!("bad finalized block: {block}"))?;
    let hash = block
        .get("hash")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("bad finalized block: {block}"))?;
    Ok(Some((number, hash.to_lowercase())))
}

/// Values of `slots` of `address` at `block`.
pub fn storage_at(
    address: &str,
    slots: &[u64],
    block: u64,
) -> Result<crate::trie_ref::Storage, String> {
    slots
        .iter()
        .map(|slot| {
            let value = rpc(
                "eth_getStorageAt",
                json!([address, format!("0x{slot:x}"), format!("0x{block:x}")]),
            )?;
            Ok((
                *slot,
                serde_json::from_value(value).map_err(|e| e.to_string())?,
            ))
        })
        .collect()
}

/// `eth_getProof` for `slots` of `address` at `block`.
pub fn proof(
    address: &str,
    slots: &[u64],
    block: u64,
) -> Result<crate::trie_ref::AccountProof, String> {
    let keys: Vec<String> = slots.iter().map(|s| format!("0x{s:x}")).collect();
    let proof = rpc(
        "eth_getProof",
        json!([address, keys, format!("0x{block:x}")]),
    )?;
    serde_json::from_value(proof.clone()).map_err(|e| format!("bad eth_getProof: {e}: {proof}"))
}

/// Number of transactions in `block`.
pub fn tx_count(block: u64) -> Result<u64, String> {
    let n = rpc(
        "eth_getBlockTransactionCountByNumber",
        json!([format!("0x{block:x}")]),
    )?;
    serde_json::from_value::<alloy_primitives::U64>(n.clone())
        .map(|n| n.to())
        .map_err(|e| format!("bad transaction count: {e}: {n}"))
}

/// Whether `address` has code at the latest block.
pub fn has_code(address: &str) -> Result<bool, String> {
    let code = rpc("eth_getCode", json!([address, "latest"]))?;
    Ok(code.as_str().is_some_and(|c| c.len() > 2))
}

/// reth's `eth_getMultiProof` for `slots` of `address` at `block`.
pub fn multiproof(
    address: &str,
    slots: &[u64],
    block: u64,
) -> Result<crate::trie_ref::AccountProof, String> {
    let keys: Vec<String> = slots.iter().map(|s| format!("0x{s:064x}")).collect();
    let proofs = rpc(
        "eth_getMultiProof",
        json!([[[address, keys]], format!("0x{block:x}")]),
    )?;
    serde_json::from_value(proofs[0].clone())
        .map_err(|e| format!("bad eth_getMultiProof: {e}: {proofs}"))
}

/// reth's `debug_executionWitness` for `block`, normalized (see
/// [`crate::witness`]). The returned [`WitnessRpc`] distinguishes a node whose
/// debug namespace is off (method not found) from a transient failure, so the
/// oracle treats the former as capability-gated coverage, not a failure.
///
/// [`WitnessRpc`]: crate::witness::WitnessRpc
pub fn execution_witness(block: u64) -> crate::witness::WitnessRpc {
    use crate::witness::{is_method_not_found, ExecutionWitness, WitnessRpc};
    match rpc("debug_executionWitness", json!([format!("0x{block:x}")])) {
        Ok(v) => WitnessRpc::Ok(ExecutionWitness::from_value(&v)),
        Err(e) if is_method_not_found(&e) => WitnessRpc::Unsupported,
        Err(_) => WitnessRpc::Unavailable,
    }
}

/// Header `stateRoot` of `block`.
pub fn state_root(block: u64) -> Result<alloy_primitives::B256, String> {
    let header = rpc(
        "eth_getBlockByNumber",
        json!([format!("0x{block:x}"), false]),
    )?;
    serde_json::from_value(header["stateRoot"].clone())
        .map_err(|e| format!("bad stateRoot: {e}: {header}"))
}

/// `(hash, stateRoot)` of canonical block `number`; `None` past the head.
/// One call for the cross-validator execution differential
/// (`consensus::ExecDiffOracle`).
pub fn block_state(number: u64) -> Result<Option<(B256, B256)>, String> {
    let block = rpc(
        "eth_getBlockByNumber",
        json!([format!("0x{number:x}"), false]),
    )?;
    if block.is_null() {
        return Ok(None);
    }
    let field = |name: &str| {
        serde_json::from_value::<B256>(block[name].clone())
            .map_err(|e| format!("bad block {name}: {e}: {block}"))
    };
    Ok(Some((field("hash")?, field("stateRoot")?)))
}

/// `(hash, parent hash)` of canonical block `number`; `None` past the head.
pub fn block_ref(number: u64) -> Result<Option<(B256, B256)>, String> {
    let block = rpc(
        "eth_getBlockByNumber",
        json!([format!("0x{number:x}"), false]),
    )?;
    if block.is_null() {
        return Ok(None);
    }
    let field = |name: &str| {
        serde_json::from_value::<B256>(block[name].clone())
            .map_err(|e| format!("bad block {name}: {e}: {block}"))
    };
    Ok(Some((field("hash")?, field("parentHash")?)))
}

/// `eth_call`s of `(to, data)` against the state of block `hash`, which must
/// still be canonical (EIP-1898), in one JSON-RPC batch.
pub fn calls_at(calls: &[(Address, Vec<u8>)], hash: B256) -> Result<Vec<Bytes>, String> {
    let batch: Vec<Value> = calls
        .iter()
        .enumerate()
        .map(|(id, (to, data))| {
            json!({"jsonrpc": "2.0", "id": id, "method": "eth_call", "params": [
                {"to": to, "data": Bytes::copy_from_slice(data)},
                {"blockHash": hash, "requireCanonical": true}
            ]})
        })
        .collect();
    let resp: Vec<Value> = ureq::post(&rpc_url())
        .timeout(Duration::from_secs(10))
        .send_json(Value::Array(batch))
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    let mut out = vec![None; calls.len()];
    for r in resp {
        if let Some(err) = r.get("error") {
            return Err(err.to_string());
        }
        let id = r["id"]
            .as_u64()
            .map(|i| i as usize)
            .filter(|i| *i < out.len());
        let id = id.ok_or_else(|| format!("bad batch response: {r}"))?;
        out[id] = Some(
            serde_json::from_value(r["result"].clone())
                .map_err(|e| format!("bad eth_call result: {e}: {r}"))?,
        );
    }
    out.into_iter()
        .map(|r| r.ok_or_else(|| "missing batch response".to_string()))
        .collect()
}

/// One receipt log.
#[derive(Debug, Clone, Deserialize)]
pub struct ReceiptLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

/// Logs in block `hash`'s receipts, in order (`eth_getBlockReceipts`). A
/// reverted Tempo transaction keeps its fee-payment logs, so receipts are not
/// filtered by status: logs a revert should have discarded are kept too.
pub fn block_logs(hash: B256) -> Result<Vec<ReceiptLog>, String> {
    #[derive(Deserialize)]
    struct Receipt {
        logs: Vec<ReceiptLog>,
    }
    let receipts = rpc("eth_getBlockReceipts", json!([hash]))?;
    if receipts.is_null() {
        return Err(format!("no receipts for block {hash}"));
    }
    let receipts: Vec<Receipt> = serde_json::from_value(receipts.clone())
        .map_err(|e| format!("bad eth_getBlockReceipts: {e}: {receipts}"))?;
    Ok(receipts.into_iter().flat_map(|r| r.logs).collect())
}

/// The 32-byte storage word at `slot` of `address` at `block`.
pub fn storage_word(
    address: &str,
    slot: alloy_primitives::B256,
    block: u64,
) -> Result<alloy_primitives::B256, String> {
    let value = rpc(
        "eth_getStorageAt",
        json!([address, slot, format!("0x{block:x}")]),
    )?;
    serde_json::from_value::<alloy_primitives::U256>(value.clone())
        .map(alloy_primitives::B256::from)
        .map_err(|e| format!("bad eth_getStorageAt: {e}: {value}"))
}

/// One `eth_getLogs` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    pub block: u64,
    pub block_hash: String,
    pub data: Vec<u8>,
}

/// Logs of `address` with first topic `topic` in blocks `from..=to`, in
/// chain order.
pub fn logs(
    address: &str,
    topic: alloy_primitives::B256,
    from: u64,
    to: u64,
) -> Result<Vec<Log>, String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Raw {
        block_number: alloy_primitives::U64,
        block_hash: String,
        data: alloy_primitives::Bytes,
    }
    let logs = rpc(
        "eth_getLogs",
        json!([{
            "address": address,
            "topics": [topic],
            "fromBlock": format!("0x{from:x}"),
            "toBlock": format!("0x{to:x}"),
        }]),
    )?;
    let raw: Vec<Raw> = serde_json::from_value(logs.clone())
        .map_err(|e| format!("bad eth_getLogs: {e}: {logs}"))?;
    Ok(raw
        .into_iter()
        .map(|r| Log {
            block: r.block_number.to(),
            block_hash: r.block_hash.to_lowercase(),
            data: r.data.to_vec(),
        })
        .collect())
}

pub fn block_hash(number: u64) -> Result<Option<String>, String> {
    let block = rpc(
        "eth_getBlockByNumber",
        json!([format!("0x{number:x}"), false]),
    )?;
    Ok(block
        .get("hash")
        .and_then(Value::as_str)
        .map(str::to_string))
}

/// Runs a guest shell command, returning success and combined stdout/stderr.
pub(crate) fn sh(cmd: &str) -> (bool, String) {
    match Command::new("sh").args(["-c", cmd]).output() {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), text)
        }
        Err(e) => (false, e.to_string()),
    }
}

/// One `eth_getLogs` entry with everything the zones oracle decodes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FullLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    #[serde(with = "u64_hex")]
    pub block_number: u64,
    pub block_hash: B256,
    pub transaction_hash: B256,
}

mod u64_hex {
    use serde::{Deserialize, Deserializer};
    /// Deserializes an RPC hex quantity into a u64, rejecting invalid or overflowing quantities.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        Ok(alloy_primitives::U64::deserialize(d)?.to())
    }
}

/// Logs of any of `addresses` in blocks `from..=to`, in chain order.
pub fn logs_of(addresses: &[Address], from: u64, to: u64) -> Result<Vec<FullLog>, String> {
    let logs = rpc(
        "eth_getLogs",
        json!([{
            "address": addresses,
            "fromBlock": format!("0x{from:x}"),
            "toBlock": format!("0x{to:x}"),
        }]),
    )?;
    serde_json::from_value(logs.clone()).map_err(|e| format!("bad eth_getLogs: {e}: {logs}"))
}

/// Number of the block with hash `hash`, if the node has it.
pub fn block_number_by_hash(hash: B256) -> Result<Option<u64>, String> {
    let block = rpc("eth_getBlockByHash", json!([hash, false]))?;
    if block.is_null() {
        return Ok(None);
    }
    serde_json::from_value::<alloy_primitives::U64>(block["number"].clone())
        .map(|n| Some(n.to()))
        .map_err(|e| format!("bad block number: {e}: {block}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_fill_missing_fields() {
        // Seeds are recorded for the driver; guest randomness comes from Bedrock.
        let c: Config = serde_json::from_str(r#"{"seed": 7, "liveness_secs": 9}"#).unwrap();
        assert_eq!(c.liveness_secs, 9);
        assert_eq!(c.run_secs, 120);
        assert_eq!(c.nemesis, NemesisConfig::default());
        assert_eq!(c.trie, None);
        assert!(!c.tip20);
    }

    #[test]
    fn trie_config_lists_every_planned_contract() {
        let addr = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
        // The driver's single-contract config: one contract, run-seed slots.
        let one: Config = serde_json::from_str(&format!(
            r#"{{"seed": 3, "trie": {{"address": "{addr}"}}}}"#
        ))
        .unwrap();
        let tries = one.tries();
        assert_eq!(tries.len(), 1);
        assert_eq!(tries[0].address, addr);
        assert_eq!(tries[0].slots, crate::trie_gen::slots(3));
        assert_eq!(one.trie_plan().unwrap().writers().len(), 1);
        // trie_contracts=auto.
        let many: Config = serde_json::from_str(&format!(
            r#"{{"seed": 3, "trie": {{"address": "{addr}", "contracts": 15, "senders": 5}}}}"#
        ))
        .unwrap();
        let tries = many.tries();
        let (n, senders) = (15, 5);
        assert_eq!(tries.len(), n);
        assert_eq!(tries[0].address, addr);
        assert_eq!(tries[0].slots, crate::trie_gen::slots(3));
        for (c, t) in tries.iter().enumerate().skip(1) {
            assert_eq!(
                t.address,
                crate::trie_gen::pool_address(c).to_checksum(None)
            );
        }
        assert_eq!(many.trie_plan().unwrap().writers().len(), senders);
        // Explicit slots: that contract only, no generated load.
        let fixed: Config = serde_json::from_str(&format!(
            r#"{{"trie": {{"address": "{addr}", "slots": [1, 2], "contracts": 5}}}}"#
        ))
        .unwrap();
        assert_eq!(fixed.tries().len(), 1);
        assert!(fixed.trie_plan().is_none());
    }
}

/// Runs `program` with `args` and returns its stdout; an error names the
/// command with its exit status and stderr.
pub fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{program} {args:?}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{program} {args:?}: {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Canonical block identity, including its parent link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    pub number: u64,
    pub hash: B256,
    pub parent: B256,
}
