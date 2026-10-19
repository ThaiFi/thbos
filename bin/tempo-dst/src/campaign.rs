// SPDX-License-Identifier: GPL-2.0

//! Campaign domain choices shared by configs, recorded scenarios, and planning.

use bedrock_dst_contract::Preempt;

use crate::cluster::ClusterSwarm;
use serde::{Deserialize, Serialize};

/// The supported Tempo workload kinds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Load {
    /// pathUSD transfers (txgen).
    #[default]
    Transfers,
    /// RawStorage writes over slot shapes generated per seed (E5/E6).
    Trie,
    /// Transfers among a closed set of holders of a fresh TIP-20 (E8).
    Tip20,
    /// ChainOfBlocks appends (E9).
    Chain,
    /// Generic state-mutation mix over a Mutator contract (`statemix_gen`),
    /// the generic workload behind the valid-state-root invariant (Strand A).
    StateMix,
    /// A Tempo zone settling to the node: sequencer, batch prover, and
    /// txgen's deposit/withdrawal driver (E12). Needs run.sh's zones compose
    /// services (kept with `--workload-arg load=zones`).
    Zones,
}

/// One seed's swarm record (the contract's `S`): every feature that shapes
/// the run, so verdicts can be grouped by feature. In config.json,
/// scenario.json and verdict.json. Fields in alphabetical order (see
/// [`crate::common::LoadConfig`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Swarm {
    /// The four-validator cluster's features; absent for the dev node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<ClusterSwarm>,
    /// A certified L1 follower runs alongside the validators (`follower=true`):
    /// the tempo#8263 catch-up detector. Omitted when off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub follower: bool,
    /// Campaign-wide, recorded so a verdict names its whole configuration.
    pub load: Load,
    pub nemesis: bool,
    /// The network nemesis runs (omitted when not).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub network: bool,
    /// Drawn per seed by the driver.
    pub preempt: Preempt,
    /// `process_faults`: the guest nemesis also draws pauses, CPU throttles
    /// and graceful stops per seed. Left out while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub process_faults: bool,
    pub reference: bool,
    /// `storage_faults`: the datadir on LazyFS; the guest nemesis draws
    /// each fault's family per seed. Left out while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub storage_faults: bool,
    /// Zone sequencers (omitted for the single sequencer).
    #[serde(default, skip_serializing_if = "single")]
    pub zone_sequencers: u32,
    /// The multi-contract trie load's shape, drawn per seed with
    /// `trie_contracts=auto` (absent otherwise, so single-contract records
    /// are unchanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trie: Option<TrieShape>,
}

/// Whether `n` sequencers is the single-sequencer zone (0 or 1).
pub fn single(n: &u32) -> bool {
    *n <= 1
}

/// `trie_contracts=auto`: the first `contracts` RawStorage contracts of the
/// pool, written by `senders` writers (`trie_gen::draw`, `trie_gen::plan`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrieShape {
    pub contracts: usize,
    pub senders: usize,
}

/// `trie_contracts`: how many RawStorage contracts the trie load writes.
/// Accepts `1` (number or string) and `"auto"`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TrieContracts {
    /// One contract from one sender (`trie/deploy.yaml`): the original load.
    #[default]
    One,
    /// The 16-contract pool (`trie/deploy-pool.yaml`, deployed at warmup);
    /// each seed draws how many contracts it writes and from how many
    /// senders (`trie_gen::draw`).
    Auto,
}

impl TrieContracts {
    pub(crate) fn is_one(&self) -> bool {
        *self == TrieContracts::One
    }
}

impl Serialize for TrieContracts {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            TrieContracts::One => s.serialize_u64(1),
            TrieContracts::Auto => s.serialize_str("auto"),
        }
    }
}

impl<'de> Deserialize<'de> for TrieContracts {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match serde_json::Value::deserialize(d)? {
            serde_json::Value::Number(n) if n.as_u64() == Some(1) => Ok(TrieContracts::One),
            serde_json::Value::String(s) if s == "1" => Ok(TrieContracts::One),
            serde_json::Value::String(s) if s == "auto" => Ok(TrieContracts::Auto),
            v => Err(serde::de::Error::custom(format!(
                "trie_contracts: want 1 or auto, got {v}"
            ))),
        }
    }
}
