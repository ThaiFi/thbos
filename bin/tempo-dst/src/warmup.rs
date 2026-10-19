// SPDX-License-Identifier: GPL-2.0

//! `tempo-dst warmup '<json>'`: the workload contract's warmup hook, run in
//! the guest by `bedrock-dst` after boot, every 5 virtual seconds, until it
//! prints `{"ready": true, ...}`; the driver then takes the warm checkpoint.
//!
//! Each call does what it can and returns: wait for the node to reach
//! `warm_blocks`, then (once) deploy the load's contracts or mint its TIP-20
//! token, so branches start loading at once, then, with `reference`, wait
//! for the reference node to backfill the primary's chain (seen: a reference
//! that never backfilled stalled at head 0 all run). With `storage_faults`,
//! after the deploy (once): move the node's datadir onto LazyFS
//! (`storage::attach`); everything on disk then is durable. A failed deploy
//! or attach is an error (exit 1); a node that is not up yet is just not
//! ready.
//! that never backfilled stalled at head 0 all run). A failed deploy is an
//! error (exit 1); a node that is not up yet is just not ready.
//!
//! With `validators=4` the gate is the cluster's: every validator has
//! finalized `warm_blocks` and the full mesh has formed (each validator
//! connected to the three others), then (with `storage=lazyfs`) each
//! validator moves onto its LazyFS and the gate is waited for again, then
//! the load deploys through v1.

use std::{fs, io, path::Path};

use bedrock_dst_contract::{WarmupRequest, WarmupStatus};

use crate::{
    campaign::{Load, TrieContracts},
    cluster::{self, ValidatorId},
    cluster_live, common, node_storage,
    planner::{
        TempoArgs, CHAIN_CONTRACT, CHAIN_IMAGE, STATEMIX_CONTRACT, STATEMIX_IMAGE, TIP20_IMAGE,
        TRIE_CONTRACT, TRIE_IMAGE, ZONES_IMAGE,
    },
    start, storage,
    topology::Topology,
    trie_gen,
};

/// Blocks the reference may trail the primary at the warm checkpoint.
const REFERENCE_SYNC_SLACK: u64 = 2;
/// Marks the load's deploy done, across calls (and in every branch).
const DEPLOYED_PATH: &str = "/bedrock/warmup-deployed";
/// Marks the datadir moved onto LazyFS.
const ATTACHED_PATH: &str = "/bedrock/warmup-lazyfs";
/// Marks the policy account funded, across warmup calls.
const FUNDED_PATH: &str = "/bedrock/warmup-policy-funded";
/// Marks the validators' storage layer attached (`storage=lazyfs`).
const STORAGE_ATTACHED_PATH: &str = "/bedrock/warmup-storage-attached";

fn head(rpc: Option<&'static str>) -> Option<u64> {
    match rpc {
        Some(url) => common::with_rpc_url(url, common::head_number).ok(),
        None => common::head_number().ok(),
    }
}

fn status(ready: bool, detail: String) -> WarmupStatus {
    WarmupStatus { ready, detail }
}

/// The cluster's gate: every validator finalized `warm_blocks`, and the
/// full mesh; `None` when it holds, else what is missing.
fn cluster_not_ready(warm_blocks: u64) -> Option<String> {
    let finalized: Vec<Option<u64>> = ValidatorId::all()
        .map(|v| cluster_live::finalized_height(v).ok().flatten())
        .collect();
    if !finalized
        .iter()
        .all(|f| f.is_some_and(|f| f >= warm_blocks))
    {
        return Some(format!("finalized {finalized:?} < {warm_blocks}"));
    }
    let peers: Vec<Option<usize>> = ValidatorId::all()
        .map(|v| cluster_live::metrics(v).ok().map(|m| m.connected_peers))
        .collect();
    let full = usize::from(cluster::VALIDATORS) - 1;
    if !peers.iter().all(|p| p.is_some_and(|p| p >= full)) {
        return Some(format!("mesh: connected peers {peers:?}, want {full} each"));
    }
    None
}

/// One warmup step.
pub fn run(req: &WarmupRequest<TempoArgs>) -> io::Result<WarmupStatus> {
    let wa = &req.args;
    let topo = Topology::from_args(wa);
    if wa.load == Load::Zones {
        if let Some(missing) = cluster_not_ready(req.warmup.warm_blocks) {
            return Ok(status(false, missing));
        }
    }
    // The cluster deploys through its first validator.
    let rpc = topo.validators().next().map(|n| {
        n.validator_id()
            .expect("a cluster node is a validator")
            .rpc_url()
    });
    if topo.validators().next().is_some() {
        if let Some(missing) = cluster_not_ready(req.warmup.warm_blocks) {
            return Ok(status(false, missing));
        }
        if wa.storage.is_some() && !Path::new(STORAGE_ATTACHED_PATH).exists() {
            // Each validator onto its storage layer, once; the next calls
            // wait for the cluster to re-form.
            for n in topo.validators() {
                let v = n.validator_id().expect("a cluster node is a validator");
                node_storage::attach(v).map_err(io::Error::other)?;
            }
            fs::create_dir_all(Path::new(STORAGE_ATTACHED_PATH).parent().unwrap())?;
            fs::write(STORAGE_ATTACHED_PATH, "lazyfs")?;
            return Ok(status(false, "validators moved onto lazyfs".into()));
        }
    } else {
        let primary = head(None);
        if !primary.is_some_and(|h| h >= req.warmup.warm_blocks) {
            return Ok(status(
                false,
                format!("head {primary:?} < {}", req.warmup.warm_blocks),
            ));
        }
    }
    if !Path::new(DEPLOYED_PATH).exists() {
        let what = match wa.load {
            Load::Transfers => None,
            Load::Trie if wa.trie_contracts == TrieContracts::Auto => {
                // Funds the extra writers, deploys all 16 contracts, and
                // checks each CREATE address has code.
                start::deploy(TRIE_IMAGE, TRIE_CONTRACT, start::TRIE_POOL_SPEC, rpc)
                    .map_err(|e| io::Error::other(format!("trie pool deploy failed: {e}")))?;
                Some(format!(
                    "trie pool deployed: {}",
                    trie_gen::pool_addresses().join(" ")
                ))
            }
            Load::Trie => {
                start::deploy(TRIE_IMAGE, TRIE_CONTRACT, "/workload/trie/deploy.yaml", rpc)
                    .map_err(|e| io::Error::other(format!("{TRIE_CONTRACT} deploy failed: {e}")))?;
                Some(format!("{TRIE_CONTRACT} deployed"))
            }
            Load::Chain => {
                start::deploy(
                    CHAIN_IMAGE,
                    CHAIN_CONTRACT,
                    "/workload/chain/deploy.yaml",
                    rpc,
                )
                .map_err(|e| io::Error::other(format!("{CHAIN_CONTRACT} deploy failed: {e}")))?;
                Some(format!("{CHAIN_CONTRACT} deployed"))
            }
            Load::Tip20 => {
                start::deploy_tip20(TIP20_IMAGE, rpc)
                    .map_err(|e| io::Error::other(format!("TIP-20 token deploy failed: {e}")))?;
                Some("TIP-20 token minted".to_string())
            }
            Load::StateMix => {
                start::deploy(
                    STATEMIX_IMAGE,
                    STATEMIX_CONTRACT,
                    "/workload/statemix/deploy.yaml",
                    rpc,
                )
                .map_err(|e| io::Error::other(format!("{STATEMIX_CONTRACT} deploy failed: {e}")))?;
                Some(format!("{STATEMIX_CONTRACT} (Mutator) deployed"))
            }
            Load::Zones => {
                // Gives pathUSD the TIP-403 binding createZone requires; the
                // compose `zone` service then provisions the zone (below).
                crate::zones_live::setup(ZONES_IMAGE)
                    .map_err(|e| io::Error::other(format!("zone setup failed: {e}")))?;
                if wa.zone_sequencers == 3 {
                    // The multi-sequencer zone: create-zone with the 2-of-3
                    // set; the zone-N services start once it is written.
                    crate::zones_cluster::provision(ZONES_IMAGE).map_err(|e| {
                        io::Error::other(format!("multi-sequencer zone provisioning failed: {e}"))
                    })?;
                    Some("multi-sequencer zone provisioned (3 sequencers, 2-of-3)".to_string())
                } else {
                    Some("pathUSD transfer policy migrated for the zone".to_string())
                }
            }
        };
        fs::create_dir_all(Path::new(DEPLOYED_PATH).parent().unwrap())?;
        fs::write(
            DEPLOYED_PATH,
            what.as_deref().unwrap_or("nothing to deploy"),
        )?;
        if let Some(what) = what {
            // Report the deploy on its own line; the next call goes on.
            return Ok(status(false, what));
        }
    }
    if wa.storage_faults && !Path::new(ATTACHED_PATH).exists() {
        storage::attach().map_err(|e| io::Error::other(format!("storage-attach failed: {e}")))?;
        fs::write(ATTACHED_PATH, "attached")?;
        // The next call (5 s on) goes on: the node settles on LazyFS.
        return Ok(status(false, "datadir on lazyfs".into()));
    }
    if wa.load == Load::Zones {
        // Branches start from a provisioned zone that has settled batch 1.
        let ready = if wa.zone_sequencers == 3 {
            crate::zones_cluster::ready()
        } else {
            crate::zones_live::zone_ready(crate::zones::ZoneEndpoints::SINGLE)
        };
        match ready {
            Ok((true, _)) => {}
            Ok((false, detail)) => return Ok(status(false, detail)),
            Err(e) => return Ok(status(false, format!("zone not up: {e}"))),
        }
        // Fund the policy family's account before the checkpoint (the slow
        // deposit then runs once, outside any nemesis window), so every branch
        // can run the fast policy flow.
        if wa.zones_policy && !Path::new(FUNDED_PATH).exists() {
            crate::zones_live::fund_policy_account(ZONES_IMAGE)
                .map_err(|e| io::Error::other(format!("policy account funding failed: {e}")))?;
            fs::write(FUNDED_PATH, "funded")?;
            return Ok(status(false, "policy account funded".into()));
        }
    }
    if wa.follower_on() && !crate::follower::snapshot_exists() {
        crate::follower::snapshot()?;
        return Ok(status(
            false,
            "certified follower snapshot saved; waiting for restart".into(),
        ));
    }
    if topo.reference().is_some() {
        let primary = head(None);
        let reference = head(Some(common::REFERENCE_RPC_URL));
        let synced =
            matches!((primary, reference), (Some(p), Some(r)) if r + REFERENCE_SYNC_SLACK >= p);
        return Ok(status(
            synced,
            format!("head {primary:?}, reference head {reference:?}"),
        ));
    }
    match rpc {
        Some(url) => Ok(status(
            true,
            format!("cluster ready, v1 head {:?}", head(Some(url))),
        )),
        None => Ok(status(true, format!("head {:?}", head(None)))),
    }
}
