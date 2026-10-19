// SPDX-License-Identifier: GPL-2.0

//! Multi-sequencer zones (`load=zones zone_sequencers=3`): the cluster's
//! constants, its RPC (roles, `zone_setLeader`), and the cluster oracle
//! (E12 cluster checks).
//!
//! Three `tempo-zone node`s in tempoxyz/zones' multi-sequencer mode
//! (`--sequencer.manifest`): a portal created with all three as sequencers
//! and a 2-of-3 settlement threshold (`tempo-xtask create-zone`, run by
//! zones/zone-provision.sh during warmup), Commonware P2P between them,
//! leadership from the portal's finalized `LeaderUpdated` (bootstrap leader
//! node 0; `zone_setLeader` hands it over). Each node signs its own blocks
//! (its individual key is also its `--sequencer-key-file`, as in zones' real
//! P2P cluster fixture), so a block's beneficiary names its producer. E12
//! keeps following node 0's chain; E12's cluster checks compare all three:
//!
//! - **No fork** (`E12/zones-cluster-fork`): nodes holding the same height
//!   hold the same block, at once below the portal's settled height, else
//!   within [`FORK_GRACE_NS`].
//! - **One leader per term** (`E12/zones-cluster-leader-mismatch`): every block's
//!   beneficiary is the leader of an epoch active over the L1 anchors it
//!   applied (from the portal's `LeaderUpdated` history), and
//!   (`E12/zones-cluster-double-leader`) no two nodes report the leader role for the same
//!   locally applied epoch in consecutive samples.
//! - **L1 backfill** (`E12/zones-cluster-anchor-regressed`, `E12/zones-cluster-anchor-mismatch`):
//!   each node's `TempoBlockFinalized` L1 numbers only move forward, and
//!   each finalized hash is the L1's canonical block. TempoState itself
//!   rejects a header whose parent is not the previous one, so a forward
//!   jump (one event names the last header a block imported; a reconnect
//!   backfills many at once, `S/cluster-l1-backfilled`) skipped nothing as
//!   long as the hashes are canonical; deposits in skipped blocks would
//!   also stay unprocessed (E12).
//! - **Recovery** (`E12/zones-cluster-not-caught-up`): after a network fault heals,
//!   every node it hit reaches the cluster's height (and, after an L1 cut,
//!   the L1 head) at the heal within `liveness_secs`.
//! - **Handoff** (`E12/zones-cluster-handoff-incomplete`): after `zone_setLeader`, the
//!   portal names the target and a block it produced lands, within
//!   `liveness_secs` of the fault healing.
//! - **Production** (`E12/zones-cluster-production-stalled`): the cluster's height
//!   advances within `liveness_secs` unless a fault or kill stops the
//!   leader (clock restarted when it ends).
//!
//! Coverage: `S/cluster-converged`, `S/cluster-blocks-checked`,
//! `S/net-l1-cut-restored`, `S/net-partition-healed`,
//! `S/net-leader-isolated`, `S/net-handoff-completed`,
//! `S/net-degraded-kept-up`.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    time::Duration,
};

use alloy_primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    netfault::{self, NetEndpoint, NetNode, NetTopology, NetWorkload},
    planner::{CutMode, NetAction, NetFault, NetFaultKind, NetStep, NetemShape, NodeRef, Peer},
};

use crate::{
    common,
    verdict::{finding, Verdict},
    zones::PORTAL,
};

/// Sequencers in the cluster.
pub const NODES: usize = 3;
/// Individual sequencer addresses (dev accounts 5, 6, 7; zone-provision.sh).
pub const SEQUENCERS: [&str; NODES] = [
    "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
    "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
    "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
];
/// Disagreeing heights above the settled one may be transient this long.
pub const FORK_GRACE_NS: u64 = 20_000_000_000;
/// Zone blocks read per node per tick.
const BLOCKS_PER_TICK: u64 = 30;
/// Heights remembered per node.
const KEEP_HEIGHTS: u64 = 1024;

/// Container of sequencer `i`.
pub fn container(i: usize) -> String {
    format!("zone-{i}")
}

pub fn sequencer_address(i: usize) -> Address {
    SEQUENCERS[i].parse().expect("valid sequencer address")
}

/// Index of the sequencer with address `a`.
pub fn index_of(a: Address) -> Option<usize> {
    (0..NODES).find(|&i| sequencer_address(i) == a)
}

fn selector(signature: &str) -> String {
    format!(
        "0x{}",
        alloy_primitives::hex::encode(&keccak256(signature)[..4])
    )
}

fn call_l1(data: &str, block: &str) -> Result<B256, String> {
    let v = common::rpc_at(
        "http://127.0.0.1:8545",
        "eth_call",
        json!([{"to": PORTAL, "data": data}, block]),
        Duration::from_secs(10),
    )?;
    let s = v.as_str().ok_or_else(|| format!("bad eth_call: {v}"))?;
    let bytes = alloy_primitives::hex::decode(s).map_err(|e| e.to_string())?;
    bytes
        .get(..32)
        .map(B256::from_slice)
        .ok_or_else(|| format!("short eth_call result {s}"))
}

/// The portal's current (latest-block) leader, as a node index.
pub fn leader_index() -> Result<usize, String> {
    let w = call_l1(&selector("leader()"), "latest")?;
    let a = Address::from_word(w);
    index_of(a).ok_or_else(|| format!("leader {a} is not a cluster sequencer"))
}

/// Asks the first of `relays` that answers to `zone_setLeader(target)` on
/// its operator RPC (the guarded operator handoff path; it relays a
/// `setLeader` with its individual key and waits for the receipt).
pub fn set_leader(relays: &[usize], target: usize) -> Result<Value, String> {
    let mut errors = Vec::new();
    for &via in relays {
        match common::rpc_at(
            &rpc_url(via),
            "zone_setLeader",
            json!([sequencer_address(target)]),
            Duration::from_secs(45),
        ) {
            Ok(v) => return Ok(json!({"via": via, "response": v})),
            Err(e) => errors.push(format!("via {via}: {e}")),
        }
    }
    Err(errors.join("; "))
}

/// Node `i`'s IP in the cluster network (`zseq`, 10.90.10.0/24).
pub fn node_ip(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, 90, 10, 11 + i as u8)
}

/// The cluster network's gateway: the guest host namespace, where the L1
/// forwarder listens and the oracles connect from.
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 90, 10, 1);
/// Commonware P2P port of every sequencer.
pub const P2P_PORT: u16 = 9200;
/// Zone HTTP and redacted RPC ports of every sequencer.
pub const RPC_PORT: u16 = 9545;
pub const PRIVATE_RPC_PORT: u16 = 8544;

/// The forwarder port sequencer `i` reaches the L1 WebSocket on.
pub fn l1_port(i: usize) -> u16 {
    18600 + i as u16
}

pub fn rpc_url(i: usize) -> String {
    format!("http://{}:{RPC_PORT}", node_ip(i))
}

/// The cluster for the network nemesis: the three sequencers, the L1
/// forwarder on the gateway (`l1`), faults between sequencers scoped to the
/// Commonware P2P port, and the oracles' path (from the gateway to RPC).
pub fn topology() -> NetTopology {
    NetTopology {
        nodes: (0..NODES)
            .map(|i| NetNode {
                name: container(i),
                ip: node_ip(i),
            })
            .collect(),
        endpoints: vec![NetEndpoint {
            name: "l1".into(),
            ip: GATEWAY,
            ports: (0..NODES).map(l1_port).collect(),
        }],
        fault_ports: vec![P2P_PORT],
        oracle: Some(NetEndpoint {
            name: "oracle".into(),
            ip: GATEWAY,
            ports: vec![RPC_PORT, PRIVATE_RPC_PORT],
        }),
    }
}

/// The zones families: zones' network-chaos e2e tests (PRs #1261, #1278).
pub const FAMILIES: [NetFaultKind; 12] = [
    NetFaultKind::L1CutAll,
    NetFaultKind::L1CutFollowers,
    NetFaultKind::L1CutLeader,
    NetFaultKind::L1CutFollower,
    NetFaultKind::L1Resets,
    NetFaultKind::L1Netem,
    NetFaultKind::HandoffFollowerCut,
    NetFaultKind::HandoffIncomingIsolated,
    NetFaultKind::HandoffOutgoingIsolated,
    NetFaultKind::HandoffIncomingP2pIsolated,
    NetFaultKind::HandoffLatency,
    NetFaultKind::HandoffLoss,
];

fn role(role: &str, pick: u32) -> NodeRef {
    NodeRef::Role {
        role: role.into(),
        pick,
    }
}

fn l1() -> Vec<Peer> {
    vec![Peer::Endpoint {
        endpoint: "l1".into(),
    }]
}

fn everyone() -> Vec<Peer> {
    vec![Peer::Node(role("all", 0))]
}

/// Steps that cut `who` off on both planes: its L1 link and its P2P links.
fn isolate(who: NodeRef) -> Vec<NetStep> {
    vec![
        NetStep {
            after_secs: 0,
            action: NetAction::Cut {
                from: vec![who.clone()],
                to: l1(),
                ports: vec![],
                mode: CutMode::Reset,
            },
        },
        NetStep {
            after_secs: 0,
            action: NetAction::Cut {
                from: vec![who],
                to: everyone(),
                ports: vec![P2P_PORT],
                mode: CutMode::Reset,
            },
        },
    ]
}

/// The steps of a zones family (`None` for a generic one). Roles: `leader`,
/// `follower` (`followers[pick % 2]`), `other-follower`, `followers`, `all`.
pub fn draw_family(
    kind: NetFaultKind,
    dur_secs: u64,
    draw: &mut dyn FnMut(u64, u64) -> u64,
) -> Option<Vec<NetStep>> {
    let l1_cut = |group: &str, draw: &mut dyn FnMut(u64, u64) -> u64| {
        let pick = draw(0, 1) as u32;
        let mode = [CutMode::Reset, CutMode::Drop][draw(0, 1) as usize];
        vec![NetStep {
            after_secs: 0,
            action: NetAction::Cut {
                from: vec![role(group, pick)],
                to: l1(),
                ports: vec![],
                mode,
            },
        }]
    };
    let handoff = |pick: u32| NetStep {
        // Let the degraded condition take hold, then rotate.
        after_secs: 2,
        action: NetAction::SetLeader {
            target: role("follower", pick),
        },
    };
    Some(match kind {
        NetFaultKind::L1CutAll => l1_cut("all", draw),
        NetFaultKind::L1CutFollowers => l1_cut("followers", draw),
        NetFaultKind::L1CutLeader => l1_cut("leader", draw),
        NetFaultKind::L1CutFollower => l1_cut("follower", draw),
        NetFaultKind::L1Resets => vec![NetStep {
            after_secs: 0,
            action: NetAction::Reset {
                from: vec![role("all", 0)],
                to: l1(),
                ports: vec![],
                at_offsets: netfault::reset_offsets(dur_secs, draw(2, 6), draw),
            },
        }],
        NetFaultKind::L1Netem => {
            let group = ["all", "leader", "follower"][draw(0, 2) as usize];
            let pick = draw(0, 1) as u32;
            vec![NetStep {
                after_secs: 0,
                action: NetAction::Netem {
                    from: vec![role(group, pick)],
                    to: l1(),
                    ports: vec![],
                    shape: netfault::draw_shape(draw),
                },
            }]
        }
        NetFaultKind::HandoffFollowerCut => {
            let pick = draw(0, 1) as u32;
            let mut s = isolate(role("other-follower", pick));
            s.push(handoff(pick));
            s
        }
        NetFaultKind::HandoffIncomingIsolated => {
            let pick = draw(0, 1) as u32;
            let mut s = isolate(role("follower", pick));
            s.extend(isolate(role("other-follower", pick)));
            s.push(handoff(pick));
            s
        }
        NetFaultKind::HandoffOutgoingIsolated => {
            let pick = draw(0, 1) as u32;
            // Rotate first; the outgoing leader then loses both planes
            // before the activation block.
            let mut s = vec![handoff(pick)];
            s.extend(isolate(role("leader", 0)).into_iter().map(|mut st| {
                st.after_secs = 3;
                st
            }));
            s
        }
        NetFaultKind::HandoffIncomingP2pIsolated => {
            let pick = draw(0, 1) as u32;
            vec![
                NetStep {
                    after_secs: 0,
                    action: NetAction::Cut {
                        from: vec![role("follower", pick)],
                        to: everyone(),
                        ports: vec![P2P_PORT],
                        mode: CutMode::Reset,
                    },
                },
                handoff(pick),
            ]
        }
        NetFaultKind::HandoffLatency => {
            let pick = draw(0, 1) as u32;
            let shape = |ms| NetemShape {
                latency_ms: ms,
                ..NetemShape::default()
            };
            vec![
                NetStep {
                    after_secs: 0,
                    action: NetAction::Netem {
                        from: vec![role("all", 0)],
                        to: everyone(),
                        ports: vec![P2P_PORT],
                        shape: shape(400),
                    },
                },
                NetStep {
                    after_secs: 0,
                    action: NetAction::Netem {
                        from: vec![role("all", 0)],
                        to: l1(),
                        ports: vec![],
                        shape: shape(500),
                    },
                },
                handoff(pick),
            ]
        }
        NetFaultKind::HandoffLoss => {
            let pick = draw(0, 1) as u32;
            vec![
                NetStep {
                    after_secs: 0,
                    action: NetAction::Netem {
                        from: vec![role("all", 0)],
                        to: everyone(),
                        ports: vec![P2P_PORT],
                        shape: NetemShape {
                            latency_ms: 50,
                            jitter_ms: 50,
                            loss_permille: 50,
                            rate_kbps: 0,
                        },
                    },
                },
                handoff(pick),
            ]
        }
        _ => return None,
    })
}

/// The coverage E12 (zones and cluster checks) must see a `family` fault produce in the cluster.
pub fn required_effects(family: NetFaultKind) -> &'static [&'static str] {
    match family {
        NetFaultKind::Partition | NetFaultKind::OneWayPartition => &["S/net-partition-healed"],
        // Only a cut leader stops production, so only it makes a zone
        // block import many L1 headers at once on reconnect.
        NetFaultKind::L1CutAll | NetFaultKind::L1CutLeader => &[
            "S/net-l1-cut-restored",
            "S/cluster-l1-backfilled",
            "S/net-quorum-lost-and-regained",
            "S/net-leader-isolated",
        ],
        NetFaultKind::L1CutFollowers => {
            &["S/net-l1-cut-restored", "S/net-quorum-lost-and-regained"]
        }
        NetFaultKind::L1CutFollower => {
            &["S/net-l1-cut-restored", "S/net-quorum-settled-during-fault"]
        }
        NetFaultKind::HandoffFollowerCut
        | NetFaultKind::HandoffIncomingIsolated
        | NetFaultKind::HandoffOutgoingIsolated
        | NetFaultKind::HandoffIncomingP2pIsolated
        | NetFaultKind::HandoffLatency
        | NetFaultKind::HandoffLoss => &["S/net-handoff-completed"],
        NetFaultKind::LinkCut | NetFaultKind::LinkReset | NetFaultKind::LinkNetem => &[],
        NetFaultKind::L1Resets | NetFaultKind::L1Netem => &[],
    }
}

/// What a running fault excuses in E12's liveness clocks (zones and cluster).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetExcuse {
    /// No 2-of-3 quorum with the leader: batches may stop.
    pub settlement: bool,
    /// The leader cannot build blocks (no L1, or a blocked handoff).
    pub production: bool,
    /// Node 0, whose chain E12 and the prover read, is cut off from the
    /// leader.
    pub observer: bool,
}

/// The excuses of a `family` fault hitting `hit` (node indices) with
/// `leader` leading, from what zones' tests expect to stall.
pub fn excuse(
    family: NetFaultKind,
    leader: usize,
    hit: &[usize],
    sides: Option<&[Vec<usize>]>,
) -> NetExcuse {
    let n = NODES;
    let leader_hit = hit.contains(&leader);
    match family {
        NetFaultKind::L1CutAll
        | NetFaultKind::L1CutFollowers
        | NetFaultKind::L1CutLeader
        | NetFaultKind::L1CutFollower => NetExcuse {
            settlement: leader_hit || n - hit.len() < 2,
            production: leader_hit,
            observer: hit.contains(&0) || leader_hit,
        },
        NetFaultKind::Partition | NetFaultKind::OneWayPartition => {
            // The leader keeps building on its side; settlement needs a
            // quorum there; node 0 elsewhere stops following.
            let side = sides
                .and_then(|s| s.iter().find(|s| s.contains(&leader)).cloned())
                .unwrap_or_else(|| (0..n).collect());
            NetExcuse {
                settlement: side.len() < 2,
                production: false,
                observer: !side.contains(&0),
            }
        }
        NetFaultKind::LinkCut => NetExcuse {
            settlement: false,
            production: false,
            observer: hit.contains(&0),
        },
        NetFaultKind::HandoffIncomingIsolated
        | NetFaultKind::HandoffOutgoingIsolated
        | NetFaultKind::HandoffIncomingP2pIsolated => NetExcuse {
            settlement: true,
            production: true,
            observer: true,
        },
        NetFaultKind::HandoffFollowerCut => NetExcuse {
            observer: hit.contains(&0),
            ..NetExcuse::default()
        },
        // Resets, netem, latency/loss handoffs: a healthy quorum must keep
        // settling.
        _ => NetExcuse::default(),
    }
}

/// The zones side of the network nemesis.
pub struct ZonesNet {
    leader: Option<usize>,
}

impl ZonesNet {
    pub fn new() -> Self {
        ZonesNet { leader: None }
    }

    fn leader(&mut self) -> Result<usize, String> {
        if let Some(l) = self.leader {
            return Ok(l);
        }
        let l = leader_index()?;
        self.leader = Some(l);
        Ok(l)
    }
}

fn index_of_name(name: &str) -> Option<usize> {
    (0..NODES).find(|&i| container(i) == name)
}

impl NetWorkload for ZonesNet {
    fn resolve_role(&mut self, role: &str, pick: u32) -> Result<Vec<String>, String> {
        let leader = self.leader()?;
        let f = netfault_followers(leader);
        let chosen = f[pick as usize % f.len()];
        let other = *f.iter().find(|&&x| x != chosen).unwrap_or(&chosen);
        let idx: Vec<usize> = match role {
            "leader" => vec![leader],
            "follower" => vec![chosen],
            "other-follower" => vec![other],
            "followers" => f,
            _ => return Err(format!("no role {role:?} in the zone cluster")),
        };
        Ok(idx.into_iter().map(container).collect())
    }

    fn describe(&mut self, fault: &NetFault, hit: &[String]) -> Value {
        let Ok(leader) = self.leader() else {
            return json!({"excuse": NetExcuse { settlement: true, production: true, observer: true }});
        };
        let hit_idx: Vec<usize> = hit.iter().filter_map(|n| index_of_name(n)).collect();
        // Partition sides by index, from the plan (generic families name
        // their nodes).
        let sides: Option<Vec<Vec<usize>>> = fault.steps.iter().find_map(|s| match &s.action {
            NetAction::Partition { sides, .. } => Some(
                sides
                    .iter()
                    .map(|side| {
                        side.iter()
                            .filter_map(|r| match r {
                                NodeRef::Node { node } => index_of_name(node),
                                NodeRef::Role { .. } => None,
                            })
                            .collect()
                    })
                    .collect(),
            ),
            _ => None,
        });
        let target = fault.steps.iter().find_map(|s| match &s.action {
            NetAction::SetLeader {
                target: NodeRef::Role { role, pick },
            } => self
                .resolve_role(role, *pick)
                .ok()
                .and_then(|n| n.first().and_then(|n| index_of_name(n))),
            _ => None,
        });
        json!({
            "leader": leader,
            "hit": hit_idx,
            "target": target,
            "excuse": excuse(fault.family, leader, &hit_idx, sides.as_deref()),
        })
    }

    fn hook(&mut self, step: &NetAction, _topo: &NetTopology) -> Result<Value, String> {
        let NetAction::SetLeader { target } = step else {
            return Err(format!("no zones hook {step:?}"));
        };
        let target = match target {
            NodeRef::Node { node } => index_of_name(node).ok_or("unknown node")?,
            NodeRef::Role { role, pick } => {
                let n = self.resolve_role(role, *pick)?;
                n.first()
                    .and_then(|n| index_of_name(n))
                    .ok_or("no target")?
            }
        };
        let leader = self.leader()?;
        // Relays: the outgoing leader first (it is cut only after an
        // outgoing-isolated rotation), then the followers; a relay without
        // L1 fails and the next is asked.
        let relays: Vec<usize> = std::iter::once(leader)
            .chain(netfault_followers(leader))
            .collect();
        let res = set_leader(&relays, target);
        common::emit_event(
            "network",
            "handoff",
            None,
            json!({
                "from": leader,
                "to": target,
                "to_address": sequencer_address(target),
                "result": res.as_ref().map_or_else(|e| json!({"error": e}), |v| v.clone()),
            }),
        );
        res
    }
}

fn netfault_followers(leader: usize) -> Vec<usize> {
    (0..NODES).filter(|&i| i != leader).collect()
}

/// Provisions the cluster's zone (warmup, once): runs zones/zone-provision.sh
/// from `image` on the guest host network (it needs the L1's HTTP RPC) with
/// the `/shared` volume of `zone-0` mounted, so every sequencer finds the
/// genesis, manifests and keys it writes there.
pub fn provision(image: &str) -> Result<(), String> {
    let volume = common::command_output(
        "podman",
        &[
            "inspect",
            "-f",
            r#"{{range .Mounts}}{{if eq .Destination "/shared"}}{{.Name}}{{end}}{{end}}"#,
            &container(0),
        ],
    )?;
    let volume = volume.trim();
    if volume.is_empty() {
        return Err(format!("{} has no /shared volume", container(0)));
    }
    common::command_output(
        "podman",
        &[
            "run",
            "--rm",
            "--network",
            "host",
            "-v",
            &format!("{volume}:/shared"),
            "--entrypoint",
            "/bin/sh",
            image,
            "/usr/local/bin/zone-provision.sh",
        ],
    )
    .map(drop)
}

/// Whether the cluster is ready for the warm checkpoint: the zone settled
/// batch 1 ([`crate::zones_live::zone_ready`] on node 0) and every node
/// serves blocks within a few of each other, with a progress line.
pub fn ready() -> Result<(bool, String), String> {
    let (zone_ok, detail) = crate::zones_live::zone_ready(crate::zones::ZoneEndpoints::CLUSTER)?;
    let mut heads = Vec::new();
    for i in 0..NODES {
        heads.push(RpcCluster.head(i)?);
    }
    let (lo, hi) = (
        heads.iter().min().copied().unwrap_or(0),
        heads.iter().max().copied().unwrap_or(0),
    );
    Ok((
        zone_ok && lo > 0 && hi - lo <= 3,
        format!("{detail}; sequencer heads {heads:?}"),
    ))
}

/// A zone block as the cluster checks need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZBlock {
    pub number: u64,
    pub hash: B256,
    pub parent: B256,
    pub beneficiary: Address,
}

/// One `LeaderUpdated` (or the portal's state at the oracle's start).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leadership {
    pub epoch: u64,
    pub leader: Address,
    pub activation: u64,
}

/// A node's `zone_getSequencerInfo` essentials.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeInfo {
    pub role: String,
    pub applied_epoch: Option<u64>,
}

/// What the cluster checks read; [`RpcCluster`] live, fakes in tests.
pub trait Cluster {
    fn head(&mut self, node: usize) -> Result<u64, String>;
    fn block(&mut self, node: usize, number: u64) -> Result<Option<ZBlock>, String>;
    /// `(zone block, L1 number, L1 hash)` of every `TempoBlockFinalized`
    /// in zone blocks `from..=to`, in order.
    fn finalized(
        &mut self,
        node: usize,
        from: u64,
        to: u64,
    ) -> Result<Vec<(u64, u64, B256)>, String>;
    fn info(&mut self, node: usize) -> Result<NodeInfo, String>;
    fn l1_head(&mut self) -> Result<u64, String>;
    fn l1_hash(&mut self, number: u64) -> Result<Option<B256>, String>;
    /// `LeaderUpdated` logs in L1 blocks `from..=to`.
    fn leader_updates(&mut self, from: u64, to: u64) -> Result<Vec<Leadership>, String>;
    /// The portal's latest leader state.
    fn leadership_now(&mut self) -> Result<Leadership, String>;
    /// The portal's settled zone height.
    fn settled_height(&mut self) -> Result<u64, String>;
}

/// The live cluster over RPC.
#[derive(Default)]
pub struct RpcCluster;

fn hex_u64(v: &Value) -> Option<u64> {
    v.as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
}

fn topic(signature: &str) -> B256 {
    keccak256(signature.as_bytes())
}

fn zone_rpc(node: usize, method: &str, params: Value) -> Result<Value, String> {
    common::rpc_at(&rpc_url(node), method, params, Duration::from_secs(5))
}

fn l1_rpc(method: &str, params: Value) -> Result<Value, String> {
    common::rpc_at(
        "http://127.0.0.1:8545",
        method,
        params,
        Duration::from_secs(10),
    )
}

impl Cluster for RpcCluster {
    fn head(&mut self, node: usize) -> Result<u64, String> {
        let v = zone_rpc(node, "eth_blockNumber", json!([]))?;
        hex_u64(&v).ok_or_else(|| format!("bad head {v}"))
    }
    fn block(&mut self, node: usize, number: u64) -> Result<Option<ZBlock>, String> {
        let b = zone_rpc(
            node,
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), false]),
        )?;
        if b.is_null() {
            return Ok(None);
        }
        let f = |k: &str| -> Result<B256, String> {
            serde_json::from_value(b[k].clone()).map_err(|e| format!("bad {k}: {e}"))
        };
        Ok(Some(ZBlock {
            number,
            hash: f("hash")?,
            parent: f("parentHash")?,
            beneficiary: serde_json::from_value(b["miner"].clone())
                .map_err(|e| format!("bad miner: {e}"))?,
        }))
    }
    fn finalized(
        &mut self,
        node: usize,
        from: u64,
        to: u64,
    ) -> Result<Vec<(u64, u64, B256)>, String> {
        let logs = zone_rpc(
            node,
            "eth_getLogs",
            json!([{
                "address": crate::zones::TEMPO_STATE,
                "topics": [topic("TempoBlockFinalized(bytes32,uint64,bytes32)")],
                "fromBlock": format!("0x{from:x}"),
                "toBlock": format!("0x{to:x}"),
            }]),
        )?;
        let logs = logs.as_array().cloned().unwrap_or_default();
        logs.iter()
            .map(|l| {
                let zb = hex_u64(&l["blockNumber"]).ok_or("bad log blockNumber")?;
                let t: Vec<B256> =
                    serde_json::from_value(l["topics"].clone()).map_err(|e| e.to_string())?;
                let (hash, num) = (t.get(1).ok_or("no topic 1")?, t.get(2).ok_or("no topic 2")?);
                let num = u64::try_from(U256::from_be_bytes(num.0)).map_err(|e| e.to_string())?;
                Ok((zb, num, *hash))
            })
            .collect()
    }
    fn info(&mut self, node: usize) -> Result<NodeInfo, String> {
        let v = zone_rpc(node, "zone_getSequencerInfo", json!([]))?;
        Ok(NodeInfo {
            role: v["local"]["role"].as_str().unwrap_or_default().to_string(),
            applied_epoch: hex_u64(&v["progress"]["locallyAppliedLeadershipEpoch"])
                .or_else(|| v["progress"]["locallyAppliedLeadershipEpoch"].as_u64()),
        })
    }
    fn l1_head(&mut self) -> Result<u64, String> {
        common::head_number()
    }
    fn l1_hash(&mut self, number: u64) -> Result<Option<B256>, String> {
        Ok(common::block_ref(number)?.map(|(h, _)| h))
    }
    fn leader_updates(&mut self, from: u64, to: u64) -> Result<Vec<Leadership>, String> {
        let logs = l1_rpc(
            "eth_getLogs",
            json!([{
                "address": PORTAL,
                "topics": [topic("LeaderUpdated(address,address,uint64,uint64)")],
                "fromBlock": format!("0x{from:x}"),
                "toBlock": format!("0x{to:x}"),
            }]),
        )?;
        let logs = logs.as_array().cloned().unwrap_or_default();
        logs.iter()
            .map(|l| {
                let t: Vec<B256> =
                    serde_json::from_value(l["topics"].clone()).map_err(|e| e.to_string())?;
                let data: alloy_primitives::Bytes =
                    serde_json::from_value(l["data"].clone()).map_err(|e| e.to_string())?;
                let word = |b: &B256| u64::try_from(U256::from_be_bytes(b.0)).unwrap_or(u64::MAX);
                Ok(Leadership {
                    leader: Address::from_word(*t.get(2).ok_or("no newLeader")?),
                    epoch: word(t.get(3).ok_or("no epoch")?),
                    activation: data.get(..32).map(B256::from_slice).map_or(0, |w| word(&w)),
                })
            })
            .collect()
    }
    fn leadership_now(&mut self) -> Result<Leadership, String> {
        let w = |sig: &str| call_l1(&selector(sig), "latest");
        let num = |b: B256| u64::try_from(U256::from_be_bytes(b.0)).unwrap_or(u64::MAX);
        Ok(Leadership {
            leader: Address::from_word(w("leader()")?),
            epoch: num(w("leaderEpoch()")?),
            activation: num(w("leaderActivationTempoBlock()")?),
        })
    }
    fn settled_height(&mut self) -> Result<u64, String> {
        let w = call_l1(&selector("zoneHeight()"), "latest")?;
        Ok(u64::try_from(U256::from_be_bytes(w.0)).unwrap_or(u64::MAX))
    }
}

#[derive(Debug, Default)]
struct NodeTrack {
    /// Next height to read.
    cursor: Option<u64>,
    hashes: BTreeMap<u64, B256>,
    /// Anchor (last finalized L1 number) after each zone block read.
    anchors: BTreeMap<u64, u64>,
    last_l1: Option<u64>,
    head: u64,
    /// Consecutive samples reporting the leader role, with the epoch.
    leader_samples: (u32, Option<u64>),
}

impl NodeTrack {
    fn anchor_at(&self, height: u64) -> Option<u64> {
        self.anchors.range(..=height).next_back().map(|(_, a)| *a)
    }
}

#[derive(Debug, Clone)]
struct Healed {
    index: u64,
    kind: String,
    nodes: Vec<usize>,
    leader_hit: bool,
    end_ns: u64,
    /// Cluster height and L1 head at the heal.
    height: u64,
    /// The L1 head at the heal, read at the next tick.
    l1_head: Option<u64>,
    done: BTreeSet<usize>,
    resumed: bool,
}

#[derive(Debug, Clone)]
struct Handoff {
    to: Address,
    /// Checked from here (the later of the rotation and the fault's end).
    from_ns: u64,
    fault: u64,
    portal_ok: bool,
}

/// E12's cluster checks (`E12/zones-cluster-*`, see the module docs). A pure state machine over [`Cluster`].
#[derive(Debug)]
pub struct ClusterOracle {
    nodes: usize,
    liveness_ns: u64,
    tracks: Vec<NodeTrack>,
    /// `(height, a, b)` disagreements and when first seen.
    disagree: BTreeMap<(u64, usize, usize), u64>,
    epochs: BTreeMap<u64, Leadership>,
    l1_scanned: Option<u64>,
    checked_blocks: BTreeSet<B256>,
    /// Network faults running: index -> (kind, nodes, excuse production,
    /// leader hit).
    active: BTreeMap<u64, (String, Vec<usize>, bool, bool)>,
    healed: Vec<Healed>,
    handoffs: Vec<Handoff>,
    down: BTreeSet<String>,
    progress_ns: u64,
    max_height: u64,
    /// Cluster height at the last progress.
    prev_height: u64,
    stall_reported: bool,
    /// The highest L1 anchor of a block each producer built.
    last_block_by: BTreeMap<Address, u64>,
    covered: BTreeSet<&'static str>,
    reported: BTreeSet<String>,
    /// Heights before this are history (not counted for coverage).
    start_heights: Vec<Option<u64>>,
}

impl ClusterOracle {
    pub fn new(nodes: usize, liveness_secs: u64, now_ns: u64) -> Self {
        ClusterOracle {
            nodes,
            liveness_ns: liveness_secs * 1_000_000_000,
            tracks: (0..nodes).map(|_| NodeTrack::default()).collect(),
            disagree: BTreeMap::new(),
            epochs: BTreeMap::new(),
            l1_scanned: None,
            checked_blocks: BTreeSet::new(),
            active: BTreeMap::new(),
            healed: Vec::new(),
            handoffs: Vec::new(),
            down: BTreeSet::new(),
            progress_ns: now_ns,
            max_height: 0,
            prev_height: 0,
            stall_reported: false,
            last_block_by: BTreeMap::new(),
            covered: BTreeSet::new(),
            reported: BTreeSet::new(),
            start_heights: vec![None; nodes],
        }
    }

    fn fail(&mut self, out: &mut Vec<Verdict>, sig: &'static str, key: String, detail: String) {
        if self.reported.insert(format!("{sig}:{key}")) {
            out.push(Verdict::Always(false, finding(sig, detail)));
        }
    }

    fn cover(&mut self, out: &mut Vec<Verdict>, sig: &'static str, detail: String) {
        if self.covered.insert(sig) {
            out.push(Verdict::Sometimes(true, finding(sig, detail)));
        }
    }

    fn node_down(&self, i: usize) -> bool {
        self.down.contains(&container(i)) || self.down.contains(crate::common::NODE_CONTAINER)
    }

    fn production_excused(&self) -> bool {
        self.active.values().any(|a| a.2)
            || self.down.contains(crate::common::NODE_CONTAINER)
            || (0..self.nodes).any(|i| self.down.contains(&container(i)))
    }

    /// Nemesis kills/restarts and network fault events.
    pub fn on_event(&mut self, ev: &common::DstEvent, now_ns: u64) {
        let d = &ev.detail;
        match (ev.source.as_str(), ev.kind.as_str()) {
            ("nemesis", "kill") if d.get("index").is_some() => {
                if let Some(c) = &ev.container {
                    self.down.insert(c.clone());
                }
            }
            ("nemesis", "restart") if d.get("index").is_some() => {
                if let Some(c) = &ev.container {
                    self.down.remove(c);
                }
                self.restart_clock(now_ns);
            }
            ("network", "fault-start") => {
                let index = d["index"].as_u64().unwrap_or(0);
                let nodes: Vec<usize> =
                    serde_json::from_value(d["hit"].clone()).unwrap_or_default();
                let leader = d["leader"].as_u64().map(|l| l as usize);
                let leader_hit = leader.is_some_and(|l| nodes.contains(&l));
                self.active.insert(
                    index,
                    (
                        d["kind"].as_str().unwrap_or_default().to_string(),
                        nodes,
                        d["excuse"]["production"].as_bool().unwrap_or(false),
                        leader_hit,
                    ),
                );
            }
            ("network", "fault-end") => {
                let index = d["index"].as_u64().unwrap_or(0);
                if let Some((kind, nodes, _, leader_hit)) = self.active.remove(&index) {
                    self.healed.push(Healed {
                        index,
                        kind,
                        nodes,
                        leader_hit,
                        end_ns: now_ns,
                        height: self.max_height,
                        l1_head: None,
                        done: BTreeSet::new(),
                        resumed: false,
                    });
                }
                self.restart_clock(now_ns);
                // A handoff made during the fault is judged from its heal.
                for h in &mut self.handoffs {
                    if h.from_ns == u64::MAX {
                        h.from_ns = now_ns;
                        h.fault = index;
                    }
                }
            }
            ("network", "handoff") => {
                let ok = d["result"].get("error").is_none();
                let to = d["to_address"].as_str().and_then(|s| s.parse().ok());
                if let (true, Some(to)) = (ok, to) {
                    let fault = self.active.keys().next_back().copied().unwrap_or(0);
                    let from_ns = if self.active.is_empty() {
                        now_ns
                    } else {
                        u64::MAX
                    };
                    self.handoffs.push(Handoff {
                        to,
                        from_ns,
                        fault,
                        portal_ok: false,
                    });
                }
            }
            _ => {}
        }
    }

    fn restart_clock(&mut self, now_ns: u64) {
        self.progress_ns = now_ns;
        self.stall_reported = false;
    }

    pub fn tick(&mut self, c: &mut impl Cluster, now_ns: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        self.sync_leadership(c);
        for i in 0..self.nodes {
            if !self.node_down(i) {
                self.sync_node(c, i, &mut out);
            }
        }
        self.check_forks(c, now_ns, &mut out);
        self.check_roles(c, &mut out);
        self.check_progress(now_ns, &mut out);
        if let Ok(head) = c.l1_head() {
            for h in self.healed.iter_mut().filter(|h| h.l1_head.is_none()) {
                h.l1_head = Some(head);
            }
        }
        self.check_healed(now_ns, &mut out);
        self.check_handoffs(c, now_ns, &mut out);
        out
    }

    fn sync_leadership(&mut self, c: &mut impl Cluster) {
        let Ok(head) = c.l1_head() else { return };
        if self.l1_scanned.is_none() {
            if let Ok(now) = c.leadership_now() {
                self.epochs.entry(now.epoch).or_insert(now);
            }
        }
        let from = self.l1_scanned.map_or(0, |s| s + 1);
        if from > head {
            return;
        }
        let to = head.min(from + 5000);
        if let Ok(updates) = c.leader_updates(from, to) {
            for u in updates {
                self.epochs.insert(u.epoch, u);
            }
            self.l1_scanned = Some(to);
        }
    }

    /// Leaders of epochs active for any anchor in `lo..=hi`.
    fn leaders_over(&self, lo: u64, hi: u64) -> Option<BTreeSet<Address>> {
        let first = self.epochs.values().next()?;
        if lo < first.activation {
            // Older than the history we know.
            return None;
        }
        let mut out = BTreeSet::new();
        let mut current = None;
        for e in self.epochs.values() {
            if e.activation <= lo {
                current = Some(e.leader);
            } else if e.activation <= hi {
                out.insert(e.leader);
            }
        }
        out.extend(current);
        Some(out)
    }

    fn sync_node(&mut self, c: &mut impl Cluster, i: usize, out: &mut Vec<Verdict>) {
        let Ok(head) = c.head(i) else { return };
        let t = &mut self.tracks[i];
        t.head = head;
        if self.start_heights[i].is_none() {
            self.start_heights[i] = Some(head);
        }
        let mut next = t.cursor.unwrap_or(head.saturating_sub(4).max(1));
        // A rebuilt tip: walk back to where the parent links up.
        while next > 1 {
            let Some(prev) = self.tracks[i].hashes.get(&(next - 1)).copied() else {
                break;
            };
            match c.block(i, next - 1) {
                Ok(Some(b)) if b.hash == prev => break,
                Ok(_) => {
                    let t = &mut self.tracks[i];
                    t.hashes.remove(&(next - 1));
                    t.anchors.remove(&(next - 1));
                    next -= 1;
                    // The rebuilt blocks finalize their L1 blocks again.
                    t.last_l1 = t.anchor_at(next - 1);
                }
                Err(_) => return,
            }
        }
        let end = head.min(next + BLOCKS_PER_TICK - 1);
        if next > end {
            self.tracks[i].cursor = Some(next);
            return;
        }
        let Ok(finalized) = c.finalized(i, next, end) else {
            return;
        };
        let mut by_block: BTreeMap<u64, Vec<(u64, B256)>> = BTreeMap::new();
        for (zb, num, hash) in finalized {
            by_block.entry(zb).or_default().push((num, hash));
        }
        for n in next..=end {
            let Ok(Some(b)) = c.block(i, n) else { break };
            let prev_anchor = self.tracks[i].anchor_at(n.saturating_sub(1));
            for (num, hash) in by_block.remove(&n).unwrap_or_default() {
                // TempoState links consecutive headers by parent hash, and
                // one finalization event names the last header of a batch
                // (a backfill imports many per block), so anchors only move
                // forward; a jump is the backfill path at work.
                if let Some(last) = self.tracks[i].last_l1 {
                    if num <= last {
                        self.fail(
                            out,
                            "E12/zones-cluster-anchor-regressed",
                            format!("{i}:{num}"),
                            format!("node {i} zone block {n}: finalized L1 {num} after {last}"),
                        );
                    } else if num > last + 1 && self.start_heights[i].is_some_and(|s| n > s) {
                        self.cover(
                            out,
                            "S/cluster-l1-backfilled",
                            format!("node {i} zone block {n} imported L1 {}..={num}", last + 1),
                        );
                    }
                }
                self.tracks[i].last_l1 = Some(num);
                if let Ok(Some(l1)) = c.l1_hash(num) {
                    if l1 != hash {
                        self.fail(
                            out,
                            "E12/zones-cluster-anchor-mismatch",
                            format!("{i}:{num}"),
                            format!(
                                "node {i} zone block {n}: finalized L1 {num} as {hash}, L1 has {l1}"
                            ),
                        );
                    }
                }
            }
            let t = &mut self.tracks[i];
            if let Some(a) = t.last_l1 {
                t.anchors.insert(n, a);
            }
            t.hashes.insert(n, b.hash);
            let anchor = t.anchor_at(n);
            if n > KEEP_HEIGHTS {
                let cut = n - KEEP_HEIGHTS;
                t.hashes = t.hashes.split_off(&cut);
                t.anchors = t.anchors.split_off(&cut);
            }
            t.cursor = Some(n + 1);
            self.max_height = self.max_height.max(n);
            if let Some(a) = anchor {
                let e = self.last_block_by.entry(b.beneficiary).or_insert(a);
                *e = (*e).max(a);
            }
            self.check_producer(&b, prev_anchor, anchor, i, out);
        }
    }

    fn check_producer(
        &mut self,
        b: &ZBlock,
        prev_anchor: Option<u64>,
        anchor: Option<u64>,
        node: usize,
        out: &mut Vec<Verdict>,
    ) {
        if !self.checked_blocks.insert(b.hash) {
            return;
        }
        let (Some(lo), Some(hi)) = (prev_anchor, anchor) else {
            return;
        };
        let Some(allowed) = self.leaders_over(lo, hi + 1) else {
            return;
        };
        if self.start_heights[node].is_some_and(|s| b.number > s) {
            self.cover(
                out,
                "S/cluster-blocks-checked",
                format!("node {node} block {} by {}", b.number, b.beneficiary),
            );
        }
        if !allowed.contains(&b.beneficiary) {
            self.fail(
                out,
                "E12/zones-cluster-leader-mismatch",
                b.hash.to_string(),
                format!(
                    "zone block {} ({}) on node {node} produced by {} applying L1 anchors {lo}..={hi}; \
                     leaders of those epochs: {allowed:?}",
                    b.number, b.hash, b.beneficiary
                ),
            );
        }
    }

    fn check_forks(&mut self, c: &mut impl Cluster, now_ns: u64, out: &mut Vec<Verdict>) {
        let settled = c.settled_height().unwrap_or(0);
        let mut seen = BTreeSet::new();
        for a in 0..self.nodes {
            for b in a + 1..self.nodes {
                let common: Vec<(u64, B256, B256)> = self.tracks[a]
                    .hashes
                    .iter()
                    .filter_map(|(h, x)| self.tracks[b].hashes.get(h).map(|y| (*h, *x, *y)))
                    .collect();
                for (h, x, y) in common {
                    let key = (h, a, b);
                    if x == y {
                        self.disagree.remove(&key);
                        continue;
                    }
                    seen.insert(key);
                    let first = *self.disagree.entry(key).or_insert(now_ns);
                    if h <= settled || now_ns.saturating_sub(first) > FORK_GRACE_NS {
                        self.fail(
                            out,
                            "E12/zones-cluster-fork",
                            format!("{h}"),
                            format!(
                                "height {h}: node {a} has {x}, node {b} has {y} (settled height {settled})"
                            ),
                        );
                    }
                }
            }
        }
        self.disagree.retain(|k, _| seen.contains(k));
        // All nodes agree at a height produced during the run.
        let start = self.start_heights.iter().flatten().max().copied();
        if let Some(start) = start {
            let agreed = self.tracks[0].hashes.iter().rev().find(|(h, x)| {
                **h > start && self.tracks[1..].iter().all(|t| t.hashes.get(h) == Some(x))
            });
            if let Some((h, x)) = agreed {
                let d = format!("all {} nodes hold {x} at height {h}", self.nodes);
                self.cover(out, "S/cluster-converged", d);
            }
        }
    }

    fn check_roles(&mut self, c: &mut impl Cluster, out: &mut Vec<Verdict>) {
        let mut leaders: BTreeMap<Option<u64>, Vec<usize>> = BTreeMap::new();
        for i in 0..self.nodes {
            if self.node_down(i) {
                self.tracks[i].leader_samples = (0, None);
                continue;
            }
            match c.info(i) {
                Ok(info) if info.role == "leader" => {
                    let s = &mut self.tracks[i].leader_samples;
                    *s = if s.1 == info.applied_epoch {
                        (s.0 + 1, s.1)
                    } else {
                        (1, info.applied_epoch)
                    };
                    if s.0 >= 2 {
                        leaders.entry(info.applied_epoch).or_default().push(i);
                    }
                }
                Ok(_) => self.tracks[i].leader_samples = (0, None),
                Err(_) => {}
            }
        }
        for (epoch, nodes) in leaders {
            if nodes.len() > 1 && epoch.is_some() {
                self.fail(
                    out,
                    "E12/zones-cluster-double-leader",
                    format!("{epoch:?}"),
                    format!("nodes {nodes:?} both lead locally applied epoch {epoch:?}"),
                );
            }
        }
    }

    fn check_progress(&mut self, now_ns: u64, out: &mut Vec<Verdict>) {
        let height = self.tracks.iter().map(|t| t.head).max().unwrap_or(0);
        self.max_height = self.max_height.max(height);
        if height > self.prev_height {
            self.prev_height = height;
            self.progress_ns = now_ns;
            self.stall_reported = false;
            return;
        }
        if self.production_excused() {
            self.progress_ns = now_ns;
            return;
        }
        if !self.stall_reported && now_ns.saturating_sub(self.progress_ns) > self.liveness_ns {
            self.stall_reported = true;
            out.push(Verdict::Always(
                false,
                finding(
                    "E12/zones-cluster-production-stalled",
                    format!(
                        "cluster height {height} did not advance for {}s with the leader healthy",
                        self.liveness_ns / 1_000_000_000
                    ),
                ),
            ));
        }
    }

    fn check_healed(&mut self, now_ns: u64, out: &mut Vec<Verdict>) {
        let cluster = self.tracks.iter().map(|t| t.head).max().unwrap_or(0);
        let mut healed = std::mem::take(&mut self.healed);
        for h in &mut healed {
            let l1_cut = h.kind.starts_with("l1-cut");
            for &i in &h.nodes {
                let t = &self.tracks[i];
                let zone_ok = t.head >= h.height;
                // Backfilled to (within finality of) the L1 head at the heal.
                let l1_ok = !l1_cut
                    || h.l1_head
                        .is_some_and(|head| t.last_l1.is_some_and(|a| a + 4 >= head));
                if zone_ok && l1_ok {
                    h.done.insert(i);
                }
            }
            if !h.resumed && h.leader_hit && cluster > h.height {
                h.resumed = true;
                let d = format!(
                    "fault {} ({}) cut off the leader; cluster height {} -> {cluster} after the heal",
                    h.index, h.kind, h.height
                );
                self.cover(out, "S/net-leader-isolated", d);
            }
            let all = h.nodes.iter().all(|i| h.done.contains(i));
            if all {
                let d = format!(
                    "fault {} ({}): nodes {:?} back at height {} / L1 {}",
                    h.index,
                    h.kind,
                    h.nodes,
                    h.height,
                    h.l1_head.unwrap_or(0)
                );
                match h.kind.as_str() {
                    k if k.starts_with("l1-cut") => self.cover(out, "S/net-l1-cut-restored", d),
                    "partition" | "one-way-partition" => {
                        self.cover(out, "S/net-partition-healed", d)
                    }
                    "link-netem" | "l1-netem" => self.cover(out, "S/net-degraded-kept-up", d),
                    _ => {}
                }
            } else if now_ns.saturating_sub(h.end_ns) > self.liveness_ns
                && h.nodes.iter().all(|&i| !self.node_down(i))
            {
                let lagging: Vec<_> = h
                    .nodes
                    .iter()
                    .filter(|i| !h.done.contains(i))
                    .map(|&i| (i, self.tracks[i].head, self.tracks[i].last_l1))
                    .collect();
                let detail = format!(
                    "fault {} ({}) healed {}s ago: (node, height, L1 anchor) {lagging:?} short of height {} / L1 {}",
                    h.index,
                    h.kind,
                    self.liveness_ns / 1_000_000_000,
                    h.height,
                    h.l1_head.unwrap_or(0)
                );
                self.fail(
                    out,
                    "E12/zones-cluster-not-caught-up",
                    h.index.to_string(),
                    detail,
                );
            }
        }
        healed.retain(|h| {
            let all = h.nodes.iter().all(|i| h.done.contains(i));
            let expired = now_ns.saturating_sub(h.end_ns) > self.liveness_ns;
            !(all && (h.resumed || !h.leader_hit)) && !expired
        });
        self.healed = healed;
    }

    fn check_handoffs(&mut self, c: &mut impl Cluster, now_ns: u64, out: &mut Vec<Verdict>) {
        let now_leader = c.leadership_now().ok();
        let mut handoffs = std::mem::take(&mut self.handoffs);
        handoffs.retain_mut(|h| {
            if h.from_ns == u64::MAX {
                return true;
            }
            if now_leader.is_some_and(|l| l.leader == h.to) {
                h.portal_ok = true;
            }
            // A block the target built at or after its epoch's activation.
            let activation = self
                .epochs
                .values()
                .filter(|e| e.leader == h.to)
                .map(|e| e.activation)
                .max();
            let produced = activation.is_some_and(|act| {
                self.last_block_by.get(&h.to).is_some_and(|&a| a >= act)
            });
            if h.portal_ok && produced {
                let d = format!("leadership handed to {} (fault {})", h.to, h.fault);
                self.cover(out, "S/net-handoff-completed", d);
                return false;
            }
            if now_ns.saturating_sub(h.from_ns) > self.liveness_ns {
                let d = format!(
                    "fault {}: {}s after the heal, portal leader {:?}, target {} produced a block: {produced}",
                    h.fault,
                    self.liveness_ns / 1_000_000_000,
                    now_leader.map(|l| l.leader),
                    h.to
                );
                self.fail(out, "E12/zones-cluster-handoff-incomplete", h.fault.to_string(), d);
                return false;
            }
            true
        });
        self.handoffs = handoffs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::DstEvent;

    const S: u64 = 1_000_000_000;

    /// A fake three-sequencer cluster: every node holds a prefix of one
    /// chain (or its own fork), each zone block finalizing one L1 block.
    #[derive(Default)]
    struct Fake {
        /// Per node: zone blocks (index = number - 1).
        chains: Vec<Vec<ZBlock>>,
        /// Per node: zone block -> finalized L1 numbers.
        finalized: Vec<BTreeMap<u64, Vec<u64>>>,
        roles: Vec<NodeInfo>,
        l1_head: u64,
        updates: Vec<(u64, Leadership)>,
        now: Option<Leadership>,
        settled: u64,
    }

    fn h(tag: u64) -> B256 {
        B256::from(U256::from(tag))
    }

    fn l1_hash(n: u64) -> B256 {
        h(1_000_000 + n)
    }

    fn producer(i: usize) -> Address {
        sequencer_address(i)
    }

    impl Fake {
        fn new() -> Fake {
            let lead = Leadership {
                epoch: 1,
                leader: producer(0),
                activation: 1,
            };
            Fake {
                chains: vec![Vec::new(); 3],
                finalized: vec![BTreeMap::new(); 3],
                roles: (0..3)
                    .map(|i| NodeInfo {
                        role: if i == 0 { "leader" } else { "follower" }.into(),
                        applied_epoch: Some(1),
                    })
                    .collect(),
                l1_head: 100,
                updates: vec![(1, lead)],
                now: Some(lead),
                settled: 0,
            }
        }

        /// Appends a block built by `by` finalizing `l1` to `nodes`.
        fn push(&mut self, nodes: &[usize], by: usize, l1: &[u64], fork: u64) {
            for &i in nodes {
                let number = self.chains[i].len() as u64 + 1;
                let parent = self.chains[i].last().map_or(B256::ZERO, |b| b.hash);
                self.chains[i].push(ZBlock {
                    number,
                    hash: h(number * 10 + fork),
                    parent,
                    beneficiary: producer(by),
                });
                self.finalized[i].insert(number, l1.to_vec());
            }
        }
    }

    impl Cluster for Fake {
        fn head(&mut self, node: usize) -> Result<u64, String> {
            Ok(self.chains[node].len() as u64)
        }
        fn block(&mut self, node: usize, number: u64) -> Result<Option<ZBlock>, String> {
            Ok(number
                .checked_sub(1)
                .and_then(|i| self.chains[node].get(i as usize).cloned()))
        }
        fn finalized(
            &mut self,
            node: usize,
            from: u64,
            to: u64,
        ) -> Result<Vec<(u64, u64, B256)>, String> {
            Ok(self.finalized[node]
                .range(from..=to)
                .flat_map(|(zb, nums)| nums.iter().map(move |&n| (*zb, n, l1_hash(n))))
                .collect())
        }
        fn info(&mut self, node: usize) -> Result<NodeInfo, String> {
            Ok(self.roles[node].clone())
        }
        fn l1_head(&mut self) -> Result<u64, String> {
            Ok(self.l1_head)
        }
        fn l1_hash(&mut self, number: u64) -> Result<Option<B256>, String> {
            Ok(Some(l1_hash(number)))
        }
        fn leader_updates(&mut self, from: u64, to: u64) -> Result<Vec<Leadership>, String> {
            Ok(self
                .updates
                .iter()
                .filter(|(b, _)| (from..=to).contains(b))
                .map(|(_, l)| *l)
                .collect())
        }
        fn leadership_now(&mut self) -> Result<Leadership, String> {
            self.now.ok_or_else(|| "no portal".into())
        }
        fn settled_height(&mut self) -> Result<u64, String> {
            Ok(self.settled)
        }
    }

    fn sigs(out: &[Verdict]) -> Vec<(bool, String)> {
        out.iter()
            .map(|v| match v {
                Verdict::Always(ok, f) => (*ok, f.signature.clone()),
                Verdict::Sometimes(ok, f) => (*ok, f.signature.clone()),
            })
            .collect()
    }

    fn failures(out: &[Verdict]) -> Vec<String> {
        sigs(out)
            .into_iter()
            .filter(|(ok, s)| !ok || s.starts_with('E'))
            .map(|(_, s)| s)
            .collect()
    }

    fn ev(source: &str, kind: &str, container: Option<&str>, detail: Value) -> DstEvent {
        DstEvent {
            source: source.into(),
            kind: kind.into(),
            container: container.map(Into::into),
            guest_time_ns: 0,
            detail,
        }
    }

    /// A healthy cluster: node 0 leads, every node holds every block.
    fn healthy(blocks: u64) -> Fake {
        let mut f = Fake::new();
        for n in 1..=blocks {
            f.push(&[0, 1, 2], 0, &[n], 0);
        }
        f
    }

    #[test]
    fn a_converged_cluster_passes_with_coverage() {
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        assert!(failures(&o.tick(&mut f, S)).is_empty());
        for n in 4..=6 {
            f.push(&[0, 1, 2], 0, &[n], 0);
        }
        let out = o.tick(&mut f, 2 * S);
        assert!(failures(&out).is_empty(), "{:?}", sigs(&out));
        let s: Vec<_> = sigs(&out).into_iter().map(|x| x.1).collect();
        assert!(s.contains(&"S/cluster-converged".to_string()), "{s:?}");
        assert!(s.contains(&"S/cluster-blocks-checked".to_string()));
    }

    #[test]
    fn diverging_sequencers_are_a_fork() {
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        // Node 2 imports another block at height 4.
        f.push(&[0, 1], 0, &[4], 0);
        f.push(&[2], 0, &[4], 7);
        assert!(
            failures(&o.tick(&mut f, 2 * S)).is_empty(),
            "within the grace"
        );
        let out = o.tick(&mut f, 2 * S + FORK_GRACE_NS + S);
        assert_eq!(failures(&out), ["E12/zones-cluster-fork"]);
        // At or below the settled height there is no grace.
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        f.settled = 4;
        f.push(&[0], 0, &[4], 0);
        f.push(&[1, 2], 0, &[4], 3);
        assert_eq!(failures(&o.tick(&mut f, 2 * S)), ["E12/zones-cluster-fork"]);
    }

    #[test]
    fn blocks_must_come_from_the_epochs_leader() {
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        // Node 1 builds without leadership.
        f.push(&[0, 1, 2], 1, &[4], 0);
        assert_eq!(
            failures(&o.tick(&mut f, 2 * S)),
            ["E12/zones-cluster-leader-mismatch"]
        );
        // After a handoff activating at L1 10, node 1's blocks are fine.
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        let next = Leadership {
            epoch: 2,
            leader: producer(1),
            activation: 10,
        };
        f.updates.push((101, next));
        f.now = Some(next);
        f.l1_head = 102;
        for n in 4..10 {
            f.push(&[0, 1, 2], 0, &[n], 0);
        }
        f.push(&[0, 1, 2], 1, &[10], 0);
        f.push(&[0, 1, 2], 1, &[11], 0);
        let out = o.tick(&mut f, 2 * S);
        assert!(failures(&out).is_empty(), "{:?}", sigs(&out));
        // The old leader past the activation is not.
        f.push(&[0, 1, 2], 0, &[12], 0);
        assert_eq!(
            failures(&o.tick(&mut f, 3 * S)),
            ["E12/zones-cluster-leader-mismatch"]
        );
    }

    #[test]
    fn l1_anchors_move_forward_on_the_canonical_chain() {
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        // A reconnect backfills L1 4..=9 in one zone block: fine, covered.
        f.push(&[0, 1, 2], 0, &[9], 0);
        let out = o.tick(&mut f, 2 * S);
        assert!(failures(&out).is_empty(), "{:?}", sigs(&out));
        assert!(sigs(&out).iter().any(|s| s.1 == "S/cluster-l1-backfilled"));
        // Going back is not.
        f.push(&[0], 0, &[8], 0);
        assert_eq!(
            failures(&o.tick(&mut f, 3 * S)),
            ["E12/zones-cluster-anchor-regressed"]
        );
    }

    #[test]
    fn two_leaders_for_one_epoch_are_reported_once_sustained() {
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        f.roles[2].role = "leader".into();
        assert!(failures(&o.tick(&mut f, 2 * S)).is_empty(), "one sample");
        assert_eq!(
            failures(&o.tick(&mut f, 3 * S)),
            ["E12/zones-cluster-double-leader"]
        );
        // A handoff in flight (another applied epoch) is not.
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        f.roles[1] = NodeInfo {
            role: "leader".into(),
            applied_epoch: Some(2),
        };
        for t in 1..4 {
            assert!(failures(&o.tick(&mut f, t * S)).is_empty());
        }
    }

    #[test]
    fn production_stalls_are_excused_only_while_the_leader_is_cut() {
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        // The leader loses L1: the fault excuses production.
        o.on_event(
            &ev(
                "network",
                "fault-start",
                None,
                json!({"index": 0, "kind": "l1-cut-leader", "hit": [0], "leader": 0,
                       "excuse": {"settlement": true, "production": true, "observer": true}}),
            ),
            2 * S,
        );
        assert!(failures(&o.tick(&mut f, 100 * S)).is_empty());
        o.on_event(
            &ev(
                "network",
                "fault-end",
                None,
                json!({"index": 0, "kind": "l1-cut-leader", "hit": [0]}),
            ),
            100 * S,
        );
        // The clock restarted at the heal; production resumes in time and
        // backfills the L1 blocks of the outage.
        f.l1_head = 10;
        let out = o.tick(&mut f, 150 * S);
        assert!(failures(&out).is_empty());
        assert!(!sigs(&out).iter().any(|s| s.1 == "S/net-l1-cut-restored"));
        f.push(&[0, 1, 2], 0, &[9], 0);
        let out = o.tick(&mut f, 155 * S);
        assert!(failures(&out).is_empty(), "{:?}", sigs(&out));
        let s: Vec<_> = sigs(&out).into_iter().map(|x| x.1).collect();
        assert!(s.contains(&"S/net-leader-isolated".into()), "{s:?}");
        assert!(s.contains(&"S/net-l1-cut-restored".into()), "{s:?}");
        // Without an excuse a stall is a finding.
        assert_eq!(
            failures(&o.tick(&mut f, 300 * S)),
            ["E12/zones-cluster-production-stalled"]
        );
    }

    #[test]
    fn healed_nodes_must_catch_up() {
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        o.on_event(
            &ev(
                "network",
                "fault-start",
                None,
                json!({"index": 1, "kind": "partition", "hit": [2], "leader": 0,
                       "excuse": {"settlement": false, "production": false, "observer": false}}),
            ),
            2 * S,
        );
        for n in 4..=8 {
            f.push(&[0, 1], 0, &[n], 0);
        }
        o.tick(&mut f, 10 * S);
        o.on_event(
            &ev(
                "network",
                "fault-end",
                None,
                json!({"index": 1, "kind": "partition", "hit": [2]}),
            ),
            12 * S,
        );
        // Node 2 never catches up.
        assert!(failures(&o.tick(&mut f, 20 * S)).is_empty());
        f.push(&[0, 1], 0, &[9], 0);
        assert_eq!(
            failures(&o.tick(&mut f, 80 * S)),
            ["E12/zones-cluster-not-caught-up"]
        );
        // The same partition healing properly is covered.
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        o.on_event(
            &ev(
                "network",
                "fault-start",
                None,
                json!({"index": 1, "kind": "partition", "hit": [2], "leader": 0, "excuse": {}}),
            ),
            2 * S,
        );
        for n in 4..=8 {
            f.push(&[0, 1], 0, &[n], 0);
        }
        o.tick(&mut f, 10 * S);
        o.on_event(
            &ev("network", "fault-end", None, json!({"index": 1})),
            12 * S,
        );
        f.chains[2] = f.chains[0].clone();
        f.finalized[2] = f.finalized[0].clone();
        let out = o.tick(&mut f, 14 * S);
        assert!(failures(&out).is_empty(), "{:?}", sigs(&out));
        assert!(sigs(&out).iter().any(|s| s.1 == "S/net-partition-healed"));
    }

    #[test]
    fn handoffs_must_complete_after_the_heal() {
        let handoff = |o: &mut ClusterOracle, t| {
            o.on_event(
                &ev(
                    "network",
                    "handoff",
                    None,
                    json!({"index": 3, "from": 0, "to": 2, "to_address": producer(2),
                           "result": {"via": 0}}),
                ),
                t,
            );
        };
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        handoff(&mut o, 2 * S);
        let next = Leadership {
            epoch: 2,
            leader: producer(2),
            activation: 6,
        };
        f.updates.push((101, next));
        f.now = Some(next);
        f.l1_head = 102;
        f.push(&[0, 1, 2], 0, &[4], 0);
        f.push(&[0, 1, 2], 0, &[5], 0);
        assert!(failures(&o.tick(&mut f, 3 * S)).is_empty());
        f.push(&[0, 1, 2], 2, &[6], 0);
        let out = o.tick(&mut f, 4 * S);
        assert!(failures(&out).is_empty(), "{:?}", sigs(&out));
        assert!(sigs(&out).iter().any(|s| s.1 == "S/net-handoff-completed"));
        // A rotation that never takes effect is a finding.
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        handoff(&mut o, 2 * S);
        for t in [10, 40, 70] {
            f.push(&[0, 1, 2], 0, &[4 + t], 0);
            let out = o.tick(&mut f, t * S);
            if t == 70 {
                assert!(
                    failures(&out).contains(&"E12/zones-cluster-handoff-incomplete".to_string())
                );
            } else {
                assert!(failures(&out).is_empty());
            }
        }
    }

    #[test]
    fn killed_nodes_are_not_read_and_excuse_production() {
        let mut f = healthy(3);
        let mut o = ClusterOracle::new(3, 60, 0);
        o.tick(&mut f, S);
        o.on_event(
            &ev("nemesis", "kill", Some("zone-0"), json!({"index": 0})),
            2 * S,
        );
        assert!(failures(&o.tick(&mut f, 200 * S)).is_empty());
        o.on_event(
            &ev("nemesis", "restart", Some("zone-0"), json!({"index": 0})),
            200 * S,
        );
        f.push(&[0, 1, 2], 0, &[4], 0);
        assert!(failures(&o.tick(&mut f, 201 * S)).is_empty());
    }
    #[test]
    fn compose_and_provisioning_match_the_topology() {
        let compose = include_str!("../../../contrib/bedrock-dst/compose.yaml");
        let provision = include_str!("../../../contrib/bedrock-dst/zones/zone-provision.sh");
        let multi = include_str!("../../../contrib/bedrock-dst/zones/zone-multi.sh");
        for (i, sequencer) in SEQUENCERS.iter().enumerate() {
            let ip = node_ip(i).to_string();
            assert!(compose.contains(&format!("ipv4_address: {ip}")), "{ip}");
            assert!(compose.contains(&format!("container_name: {}", container(i))));
            assert!(compose.contains(&format!("0.0.0.0:{}=127.0.0.1:8546", l1_port(i))));
            assert!(provision.contains(sequencer), "{sequencer}");
        }
        assert!(compose.contains(&format!("gateway: {GATEWAY}")));
        assert!(provision.contains("10.90.10.$((11 + j)):9200") && multi.contains("18600 + N"));
        assert!(multi.contains(&format!("GW={GATEWAY}")));
        assert_eq!(crate::zones::ZoneEndpoints::CLUSTER.rpc, rpc_url(0));
        assert_eq!(
            crate::zones::ZoneEndpoints::CLUSTER.private_rpc,
            format!("http://{}:{PRIVATE_RPC_PORT}", node_ip(0))
        );
    }
    #[test]
    fn zones_families_draw_role_based_steps() {
        let mut x = 7u64;
        let mut d = |lo: u64, hi: u64| {
            x = crate::planner::splitmix64(x);
            lo + x % (hi - lo + 1)
        };
        for kind in FAMILIES {
            let steps = draw_family(kind, 20, &mut d).unwrap();
            assert!(!steps.is_empty(), "{kind:?}");
            let handoff = steps
                .iter()
                .any(|s| matches!(s.action, NetAction::SetLeader { .. }));
            assert_eq!(handoff, kind.name().starts_with("handoff"), "{kind:?}");
        }
        // Generic families are not the cluster's to draw.
        assert!(draw_family(NetFaultKind::Partition, 20, &mut d).is_none());
        // The outgoing leader is cut only after the rotation.
        let s = draw_family(NetFaultKind::HandoffOutgoingIsolated, 20, &mut d).unwrap();
        assert!(matches!(s[0].action, NetAction::SetLeader { .. }));
        assert!(s[1..].iter().all(|st| st.after_secs > s[0].after_secs));
        // L1 cuts target the forwarder endpoint with the node's role.
        let s = draw_family(NetFaultKind::L1CutLeader, 20, &mut d).unwrap();
        let NetAction::Cut { from, to, .. } = &s[0].action else {
            panic!()
        };
        assert_eq!(
            from,
            &[NodeRef::Role {
                role: "leader".into(),
                pick: from_pick(from)
            }]
        );
        assert_eq!(
            to,
            &[Peer::Endpoint {
                endpoint: "l1".into()
            }]
        );
    }

    fn from_pick(f: &[NodeRef]) -> u32 {
        match &f[0] {
            NodeRef::Role { pick, .. } => *pick,
            _ => 0,
        }
    }

    #[test]
    fn excuses_follow_zones_fault_matrix() {
        // Leader 1, followers 0 and 2.
        let e = |k, hit: &[usize]| excuse(k, 1, hit, None);
        // Both followers lose L1: production continues, settlement stalls.
        assert_eq!(
            e(NetFaultKind::L1CutFollowers, &[0, 2]),
            NetExcuse {
                settlement: true,
                production: false,
                observer: true
            }
        );
        // The leader: both stall.
        let l = e(NetFaultKind::L1CutLeader, &[1]);
        assert!(l.settlement && l.production);
        // One follower: 2-of-3 continues; nothing excused.
        assert_eq!(e(NetFaultKind::L1CutFollower, &[2]), NetExcuse::default());
        // Partitions: the leader's side needs a quorum; node 0 elsewhere.
        let lone_follower = excuse(
            NetFaultKind::Partition,
            1,
            &[2],
            Some(&[vec![2], vec![0, 1]]),
        );
        assert_eq!(lone_follower, NetExcuse::default());
        let lone_leader = excuse(
            NetFaultKind::Partition,
            1,
            &[1],
            Some(&[vec![1], vec![0, 2]]),
        );
        assert!(lone_leader.settlement && lone_leader.observer);
        // Blocked handoffs excuse everything; latency must keep settling.
        assert!(e(NetFaultKind::HandoffIncomingIsolated, &[0, 2]).production);
        assert_eq!(
            e(NetFaultKind::HandoffLatency, &[0, 1, 2]),
            NetExcuse::default()
        );
    }

    #[test]
    fn the_cluster_topology_scopes_faults_to_p2p_and_spares_the_oracle() {
        let t = topology();
        assert_eq!(t.names(), ["zone-0", "zone-1", "zone-2"]);
        assert_eq!(t.fault_ports, [P2P_PORT]);
        let l1 = t.endpoint("l1").unwrap();
        assert_eq!(l1.ports, [18600, 18601, 18602]);
        let mut wl = netfault::Plain;
        let mut r = netfault::Resolver::new(&t, &mut wl);
        let cut = NetAction::Cut {
            from: vec![NodeRef::Node {
                node: "zone-1".into(),
            }],
            to: l1_peer(),
            ports: vec![],
            mode: CutMode::Reset,
        };
        let rules = netfault::rules(&cut, &mut r).unwrap();
        assert!(!netfault::oracle_path_cut(&rules, &t));
    }

    fn l1_peer() -> Vec<Peer> {
        vec![Peer::Endpoint {
            endpoint: "l1".into(),
        }]
    }
}
