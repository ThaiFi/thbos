// SPDX-License-Identifier: GPL-2.0

//! Network nemesis: partitions, link cuts, connection resets and per-link
//! netem between named containers, planned like the crash nemesis' kills.
//!
//! Generic over the workload: a [`NetTopology`] names the nodes the nemesis
//! may fault (containers with their IPs, each in its own network namespace),
//! named external endpoints they talk to (e.g. a proxy in front of the
//! host-network L1), the ports faults are scoped to by default, and the path
//! the oracles use (so a fault that cuts it is reported). Plan entries are
//! the typed [`NetFault`]s of `planner.rs`; this module schedules them and
//! applies them inside each node's network namespace (`nsenter -t <pid> -n`):
//!
//! - **cut** / **partition**: `iptables` rules in a `BEDROCK_NET` chain hooked
//!   first into `INPUT` and `OUTPUT`. [`CutMode::Reset`] rejects with TCP RST:
//!   established connections die on their next segment and new ones are
//!   refused, without touching the processes; [`CutMode::Drop`] silently
//!   drops (a stall). Rules match the peer's IP and, when scoped, the ports
//!   in either direction (whoever dialed). One-way partitions only block what
//!   a side sends. Restoring flushes the chain: clients reconnect through
//!   their normal path to the same endpoint.
//! - **reset**: `ss -K` kills established TCP sockets to the peers (the
//!   listener and new connections are untouched), at planned offsets.
//! - **netem**: a `prio` qdisc on the node's `eth0` with `netem` on an extra
//!   band and `u32` filters for each (peer IP, port): delay, jitter, loss and
//!   rate on exactly the planned links, in the planned direction only.
//!
//! Determinism: timing is guest time from the nemesis' start; every planned
//! parameter is drawn from Bedrock-controlled randomness (`decisions=guest`)
//! or by the planner from the seed (`decisions=explicit`) and recorded in the
//! plan; netem's per-packet draws use the guest kernel's PRNG (seeded by
//! Bedrock, on the tape) and its timers run on the emulated clock. Roles
//! ([`NodeRef::Role`], e.g. a leader) are resolved by the workload
//! ([`NetWorkload`]) when a fault starts and logged in its `fault-start`
//! event. Faults never overlap each other or a kill, and every fault ends
//! with every node healed. Needs a guest kernel with `CONFIG_NET_SCH_NETEM`,
//! `NET_SCH_PRIO`, `NET_CLS_U32`, `IP_NF_TARGET_REJECT` and
//! `INET_DIAG_DESTROY` (nix/guest-kernel.nix).

use std::{collections::BTreeSet, net::Ipv4Addr, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::common;
pub use crate::planner::{
    CutMode, NetAction, NetFault, NetFaultKind, NetStep, NetemShape, NodeRef, Peer,
};

/// Guest seconds after nemesis start before the first network fault.
pub const NET_WARMUP_SECS: u64 = 10;
/// Fault durations.
pub const MIN_FAULT_SECS: u64 = 10;
pub const MAX_FAULT_SECS: u64 = 30;
/// Quiet time kept before a kill and after its restart.
pub const KILL_MARGIN_BEFORE_SECS: u64 = 5;
pub const KILL_MARGIN_AFTER_SECS: u64 = 20;
/// The `iptables` chain the nemesis owns in each node's namespace.
const CHAIN: &str = "BEDROCK_NET";

/// A container the nemesis may fault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetNode {
    /// Container name (`podman inspect` finds its namespace).
    pub name: String,
    pub ip: Ipv4Addr,
}

/// Something outside the topology's nodes they connect to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetEndpoint {
    pub name: String,
    pub ip: Ipv4Addr,
    /// Its ports (a fault scoped to the endpoint without ports uses these).
    pub ports: Vec<u16>,
}

/// What the network nemesis may fault, from the workload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetTopology {
    pub nodes: Vec<NetNode>,
    pub endpoints: Vec<NetEndpoint>,
    /// Ports generic faults between nodes are scoped to (e.g. the consensus
    /// P2P port, leaving RPC and other traffic alone); empty: all.
    pub fault_ports: Vec<u16>,
    /// Where the oracles reach the nodes from, and the node ports they use;
    /// a rule that blocks this path is reported (`oracle_path_cut`).
    pub oracle: Option<NetEndpoint>,
}

impl NetTopology {
    pub fn node(&self, name: &str) -> Option<&NetNode> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub fn endpoint(&self, name: &str) -> Option<&NetEndpoint> {
        self.endpoints.iter().find(|e| e.name == name)
    }

    pub fn names(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.name.clone()).collect()
    }
}

/// `config.json` `network`: the network nemesis' settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub enabled: bool,
    /// Families to draw from (empty: none).
    pub kinds: Vec<NetFaultKind>,
    pub max_faults: u32,
    pub min_gap_secs: u32,
    pub topology: NetTopology,
}

/// A random subset of `k` of `names` (in their order), and the rest.
fn split(
    names: &[String],
    k: usize,
    draw: &mut dyn FnMut(u64, u64) -> u64,
) -> (Vec<String>, Vec<String>) {
    let mut pool: Vec<String> = names.to_vec();
    let mut side = Vec::new();
    for _ in 0..k.min(pool.len()) {
        let i = draw(0, pool.len() as u64 - 1) as usize;
        side.push(pool.remove(i));
    }
    let keep =
        |v: &[String]| -> Vec<String> { names.iter().filter(|n| v.contains(n)).cloned().collect() };
    (keep(&side), keep(&pool))
}

fn named(names: &[String]) -> Vec<NodeRef> {
    names
        .iter()
        .map(|n| NodeRef::Node { node: n.clone() })
        .collect()
}

fn mode(draw: &mut dyn FnMut(u64, u64) -> u64) -> CutMode {
    [CutMode::Reset, CutMode::Drop][draw(0, 1) as usize]
}

/// A drawn netem shape (latency 20-500 ms, jitter, loss, rate cap).
pub fn draw_shape(draw: &mut dyn FnMut(u64, u64) -> u64) -> NetemShape {
    NetemShape {
        latency_ms: draw(20, 500) as u32,
        jitter_ms: draw(0, 100) as u32,
        loss_permille: [0, 0, 10, 50][draw(0, 3) as usize],
        rate_kbps: [0, 0, 1024, 4096][draw(0, 3) as usize],
    }
}

/// Offsets (seconds into a window of `dur_secs`) of `resets` drops.
pub fn reset_offsets(
    dur_secs: u64,
    resets: u64,
    draw: &mut dyn FnMut(u64, u64) -> u64,
) -> Vec<u64> {
    let n = resets.max(1);
    let slot = (dur_secs / n).max(1);
    (0..n).map(|k| k * slot + draw(0, slot - 1)).collect()
}

/// The steps of a generic family over `topo`'s nodes (by name, on its
/// fault ports); `None` for a workload family.
pub fn draw_generic(
    kind: NetFaultKind,
    topo: &NetTopology,
    dur_secs: u64,
    draw: &mut dyn FnMut(u64, u64) -> u64,
) -> Option<Vec<NetStep>> {
    let names = topo.names();
    let n = names.len();
    let ports = topo.fault_ports.clone();
    let action = match kind {
        NetFaultKind::Partition | NetFaultKind::OneWayPartition => {
            // 1|n-1 up to an even split (1|3, 2|2 for four nodes).
            let k = draw(1, (n / 2).max(1) as u64) as usize;
            let (a, b) = split(&names, k, draw);
            NetAction::Partition {
                sides: vec![named(&a), named(&b)],
                ports,
                one_way: kind == NetFaultKind::OneWayPartition,
                mode: mode(draw),
            }
        }
        NetFaultKind::LinkCut => {
            let (a, rest) = split(&names, 1, draw);
            let (b, _) = split(&rest, 1, draw);
            NetAction::Cut {
                from: named(&a),
                to: named(&b).into_iter().map(Peer::Node).collect(),
                ports,
                mode: mode(draw),
            }
        }
        NetFaultKind::LinkReset => NetAction::Reset {
            from: named(&names),
            to: named(&names).into_iter().map(Peer::Node).collect(),
            ports,
            at_offsets: reset_offsets(dur_secs, draw(2, 6), draw),
        },
        NetFaultKind::LinkNetem => {
            let (a, rest) = split(&names, 1, draw);
            let k = draw(1, rest.len().max(1) as u64) as usize;
            let (to, _) = split(&rest, k, draw);
            NetAction::Netem {
                from: named(&a),
                to: named(&to).into_iter().map(Peer::Node).collect(),
                ports,
                shape: draw_shape(draw),
            }
        }
        #[allow(unreachable_patterns)]
        _ => return None,
    };
    Some(vec![NetStep {
        after_secs: 0,
        action,
    }])
}

/// The run's network faults: at most `count`, starting no earlier than
/// `from_secs`, at least `min_gap_secs` apart, each kept clear of every
/// kill (`kills` as `(at_secs, down_secs)`) by the kill margins, all fitting
/// in `run_secs` with a full gap after the last. `steps` draws a family's
/// steps. Draws only when enabled with kinds and nodes, so a run without
/// network faults consumes no randomness.
pub fn plan_from(
    cfg: &NetworkConfig,
    run_secs: u64,
    kills: &[(u64, u64)],
    from_secs: u64,
    count: u32,
    mut draw: impl FnMut(u64, u64) -> u64,
    mut steps: impl FnMut(NetFaultKind, u64, &mut dyn FnMut(u64, u64) -> u64) -> Vec<NetStep>,
) -> Vec<NetFault> {
    let mut out = Vec::new();
    if !cfg.enabled || cfg.kinds.is_empty() || cfg.topology.nodes.len() < 2 {
        return out;
    }
    let gap = u64::from(cfg.min_gap_secs.max(1));
    let mut t = from_secs;
    for _ in 0..count {
        let mut at = t + draw(0, gap);
        let dur = draw(MIN_FAULT_SECS, MAX_FAULT_SECS);
        let kind = cfg.kinds[draw(0, cfg.kinds.len() as u64 - 1) as usize];
        let fault_steps = steps(kind, dur, &mut draw);
        while let Some(&(k_at, k_down)) = kills.iter().find(|&&(k_at, k_down)| {
            at < k_at + k_down + KILL_MARGIN_AFTER_SECS && at + dur + KILL_MARGIN_BEFORE_SECS > k_at
        }) {
            at = k_at + k_down + KILL_MARGIN_AFTER_SECS;
        }
        if at + dur + gap > run_secs {
            break;
        }
        out.push(NetFault {
            at_secs: at,
            dur_secs: dur,
            family: kind,
            steps: fault_steps,
        });
        t = at + dur + gap;
    }
    out
}

/// Rejects a network plan whose faults overlap each other or whose steps
/// fall outside their fault.
pub fn validate(plan: &[NetFault]) -> Result<(), String> {
    let mut free = 0;
    for (i, f) in plan.iter().enumerate() {
        if f.at_secs < free {
            return Err(format!(
                "network_plan[{i}] at {}s overlaps the previous fault (ends {free}s)",
                f.at_secs
            ));
        }
        if let Some(s) = f.steps.iter().find(|s| s.after_secs > f.dur_secs) {
            return Err(format!(
                "network_plan[{i}]: step at +{}s is past the fault's {}s",
                s.after_secs, f.dur_secs
            ));
        }
        free = f.end_secs();
    }
    Ok(())
}

/// What a workload adds to the network nemesis.
pub trait NetWorkload {
    /// The nodes (names) role `role` with `pick` names now. The generic
    /// role `all` (every node) is resolved before this is asked.
    fn resolve_role(&mut self, role: &str, pick: u32) -> Result<Vec<String>, String>;
    /// Workload context logged in the fault-start event (e.g. roles and
    /// which oracle clocks the fault excuses), as an object merged into it.
    fn describe(&mut self, fault: &NetFault, hit: &[String]) -> Value;
    /// Runs a step the generic nemesis does not know (a workload action,
    /// e.g. a leadership handoff), resolving its own references.
    fn hook(&mut self, step: &NetAction, topo: &NetTopology) -> Result<Value, String> {
        let _ = topo;
        Err(format!("this workload has no hook {step:?}"))
    }
}

/// A topology without roles beyond `all`.
pub struct Plain;

impl NetWorkload for Plain {
    fn resolve_role(&mut self, role: &str, _pick: u32) -> Result<Vec<String>, String> {
        Err(format!("no role {role:?} in this topology"))
    }
    fn describe(&mut self, _fault: &NetFault, _hit: &[String]) -> Value {
        json!({})
    }
}

/// Resolves node references once per fault (roles stay what they were when
/// the fault started).
pub struct Resolver<'a> {
    topo: &'a NetTopology,
    wl: &'a mut dyn NetWorkload,
    cache: Vec<(String, u32, Vec<String>)>,
}

impl<'a> Resolver<'a> {
    pub fn new(topo: &'a NetTopology, wl: &'a mut dyn NetWorkload) -> Self {
        Resolver {
            topo,
            wl,
            cache: Vec::new(),
        }
    }

    pub fn nodes(&mut self, refs: &[NodeRef]) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for r in refs {
            let names = match r {
                NodeRef::Node { node } => {
                    self.topo
                        .node(node)
                        .ok_or_else(|| format!("no node {node:?} in the topology"))?;
                    vec![node.clone()]
                }
                NodeRef::Role { role, .. } if role == "all" => self.topo.names(),
                NodeRef::Role { role, pick } => {
                    match self.cache.iter().find(|(r, p, _)| r == role && p == pick) {
                        Some((_, _, n)) => n.clone(),
                        None => {
                            let n = self.wl.resolve_role(role, *pick)?;
                            self.cache.push((role.clone(), *pick, n.clone()));
                            n
                        }
                    }
                }
            };
            for n in names {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
        Ok(out)
    }

    /// `(name, ip, default ports)` of each peer.
    pub fn peers(&mut self, peers: &[Peer]) -> Result<Vec<(String, Ipv4Addr, Vec<u16>)>, String> {
        let mut out = Vec::new();
        for p in peers {
            match p {
                Peer::Node(r) => {
                    for n in self.nodes(std::slice::from_ref(r))? {
                        let ip = self.topo.node(&n).map(|n| n.ip).ok_or("no node")?;
                        out.push((n, ip, Vec::new()));
                    }
                }
                Peer::Endpoint { endpoint } => {
                    let e = self
                        .topo
                        .endpoint(endpoint)
                        .ok_or_else(|| format!("no endpoint {endpoint:?} in the topology"))?;
                    out.push((e.name.clone(), e.ip, e.ports.clone()));
                }
            }
        }
        Ok(out)
    }
}

/// One node's view of one faulted link: traffic with `peer` (on `ports`,
/// all if empty) is blocked, or only what the node sends (`egress_only`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkRule {
    pub node: String,
    pub peer: String,
    pub peer_ip: Ipv4Addr,
    pub ports: Vec<u16>,
    pub egress_only: bool,
}

/// The rules of a cut or partition step.
pub fn rules(action: &NetAction, r: &mut Resolver) -> Result<Vec<LinkRule>, String> {
    let mut out = Vec::new();
    match action {
        NetAction::Cut {
            from, to, ports, ..
        } => {
            let from = r.nodes(from)?;
            for (peer, ip, default) in r.peers(to)? {
                for node in &from {
                    if *node != peer {
                        out.push(LinkRule {
                            node: node.clone(),
                            peer: peer.clone(),
                            peer_ip: ip,
                            ports: if ports.is_empty() {
                                default.clone()
                            } else {
                                ports.clone()
                            },
                            egress_only: false,
                        });
                    }
                }
            }
        }
        NetAction::Partition {
            sides,
            ports,
            one_way,
            ..
        } => {
            let sides: Vec<Vec<String>> =
                sides.iter().map(|s| r.nodes(s)).collect::<Result<_, _>>()?;
            for (i, a_side) in sides.iter().enumerate() {
                for (j, b_side) in sides.iter().enumerate() {
                    // One-way: only side 0 loses its sending direction.
                    if i == j || (*one_way && i != 0) {
                        continue;
                    }
                    for a in a_side {
                        for b in b_side {
                            let ip = r.topo.node(b).map(|n| n.ip).ok_or("no node")?;
                            out.push(LinkRule {
                                node: a.clone(),
                                peer: b.clone(),
                                peer_ip: ip,
                                ports: ports.clone(),
                                egress_only: *one_way,
                            });
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(out)
}

/// `iptables` rule specs (after `-A BEDROCK_NET`) for `rule` in `mode`.
pub fn iptables_specs(rule: &LinkRule, mode: CutMode) -> Vec<Vec<String>> {
    let ip = rule.peer_ip.to_string();
    let verdict = |tcp: bool| -> Vec<String> {
        match (mode, tcp) {
            (CutMode::Reset, true) => ["-j", "REJECT", "--reject-with", "tcp-reset"]
                .map(String::from)
                .to_vec(),
            _ => vec!["-j".into(), "DROP".into()],
        }
    };
    let mut out = Vec::new();
    let dirs: &[(&str, &str, &str)] = if rule.egress_only {
        &[("-d", "--dport", "--sport")]
    } else {
        &[("-d", "--dport", "--sport"), ("-s", "--sport", "--dport")]
    };
    for &(addr, peer_port, own_port) in dirs {
        if rule.ports.is_empty() {
            let mut tcp = vec![addr.to_string(), ip.clone(), "-p".into(), "tcp".into()];
            tcp.extend(verdict(true));
            out.push(tcp);
            let mut rest = vec![addr.to_string(), ip.clone()];
            rest.extend(verdict(false));
            out.push(rest);
        } else {
            for p in &rule.ports {
                // Whoever dialed: the peer's port, or ours.
                for flag in [peer_port, own_port] {
                    let mut spec = vec![
                        addr.to_string(),
                        ip.clone(),
                        "-p".into(),
                        "tcp".into(),
                        flag.into(),
                        p.to_string(),
                    ];
                    spec.extend(verdict(true));
                    out.push(spec);
                }
            }
        }
    }
    out
}

/// Whether any of `rules` blocks the oracles' path (`topo.oracle`).
pub fn oracle_path_cut(rules: &[LinkRule], topo: &NetTopology) -> bool {
    let Some(o) = &topo.oracle else { return false };
    rules.iter().any(|r| {
        r.peer_ip == o.ip
            && (r.ports.is_empty()
                || o.ports.is_empty()
                || r.ports.iter().any(|p| o.ports.contains(p)))
    })
}

/// `tc` commands (argument lists) that put `shape` on `node`'s traffic to
/// each `(ip, ports)` and nothing else.
pub fn netem_commands(shape: &NetemShape, links: &[(Ipv4Addr, Vec<u16>)]) -> Vec<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let mut out = vec![
        // Bands 1-3 as pfifo_fast would use them; band 4 is the faulted one.
        s(&[
            "qdisc", "replace", "dev", "eth0", "root", "handle", "1:", "prio", "bands", "4",
            "priomap", "1", "2", "2", "2", "1", "2", "0", "0", "1", "1", "1", "1", "1", "1", "1",
            "1",
        ]),
    ];
    let mut netem = s(&[
        "qdisc", "replace", "dev", "eth0", "parent", "1:4", "handle", "40:",
    ]);
    netem.extend(netem_args(shape));
    out.push(netem);
    for (ip, ports) in links {
        let base = s(&[
            "filter", "add", "dev", "eth0", "parent", "1:0", "protocol", "ip", "prio", "1", "u32",
            "match", "ip", "dst",
        ]);
        if ports.is_empty() {
            let mut f = base.clone();
            f.extend([format!("{ip}/32"), "flowid".into(), "1:4".into()]);
            out.push(f);
        }
        for p in ports {
            for field in ["dport", "sport"] {
                let mut f = base.clone();
                f.extend([
                    format!("{ip}/32"),
                    "match".into(),
                    "ip".into(),
                    field.into(),
                    p.to_string(),
                    "0xffff".into(),
                    "flowid".into(),
                    "1:4".into(),
                ]);
                out.push(f);
            }
        }
    }
    out
}

/// `netem` qdisc arguments for `shape`.
pub fn netem_args(shape: &NetemShape) -> Vec<String> {
    let mut a = vec!["netem".to_string()];
    if shape.latency_ms > 0 || shape.jitter_ms > 0 {
        a.extend([
            "delay".into(),
            format!("{}ms", shape.latency_ms),
            format!("{}ms", shape.jitter_ms),
        ]);
    }
    if shape.loss_permille > 0 {
        a.extend([
            "loss".into(),
            format!("{}.{}%", shape.loss_permille / 10, shape.loss_permille % 10),
        ]);
    }
    if shape.rate_kbps > 0 {
        a.extend(["rate".into(), format!("{}kbit", shape.rate_kbps)]);
    }
    a
}

// ---- runtime (guest) ----

fn sleep_until(ns: u64) {
    let now = common::guest_time_ns();
    if ns > now {
        std::thread::sleep(Duration::from_nanos(ns - now));
    }
}

/// The PID of container `name`'s process (its network namespace).
fn container_pid(name: &str) -> Result<u32, String> {
    let out = common::command_output("podman", &["inspect", "-f", "{{.State.Pid}}", name])?;
    out.trim()
        .parse()
        .ok()
        .filter(|&p| p > 0)
        .ok_or_else(|| format!("{name}: not running (pid {:?})", out.trim()))
}

/// Runs `program args` in container `node`'s network namespace.
fn in_netns(node: &str, program: &str, args: &[String]) -> Result<String, String> {
    let pid = container_pid(node)?.to_string();
    let mut argv: Vec<&str> = vec!["-t", &pid, "-n", program];
    argv.extend(args.iter().map(String::as_str));
    common::command_output("nsenter", &argv)
}

/// Makes sure `node` has the nemesis' chain, hooked first into INPUT and
/// OUTPUT.
fn ensure_chain(node: &str) -> Result<(), String> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    if in_netns(node, "iptables", &s(&["-n", "-L", CHAIN])).is_err() {
        in_netns(node, "iptables", &s(&["-N", CHAIN]))?;
        in_netns(node, "iptables", &s(&["-I", "INPUT", "1", "-j", CHAIN]))?;
        in_netns(node, "iptables", &s(&["-I", "OUTPUT", "1", "-j", CHAIN]))?;
    }
    Ok(())
}

fn apply_rules(rules: &[LinkRule], mode: CutMode) -> Result<(), String> {
    for r in rules {
        ensure_chain(&r.node)?;
        for spec in iptables_specs(r, mode) {
            let mut args = vec!["-A".to_string(), CHAIN.into()];
            args.extend(spec);
            in_netns(&r.node, "iptables", &args)?;
        }
    }
    Ok(())
}

/// Kills `node`'s established TCP sockets to each peer (on `ports`, all if
/// empty); how many `ss` reported killing.
fn reset_sockets(
    node: &str,
    peers: &[(String, Ipv4Addr, Vec<u16>)],
    ports: &[u16],
) -> Result<usize, String> {
    let mut killed = 0;
    for (_, ip, default) in peers {
        let ports = if ports.is_empty() {
            default.as_slice()
        } else {
            ports
        };
        let filters: Vec<Vec<String>> = if ports.is_empty() {
            vec![vec!["dst".into(), ip.to_string()]]
        } else {
            ports
                .iter()
                .flat_map(|p| {
                    ["dport", "sport"].map(|f| {
                        vec![
                            "dst".into(),
                            ip.to_string(),
                            f.into(),
                            "=".into(),
                            format!(":{p}"),
                        ]
                    })
                })
                .collect()
        };
        for f in filters {
            let mut args = vec![
                "-K".to_string(),
                "-t".into(),
                "-n".into(),
                "state".into(),
                "established".into(),
            ];
            args.extend(f);
            let out = in_netns(node, "ss", &args)?;
            killed += out.lines().skip(1).filter(|l| !l.trim().is_empty()).count();
        }
    }
    Ok(killed)
}

fn apply_netem(
    from: &[String],
    peers: &[(String, Ipv4Addr, Vec<u16>)],
    ports: &[u16],
    shape: &NetemShape,
) -> Result<(), String> {
    for node in from {
        let links: Vec<(Ipv4Addr, Vec<u16>)> = peers
            .iter()
            .filter(|(n, ..)| n != node)
            .map(|(_, ip, d)| {
                (
                    *ip,
                    if ports.is_empty() {
                        d.clone()
                    } else {
                        ports.to_vec()
                    },
                )
            })
            .collect();
        for cmd in netem_commands(shape, &links) {
            in_netns(node, "tc", &cmd)?;
        }
    }
    Ok(())
}

/// Heals `node`: flushes the nemesis' chain and removes its qdisc. Nothing
/// installed is fine; a node whose namespace cannot be entered is an error.
pub fn heal_node(node: &str) -> Result<(), String> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    if in_netns(node, "iptables", &s(&["-n", "-L", CHAIN])).is_ok() {
        in_netns(node, "iptables", &s(&["-F", CHAIN]))?;
    } else {
        container_pid(node)?;
    }
    if let Err(e) = in_netns(node, "tc", &s(&["qdisc", "del", "dev", "eth0", "root"])) {
        if !e.contains("handle of zero") && !e.contains("No such file") {
            return Err(e);
        }
    }
    Ok(())
}

/// Heals every node of `topo`, reporting every failure.
pub fn heal(topo: &NetTopology) -> Result<(), String> {
    let errors: Vec<String> = topo
        .nodes
        .iter()
        .filter_map(|n| heal_node(&n.name).err().map(|e| format!("{}: {e}", n.name)))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn cover(sig: &str, detail: &str) {
    common::assert_sometimes(
        bedrock_assertions::Condition::Bool(true),
        "network",
        sig,
        detail,
    );
}

/// The nodes a step cuts off or degrades.
fn hit_by(action: &NetAction, r: &mut Resolver) -> Result<Vec<String>, String> {
    Ok(match action {
        NetAction::Partition { sides, .. } => match sides.first() {
            Some(s) => r.nodes(s)?,
            None => Vec::new(),
        },
        NetAction::Cut { from, .. }
        | NetAction::Reset { from, .. }
        | NetAction::Netem { from, .. } => r.nodes(from)?,
        #[allow(unreachable_patterns)]
        _ => Vec::new(),
    })
}

/// Applies one step; what it did, for the event log.
fn apply_step(
    index: usize,
    fault: &NetFault,
    step: &NetStep,
    r: &mut Resolver,
    secs: &dyn Fn(u64) -> u64,
) -> Result<Value, String> {
    match &step.action {
        NetAction::Cut { mode, .. } | NetAction::Partition { mode, .. } => {
            let rules = rules(&step.action, r)?;
            apply_rules(&rules, *mode)?;
            Ok(json!({"rules": rules, "oracle_path_cut": oracle_path_cut(&rules, r.topo)}))
        }
        NetAction::Reset {
            from,
            to,
            ports,
            at_offsets,
        } => {
            let from = r.nodes(from)?;
            let peers = r.peers(to)?;
            let mut done = Vec::new();
            for &off in at_offsets {
                sleep_until(secs(fault.at_secs + step.after_secs + off));
                let mut killed = 0;
                for node in &from {
                    let others: Vec<_> = peers.iter().filter(|p| &p.0 != node).cloned().collect();
                    killed += reset_sockets(node, &others, ports)?;
                }
                if killed > 0 {
                    cover(
                        "S/net-connections-reset",
                        &format!(
                            "fault {index}: {killed} established connections reset at +{off}s"
                        ),
                    );
                }
                done.push(json!({"at": off, "killed": killed}));
            }
            Ok(json!({"resets": done}))
        }
        NetAction::Netem {
            from,
            to,
            ports,
            shape,
        } => {
            let from = r.nodes(from)?;
            let peers = r.peers(to)?;
            apply_netem(&from, &peers, ports, shape)?;
            cover(
                "S/net-netem-applied",
                &format!(
                    "fault {index}: {from:?} -> {:?}: {:?}",
                    peers.iter().map(|p| &p.0).collect::<Vec<_>>(),
                    netem_args(shape)
                ),
            );
            Ok(
                json!({"netem": netem_args(shape), "from": from, "to": peers.iter().map(|p| &p.0).collect::<Vec<_>>()}),
            )
        }
        #[allow(unreachable_patterns)]
        hook => r.wl.hook(hook, r.topo),
    }
}

/// Runs fault `index` from its start to its end (blocking; the nemesis'
/// timeline holds nothing else then): resolves roles, applies its steps at
/// their offsets, heals every node, and logs `network` events. The first
/// error applying it or healing it is returned (and logged in `fault-end`).
pub fn run(
    index: usize,
    fault: &NetFault,
    cfg: &NetworkConfig,
    start_ns: u64,
    wl: &mut dyn NetWorkload,
) -> Result<(), String> {
    let secs = move |s: u64| start_ns + s * 1_000_000_000;
    sleep_until(secs(fault.at_secs));
    let topo = &cfg.topology;
    let mut r = Resolver::new(topo, wl);
    let mut hit = BTreeSet::new();
    let mut hit_err = None;
    for s in &fault.steps {
        match hit_by(&s.action, &mut r) {
            Ok(h) => hit.extend(h),
            Err(e) => hit_err = Some(e),
        }
    }
    let hit: Vec<String> = topo
        .names()
        .into_iter()
        .filter(|n| hit.contains(n))
        .collect();
    let family = fault.family.name();
    let mut detail = json!({
        "index": index,
        "kind": family,
        "fault": fault,
        "nodes": hit,
    });
    let extra = r.wl.describe(fault, &hit);
    if let (Some(d), Some(e)) = (detail.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    common::emit_event("network", "fault-start", None, detail);
    cover(
        &format!("S/net-fault-{family}"),
        &format!("fault {index} hits {hit:?}"),
    );
    let mut applied: Result<(), String> = match hit_err {
        Some(e) => Err(e),
        None => Ok(()),
    };
    if applied.is_ok() {
        for (k, step) in fault.steps.iter().enumerate() {
            sleep_until(secs(fault.at_secs + step.after_secs));
            match apply_step(index, fault, step, &mut r, &secs) {
                Ok(v) => common::emit_event(
                    "network",
                    "step",
                    None,
                    json!({"index": index, "step": k, "applied": v}),
                ),
                Err(e) => {
                    applied = Err(format!("step {k}: {e}"));
                    break;
                }
            }
        }
    }
    sleep_until(secs(fault.end_secs()));
    let healed = heal(topo);
    let error = applied.as_ref().err().or(healed.as_ref().err());
    common::emit_event(
        "network",
        "fault-end",
        None,
        json!({"index": index, "kind": family, "nodes": hit, "error": error}),
    );
    applied.and(healed)
}

/// The network plan event's detail.
pub fn plan_detail(plan: &[NetFault]) -> Value {
    json!({ "faults": plan })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topo(n: usize) -> NetTopology {
        NetTopology {
            nodes: (0..n)
                .map(|i| NetNode {
                    name: format!("v{i}"),
                    ip: Ipv4Addr::new(10, 89, 77, 11 + i as u8),
                })
                .collect(),
            endpoints: vec![NetEndpoint {
                name: "l1".into(),
                ip: Ipv4Addr::new(10, 89, 77, 1),
                ports: vec![18600],
            }],
            fault_ports: vec![8000],
            oracle: Some(NetEndpoint {
                name: "oracle".into(),
                ip: Ipv4Addr::new(10, 89, 77, 1),
                ports: vec![8545],
            }),
        }
    }

    fn cfg(kinds: &[NetFaultKind], n: usize) -> NetworkConfig {
        NetworkConfig {
            enabled: true,
            kinds: kinds.to_vec(),
            max_faults: 4,
            min_gap_secs: 30,
            topology: topo(n),
        }
    }

    fn lcg(seed: u64) -> impl FnMut(u64, u64) -> u64 {
        let mut x = seed;
        move |lo, hi| {
            x = crate::planner::splitmix64(x);
            lo + x % (hi - lo + 1)
        }
    }

    fn generic_plan(c: &NetworkConfig, run: u64, kills: &[(u64, u64)], seed: u64) -> Vec<NetFault> {
        let topo = c.topology.clone();
        plan_from(
            c,
            run,
            kills,
            NET_WARMUP_SECS,
            c.max_faults,
            lcg(seed),
            |k, d, draw| draw_generic(k, &topo, d, draw).unwrap(),
        )
    }

    const GENERIC: [NetFaultKind; 5] = [
        NetFaultKind::Partition,
        NetFaultKind::OneWayPartition,
        NetFaultKind::LinkCut,
        NetFaultKind::LinkReset,
        NetFaultKind::LinkNetem,
    ];

    #[test]
    fn plans_fit_the_run_avoid_kills_and_never_overlap() {
        let kills = [(40, 3), (120, 0)];
        for seed in 0..64 {
            let p = generic_plan(&cfg(&GENERIC, 4), 300, &kills, seed);
            assert!(!p.is_empty() && p.len() <= 4, "{p:?}");
            validate(&p).unwrap();
            for f in &p {
                assert!(f.at_secs >= NET_WARMUP_SECS);
                assert!((MIN_FAULT_SECS..=MAX_FAULT_SECS).contains(&f.dur_secs));
                assert!(f.end_secs() + 30 <= 300);
                for &(k, d) in &kills {
                    assert!(
                        f.end_secs() + KILL_MARGIN_BEFORE_SECS <= k
                            || f.at_secs >= k + d + KILL_MARGIN_AFTER_SECS
                    );
                }
            }
        }
    }

    #[test]
    fn disabled_or_kindless_plans_draw_nothing() {
        let mut draws = 0;
        let off = NetworkConfig {
            enabled: false,
            ..cfg(&GENERIC, 4)
        };
        for c in [off, cfg(&[], 4)] {
            assert!(plan_from(
                &c,
                300,
                &[],
                10,
                4,
                |lo, _| {
                    draws += 1;
                    lo
                },
                |_, _, _| vec![]
            )
            .is_empty());
        }
        assert_eq!(draws, 0);
    }

    #[test]
    fn partitions_split_one_against_rest_up_to_even() {
        let mut sizes = BTreeSet::new();
        for seed in 0..64 {
            let mut d = lcg(seed);
            let steps = draw_generic(NetFaultKind::Partition, &topo(4), 20, &mut d).unwrap();
            let NetAction::Partition { sides, ports, .. } = &steps[0].action else {
                panic!()
            };
            assert_eq!(ports, &[8000]);
            assert_eq!(sides[0].len() + sides[1].len(), 4);
            sizes.insert(sides[0].len());
        }
        // 1|3 and 2|2.
        assert_eq!(sizes, [1, 2].into());
    }

    fn resolver_rules(action: &NetAction) -> Vec<LinkRule> {
        let t = topo(4);
        let mut wl = Plain;
        let mut r = Resolver::new(&t, &mut wl);
        rules(action, &mut r).unwrap()
    }

    fn n(name: &str) -> NodeRef {
        NodeRef::Node { node: name.into() }
    }

    #[test]
    fn partitions_block_both_sides_or_one_way() {
        let p = |one_way| NetAction::Partition {
            sides: vec![vec![n("v0")], vec![n("v1"), n("v2")]],
            ports: vec![8000],
            one_way,
            mode: CutMode::Reset,
        };
        let sym = resolver_rules(&p(false));
        // v0 against each of v1, v2, and each of them against v0.
        assert_eq!(sym.len(), 4);
        assert!(sym.iter().any(|r| r.node == "v1" && r.peer == "v0"));
        let one = resolver_rules(&p(true));
        assert_eq!(one.len(), 2);
        assert!(one.iter().all(|r| r.node == "v0" && r.egress_only));
        // Scoped specs match the port whoever dialed, both directions.
        let specs = iptables_specs(&sym[0], CutMode::Reset);
        assert_eq!(specs.len(), 4);
        assert_eq!(
            specs[0].join(" "),
            "-d 10.89.77.12 -p tcp --dport 8000 -j REJECT --reject-with tcp-reset"
        );
        assert_eq!(
            specs[3].join(" "),
            "-s 10.89.77.12 -p tcp --dport 8000 -j REJECT --reject-with tcp-reset"
        );
        let drop = iptables_specs(&one[0], CutMode::Drop);
        assert_eq!(drop.len(), 2);
        assert!(drop
            .iter()
            .all(|s| s[0] == "-d" && s.ends_with(&["-j".into(), "DROP".into()])));
    }

    #[test]
    fn cuts_to_endpoints_use_their_ports_and_report_the_oracle_path() {
        let cut = NetAction::Cut {
            from: vec![n("v1")],
            to: vec![Peer::Endpoint {
                endpoint: "l1".into(),
            }],
            ports: vec![],
            mode: CutMode::Drop,
        };
        let r = resolver_rules(&cut);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].ports, [18600]);
        assert!(!oracle_path_cut(&r, &topo(4)));
        // An unscoped cut to the oracle's address cuts its path.
        let mut wide = r.clone();
        wide[0].ports.clear();
        assert!(oracle_path_cut(&wide, &topo(4)));
        // Unscoped node cuts: TCP reset plus a drop of everything else.
        let all = iptables_specs(
            &LinkRule {
                node: "v0".into(),
                peer: "v1".into(),
                peer_ip: Ipv4Addr::new(10, 0, 0, 2),
                ports: vec![],
                egress_only: false,
            },
            CutMode::Reset,
        );
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn netem_shapes_only_the_planned_links() {
        let cmds = netem_commands(
            &NetemShape {
                latency_ms: 120,
                jitter_ms: 30,
                loss_permille: 15,
                rate_kbps: 1024,
            },
            &[(Ipv4Addr::new(10, 89, 77, 12), vec![8000])],
        );
        assert_eq!(cmds.len(), 4);
        assert!(cmds[0]
            .join(" ")
            .starts_with("qdisc replace dev eth0 root handle 1: prio bands 4"));
        assert_eq!(
            cmds[1].join(" "),
            "qdisc replace dev eth0 parent 1:4 handle 40: netem delay 120ms 30ms loss 1.5% rate 1024kbit"
        );
        assert_eq!(
            cmds[2].join(" "),
            "filter add dev eth0 parent 1:0 protocol ip prio 1 u32 match ip dst 10.89.77.12/32 match ip dport 8000 0xffff flowid 1:4"
        );
    }

    #[test]
    fn unknown_nodes_and_roles_are_errors() {
        let t = topo(2);
        let mut wl = Plain;
        let mut r = Resolver::new(&t, &mut wl);
        assert!(r.nodes(&[n("nope")]).unwrap_err().contains("no node"));
        assert!(r
            .nodes(&[NodeRef::Role {
                role: "leader".into(),
                pick: 0
            }])
            .unwrap_err()
            .contains("no role"));
        assert_eq!(
            r.nodes(&[NodeRef::Role {
                role: "all".into(),
                pick: 0
            }])
            .unwrap(),
            ["v0", "v1"]
        );
    }

    #[test]
    fn reset_offsets_spread_over_the_window() {
        let mut d = lcg(9);
        let t = reset_offsets(20, 4, &mut d);
        for (k, off) in t.iter().enumerate() {
            assert!((k as u64 * 5..(k as u64 + 1) * 5).contains(off), "{t:?}");
        }
    }

    #[test]
    fn validate_rejects_overlaps_and_late_steps() {
        let f = |at, dur| NetFault {
            at_secs: at,
            dur_secs: dur,
            family: NetFaultKind::LinkCut,
            steps: vec![],
        };
        assert!(validate(&[f(10, 20), f(25, 5)]).is_err());
        let mut late = f(10, 5);
        late.steps.push(NetStep {
            after_secs: 6,
            action: NetAction::Reset {
                from: vec![],
                to: vec![],
                ports: vec![],
                at_offsets: vec![],
            },
        });
        assert!(validate(&[late]).is_err());
        assert!(validate(&[f(10, 20), f(30, 5)]).is_ok());
    }
}
