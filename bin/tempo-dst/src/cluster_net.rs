// SPDX-License-Identifier: GPL-2.0

//! Network impairments of the validator cluster's consensus traffic, held
//! around a planned fault ([`crate::cluster::Impair`]).
//!
//! Everything runs inside each validator's network namespace
//! (`nsenter -t <pid> -n`) and touches only [`CONSENSUS_PORT`], so execution
//! p2p and the oracles' RPC are never faulted:
//!
//! - **delay**: a `prio` qdisc on the sender's `eth0` with `netem` on an
//!   extra band and `u32` filters for the receiver's IP and the consensus
//!   port (either side of the connection), so only that directed link is
//!   delayed;
//! - **partition**: `iptables` DROP rules in a `BEDROCK_NET` chain hooked
//!   first into `INPUT` and `OUTPUT`, installed on every node for every peer
//!   across the cut, in both directions. A node that restarts gets a fresh
//!   namespace (its rules are gone), so its peers' rules keep the partition,
//!   and the nemesis re-applies the restarted node's own after it is back.
//!
//! Healing flushes the chain and removes the qdisc on every validator.
//! Ported from the generic network nemesis' iptables and netem builders.
//! netem's per-packet draws use the guest kernel's PRNG (seeded from
//! Bedrock-controlled randomness) and its timers run on the emulated clock.

use std::process::Command;

use serde_json::json;

use crate::{
    cluster::{Impairment, ValidatorId, CONSENSUS_PORT},
    common,
};

/// The chain the nemesis owns in each validator's namespace.
const CHAIN: &str = "BEDROCK_NET";

/// Runs `program args`, returning stdout; an error carries the exit status
/// and stderr.
fn run(program: &str, args: &[String]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
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

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// Runs `program args` in validator `v`'s network namespace.
fn in_netns(v: ValidatorId, program: &str, args: &[String]) -> Result<String, String> {
    let pid = run(
        "podman",
        &strings(&["inspect", "-f", "{{.State.Pid}}", v.container()]),
    )?;
    let pid = pid.trim();
    if pid.parse::<u32>().map_or(true, |p| p == 0) {
        return Err(format!("{v}: not running (pid {pid:?})"));
    }
    let mut argv = strings(&["-t", pid, "-n", program]);
    argv.extend(args.iter().cloned());
    run("nsenter", &argv)
}

/// `iptables` specs (after `-A BEDROCK_NET`) dropping consensus traffic
/// between this node and `peer`, in both directions and whoever dialed.
pub fn drop_specs(peer: ValidatorId) -> Vec<Vec<String>> {
    let ip = peer.ip().to_string();
    let port = CONSENSUS_PORT.to_string();
    let mut out = Vec::new();
    for (addr, peer_port, own_port) in [("-d", "--dport", "--sport"), ("-s", "--sport", "--dport")]
    {
        for flag in [peer_port, own_port] {
            out.push(strings(&[
                addr, &ip, "-p", "tcp", flag, &port, "-j", "DROP",
            ]));
        }
    }
    out
}

/// `tc` commands putting a `latency_ms` (+ up to `jitter_ms`) delay on this
/// node's consensus traffic to `to`, and nothing else.
pub fn delay_commands(to: ValidatorId, latency_ms: u32, jitter_ms: u32) -> Vec<Vec<String>> {
    let ip = format!("{}/32", to.ip());
    let port = CONSENSUS_PORT.to_string();
    let mut out = vec![
        // Bands 1-3 as pfifo_fast would use them; band 4 is the delayed one.
        strings(&[
            "qdisc", "replace", "dev", "eth0", "root", "handle", "1:", "prio", "bands", "4",
            "priomap", "1", "2", "2", "2", "1", "2", "0", "0", "1", "1", "1", "1", "1", "1", "1",
            "1",
        ]),
        strings(&[
            "qdisc",
            "replace",
            "dev",
            "eth0",
            "parent",
            "1:4",
            "handle",
            "40:",
            "netem",
            "delay",
            &format!("{latency_ms}ms"),
            &format!("{jitter_ms}ms"),
        ]),
    ];
    for field in ["dport", "sport"] {
        out.push(strings(&[
            "filter", "add", "dev", "eth0", "parent", "1:0", "protocol", "ip", "prio", "1", "u32",
            "match", "ip", "dst", &ip, "match", "ip", field, &port, "0xffff", "flowid", "1:4",
        ]));
    }
    out
}

/// The per-node commands of `imp`, limited to the nodes in `only` (all when
/// `None`): `(node, program, args)` in order.
pub fn commands(
    imp: &Impairment,
    only: Option<&[ValidatorId]>,
) -> Vec<(ValidatorId, &'static str, Vec<String>)> {
    let wanted = |v: &ValidatorId| only.is_none_or(|o| o.contains(v));
    let mut out = Vec::new();
    match imp {
        Impairment::Delay {
            from,
            to,
            latency_ms,
            jitter_ms,
        } => {
            if wanted(from) {
                for c in delay_commands(*to, *latency_ms, *jitter_ms) {
                    out.push((*from, "tc", c));
                }
            }
        }
        Impairment::Partition { sides } => {
            for (i, side) in sides.iter().enumerate() {
                for node in side.iter().filter(|v| wanted(v)) {
                    out.push((*node, "iptables", strings(&["-N", CHAIN])));
                    out.push((
                        *node,
                        "iptables",
                        strings(&["-I", "INPUT", "1", "-j", CHAIN]),
                    ));
                    out.push((
                        *node,
                        "iptables",
                        strings(&["-I", "OUTPUT", "1", "-j", CHAIN]),
                    ));
                    for (j, other) in sides.iter().enumerate() {
                        if i == j {
                            continue;
                        }
                        for peer in other {
                            for spec in drop_specs(*peer) {
                                let mut args = strings(&["-A", CHAIN]);
                                args.extend(spec);
                                out.push((*node, "iptables", args));
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Applies `imp` on the nodes in `only` (all when `None`).
fn apply(imp: &Impairment, only: Option<&[ValidatorId]>) -> Result<(), String> {
    for (node, program, args) in commands(imp, only) {
        in_netns(node, program, &args)?;
    }
    Ok(())
}

/// Removes everything the nemesis installed on `v` (nothing installed is
/// fine; a namespace that cannot be entered is an error).
fn heal_node(v: ValidatorId) -> Result<(), String> {
    if in_netns(v, "iptables", &strings(&["-n", "-L", CHAIN])).is_ok() {
        in_netns(v, "iptables", &strings(&["-F", CHAIN]))?;
    }
    if let Err(e) = in_netns(v, "tc", &strings(&["qdisc", "del", "dev", "eth0", "root"])) {
        if !e.contains("handle of zero") && !e.contains("No such file") {
            return Err(e);
        }
    }
    Ok(())
}

fn report(result: &Result<(), String>, what: &str, index: usize) {
    common::assert_always(
        bedrock_assertions::Condition::Bool(result.is_ok()),
        "nemesis",
        "H/network-fault-failed",
        &format!("fault {index}: {what}: {:?}", result.as_ref().err()),
    );
}

/// Applies fault `index`'s impairment and logs the `impair` window over the
/// validators it counts against the fault budget.
pub fn impair(index: usize, imp: &Impairment) {
    common::emit_event(
        "nemesis",
        "impair",
        None,
        json!({"index": index, "impairment": imp, "targets": imp.impaired()}),
    );
    let applied = apply(imp, None);
    report(&applied, "applying", index);
    if applied.is_ok() {
        common::assert_sometimes(
            bedrock_assertions::Condition::Bool(true),
            "nemesis",
            "S/net-impairment-applied",
            &format!("fault {index}: {imp:?}"),
        );
    }
}

/// Re-applies `imp`'s rules on `restarted` (a restart gets a new network
/// namespace).
pub fn reapply(index: usize, imp: &Impairment, restarted: &[ValidatorId]) {
    report(
        &apply(imp, Some(restarted)),
        "re-applying after restart",
        index,
    );
}

/// Heals every validator and closes the `impair` window.
pub fn heal(index: usize, imp: &Impairment) {
    let errors: Vec<String> = ValidatorId::all()
        .filter_map(|v| heal_node(v).err().map(|e| format!("{v}: {e}")))
        .collect();
    let healed = if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    };
    report(&healed, "healing", index);
    common::emit_event(
        "nemesis",
        "heal",
        None,
        json!({"index": index, "targets": imp.impaired(), "error": healed.as_ref().err()}),
    );
    if healed.is_ok() {
        common::assert_sometimes(
            bedrock_assertions::Condition::Bool(true),
            "nemesis",
            "S/net-impairment-healed",
            &format!("fault {index}"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u8) -> ValidatorId {
        ValidatorId::new(n).unwrap()
    }

    #[test]
    fn delay_touches_only_the_directed_consensus_link() {
        let cmds = commands(
            &Impairment::Delay {
                from: v(2),
                to: v(1),
                latency_ms: 1500,
                jitter_ms: 100,
            },
            None,
        );
        assert!(cmds.iter().all(|(n, p, _)| *n == v(2) && *p == "tc"));
        let joined: Vec<String> = cmds.iter().map(|(_, _, a)| a.join(" ")).collect();
        assert!(
            joined[1].ends_with("netem delay 1500ms 100ms"),
            "{joined:?}"
        );
        assert!(
            joined[2].contains("dst 10.89.77.11/32 match ip dport 8000"),
            "{joined:?}"
        );
        assert!(joined[3].contains("sport 8000"), "{joined:?}");
        assert_eq!(cmds.len(), 4);
    }

    #[test]
    fn partition_blocks_both_directions_on_every_node() {
        let imp = Impairment::Partition {
            sides: vec![vec![v(1)], vec![v(2), v(3), v(4)]],
        };
        let cmds = commands(&imp, None);
        // v1 drops traffic with each of the three, each of them with v1.
        let drops = |node: ValidatorId, peer: ValidatorId| {
            cmds.iter()
                .filter(|(n, _, a)| *n == node && a.join(" ").contains(&peer.ip().to_string()))
                .count()
        };
        for peer in [v(2), v(3), v(4)] {
            assert_eq!(drops(v(1), peer), 4);
            assert_eq!(drops(peer, v(1)), 4);
        }
        assert_eq!(drops(v(2), v(3)), 0, "same side stays connected");
        assert!(cmds
            .iter()
            .all(|(_, _, a)| !a.join(" ").contains("8545") && !a.join(" ").contains("8001")));
        // Re-applying after v1's restart installs only v1's rules.
        assert!(commands(&imp, Some(&[v(1)]))
            .iter()
            .all(|(n, ..)| *n == v(1)));
    }
}
