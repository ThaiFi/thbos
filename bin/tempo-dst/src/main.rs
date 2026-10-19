// SPDX-License-Identifier: GPL-2.0

//! In-guest side of the Tempo deterministic simulation harness.
//!
//! It implements the bedrock-dst workload contract (`bedrock-dst-contract`,
//! contrib/bedrock-dst/README.md); requests are JSON, `-` reads one from
//! stdin:
//!
//! ```text
//! tempo-dst parse-args <req|->  # host: ArgsRequest -> TempoArgs
//! tempo-dst config <req|->      # host: PlanRequest -> Plan (config.json, scenario, coverage)
//! tempo-dst observe <req|->     # host: ObserveRequest -> Observation
//! tempo-dst warmup '<req>'      # guest: WarmupRequest -> WarmupStatus (one warmup step)
//! tempo-dst start '<config json>'  # set up a branch and snapshot assertion offsets
//! tempo-dst nemesis    # crash/restart the node per /bedrock/in/config.json
//! tempo-dst redecide '<json>'  # replace the rest of a running branch's kill plan / load generations
//! tempo-dst oracle     # online oracles (log scan, liveness, durability)
//! tempo-dst progress   # new assertion records since the last call -> /bedrock/out/progress.jsonl
//! tempo-dst finalize   # end-of-run oracles (graceful stop, re-execute)
//! tempo-dst head       # print the node's head block number
//! tempo-dst deploy <image> <address> [spec]  # deploy a load's contract(s; the trie pool too)
//! tempo-dst deploy-tip20 <image>      # create and mint the TIP-20 load's token
//! tempo-dst trie-spec <seed> <generation> <steps> [contracts senders]  # generated trie load spec(s)
//! tempo-dst tip20-spec <seed> <generation> <steps> # print a generated TIP-20 load spec
//! tempo-dst chain-spec <seed> <generation> <steps>  # print a generated chain load spec
//! tempo-dst chain-check [block]  # one-shot E9 at block (default: head)
//! tempo-dst chain-watch <secs>   # E9 against a live node, outside Bedrock
//! tempo-dst deploy-zones [image]  # zones setup; wait for the zone's first settled batch
//! tempo-dst zone-prover    # replay every submitted zone batch (prover service)
//! tempo-dst tcp-forward LISTEN=UPSTREAM...  # TCP forwarder (compose service)
//! tempo-dst zones-watch <secs>  # E12 against live nodes, outside Bedrock
//! tempo-dst storage-attach       # warmup: move the node's datadir onto LazyFS
//! tempo-dst storage-ctl <cmd..>  # one LazyFS control command (see `storage`)
//! tempo-dst cluster-watch <secs> # E13-E18 against a live cluster, outside Bedrock
//! ```
//!
//! Assertions go to /bedrock/assertions/*.jsonl, control events to
//! /bedrock/events.jsonl. `TEMPO_DST_RPC` overrides the node's RPC URL.

use bedrock_assertions::files as assertions;
mod campaign;
mod cluster;
mod cluster_live;
mod cluster_net;
mod cob;
mod cob_gen;
mod common;
mod consensus;
mod deploy;
mod durable;
mod finalize;
mod follower;
mod forward;
mod historical;
mod nemesis;
mod netfault;
mod node_storage;
mod oracle;
mod planner;
mod process;
mod reference;
mod scenario;
mod start;
mod state_root;
mod statemix_gen;
mod storage;
mod tip20;
mod topology;
mod trie_gen;
mod trie_ref;
mod verdict;
mod warmup;
mod witness;
mod zones;
mod zones_cluster;
mod zones_l1_proxy;
mod zones_live;

/// Prints `value` as one JSON line, or exits 1 with `what: error`.
fn print_json<T: serde::Serialize, E: std::fmt::Display>(what: &str, r: Result<T, E>) {
    match r
        .map_err(|e| e.to_string())
        .and_then(|v| serde_json::to_string(&v).map_err(|e| e.to_string()))
    {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("{what}: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
fn enter_guest_host() -> std::io::Result<()> {
    use nix::sched::{setns, CloneFlags};
    use std::fs::File;

    if std::env::var_os("TEMPO_DST_HOST_NS").is_none() {
        return Ok(());
    }
    // Compose gives this privileged controller the guest host PID namespace.
    // Its hooks need the host cgroup paths and mount table, especially when
    // LazyFS replaces a node volume's backing directory.
    setns(
        File::open("/proc/1/ns/cgroup")?,
        CloneFlags::CLONE_NEWCGROUP,
    )?;
    setns(File::open("/proc/1/ns/mnt")?, CloneFlags::CLONE_NEWNS)?;
    nix::unistd::chroot("/proc/1/root")?;
    std::env::set_current_dir("/")
}

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(e) = enter_guest_host() {
        eprintln!("tempo-dst: cannot enter guest host namespace: {e}");
        std::process::exit(1);
    }
    let arg = |i| std::env::args().nth(i).unwrap_or_default();
    match std::env::args().nth(1).as_deref() {
        Some("parse-args") => print_json(
            "parse-args",
            planner::request(&arg(2)).and_then(|r| planner::parse_args(&r)),
        ),
        Some("config") => print_json(
            "config",
            planner::request(&arg(2)).and_then(|r| planner::config(&r)),
        ),
        Some("observe") => print_json(
            "observe",
            planner::request(&arg(2)).and_then(|r| planner::observe(&r)),
        ),
        Some("warmup") => print_json(
            "warmup",
            planner::request(&arg(2)).and_then(|r| warmup::run(&r).map_err(|e| e.to_string())),
        ),
        Some("start") => {
            let config = std::env::args().nth(2).unwrap_or_default();
            if let Err(e) = start::run(&config) {
                eprintln!("start: {e}");
                std::process::exit(1);
            }
        }
        Some("nemesis") => {
            let cfg = common::Config::load();
            if cfg.cluster.is_some() {
                cluster_live::run_nemesis(&cfg);
            } else {
                nemesis::run(std::env::args().nth(2).as_deref() == Some("--resume"));
            }
        }
        Some("redecide") => {
            if let Err(e) = nemesis::redecide(&std::env::args().nth(2).unwrap_or_default()) {
                eprintln!("redecide: {e}");
                std::process::exit(1);
            }
        }
        Some("oracle") => {
            let cfg = common::Config::load();
            if cfg.cluster.is_some() {
                cluster_live::run_oracle(&cfg);
            } else {
                oracle::run();
            }
        }
        Some("finalize") => finalize::run(),
        Some("progress") => {
            if let Err(e) = assertions::progress() {
                eprintln!("progress: {e}");
                std::process::exit(1);
            }
        }
        Some("merge-assertions") => {
            if let Err(e) = assertions::merge_seed() {
                eprintln!("merge-assertions: {e}");
                std::process::exit(1);
            }
        }
        Some("deploy") => {
            let arg = |i| std::env::args().nth(i).unwrap_or_default();
            let spec = std::env::args()
                .nth(4)
                .unwrap_or_else(|| start::TRIE_DEPLOY_SPEC.into());
            if let Err(e) = start::deploy(&arg(2), &arg(3), &spec, None) {
                eprintln!("deploy: {e}");
                std::process::exit(1);
            }
        }
        Some("deploy-tip20") => {
            if let Err(e) = start::deploy_tip20(&std::env::args().nth(2).unwrap_or_default(), None)
            {
                eprintln!("deploy-tip20: {e}");
                std::process::exit(1);
            }
        }
        Some("deploy-zones") => {
            let image = std::env::args().nth(2);
            if let Err(e) = zones_live::deploy(image.as_deref().unwrap_or(zones::IMAGE)) {
                eprintln!("deploy-zones: {e}");
                std::process::exit(1);
            }
        }
        Some("zone-prover") => {
            if let Err(e) = zones_live::prover() {
                eprintln!("zone-prover: {e}");
                std::process::exit(1);
            }
        }
        Some("tcp-forward") => {
            if let Err(e) = forward::run(&std::env::args().skip(2).collect::<Vec<_>>()) {
                eprintln!("tcp-forward: {e}");
                std::process::exit(1);
            }
        }
        Some("zones-watch") => zones_live::watch(
            std::env::args()
                .nth(2)
                .and_then(|a| a.parse().ok())
                .unwrap_or(60),
        ),
        Some("tip20-spec") => {
            let arg = |i| {
                std::env::args()
                    .nth(i)
                    .and_then(|a| a.parse().ok())
                    .unwrap_or(0)
            };
            print!("{}", tip20::spec(arg(2), arg(3), arg(4) as usize));
        }
        Some("trie-spec") => {
            let arg = |i| {
                std::env::args()
                    .nth(i)
                    .and_then(|a| a.parse().ok())
                    .unwrap_or(0)
            };
            let seed = arg(2);
            // Optional contracts and senders (`trie_contracts=auto`): every
            // writer's spec, in writer order.
            let plan = trie_gen::plan(seed, arg(5).max(1) as usize, arg(6).max(1) as usize);
            for k in 0..plan.writers().len() {
                print!("{}", plan.writer_spec(k, seed, arg(3), arg(4) as usize));
            }
        }
        Some("chain-spec") => {
            let arg = |i| {
                std::env::args()
                    .nth(i)
                    .and_then(|a| a.parse().ok())
                    .unwrap_or(0)
            };
            print!("{}", cob_gen::spec(arg(2), arg(3), arg(4) as usize));
        }
        Some("statemix-spec") => {
            let arg = |i| {
                std::env::args()
                    .nth(i)
                    .and_then(|a| a.parse().ok())
                    .unwrap_or(0)
            };
            print!("{}", statemix_gen::spec(arg(2), arg(3), arg(4) as usize));
        }
        Some("chain-check") => {
            let mut chain = oracle::RpcChain;
            let block = match std::env::args().nth(2) {
                Some(b) => b.parse().ok(),
                None => common::head_number().ok(),
            };
            let Some(block) = block else {
                eprintln!("chain-check: no block");
                std::process::exit(1);
            };
            match cob::check_once(&mut chain, cob_gen::CONTRACT, block) {
                Ok((summary, verdicts)) => {
                    println!("{summary}");
                    for v in &verdicts {
                        println!("{v:?}");
                    }
                    if !verdicts.is_empty() {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("chain-check: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("chain-watch") => {
            let secs = std::env::args()
                .nth(2)
                .and_then(|a| a.parse().ok())
                .unwrap_or(60);
            cob::watch(&mut oracle::RpcChain, cob_gen::CONTRACT, secs);
        }
        Some("cluster-watch") => {
            let secs = std::env::args()
                .nth(2)
                .and_then(|a| a.parse().ok())
                .unwrap_or(60);
            cluster_live::watch(secs);
        }
        Some("reference-head") => {
            match common::with_rpc_url(common::REFERENCE_RPC_URL, common::head_number) {
                Ok(n) => println!("{n}"),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Some("storage-attach") => {
            if let Err(e) = storage::attach() {
                eprintln!("storage-attach: {e}");
                std::process::exit(1);
            }
        }
        Some("storage-ctl") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            let words: Vec<&str> = args.iter().map(String::as_str).collect();
            match storage::Control::parse(&words).and_then(storage::ctl) {
                Ok(v) => println!("{v}"),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Some("head") => match common::head_number() {
            Ok(n) => println!("{n}"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        },
        _ => {
            eprintln!("usage: tempo-dst <parse-args|config|observe|warmup|start|nemesis|redecide|oracle|finalize|head|reference-head|deploy|deploy-tip20|deploy-zones|zone-prover|tcp-forward|zones-watch|trie-spec|tip20-spec|chain-spec|statemix-spec|chain-check|chain-watch|storage-attach|storage-ctl|cluster-watch>");
            std::process::exit(2);
        }
    }
}
