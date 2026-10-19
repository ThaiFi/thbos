// SPDX-License-Identifier: GPL-2.0

//! End-of-run oracles, invoked once by the host driver:
//!
//! - stops the nemesis, load, and online oracle so shutdown isn't judged as a
//!   fault;
//! - E4: stops the node gracefully, checks its trie, then re-executes
//!   `[1, head]` from its datadir in a fresh container, which checks
//!   receipts, gas, and changesets against what the node persisted. A stop
//!   that only ended because podman fell back to SIGKILL (it still exits 0)
//!   fails `E4/graceful-stop` (see `process::StopOutcome::judge`).
//! - E7: stops (judged the same) and checks the reference node (if any) first.
//! - with a cluster (`validators=4`), E4 for every validator, against the
//!   cluster's genesis;
//! - merges the run's assertion files into `/bedrock/out/assertions.jsonl`
//!   for the driver.

use std::{path::Path, time::Duration};

use bedrock_assertions::Condition;
use serde_json::json;

use crate::{
    common::{self, sh, Config},
    process::{self, StopOutcome},
    topology::{self, NodeSpec},
};

fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

fn repair_trie(
    image: &str,
    volume: &str,
    chain: &str,
    binary: &str,
    signature: &str,
) -> serde_json::Value {
    let cmd = format!(
        "podman run --rm --network none -v {volume}:/data --entrypoint {binary} {image} \
         db --chain {chain} --datadir /data repair-trie --dry-run 2>&1"
    );
    let (ok, out) = sh(&cmd);
    // repair-trie reports findings but exits successfully in dry-run mode.
    let clean = ok
        && out.contains("Found 0 inconsistencies (dry run - no changes made)")
        && !out.contains("Inconsistency found:");
    common::assert_always(
        Condition::Bool(clean),
        "finalize",
        signature,
        &tail(&out, 40),
    );
    json!({"ok": ok, "clean": clean, "output_tail": tail(&out, 200)})
}

/// Stops `container` gracefully and asserts it went cleanly (`signature`).
fn stop(container: &str, timeout_secs: u64, signature: &str) -> StopOutcome {
    // Logged first, so workload-monitor leaves a SIGKILL fallback to
    // `signature` instead of also reporting the death.
    common::emit_event(
        "nemesis",
        "stop",
        Some(container),
        json!({"reason": "finalize", "timeout_secs": timeout_secs}),
    );
    let outcome = process::graceful_stop(container, timeout_secs);
    common::assert_always(
        Condition::Bool(outcome.judge().is_ok()),
        "finalize",
        signature,
        &outcome.detail(),
    );
    outcome
}

/// How a validator's graceful stop went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopVerdict {
    /// Exit 0.
    Clean,
    /// Exit 1 from Tempo's deliberate executor fail-stop during shutdown:
    /// on SIGTERM reth stops its engine first, the consensus executor's next
    /// engine call fails with "beacon consensus engine task stopped", and
    /// the executor shuts down on purpose ("an engine call that fails
    /// outright ... is fatal", tempo crates/consensus/src/executor/actor.rs
    /// module docs, `log_fatal`), so the consensus task exits with an error.
    /// Expected, nothing lost: the next start backfills.
    ExecutorFailStop,
    /// Anything else.
    Failed,
}

/// The executor's fail-stop line and its engine-shutdown cause.
const EXECUTOR_FAIL_STOP: &str = "executor encountered fatal execution-layer update error";
const ENGINE_STOPPED: &str = "beacon consensus engine task stopped";

/// Classifies a stop by its exit code and the node's log: only exit 1 whose
/// log, after the last "Received SIGTERM", shows the executor fail-stop on
/// a stopped engine (and no panic) is the expected shutdown path.
fn classify_stop(exit_code: &str, log: &str) -> StopVerdict {
    match exit_code {
        "0" => StopVerdict::Clean,
        "1" => {
            let Some((_, after)) = log.rsplit_once("Received SIGTERM") else {
                return StopVerdict::Failed;
            };
            let fail_stop = after.lines().any(|l| {
                (l.contains(EXECUTOR_FAIL_STOP) || l.contains("execution task failed"))
                    && l.contains(ENGINE_STOPPED)
            });
            if fail_stop && !after.contains("panicked at") {
                StopVerdict::ExecutorFailStop
            } else {
                StopVerdict::Failed
            }
        }
        _ => StopVerdict::Failed,
    }
}

/// A node to stop and re-execute: its container, the binary its re-execute and
/// trie-repair run in, and the head to re-execute to.
struct StopTarget<'a> {
    container: &'a str,
    binary: &'a str,
    head: Option<u64>,
}

/// Stops `targets` gracefully with one `podman stop` (E4/graceful-stop;
/// with `require_exit_zero`, the node must also exit 0), then re-executes
/// blocks `1..=head` from each datadir against `chain` in a fresh container
/// (E4/re-execute); the summary of each, by container.
fn stop_and_reexecute(
    targets: &[StopTarget],
    chain: &str,
    require_exit_zero: bool,
) -> serde_json::Map<String, serde_json::Value> {
    let inspect = |container: &str, format: &str| {
        sh(&format!("podman inspect {container} --format '{format}'"))
            .1
            .trim()
            .to_string()
    };
    let mounts = "{{range .Mounts}}{{if eq .Destination \"/data\"}}{{.Name}}{{end}}{{end}}";
    let found: Vec<(String, String)> = targets
        .iter()
        .map(|t| {
            (
                inspect(t.container, "{{.ImageName}}"),
                inspect(t.container, mounts),
            )
        })
        .collect();
    let names: Vec<&str> = targets.iter().map(|t| t.container).collect();
    if require_exit_zero {
        // E4 judges these exits (with the node's log in hand), not
        // workload-monitor's generic exit-code check.
        for name in &names {
            common::emit_event(
                "finalize",
                "stop",
                Some(name),
                json!({"judged_by": "E4/graceful-stop"}),
            );
        }
    }
    let (stopped, stop_out) = sh(&format!("podman stop -t 120 {}", names.join(" ")));
    let mut out = serde_json::Map::new();
    for (t, (image, volume)) in targets.iter().zip(found) {
        let container = t.container;
        let exit_code = inspect(container, "{{.State.ExitCode}}");
        let verdict = if require_exit_zero {
            let (_, log) = sh(&format!("podman logs {container} 2>&1"));
            classify_stop(&exit_code, &log)
        } else {
            StopVerdict::Clean
        };
        if verdict == StopVerdict::ExecutorFailStop {
            common::assert_sometimes(
                Condition::Bool(true),
                "finalize",
                "S/shutdown-executor-fail-stop",
                &format!("{container}: exit code {exit_code}"),
            );
        }
        common::assert_always(
            Condition::Bool(stopped && verdict != StopVerdict::Failed),
            "finalize",
            "E4/graceful-stop",
            &format!("{container}: exit code {exit_code}; {}", tail(&stop_out, 5)),
        );
        let trie = repair_trie(&image, &volume, chain, t.binary, "E4/repair-trie");
        let mut reexec = json!(null);
        if let Some(head) = t.head.filter(|h| *h > 1) {
            let cmd = format!(
                "podman run --rm --network none -v {volume}:/data --entrypoint {} {image} \
                 re-execute --datadir /data --chain {chain} --from 1 --to {head} 2>&1",
                t.binary
            );
            let (ok, text) = sh(&cmd);
            let clean = ok && !text.contains("Invalid block") && !text.contains("mismatch");
            common::assert_always(
                Condition::Bool(clean),
                "finalize",
                "E4/re-execute",
                &format!("{container}: blocks 1..={head}\n{}", tail(&text, 40)),
            );
            common::assert_sometimes(Condition::Bool(ok), "finalize", "S/re-executed", "");
            reexec = json!({"ok": ok, "clean": clean, "output_tail": tail(&text, 200)});
        }
        out.insert(
            container.to_string(),
            json!({
                "head": t.head,
                "image": image,
                "volume": volume,
                "stopped": stopped,
                "exit_code": exit_code,
                "repair_trie": trie,
                "re_execute": reexec,
            }),
        );
    }
    out
}

pub fn run() {
    common::emit_event("driver", "finalize_start", None, json!({}));
    // `[t]` keeps the pattern from matching this `sh -c` itself: with plain
    // patterns the first pkill killed the shell and the oracle ran on
    // through finalize.
    sh("pkill -f '[t]empo-dst (nemesis|oracle)'");
    if sh("podman container exists txgen && test \"$(podman inspect txgen --format '{{.State.Running}}')\" = true").0 {
        // Logged as a nemesis kill so workload-monitor excuses the SIGKILL.
        common::emit_event("nemesis", "kill", Some("txgen"), json!({"reason": "finalize"}));
        sh("podman kill -s KILL txgen");
    }

    let cfg = Config::load();
    // One source of truth for what nodes to finalize: the cluster replaces the
    // dev node, so an empty validator set means the dev node (optionally with
    // its reference). Container names, binaries and chains come from the
    // topology, not literals here.
    let topo = topology::topology(&cfg);
    let validators: Vec<&NodeSpec> = topo.validators().collect();

    let summary = if cfg.zones {
        let heads: Vec<_> = topo
            .iter()
            .map(|n| {
                let url = n
                    .validator_id()
                    .map_or("http://127.0.0.1:8545", |v| v.rpc_url());
                common::with_rpc_url(url, common::head_number).ok()
            })
            .collect();
        std::thread::sleep(Duration::from_secs(5));
        let targets: Vec<_> = topo
            .iter()
            .zip(heads)
            .map(|(n, head)| StopTarget {
                container: &n.name,
                binary: &n.binary,
                head,
            })
            .collect();
        json!({ "zones_l1": stop_and_reexecute(&targets, &topo.primary().chain, true) })
    } else if validators.is_empty() {
        let primary = topo.primary();
        let head = common::head_number().ok();
        // Wait for the node to persist what it has before a graceful stop.
        std::thread::sleep(Duration::from_secs(5));
        let inspect = |container: &str, format: &str| {
            sh(&format!("podman inspect {container} --format '{format}'"))
                .1
                .trim()
                .to_string()
        };
        let mounts = "{{range .Mounts}}{{if eq .Destination \"/data\"}}{{.Name}}{{end}}{{end}}";
        let image = inspect(&primary.name, "{{.ImageName}}");
        let volume = inspect(&primary.name, mounts);
        let timeout = cfg.finalize_stop_timeout_secs;
        // The reference (E7) stops first, then the primary (E4); both repair
        // after, in that order, then the primary re-executes.
        let reference = topo.reference().map(|reference| {
            stop(&reference.name, timeout, "E7/reference-graceful-stop");
            (
                inspect(&reference.name, "{{.ImageName}}"),
                inspect(&reference.name, mounts),
                reference,
            )
        });
        let node_stop = stop(&primary.name, timeout, "E4/graceful-stop");
        let stopped = node_stop.judge().is_ok();
        let reference_repair_trie = reference.map_or(json!(null), |(image, volume, reference)| {
            repair_trie(
                &image,
                &volume,
                &reference.chain,
                &reference.binary,
                "E7/reference-repair-trie",
            )
        });
        let trie_repair = repair_trie(
            &image,
            &volume,
            &primary.chain,
            &primary.binary,
            "E4/repair-trie",
        );
        let mut reexec = json!(null);
        if let Some(head) = head.filter(|h| *h > 1) {
            let cmd = format!(
                "podman run --rm --network none -v {volume}:/data --entrypoint {} {image} \
                 re-execute --datadir /data --chain {} --from 1 --to {head} 2>&1",
                primary.binary, primary.chain
            );
            let (ok, out) = sh(&cmd);
            let clean = ok && !out.contains("Invalid block") && !out.contains("mismatch");
            common::assert_always(
                Condition::Bool(clean),
                "finalize",
                "E4/re-execute",
                &format!("blocks 1..={head}\n{}", tail(&out, 40)),
            );
            common::assert_sometimes(Condition::Bool(ok), "finalize", "S/re-executed", "");
            reexec = json!({"ok": ok, "clean": clean, "output_tail": tail(&out, 200)});
        }
        json!({
            "head": head,
            "image": image,
            "volume": volume,
            "stopped": stopped,
            "stop": node_stop,
            "repair_trie": trie_repair,
            "reference_repair_trie": reference_repair_trie,
            "re_execute": reexec,
        })
    } else {
        // Every validator, stopped together (a cluster shutdown: no
        // finalization races the stop of the last ones), each exiting 0, and
        // its datadir re-executed against the cluster's genesis (in its image
        // at /net). The certified follower's datadir is finalized the same way,
        // so the tempo#8263 run checks that its post-catch-up chain re-executes.
        let mut l1_nodes: Vec<&NodeSpec> = validators.clone();
        if let Some(follower) = topo.follower() {
            l1_nodes.push(follower);
        }
        let heads: Vec<Option<u64>> = l1_nodes
            .iter()
            .map(|n| {
                let url = n
                    .validator_id()
                    .map_or("http://127.0.0.1:8545", |v| v.rpc_url());
                common::with_rpc_url(url, common::head_number).ok()
            })
            .collect();
        // Let the nodes persist what they have before a graceful stop.
        std::thread::sleep(Duration::from_secs(5));
        let targets: Vec<StopTarget> = l1_nodes
            .iter()
            .enumerate()
            .map(|(i, n)| StopTarget {
                container: &n.name,
                binary: &n.binary,
                head: heads[i],
            })
            .collect();
        json!({ "validators": stop_and_reexecute(&targets, &validators[0].chain, true) })
    };

    let _ = std::fs::create_dir_all(common::OUT_DIR);
    let _ = std::fs::write(
        Path::new(common::OUT_DIR).join("finalize.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    );
    common::emit_event("oracle", "finalized", None, summary);
    // The contract: finalize leaves the run's assertions for the driver.
    if let Err(e) = crate::assertions::merge_seed() {
        eprintln!("merge-assertions: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHUTDOWN: &str = "2024-01-01T00:06:05.787689Z  INFO reth::cli: Received SIGTERM
2024-01-01T00:06:05.933034Z ERROR shutdown: tempo_consensus::executor::actor: executor encountered fatal execution-layer update error; shutting down to prevent consensus-execution divergence error=[failed delivering finalized block `0x2e` at height `245`, failed sending new-payload request to execution layer, beacon consensus engine task stopped]
Error: consensus task exited with error";

    #[test]
    fn only_the_engine_shutdown_fail_stop_is_an_expected_exit_1() {
        assert_eq!(classify_stop("0", ""), StopVerdict::Clean);
        assert_eq!(classify_stop("1", SHUTDOWN), StopVerdict::ExecutorFailStop);
        // The same fail-stop before the SIGTERM (mid-run) is not shutdown.
        let before = format!(
            "{}\nINFO reth::cli: Received SIGTERM\n",
            SHUTDOWN.lines().nth(1).unwrap()
        );
        assert_eq!(classify_stop("1", &before), StopVerdict::Failed);
        // Another cause, a panic, or another exit code is a failure.
        let other = SHUTDOWN.replace("beacon consensus engine task stopped", "database error");
        assert_eq!(classify_stop("1", &other), StopVerdict::Failed);
        let panic = format!("{SHUTDOWN}\nthread 'x' panicked at src/lib.rs:1:1:");
        assert_eq!(classify_stop("1", &panic), StopVerdict::Failed);
        assert_eq!(classify_stop("137", SHUTDOWN), StopVerdict::Failed);
        assert_eq!(classify_stop("1", ""), StopVerdict::Failed);
    }
}
