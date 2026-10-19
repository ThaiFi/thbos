// SPDX-License-Identifier: GPL-2.0

//! Branch setup, invoked once by the host driver right after forking: installs
//! the run config, resets the event log, starts the oracle, nemesis, and load,
//! and snapshots assertion file offsets for this run.

use std::{
    fs::{self, File},
    io,
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
};

use serde_json::json;

use crate::{
    cob_gen,
    common::{self, Config, CONFIG_PATH, EVENTS_PATH, OUT_DIR},
    statemix_gen, tip20, trie_gen,
};

/// Starts `tempo-dst <sub>` in its own session so it outlives the I/O-channel
/// command that launched it.
fn spawn_detached(sub: &str) -> io::Result<()> {
    spawn_detached_with(sub, &[], false)
}

/// [`spawn_detached`] with extra arguments; `append` keeps the existing log
/// (a resumed nemesis continues the original's `nemesis.log`).
pub(crate) fn spawn_detached_with(sub: &str, args: &[&str], append: bool) -> io::Result<()> {
    let path = Path::new(OUT_DIR).join(format!("{sub}.log"));
    let log = if append {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?
    } else {
        File::create(path)?
    };
    // After the controller enters the guest host mount namespace, its image
    // path is unavailable; /proc/self/exe still names this running binary.
    let mut cmd = Command::new("/proc/self/exe");
    cmd.arg0("tempo-dst")
        .arg(sub)
        .args(args)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    // SAFETY: setsid is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| nix::unistd::setsid().map(drop).map_err(io::Error::from));
    }
    cmd.spawn().map(drop)
}

pub fn run(config_json: &str) -> io::Result<()> {
    let config: Config = serde_json::from_str(config_json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    config
        .validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    fs::create_dir_all(Path::new(CONFIG_PATH).parent().unwrap())?;
    fs::create_dir_all(OUT_DIR)?;
    fs::write(CONFIG_PATH, config_json)?;
    fs::write(EVENTS_PATH, "")?;
    crate::assertions::snapshot()?;
    if let Some(plan) = config.trie_plan().filter(|_| config.trie_pool()) {
        // The seed's drawn trie shape, recorded with the run (events.jsonl
        // is collected and compared by replay).
        common::emit_event("tempo-dst", "trie-plan", None, plan.summary());
    }
    if config.statemix {
        // The generation-0 mutation mix (deterministic from the seed), recorded
        // so a build-differential strand can replay the exact tx set.
        let steps = usize::try_from(config.load.count).unwrap_or(usize::MAX);
        let seed = config.load_generation(0).spec_seed;
        common::emit_event(
            "tempo-dst",
            "statemix-plan",
            None,
            statemix_gen::summary(seed, 0, steps),
        );
    }

    spawn_detached("oracle")?;
    spawn_detached("nemesis")?;
    start_load(&config, 0)?;
    Ok(())
}

/// The trie load's specs for one generation: each writer's burst (several
/// writers only; see `TriePlan::burst_spec`) and each writer's write stream.
fn trie_specs(
    plan: &trie_gen::TriePlan,
    seed: u64,
    generation: u64,
    steps: usize,
) -> (Vec<String>, Vec<String>) {
    let writers = plan.writers().len();
    let bursts = (0..writers)
        .filter(|_| writers > 1)
        .map(|k| plan.burst_spec(k, seed, generation))
        .collect();
    let specs = (0..writers)
        .map(|k| plan.writer_spec(k, seed, generation, steps))
        .collect();
    (bursts, specs)
}

/// The generated load spec of `generation` with spec seed `seed`, as
/// `(kind, text)`; `None` for a load that runs `load.spec` as is.
pub fn generated_spec(
    config: &Config,
    generation: u64,
    seed: u64,
) -> Option<(&'static str, String)> {
    let steps = usize::try_from(config.load.count).unwrap_or(usize::MAX);
    if let Some(plan) = config.trie_plan() {
        // Several writers: their bursts, then their specs, in writer order
        // (one text, for the recorded keccak; start_load writes them
        // separately). One writer: its spec only.
        let (bursts, specs) = trie_specs(&plan, seed, generation, steps);
        let text = bursts.concat() + &specs.concat();
        Some(("trie", text))
    } else if config.tip20 {
        Some(("tip20", tip20::spec(seed, generation, steps)))
    } else if config.cob.is_some() {
        Some(("chain", cob_gen::spec(seed, generation, steps)))
    } else if config.statemix {
        Some(("statemix", statemix_gen::spec(seed, generation, steps)))
    } else {
        None
    }
}

/// Starts the txgen load as container `txgen`. Generation `n` (0 at branch
/// start, then one per node restart) takes its inputs from
/// [`Config::load_generation`]: by default it draws its transactions from
/// workload seed `load.seed + n`; a generated trie load also gets a fresh
/// write stream (`trie_gen::spec`) over the run's slots, the TIP-20 load a
/// fresh transfer stream (`tip20::spec`), and a chain-of-blocks load fresh
/// payloads (`cob_gen::spec`). Each generation is logged as a `load`
/// `generation` event with its inputs and the spec's keccak, which the
/// driver copies into the run's scenario.
///
/// Load only: failures (e.g. while the node is down) are not oracles. The
/// oracle's S/load-included shows the load actually landed.
pub fn start_load(config: &Config, generation: u64) -> io::Result<()> {
    let load = &config.load;
    if load.count == 0 {
        return Ok(());
    }
    let inputs = config.draw_load_generation(generation);
    let trie_plan = config.trie_plan();
    let trie_specs = trie_plan.as_ref().map(|plan| {
        let steps = usize::try_from(load.count).unwrap_or(usize::MAX);
        trie_specs(plan, inputs.spec_seed, generation, steps)
    });
    let generated = trie_specs
        .as_ref()
        .map(|(bursts, specs)| ("trie", bursts.concat() + &specs.concat()))
        .or_else(|| generated_spec(config, generation, inputs.spec_seed));
    common::emit_event(
        "load",
        "generation",
        Some(load_container(config)),
        json!({
            "generation": generation,
            "txgen_seed": inputs.txgen_seed,
            "spec_seed": inputs.spec_seed,
            "steps": load.count,
            "kind": generated.as_ref().map(|g| g.0),
            "spec_keccak": generated
                .as_ref()
                .map(|g| alloy_primitives::keccak256(g.1.as_bytes()).to_string()),
            // Trie slots are derived in the guest; recorded so a scenario can
            // pin them.
            "slots": generated
                .as_ref()
                .filter(|g| g.0 == "trie")
                .and_then(|_| config.trie())
                .map(|t| t.slots),
            // The consumer of any getrandom draw above, for the input tape.
            "pid": std::process::id(),
            // The validator it sends to (cluster runs only).
            "target": config.cluster.as_ref().map(|c| c.load_target(generation).container()),
        }),
    );
    if config.zones {
        return crate::zones_live::start_load(
            config,
            generation,
            crate::zones_live::load_seed(inputs.spec_seed, generation),
        );
    }
    if let Some(plan) = trie_plan.filter(|p| p.writers().len() > 1) {
        let (bursts, specs) = trie_specs.as_ref().unwrap();
        return start_multi_writer_load(config, &plan, bursts, specs, generation, inputs);
    }
    let mut spec = load.spec.clone();
    let mut mount = Vec::new();
    if let Some((kind, text)) = generated {
        // Next to the image's artifacts, which the spec names relatively.
        let path = Path::new(OUT_DIR).join(format!("{kind}-load-{generation}.yaml"));
        fs::write(&path, text)?;
        spec = format!("/workload/{kind}/generated.yaml");
        mount = vec!["-v".to_string(), format!("{}:{spec}:ro", path.display())];
    }
    let image = if load.image.is_empty() {
        "bedrock/tempo-txgen:latest"
    } else {
        &load.image
    };
    let rpc = config
        .load_rpc_url(generation)
        .map(|url| format!("TEMPO_RPC_URL={url}"));
    let status = Command::new("podman")
        .args(["run", "-d", "--name", "txgen", "--network", "host"])
        .args(["-e", "BEDROCK=0"])
        .args(rpc.iter().flat_map(|r| ["-e", r.as_str()]))
        .args(["-e", &format!("TXGEN_SEED={}", inputs.txgen_seed)])
        .args(["-e", &format!("TXGEN_COUNT={}", load.count)])
        .args(["-e", &format!("TXGEN_TPS={}", load.tps)])
        .args(["-e", &format!("TXGEN_SPEC={spec}")])
        .args(&mount)
        .args(["--entrypoint", "/bin/bash", image])
        .args(["-c", "bash /workload/run.sh || true"])
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("podman run txgen: {status}")));
    }
    Ok(())
}

/// The load's container: txgen, or the zones driver.
pub fn load_container(config: &Config) -> &'static str {
    if config.zones {
        crate::zones::LOAD_CONTAINER
    } else {
        "txgen"
    }
}

/// The trie load with several writers (`trie_gen::plan`): one spec per
/// writer, each one sequence from one sender, run by the trie image's
/// `run-multi.sh`, which interleaves them so the writers send concurrently.
/// Each writer gets `steps` writes at the configured per-writer rate.
fn start_multi_writer_load(
    config: &Config,
    plan: &trie_gen::TriePlan,
    burst_specs: &[String],
    writer_specs: &[String],
    generation: u64,
    inputs: crate::common::LoadGeneration,
) -> io::Result<()> {
    let load = &config.load;
    let mut mount = Vec::new();
    let mut specs = Vec::new();
    let mut bursts = Vec::new();
    for (k, text) in burst_specs.iter().enumerate() {
        let path = Path::new(OUT_DIR).join(format!("trie-burst-{generation}-{k}.yaml"));
        fs::write(&path, text)?;
        let spec = format!("/workload/trie/burst-{k}.yaml");
        mount.extend(["-v".to_string(), format!("{}:{spec}:ro", path.display())]);
        bursts.push(spec);
    }
    for (k, text) in writer_specs.iter().enumerate() {
        let path = Path::new(OUT_DIR).join(format!("trie-load-{generation}-{k}.yaml"));
        fs::write(&path, text)?;
        let spec = format!("/workload/trie/generated-{k}.yaml");
        mount.extend(["-v".to_string(), format!("{}:{spec}:ro", path.display())]);
        specs.push(spec);
    }
    let tps = load.tps * plan.writers().len() as u64;
    let status = Command::new("podman")
        .args(["run", "-d", "--name", "txgen", "--network", "host"])
        .args(["-e", "BEDROCK=0"])
        .args(["-e", &format!("TXGEN_SEED={}", inputs.txgen_seed)])
        .args(["-e", &format!("TXGEN_COUNT={}", load.count)])
        .args(["-e", &format!("TXGEN_TPS={tps}")])
        .args(["-e", &format!("TXGEN_SPECS={}", specs.join(" "))])
        .args(["-e", &format!("TXGEN_BURST_SPECS={}", bursts.join(" "))])
        .args(&mount)
        .args(["--entrypoint", "/bin/bash", &load.image])
        .args(["-c", "bash /workload/trie/run-multi.sh || true"])
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("podman run txgen: {status}")));
    }
    Ok(())
}

/// Replaces the load after node restart `generation`. txgen pre-signs its
/// transactions with consecutive nonces, and a SIGKILL drops the node's
/// transaction pool, so the old load's remaining transactions sit behind a
/// nonce gap forever. The new generation re-reads nonces from the node.
pub fn restart_load(config: &Config, generation: u64) -> io::Result<()> {
    if config.load.count == 0 {
        return Ok(());
    }
    // Logged as a nemesis kill so workload-monitor excuses the SIGKILL.
    let name = load_container(config);
    common::emit_event(
        "nemesis",
        "kill",
        Some(name),
        json!({"reason": "reload", "generation": generation}),
    );
    for args in [
        &["kill", "-s", "KILL", name][..],
        &["wait", name],
        &["rm", "-f", name],
    ] {
        Command::new("podman")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
    }
    start_load(config, generation)
}

/// The trie load's deploy spec inside its image.
pub const TRIE_DEPLOY_SPEC: &str = "/workload/trie/deploy.yaml";

/// Deploys a load's contract (deploy spec `spec` inside `image`, e.g. the
/// trie load's RawStorage) through the node at `rpc` (`None`: the dev node)
/// and waits until `address` has code. The trie pool's spec
/// (`trie_contracts=auto`) waits for every pool contract.
pub fn deploy(image: &str, address: &str, spec: &str, rpc: Option<&'static str>) -> io::Result<()> {
    if spec == TRIE_POOL_SPEC {
        return deploy_trie_pool(image);
    }
    crate::deploy::run(image, spec, rpc, &format!("no code at {address}"), || {
        common::has_code(address)
    })
}

/// The multi-contract trie load's deploy spec inside its image.
pub const TRIE_POOL_SPEC: &str = "/workload/trie/deploy-pool.yaml";

/// Funds the extra writers and deploys the trie load's contract pool
/// (`trie/deploy-pool.yaml`), and waits until every predicted CREATE address
/// (`trie_gen::pool_address`) has code.
fn deploy_trie_pool(image: &str) -> io::Result<()> {
    let pool = trie_gen::pool_addresses();
    crate::deploy::run(
        image,
        TRIE_POOL_SPEC,
        None,
        "trie pool contract without code",
        || {
            for address in &pool {
                if !common::has_code(address)? {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )?;
    println!("{}", pool.join(" "));
    Ok(())
}

/// Creates the TIP-20 load's token and mints its supply to the holders
/// (`tip20/deploy.yaml`) through the node at `rpc` (`None`: the dev node),
/// and waits until the latest block holds exactly `tip20::Ledger::initial()`.
pub fn deploy_tip20(image: &str, rpc: Option<&'static str>) -> io::Result<()> {
    use crate::tip20::{Ledger, Tip20Chain};
    let mut chain = crate::oracle::RpcChain;
    crate::deploy::run(
        image,
        "/workload/tip20/deploy.yaml",
        rpc,
        "TIP-20 holders do not hold the minted supply",
        || {
            let head = common::head_number()?;
            let Some(block) = chain.block(head)? else {
                return Ok(false);
            };
            // The token does not exist until its create lands.
            Ok(chain.ledger(block.hash).ok() == Some(Ledger::initial()))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{LoadGeneration, ScheduledFault},
        nemesis,
    };

    fn config(json: &str) -> Config {
        let c: Config = serde_json::from_str(json).unwrap();
        c.validate().unwrap();
        c
    }

    #[test]
    fn explicit_nemesis_plan_wins_but_still_draws() {
        let c = config(
            r#"{"seed": 3, "run_secs": 300,
                "nemesis": {"enabled": true, "max_kills": 3, "min_gap_secs": 20},
                "nemesis_plan": [{"at_secs": 11, "down_secs": 2}, {"at_secs": 40, "down_secs": 0}]}"#,
        );
        let mut draws = 0;
        let faults = nemesis::faults_for(&c, |lo, _| {
            draws += 1;
            lo
        });
        assert_eq!(
            faults
                .iter()
                .map(|k| (k.at_secs, k.down_secs))
                .collect::<Vec<_>>(),
            [(11, 2), (40, 0)]
        );
        // The same randomness is consumed as without a plan.
        let derived = Config {
            nemesis_plan: None,
            ..c.clone()
        };
        let mut plain_draws = 0;
        let drawn = nemesis::faults_for(&derived, |lo, _| {
            plain_draws += 1;
            lo
        });
        assert_eq!(draws, plain_draws);
        assert_ne!(drawn, faults);
        // An empty explicit plan means no kills.
        let none = Config {
            nemesis_plan: Some(vec![]),
            ..c
        };
        assert!(nemesis::faults_for(&none, |lo, _| lo).is_empty());
    }

    #[test]
    fn overlapping_explicit_plans_are_rejected() {
        let kill = |at_secs, down_secs| ScheduledFault {
            at_secs,
            down_secs,
            ..Default::default()
        };
        let mut c = Config {
            nemesis_plan: Some(vec![kill(30, 3), kill(32, 1)]),
            ..Config::default()
        };
        assert!(c.validate().unwrap_err().contains("nemesis_plan[1]"));
        c.nemesis_plan.as_mut().unwrap()[1].at_secs = 33;
        assert!(c.validate().is_ok());
        assert!(run(
            r#"{"nemesis_plan": [{"at_secs": 9, "down_secs": 3}, {"at_secs": 10, "down_secs": 0}]}"#
        )
        .is_err());
    }

    #[test]
    fn explicit_load_generations_drive_seeds_and_specs() {
        let c = config(
            r#"{"seed": 3, "tip20": true,
                "load": {"seed": 99, "count": 20, "tps": 5,
                         "generations": [{"txgen_seed": 7, "spec_seed": 1234}]}}"#,
        );
        assert_eq!(
            c.load_generation(0),
            LoadGeneration {
                txgen_seed: 7,
                spec_seed: 1234
            }
        );
        // Past the explicit ones: derived as before.
        assert_eq!(
            c.load_generation(2),
            LoadGeneration {
                txgen_seed: 101,
                spec_seed: 3
            }
        );
        let (kind, text) = generated_spec(&c, 0, c.load_generation(0).spec_seed).unwrap();
        assert_eq!(kind, "tip20");
        assert_eq!(text, tip20::spec(1234, 0, 20));
        assert_eq!(
            generated_spec(&c, 2, c.load_generation(2).spec_seed)
                .unwrap()
                .1,
            tip20::spec(3, 2, 20)
        );

        let chain = config(
            r#"{"seed": 3, "cob": {"address": "0x0"},
                "load": {"count": 4, "generations": [{"txgen_seed": 1, "spec_seed": 9}]}}"#,
        );
        assert_eq!(
            generated_spec(&chain, 0, 9).unwrap().1,
            cob_gen::spec(9, 0, 4)
        );
    }

    #[test]
    fn explicit_trie_slots_still_generate_the_spec() {
        // A scenario's recorded slots with `generated`: the spec is
        // trie_gen's over exactly those slots, not the seed's.
        let c = config(
            r#"{"seed": 3, "trie": {"address": "0x0", "slots": [5, 6, 70000], "generated": true},
                "load": {"count": 10, "generations": [{"txgen_seed": 1, "spec_seed": 3}]}}"#,
        );
        assert_eq!(c.trie().unwrap().slots, [5, 6, 70000]);
        let (kind, text) = generated_spec(&c, 0, c.load_generation(0).spec_seed).unwrap();
        assert_eq!(kind, "trie");
        assert_eq!(text, trie_gen::spec(3, 0, &[5, 6, 70000], 10));
        // Without slots they come from the seed, as before.
        let derived = config(r#"{"seed": 3, "trie": {"address": "0x0"}, "load": {"count": 10}}"#);
        assert_eq!(derived.trie().unwrap().slots, trie_gen::slots(3));
        // Hand-written slots without `generated` keep the image's spec.
        let manual = config(
            r#"{"seed": 3, "trie": {"address": "0x0", "slots": [1]}, "load": {"count": 10}}"#,
        );
        assert!(generated_spec(&manual, 0, 3).is_none());
    }

    #[test]
    fn derived_configs_serialize_without_explicit_fields() {
        let c = config(r#"{"seed": 3, "trie": {"address": "0x0"}, "load": {"count": 10}}"#);
        let s = serde_json::to_string(&c).unwrap();
        for key in ["nemesis_plan", "generations", "generated"] {
            assert!(!s.contains(key), "{key} in {s}");
        }
    }
}
