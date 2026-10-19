// SPDX-License-Identifier: GPL-2.0

//! Load-image setup before the shared warm checkpoint.

use crate::common;
use std::{
    io,
    process::{Command, Stdio},
};

/// Runs a load image's `spec` (its setup steps) once against the node at `rpc`
/// (`None`: the dev node) and waits until `done` holds there. Run before the
/// warm checkpoint, so every branch starts with the load's contracts in place.
pub(crate) fn run(
    image: &str,
    spec: &str,
    rpc: Option<&'static str>,
    what: &str,
    mut done: impl FnMut() -> Result<bool, String>,
) -> io::Result<()> {
    let rpc_env = rpc.map(|url| format!("TEMPO_RPC_URL={url}"));
    let mut done = || match rpc {
        Some(url) => common::with_rpc_url(url, &mut done),
        None => done(),
    };
    // run.sh's own pass check expects a pure-load run; `done` is ours.
    let status = Command::new("podman")
        .args(["run", "--rm", "--network", "host", "-e", "BEDROCK=0"])
        .args(rpc_env.iter().flat_map(|r| ["-e", r.as_str()]))
        .args(["-e", &format!("TXGEN_SPEC={spec}")])
        .args(["-e", "TXGEN_COUNT=1", "-e", "TXGEN_TPS=1"])
        .args(["--entrypoint", "/bin/bash", image, "/workload/run.sh"])
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        eprintln!("setup command exited {status}; checking {what}");
    }
    for _ in 0..60 {
        if done().map_err(io::Error::other)? {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err(io::Error::other(format!("deploy incomplete: {what}")))
}
