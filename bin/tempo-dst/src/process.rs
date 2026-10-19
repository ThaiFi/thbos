// SPDX-License-Identifier: GPL-2.0

//! Process-level faults on a container (`process_faults=true`; see `nemesis`):
//! graceful stops judged for SIGKILL fallback, pause/resume, and CPU
//! throttling through the container's cgroup v2 directory.
//!
//! Throttling writes the drawn quota to the cgroup's `cpu.max`, but that is
//! CFS bandwidth control: it does not govern the node, whose threads run
//! under thread-fuzz as `SCHED_EXT` tasks (scx-fuzz implements no
//! `cgroup_set_bandwidth`). So the quota is also enforced with the freezer
//! (`cgroup.freeze`, which stops tasks of every scheduling class), duty-cycled
//! in guest time: thawed for `quota_pct` of each [`THROTTLE_PERIOD_MS`],
//! frozen for the rest. Everything is timed by the guest's emulated clock.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Serialize;
use serde_json::{json, Value};

use crate::common::{self, sh};

/// Duty-cycle period of a CPU throttle, and the CFS period written to
/// `cpu.max`.
pub const THROTTLE_PERIOD_MS: u64 = 100;
/// Exit code of a container that ended by SIGKILL (128 + 9).
const SIGKILL_EXIT: i64 = 137;

/// What a `podman stop -t <timeout>` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StopOutcome {
    pub timeout_secs: u64,
    /// `podman stop` exited 0.
    pub success: bool,
    /// The container's exit code afterwards (`.State.ExitCode`).
    pub exit_code: Option<i64>,
    /// Guest milliseconds `podman stop` took.
    pub elapsed_ms: u64,
    pub output: String,
}

impl StopOutcome {
    /// `Err(why)` when the stop was not graceful: podman failed, had to fall
    /// back to SIGKILL (it says so, and still exits 0; the container then
    /// exits 137), or waited out the whole timeout.
    pub fn judge(&self) -> Result<(), String> {
        let mut why = Vec::new();
        if !self.success {
            why.push("podman stop failed".to_string());
        }
        if self.exit_code.is_none() {
            why.push("container exit code unavailable".to_string());
        }
        if self.exit_code == Some(SIGKILL_EXIT) {
            why.push(format!("exit code {SIGKILL_EXIT} (SIGKILL)"));
        }
        if self.output.contains("SIGKILL") {
            why.push("podman resorted to SIGKILL".to_string());
        }
        if self.elapsed_ms >= self.timeout_secs * 1000 {
            why.push(format!(
                "took {} ms, timeout {} s",
                self.elapsed_ms, self.timeout_secs
            ));
        }
        if why.is_empty() {
            Ok(())
        } else {
            Err(why.join("; "))
        }
    }

    /// Formats the stop judgment, exit status, timing, and the final five output lines.
    pub fn detail(&self) -> String {
        let tail: Vec<&str> = self.output.lines().rev().take(5).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        format!(
            "{}: podman stop -t {} took {} ms, exit code {:?}\n{}",
            self.judge().err().unwrap_or_else(|| "clean".into()),
            self.timeout_secs,
            self.elapsed_ms,
            self.exit_code,
            tail.join("\n")
        )
    }
}

/// `podman stop -t <timeout_secs> <container>`, timed in guest time.
pub fn graceful_stop(container: &str, timeout_secs: u64) -> StopOutcome {
    let start = common::guest_time_ns();
    let (success, mut output) = sh(&format!("podman stop -t {timeout_secs} {container}"));
    let elapsed_ms = (common::guest_time_ns() - start) / 1_000_000;
    let (inspected, code) = sh(&format!(
        "podman inspect {container} --format '{{{{.State.ExitCode}}}}'"
    ));
    let exit_code = inspected.then(|| code.trim().parse().ok()).flatten();
    if exit_code.is_none() {
        output.push_str(&format!("\nexit-code inspection failed: {code}"));
    }
    StopOutcome {
        timeout_secs,
        success,
        exit_code,
        elapsed_ms,
        output,
    }
}

/// The container's cgroup v2 directory, from its main process.
pub fn cgroup_dir(container: &str) -> Result<PathBuf, String> {
    let (ok, pid) = sh(&format!(
        "podman inspect {container} --format '{{{{.State.Pid}}}}'"
    ));
    let pid = pid.trim();
    if !ok || pid == "0" || pid.is_empty() {
        return Err(format!("{container} has no process: {pid}"));
    }
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|e| format!("/proc/{pid}/cgroup: {e}"))?;
    parse_cgroup(&cgroup)
        .map(|rel| Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
        .ok_or_else(|| format!("no cgroup v2 entry in /proc/{pid}/cgroup: {cgroup}"))
}

/// The unified-hierarchy path in a `/proc/<pid>/cgroup` (`0::<path>`).
fn parse_cgroup(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_string)
}

fn write(dir: &Path, file: &str, value: &str) -> Result<(), String> {
    std::fs::write(dir.join(file), value).map_err(|e| format!("{}/{file}: {e}", dir.display()))
}

/// `cpu.stat`'s fields as JSON (`null` if unreadable).
pub fn cpu_stat(dir: &Path) -> Value {
    let Ok(text) = std::fs::read_to_string(dir.join("cpu.stat")) else {
        return Value::Null;
    };
    let map: serde_json::Map<String, Value> = text
        .lines()
        .filter_map(|l| l.split_once(' '))
        .filter_map(|(k, v)| Some((k.to_string(), json!(v.trim().parse::<u64>().ok()?))))
        .collect();
    Value::Object(map)
}

/// `cpu.max` contents for `quota_pct` percent of one CPU.
pub fn cpu_max(quota_pct: u32) -> String {
    let period_us = THROTTLE_PERIOD_MS * 1000;
    format!("{} {period_us}", period_us * u64::from(quota_pct) / 100)
}

/// Thawed and frozen milliseconds of each duty cycle at `quota_pct`.
pub fn duty_cycle(quota_pct: u32) -> (u64, u64) {
    let run = THROTTLE_PERIOD_MS * u64::from(quota_pct.min(100)) / 100;
    (run, THROTTLE_PERIOD_MS - run)
}

/// Throttles the container's cgroup to `quota_pct` of a CPU for
/// `window_secs` (see the module docs), then restores it. Returns what was
/// applied and the cgroup's `cpu.stat` before and after.
pub fn throttle(container: &str, quota_pct: u32, window_secs: u64) -> Result<Value, String> {
    let dir = cgroup_dir(container)?;
    let before = cpu_stat(&dir);
    // Absent when the cpu controller is not enabled for this subtree.
    let cpu_max_set = write(&dir, "cpu.max", &cpu_max(quota_pct)).is_ok();
    let (run_ms, frozen_ms) = duty_cycle(quota_pct);
    let end = common::guest_time_ns() + window_secs * 1_000_000_000;
    let mut result = Ok(());
    let mut cycles = 0u64;
    while common::guest_time_ns() < end {
        if frozen_ms > 0 {
            if let Err(e) = write(&dir, "cgroup.freeze", "1") {
                result = Err(e);
                break;
            }
            std::thread::sleep(Duration::from_millis(frozen_ms));
            if let Err(e) = write(&dir, "cgroup.freeze", "0") {
                result = Err(e);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(run_ms.max(1)));
        cycles += 1;
    }
    // Always leave the container thawed and unthrottled.
    let thawed = write(&dir, "cgroup.freeze", "0");
    let restored = if cpu_max_set {
        write(&dir, "cpu.max", "max 100000")
    } else {
        Ok(())
    };
    result.and(thawed).and(restored)?;
    Ok(json!({
        "cgroup": dir.display().to_string(),
        "cpu_max_set": cpu_max_set,
        "duty_ms": [run_ms, frozen_ms],
        "cycles": cycles,
        "cpu_stat_before": before,
        "cpu_stat_after": cpu_stat(&dir),
    }))
}

/// Thaws the container and lifts its CPU quota (a throttle cut short).
pub fn release(container: &str) -> Result<(), String> {
    let dir = cgroup_dir(container)?;
    // A subtree without the CPU controller still supports the freezer.
    let restored = if dir.join("cpu.max").exists() {
        write(&dir, "cpu.max", "max 100000")
    } else {
        Ok(())
    };
    let thawed = write(&dir, "cgroup.freeze", "0");
    restored.and(thawed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(
        success: bool,
        exit_code: Option<i64>,
        elapsed_ms: u64,
        output: &str,
    ) -> StopOutcome {
        StopOutcome {
            timeout_secs: 120,
            success,
            exit_code,
            elapsed_ms,
            output: output.into(),
        }
    }

    #[test]
    fn clean_stop_passes() {
        assert_eq!(outcome(true, Some(0), 2_000, "tempo\n").judge(), Ok(()));
        assert_eq!(
            outcome(true, None, 2_000, "tempo\n").judge(),
            Err("container exit code unavailable".into())
        );
    }

    #[test]
    fn sigkill_fallback_fails_even_though_podman_succeeds() {
        // podman 4/5 after the timeout: exit 0, a warning, container 137.
        let o = outcome(
            true,
            Some(137),
            120_050,
            "time=\"..\" level=warning msg=\"StopSignal SIGTERM failed to stop container tempo in 120 seconds, resorting to SIGKILL\"\ntempo\n",
        );
        let why = o.judge().unwrap_err();
        assert!(why.contains("137"), "{why}");
        assert!(why.contains("resorted to SIGKILL"), "{why}");
        assert!(why.contains("timeout 120 s"), "{why}");
        // Any one sign is enough.
        assert!(outcome(true, Some(137), 1_000, "").judge().is_err());
        assert!(outcome(true, Some(0), 120_000, "").judge().is_err());
        assert!(outcome(true, None, 1_000, "resorting to SIGKILL")
            .judge()
            .is_err());
        assert!(outcome(false, Some(0), 1_000, "Error: no such container")
            .judge()
            .is_err());
        assert!(o.detail().contains("took 120050 ms"), "{}", o.detail());
    }

    #[test]
    fn parses_unified_cgroup_path() {
        assert_eq!(
            parse_cgroup("0::/libpod_parent/libpod-abc/container\n").as_deref(),
            Some("/libpod_parent/libpod-abc/container")
        );
        assert_eq!(parse_cgroup("1:name=systemd:/x\n"), None);
    }

    #[test]
    fn throttle_quota_and_duty_cycle() {
        assert_eq!(cpu_max(20), "20000 100000");
        assert_eq!(duty_cycle(10), (10, 90));
        assert_eq!(duty_cycle(30), (30, 70));
        assert_eq!(duty_cycle(100), (100, 0));
    }

    #[test]
    fn parses_cpu_stat() {
        let dir = std::env::temp_dir().join(format!("tempo-dst-cpustat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cpu.stat"), "usage_usec 100\nnr_throttled 3\n").unwrap();
        assert_eq!(
            cpu_stat(&dir),
            json!({"usage_usec": 100, "nr_throttled": 3})
        );
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(cpu_stat(&dir), Value::Null);
    }
}
