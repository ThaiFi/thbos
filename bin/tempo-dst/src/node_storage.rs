// SPDX-License-Identifier: GPL-2.0

//! Machine crashes of one validator's storage (`storage=lazyfs`): each
//! validator's datadir volume on its own [LazyFS](https://github.com/dsrhaslab/lazyfs)
//! instance, which keeps written data in its page cache until the node syncs
//! it, so a crash can drop what was never synced.
//!
//! LazyFS, its pin and its patch (`nix/lazyfs.nix`, `nix/lazyfs/bedrock.patch`:
//! the `bedrock <id> crash <keep_permille> <seed>` command and its stats) come
//! from the single-node storage-fault work (branch `dst/lazyfs`); this module
//! runs one instance per validator, each under `/run/lazyfs/<container>/`.
//! The interface the nemesis uses is [`attach`] and [`machine_crash`] over a
//! [`Discard`], so another layer (faultfs) can stand behind it.
//!
//! A machine crash: with the node already dead, flush the kernel's dirty
//! pages of the mount to LazyFS (they were volatile too), have LazyFS write
//! the drawn subset of its un-synced blocks to the backing files and exit
//! (the rest is lost), unmount (dropping the kernel's caches of the old
//! mount) and mount a fresh LazyFS. The node then reopens cold.

use std::{
    io::{Read, Write},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    cluster::{Discard, ValidatorId},
    common::OUT_DIR,
};

/// Counters of one machine crash, as LazyFS reports them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CrashStats {
    /// Files with un-synced blocks or size at the crash.
    pub dirty_files: u64,
    pub dirty_pages: u64,
    pub kept_pages: u64,
    pub reverted_pages: u64,
    /// Files whose un-synced size was discarded, and the bytes that cut.
    pub reverted_sizes: u64,
    pub truncated_bytes: u64,
    /// Backing writes that failed while keeping blocks; nonzero is a harness
    /// bug.
    pub undo_errors: u64,
    /// Dirty blocks LazyFS wrote back without a sync (cache full of dirty
    /// blocks): durable earlier than the node asked.
    pub early_writebacks: u64,
}

impl CrashStats {
    /// Whether the crash discarded anything.
    pub fn discarded(&self) -> bool {
        self.reverted_pages + self.reverted_sizes > 0
    }
}

/// The patch's `crash` arguments for `d`: `<keep_permille> <seed>`.
fn crash_args(d: Discard) -> String {
    match d {
        Discard::All => "0 0".into(),
        Discard::Subset {
            seed,
            keep_permille,
        } => format!("{} {seed}", keep_permille.min(1000)),
    }
}

/// Each LazyFS's page cache, preallocated at mount.
const CACHE_SIZE: &str = "128mb";

/// One validator's LazyFS instance: its control FIFOs, config and the
/// private bind of the volume's backing directory it reaches files through.
struct Instance {
    v: ValidatorId,
}

impl Instance {
    fn path(&self, name: &str) -> PathBuf {
        Path::new("/run/lazyfs").join(self.v.container()).join(name)
    }

    /// Sends one control command; the reply's JSON on success.
    fn ctl(&self, cmd: &str) -> Result<Value, String> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let id = format!(
            "{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        // The reply FIFO first (non-blocking: LazyFS holds it open); no
        // reader on the command FIFO (ENXIO) means LazyFS is not running.
        let mut done = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
            .open(self.path("done.fifo"))
            .map_err(|e| format!("{} lazyfs reply fifo: {e}", self.v))?;
        std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
            .open(self.path("faults.fifo"))
            .and_then(|mut f| f.write_all(format!("bedrock {id} {cmd}\n").as_bytes()))
            .map_err(|e| format!("{} lazyfs fault fifo: {e}", self.v))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        for _ in 0..12_000 {
            match done.read(&mut chunk) {
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("{} lazyfs reply fifo: {e}", self.v)),
            }
            for line in String::from_utf8_lossy(&buf).lines() {
                if let Some(reply) = line.strip_prefix(&format!("{id} ")) {
                    let v: Value =
                        serde_json::from_str(reply).map_err(|e| format!("{e}: {reply}"))?;
                    return if v["ok"] == true {
                        Ok(v)
                    } else {
                        Err(format!("{} lazyfs {cmd}: {}", self.v, v["error"]))
                    };
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(format!("{} lazyfs {cmd}: no reply", self.v))
    }

    fn running(&self) -> bool {
        std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
            .open(self.path("faults.fifo"))
            .is_ok()
    }

    /// Starts LazyFS over `dir` and waits until it answers.
    fn mount(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(OUT_DIR).map_err(|e| e.to_string())?;
        let config = self.path("lazyfs.toml");
        // Single-threaded (-s); its only clock reads are file times, from
        // the guest's emulated clock.
        std::fs::write(
            &config,
            format!(
                "[faults]\nfifo_path=\"{}\"\nfifo_path_completed=\"{}\"\n\
                 [cache]\napply_eviction=true\n\
                 [cache.simple]\ncustom_size=\"{CACHE_SIZE}\"\nblocks_per_page=1\n\
                 [filesystem]\nlog_all_operations=false\nlogfile=\"\"\n",
                self.path("faults.fifo").display(),
                self.path("done.fifo").display(),
            ),
        )
        .map_err(|e| e.to_string())?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(OUT_DIR).join(format!("lazyfs-{}.log", self.v.container())))
            .map_err(|e| e.to_string())?;
        let mut cmd = Command::new("lazyfs");
        cmd.arg(dir)
            .arg("--config-path")
            .arg(&config)
            .args(["-o", "allow_other", "-o", "modules=subdir"])
            .arg("-o")
            .arg(format!("subdir={}", self.path("root").display()))
            // libmdbx refuses mount sources named `fuse*` unless opened
            // exclusively.
            .args(["-o", "fsname=lazyfs", "-f", "-s"])
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log);
        // SAFETY: setsid is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                nix::unistd::setsid()
                    .map(drop)
                    .map_err(std::io::Error::from)
            });
        }
        cmd.spawn()
            .map_err(|e| format!("{} spawn lazyfs: {e}", self.v))?;
        for _ in 0..300 {
            if mounted(dir) && self.ctl("stats").is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(format!(
            "{} lazyfs did not come up on {}",
            self.v,
            dir.display()
        ))
    }

    fn mount_dir(&self) -> Result<PathBuf, String> {
        std::fs::read_to_string(self.path("mount"))
            .map(|s| PathBuf::from(s.trim()))
            .map_err(|e| format!("{} not on lazyfs: {e}", self.v))
    }
}

/// Whether `dir` is a LazyFS mount point.
fn mounted(dir: &Path) -> bool {
    std::fs::read_to_string("/proc/self/mounts")
        .unwrap_or_default()
        .lines()
        .any(|l| {
            let mut f = l.split(' ');
            f.next() == Some("lazyfs") && f.next() == Some(&*dir.to_string_lossy())
        })
}

fn sh(cmd: &str) -> (bool, String) {
    match Command::new("sh").args(["-c", cmd]).output() {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), text)
        }
        Err(e) => (false, e.to_string()),
    }
}

/// Unmounts the LazyFS at `dir` (its process already exited).
#[cfg(target_os = "linux")]
fn unmount(dir: &Path) -> Result<(), String> {
    use nix::mount::{umount2, MntFlags};
    for i in 0..50 {
        match umount2(dir, MntFlags::empty()) {
            Ok(()) => break,
            Err(nix::errno::Errno::EBUSY) if i < 49 => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(nix::errno::Errno::EBUSY) => {
                umount2(dir, MntFlags::MNT_DETACH).map_err(|e| format!("umount -l: {e}"))?;
            }
            Err(e) => return Err(format!("umount {}: {e}", dir.display())),
        }
    }
    if mounted(dir) {
        return Err(format!("{} still mounted", dir.display()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn unmount(dir: &Path) -> Result<(), String> {
    Err(format!("lazyfs needs Linux ({})", dir.display()))
}

/// Binds `dir` privately at `root`, so the LazyFS mount over `dir` does not
/// propagate to it.
#[cfg(target_os = "linux")]
fn bind_private(dir: &Path, root: &Path) -> Result<(), String> {
    use nix::mount::{mount, MsFlags};
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    mount(
        Some(dir),
        root,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| format!("bind {}: {e}", dir.display()))?;
    mount(
        None::<&str>,
        root,
        None::<&str>,
        MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| format!("make-private {}: {e}", root.display()))
}

#[cfg(not(target_os = "linux"))]
fn bind_private(dir: &Path, _root: &Path) -> Result<(), String> {
    Err(format!("lazyfs needs Linux ({})", dir.display()))
}

/// Warmup step (before the checkpoint): SIGKILLs `v`'s node, mounts LazyFS
/// over its datadir volume's backing directory and starts it again.
/// Everything on disk at attach is durable. SIGKILL, not a graceful stop:
/// the node's shutdown path would log into every branch's E1.
pub fn attach(v: ValidatorId) -> Result<(), String> {
    let me = Instance { v };
    let c = v.container();
    let (ok, source) = sh(&format!(
        "podman inspect {c} --format '{{{{range .Mounts}}}}{{{{if eq .Destination \"/data\"}}}}{{{{.Source}}}}{{{{end}}}}{{{{end}}}}'"
    ));
    let dir = PathBuf::from(source.trim());
    if !ok || !dir.is_absolute() {
        return Err(format!("no /data volume on {c}: {source}"));
    }
    let (killed, out) = sh(&format!("podman kill -s KILL {c} && podman wait {c}"));
    if !killed {
        return Err(format!("podman kill {c}: {out}"));
    }
    std::fs::create_dir_all(me.path("")).map_err(|e| e.to_string())?;
    std::fs::write(me.path("mount"), dir.to_string_lossy().as_bytes())
        .map_err(|e| e.to_string())?;
    bind_private(&dir, &me.path("root"))?;
    me.mount(&dir)?;
    let (started, out) = sh(&format!("podman start {c}"));
    if !started {
        return Err(format!("podman start {c}: {out}"));
    }
    Ok(())
}

/// Power loss of `v`'s storage under its dead node (see the module docs);
/// the crash's counters.
pub fn machine_crash(v: ValidatorId, discard: Discard) -> Result<CrashStats, String> {
    let me = Instance { v };
    let dir = me.mount_dir()?;
    // Pages the node dirtied (e.g. through a write map) and the kernel has
    // not written back yet reach LazyFS first, as un-synced writes.
    sh(&format!("sync -f {}", dir.display()));
    let reply = me.ctl(&format!("crash {}", crash_args(discard)))?;
    let stats: CrashStats =
        serde_json::from_value(reply["stats"].clone()).map_err(|e| e.to_string())?;
    // LazyFS exits right after replying.
    for _ in 0..300 {
        if !me.running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if me.running() {
        return Err(format!("{v} lazyfs did not exit after the crash"));
    }
    unmount(&dir)?;
    me.mount(&dir)?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_commands_and_stats_match_the_patch() {
        assert_eq!(crash_args(Discard::All), "0 0");
        assert_eq!(
            crash_args(Discard::Subset {
                seed: 7,
                keep_permille: 1500
            }),
            "1000 7"
        );
        let s: CrashStats = serde_json::from_str(
            r#"{"dirty_files":1,"dirty_pages":64,"kept_pages":31,"reverted_pages":33,
                "reverted_sizes":0,"truncated_bytes":0,"undo_errors":0,
                "injected_errors":0,"early_writebacks":0}"#,
        )
        .unwrap();
        assert!(s.discarded() && !CrashStats::default().discarded());
        let i = Instance {
            v: ValidatorId::new(3).unwrap(),
        };
        assert_eq!(
            i.path("faults.fifo"),
            Path::new("/run/lazyfs/v3/faults.fifo")
        );
    }
}
