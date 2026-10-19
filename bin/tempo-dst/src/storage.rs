// SPDX-License-Identifier: GPL-2.0

//! Storage faults (`storage_faults=true`): the node's datadir on LazyFS, and
//! the nemesis side of driving it.
//!
//! [LazyFS](https://github.com/dsrhaslab/lazyfs) (pinned and patched in
//! `nix/lazyfs.nix`, `nix/lazyfs/bedrock.patch`) is a FUSE file system that
//! keeps written data in its own page cache until the application syncs the
//! file, so a power loss can drop it. Mounted over the datadir volume's
//! backing directory, which it reaches through a private bind mount made
//! first (`/run/lazyfs/root`), so compose, `podman start` and E4's re-execute
//! are unchanged.
//!
//! ```text
//! tempo-dst storage-attach        # warmup: move the node's datadir onto LazyFS
//! tempo-dst storage-ctl <cmd...>  # one control command, prints the reply
//! ```
//!
//! Control commands (the patch's, one line in, one JSON line out, over
//! LazyFS's fault FIFOs; see [`Control`]): `stats`; `crash <keep_permille>
//! <seed>`; `torn-op <file> <parts> <persist> <occurrence>` and `torn-seq
//! <file> <persist> <occurrence>`, which arm LazyFS's own torn-write faults.
//!
//! A machine crash ([`machine_crash`]): with the node already dead, flush the
//! kernel's dirty pages of the mount to LazyFS (they were volatile too), have
//! LazyFS write the drawn subset of its un-synced blocks to the backing files
//! and exit (the rest dies with it), unmount (dropping every kernel cache of
//! the old mount), and mount a fresh LazyFS. The node then reopens cold.
//! An armed torn write that fires kills LazyFS itself (after persisting part
//! of the write, or of the group of writes): the crash then only remounts.

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

use crate::common::{self, sh, NODE_CONTAINER, OUT_DIR};

/// A datadir file a torn write can target: files every run writes, at paths
/// fixed for runs below block 500,000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TornFile {
    /// MDBX's datafile (written back from its write map).
    Mdbx,
    /// The headers static file, its offsets, and the change-set static files.
    Headers,
    HeadersOffsets,
    AccountChangeSets,
    StorageChangeSets,
}

impl TornFile {
    /// Every target, in draw order.
    pub const ALL: [TornFile; 5] = [
        TornFile::Mdbx,
        TornFile::Headers,
        TornFile::HeadersOffsets,
        TornFile::AccountChangeSets,
        TornFile::StorageChangeSets,
    ];

    /// The path under the datadir.
    pub fn path(self) -> &'static str {
        match self {
            TornFile::Mdbx => "db/mdbx.dat",
            TornFile::Headers => "static_files/static_file_headers_0_499999",
            TornFile::HeadersOffsets => "static_files/static_file_headers_0_499999.off",
            TornFile::AccountChangeSets => "static_files/static_file_account-change-sets_0_499999",
            TornFile::StorageChangeSets => "static_files/static_file_storage-change-sets_0_499999",
        }
    }
}

/// A torn write, armed in LazyFS (its `torn-op` and `torn-seq` faults). When
/// it fires, LazyFS writes the persisted part to disk and kills itself: every
/// other un-synced write is lost, as in a machine crash. `persist` is a bit
/// set: bit `i` stands for part (or write) `i + 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum Torn {
    /// The `occurrence`-th write to `file` is split into `parts` equal parts;
    /// only those in `persist` reach the disk.
    Op {
        file: TornFile,
        parts: u32,
        persist: u32,
        occurrence: u32,
    },
    /// Of the `occurrence`-th run of writes to `file` without an `fsync`,
    /// only the writes in `persist` reach the disk (possibly out of order);
    /// it fires at the last of them.
    Seq {
        file: TornFile,
        persist: u32,
        occurrence: u32,
    },
}

/// `1,3` for bits 0 and 2.
fn persist_list(mask: u32) -> String {
    (0..32)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| (i + 1).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

impl Torn {
    /// The patch's command for this fault (`torn-op ...`, `torn-seq ...`).
    fn command(self) -> String {
        let at = |f: TornFile| root().join(f.path()).display().to_string();
        match self {
            Torn::Op {
                file,
                parts,
                persist,
                occurrence,
            } => format!(
                "torn-op {} {parts} {} {occurrence}",
                at(file),
                persist_list(persist)
            ),
            Torn::Seq {
                file,
                persist,
                occurrence,
            } => format!(
                "torn-seq {} {} {occurrence}",
                at(file),
                persist_list(persist)
            ),
        }
    }
}

/// Which un-synced writes a crash discards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum Discard {
    /// Every un-synced write is lost.
    All,
    /// Each un-synced block (and each file's un-synced size) survives with
    /// probability `keep_permille / 1000`.
    Subset { seed: u64, keep_permille: u32 },
}

impl Discard {
    /// The patch's `crash` arguments: `<keep_permille> <seed>`.
    fn to_command(self) -> String {
        match self {
            Discard::All => "0 0".into(),
            Discard::Subset {
                seed,
                keep_permille,
            } => format!("{} {seed}", keep_permille.min(1000)),
        }
    }
}

/// One control command of the LazyFS patch (`nix/lazyfs/bedrock.patch`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Liveness probe.
    Stats,
    /// Write the discard's surviving share of the un-synced blocks to the
    /// backing files and exit; the rest is lost.
    Crash(Discard),
    /// Arm a torn write.
    Torn(Torn),
}

impl Control {
    /// The command as the patch reads it (after `bedrock <id> `).
    fn line(self) -> String {
        match self {
            Control::Stats => "stats".into(),
            Control::Crash(d) => format!("crash {}", d.to_command()),
            Control::Torn(t) => t.command(),
        }
    }

    /// Parses `tempo-dst storage-ctl` arguments: `stats`, `crash all`,
    /// `crash subset <seed> <keep_permille>`, or a torn write as JSON (its
    /// plan form, e.g. `{"mode":"op","file":"headers","parts":3,"persist":5,
    /// "occurrence":2}`).
    pub fn parse(words: &[&str]) -> Result<Control, String> {
        let num = |w: &str| w.parse::<u64>().map_err(|e| format!("{w}: {e}"));
        match words {
            ["stats"] => Ok(Control::Stats),
            ["crash", "all"] => Ok(Control::Crash(Discard::All)),
            ["crash", "subset", seed, keep] => {
                let keep_permille = keep.parse::<u32>().map_err(|e| format!("{keep}: {e}"))?;
                if keep_permille > 1000 {
                    return Err(format!("{keep_permille} > 1000 permille"));
                }
                Ok(Control::Crash(Discard::Subset {
                    seed: num(seed)?,
                    keep_permille,
                }))
            }
            ["torn", json] => serde_json::from_str(json)
                .map(Control::Torn)
                .map_err(|e| format!("torn write {json}: {e}")),
            _ => Err(format!("unknown control command: {}", words.join(" "))),
        }
    }
}

/// Counters of one machine crash, as LazyFS reports them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Stats {
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
    /// An armed torn write fired: LazyFS had already crashed itself, keeping
    /// part of one write (or group) and discarding every other un-synced
    /// write (the counters above are then not known).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub torn_fired: bool,
}

impl Stats {
    /// Whether the crash discarded anything.
    pub fn discarded(&self) -> bool {
        self.torn_fired || self.reverted_pages + self.reverted_sizes > 0
    }
}

/// LazyFS's page cache, preallocated at mount. It holds every un-synced
/// block until the node syncs it (and clean blocks until evicted); when it is
/// full, LRU eviction writes a dirty block back early (a state Linux
/// writeback can also reach).
const CACHE_SIZE: &str = "128mb";

const RUN_DIR: &str = "/run/lazyfs";

fn run_path(name: &str) -> PathBuf {
    Path::new(RUN_DIR).join(name)
}

/// Private bind mount of the backing directory, made before LazyFS covers
/// it: LazyFS's `subdir` reaches the real files through it.
fn root() -> PathBuf {
    run_path("root")
}

/// The mounted directory (the node volume's backing directory), written by
/// `storage-attach`.
fn mount_file() -> PathBuf {
    run_path("mount")
}

/// Log of every LazyFS instance; under `/bedrock/out` so the driver collects
/// it.
const LOG: &str = "lazyfs.log";

/// How long a control command may take (a crash writes kept blocks first).
const CTL_TIMEOUT: Duration = Duration::from_secs(120);

/// Sends one control command; the reply's JSON on success.
pub fn ctl(control: Control) -> Result<Value, String> {
    let cmd = control.line();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let id = format!(
        "{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    // Open the reply FIFO first (non-blocking: LazyFS holds it open); a
    // missing reader of the command FIFO (ENXIO) means LazyFS is not running.
    let mut done = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(run_path("done.fifo"))
        .map_err(|e| format!("lazyfs reply fifo: {e}"))?;
    std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(run_path("faults.fifo"))
        .and_then(|mut f| f.write_all(format!("bedrock {id} {cmd}\n").as_bytes()))
        .map_err(|e| format!("lazyfs fault fifo: {e}"))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = std::time::Instant::now() + CTL_TIMEOUT;
    while std::time::Instant::now() < deadline {
        match done.read(&mut chunk) {
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(format!("lazyfs reply fifo: {e}")),
        }
        // Earlier commands' replies nobody read may come first.
        for line in String::from_utf8_lossy(&buf).lines() {
            if let Some(reply) = line.strip_prefix(&format!("{id} ")) {
                let v: Value = serde_json::from_str(reply).map_err(|e| format!("{e}: {reply}"))?;
                return if v["ok"] == true {
                    Ok(v)
                } else {
                    Err(format!("lazyfs {cmd}: {}", v["error"]))
                };
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(format!("lazyfs {cmd}: no reply in {CTL_TIMEOUT:?}"))
}

/// Whether a LazyFS process reads its command FIFO: opening it for writing
/// without a reader fails with `ENXIO`.
fn running() -> Result<bool, String> {
    match std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(run_path("faults.fifo"))
    {
        Ok(_) => Ok(true),
        Err(e) if e.raw_os_error() == Some(nix::errno::Errno::ENXIO as i32) => Ok(false),
        Err(e) => Err(format!("lazyfs fault fifo: {e}")),
    }
}

/// Whether `dir` is a LazyFS mount point.
fn mounted(dir: &Path) -> Result<bool, String> {
    let mounts = std::fs::read_to_string("/proc/self/mounts")
        .map_err(|e| format!("/proc/self/mounts: {e}"))?;
    Ok(mounts.lines().any(|l| {
        let mut f = l.split(' ');
        f.next() == Some("lazyfs") && f.next() == Some(&*dir.to_string_lossy())
    }))
}

/// Starts LazyFS over `dir` and waits until it answers.
fn mount(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(OUT_DIR).map_err(|e| e.to_string())?;
    let config = run_path("lazyfs.toml");
    // Single-threaded (-s); the only clock reads are file times, which come
    // from the guest's emulated clock.
    std::fs::write(
        &config,
        format!(
            "[faults]\nfifo_path=\"{}\"\nfifo_path_completed=\"{}\"\n\
             [cache]\napply_eviction=true\n\
             [cache.simple]\ncustom_size=\"{CACHE_SIZE}\"\nblocks_per_page=1\n\
             [filesystem]\nlog_all_operations=false\nlogfile=\"\"\n",
            run_path("faults.fifo").display(),
            run_path("done.fifo").display(),
        ),
    )
    .map_err(|e| e.to_string())?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(Path::new(OUT_DIR).join(LOG))
        .map_err(|e| e.to_string())?;
    let mut cmd = Command::new("lazyfs");
    cmd.arg(dir)
        .arg("--config-path")
        .arg(&config)
        .args(["-o", "allow_other", "-o", "modules=subdir"])
        .arg("-o")
        .arg(format!("subdir={}", root().display()))
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
    cmd.spawn().map_err(|e| format!("spawn lazyfs: {e}"))?;
    // Until the mount is live and the FIFO thread answers, a failed probe
    // only means "not yet"; the last one explains a timeout.
    let mut last = String::from("not mounted");
    for _ in 0..300 {
        if mounted(dir)? {
            match ctl(Control::Stats) {
                Ok(_) => return Ok(()),
                Err(e) => last = e,
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "lazyfs did not come up on {}: {last}",
        dir.display()
    ))
}

fn mount_dir() -> Result<PathBuf, String> {
    std::fs::read_to_string(mount_file())
        .map(|s| PathBuf::from(s.trim()))
        .map_err(|e| format!("{}: {e} (storage-attach not run?)", mount_file().display()))
}

/// Unmounts the LazyFS at `dir` (its process already exited).
#[cfg(not(target_os = "linux"))]
fn unmount(dir: &Path) -> Result<(), String> {
    Err(format!("lazyfs needs Linux ({})", dir.display()))
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
    if mounted(dir)? {
        return Err(format!("{} still mounted", dir.display()));
    }
    Ok(())
}

/// Arms a torn write; it fires on the matching write, if one comes.
pub fn arm_torn(torn: Torn) -> Result<(), String> {
    ctl(Control::Torn(torn)).map(drop)
}

/// Power loss under the dead node: see the module docs. `torn_armed`: a torn
/// write was armed, so LazyFS may already be gone (it fired); otherwise a
/// dead LazyFS is an error. Returns the crash's counters.
pub fn machine_crash(discard: Discard, torn_armed: bool) -> Result<Stats, String> {
    let dir = mount_dir()?;
    if torn_armed && !running()? {
        unmount(&dir)?;
        mount(&dir)?;
        return Ok(Stats {
            torn_fired: true,
            ..Stats::default()
        });
    }
    // Pages the node dirtied through its write map and the kernel has not
    // written back yet go to LazyFS first, as un-synced writes.
    let (synced, out) = sh(&format!("sync -f {}", dir.display()));
    if !synced {
        return Err(format!("sync -f {}: {out}", dir.display()));
    }
    let reply = ctl(Control::Crash(discard))?;
    let stats: Stats = serde_json::from_value(reply["stats"].clone())
        .map_err(|e| format!("crash stats {}: {e}", reply["stats"]))?;
    // LazyFS exits right after replying.
    let mut exited = false;
    for _ in 0..300 {
        if !running()? {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !exited {
        return Err("lazyfs did not exit after the crash".into());
    }
    unmount(&dir)?;
    mount(&dir)?;
    Ok(stats)
}

/// Whether the node container is running.
pub fn node_running() -> Result<bool, String> {
    let (ok, out) = sh(&format!(
        "podman inspect {NODE_CONTAINER} --format '{{{{.State.Running}}}}'"
    ));
    match (ok, out.trim()) {
        (true, "true") => Ok(true),
        (true, "false") => Ok(false),
        _ => Err(format!("podman inspect {NODE_CONTAINER}: {out}")),
    }
}

/// Binds `dir` privately at [`root`], so the LazyFS mount over `dir` does not
/// propagate to it.
#[cfg(target_os = "linux")]
fn bind_root(dir: &Path) -> Result<(), String> {
    use nix::mount::{mount, MsFlags};
    std::fs::create_dir_all(root()).map_err(|e| e.to_string())?;
    mount(
        Some(dir),
        &root(),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| format!("bind {}: {e}", dir.display()))?;
    mount(
        None::<&str>,
        &root(),
        None::<&str>,
        MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| format!("make-private {}: {e}", root().display()))
}

#[cfg(not(target_os = "linux"))]
fn bind_root(dir: &Path) -> Result<(), String> {
    Err(format!("lazyfs needs Linux ({})", dir.display()))
}

/// Warmup step (before the checkpoint): kills the node, mounts LazyFS over
/// its datadir volume, and starts it again. Everything on disk at attach is
/// durable (the page cache is the guest's RAM-backed root). SIGKILL, not a
/// graceful stop: reth's shutdown panic (the WorkerMap self-join, see
/// regressions/known-fixes) would otherwise reach every branch's E1, whose
/// log follower replays the container's whole journal.
pub fn attach() -> Result<(), String> {
    let (ok, source) = sh(&format!(
        "podman inspect {NODE_CONTAINER} --format '{{{{range .Mounts}}}}{{{{if eq .Destination \"/data\"}}}}{{{{.Source}}}}{{{{end}}}}{{{{end}}}}'"
    ));
    let dir = PathBuf::from(source.trim());
    if !ok || !dir.is_absolute() {
        return Err(format!("no /data volume on {NODE_CONTAINER}: {source}"));
    }
    let (killed, out) = sh(&format!(
        "podman kill -s KILL {NODE_CONTAINER} && podman wait {NODE_CONTAINER}"
    ));
    if !killed {
        return Err(format!("podman kill: {out}"));
    }
    std::fs::create_dir_all(RUN_DIR).map_err(|e| e.to_string())?;
    std::fs::write(mount_file(), dir.to_string_lossy().as_bytes()).map_err(|e| e.to_string())?;
    bind_root(&dir)?;
    mount(&dir)?;
    let (started, out) = sh(&format!("podman start {NODE_CONTAINER}"));
    if !started {
        return Err(format!("podman start: {out}"));
    }
    for _ in 0..240 {
        if common::head_number().is_ok() {
            eprintln!("node on lazyfs at {}", dir.display());
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("node did not answer RPC after moving onto lazyfs".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_forms_are_unchanged() {
        // The plan format (scenarios, golden planner cases) predates LazyFS.
        let d = Discard::Subset {
            seed: 7,
            keep_permille: 500,
        };
        assert_eq!(
            serde_json::to_string(&d).unwrap(),
            r#"{"mode":"subset","seed":7,"keep_permille":500}"#
        );
        assert_eq!(
            serde_json::to_string(&Discard::All).unwrap(),
            r#"{"mode":"all"}"#
        );
        let t = Torn::Op {
            file: TornFile::Headers,
            parts: 3,
            persist: 5,
            occurrence: 2,
        };
        assert_eq!(
            serde_json::to_string(&t).unwrap(),
            r#"{"mode":"op","file":"headers","parts":3,"persist":5,"occurrence":2}"#
        );
        assert_eq!(d.to_command(), "500 7");
        assert_eq!(Discard::All.to_command(), "0 0");
    }

    #[test]
    fn control_commands_round_trip() {
        for (words, line) in [
            ("stats", "stats"),
            ("crash all", "crash 0 0"),
            ("crash subset 7 500", "crash 500 7"),
            (
                r#"torn {"mode":"op","file":"headers","parts":3,"persist":5,"occurrence":2}"#,
                "torn-op /run/lazyfs/root/static_files/static_file_headers_0_499999 3 1,3 2",
            ),
            (
                r#"torn {"mode":"seq","file":"mdbx","persist":10,"occurrence":1}"#,
                "torn-seq /run/lazyfs/root/db/mdbx.dat 2,4 1",
            ),
        ] {
            let w: Vec<&str> = match words.strip_prefix("torn ") {
                Some(json) => vec!["torn", json],
                None => words.split(' ').collect(),
            };
            assert_eq!(Control::parse(&w).unwrap().line(), line);
        }
        assert!(Control::parse(&["crash", "subset", "7", "1001"]).is_err());
        assert!(Control::parse(&["torn", "{}"]).is_err());
        assert!(Control::parse(&["bogus"]).is_err());
    }

    #[test]
    fn stats_parse_the_patch_reply() {
        let s: Stats = serde_json::from_str(
            r#"{"dirty_files":1,"dirty_pages":64,"kept_pages":31,"reverted_pages":33,
                "reverted_sizes":0,"truncated_bytes":0,"undo_errors":0}"#,
        )
        .unwrap();
        assert!(s.discarded());
        assert!(!Stats::default().discarded());
    }
}
