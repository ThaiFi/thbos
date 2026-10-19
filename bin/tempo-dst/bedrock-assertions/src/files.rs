// SPDX-License-Identifier: GPL-2.0

//! Per-writer assertion files, live forwarding, and the seed's ordered merge.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

/// Directory containing one JSONL file per assertion writer.
pub const DIR: &str = "/bedrock/assertions";
const OFFSETS: &str = "/bedrock/in/assertion-offsets.json";
/// The merged records for a finalized seed.
pub const MERGED: &str = "/bedrock/out/assertions.jsonl";
/// What `progress` has reported so far (per-file offsets).
const PROGRESS_STATE: &str = "/bedrock/in/progress-offsets.json";
/// Where `progress` leaves the records it reports.
pub const PROGRESS_OUT: &str = "/bedrock/out/progress.jsonl";

fn files(dir: &Path) -> io::Result<BTreeMap<String, (u64, PathBuf)>> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".jsonl") && entry.file_type()?.is_file() {
            out.insert(name, (entry.metadata()?.len(), entry.path()));
        }
    }
    Ok(out)
}

/// Records each writer's current byte offset before a seed starts.
pub fn snapshot() -> io::Result<()> {
    let offsets: BTreeMap<_, _> = files(Path::new(DIR))?
        .into_iter()
        .map(|(name, (len, _))| (name, len))
        .collect();
    let _ = fs::remove_file(PROGRESS_STATE);
    fs::write(OFFSETS, serde_json::to_vec(&offsets)?)
}

/// The complete new lines of every writer's file past `offsets` (in file
/// name order, each file's in order), and the offsets after them.
fn new_records(
    dir: &Path,
    offsets: &BTreeMap<String, u64>,
) -> io::Result<(String, BTreeMap<String, u64>)> {
    let mut out = String::new();
    let mut next = offsets.clone();
    for (name, (len, path)) in files(dir)? {
        let offset = offsets
            .get(&name)
            .copied()
            .filter(|n| *n <= len)
            .unwrap_or(0);
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(len - offset)
            .read_to_end(&mut bytes)?;
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        out.push_str(&String::from_utf8_lossy(&bytes[..complete]));
        next.insert(name, offset + complete as u64);
    }
    Ok((out, next))
}

/// The `progress` hook: the run's assertion records written since the
/// previous call (since `start` at first) into [`PROGRESS_OUT`], for the
/// driver to observe mid-run. Its state lives in the guest, so a fork of a
/// checkpoint continues from where its parent's last call left off.
pub fn progress() -> io::Result<()> {
    let state = fs::read(PROGRESS_STATE).or_else(|_| fs::read(OFFSETS))?;
    let offsets: BTreeMap<String, u64> = serde_json::from_slice(&state)?;
    let (records, next) = new_records(Path::new(DIR), &offsets)?;
    fs::write(PROGRESS_OUT, records)?;
    fs::write(PROGRESS_STATE, serde_json::to_vec(&next)?)
}

fn timestamp(line: &str, fallback: u64) -> u64 {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|v| {
            v.get("Always")
                .or_else(|| v.get("Sometimes"))
                .and_then(|data| data.get("timestamp_unix_nano"))
                .and_then(Value::as_u64)
        })
        .filter(|t| *t > 0)
        .unwrap_or(fallback)
}

fn unix_nano(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn ordered(lines: Vec<(String, usize, String, u64)>) -> String {
    let mut lines = lines;
    lines.sort_by(|a, b| (a.3, &a.0, a.1).cmp(&(b.3, &b.0, b.1)));
    lines
        .into_iter()
        .map(|(_, _, line, _)| format!("{line}\n"))
        .collect()
}

fn merge(dir: &Path, offsets: &BTreeMap<String, u64>) -> io::Result<String> {
    let mut lines = Vec::new();
    for (name, (len, path)) in files(dir)? {
        let offset = offsets
            .get(&name)
            .copied()
            .filter(|n| *n <= len)
            .unwrap_or(0);
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let data = String::from_utf8_lossy(&bytes);
        let fallback = unix_nano(file.metadata()?.modified()?);
        for (index, line) in data.lines().enumerate() {
            lines.push((
                name.clone(),
                index,
                line.to_owned(),
                timestamp(line, fallback),
            ));
        }
    }
    Ok(ordered(lines))
}

/// Merges records written since the seed snapshot in timestamp order.
pub fn merge_seed() -> io::Result<()> {
    let offsets = serde_json::from_slice(&fs::read(OFFSETS)?)?;
    // Give the monitor time to record final container exits and the live
    // forwarder time to publish finalizer records before collecting them.
    std::thread::sleep(Duration::from_secs(2));
    fs::write(MERGED, merge(Path::new(DIR), &offsets)?)?;
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Cursor {
    offset: u64,
    pending: Vec<u8>,
    index: usize,
}

fn read_new(
    dir: &Path,
    cursors: &mut BTreeMap<String, Cursor>,
) -> io::Result<Vec<(String, usize, String, u64)>> {
    read_files(files(dir)?, cursors)
}

fn read_files(
    writers: BTreeMap<String, (u64, PathBuf)>,
    cursors: &mut BTreeMap<String, Cursor>,
) -> io::Result<Vec<(String, usize, String, u64)>> {
    let mut lines = Vec::new();
    // Commit cursors only after every writer is read, so a failed batch
    // can be retried without losing its complete or partial records.
    let mut next = cursors.clone();
    for (name, (len, path)) in writers {
        let cursor = next.entry(name.clone()).or_default();
        if len < cursor.offset {
            *cursor = Cursor::default();
        }
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(cursor.offset))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        cursor.offset += bytes.len() as u64;
        cursor.pending.extend(bytes);
        while let Some(end) = cursor.pending.iter().position(|b| *b == b'\n') {
            let line = String::from_utf8_lossy(&cursor.pending[..end]).into_owned();
            cursor.pending.drain(..=end);
            lines.push((
                name.clone(),
                cursor.index,
                line.clone(),
                timestamp(&line, unix_nano(SystemTime::now())),
            ));
            cursor.index += 1;
        }
    }
    *cursors = next;
    Ok(lines)
}

/// Forwards complete writer records to stdout, retrying read failures.
/// Output errors stop forwarding and are returned to the caller.
pub fn forward() -> io::Result<()> {
    forward_to(Path::new(DIR), &mut io::stdout())
}

fn forward_to(dir: &Path, sink: &mut impl Write) -> io::Result<()> {
    let mut cursors = BTreeMap::new();
    let mut pending = Vec::new();
    loop {
        match read_new(dir, &mut cursors) {
            Ok(lines) => pending.extend(lines),
            Err(e) => eprintln!("assertion forwarder: {e}"),
        }
        // Give other writers half a second to publish nearby timestamps.
        let cutoff = unix_nano(SystemTime::now()).saturating_sub(500_000_000);
        let (ready, later) = pending.into_iter().partition(|line| line.3 <= cutoff);
        pending = later;
        let output = ordered(ready);
        if !output.is_empty() {
            sink.write_all(output.as_bytes())?;
            sink.flush()?;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_only_seed_records_in_timestamp_order() {
        let dir = std::env::temp_dir().join(format!(
            "bedrock-assertions-{}-{}",
            std::process::id(),
            unix_nano(SystemTime::now())
        ));
        fs::create_dir(&dir).unwrap();
        let a = dir.join("a.jsonl");
        let b = dir.join("b.jsonl");
        fs::write(&a, "warmup\n").unwrap();
        let offsets = BTreeMap::from([("a.jsonl".to_owned(), 7)]);
        fs::write(&a, "warmup\n{\"Always\":{\"timestamp_unix_nano\":30}}\n").unwrap();
        fs::write(&b, "{\"Sometimes\":{\"timestamp_unix_nano\":20}}\n").unwrap();
        let merged = merge(&dir, &offsets).unwrap();
        assert_eq!(
            merged,
            concat!(
                "{\"Sometimes\":{\"timestamp_unix_nano\":20}}\n",
                "{\"Always\":{\"timestamp_unix_nano\":30}}\n"
            )
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn progress_reports_complete_new_lines_once() {
        let dir = std::env::temp_dir().join(format!(
            "bedrock-progress-{}-{}",
            std::process::id(),
            unix_nano(SystemTime::now())
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("a.jsonl"), "warm\nx1\nx2").unwrap();
        fs::write(dir.join("b.jsonl"), "y1\n").unwrap();
        let start = BTreeMap::from([("a.jsonl".to_owned(), 5)]);
        let (out, next) = new_records(&dir, &start).unwrap();
        assert_eq!(out, "x1\ny1\n");
        assert_eq!(next["a.jsonl"], 8);
        fs::write(dir.join("a.jsonl"), "warm\nx1\nx2\n").unwrap();
        let (out, _) = new_records(&dir, &next).unwrap();
        assert_eq!(out, "x2\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn forwarder_discovers_files_and_waits_for_complete_lines() {
        let dir = std::env::temp_dir().join(format!(
            "bedrock-forwarder-{}-{}",
            std::process::id(),
            unix_nano(SystemTime::now())
        ));
        fs::create_dir(&dir).unwrap();
        let mut cursors = BTreeMap::new();
        assert!(read_new(&dir, &mut cursors).unwrap().is_empty());
        let path = dir.join("tempo.jsonl");
        fs::write(&path, b"{\"Always\":{\"timestamp_unix_nano\":2}}").unwrap();
        assert!(read_new(&dir, &mut cursors).unwrap().is_empty());
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert_eq!(read_new(&dir, &mut cursors).unwrap()[0].3, 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn read_failure_preserves_all_cursors_and_unfinished_records() {
        let dir = std::env::temp_dir().join(format!(
            "bedrock-read-failure-{}-{}",
            std::process::id(),
            unix_nano(SystemTime::now())
        ));
        fs::create_dir(&dir).unwrap();
        let a = dir.join("a.jsonl");
        let b = dir.join("b.jsonl");
        let first = "{\"Always\":{\"timestamp_unix_nano\":2}}";
        let second = "{\"Always\":{\"timestamp_unix_nano\":3}}";
        let third = "{\"Sometimes\":{\"timestamp_unix_nano\":4}}";
        fs::write(&a, first).unwrap();
        let mut cursors = BTreeMap::new();
        assert!(read_new(&dir, &mut cursors).unwrap().is_empty());
        let before = cursors.clone();
        fs::OpenOptions::new()
            .append(true)
            .open(&a)
            .unwrap()
            .write_all(format!("\n{second}\n").as_bytes())
            .unwrap();
        fs::write(&b, format!("{third}\n")).unwrap();
        // A later writer disappears after discovery, so the earlier writer
        // has been read successfully before this batch fails.
        let writers = files(&dir).unwrap();
        fs::remove_file(&b).unwrap();
        assert_eq!(
            read_files(writers, &mut cursors).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(cursors, before);
        fs::write(&b, format!("{third}\n")).unwrap();
        assert_eq!(
            ordered(read_new(&dir, &mut cursors).unwrap()),
            format!("{first}\n{second}\n{third}\n")
        );
        assert!(read_new(&dir, &mut cursors).unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    struct FailingOutput {
        fail_write: bool,
        bytes: Vec<u8>,
    }

    impl Write for FailingOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn forwarder_returns_write_and_flush_failures() {
        let dir = std::env::temp_dir().join(format!(
            "bedrock-output-failure-{}-{}",
            std::process::id(),
            unix_nano(SystemTime::now())
        ));
        fs::create_dir(&dir).unwrap();
        let record = "{\"Always\":{\"timestamp_unix_nano\":2}}\n";
        fs::write(dir.join("writer.jsonl"), record).unwrap();
        for fail_write in [true, false] {
            let mut sink = FailingOutput {
                fail_write,
                bytes: Vec::new(),
            };
            assert_eq!(
                forward_to(&dir, &mut sink).unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(
                sink.bytes,
                if fail_write {
                    b"".as_slice()
                } else {
                    record.as_bytes()
                }
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
