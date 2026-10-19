// SPDX-License-Identifier: GPL-2.0

//! E9: chain of blocks (<https://antithesis.com/docs/resources/chain-of-blocks/>)
//! over a node's own history.
//!
//! `ChainOfBlocks` (contrib/bedrock-dst/chain) keeps `(length, head)` with
//! `head = keccak256(prev, payload, index)` per append, plus every link in
//! `links[i]`, and logs each append. The oracle rebuilds the chain from the
//! logs (receipts, not state), recomputing every link from its payload, and
//! holds the node's *state* to it:
//!
//! - `E9/chain-link-broken`: in canonical receipt order, an append's index is
//!   not the next one or its link is not `keccak(prev, payload, index)`, i.e.
//!   the node executed an append against the wrong pre-state.
//! - `E9/chain-state-mismatch`: at a checked block B, the stored length, head,
//!   or a link differs from the chain the receipts of blocks `..=B` give.
//! - `E9/chain-shrunk`: the stored length decreased between two checked
//!   canonical blocks.
//! - `E9/chain-not-prefix`: the chain stored at an older block B is not a
//!   prefix of the chain stored at the head (state against state, no receipts).
//! - `E9/chain-entry-lost`: after a restart, the head no longer holds the
//!   chain stored at the block that was finalized before the kill.
//! - `E9/chain-history-changed`: re-reading a pinned finalized block's stored
//!   chain later (across persistence cycles and restarts) gives another value.
//!
//! Coverage: `S/chain-appended` (an append made during the run was checked
//! against state), `S/chain-survived-restart` (the head's length passed its
//! pre-kill length after a restart), `S/chain-history-reread` (a pinned block
//! re-read clean after a restart).
//!
//! Blocks above the persisted frontier may legitimately be rebuilt after a
//! crash: when a synced block's hash changes, the oracle drops the appends of
//! the replaced blocks and re-reads their logs.

use std::collections::BTreeSet;

use alloy_primitives::{keccak256, B256, U256};

use crate::{
    common::Log,
    oracle::{sweep_depth, Chain, DEEP_DEPTHS, SHALLOW_DEPTHS},
    verdict::{finding, Verdict},
};

/// Newest blocks checked per tick; older unchecked blocks are skipped.
const BLOCKS_PER_TICK: u64 = 10;
/// Pinned finalized blocks kept for re-reading (the first is never evicted).
const MAX_PINS: usize = 8;
/// Links compared one by one by `check_once`.
const CHECK_ONCE_MAX_LINKS: u64 = 4096;

const LENGTH_SLOT: B256 = B256::ZERO;
const HEAD_SLOT: B256 = B256::with_last_byte(1);
const LINKS_SLOT: u64 = 2;

/// `Appended(uint256 index, bytes32 payload, bytes32 link)`.
pub fn appended_topic() -> B256 {
    keccak256("Appended(uint256,bytes32,bytes32)")
}

fn word(n: u64) -> [u8; 32] {
    U256::from(n).to_be_bytes()
}

/// `keccak256(abi.encode(prev, payload, index))`, as the contract computes it.
pub fn link(prev: B256, payload: B256, index: u64) -> B256 {
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(prev.as_slice());
    buf[32..64].copy_from_slice(payload.as_slice());
    buf[64..].copy_from_slice(&word(index));
    keccak256(buf)
}

/// Storage slot of `links[index]`.
pub fn link_slot(index: u64) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&word(index));
    buf[32..].copy_from_slice(&word(LINKS_SLOT));
    keccak256(buf)
}

/// The chain a node's state holds at one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stored {
    pub len: u64,
    pub head: B256,
}

/// One append, from its log.
#[derive(Debug, Clone)]
struct Entry {
    block: u64,
    block_hash: String,
    link: B256,
}

/// A finalized block's stored chain.
#[derive(Debug, Clone)]
struct Pin {
    block: u64,
    hash: String,
    stored: Stored,
    /// Restarts before the pin was taken.
    restarts: u32,
}

#[derive(Debug)]
pub struct CobOracle {
    address: String,
    /// The chain rebuilt from canonical logs, in order.
    entries: Vec<Entry>,
    /// Last block whose logs are in `entries`, and its hash.
    synced: Option<(u64, String)>,
    /// Entries at the first sync: appends made before the run.
    initial: Option<usize>,
    /// Last new block checked against state.
    checked: u64,
    /// Stored length at the last checked new block; cleared by a rewind.
    last_len: Option<(u64, u64)>,
    /// Stored length at the head as last read.
    head_len: Option<u64>,
    ticks: u64,
    down: bool,
    restarts: u32,
    /// Stored chain at the latest finalized block.
    finalized: Option<Pin>,
    /// Captured at the last kill: the finalized chain the head must still
    /// hold, and the head's length the chain must grow past.
    pending_lost: Option<Pin>,
    pending_growth: Option<u64>,
    pins: Vec<Pin>,
    pin_cursor: usize,
    /// Failure signatures already reported; the first report is the useful one.
    reported: BTreeSet<&'static str>,
    covered: BTreeSet<&'static str>,
}

impl CobOracle {
    pub fn new(address: &str) -> CobOracle {
        CobOracle {
            address: address.to_lowercase(),
            entries: Vec::new(),
            synced: None,
            initial: None,
            checked: 0,
            last_len: None,
            head_len: None,
            ticks: 0,
            down: false,
            restarts: 0,
            finalized: None,
            pending_lost: None,
            pending_growth: None,
            pins: Vec::new(),
            pin_cursor: 0,
            reported: BTreeSet::new(),
            covered: BTreeSet::new(),
        }
    }

    pub fn on_kill(&mut self) {
        self.down = true;
        self.pending_lost = self.finalized.clone();
        self.pending_growth = self.head_len;
        if let Some(p) = self.finalized.clone() {
            self.pin(p);
        }
    }

    pub fn on_restart(&mut self) {
        self.down = false;
        self.restarts += 1;
    }

    /// All E9 checks for one oracle tick at `head`. A failed RPC (node down or
    /// restarting) ends the tick; the next one resumes.
    pub fn tick(&mut self, chain: &mut impl Chain, head: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        if !self.down {
            let _ = self.step(chain, head, &mut out);
        }
        out
    }

    fn step(
        &mut self,
        chain: &mut impl Chain,
        head: u64,
        out: &mut Vec<Verdict>,
    ) -> Result<(), String> {
        self.sync(chain, head, out)?;
        self.check_blocks(chain, head, out)?;
        self.track_finalized(chain, out)?;
        self.check_durability(chain, head, out)?;
        self.reread_pin(chain, out)?;
        self.ticks += 1;
        Ok(())
    }

    fn fail(&mut self, out: &mut Vec<Verdict>, signature: &'static str, detail: String) {
        if self.reported.insert(signature) {
            out.push(Verdict::Always(false, finding(signature, detail)));
        }
    }

    fn cover(&mut self, out: &mut Vec<Verdict>, signature: &'static str, detail: String) {
        if self.covered.insert(signature) {
            out.push(Verdict::Sometimes(true, finding(signature, detail)));
        }
    }

    fn pin(&mut self, p: Pin) {
        if self.pins.iter().any(|q| q.block == p.block) {
            return;
        }
        if self.pins.len() == MAX_PINS {
            self.pins.remove(1);
        }
        self.pins.push(p);
    }

    /// The chain the logs of blocks `..=block` give.
    fn expected(&self, block: u64) -> Stored {
        let len = self.entries.partition_point(|e| e.block <= block);
        Stored {
            len: len as u64,
            head: len
                .checked_sub(1)
                .map_or(B256::ZERO, |i| self.entries[i].link),
        }
    }

    fn read(&self, chain: &mut impl Chain, slot: B256, block: u64) -> Result<B256, String> {
        chain.storage_word(&self.address, slot, block)
    }

    fn read_stored(&self, chain: &mut impl Chain, block: u64) -> Result<Stored, String> {
        let len = U256::from_be_bytes(self.read(chain, LENGTH_SLOT, block)?.0);
        Ok(Stored {
            len: len.saturating_to(),
            head: self.read(chain, HEAD_SLOT, block)?,
        })
    }

    /// Brings `entries` up to `head`. A synced block whose hash changed (crash
    /// recovery rebuilt it) drops the appends of the replaced blocks first.
    fn sync(
        &mut self,
        chain: &mut impl Chain,
        head: u64,
        out: &mut Vec<Verdict>,
    ) -> Result<(), String> {
        if let Some((n, hash)) = self.synced.clone() {
            if n > head || !same_hash(chain.hash(n)?, &hash) {
                self.rewind(chain, head)?;
            }
        }
        let from = self.synced.as_ref().map_or(0, |(n, _)| n + 1);
        if from > head {
            return Ok(());
        }
        // Hash before logs: if the chain changes in between, the next tick sees
        // the old hash and rewinds.
        let head_hash = chain.hash(head)?.ok_or("no head block")?.to_lowercase();
        for log in chain.logs(&self.address, appended_topic(), from, head)? {
            self.append(log, out);
        }
        self.synced = Some((head, head_hash));
        if self.initial.is_none() {
            self.initial = Some(self.entries.len());
        }
        Ok(())
    }

    fn rewind(&mut self, chain: &mut impl Chain, head: u64) -> Result<(), String> {
        let mut keep = self.entries.len();
        let mut known: Option<(u64, bool)> = None;
        while let Some(e) = keep.checked_sub(1).map(|i| &self.entries[i]) {
            let kept = e.block <= head
                && match known {
                    Some((b, k)) if b == e.block => k,
                    _ => same_hash(chain.hash(e.block)?, &e.block_hash),
                };
            known = Some((e.block, kept));
            if kept {
                break;
            }
            keep -= 1;
        }
        self.entries.truncate(keep);
        self.synced = self.entries.last().map(|e| (e.block, e.block_hash.clone()));
        let fork = self.synced.as_ref().map_or(0, |(n, _)| *n);
        self.checked = self.checked.min(fork);
        self.last_len = None;
        Ok(())
    }

    /// E9/chain-link-broken: the log extends the receipts' chain.
    fn append(&mut self, log: Log, out: &mut Vec<Verdict>) {
        let index = self.entries.len() as u64;
        if log.data.len() != 96 {
            self.fail(
                out,
                "E9/chain-link-broken",
                format!(
                    "block {}: malformed Appended data {:?}",
                    log.block, log.data
                ),
            );
            return;
        }
        let logged_index = U256::from_be_slice(&log.data[..32]);
        let payload = B256::from_slice(&log.data[32..64]);
        let logged = B256::from_slice(&log.data[64..]);
        let prev = self.entries.last().map_or(B256::ZERO, |e| e.link);
        let want = link(prev, payload, index);
        if logged_index != U256::from(index) || logged != want {
            self.fail(
                out,
                "E9/chain-link-broken",
                format!(
                    "block {}: append #{logged_index} (expected #{index}) of payload {payload} \
                     logged link {logged}, keccak(prev {prev}, payload, {index}) = {want}",
                    log.block
                ),
            );
        }
        // Follow the node's chain from here, so one fault is one report.
        self.entries.push(Entry {
            block: log.block,
            block_hash: log.block_hash,
            link: logged,
        });
    }

    /// E9/chain-state-mismatch at `block`: the stored chain, and its last
    /// link, against the receipts. Returns the stored chain and whether it
    /// matched.
    fn check_block(
        &mut self,
        chain: &mut impl Chain,
        block: u64,
        out: &mut Vec<Verdict>,
    ) -> Result<(Stored, bool), String> {
        let got = self.read_stored(chain, block)?;
        let tail = match got.len.checked_sub(1) {
            Some(i) => Some(self.read(chain, link_slot(i), block)?),
            None => None,
        };
        let want = self.expected(block);
        let ok = got == want && tail.is_none_or(|t| t == got.head);
        if !ok {
            self.fail(
                out,
                "E9/chain-state-mismatch",
                format!(
                    "block {block}: stored length {} head {} (links[length-1] {tail:?}); \
                     receipts give length {} head {}",
                    got.len, got.head, want.len, want.head
                ),
            );
        }
        Ok((got, ok))
    }

    /// E9/chain-not-prefix: the chain stored at `block` is a prefix of the
    /// one stored at `head`, by its last link.
    fn check_prefix(
        &mut self,
        chain: &mut impl Chain,
        block: u64,
        stored: Stored,
        head: u64,
        out: &mut Vec<Verdict>,
    ) -> Result<(), String> {
        let Some(i) = stored.len.checked_sub(1) else {
            return Ok(());
        };
        let at_head = self.read(chain, link_slot(i), head)?;
        if at_head != stored.head {
            self.fail(
                out,
                "E9/chain-not-prefix",
                format!(
                    "block {block} stores length {} head {}, but links[{i}] at head {head} is {at_head}",
                    stored.len, stored.head
                ),
            );
        }
        Ok(())
    }

    /// New blocks up to `head`, two older blocks on the trie oracle's depth
    /// sweep, and one swept link at the head.
    fn check_blocks(
        &mut self,
        chain: &mut impl Chain,
        head: u64,
        out: &mut Vec<Verdict>,
    ) -> Result<(), String> {
        if head < self.checked {
            self.checked = head.saturating_sub(1);
            self.last_len = None;
        }
        let first = (self.checked + 1).max(head.saturating_sub(BLOCKS_PER_TICK - 1));
        let older: Vec<u64> = [SHALLOW_DEPTHS, DEEP_DEPTHS]
            .into_iter()
            .filter_map(|range| head.checked_sub(sweep_depth(range, self.ticks)))
            .filter(|b| *b > 0 && *b < first)
            .collect();
        for block in older {
            let (stored, _) = self.check_block(chain, block, out)?;
            self.check_prefix(chain, block, stored, head, out)?;
        }
        for block in first..=head {
            let (stored, ok) = self.check_block(chain, block, out)?;
            if let Some((b, len)) = self.last_len {
                if stored.len < len {
                    self.fail(
                        out,
                        "E9/chain-shrunk",
                        format!(
                            "stored length {len} at block {b}, {} at block {block}",
                            stored.len
                        ),
                    );
                }
            }
            if ok && self.initial.is_some_and(|n| stored.len > n as u64) {
                self.cover(
                    out,
                    "S/chain-appended",
                    format!("block {block}: length {}", stored.len),
                );
            }
            self.last_len = Some((block, stored.len));
            self.checked = block;
            if block == head {
                self.head_len = Some(stored.len);
            }
        }
        // Old links are written once and never touched again: sweep them at
        // the head.
        if let Some(len) = self.head_len.filter(|n| *n > 0) {
            let i = self.ticks.wrapping_mul(0x9e37_79b9) % len;
            let got = self.read(chain, link_slot(i), head)?;
            if let Some(e) = self.entries.get(i as usize) {
                if got != e.link {
                    self.fail(
                        out,
                        "E9/chain-state-mismatch",
                        format!("head {head}: links[{i}] is {got}, receipts give {}", e.link),
                    );
                }
            }
        }
        Ok(())
    }

    /// Snapshots the stored chain at each new finalized block.
    fn track_finalized(
        &mut self,
        chain: &mut impl Chain,
        out: &mut Vec<Verdict>,
    ) -> Result<(), String> {
        let Some((block, hash)) = chain.finalized()? else {
            return Ok(());
        };
        if self.finalized.as_ref().is_some_and(|p| p.block == block)
            || self.synced.as_ref().is_none_or(|(n, _)| block > *n)
        {
            return Ok(());
        }
        let (stored, _) = self.check_block(chain, block, out)?;
        let pin = Pin {
            block,
            hash: hash.to_lowercase(),
            stored,
            restarts: self.restarts,
        };
        if self.pins.is_empty() && stored.len > 0 {
            self.pin(pin.clone());
        }
        self.finalized = Some(pin);
        Ok(())
    }

    /// E9/chain-entry-lost and S/chain-survived-restart after a restart.
    fn check_durability(
        &mut self,
        chain: &mut impl Chain,
        head: u64,
        out: &mut Vec<Verdict>,
    ) -> Result<(), String> {
        if let Some(p) = self.pending_lost.clone().filter(|p| head >= p.block) {
            let len = self.read_stored(chain, head)?.len;
            let kept = match p.stored.len.checked_sub(1) {
                Some(i) => {
                    len >= p.stored.len && self.read(chain, link_slot(i), head)? == p.stored.head
                }
                None => true,
            };
            if !kept {
                self.fail(
                    out,
                    "E9/chain-entry-lost",
                    format!(
                        "finalized block {} stored length {} head {} before the kill; head {head} \
                         after restart {} has length {len} without it",
                        p.block, p.stored.len, p.stored.head, self.restarts
                    ),
                );
            }
            self.pending_lost = None;
        }
        if let (Some(before), Some(now)) = (self.pending_growth, self.head_len) {
            if now > before {
                self.pending_growth = None;
                self.cover(
                    out,
                    "S/chain-survived-restart",
                    format!("length {now} at head {head} passed pre-kill length {before}"),
                );
            }
        }
        Ok(())
    }

    /// E9/chain-history-changed: re-reads one pinned block per tick.
    fn reread_pin(&mut self, chain: &mut impl Chain, out: &mut Vec<Verdict>) -> Result<(), String> {
        if self.pins.is_empty() {
            return Ok(());
        }
        let i = self.pin_cursor % self.pins.len();
        self.pin_cursor += 1;
        let p = self.pins[i].clone();
        if !same_hash(chain.hash(p.block)?, &p.hash) {
            // The finalized block itself was replaced: E3's finding.
            self.pins.remove(i);
            return Ok(());
        }
        let got = self.read_stored(chain, p.block)?;
        if got != p.stored {
            self.fail(
                out,
                "E9/chain-history-changed",
                format!(
                    "block {}: pinned length {} head {} after {} restart(s), now length {} head {} after {}",
                    p.block, p.stored.len, p.stored.head, p.restarts, got.len, got.head, self.restarts
                ),
            );
        } else if self.restarts > p.restarts {
            self.cover(
                out,
                "S/chain-history-reread",
                format!("block {} pinned before restart {}", p.block, p.restarts + 1),
            );
        }
        Ok(())
    }
}

fn same_hash(got: Option<String>, want: &str) -> bool {
    got.is_some_and(|g| g.eq_ignore_ascii_case(want))
}

/// One-shot E9 at `block` (`tempo-dst chain-check`): rebuilds the chain from
/// logs up to `block`, checks the stored chain at every block with an append
/// (and the block before it) against the receipts and as a prefix of the chain
/// at `block`, and every stored link at `block`. Returns a summary line.
pub fn check_once(
    chain: &mut impl Chain,
    address: &str,
    block: u64,
) -> Result<(String, Vec<Verdict>), String> {
    let mut o = CobOracle::new(address);
    let mut out = Vec::new();
    o.sync(chain, block, &mut out)?;
    let mut blocks: BTreeSet<u64> = o
        .entries
        .iter()
        .flat_map(|e| [e.block.saturating_sub(1), e.block])
        .collect();
    blocks.insert(block);
    for b in &blocks {
        let (stored, _) = o.check_block(chain, *b, &mut out)?;
        o.check_prefix(chain, *b, stored, block, &mut out)?;
    }
    let stored = o.read_stored(chain, block)?;
    for i in 0..stored.len.min(CHECK_ONCE_MAX_LINKS) {
        let got = o.read(chain, link_slot(i), block)?;
        if o.entries.get(i as usize).is_none_or(|e| e.link != got) {
            o.fail(
                &mut out,
                "E9/chain-state-mismatch",
                format!("block {block}: links[{i}] is {got}"),
            );
        }
    }
    let summary = format!(
        "block {block}: {} appends from receipts over {} blocks; stored length {} head {}; \
         checked {} blocks and {} links",
        o.entries.len(),
        o.entries
            .iter()
            .map(|e| e.block)
            .collect::<BTreeSet<_>>()
            .len(),
        stored.len,
        stored.head,
        blocks.len(),
        stored.len.min(CHECK_ONCE_MAX_LINKS),
    );
    Ok((summary, out))
}

/// Runs E9 against a live node for `secs` seconds (`tempo-dst chain-watch`),
/// outside Bedrock: an RPC failure after success counts as a kill, the first
/// success after that as a restart. Prints verdicts as they happen.
pub fn watch(chain: &mut impl Chain, address: &str, secs: u64) {
    let mut o = CobOracle::new(address);
    let mut up = true;
    for t in 0..secs {
        match chain.head() {
            Ok(head) => {
                if !up {
                    up = true;
                    o.on_restart();
                    println!("[{t:>4}s] node back at head {head}");
                }
                for v in o.tick(chain, head) {
                    println!("[{t:>4}s] {v:?}");
                }
                if t % 10 == 0 {
                    println!(
                        "[{t:>4}s] head {head}: {} appends, stored length at head {:?}, finalized {:?}, {} pins",
                        o.entries.len(),
                        o.head_len,
                        o.finalized.as_ref().map(|p| (p.block, p.stored.len)),
                        o.pins.len()
                    );
                }
            }
            Err(e) if up => {
                up = false;
                o.on_kill();
                println!("[{t:>4}s] node down ({e})");
            }
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tip20::{BlockRef, Tip20Chain, Transfer},
        trie_ref,
    };
    use alloy_primitives::Address;
    use std::collections::HashMap;

    const ADDR: &str = "0x700b6a60ce7eaaea56f065753d8dcb9653dbad35";

    /// An honest node holding a ChainOfBlocks, with injectable faults.
    #[derive(Default)]
    struct Node {
        /// Block n's hash and payloads; block 0 is genesis.
        blocks: Vec<(String, Vec<B256>)>,
        up: bool,
        finalized: Option<u64>,
        /// Builds so far, so rebuilt blocks get new hashes.
        builds: u64,
        /// Storage words served instead of the honest ones.
        storage: HashMap<(u64, B256), B256>,
        /// (block, position) -> logged (index, link).
        logs: HashMap<(u64, usize), (u64, B256)>,
    }

    impl Node {
        fn new() -> Node {
            let mut n = Node {
                up: true,
                ..Default::default()
            };
            n.push(&[]);
            n
        }

        fn head(&self) -> u64 {
            self.blocks.len() as u64 - 1
        }

        fn push(&mut self, payloads: &[u64]) {
            self.builds += 1;
            let hash = format!("0x{:x}{:04x}", self.blocks.len(), self.builds);
            self.blocks.push((
                hash,
                payloads
                    .iter()
                    .map(|p| B256::from(U256::from(*p)))
                    .collect(),
            ));
        }

        fn grow(&mut self, blocks: usize, per_block: usize) {
            for _ in 0..blocks {
                let base = self.builds * 100;
                let p: Vec<u64> = (0..per_block as u64).map(|i| base + i).collect();
                self.push(&p);
            }
        }

        /// Crash recovery: keep blocks `..=n`, rebuild the rest differently.
        fn rewind(&mut self, n: u64) {
            self.blocks.truncate(n as usize + 1);
        }

        /// Honest (index, link) of every append up to `block`.
        fn chain_at(&self, block: u64) -> Vec<B256> {
            let mut links: Vec<B256> = Vec::new();
            for (_, payloads) in &self.blocks[..=block as usize] {
                for p in payloads {
                    let prev = links.last().copied().unwrap_or_default();
                    links.push(link(prev, *p, links.len() as u64));
                }
            }
            links
        }

        fn honest_word(&self, slot: B256, block: u64) -> B256 {
            let links = self.chain_at(block);
            if slot == LENGTH_SLOT {
                B256::from(U256::from(links.len()))
            } else if slot == HEAD_SLOT {
                links.last().copied().unwrap_or_default()
            } else {
                (0..links.len())
                    .find(|i| link_slot(*i as u64) == slot)
                    .map_or(B256::ZERO, |i| links[i])
            }
        }
    }

    fn down<T>() -> Result<T, String> {
        Err("down".into())
    }

    /// E8 is exercised in `tip20`'s tests; here the token is never readable.
    impl Tip20Chain for Node {
        fn block(&mut self, _: u64) -> Result<Option<BlockRef>, String> {
            Ok(None)
        }
        fn balances(&mut self, _: Address, _: &[Address], _: B256) -> Result<Vec<U256>, String> {
            Err("no token".into())
        }
        fn supply(&mut self, _: Address, _: B256) -> Result<U256, String> {
            Err("no token".into())
        }
        fn transfers(&mut self, _: Address, _: B256) -> Result<Vec<Transfer>, String> {
            Err("no token".into())
        }
    }

    impl Chain for Node {
        fn head(&mut self) -> Result<u64, String> {
            if self.up {
                Ok(Node::head(self))
            } else {
                down()
            }
        }
        fn hash(&mut self, n: u64) -> Result<Option<String>, String> {
            if !self.up {
                return down();
            }
            Ok(self.blocks.get(n as usize).map(|b| b.0.clone()))
        }
        fn finalized(&mut self) -> Result<Option<(u64, String)>, String> {
            Ok(self
                .finalized
                .map(|n| (n, self.blocks[n as usize].0.clone())))
        }
        fn storage(&mut self, _: &str, _: &[u64], _: u64) -> Result<trie_ref::Storage, String> {
            down()
        }
        fn proof(&mut self, _: &str, _: &[u64], _: u64) -> Result<trie_ref::AccountProof, String> {
            down()
        }
        fn multiproof(
            &mut self,
            _: &str,
            _: &[u64],
            _: u64,
        ) -> Result<trie_ref::AccountProof, String> {
            down()
        }
        fn state_root(&mut self, _: u64) -> Result<B256, String> {
            down()
        }
        fn tx_count(&mut self, _: u64) -> Result<u64, String> {
            down()
        }
        fn storage_word(&mut self, address: &str, slot: B256, block: u64) -> Result<B256, String> {
            assert_eq!(address, ADDR);
            if !self.up || block > Node::head(self) {
                return down();
            }
            Ok(self
                .storage
                .get(&(block, slot))
                .copied()
                .unwrap_or_else(|| self.honest_word(slot, block)))
        }
        fn logs(&mut self, _: &str, topic: B256, from: u64, to: u64) -> Result<Vec<Log>, String> {
            assert_eq!(topic, appended_topic());
            if !self.up {
                return down();
            }
            let mut out = Vec::new();
            let (mut prev, mut index) = (B256::ZERO, 0);
            for (b, (hash, payloads)) in self.blocks.iter().enumerate() {
                let b = b as u64;
                for (pos, p) in payloads.iter().enumerate() {
                    let honest = link(prev, *p, index);
                    if (from..=to).contains(&b) {
                        let (i, l) = self.logs.get(&(b, pos)).copied().unwrap_or((index, honest));
                        let mut data = word(i).to_vec();
                        data.extend_from_slice(p.as_slice());
                        data.extend_from_slice(l.as_slice());
                        out.push(Log {
                            block: b,
                            block_hash: hash.clone(),
                            data,
                        });
                    }
                    prev = honest;
                    index += 1;
                }
            }
            Ok(out)
        }
    }

    fn sigs(v: &[Verdict]) -> Vec<(bool, String)> {
        v.iter()
            .map(|v| match v {
                Verdict::Always(ok, f) | Verdict::Sometimes(ok, f) => (*ok, f.signature.clone()),
            })
            .collect()
    }

    fn failures(v: &[Verdict]) -> Vec<String> {
        sigs(v)
            .into_iter()
            .filter(|(ok, s)| !ok && s.starts_with("E9"))
            .map(|(_, s)| s)
            .collect()
    }

    /// Ticks once per block for `blocks` blocks of `per_block` appends.
    fn run(o: &mut CobOracle, n: &mut Node, blocks: usize, per_block: usize) -> Vec<Verdict> {
        let mut out = Vec::new();
        for _ in 0..blocks {
            n.grow(1, per_block);
            let head = Node::head(n);
            out.extend(o.tick(n, head));
        }
        out
    }

    #[test]
    fn link_and_slot_match_solidity() {
        // keccak256(abi.encode(bytes32(0), bytes32(0), uint256(0))), as
        // logged by the deploy's genesis append on a live node.
        assert_eq!(
            link(B256::ZERO, B256::ZERO, 0).to_string(),
            "0x46700b4d40ac5c35af2c22dda2787a91eb567b06c924a8fb8ae9a05b20c08c21"
        );
        // links[0]: keccak256(abi.encode(uint256(0), uint256(2))).
        assert_eq!(
            link_slot(0).to_string(),
            "0xac33ff75c19e70fe83507db0d683fd3465c996598dc972688b7ace676c89077b"
        );
    }

    #[test]
    fn honest_node_passes_and_covers_appends() {
        let mut n = Node::new();
        n.grow(3, 1);
        let mut o = CobOracle::new(ADDR);
        let head = Node::head(&n);
        assert!(o.tick(&mut n, head).is_empty());
        let v = run(&mut o, &mut n, 300, 2);
        assert!(failures(&v).is_empty(), "{v:?}");
        assert!(sigs(&v).contains(&(true, "S/chain-appended".into())));
        assert_eq!(o.entries.len(), 3 + 600);
    }

    #[test]
    fn append_against_stale_state_breaks_the_link() {
        let mut n = Node::new();
        let mut o = CobOracle::new(ADDR);
        run(&mut o, &mut n, 5, 2);
        // The node executes block 7's second append against the head before
        // the first: same index again, linked to the older head.
        n.grow(2, 2);
        let links = n.chain_at(6);
        let stale = link(links[9], B256::from(U256::from(n.builds * 100 + 1)), 10);
        n.logs.insert((7, 1), (10, stale));
        let head = Node::head(&n);
        assert!(failures(&o.tick(&mut n, head)).contains(&"E9/chain-link-broken".into()));
    }

    #[test]
    fn wrong_historical_state_is_found_by_the_depth_sweep() {
        let mut n = Node::new();
        let mut o = CobOracle::new(ADDR);
        run(&mut o, &mut n, 300, 1);
        // After an unwind, the node serves block 200 with block 199's head.
        let old = n.honest_word(HEAD_SLOT, 199);
        n.storage.insert((200, HEAD_SLOT), old);
        let mut v = Vec::new();
        for _ in 0..300 {
            let head = Node::head(&n);
            v.extend(o.tick(&mut n, head));
        }
        // Wrong against the receipts, and not a prefix of the head's chain.
        assert_eq!(
            failures(&v),
            ["E9/chain-state-mismatch", "E9/chain-not-prefix"],
            "{v:?}"
        );
    }

    #[test]
    fn decreasing_length_is_shrunk() {
        let mut n = Node::new();
        let mut o = CobOracle::new(ADDR);
        run(&mut o, &mut n, 5, 1);
        n.grow(2, 1);
        n.storage
            .insert((7, LENGTH_SLOT), B256::from(U256::from(3)));
        let head = Node::head(&n);
        let f = failures(&o.tick(&mut n, head));
        assert!(f.contains(&"E9/chain-shrunk".into()), "{f:?}");
        assert!(f.contains(&"E9/chain-state-mismatch".into()), "{f:?}");
    }

    #[test]
    fn head_state_missing_an_old_link_is_not_a_prefix() {
        let mut n = Node::new();
        let mut o = CobOracle::new(ADDR);
        run(&mut o, &mut n, 100, 1);
        // The latest state lost every old link; history and receipts agree.
        let head = Node::head(&n) + 1;
        n.grow(1, 1);
        for i in 0..100 {
            n.storage.insert((head, link_slot(i)), B256::ZERO);
        }
        let f = failures(&o.tick(&mut n, head));
        assert!(f.contains(&"E9/chain-not-prefix".into()), "{f:?}");
    }

    /// Kill at head 60 with block 40 finalized; recovery unwinds to 50.
    fn crash(o: &mut CobOracle, n: &mut Node) {
        run(o, n, 60, 1);
        n.finalized = Some(40);
        let head = Node::head(n);
        o.tick(n, head);
        o.on_kill();
        n.up = false;
        let head = Node::head(n);
        assert!(o.tick(n, head).is_empty());
        n.rewind(50);
        n.up = true;
        o.on_restart();
    }

    #[test]
    fn rebuilt_unfinalized_blocks_survive_a_restart() {
        let mut n = Node::new();
        let mut o = CobOracle::new(ADDR);
        crash(&mut o, &mut n);
        // Blocks 51.. are rebuilt with other appends (the pool was lost).
        let v = run(&mut o, &mut n, 30, 2);
        assert!(failures(&v).is_empty(), "{v:?}");
        let s = sigs(&v);
        assert!(
            s.contains(&(true, "S/chain-survived-restart".into())),
            "{s:?}"
        );
        assert!(
            s.contains(&(true, "S/chain-history-reread".into())),
            "{s:?}"
        );
        assert_eq!(o.entries.len(), 50 + 60);
    }

    #[test]
    fn finalized_entry_missing_after_restart_is_lost() {
        let mut n = Node::new();
        let mut o = CobOracle::new(ADDR);
        crash(&mut o, &mut n);
        // The new head's state lost entry 39 (finalized block 40's head).
        n.storage.insert((51, link_slot(39)), B256::repeat_byte(7));
        let f = failures(&run(&mut o, &mut n, 1, 1));
        assert!(f.contains(&"E9/chain-entry-lost".into()), "{f:?}");
    }

    #[test]
    fn pinned_history_that_changes_is_reported() {
        let mut n = Node::new();
        let mut o = CobOracle::new(ADDR);
        crash(&mut o, &mut n);
        // After the restart, block 40 is served with a shorter chain.
        n.storage
            .insert((40, LENGTH_SLOT), B256::from(U256::from(30)));
        let f = failures(&run(&mut o, &mut n, 10, 1));
        assert!(f.contains(&"E9/chain-history-changed".into()), "{f:?}");
    }

    #[test]
    fn check_once_on_an_honest_node() {
        let mut n = Node::new();
        n.grow(20, 3);
        let (summary, v) = check_once(&mut n, ADDR, 20).unwrap();
        assert!(v.is_empty(), "{v:?}");
        assert!(summary.contains("60 appends"), "{summary}");
        n.storage.insert((20, link_slot(5)), B256::ZERO);
        let (_, v) = check_once(&mut n, ADDR, 20).unwrap();
        assert!(!failures(&v).is_empty());
    }
}
