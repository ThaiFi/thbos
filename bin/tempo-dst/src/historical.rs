// SPDX-License-Identifier: GPL-2.0

//! Historical RPC oracles: what a node serves about an old block.
//!
//! Our bugs so far (wrong historical proofs after a crash, reth#27615, and
//! bedrock#13-#16) live in the code that serves *old* state from the
//! persisted trie, changesets and in-memory overlays after crashes, unwinds
//! and restarts. E5/E6/E7 cover RawStorage storage proofs; these oracles ask
//! the general historical questions:
//!
//! - **E7h** ([`Differential`], `reference=true`): on blocks both nodes agree
//!   on (same hash at the newest common block, so the same chain below it),
//!   the primary and the reference answer the same. Signatures
//!   `E7/historical-<method>-differs`, and `E7/historical-unavailable` when one
//!   side keeps erroring for [`GRACE_NS`] while the other answers.
//! - **E3h** ([`AcrossRestart`], every run): what the primary served about a
//!   block before a kill, it serves the same after the restart, if it kept the
//!   block (same hash): `E3/historical-changed-across-restart`, and
//!   `E3/historical-unavailable-after-restart` for a read that errors for
//!   [`GRACE_NS`] after the restart.
//!
//! Each tick picks blocks with a draw derived from the run seed and the tick
//! number ([`Draw`], logged to oracle.log). The strata follow
//! tempoxyz/rpc-tester's sampling (its tip range, its near-history window
//! `[head-128, head-8]` across the in-memory/persisted boundary, its
//! log-spaced deep strata), capped to `--rpc.eth-proof-window 256`: in turn
//! tip (depth 1-8), deep (49-250, one of [`DEEP_STRATA`] then a depth in it),
//! near (8-128) and shallow (1-48, as E5/E6), plus a focus block around the
//! most recent kill (from below the primary's persisted watermark at the
//! kill, "Saved range of blocks", to just past its head at the kill: blocks a
//! crash may unwind and the restart re-derives), or around the current
//! watermark before any kill (the next stratum when there is neither).
//!
//! At each block, by block hash (EIP-1898, `requireCanonical`, so a reorg
//! makes a read fail, never answer for another block), the core queries
//! ([`plan`]) are `eth_getBalance` and `eth_getTransactionCount` of a load
//! account or a party of the block's transactions, `eth_getBalance` of a
//! random untouched account, `eth_getCode` and `eth_getStorageAt` of the
//! load's contracts (trie slots, the chain contract's length/head, TIP-20
//! token and pathUSD), an `eth_call` (pathUSD/TIP-20
//! `totalSupply`/`balanceOf`, ChainOfBlocks `length`/`head`), `eth_getProof`
//! account fields (balance, nonce, codeHash, storageHash, proven slot
//! values) of a contract, a load account or a random one (only up to
//! [`PROOF_DEPTH`] below the higher head), `eth_getBlockReceipts`,
//! `eth_getTransactionReceipt` and `debug_traceTransaction` (callTracer,
//! prestateTracer or its diff mode) of a sampled transaction, and
//! `eth_getLogs` over the block and its two parents; the block itself
//! (`eth_getBlockByNumber` with transactions) is compared too. On top,
//! [`EXTENDED_PER_BLOCK`] methods per block are drawn from rpc-tester's
//! method set ([`extended`]: raw header/block/receipts/transaction, block by
//! hash, counts, `trace_*`, `debug_traceBlockByHash`,
//! `reth_getBalanceChangesInBlock`, `eth_feeHistory`, the transaction
//! replayed with `eth_call`/`eth_estimateGas`/`eth_createAccessList` on its
//! parent, `debug_executionWitness`, a missing-hash lookup). Not taken from
//! it: finality tags (the reference follows the primary without its
//! consensus view, so `safe`/`finalized` legitimately differ) and its
//! sync-wait. Only ideas are taken; nothing of it runs or is linked.
//!
//! Cost: E7h reads [`BLOCKS_PER_TICK`] blocks of at most 14 calls each per
//! node per tick (two JSON-RPC batches), plus at most [`PENDING_PER_TICK`]
//! retry of a one-sided error (two calls): at most [`MAX_CALLS`] per node per
//! tick; only an answer that differs or errors costs a re-check of the block
//! hashes (one call per node and block). E3h reads one block per tick while
//! the node runs (at most 15 calls with the head), and after a restart
//! re-reads at most [`SWEEP_PER_TICK`] recorded blocks per tick instead (14
//! calls each, in one batch per block; one block fewer while a retry runs):
//! at most 29.
//!
//! Errors where both nodes fail, and `eth_getProof`'s proof-window error, are
//! not findings; transport errors (the node is down, paused or restarting)
//! end the tick.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use alloy_primitives::{keccak256, Address, U256};
use serde_json::{json, Value};

use crate::{
    common::{self, Config, DstEvent, NODE_CONTAINER},
    verdict::{finding, Verdict},
};

/// Depth strata below the newest common block, after rpc-tester's
/// sampling (`sampling.rs`): its tip range (the newest 8 blocks), E5/E6's
/// shallow range, its near-history window `[head-128, head-8]` (the
/// in-memory to persisted-state boundary) and its log-spaced deep strata,
/// capped to the proof window: one of [`DEEP_STRATA`] is drawn, then a
/// depth inside it.
pub const TIP: (u64, u64) = (1, 8);
pub const SHALLOW: (u64, u64) = (1, 48);
pub const NEAR: (u64, u64) = (8, 128);
pub const DEEP: (u64, u64) = (49, 250);
pub const DEEP_STRATA: [(u64, u64); 3] = [(49, 96), (97, 160), (161, 250)];

/// A depth in [`DEEP`], log-spread over [`DEEP_STRATA`].
fn deep_depth(d: &mut Draw) -> u64 {
    let k = d.below(DEEP_STRATA.len() as u64) as usize;
    d.range(DEEP_STRATA[k])
}
/// `eth_getProof` only this far below the higher head: compose's proof
/// window is 256, and heads move while a tick's batches run.
pub const PROOF_DEPTH: u64 = 200;
/// A pending `eth_getProof` retry is dropped past this depth.
const PROOF_WINDOW: u64 = 240;
/// E3h records `eth_getProof` only this deep, so the record is still inside
/// the window after the restart.
const RESTART_PROOF_DEPTH: u64 = 120;
/// Blocks E7h compares per tick.
pub const BLOCKS_PER_TICK: usize = 2;
/// Methods drawn per block from rpc-tester's set ([`extended`]).
pub const EXTENDED_PER_BLOCK: usize = 2;
/// The same for E3h's recorded blocks.
const RESTART_EXTENDED: usize = 1;
/// One-sided errors retried per tick.
pub const PENDING_PER_TICK: usize = 1;
/// Calls per node per tick in the steady state (no re-checks).
pub const MAX_CALLS: usize = 30;
/// A read that keeps failing on one side this long is a finding.
pub const GRACE_NS: u64 = 30_000_000_000;
/// E3h: blocks recorded before a kill, newest kept.
const RING: usize = 24;
/// E3h: recorded blocks re-read per tick after a restart.
pub const SWEEP_PER_TICK: usize = 2;
/// Focus range after a kill: from this far below the persisted watermark
/// to this far above the head at the kill.
const FOCUS_BELOW_SAVED: u64 = 16;
const FOCUS_ABOVE_KILL: u64 = 4;
/// Focus range before any kill: around the current watermark.
const FOCUS_AROUND_SAVED: u64 = 8;
/// Primary block hashes remembered for `S/historical-after-unwind`.
const HASHES_KEPT: usize = 2048;
/// Draw salts.
const E7H_SALT: u64 = 0x6537_6869_7374_6f72;
const E3H_SALT: u64 = 0x6533_6869_7374_6f72;
/// Characters of each answer in a finding's detail (the full answers go to
/// oracle.log).
const ANSWER_CHARS: usize = 600;

/// One JSON-RPC call.
#[derive(Clone, Debug, PartialEq)]
pub struct Query {
    pub method: &'static str,
    pub params: Value,
}

impl Query {
    fn new(method: &'static str, params: Value) -> Query {
        Query { method, params }
    }
}

/// A node's JSON-RPC, as these oracles ask it.
pub trait HistNode {
    /// One batch: each call's result, or its JSON-RPC error. `Err` when the
    /// request itself fails (the node is down, paused or restarting).
    fn batch(&mut self, calls: &[Query]) -> Result<Vec<Result<Value, String>>, String>;
}

/// The primary (`None`) or another node's RPC.
pub struct RpcHist(pub Option<&'static str>);

impl HistNode for RpcHist {
    fn batch(&mut self, calls: &[Query]) -> Result<Vec<Result<Value, String>>, String> {
        let calls: Vec<(&str, Value)> =
            calls.iter().map(|q| (q.method, q.params.clone())).collect();
        match self.0 {
            Some(url) => common::with_rpc_url(url, || common::rpc_batch(&calls)),
            None => common::rpc_batch(&calls),
        }
    }
}

/// Deterministic draws: splitmix64 over the run seed, a salt and the tick,
/// so a seed's picks are a function of the seed (and logged).
pub struct Draw(u64);

impl Draw {
    pub fn new(seed: u64, salt: u64, tick: u64) -> Draw {
        let mut d = Draw(seed ^ salt);
        d.0 ^= d
            .next()
            .wrapping_add(tick.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        d
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, (lo, hi): (u64, u64)) -> u64 {
        lo + self.below(hi.saturating_sub(lo) + 1)
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        items.get(self.below(items.len() as u64) as usize)
    }
    fn address(&mut self) -> Address {
        let mut b = [0u8; 20];
        for chunk in b.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        Address::from(b)
    }
}

/// A view call: `to`, selector, and whether it takes an account argument.
#[derive(Clone, Debug)]
struct ViewCall {
    to: Address,
    selector: [u8; 4],
    with_account: bool,
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4].try_into().unwrap()
}

/// The load's accounts, contracts (with the slots worth reading) and view
/// calls.
#[derive(Clone, Debug, Default)]
pub struct Targets {
    accounts: Vec<Address>,
    contracts: Vec<(Address, Vec<U256>)>,
    calls: Vec<ViewCall>,
}

impl Targets {
    pub fn of(cfg: &Config) -> Targets {
        let mut t = Targets::default();
        let mut accounts: Vec<Address> = crate::trie_gen::WRITER_ADDRESSES.to_vec();
        accounts.extend(crate::tip20::HOLDERS);
        t.accounts = accounts;
        for trie in cfg.tries() {
            if let Ok(a) = trie.address.parse::<Address>() {
                t.contracts
                    .push((a, trie.slots.iter().map(|s| U256::from(*s)).collect()));
            }
        }
        let path_usd = crate::durable::PATH_USD;
        t.contracts.push((path_usd, Vec::new()));
        let token_calls = |t: &mut Targets, to: Address| {
            for (sig, with_account) in [("totalSupply()", false), ("balanceOf(address)", true)] {
                t.calls.push(ViewCall {
                    to,
                    selector: selector(sig),
                    with_account,
                });
            }
        };
        token_calls(&mut t, path_usd);
        if cfg.tip20 {
            t.contracts.push((crate::tip20::TOKEN, Vec::new()));
            token_calls(&mut t, crate::tip20::TOKEN);
        }
        if let Some(cob) = cfg
            .cob
            .as_ref()
            .and_then(|c| c.address.parse::<Address>().ok())
        {
            t.contracts.push((cob, vec![U256::from(0), U256::from(1)]));
            for sig in ["length()", "head()"] {
                t.calls.push(ViewCall {
                    to: cob,
                    selector: selector(sig),
                    with_account: false,
                });
            }
        }
        t
    }
}

/// A block as both oracles need it.
#[derive(Clone, Debug)]
struct BlockView {
    number: u64,
    hash: String,
    parent: String,
    txs: Vec<TxView>,
}

/// One transaction of a [`BlockView`].
#[derive(Clone, Debug)]
struct TxView {
    hash: String,
    index: u64,
    /// Sender and recipient.
    parties: Vec<Address>,
    /// The transaction as an `eth_call` request (rpc-tester's
    /// `call_request_json`), when it has a plain `to`/`input` form.
    call: Option<Value>,
}

/// The call request rpc-tester replays a transaction as: its sender,
/// recipient, input, value and gas.
fn call_request(tx: &Value) -> Option<Value> {
    let mut req = serde_json::Map::new();
    for k in ["from", "to", "input", "value", "gas"] {
        req.insert(k.into(), tx.get(k).filter(|v| !v.is_null())?.clone());
    }
    Some(Value::Object(req))
}

fn parse_block(v: &Value) -> Option<BlockView> {
    let number = v.get("number")?.as_str()?;
    let number = u64::from_str_radix(number.trim_start_matches("0x"), 16).ok()?;
    let hash = v.get("hash")?.as_str()?.to_lowercase();
    let parent = v
        .get("parentHash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_lowercase();
    let txs = v
        .get("transactions")
        .and_then(Value::as_array)
        .map(|txs| {
            txs.iter()
                .enumerate()
                .filter_map(|(i, tx)| {
                    let hash = tx.get("hash")?.as_str()?.to_lowercase();
                    let parties = ["from", "to"]
                        .iter()
                        .filter_map(|k| tx.get(*k)?.as_str()?.parse().ok())
                        .collect();
                    Some(TxView {
                        hash,
                        index: i as u64,
                        parties,
                        call: call_request(tx),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(BlockView {
        number,
        hash,
        parent,
        txs,
    })
}

fn hex(n: u64) -> String {
    format!("0x{n:x}")
}

fn get_block(n: u64, full: bool) -> Query {
    Query::new("eth_getBlockByNumber", json!([hex(n), full]))
}

const TRACERS: [&str; 3] = ["callTracer", "prestateTracer", "prestateTracer-diff"];

/// The reads at one block (see the module docs); `proof`: whether
/// `eth_getProof` is inside the window.
fn plan(
    targets: &Targets,
    block: &BlockView,
    d: &mut Draw,
    proof: bool,
    extended_methods: usize,
) -> Vec<Query> {
    let at = json!({"blockHash": block.hash, "requireCanonical": true});
    let mut accounts: Vec<Address> = block.txs.iter().flat_map(|t| t.parties.clone()).collect();
    accounts.extend(&targets.accounts);
    let account = d.pick(&accounts).copied().unwrap_or_default();
    let untouched = d.address();
    let mut q = vec![
        Query::new("eth_getBalance", json!([account, at])),
        Query::new("eth_getTransactionCount", json!([account, at])),
        Query::new("eth_getBalance", json!([untouched, at])),
    ];
    let slot_of = |d: &mut Draw| -> Option<(Address, U256)> {
        let (c, slots) = d.pick(&targets.contracts)?;
        let slot = d.pick(slots).copied().unwrap_or(U256::from(d.below(4)));
        Some((*c, slot))
    };
    if let Some((c, _)) = d.pick(&targets.contracts) {
        q.push(Query::new("eth_getCode", json!([c, at])));
    }
    if let Some((c, slot)) = slot_of(d) {
        q.push(Query::new(
            "eth_getStorageAt",
            json!([c, format!("{slot:#x}"), at]),
        ));
    }
    if let Some(call) = d.pick(&targets.calls) {
        let mut data = call.selector.to_vec();
        if call.with_account {
            data.extend_from_slice(account.into_word().as_slice());
        }
        q.push(Query::new(
            "eth_call",
            json!([{"to": call.to, "data": alloy_primitives::Bytes::from(data)}, at]),
        ));
    }
    if proof {
        let (who, keys): (Address, Vec<String>) = match d.below(3) {
            0 => match d.pick(&targets.contracts) {
                Some((c, slots)) => (
                    *c,
                    slots.iter().take(3).map(|s| format!("{s:#x}")).collect(),
                ),
                None => (account, Vec::new()),
            },
            1 => (account, Vec::new()),
            _ => (untouched, Vec::new()),
        };
        q.push(Query::new("eth_getProof", json!([who, keys, at])));
    }
    q.push(Query::new("eth_getBlockReceipts", json!([block.hash])));
    let tx = d.pick(&block.txs).cloned();
    if let Some(TxView { hash: tx, .. }) = &tx {
        q.push(Query::new("eth_getTransactionReceipt", json!([tx])));
        let tracer = match *d.pick(&TRACERS).unwrap() {
            "prestateTracer-diff" => {
                json!({"tracer": "prestateTracer", "tracerConfig": {"diffMode": true}})
            }
            t => json!({"tracer": t}),
        };
        q.push(Query::new("debug_traceTransaction", json!([tx, tracer])));
    }
    q.push(Query::new(
        "eth_getLogs",
        json!([{"fromBlock": hex(block.number.saturating_sub(2).max(1)), "toBlock": hex(block.number)}]),
    ));
    let mut extra = extended(block, tx.as_ref(), d);
    for _ in 0..extended_methods {
        if extra.is_empty() {
            break;
        }
        let i = d.below(extra.len() as u64) as usize;
        q.push(extra.swap_remove(i));
    }
    q
}

/// rpc-tester's (tempoxyz/rpc-tester `a720714`, `RpcTester::test_per_block`
/// and its per-transaction, range and negative tests) methods that [`plan`]'s
/// core set lacks, by block hash where the method takes one; [`plan`] draws
/// [`EXTENDED_PER_BLOCK`] of them per block (E3h: [`RESTART_EXTENDED`]). The transaction's `eth_call`,
/// `eth_estimateGas` and `eth_createAccessList` replay it on its parent's
/// state, as rpc-tester does; the missing-hash lookup is its negative test.
fn extended(block: &BlockView, tx: Option<&TxView>, d: &mut Draw) -> Vec<Query> {
    let h = &block.hash;
    let n = block.number;
    let range = json!({"fromBlock": hex(n.saturating_sub(2).max(1)), "toBlock": hex(n)});
    let missing = format!(
        "0x{:016x}{:016x}{:016x}{:016x}",
        d.next(),
        d.next(),
        d.next(),
        d.next()
    );
    let mut q = vec![
        Query::new("eth_getBlockByHash", json!([h, true])),
        Query::new("eth_getBlockTransactionCountByHash", json!([h])),
        Query::new("eth_getBlockTransactionCountByNumber", json!([hex(n)])),
        Query::new("eth_getUncleCountByBlockHash", json!([h])),
        Query::new("debug_getRawHeader", json!([h])),
        Query::new("debug_getRawBlock", json!([h])),
        Query::new("debug_getRawReceipts", json!([h])),
        Query::new("reth_getBalanceChangesInBlock", json!([h])),
        Query::new("trace_block", json!([h])),
        Query::new("trace_replayBlockTransactions", json!([h, ["stateDiff"]])),
        Query::new(
            "debug_traceBlockByHash",
            json!([h, {"tracer": "callTracer"}]),
        ),
        Query::new(
            "debug_traceBlockByHash",
            json!([h, {"tracer": "prestateTracer"}]),
        ),
        Query::new("trace_filter", json!([range])),
        Query::new(
            "eth_feeHistory",
            json!([hex(3), hex(n), [25.0, 50.0, 75.0]]),
        ),
        Query::new("eth_getBlockByHash", json!([missing, false])),
        Query::new("debug_executionWitness", json!([hex(n)])),
    ];
    if let Some(tx) = tx {
        let t = &tx.hash;
        q.extend([
            Query::new("eth_getTransactionByHash", json!([t])),
            Query::new("eth_getRawTransactionByHash", json!([t])),
            Query::new("debug_getRawTransaction", json!([t])),
            Query::new("trace_transaction", json!([t])),
            Query::new(
                "eth_getTransactionByBlockHashAndIndex",
                json!([h, hex(tx.index)]),
            ),
        ]);
        if let (Some(call), false) = (&tx.call, block.parent.is_empty()) {
            let parent = json!({"blockHash": block.parent, "requireCanonical": true});
            for m in ["eth_call", "eth_estimateGas", "eth_createAccessList"] {
                q.push(Query::new(m, json!([call, parent])));
            }
        }
    }
    q
}

/// An answer pair to report once the block is re-checked: `(number, hash,
/// query, primary, reference)`.
type Candidate = (
    u64,
    String,
    Query,
    Result<Value, String>,
    Result<Value, String>,
);

/// What is compared: `eth_getProof`'s account fields and proven values (the
/// proof nodes are E6's), `debug_executionWitness`'s lists as sets,
/// everything else as served.
fn normalize(method: &str, v: &Value) -> Value {
    if method == "debug_executionWitness" {
        // Sets of trie nodes, codes, keys and headers: order is not part of
        // the answer (rpc-tester compares them structurally too).
        let mut v = v.clone();
        if let Some(o) = v.as_object_mut() {
            for list in o.values_mut().filter_map(Value::as_array_mut) {
                list.sort_by_key(|e| e.to_string());
            }
        }
        return v;
    }
    if method != "eth_getProof" || v.get("storageHash").is_none() {
        return v.clone();
    }
    let storage: Vec<Value> = v
        .get("storageProof")
        .and_then(Value::as_array)
        .map(|s| {
            s.iter()
                .map(|p| json!([p.get("key"), p.get("value")]))
                .collect()
        })
        .unwrap_or_default();
    json!({
        "balance": v.get("balance"),
        "nonce": v.get("nonce"),
        "codeHash": v.get("codeHash"),
        "storageHash": v.get("storageHash"),
        "storage": storage,
    })
}

fn short(s: &str) -> String {
    if s.chars().count() <= ANSWER_CHARS {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(ANSWER_CHARS).collect();
        t.push_str("...");
        t
    }
}

fn answer(r: &Result<Value, String>) -> String {
    match r {
        Ok(v) => v.to_string(),
        Err(e) => format!("error {e}"),
    }
}

/// `eth_getProof`'s "distance to target block exceeds maximum proof
/// window": the block left the window, not a finding.
fn window_error(e: &str) -> bool {
    let e = e.to_lowercase();
    e.contains("proof window") || e.contains("distance to target block")
}

fn is_proof(q: &Query) -> bool {
    q.method == "eth_getProof"
}

/// The block at `n` on `node` still has `hash`: `None` while unreachable.
fn canonical(node: &mut impl HistNode, n: u64, hash: &str) -> Option<bool> {
    Some(hash_at(node, n)?.as_deref() == Some(hash))
}

/// The hash of block `n` on `node` (`Some(None)`: no such block, or an
/// error); `None` while unreachable.
fn hash_at(node: &mut impl HistNode, n: u64) -> Option<Option<String>> {
    let r = node.batch(&[get_block(n, false)]).ok()?;
    Some(
        r.first()
            .and_then(|r| r.as_ref().ok())
            .and_then(|b| b.get("hash")?.as_str().map(str::to_lowercase)),
    )
}

/// Which node a one-sided error came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Primary,
    Reference,
}

/// A read that failed on one side, retried until it answers or
/// [`GRACE_NS`] passes.
#[derive(Clone, Debug)]
struct Pending {
    side: Side,
    query: Query,
    number: u64,
    hash: String,
    since: u64,
    error: String,
    /// The other side's answer (E7h) or the recorded one (E3h).
    expected: String,
}

/// After a kill: the range a restart may re-derive, and the primary's
/// hashes before it.
#[derive(Clone, Debug)]
struct Focus {
    lo: u64,
    hi: u64,
}

fn sometimes(seen: &mut BTreeSet<String>, signature: String, detail: String) -> Option<Verdict> {
    seen.insert(signature.clone())
        .then(|| Verdict::Sometimes(true, finding(&signature, detail)))
}

/// Whether a nemesis event takes the primary down (kill, machine crash,
/// graceful stop), freezes it, or brings it back.
enum NodeEvent {
    Down,
    Pause,
    Up,
}

fn node_event(ev: &DstEvent) -> Option<NodeEvent> {
    if ev.source != "nemesis" || ev.container.as_deref() != Some(NODE_CONTAINER) {
        return None;
    }
    match ev.kind.as_str() {
        "kill" | "down" | "stop" => Some(NodeEvent::Down),
        "pause" => Some(NodeEvent::Pause),
        "restart" | "resume" => Some(NodeEvent::Up),
        _ => None,
    }
}

/// E7h: primary vs reference on historical blocks they agree on.
#[derive(Debug)]
pub struct Differential {
    seed: u64,
    targets: Targets,
    ticks: u64,
    /// The primary's persisted watermark ("Saved range of blocks").
    saved: Option<(u64, String)>,
    focus: Option<Focus>,
    /// Primary hashes seen (sampled blocks and the newest common block).
    hashes: BTreeMap<u64, String>,
    /// [`Differential::hashes`] and the watermark at the last kill: a block
    /// whose hash changed since was re-derived after an unwind.
    before_kill: BTreeMap<u64, String>,
    head: Option<u64>,
    down: bool,
    pending: Vec<Pending>,
    seen: BTreeSet<String>,
    /// The two nodes run different reth engine profiles (Optimized vs Simple).
    /// Then the engine-implementation-dependent methods ([`engine_dependent`],
    /// e.g. `debug_executionWitness`, whose trie-node set differs by engine)
    /// are not a differential: the cluster's own E13 oracle compares state
    /// roots and proofs across engine profiles for the same reason.
    cross_engine: bool,
}

/// Methods whose answer legitimately differs between reth engine profiles, so
/// E7h does not compare them across a cross-engine pair. `debug_executionWitness`
/// returns the trie nodes touched during execution; a different engine (sparse
/// trie vs the simple state root) can include a different node set for the same
/// block and state.
fn engine_dependent(method: &str) -> bool {
    method == "debug_executionWitness"
}

impl Differential {
    pub fn new(seed: u64, targets: Targets) -> Differential {
        Differential {
            seed,
            targets,
            ticks: 0,
            saved: None,
            focus: None,
            hashes: BTreeMap::new(),
            before_kill: BTreeMap::new(),
            head: None,
            down: false,
            pending: Vec::new(),
            seen: BTreeSet::new(),
            cross_engine: false,
        }
    }

    /// Mark the compared pair as running different engine profiles, so
    /// [`engine_dependent`] methods are not treated as a differential.
    pub fn cross_engine(mut self, yes: bool) -> Differential {
        self.cross_engine = yes;
        self
    }

    pub fn on_saved(&mut self, saved: (u64, String)) {
        self.saved = Some(saved);
    }

    pub fn on_event(&mut self, ev: &DstEvent) {
        match node_event(ev) {
            Some(NodeEvent::Down) => {
                self.down = true;
                let head = self.head.unwrap_or(0);
                let saved = self.saved.as_ref().map_or(head, |s| s.0);
                self.focus = Some(Focus {
                    lo: saved.min(head).saturating_sub(FOCUS_BELOW_SAVED).max(1),
                    hi: head + FOCUS_ABOVE_KILL,
                });
                self.before_kill = self.hashes.clone();
                if let Some((n, h)) = &self.saved {
                    self.before_kill.insert(*n, h.clone());
                }
            }
            Some(NodeEvent::Pause) => self.down = true,
            Some(NodeEvent::Up) => self.down = false,
            None => {}
        }
    }

    fn remember(&mut self, n: u64, hash: &str) {
        self.hashes.insert(n, hash.to_string());
        while self.hashes.len() > HASHES_KEPT {
            self.hashes.pop_first();
        }
    }

    /// The blocks to compare this tick, with why each was picked.
    fn pick(&mut self, common: u64, max_head: u64, d: &mut Draw) -> Vec<(u64, &'static str)> {
        let lowest = max_head.saturating_sub(DEEP.1).max(1);
        let ok = |b: u64| b >= lowest && b < common;
        let tip = common.checked_sub(d.range(TIP)).filter(|b| ok(*b));
        let shallow = common.checked_sub(d.range(SHALLOW)).filter(|b| ok(*b));
        let near = common.checked_sub(d.range(NEAR)).filter(|b| ok(*b));
        let deep = common.checked_sub(deep_depth(d)).filter(|b| ok(*b));
        if self.focus.as_ref().is_some_and(|f| f.hi < lowest) {
            self.focus = None;
        }
        let (lo, hi) = match (&self.focus, &self.saved) {
            (Some(f), _) => (f.lo, f.hi),
            (None, Some((s, _))) => (s.saturating_sub(FOCUS_AROUND_SAVED), s + FOCUS_AROUND_SAVED),
            (None, None) => (1, 0),
        };
        let (lo, hi) = (lo.max(lowest), hi.min(common.saturating_sub(1)));
        let focus = (lo <= hi).then(|| d.range((lo, hi))).filter(|b| ok(*b));
        // Strata in turn; without a focus block, the next one too.
        let strata = [
            (tip, "tip"),
            (deep, "deep"),
            (near, "near"),
            (shallow, "shallow"),
        ];
        let k = (self.ticks % strata.len() as u64) as usize;
        let (first, other) = (strata[k], strata[(k + 1) % strata.len()]);
        let second = match focus {
            Some(f) => (Some(f), "focus"),
            None => other,
        };
        let mut out: Vec<(u64, &'static str)> = Vec::new();
        for (b, why) in [first, second] {
            if let Some(b) = b.filter(|b| !out.iter().any(|(x, _)| x == b)) {
                out.push((b, why));
            }
        }
        out.truncate(BLOCKS_PER_TICK);
        out
    }

    /// One E7h tick, after E7 found both nodes with the same block at
    /// `common`; `max_head` is the higher of the two heads.
    pub fn tick(
        &mut self,
        primary: &mut impl HistNode,
        reference: &mut impl HistNode,
        common: (u64, String),
        max_head: u64,
        now_ns: u64,
    ) -> Vec<Verdict> {
        let mut out = Vec::new();
        if self.down {
            return out;
        }
        let tick = self.ticks;
        self.ticks += 1;
        self.head = Some(max_head);
        self.remember(common.0, &common.1.to_lowercase());
        self.retry(primary, reference, max_head, now_ns, &mut out);

        let mut d = Draw::new(self.seed, E7H_SALT, tick);
        let picks = self.pick(common.0, max_head, &mut d);
        eprintln!(
            "historical: E7h tick {tick} common {} blocks {picks:?}",
            common.0
        );
        if picks.is_empty() {
            return out;
        }
        let get: Vec<Query> = picks.iter().map(|(n, _)| get_block(*n, true)).collect();
        let (Ok(pb), Ok(rb)) = (primary.batch(&get), reference.batch(&get)) else {
            return out;
        };
        let mut blocks = Vec::new();
        let mut candidates: Vec<Candidate> = Vec::new();
        for (i, (n, why)) in picks.iter().enumerate() {
            let (Some(Ok(p)), Some(Ok(r))) = (pb.get(i), rb.get(i)) else {
                continue;
            };
            let (Some(pv), Some(rv)) = (parse_block(p), parse_block(r)) else {
                continue;
            };
            if pv.hash != rv.hash || pv.number != *n {
                continue;
            }
            self.remember(*n, &pv.hash);
            if p != r {
                candidates.push((
                    *n,
                    pv.hash.clone(),
                    get[i].clone(),
                    Ok(p.clone()),
                    Ok(r.clone()),
                ));
            } else {
                self.compared(&get[i], &pv, why, &mut out);
            }
            blocks.push((pv, *why));
        }
        let mut queries: Vec<(usize, Query)> = Vec::new();
        for (i, (b, _)) in blocks.iter().enumerate() {
            let proof = max_head.saturating_sub(b.number) <= PROOF_DEPTH;
            queries.extend(
                plan(&self.targets, b, &mut d, proof, EXTENDED_PER_BLOCK)
                    .into_iter()
                    .map(|q| (i, q)),
            );
        }
        let calls: Vec<Query> = queries.iter().map(|(_, q)| q.clone()).collect();
        debug_assert!(get.len() + calls.len() + 2 * PENDING_PER_TICK <= MAX_CALLS);
        let (Ok(pa), Ok(ra)) = (primary.batch(&calls), reference.batch(&calls)) else {
            return out;
        };
        for (k, (i, q)) in queries.iter().enumerate() {
            let (b, why) = &blocks[*i];
            // Across a cross-engine pair, an engine-dependent method is not a
            // differential (coverage only), so a legitimate engine difference is
            // not reported as a bug.
            if self.cross_engine && engine_dependent(q.method) {
                self.compared(q, b, why, &mut out);
                continue;
            }
            let missing = || Err("missing answer".to_string());
            let p = pa.get(k).cloned().unwrap_or_else(missing);
            let r = ra.get(k).cloned().unwrap_or_else(missing);
            match (&p, &r) {
                (Ok(pv), Ok(rv)) if normalize(q.method, pv) == normalize(q.method, rv) => {
                    self.compared(q, b, why, &mut out);
                }
                (Err(_), Err(_)) => {}
                (Err(e), Ok(_)) | (Ok(_), Err(e)) if is_proof(q) && window_error(e) => {}
                _ => candidates.push((b.number, b.hash.clone(), q.clone(), p, r)),
            }
        }
        if candidates.is_empty() {
            return out;
        }
        // Only blocks both nodes still hold with the same hash (and, for
        // eth_getLogs, its two parents: below the agreed block anyway).
        let mut kept: BTreeMap<u64, bool> = BTreeMap::new();
        for (n, hash, ..) in &candidates {
            if !kept.contains_key(n) {
                let still = canonical(primary, *n, hash) == Some(true)
                    && canonical(reference, *n, hash) == Some(true);
                kept.insert(*n, still);
            }
        }
        for (n, hash, q, p, r) in candidates {
            if kept.get(&n) != Some(&true) {
                continue;
            }
            match (&p, &r) {
                (Ok(_), Ok(_)) => {
                    let detail = format!(
                        "method {}, block {n} ({hash}), args {}: primary {}, reference {}",
                        q.method,
                        q.params,
                        answer(&p),
                        answer(&r)
                    );
                    eprintln!("historical: E7h differs: {detail}");
                    out.push(Verdict::Always(
                        false,
                        finding(
                            &format!("E7/historical-{}-differs", q.method),
                            format!(
                                "method {}, block {n} ({hash}), args {}: primary {}, reference {}",
                                q.method,
                                q.params,
                                short(&answer(&p)),
                                short(&answer(&r))
                            ),
                        ),
                    ));
                }
                (Err(e), Ok(v)) | (Ok(v), Err(e)) => {
                    let side = if p.is_err() {
                        Side::Primary
                    } else {
                        Side::Reference
                    };
                    eprintln!(
                        "historical: E7h one-sided error ({side:?}) {} at {n}: {e}",
                        q.method
                    );
                    self.pending.push(Pending {
                        side,
                        query: q,
                        number: n,
                        hash,
                        since: now_ns,
                        error: e.clone(),
                        expected: v.to_string(),
                    });
                }
                (Err(_), Err(_)) => {}
            }
        }
        out
    }

    /// Coverage for one agreeing answer.
    fn compared(&mut self, q: &Query, b: &BlockView, why: &str, out: &mut Vec<Verdict>) {
        out.extend(sometimes(
            &mut self.seen,
            format!("S/historical-compared/{}", q.method),
            format!("block {} ({why})", b.number),
        ));
        if self
            .before_kill
            .get(&b.number)
            .is_some_and(|old| *old != b.hash)
        {
            out.extend(sometimes(
                &mut self.seen,
                "S/historical-after-unwind".into(),
                format!(
                    "{} at block {}: re-derived after the restart (hash {} before the kill, {} now)",
                    q.method, b.number, self.before_kill[&b.number], b.hash
                ),
            ));
        }
    }

    /// Retries one-sided errors: an answer, a reorg of the block or the
    /// block leaving the proof window ends one; [`GRACE_NS`] of errors make
    /// it `E7/historical-unavailable`.
    fn retry(
        &mut self,
        primary: &mut impl HistNode,
        reference: &mut impl HistNode,
        max_head: u64,
        now_ns: u64,
        out: &mut Vec<Verdict>,
    ) {
        let mut keep = Vec::new();
        let pending = std::mem::take(&mut self.pending);
        for (i, p) in pending.into_iter().enumerate() {
            if i >= PENDING_PER_TICK {
                keep.push(p);
                continue;
            }
            if is_proof(&p.query) && max_head.saturating_sub(p.number) > PROOF_WINDOW {
                continue;
            }
            let (Some(a), Some(b)) = (
                canonical(primary, p.number, &p.hash),
                canonical(reference, p.number, &p.hash),
            ) else {
                keep.push(p);
                continue;
            };
            if !(a && b) {
                continue;
            }
            let retried = match p.side {
                Side::Primary => primary.batch(std::slice::from_ref(&p.query)),
                Side::Reference => reference.batch(std::slice::from_ref(&p.query)),
            };
            match retried {
                Err(_) => keep.push(p),
                Ok(r) => match r.into_iter().next() {
                    Some(Ok(_)) => {}
                    Some(Err(e)) if is_proof(&p.query) && window_error(&e) => {}
                    _ if now_ns.saturating_sub(p.since) < GRACE_NS => keep.push(p),
                    other => {
                        let e = match other {
                            Some(Err(e)) => e,
                            _ => p.error.clone(),
                        };
                        out.push(Verdict::Always(
                            false,
                            finding(
                                "E7/historical-unavailable",
                                format!(
                                    "method {}, block {} ({}), args {}: {:?} errors for {}s ({}), other side {}",
                                    p.query.method,
                                    p.number,
                                    p.hash,
                                    p.query.params,
                                    p.side,
                                    now_ns.saturating_sub(p.since) / 1_000_000_000,
                                    short(&e),
                                    short(&p.expected)
                                ),
                            ),
                        ));
                    }
                },
            }
        }
        self.pending = keep;
    }
}

/// One block's answers recorded before a kill.
#[derive(Clone, Debug)]
struct Record {
    number: u64,
    hash: String,
    answers: Vec<(Query, Value)>,
    /// Re-reads put off because the restarted node did not serve the block
    /// yet (its head still below it).
    waits: u32,
}

/// Ticks a re-read waits for a restarted node to serve the block again.
const MAX_WAITS: u32 = 60;

/// E3h: the primary against itself across a restart.
#[derive(Debug)]
pub struct AcrossRestart {
    seed: u64,
    targets: Targets,
    ticks: u64,
    saved: Option<(u64, String)>,
    ring: VecDeque<Record>,
    sweep: VecDeque<Record>,
    pending: Vec<Pending>,
    down: bool,
    paused: bool,
    seen: BTreeSet<String>,
}

impl AcrossRestart {
    pub fn new(seed: u64, targets: Targets) -> AcrossRestart {
        AcrossRestart {
            seed,
            targets,
            ticks: 0,
            saved: None,
            ring: VecDeque::new(),
            sweep: VecDeque::new(),
            pending: Vec::new(),
            down: false,
            paused: false,
            seen: BTreeSet::new(),
        }
    }

    pub fn on_saved(&mut self, saved: (u64, String)) {
        self.saved = Some(saved);
    }

    pub fn on_event(&mut self, ev: &DstEvent) {
        match (node_event(ev), ev.kind.as_str()) {
            (Some(NodeEvent::Down), _) => {
                self.down = true;
                self.sweep.extend(self.ring.drain(..));
                while self.sweep.len() > 2 * RING {
                    self.sweep.pop_front();
                }
            }
            (Some(NodeEvent::Pause), _) => self.paused = true,
            (Some(NodeEvent::Up), "resume") => self.paused = false,
            (Some(NodeEvent::Up), _) => self.down = false,
            (None, _) => {}
        }
    }

    pub fn tick(&mut self, node: &mut impl HistNode, now_ns: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        if self.down || self.paused {
            return out;
        }
        let Ok(r) = node.batch(&[Query::new("eth_blockNumber", json!([]))]) else {
            return out;
        };
        let Some(head) = r
            .first()
            .and_then(|r| r.as_ref().ok())
            .and_then(Value::as_str)
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        else {
            return out;
        };
        let tick = self.ticks;
        self.ticks += 1;
        self.retry(node, head, now_ns, &mut out);
        if !self.sweep.is_empty() {
            self.reread(node, head, now_ns, &mut out);
        } else {
            self.record(node, head, tick);
        }
        out
    }

    /// Re-reads recorded blocks after a restart.
    fn reread(&mut self, node: &mut impl HistNode, head: u64, now_ns: u64, out: &mut Vec<Verdict>) {
        // One block fewer while retries ran, to stay within MAX_CALLS.
        let blocks = if self.pending.is_empty() {
            SWEEP_PER_TICK
        } else {
            SWEEP_PER_TICK - 1
        };
        for _ in 0..blocks {
            let Some(rec) = self.sweep.pop_front() else {
                return;
            };
            // The first recorded answer is the block by number: the batch
            // tells whether the node still has it, so the rest counts only
            // then.
            let answers: Vec<&(Query, Value)> = rec
                .answers
                .iter()
                .filter(|(q, _)| !is_proof(q) || head.saturating_sub(rec.number) <= PROOF_WINDOW)
                .collect();
            let calls: Vec<Query> = answers.iter().map(|(q, _)| q.clone()).collect();
            let Ok(now) = node.batch(&calls) else {
                self.sweep.push_front(rec);
                return;
            };
            let served = now
                .first()
                .and_then(|r| r.as_ref().ok())
                .and_then(|b| b.get("hash")?.as_str().map(str::to_lowercase));
            match served {
                // Not served yet (the head is still below it): later.
                None if rec.waits < MAX_WAITS => {
                    let mut rec = rec;
                    rec.waits += 1;
                    self.sweep.push_back(rec);
                    continue;
                }
                Some(h) if h == rec.hash => {}
                // Rebuilt (an unfinalized block lost in the crash): allowed.
                _ => continue,
            }
            for (k, (q, before)) in answers.into_iter().enumerate() {
                match now.get(k) {
                    Some(Ok(v)) if normalize(q.method, v) == normalize(q.method, before) => {
                        out.extend(sometimes(
                            &mut self.seen,
                            "S/historical-reread-after-restart".into(),
                            format!("{} at block {}", q.method, rec.number),
                        ));
                    }
                    Some(Ok(v)) => {
                        let detail = format!(
                            "method {}, block {} ({}), args {}: before the kill {}, after the restart {}",
                            q.method, rec.number, rec.hash, q.params, before, v
                        );
                        eprintln!("historical: E3h changed: {detail}");
                        out.push(Verdict::Always(
                            false,
                            finding(
                                "E3/historical-changed-across-restart",
                                format!(
                                    "method {}, block {} ({}), args {}: before the kill {}, after the restart {}",
                                    q.method,
                                    rec.number,
                                    rec.hash,
                                    q.params,
                                    short(&before.to_string()),
                                    short(&v.to_string())
                                ),
                            ),
                        ));
                    }
                    Some(Err(e)) if is_proof(q) && window_error(e) => {}
                    other => {
                        let e = match other {
                            Some(Err(e)) => e.clone(),
                            _ => "missing answer".into(),
                        };
                        eprintln!(
                            "historical: E3h error after restart {} at {}: {e}",
                            q.method, rec.number
                        );
                        self.pending.push(Pending {
                            side: Side::Primary,
                            query: q.clone(),
                            number: rec.number,
                            hash: rec.hash.clone(),
                            since: now_ns,
                            error: e,
                            expected: before.to_string(),
                        });
                    }
                }
            }
        }
    }

    /// Records one block's answers while the node runs.
    fn record(&mut self, node: &mut impl HistNode, head: u64, tick: u64) {
        let mut d = Draw::new(self.seed, E3H_SALT, tick);
        let depth = match tick % 4 {
            0 => d.range(SHALLOW),
            1 => d.range(NEAR),
            2 => deep_depth(&mut d),
            _ => match &self.saved {
                Some((s, _)) => head.saturating_sub(
                    d.range((s.saturating_sub(FOCUS_AROUND_SAVED), s + FOCUS_AROUND_SAVED)),
                ),
                None => d.range(SHALLOW),
            },
        };
        let Some(n) = head.checked_sub(depth.max(1)).filter(|n| *n > 0) else {
            return;
        };
        eprintln!("historical: E3h tick {tick} head {head} records block {n}");
        let Ok(b) = node.batch(&[get_block(n, true)]) else {
            return;
        };
        let Some(Ok(raw)) = b.into_iter().next() else {
            return;
        };
        let Some(view) = parse_block(&raw).filter(|v| v.number == n) else {
            return;
        };
        let proof = head.saturating_sub(n) <= RESTART_PROOF_DEPTH;
        let mut queries = vec![get_block(n, true)];
        queries.extend(plan(&self.targets, &view, &mut d, proof, RESTART_EXTENDED));
        let Ok(answers) = node.batch(&queries[1..]) else {
            return;
        };
        let mut rec = Record {
            number: n,
            hash: view.hash,
            answers: vec![(queries[0].clone(), raw)],
            waits: 0,
        };
        for (q, a) in queries.into_iter().skip(1).zip(answers) {
            if let Ok(v) = a {
                rec.answers.push((q, v));
            }
        }
        self.ring.push_back(rec);
        while self.ring.len() > RING {
            self.ring.pop_front();
        }
    }

    fn retry(&mut self, node: &mut impl HistNode, head: u64, now_ns: u64, out: &mut Vec<Verdict>) {
        let mut keep = Vec::new();
        for (i, p) in std::mem::take(&mut self.pending).into_iter().enumerate() {
            if i >= PENDING_PER_TICK {
                keep.push(p);
                continue;
            }
            if is_proof(&p.query) && head.saturating_sub(p.number) > PROOF_WINDOW {
                continue;
            }
            match canonical(node, p.number, &p.hash) {
                None => {
                    keep.push(p);
                    continue;
                }
                Some(false) => continue,
                Some(true) => {}
            }
            let Ok(r) = node.batch(std::slice::from_ref(&p.query)) else {
                keep.push(p);
                continue;
            };
            match r.into_iter().next() {
                Some(Ok(v)) => {
                    // It answers again; a different answer is still a change.
                    if normalize(p.query.method, &v)
                        != normalize(
                            p.query.method,
                            &serde_json::from_str(&p.expected).unwrap_or(Value::Null),
                        )
                    {
                        out.push(Verdict::Always(
                            false,
                            finding(
                                "E3/historical-changed-across-restart",
                                format!(
                                    "method {}, block {} ({}), args {}: before the kill {}, after the restart {}",
                                    p.query.method,
                                    p.number,
                                    p.hash,
                                    p.query.params,
                                    short(&p.expected),
                                    short(&v.to_string())
                                ),
                            ),
                        ));
                    }
                }
                Some(Err(e)) if is_proof(&p.query) && window_error(&e) => {}
                _ if now_ns.saturating_sub(p.since) < GRACE_NS => keep.push(p),
                other => {
                    let e = match other {
                        Some(Err(e)) => e,
                        _ => p.error.clone(),
                    };
                    out.push(Verdict::Always(
                        false,
                        finding(
                            "E3/historical-unavailable-after-restart",
                            format!(
                                "method {}, block {} ({}), args {}: errors for {}s after the restart ({}), before the kill {}",
                                p.query.method,
                                p.number,
                                p.hash,
                                p.query.params,
                                now_ns.saturating_sub(p.since) / 1_000_000_000,
                                short(&e),
                                short(&p.expected)
                            ),
                        ),
                    ));
                }
            }
        }
        self.pending = keep;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    /// A wrong answer a node serves for `method` at blocks in `blocks`, for
    /// its first `times` calls (all with `None`).
    #[derive(Clone)]
    struct Wrong {
        method: &'static str,
        blocks: (u64, u64),
        answer: Result<Value, String>,
        times: Option<usize>,
    }

    /// A node as these oracles see it: block hashes by number (one fork tag
    /// per block), honest answers that are a function of the query, and
    /// injected wrong ones.
    #[derive(Clone, Default)]
    struct FakeHist {
        up: bool,
        forks: Vec<&'static str>,
        wrong: Vec<Wrong>,
        /// Calls per batch.
        batches: Vec<Vec<Query>>,
    }

    fn block_hash(fork: &str, n: u64) -> String {
        format!("0x{fork}{n:060x}")
    }

    fn tx_hash(n: u64, i: u64) -> String {
        format!("0x{:064x}", n * 16 + i)
    }

    fn number(hex: &str) -> u64 {
        u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap()
    }

    impl FakeHist {
        fn chain(n: u64, fork: &'static str) -> FakeHist {
            FakeHist {
                up: true,
                forks: vec![fork; n as usize],
                ..Default::default()
            }
        }
        /// Blocks `from..` rebuilt on `fork`.
        fn rebuild(&mut self, from: u64, fork: &'static str) {
            for n in from..=self.forks.len() as u64 {
                self.forks[n as usize - 1] = fork;
            }
        }
        fn hash(&self, n: u64) -> Option<String> {
            let f = self.forks.get(n.checked_sub(1)? as usize)?;
            Some(block_hash(f, n))
        }
        fn head(&self) -> u64 {
            self.forks.len() as u64
        }
        fn block(&self, n: u64) -> Value {
            let Some(hash) = self.hash(n) else {
                return Value::Null;
            };
            let txs: Vec<Value> = (0..n % 3)
                .map(|i| {
                    json!({"hash": tx_hash(n, i), "from": format!("0x{:040x}", 0x100 + i), "to": crate::durable::PATH_USD, "input": "0x", "value": "0x0", "gas": "0x5208"})
                })
                .collect();
            json!({"number": hex(n), "hash": hash, "parentHash": self.hash(n - 1), "transactions": txs})
        }
        /// The block a query reads, if it names one this node has.
        fn block_of(&self, q: &Query) -> Option<u64> {
            let p = q.params.to_string();
            if let Some(i) = p.find("\"blockHash\":\"") {
                let h = &p[i + 13..i + 13 + 66];
                let n = number(&h[6..]);
                return (self.hash(n).as_deref() == Some(h)).then_some(n);
            }
            match q.method {
                "eth_getBlockByNumber" | "debug_executionWitness" => {
                    Some(number(q.params[0].as_str()?))
                }
                "eth_getBlockReceipts" => {
                    let h = q.params[0].as_str()?;
                    let n = number(&h[6..]);
                    (self.hash(n).as_deref() == Some(h)).then_some(n)
                }
                "eth_getTransactionReceipt" | "debug_traceTransaction" => {
                    Some(number(q.params[0].as_str()?) / 16)
                }
                "eth_getLogs" => Some(number(q.params[0]["toBlock"].as_str()?)),
                _ => None,
            }
        }
        fn answer(&mut self, q: &Query) -> Result<Value, String> {
            if q.method == "eth_blockNumber" {
                return Ok(json!(hex(self.head())));
            }
            let Some(n) = self.block_of(q) else {
                return Err("{\"code\":-32001,\"message\":\"block not found\"}".into());
            };
            for w in self.wrong.iter_mut() {
                if w.method == q.method && (w.blocks.0..=w.blocks.1).contains(&n) {
                    match &mut w.times {
                        Some(0) => continue,
                        Some(t) => *t -= 1,
                        None => {}
                    }
                    return w.answer.clone();
                }
            }
            if q.method == "eth_getBlockByNumber" {
                return Ok(self.block(n));
            }
            Ok(json!({"method": q.method, "params": q.params}))
        }
        fn calls(&self) -> usize {
            self.batches.iter().map(Vec::len).sum()
        }
    }

    impl HistNode for FakeHist {
        fn batch(&mut self, calls: &[Query]) -> Result<Vec<Result<Value, String>>, String> {
            if !self.up {
                return Err("connection refused".into());
            }
            self.batches.push(calls.to_vec());
            Ok(calls.iter().map(|q| self.answer(q)).collect())
        }
    }

    fn targets() -> Targets {
        let cfg: Config = serde_json::from_value(json!({
            "seed": 7,
            "trie": {"address": "0x5fbdb2315678afecb367f032d93f642f64180aa3", "slots": [544, 646]},
            "cob": {"address": "0x700b6A60ce7EaaEA56F065753d8dcB9653dbAD35"},
            "tip20": true,
        }))
        .unwrap();
        Targets::of(&cfg)
    }

    fn ev(kind: &str) -> DstEvent {
        DstEvent {
            source: "nemesis".into(),
            kind: kind.into(),
            container: Some(NODE_CONTAINER.into()),
            guest_time_ns: 0,
            detail: Value::Null,
        }
    }

    fn failures(v: &[Verdict]) -> Vec<(String, String)> {
        v.iter()
            .filter_map(|v| match v {
                Verdict::Always(false, f) => Some((f.signature.clone(), f.detail.clone())),
                _ => None,
            })
            .collect()
    }

    fn covered(v: &[Verdict]) -> BTreeSet<String> {
        v.iter()
            .filter_map(|v| match v {
                Verdict::Sometimes(true, f) => Some(f.signature.clone()),
                _ => None,
            })
            .collect()
    }

    /// `ticks` E7h ticks at 1 s, both nodes at their current heads.
    fn run(
        o: &mut Differential,
        p: &mut FakeHist,
        r: &mut FakeHist,
        from_s: u64,
        ticks: u64,
    ) -> Vec<Verdict> {
        let mut out = Vec::new();
        for t in 0..ticks {
            let common = p.head().min(r.head());
            let hash = p.hash(common).unwrap();
            let max_head = p.head().max(r.head());
            out.extend(o.tick(p, r, (common, hash), max_head, (from_s + t) * S));
        }
        out
    }

    const METHODS: [&str; 11] = [
        "eth_getBlockByNumber",
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_call",
        "eth_getProof",
        "eth_getBlockReceipts",
        "eth_getTransactionReceipt",
        "debug_traceTransaction",
        "eth_getLogs",
    ];

    fn picked_blocks(batches: &[Vec<Query>]) -> Vec<Vec<u64>> {
        batches
            .iter()
            .filter(|b| {
                b.iter()
                    .all(|q| q.method == "eth_getBlockByNumber" && q.params[1] == json!(true))
            })
            .map(|b| {
                b.iter()
                    .map(|q| number(q.params[0].as_str().unwrap()))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn agreeing_nodes_pass_and_cover_every_method_within_budget() {
        let mut o = Differential::new(7, targets());
        let mut p = FakeHist::chain(300, "aaaa");
        let mut r = p.clone();
        let mut seen = BTreeSet::new();
        for t in 0..40 {
            let (pc, rc) = (p.calls(), r.calls());
            let v = run(&mut o, &mut p, &mut r, t, 1);
            assert_eq!(failures(&v), []);
            assert!(p.calls() - pc <= MAX_CALLS, "{}", p.calls() - pc);
            assert!(r.calls() - rc <= MAX_CALLS);
            seen.extend(covered(&v));
        }
        for m in METHODS {
            assert!(
                seen.contains(&format!("S/historical-compared/{m}")),
                "{m}: {seen:?}"
            );
        }
        // rpc-tester's extra methods are drawn too.
        let asked: BTreeSet<&str> = p.batches.iter().flatten().map(|q| q.method).collect();
        for m in [
            "eth_getBlockByHash",
            "debug_getRawBlock",
            "trace_block",
            "debug_traceBlockByHash",
            "eth_estimateGas",
            "debug_executionWitness",
        ] {
            assert!(asked.contains(m), "{m}: {asked:?}");
        }
        // Every stratum, all inside the window, two blocks every tick.
        let picked = picked_blocks(&p.batches);
        assert_eq!(picked.len(), 40);
        let all: BTreeSet<u64> = picked.iter().flatten().copied().collect();
        assert!(all.iter().all(|b| (50..300).contains(b)), "{all:?}");
        assert!(picked.iter().all(|b| b.len() == 2), "{picked:?}");
        for (lo, hi) in [TIP, NEAR, DEEP_STRATA[0], DEEP_STRATA[1], DEEP_STRATA[2]] {
            assert!(
                all.iter().any(|b| (300 - hi..=300 - lo).contains(b)),
                "({lo}, {hi}): {all:?}"
            );
        }
        // State reads are by block hash, never by number.
        for q in p.batches.iter().flatten() {
            if [
                "eth_getBalance",
                "eth_getStorageAt",
                "eth_call",
                "eth_getProof",
            ]
            .contains(&q.method)
            {
                assert!(q.params.to_string().contains("requireCanonical"), "{q:?}");
            }
        }
    }

    #[test]
    fn a_different_answer_is_reported_with_both_answers() {
        let mut o = Differential::new(7, targets());
        let mut p = FakeHist::chain(300, "aaaa");
        let mut r = p.clone();
        p.wrong.push(Wrong {
            method: "eth_getBalance",
            blocks: (1, 300),
            answer: Ok(json!("0xdead")),
            times: None,
        });
        let f = failures(&run(&mut o, &mut p, &mut r, 0, 1));
        assert!(!f.is_empty());
        for (sig, detail) in &f {
            assert_eq!(sig, "E7/historical-eth_getBalance-differs");
            assert!(
                detail.starts_with("method eth_getBalance, block "),
                "{detail}"
            );
            assert!(
                detail.contains("primary \"0xdead\", reference {"),
                "{detail}"
            );
        }
        // Proofs compare account fields: different proof nodes alone pass.
        let mut o = Differential::new(7, targets());
        let mut p = FakeHist::chain(300, "aaaa");
        let mut r = p.clone();
        let proof = |nodes: &str, balance: &str| {
            Ok(
                json!({"balance": balance, "nonce": "0x0", "codeHash": "0x1", "storageHash": "0x2",
                "accountProof": [nodes], "storageProof": []}),
            )
        };
        for (node, nodes) in [(&mut p, "0xaa"), (&mut r, "0xbb")] {
            node.wrong.push(Wrong {
                method: "eth_getProof",
                blocks: (1, 300),
                answer: proof(nodes, "0x1"),
                times: None,
            });
        }
        assert_eq!(failures(&run(&mut o, &mut p, &mut r, 0, 10)), []);
        r.wrong[0].answer = proof("0xbb", "0x2");
        let f = failures(&run(&mut o, &mut p, &mut r, 10, 10));
        assert!(!f.is_empty());
        assert!(f
            .iter()
            .all(|(s, _)| s == "E7/historical-eth_getProof-differs"));
    }

    #[test]
    fn one_sided_errors_need_the_grace_period() {
        let err = || Err("{\"code\":-32000,\"message\":\"missing trie node\"}".to_string());
        // Persistent: reported once the grace period is over.
        let mut o = Differential::new(7, targets());
        let mut p = FakeHist::chain(300, "aaaa");
        let mut r = p.clone();
        p.wrong.push(Wrong {
            method: "eth_getCode",
            blocks: (1, 300),
            answer: err(),
            times: None,
        });
        assert_eq!(failures(&run(&mut o, &mut p, &mut r, 0, 30)), []);
        let f = failures(&run(&mut o, &mut p, &mut r, 30, 5));
        assert!(!f.is_empty());
        assert!(
            f.iter().all(|(s, d)| s == "E7/historical-unavailable"
                && d.contains("method eth_getCode")
                && d.contains("Primary errors")
                && d.contains("missing trie node")),
            "{f:?}"
        );
        // Transient: the retry answers.
        let mut o = Differential::new(7, targets());
        let mut p = FakeHist::chain(300, "aaaa");
        let mut r = p.clone();
        r.wrong.push(Wrong {
            method: "eth_getCode",
            blocks: (1, 300),
            answer: err(),
            times: Some(1),
        });
        assert_eq!(failures(&run(&mut o, &mut p, &mut r, 0, 60)), []);
        // Both sides failing, and the proof window, are not findings.
        let mut o = Differential::new(7, targets());
        let mut p = FakeHist::chain(300, "aaaa");
        let mut r = p.clone();
        for node in [&mut p, &mut r] {
            node.wrong.push(Wrong {
                method: "eth_getCode",
                blocks: (1, 300),
                answer: err(),
                times: None,
            });
        }
        p.wrong.push(Wrong {
            method: "eth_getProof",
            blocks: (1, 300),
            answer: Err("distance to target block exceeds maximum proof window".into()),
            times: None,
        });
        assert_eq!(failures(&run(&mut o, &mut p, &mut r, 0, 60)), []);
    }

    #[test]
    fn only_blocks_both_nodes_hold_are_compared() {
        let mut o = Differential::new(7, targets());
        let mut p = FakeHist::chain(300, "aaaa");
        let mut r = p.clone();
        // Below the agreed block the reference serves another fork (as
        // mid-reorg): nothing is compared, so nothing differs.
        r.rebuild(1, "bbbb");
        r.forks[299] = "aaaa";
        p.wrong.push(Wrong {
            method: "eth_getBalance",
            blocks: (1, 300),
            answer: Ok(json!("0xdead")),
            times: None,
        });
        let v = run(&mut o, &mut p, &mut r, 0, 10);
        assert_eq!(failures(&v), []);
        assert!(covered(&v).is_empty());
    }

    #[test]
    fn primary_downtime_is_excused() {
        let mut o = Differential::new(7, targets());
        let mut p = FakeHist::chain(300, "aaaa");
        let mut r = p.clone();
        run(&mut o, &mut p, &mut r, 0, 1);
        o.on_event(&ev("pause"));
        let before = p.calls();
        p.wrong.push(Wrong {
            method: "eth_getBalance",
            blocks: (1, 300),
            answer: Ok(json!("0xdead")),
            times: None,
        });
        assert!(run(&mut o, &mut p, &mut r, 1, 5).is_empty());
        assert_eq!(p.calls(), before);
        // Unreachable mid-tick: the tick ends without findings.
        o.on_event(&ev("resume"));
        p.up = false;
        assert!(failures(&run(&mut o, &mut p, &mut r, 6, 5)).is_empty());
    }

    #[test]
    fn restarts_focus_on_the_unwound_range_and_cover_rederived_blocks() {
        let mut o = Differential::new(7, targets());
        let mut p = FakeHist::chain(300, "aaaa");
        let mut r = p.clone();
        o.on_saved((280, block_hash("aaaa", 280)));
        run(&mut o, &mut p, &mut r, 0, 30);
        o.on_event(&ev("kill"));
        // The restart unwinds to 270 and rebuilds; the reference reorgs.
        for node in [&mut p, &mut r] {
            node.rebuild(271, "bbbb");
            node.forks.extend(["bbbb"; 10]);
        }
        o.on_event(&ev("restart"));
        let first = p.batches.len();
        let v = run(&mut o, &mut p, &mut r, 30, 40);
        assert_eq!(failures(&v), []);
        assert!(covered(&v).contains("S/historical-after-unwind"), "{v:?}");
        let focus: Vec<u64> = picked_blocks(&p.batches[first..])
            .iter()
            .filter_map(|b| b.get(1).copied())
            .collect();
        // [saved - 16, head at kill + 4], below the newest common block.
        assert_eq!(focus.len(), 40);
        assert!(focus.iter().all(|b| (264..=304).contains(b)), "{focus:?}");
    }

    #[test]
    fn picks_are_a_function_of_the_seed() {
        let picks = |seed| {
            let mut o = Differential::new(seed, targets());
            let mut p = FakeHist::chain(300, "aaaa");
            let mut r = p.clone();
            run(&mut o, &mut p, &mut r, 0, 10);
            p.batches
        };
        assert_eq!(picks(7), picks(7));
        assert_ne!(picks(7), picks(8));
    }

    #[test]
    fn cross_engine_pair_excuses_engine_dependent_methods() {
        // The reference serves a different debug_executionWitness, a method whose
        // trie-node set legitimately differs between engine profiles. Across a
        // cross-engine pair it is not a finding; otherwise it is.
        let run_with = |cross: bool| {
            let mut o = Differential::new(7, targets()).cross_engine(cross);
            let mut p = FakeHist::chain(300, "aaaa");
            let mut r = p.clone();
            r.wrong.push(Wrong {
                method: "debug_executionWitness",
                blocks: (1, 300),
                answer: Ok(json!({"codes": ["0xffff"], "keys": [], "state": [], "headers": []})),
                times: None,
            });
            failures(&run(&mut o, &mut p, &mut r, 0, 40))
        };
        let reported = run_with(false);
        assert!(
            reported
                .iter()
                .any(|(s, _)| s == "E7/historical-debug_executionWitness-differs"),
            "{reported:?}"
        );
        assert_eq!(run_with(true), []);
    }

    fn across() -> AcrossRestart {
        AcrossRestart::new(7, targets())
    }

    fn tick_n(o: &mut AcrossRestart, p: &mut FakeHist, from_s: u64, n: u64) -> Vec<Verdict> {
        (0..n).flat_map(|t| o.tick(p, (from_s + t) * S)).collect()
    }

    #[test]
    fn restart_rereads_kept_blocks() {
        let mut o = across();
        let mut p = FakeHist::chain(300, "aaaa");
        for t in 0..30 {
            let before = p.calls();
            tick_n(&mut o, &mut p, t, 1);
            assert!(p.calls() - before <= MAX_CALLS);
            p.forks.push("aaaa");
        }
        o.on_event(&ev("kill"));
        o.on_event(&ev("restart"));
        let mut v = Vec::new();
        for t in 30..50 {
            let before = p.calls();
            v.extend(tick_n(&mut o, &mut p, t, 1));
            assert!(p.calls() - before <= MAX_CALLS);
        }
        assert_eq!(failures(&v), []);
        assert!(covered(&v).contains("S/historical-reread-after-restart"));
        assert!(o.sweep.is_empty());
    }

    #[test]
    fn a_restarted_node_below_the_recorded_blocks_is_waited_for() {
        let mut o = across();
        let mut p = FakeHist::chain(300, "aaaa");
        tick_n(&mut o, &mut p, 0, 12);
        o.on_event(&ev("kill"));
        o.on_event(&ev("restart"));
        // Back at 40, below every recorded block, at first (still catching
        // up), then with the same blocks.
        let kept = p.forks.split_off(40);
        let v = tick_n(&mut o, &mut p, 12, 5);
        assert!(!covered(&v).contains("S/historical-reread-after-restart"));
        p.forks.extend(kept);
        let v = tick_n(&mut o, &mut p, 17, 20);
        assert_eq!(failures(&v), []);
        assert!(covered(&v).contains("S/historical-reread-after-restart"));
        assert!(o.sweep.is_empty());
    }

    #[test]
    fn a_changed_answer_across_a_restart_is_reported() {
        let mut o = across();
        let mut p = FakeHist::chain(300, "aaaa");
        tick_n(&mut o, &mut p, 0, 12);
        o.on_event(&ev("kill"));
        p.wrong.push(Wrong {
            method: "eth_getStorageAt",
            blocks: (1, 300),
            answer: Ok(json!(
                "0x0000000000000000000000000000000000000000000000000000000000000007"
            )),
            times: None,
        });
        o.on_event(&ev("restart"));
        let f = failures(&tick_n(&mut o, &mut p, 12, 12));
        assert!(!f.is_empty());
        assert!(
            f.iter()
                .all(|(s, d)| s == "E3/historical-changed-across-restart"
                    && d.contains("method eth_getStorageAt")
                    && d.contains("after the restart \"0x00")),
            "{f:?}"
        );
    }

    #[test]
    fn rebuilt_blocks_are_not_compared_across_a_restart() {
        let mut o = across();
        let mut p = FakeHist::chain(300, "aaaa");
        tick_n(&mut o, &mut p, 0, 12);
        o.on_event(&ev("kill"));
        p.rebuild(1, "bbbb");
        p.wrong.push(Wrong {
            method: "eth_getStorageAt",
            blocks: (1, 300),
            answer: Ok(json!("0x07")),
            times: None,
        });
        o.on_event(&ev("restart"));
        let v = tick_n(&mut o, &mut p, 12, 12);
        assert_eq!(failures(&v), []);
        assert!(!covered(&v).contains("S/historical-reread-after-restart"));
    }

    #[test]
    fn errors_after_a_restart_need_the_grace_period() {
        let err = || Err("{\"code\":-32000,\"message\":\"state not available\"}".to_string());
        let mut o = across();
        let mut p = FakeHist::chain(300, "aaaa");
        tick_n(&mut o, &mut p, 0, 12);
        o.on_event(&ev("kill"));
        p.wrong.push(Wrong {
            method: "eth_getBalance",
            blocks: (1, 300),
            answer: err(),
            times: Some(3),
        });
        o.on_event(&ev("restart"));
        // Transient (e.g. the node still re-executing): no finding.
        assert_eq!(failures(&tick_n(&mut o, &mut p, 12, 60)), []);

        let mut o = across();
        let mut p = FakeHist::chain(300, "aaaa");
        tick_n(&mut o, &mut p, 0, 12);
        o.on_event(&ev("stop"));
        p.wrong.push(Wrong {
            method: "eth_getBalance",
            blocks: (1, 300),
            answer: err(),
            times: None,
        });
        o.on_event(&ev("restart"));
        assert_eq!(failures(&tick_n(&mut o, &mut p, 12, 20)), []);
        let f = failures(&tick_n(&mut o, &mut p, 32, 30));
        assert!(!f.is_empty());
        assert!(f
            .iter()
            .all(|(s, d)| s == "E3/historical-unavailable-after-restart"
                && d.contains("state not available")));
    }

    #[test]
    fn a_paused_or_down_node_is_not_read() {
        let mut o = across();
        let mut p = FakeHist::chain(300, "aaaa");
        o.on_event(&ev("pause"));
        tick_n(&mut o, &mut p, 0, 3);
        o.on_event(&ev("resume"));
        o.on_event(&ev("kill"));
        tick_n(&mut o, &mut p, 3, 3);
        assert_eq!(p.calls(), 0);
    }
}
