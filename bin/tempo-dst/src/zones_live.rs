// SPDX-License-Identifier: GPL-2.0

//! The zones load against live nodes: [`ZonesChain`] over RPC, the batch
//! prover loop (`tempo-dst zone-prover`), the warmup wait
//! (`tempo-dst deploy-zones`), and the driver container.

use std::{
    io,
    process::{Command, Stdio},
    time::Duration,
};

use alloy_primitives::{keccak256, Address, B256, U256};
use serde_json::json;

use crate::{
    common::{self, BlockRef, Config},
    zones::{
        self, decode_l1, decode_zone, L1Event, L1Fault, L1FaultOutcome, L1FaultResult, L1State,
        MutationOutcome, MutationResult, ProofResult, ProofStatus, Side, WitnessMutation,
        ZoneEndpoints, ZoneEvent, ZoneState, ZonesChain, L1FAULT_LINE, MUTATION_LINE, PORTAL,
        PROVER_LINE, TEMPO_STATE, TOKEN, ZONE_INBOX, ZONE_OUTBOX, ZONE_RPC_URL,
    },
};

fn selector(signature: &str) -> Vec<u8> {
    keccak256(signature.as_bytes())[..4].to_vec()
}

fn call(to: Address, signature: &str, args: &[B256]) -> (Address, Vec<u8>) {
    let mut data = selector(signature);
    for a in args {
        data.extend_from_slice(a.as_slice());
    }
    (to, data)
}

fn word_at(out: &[u8], i: usize) -> Result<B256, String> {
    out.get(i * 32..(i + 1) * 32)
        .map(B256::from_slice)
        .ok_or_else(|| format!("short eth_call result ({} bytes)", out.len()))
}

fn u64_at(out: &[u8], i: usize) -> Result<u64, String> {
    u64::try_from(U256::from_be_bytes(word_at(out, i)?.0)).map_err(|e| e.to_string())
}

fn block_ref(number: u64) -> Result<Option<BlockRef>, String> {
    Ok(common::block_ref(number)?.map(|(hash, parent)| BlockRef {
        number,
        hash,
        parent,
    }))
}

/// The L1 node (the primary Tempo node's RPC).
pub struct RpcL1;

impl Side for RpcL1 {
    type Event = L1Event;
    type State = L1State;
    fn head(&mut self) -> Result<u64, String> {
        common::head_number()
    }
    fn block(&mut self, number: u64) -> Result<Option<BlockRef>, String> {
        block_ref(number)
    }
    fn events(&mut self, from: u64, to: u64) -> Result<Vec<(B256, L1Event)>, String> {
        Ok(common::logs_of(&[PORTAL], from, to)?
            .iter()
            .filter_map(|l| decode_l1(l).map(|e| (l.block_hash, e)))
            .collect())
    }
    fn state(&mut self, hash: B256) -> Result<L1State, String> {
        let out = common::calls_at(
            &[
                call(TOKEN, "balanceOf(address)", &[PORTAL.into_word()]),
                call(PORTAL, "blockHash()", &[]),
                call(PORTAL, "withdrawalBatchIndex()", &[]),
            ],
            hash,
        )?;
        Ok(L1State {
            balance: U256::from_be_bytes(word_at(&out[0], 0)?.0),
            settled_hash: word_at(&out[1], 0)?,
            batch_index: u64_at(&out[2], 0)?,
        })
    }
    fn number_of(&mut self, hash: B256) -> Result<Option<u64>, String> {
        common::block_number_by_hash(hash)
    }
}

/// A zone node's unrestricted RPC (the single sequencer, or cluster node 0).
pub struct RpcZone {
    url: &'static str,
}

impl RpcZone {
    pub fn new(endpoints: ZoneEndpoints) -> RpcZone {
        RpcZone { url: endpoints.rpc }
    }
}

impl Side for RpcZone {
    type Event = ZoneEvent;
    type State = ZoneState;
    fn head(&mut self) -> Result<u64, String> {
        common::with_rpc_url(self.url, common::head_number)
    }
    fn block(&mut self, number: u64) -> Result<Option<BlockRef>, String> {
        common::with_rpc_url(self.url, || block_ref(number))
    }
    fn events(&mut self, from: u64, to: u64) -> Result<Vec<(B256, ZoneEvent)>, String> {
        let logs = common::with_rpc_url(self.url, || {
            common::logs_of(&[ZONE_INBOX, ZONE_OUTBOX], from, to)
        })?;
        Ok(logs
            .iter()
            .filter_map(|l| decode_zone(l).map(|e| (l.block_hash, e)))
            .collect())
    }
    fn state(&mut self, hash: B256) -> Result<ZoneState, String> {
        let out = common::with_rpc_url(self.url, || {
            common::calls_at(
                &[
                    call(TEMPO_STATE, "tempoBlockNumber()", &[]),
                    call(TOKEN, "totalSupply()", &[]),
                    call(ZONE_INBOX, "processedDepositNumber()", &[]),
                    call(ZONE_OUTBOX, "lastBatch()", &[]),
                ],
                hash,
            )
        })?;
        Ok(ZoneState {
            tempo_block: u64_at(&out[0], 0)?,
            supply: U256::from_be_bytes(word_at(&out[1], 0)?.0),
            processed_deposits: u64_at(&out[2], 0)?,
            last_batch_hash: word_at(&out[3], 0)?,
            last_batch_index: u64_at(&out[3], 1)?,
        })
    }
    fn number_of(&mut self, hash: B256) -> Result<Option<u64>, String> {
        common::with_rpc_url(self.url, || common::block_number_by_hash(hash))
    }
}

/// Both nodes over RPC.
pub struct RpcZones {
    l1: RpcL1,
    zone: RpcZone,
}

impl RpcZones {
    pub fn new(endpoints: ZoneEndpoints) -> RpcZones {
        RpcZones {
            l1: RpcL1,
            zone: RpcZone::new(endpoints),
        }
    }
}

impl ZonesChain for RpcZones {
    type L1 = RpcL1;
    type Zone = RpcZone;
    fn l1(&mut self) -> &mut RpcL1 {
        &mut self.l1
    }
    fn zone(&mut self) -> &mut RpcZone {
        &mut self.zone
    }
}

/// The zones load's setup spec (`zones/deploy.yaml`, warmup): gives pathUSD
/// the TIP-403 registry binding `createZone` requires. The compose `zone`
/// service retries `createZone` until it lands.
pub fn setup(image: &str) -> io::Result<()> {
    crate::deploy::run(
        image,
        "/workload/zones/deploy.yaml",
        None,
        "zone setup",
        || {
            let head = common::head_number()?;
            let Some(block) = block_ref(head)? else {
                return Ok(false);
            };
            let registry = alloy_primitives::address!("403c000000000000000000000000000000000000");
            let out = common::calls_at(
                &[call(
                    registry,
                    "tokenTransferPolicyId(address)",
                    &[TOKEN.into_word()],
                )],
                block.hash,
            )?;
            Ok(U256::from_be_bytes(word_at(&out[0], 0)?.0) == U256::from(1))
        },
    )
}

/// Funds the policy family's dedicated account (dev 2) on the zone in warmup
/// (`policy.sh fund`), before the warm checkpoint, so every branch starts with
/// it funded and no nemesis kill interrupts the slow deposit. Idempotent: a
/// container that finds dev 2 already funded exits at once.
pub fn fund_policy_account(image: &str) -> io::Result<()> {
    let status = Command::new("podman")
        .args(["run", "--rm", "--network", "host"])
        .args(["-e", "RUST_LOG=warn"])
        .args([
            "--entrypoint",
            "/bin/bash",
            image,
            "/usr/local/bin/policy.sh",
            "fund",
        ])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("policy.sh fund: {status}")));
    }
    Ok(())
}

/// `tempo-dst deploy-zones [image]`: [`setup`], then waits until
/// [`zone_ready`] (the warmup hook polls it instead).
pub fn deploy(image: &str) -> io::Result<()> {
    setup(image)?;
    let mut last = String::new();
    for _ in 0..900 {
        match zone_ready(ZoneEndpoints::SINGLE) {
            Ok((true, _)) => return Ok(()),
            Ok((false, detail)) => last = detail,
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(io::Error::other(format!(
        "zone not provisioned or no batch settled: {last}"
    )))
}

/// Whether the zone exists on L1, its node serves blocks, and a first batch
/// has settled, with a progress line.
pub fn zone_ready(endpoints: ZoneEndpoints) -> Result<(bool, String), String> {
    if !common::has_code(&PORTAL.to_string())? {
        return Ok((false, "portal not created yet".into()));
    }
    let zone_head = RpcZone::new(endpoints).head()?;
    let head = common::head_number()?;
    let Some(block) = block_ref(head)? else {
        return Ok((false, format!("no L1 block {head}")));
    };
    let state = RpcL1.state(block.hash)?;
    Ok((
        zone_head > 0 && state.batch_index >= 1,
        format!(
            "L1 head {head}, zone head {zone_head}, batches settled {}",
            state.batch_index
        ),
    ))
}

/// File in the prover container that survives its restarts (podman start
/// keeps the container's filesystem): the next L1 block to scan.
const PROVER_CURSOR: &str = "/var/tmp/zone-prover-next";
/// Witness generation attempts per batch before reporting `unavailable`.
const PROVER_ATTEMPTS: u32 = 20;

/// `tempo-dst zone-prover`: replays every submitted batch through the SPF,
/// in L1 order, and prints one [`ProofResult`] line per batch.
pub fn prover() -> io::Result<()> {
    let endpoints = ZoneEndpoints::from_env();
    let mut next = match std::fs::read_to_string(PROVER_CURSOR) {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .map_err(|e| io::Error::other(format!("prover cursor {PROVER_CURSOR}: {e}")))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => return Err(io::Error::other(format!("read prover cursor: {e}"))),
    };
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let Ok(head) = common::head_number() else {
            continue;
        };
        if head.saturating_add(1) < next {
            // The L1 rebuilt blocks after a crash; rescan them.
            next = head.saturating_sub(64);
        }
        let end = head.min(next + 2000);
        let Ok(logs) = common::logs_of(&[PORTAL], next, end) else {
            continue;
        };
        // The branch's config appears after the warm checkpoint (the prover
        // starts at boot), so the flag is re-read every scan.
        let faults = witness_faults();
        let l1_faults = l1_faults_on();
        if faults {
            std::fs::create_dir_all(WITNESS_DIR)?;
        }
        for log in &logs {
            if let Some(L1Event::Batch(batch)) = decode_l1(log) {
                let witness = faults.then(|| format!("{WITNESS_DIR}/batch-{}.json", batch.index));
                let r = prove(batch, log.block_number, endpoints, witness.as_deref());
                println!("{PROVER_LINE}{}", serde_json::to_string(&r).unwrap());
                // Witness-fault family: mutate the honest witness and check
                // the SPF rejects it (it is never submitted to L1).
                if let Some(path) = &witness {
                    if r.status == ProofStatus::Ok {
                        let m = mutate_and_replay(&batch, log.block_number, path, draw_mutation());
                        println!("{MUTATION_LINE}{}", serde_json::to_string(&m).unwrap());
                    }
                    let _ = std::fs::remove_file(path);
                }
                // L1-fault family: rebuild the witness through a byzantine L1
                // proxy and check the prover rejects it. A separate probe, so
                // the honest result above is unaffected and nothing invalid is
                // submitted.
                if l1_faults {
                    let f = l1_fault_probe(&batch, log.block_number, L1Fault::of(draw_u64()));
                    println!("{L1FAULT_LINE}{}", serde_json::to_string(&f).unwrap());
                }
            }
        }
        next = end + 1;
        let temporary = format!("{PROVER_CURSOR}.tmp");
        std::fs::write(&temporary, next.to_string())
            .map_err(|e| io::Error::other(format!("write prover cursor: {e}")))?;
        std::fs::rename(temporary, PROVER_CURSOR)
            .map_err(|e| io::Error::other(format!("commit prover cursor: {e}")))?;
    }
}

fn prove(
    batch: zones::ZoneBatch,
    l1_block: u64,
    endpoints: ZoneEndpoints,
    witness_out: Option<&str>,
) -> ProofResult {
    let mut r = ProofResult {
        batch_index: batch.index,
        l1_block,
        next_block_hash: batch.next_block_hash,
        ..ProofResult::default()
    };
    for attempt in 1..=PROVER_ATTEMPTS {
        let start = common::guest_time_ns();
        let mut cmd = Command::new("tempo-zone-prover-utils");
        cmd.args(["generate-input", "--tempo-rpc-url", "http://127.0.0.1:8545"])
            .args([
                "--zone-rpc-url",
                endpoints.rpc,
                "--chain",
                endpoints.genesis,
            ])
            .args(["--block", &batch.next_block_hash.to_string()])
            .args(["--log-filter", "warn"]);
        if let Some(path) = witness_out {
            cmd.args(["--output", path]);
        }
        let out = cmd.stdin(Stdio::null()).output();
        r.secs = (common::guest_time_ns() - start) as f64 / 1e9;
        r.max_rss_kb = children_max_rss_kb();
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                r.status = ProofStatus::Unavailable;
                r.error = format!("spawn: {e}");
                return r;
            }
        };
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        r.replayed_hash = field(&text, "Next block hash:").and_then(|h| h.parse().ok());
        r.zone_blocks = field(&text, "Zone blocks:").map(str::to_string);
        if out.status.success() && r.replayed_hash.is_none() {
            r.status = ProofStatus::Unavailable;
            r.error = "successful prover omitted the replayed block hash".into();
            return r;
        }
        if out.status.success() {
            r.status = ProofStatus::Ok;
            r.error.clear();
            return r;
        }
        r.error = tail(&text, 600);
        if text.contains("failed SPF validation") || text.contains("SPF replay produced") {
            r.status = ProofStatus::SpfFailed;
            return r;
        }
        // The L1 no longer serves proofs at the batch's imported blocks:
        // retrying cannot help (E12 then reports the batch unproven).
        if text.contains("exceeds maximum proof window") {
            r.status = ProofStatus::Unavailable;
            return r;
        }
        eprintln!(
            "zone-prover: batch {} attempt {attempt}: {}",
            batch.index, r.error
        );
        std::thread::sleep(Duration::from_secs(3));
    }
    r.status = ProofStatus::Unavailable;
    r
}

/// Where the prover writes witness JSON for the witness-fault family.
const WITNESS_DIR: &str = "/var/tmp/zone-witness";

/// The branch config's `zones_witness_faults`; false while there is no
/// (complete) config yet.
/// The branch config's `zones_l1_faults`.
fn l1_faults_on() -> bool {
    std::fs::read_to_string(common::CONFIG_PATH)
        .ok()
        .and_then(|s| serde_json::from_str::<Config>(&s).ok())
        .is_some_and(|c| c.zones_l1_faults)
}

/// Rebuilds a settled batch's witness with `generate-input` pointed at a
/// byzantine L1 proxy that lies about L1 state. The prover must reject the
/// result (its witness does not validate against the real chain); accepting it
/// with the committed hash means it trusted falsified L1 state. A separate
/// probe: nothing here is submitted to L1.
fn l1_fault_probe(batch: &zones::ZoneBatch, l1_block: u64, fault: L1Fault) -> L1FaultResult {
    let mut r = L1FaultResult {
        batch_index: batch.index,
        l1_block,
        committed_hash: batch.next_block_hash,
        fault,
        faulted: false,
        outcome: L1FaultOutcome::Skipped,
        replayed_hash: None,
        detail: String::new(),
    };
    let spec = crate::zones_l1_proxy::ProxyFault {
        kind: fault,
        stale_below: l1_block,
    };
    let proxy = match crate::zones_l1_proxy::start("http://127.0.0.1:8545", spec) {
        Ok(p) => p,
        Err(e) => {
            r.detail = format!("start proxy: {e}");
            return r;
        }
    };
    let (ok, replayed, text) = run_generate_input(batch.next_block_hash, &proxy.addr);
    proxy.stop();
    r.faulted = proxy.applied();
    r.replayed_hash = replayed;
    if !r.faulted {
        r.detail = "the faulted L1 method was not requested".into();
        return r;
    }
    r.outcome = if ok && replayed == Some(batch.next_block_hash) {
        L1FaultOutcome::Accepted
    } else {
        L1FaultOutcome::Detected
    };
    r.detail = if ok {
        format!("witness built; replayed {replayed:?}")
    } else {
        tail(&text, 200)
    };
    r
}

/// One `generate-input --block` run against `tempo_rpc`: `(success, replayed
/// nextBlockHash, combined output)`.
fn run_generate_input(block: B256, tempo_rpc: &str) -> (bool, Option<B256>, String) {
    let out = Command::new("tempo-zone-prover-utils")
        .args(["generate-input", "--tempo-rpc-url", tempo_rpc])
        .args([
            "--zone-rpc-url",
            ZONE_RPC_URL,
            "--chain",
            zones::GENESIS_PATH,
        ])
        .args(["--block", &block.to_string(), "--log-filter", "error"])
        .stdin(Stdio::null())
        .output();
    match out {
        Ok(o) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            let replayed = field(&text, "Next block hash:").and_then(|h| h.parse().ok());
            (o.status.success(), replayed, text)
        }
        Err(e) => (false, None, format!("spawn generate-input: {e}")),
    }
}

fn witness_faults() -> bool {
    std::fs::read_to_string(common::CONFIG_PATH)
        .ok()
        .and_then(|s| serde_json::from_str::<Config>(&s).ok())
        .is_some_and(|c| c.zones_witness_faults)
}

/// Draws a u64 from Bedrock's controlled getrandom stream (on the input tape,
/// so it replays). One per probe.
fn draw_u64() -> u64 {
    let mut buf = [0u8; 8];
    match std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
    {
        Ok(()) => u64::from_le_bytes(buf),
        // getrandom cannot fail under Bedrock; fall back deterministically.
        Err(_) => 0,
    }
}

/// Draws a witness mutation kind (one per mutated batch).
fn draw_mutation() -> WitnessMutation {
    WitnessMutation::of(draw_u64())
}

/// Mutates the honest witness at `path` with `mutation` and replays the result
/// offline through the SPF (`tempo-zone-prover-utils replay-witness`, a
/// read-only command that submits nothing). A sound SPF rejects it; if it
/// instead reproduces the committed hash, that is a soundness failure.
fn mutate_and_replay(
    batch: &zones::ZoneBatch,
    l1_block: u64,
    path: &str,
    mutation: WitnessMutation,
) -> MutationResult {
    let mut m = MutationResult {
        batch_index: batch.index,
        l1_block,
        committed_hash: batch.next_block_hash,
        mutation,
        outcome: MutationOutcome::Skipped,
        replayed_hash: None,
        detail: String::new(),
    };
    let witness: serde_json::Value = match std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(w) => w,
        None => {
            m.detail = "honest witness unavailable".into();
            return m;
        }
    };
    let Some(mutated) = apply_mutation(witness, mutation) else {
        m.detail = format!("{mutation:?} not applicable to this witness");
        return m;
    };
    let mutated_path = format!("{path}.mutated");
    if let Err(e) = std::fs::write(&mutated_path, mutated.to_string()) {
        m.detail = format!("write mutated witness: {e}");
        return m;
    }
    let out = Command::new("tempo-zone-prover-utils")
        .args(["replay-witness", "--input", &mutated_path])
        .args(["--chain", zones::GENESIS_PATH, "--log-filter", "error"])
        .stdin(Stdio::null())
        .output();
    let _ = std::fs::remove_file(&mutated_path);
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            m.detail = format!("spawn replay-witness: {e}");
            return m;
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if let Some(hash) = field(&text, "REPLAY ") {
        let replayed: Option<B256> = hash.trim().parse().ok();
        m.replayed_hash = replayed;
        m.outcome = if replayed == Some(batch.next_block_hash) {
            MutationOutcome::Accepted
        } else {
            MutationOutcome::Diverged
        };
    } else if let Some(err) = field(&text, "REPLAY-ERR ") {
        m.outcome = MutationOutcome::Rejected;
        m.detail = err.chars().take(200).collect();
    } else {
        m.detail = format!("no replay-witness result: {}", tail(&text, 200));
    }
    m
}

/// Applies `mutation` to a witness JSON (camelCase keys; see
/// [`WitnessMutation`]). `None` when the field or array it targets is absent.
/// Value-only, so the result still deserializes as a `BatchWitness`.
pub fn apply_mutation(
    mut w: serde_json::Value,
    mutation: WitnessMutation,
) -> Option<serde_json::Value> {
    use WitnessMutation::*;
    let bump = |v: &mut serde_json::Value| -> Option<()> {
        let n = v.as_u64()?;
        *v = serde_json::json!(n + 1);
        Some(())
    };
    match mutation {
        WrongAnchorBlock => bump(w.get_mut("publicInputs")?.get_mut("anchorBlockNumber")?)?,
        WrongTempoBlock => bump(w.get_mut("publicInputs")?.get_mut("tempoBlockNumber")?)?,
        WrongWithdrawalBatchIndex => bump(
            w.get_mut("publicInputs")?
                .get_mut("expectedWithdrawalBatchIndex")?,
        )?,
        TamperAnchorHash => flip_hex(w.get_mut("publicInputs")?.get_mut("anchorBlockHash")?)?,
        // parentHeader serializes as a header object (serde_rlp is
        // human-readable under JSON); tamper its state root.
        TamperParentHeader => flip_hex(w.get_mut("parentHeader")?.get_mut("stateRoot")?)?,
        AlterStateNode => flip_hex(first_node(&mut w, "zoneStateWitness")?)?,
        AlterTempoNode => flip_hex(first_node(&mut w, "tempoStateWitness")?)?,
        DropStateNode => drop_last(w.get_mut("zoneStateWitness")?.get_mut("nodePool")?)?,
        DropZoneBlock => drop_last(w.get_mut("zoneBlocks")?)?,
        BumpZoneTimestamp => bump(
            w.get_mut("zoneBlocks")?
                .as_array_mut()?
                .first_mut()?
                .get_mut("timestamp")?,
        )?,
    }
    Some(w)
}

fn first_node<'a>(
    w: &'a mut serde_json::Value,
    witness: &str,
) -> Option<&'a mut serde_json::Value> {
    w.get_mut(witness)?
        .get_mut("nodePool")?
        .as_array_mut()?
        .first_mut()
}

/// Flips the last hex nibble of a `0x`-prefixed string, changing its value
/// while keeping it valid hex.
fn flip_hex(v: &mut serde_json::Value) -> Option<()> {
    let s = v.as_str()?;
    let hex = s.strip_prefix("0x").filter(|h| !h.is_empty())?;
    let mut bytes: Vec<char> = hex.chars().collect();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == '0' { '1' } else { '0' };
    *v = serde_json::json!(format!("0x{}", bytes.into_iter().collect::<String>()));
    Some(())
}

/// Removes the last element of a JSON array, if it has more than one.
fn drop_last(v: &mut serde_json::Value) -> Option<()> {
    let a = v.as_array_mut()?;
    if a.len() < 2 {
        return None;
    }
    a.pop();
    Some(())
}

/// The value after `label` on its summary line.
fn field<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix(label))
        .map(str::trim)
}

fn tail(text: &str, chars: usize) -> String {
    let t: Vec<char> = text.trim().chars().collect();
    t[t.len().saturating_sub(chars)..].iter().collect()
}

fn children_max_rss_kb() -> u64 {
    nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_CHILDREN)
        .map(|u| u.max_rss() as u64)
        .unwrap_or(0)
}

/// The driver's seed for load generation `generation`: per run seed, a fresh
/// stream per generation.
pub fn load_seed(spec_seed: u64, generation: u64) -> u64 {
    spec_seed.wrapping_mul(1_000_003).wrapping_add(generation)
}

/// Starts txgen's zone-backing campaign as container `zones-load`. It
/// restarts itself (next seed) whenever a campaign ends: on a property
/// failure (which the oracle reads from its log) and on infrastructure
/// errors (e.g. a settlement timeout while a node was down).
pub fn start_load(config: &Config, generation: u64, seed: u64) -> io::Result<()> {
    let endpoints = ZoneEndpoints::of(config);
    let image = if config.load.image.is_empty() {
        zones::IMAGE
    } else {
        &config.load.image
    };
    let script = format!(
        "i=0; while true; do txgen-tempo-property \
         --l1-rpc-url http://127.0.0.1:8545 --zone-rpc-url {rpc} \
         --zone-private-rpc-url {private} --zone-id {id} --zone-chain-id {chain} \
         --portal {PORTAL} --token {TOKEN} --continuous --max-steps 12 \
         --settlement-timeout-secs 120 --verify-every-steps 0 \
         --failure-directory /tmp/property-failures --seed $(({seed} + i * 7919)); \
         echo \"zones-load: campaign exited $?\"; i=$((i + 1)); sleep 1; done",
        rpc = endpoints.rpc,
        private = endpoints.private_rpc,
        id = zones::ZONE_ID,
        chain = zones::ZONE_CHAIN_ID,
    );
    let status = Command::new("podman")
        .args([
            "run",
            "-d",
            "--name",
            zones::LOAD_CONTAINER,
            "--network",
            "host",
        ])
        .args(["-e", &format!("PRIVATE_KEY={}", zones::LOAD_KEY)])
        .args(["-e", "RUST_LOG=info"])
        .args(["--entrypoint", "/bin/sh", image, "-c", &script])
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("podman run zones-load: {status}")));
    }
    common::emit_event(
        "load",
        "zones-driver",
        Some(zones::LOAD_CONTAINER),
        json!({"generation": generation, "seed": seed}),
    );
    // The TIP-403 policy driver runs once (generation 0): a one-shot flow
    // then idle. It uses its own account (dev 2), so it does not race the
    // zones-load sender (dev 1).
    if config.zones_policy && generation == 0 {
        start_policy(image)?;
    }
    Ok(())
}

/// Starts the policy driver container (`policy.sh`), container `zones-policy`.
fn start_policy(image: &str) -> io::Result<()> {
    let status = Command::new("podman")
        .args([
            "run",
            "-d",
            "--name",
            zones::POLICY_CONTAINER,
            "--network",
            "host",
        ])
        .args(["-e", "RUST_LOG=warn"])
        .args([
            "--entrypoint",
            "/bin/bash",
            image,
            "/usr/local/bin/policy.sh",
        ])
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "podman run zones-policy: {status}"
        )));
    }
    common::emit_event(
        "load",
        "zones-policy",
        Some(zones::POLICY_CONTAINER),
        json!({}),
    );
    Ok(())
}

/// `tempo-dst zones-watch <secs>`: E12 against live nodes outside Bedrock
/// (`TEMPO_DST_RPC` for the L1; the zone at [`ZONE_RPC_URL`]), printing every
/// verdict. Prover and driver lines are read from stdin when piped
/// (`docker logs -f zone-prover | tempo-dst zones-watch 300`).
pub fn watch(secs: u64) {
    use std::io::BufRead;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let start = common::guest_time_ns();
    let endpoints = ZoneEndpoints::from_env();
    let mut oracle = zones::ZonesOracle::new(60, start);
    let mut chain = RpcZones::new(endpoints);
    let mut cluster = (endpoints == ZoneEndpoints::CLUSTER).then(|| {
        (
            crate::zones_cluster::ClusterOracle::new(crate::zones_cluster::NODES, 60, start),
            crate::zones_cluster::RpcCluster,
        )
    });
    let mut failed = false;
    while common::guest_time_ns() - start < secs * 1_000_000_000 {
        std::thread::sleep(Duration::from_secs(1));
        let now = common::guest_time_ns();
        let mut out = Vec::new();
        for line in rx.try_iter() {
            out.extend(oracle.on_prover_line(&line));
            out.extend(oracle.on_mutation_line(&line));
            out.extend(oracle.on_l1fault_line(&line));
            out.extend(oracle.on_policy_line(&line));
            out.extend(oracle.on_load_line(&line));
        }
        out.extend(oracle.tick(&mut chain, now));
        if let Some((c, rpc)) = cluster.as_mut() {
            out.extend(c.tick(rpc, now));
        }
        for v in out {
            failed |= matches!(v, crate::verdict::Verdict::Always(false, _));
            println!("{v:?}");
        }
    }
    if failed {
        std::process::exit(1);
    }
}
