use super::*;
use crate::common::DstEvent;

const S: u64 = 1_000_000_000;

/// One chain: canonical blocks `(hash, parent, events, state)` from 0.
struct FakeSide<E, S> {
    tag: u8,
    fork: u8,
    blocks: Vec<(B256, B256, Vec<E>, S)>,
    down: bool,
}

impl<E: Clone, St: Clone + Default> FakeSide<E, St> {
    fn new(tag: u8) -> Self {
        let mut s = FakeSide {
            tag,
            fork: 0,
            blocks: Vec::new(),
            down: false,
        };
        s.push(vec![], St::default());
        s
    }
    fn hash(&self, n: u64) -> B256 {
        self.blocks[n as usize].0
    }
    fn push(&mut self, events: Vec<E>, state: St) -> u64 {
        let n = self.blocks.len() as u64;
        let mut h = [0u8; 32];
        h[0] = self.tag;
        h[1] = self.fork;
        h[24..].copy_from_slice(&n.to_be_bytes());
        let parent = self.blocks.last().map_or(B256::ZERO, |b| b.0);
        self.blocks.push((B256::from(h), parent, events, state));
        n
    }
    /// Drops blocks from `n` on; later pushes get new hashes.
    fn rebuild_from(&mut self, n: u64) {
        self.blocks.truncate(n as usize);
        self.fork += 1;
    }
    fn up(&self) -> Result<(), String> {
        if self.down {
            Err("down".into())
        } else {
            Ok(())
        }
    }
}

impl<E: Clone, St: Clone + Default> Side for FakeSide<E, St> {
    type Event = E;
    type State = St;
    fn head(&mut self) -> Result<u64, String> {
        self.up()?;
        Ok(self.blocks.len() as u64 - 1)
    }
    fn block(&mut self, number: u64) -> Result<Option<BlockRef>, String> {
        self.up()?;
        Ok(self.blocks.get(number as usize).map(|b| BlockRef {
            number,
            hash: b.0,
            parent: b.1,
        }))
    }
    fn events(&mut self, from: u64, to: u64) -> Result<Vec<(B256, E)>, String> {
        self.up()?;
        Ok(self.blocks[from as usize..=to as usize]
            .iter()
            .flat_map(|b| b.2.iter().map(move |e| (b.0, e.clone())))
            .collect())
    }
    fn state(&mut self, hash: B256) -> Result<St, String> {
        self.up()?;
        self.blocks
            .iter()
            .find(|b| b.0 == hash)
            .map(|b| b.3.clone())
            .ok_or_else(|| "unknown block".into())
    }
    fn number_of(&mut self, hash: B256) -> Result<Option<u64>, String> {
        self.up()?;
        Ok(self
            .blocks
            .iter()
            .position(|b| b.0 == hash)
            .map(|i| i as u64))
    }
}

struct World {
    l1: FakeSide<L1Event, L1State>,
    zone: FakeSide<ZoneEvent, ZoneState>,
}

impl ZonesChain for World {
    type L1 = FakeSide<L1Event, L1State>;
    type Zone = FakeSide<ZoneEvent, ZoneState>;
    fn l1(&mut self) -> &mut Self::L1 {
        &mut self.l1
    }
    fn zone(&mut self) -> &mut Self::Zone {
        &mut self.zone
    }
}

const TAG: B256 = B256::with_last_byte(0x7a);
const W: B256 = B256::with_last_byte(0x77);
const USER: Address = address!("70997970c51812dc3a010c7d01b50e0d17dc79c8");

fn u(n: u64) -> U256 {
    U256::from(n)
}

fn request(amount: u64) -> ZoneEvent {
    ZoneEvent::Request(ZoneWithdrawalRequest {
        index: 0,
        sender: USER,
        token: TOKEN,
        to: USER,
        amount: u(amount),
        fallback_nonce: 1,
        sender_tag: TAG,
    })
}

fn payout(amount: u64) -> L1Event {
    L1Event::Payout(PortalPayout {
        sender_tag: TAG,
        to: USER,
        token: TOKEN,
        amount: u(amount),
        callback_success: true,
    })
}

fn l1_state(balance: u64) -> L1State {
    L1State {
        balance: u(balance),
        ..L1State::default()
    }
}

fn zone_state(tempo_block: u64, supply: u64, processed: u64, batch: u64) -> ZoneState {
    ZoneState {
        tempo_block,
        supply: u(supply),
        processed_deposits: processed,
        last_batch_hash: if batch > 0 { W } else { B256::ZERO },
        last_batch_index: batch,
    }
}

/// The honest lifecycle: a deposit of 100 is credited, 40 is withdrawn,
/// batch 1 settles the withdrawal and the portal pays it out. `balance4`
/// is the escrow after the payout (honest: 60).
fn honest(balance4: u64) -> World {
    let mut w = World {
        l1: FakeSide::new(1),
        zone: FakeSide::new(2),
    };
    w.l1.push(
        vec![L1Event::Deposit {
            number: 1,
            token: TOKEN,
            net_amount: u(100),
        }],
        l1_state(100),
    );
    w.zone.push(
        vec![ZoneEvent::DepositProcessed {
            token: TOKEN,
            amount: u(100),
            deposit_hash: B256::repeat_byte(0xd1),
        }],
        zone_state(1, 100, 1, 0),
    );
    w.l1.push(vec![], l1_state(100));
    let z2 = w.zone.push(vec![request(40)], zone_state(2, 60, 1, 1));
    let settled = w.zone.hash(z2);
    w.l1.push(
        vec![L1Event::Batch(ZoneBatch {
            index: 1,
            next_block_hash: settled,
            withdrawal_queue_hash: W,
            last_processed_deposit: 1,
        })],
        L1State {
            balance: u(100),
            settled_hash: settled,
            batch_index: 1,
        },
    );
    w.l1.push(
        vec![payout(40)],
        L1State {
            balance: u(balance4),
            settled_hash: settled,
            batch_index: 1,
        },
    );
    w.zone.push(vec![], zone_state(4, 60, 1, 1));
    w
}

fn run(o: &mut ZonesOracle, w: &mut World, ticks: u64) -> Vec<Verdict> {
    (0..ticks).flat_map(|t| o.tick(w, t * S)).collect()
}

fn failures(v: &[Verdict]) -> Vec<String> {
    v.iter()
        .filter_map(|v| match v {
            Verdict::Always(false, f) => Some(f.signature.clone()),
            _ => None,
        })
        .collect()
}

fn covered(v: &[Verdict]) -> Vec<String> {
    v.iter()
        .filter_map(|v| match v {
            Verdict::Sometimes(true, f) => Some(f.signature.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn honest_lifecycle_passes_and_covers() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(60, 0).live_from_genesis();
    let v = run(&mut o, &mut w, 3);
    assert_eq!(failures(&v), Vec::<String>::new());
    let c = covered(&v);
    for sig in [
        "S/zones-deposit-credited",
        "S/zones-batch-submitted",
        "S/zones-batch-with-withdrawals",
        "S/zones-withdrawal-finalized",
        "S/zones-solvency-checked",
    ] {
        assert!(c.contains(&sig.to_string()), "{sig} in {c:?}");
    }
}

#[test]
fn coverage_counts_only_blocks_after_the_oracle_started() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(60, 0);
    let c = covered(&run(&mut o, &mut w, 3));
    // Everything so far predates the oracle (e.g. the warmup's batch 1).
    assert!(
        !c.iter()
            .any(|s| s == "S/zones-batch-submitted" || s == "S/zones-deposit-credited"),
        "{c:?}"
    );
    batch(&mut w, 2, W);
    let c = covered(&o.tick(&mut w, 4 * S));
    assert!(c.contains(&"S/zones-batch-submitted".to_string()), "{c:?}");
}

#[test]
fn escrow_below_liabilities_is_insolvent() {
    let mut w = honest(59);
    let v = run(&mut ZonesOracle::new(60, 0).live_from_genesis(), &mut w, 3);
    assert_eq!(failures(&v), ["E12/zones-outbox-insolvent"]);
}

#[test]
fn paying_a_tag_twice_is_a_double_withdrawal() {
    let mut w = honest(60);
    w.l1.push(vec![payout(40)], l1_state(20));
    w.zone.push(vec![], zone_state(5, 60, 1, 1));
    let f = failures(&run(
        &mut ZonesOracle::new(60, 0).live_from_genesis(),
        &mut w,
        3,
    ));
    assert!(f.contains(&"E12/zones-double-withdrawal".into()), "{f:?}");
    // The second payout also exceeds what was requested.
    assert!(f.contains(&"E12/zones-withdrawal-unbacked".into()), "{f:?}");
}

#[test]
fn payout_without_request_is_unrequested() {
    let mut w = honest(60);
    // Drop the zone's request: the zone never burned anything.
    w.zone.blocks[2].2.clear();
    let f = failures(&run(
        &mut ZonesOracle::new(60, 0).live_from_genesis(),
        &mut w,
        3,
    ));
    assert!(
        f.contains(&"E12/zones-withdrawal-unrequested".into()),
        "{f:?}"
    );
}

#[test]
fn payout_of_unsettled_withdrawal_is_unproven() {
    let mut w = honest(60);
    // The request moves to zone block 3, past the settled block 2.
    w.zone.blocks[2].2.clear();
    w.zone.blocks[3].2.push(request(40));
    let f = failures(&run(
        &mut ZonesOracle::new(60, 0).live_from_genesis(),
        &mut w,
        3,
    ));
    assert!(f.contains(&"E12/zones-withdrawal-unproven".into()), "{f:?}");
}

#[test]
fn payout_amount_differs_from_request() {
    let mut w = honest(60);
    w.l1.blocks[4].2 = vec![payout(41)];
    let f = failures(&run(
        &mut ZonesOracle::new(60, 0).live_from_genesis(),
        &mut w,
        3,
    ));
    assert!(f.contains(&"E12/zones-withdrawal-mismatch".into()), "{f:?}");
}

/// A new zone block whose outbox reports batch `index` (queue hash `wqh`),
/// then an L1 block submitting batch `index` for it.
fn batch(w: &mut World, index: u64, wqh: B256) {
    let tempo = w.l1.blocks.len() as u64 - 1;
    let z = w.zone.push(
        vec![],
        ZoneState {
            last_batch_hash: wqh,
            last_batch_index: index,
            ..zone_state(tempo, 60, 1, 1)
        },
    );
    let hash = w.zone.hash(z);
    let balance = w.l1.blocks.last().unwrap().3.balance;
    w.l1.push(
        vec![L1Event::Batch(ZoneBatch {
            index,
            next_block_hash: hash,
            withdrawal_queue_hash: wqh,
            last_processed_deposit: 1,
        })],
        L1State {
            balance,
            settled_hash: hash,
            batch_index: index,
        },
    );
    // The zone imports the submission block.
    w.zone.push(
        vec![],
        ZoneState {
            last_batch_hash: wqh,
            last_batch_index: index,
            ..zone_state(tempo + 1, 60, 1, 1)
        },
    );
}

#[test]
fn skipped_batch_index_is_a_gap() {
    let mut w = honest(60);
    batch(&mut w, 3, W);
    let f = failures(&run(
        &mut ZonesOracle::new(60, 0).live_from_genesis(),
        &mut w,
        3,
    ));
    assert_eq!(f, ["E12/zones-batch-index-gap"]);
}

#[test]
fn batch_committing_other_zone_state_is_a_mismatch() {
    let mut w = honest(60);
    batch(&mut w, 2, B256::with_last_byte(9));
    // The batch commits to another withdrawal queue than the outbox's.
    let Some(L1Event::Batch(b)) = w.l1.blocks[5].2.first_mut() else {
        unreachable!()
    };
    b.withdrawal_queue_hash = W;
    let f = failures(&run(
        &mut ZonesOracle::new(60, 0).live_from_genesis(),
        &mut w,
        3,
    ));
    assert_eq!(f, ["E12/zones-batch-commitment-mismatch"]);
}

#[test]
fn batch_settling_a_block_the_zone_lacks_is_unknown() {
    let mut w = honest(60);
    w.l1.push(
        vec![L1Event::Batch(ZoneBatch {
            index: 2,
            next_block_hash: B256::with_last_byte(0xee),
            withdrawal_queue_hash: W,
            last_processed_deposit: 1,
        })],
        L1State {
            balance: u(60),
            settled_hash: B256::with_last_byte(0xee),
            batch_index: 2,
        },
    );
    w.zone.push(vec![], zone_state(6, 60, 1, 1));
    let f = failures(&run(
        &mut ZonesOracle::new(60, 0).live_from_genesis(),
        &mut w,
        3,
    ));
    assert_eq!(f, ["E12/zones-batch-unknown-block"]);
}

#[test]
fn portal_state_must_follow_the_batch() {
    let mut w = honest(60);
    w.l1.blocks[3].3.settled_hash = B256::ZERO;
    let f = failures(&run(
        &mut ZonesOracle::new(60, 0).live_from_genesis(),
        &mut w,
        3,
    ));
    assert_eq!(f, ["E12/zones-portal-state-mismatch"]);
}

#[test]
fn settled_zone_block_lost_after_rebuild() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(60, 0).live_from_genesis();
    assert!(failures(&run(&mut o, &mut w, 3)).is_empty());
    // The zone rebuilds from block 2 on: the settled block is gone.
    w.zone.rebuild_from(2);
    w.zone.push(vec![request(40)], zone_state(2, 60, 1, 1));
    w.zone.push(vec![], zone_state(4, 60, 1, 1));
    let f = failures(&run(&mut o, &mut w, 2));
    assert!(f.contains(&"E12/zones-settled-block-lost".into()), "{f:?}");
}

#[test]
fn rebuilt_unfinalized_l1_blocks_are_reread_not_double_counted() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(60, 0).live_from_genesis();
    assert!(failures(&run(&mut o, &mut w, 3)).is_empty());
    // A crash rebuilds L1 block 4 with the same payout.
    let state = w.l1.blocks[4].3;
    w.l1.rebuild_from(4);
    w.l1.push(vec![payout(40)], state);
    w.l1.push(vec![], state);
    w.zone.push(vec![], zone_state(5, 60, 1, 1));
    assert_eq!(failures(&run(&mut o, &mut w, 2)), Vec::<String>::new());
}

#[test]
fn batch_liveness_is_excused_while_down() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(10, 0).live_from_genesis();
    assert!(failures(&run(&mut o, &mut w, 1)).is_empty());
    let kill = |kind: &str, c: &str| DstEvent {
        source: "nemesis".into(),
        kind: kind.into(),
        container: Some(c.into()),
        guest_time_ns: 0,
        detail: serde_json::Value::Null,
    };
    o.on_event(&kill("kill", ZONE_CONTAINER), 5 * S);
    w.zone.down = true;
    assert!(failures(&o.tick(&mut w, 30 * S)).is_empty());
    o.on_event(&kill("restart", ZONE_CONTAINER), 31 * S);
    w.zone.down = false;
    assert!(failures(&o.tick(&mut w, 35 * S)).is_empty());
    // No batch for 10s after the restart.
    let f = failures(&o.tick(&mut w, 42 * S));
    assert_eq!(f, ["E12/zones-batch-stalled"]);
    // A batch after the restart covers recovery.
    batch(&mut w, 2, W);
    let c = covered(&o.tick(&mut w, 43 * S));
    assert!(c.contains(&"S/zones-batch-after-restart".into()), "{c:?}");
}

#[test]
fn settled_withdrawal_never_paid_is_stuck() {
    let mut w = honest(60);
    w.l1.blocks[4].2.clear();
    w.l1.blocks[4].3.balance = u(100);
    let mut o = ZonesOracle::new(10, 0).live_from_genesis();
    assert!(failures(&run(&mut o, &mut w, 3)).is_empty());
    // Batches keep landing (no stall), the withdrawal never pays.
    batch(&mut w, 2, W);
    let f = failures(&o.tick(&mut w, 12 * S));
    assert_eq!(f, ["E12/zones-withdrawal-stuck"]);
}

#[test]
fn imported_deposit_never_processed_is_stuck() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(10, 0).live_from_genesis();
    run(&mut o, &mut w, 3);
    w.l1.push(
        vec![L1Event::Deposit {
            number: 2,
            token: TOKEN,
            net_amount: u(5),
        }],
        l1_state(65),
    );
    batch(&mut w, 2, W);
    assert!(failures(&o.tick(&mut w, 4 * S)).is_empty());
    // Batches keep landing; the deposit never gets processed.
    batch(&mut w, 3, W);
    let f = failures(&o.tick(&mut w, 15 * S));
    assert_eq!(f, ["E12/zones-deposit-stuck"]);
}

#[test]
fn liabilities_track_every_terminal_path() {
    let l1 = [
        L1Event::Deposit {
            number: 1,
            token: TOKEN,
            net_amount: u(1000),
        },
        L1Event::Deposit {
            number: 2,
            token: TOKEN,
            net_amount: u(7),
        },
        payout(40),
        L1Event::DepositBounceBack {
            token: TOKEN,
            retired: u(11),
        },
        L1Event::DepositBounceBackPending {
            token: TOKEN,
            amount: u(9),
            retired: u(10),
        },
        L1Event::RefundClaimed {
            token: TOKEN,
            amount: u(4),
        },
    ];
    let zone = [
        request(100),
        ZoneEvent::BounceBackReminted {
            token: TOKEN,
            amount: u(3),
        },
        ZoneEvent::BounceBackPending {
            token: TOKEN,
            amount: u(2),
        },
        ZoneEvent::RefundClaimed {
            token: TOKEN,
            amount: u(1),
        },
    ];
    let owed = liabilities(&l1, &zone, u(500), 1).unwrap();
    assert_eq!(
        owed,
        Liabilities {
            supply: u(500),
            pending_deposits: u(7),
            // 100 - (40 + 11) - 3 - (2 + 10)
            pending_withdrawals: u(34),
            portal_refunds: u(5),
            inbox_refunds: u(1),
        }
    );
    // Other tokens are ignored.
    let other = [L1Event::Payout(PortalPayout {
        token: Address::ZERO,
        ..match payout(1000) {
            L1Event::Payout(p) => p,
            _ => unreachable!(),
        }
    })];
    assert_eq!(
        liabilities(&other, &zone, u(0), 0)
            .unwrap()
            .pending_withdrawals,
        u(95)
    );
    assert_eq!(
        liabilities(&l1, &zone, u(0), 3).unwrap_err().0,
        "E12/zones-deposit-unbacked"
    );
    assert_eq!(
        liabilities(&[payout(200)], &zone, u(0), 0).unwrap_err().0,
        "E12/zones-withdrawal-unbacked"
    );
}

fn log(address: Address, topics: Vec<B256>, words: &[B256], tx: B256) -> FullLog {
    FullLog {
        address,
        topics,
        data: words.iter().flat_map(|w| w.0).collect::<Vec<u8>>().into(),
        block_number: 7,
        block_hash: B256::with_last_byte(7),
        transaction_hash: tx,
    }
}

fn w64(n: u64) -> B256 {
    B256::from(U256::from(n))
}

#[test]
fn decodes_portal_and_outbox_events() {
    let t = topics();
    let deposit = log(
        PORTAL,
        vec![t.deposit_made, B256::ZERO, USER.into_word()],
        &[
            TOKEN.into_word(),
            w64(990),
            w64(10),
            w64(0),
            B256::ZERO,
            w64(0),
            w64(0x180),
            B256::ZERO,
            B256::ZERO,
            USER.into_word(),
            w64(3),
        ],
        B256::ZERO,
    );
    assert_eq!(
        decode_l1(&deposit),
        Some(L1Event::Deposit {
            number: 3,
            token: TOKEN,
            net_amount: u(990)
        })
    );
    let paid = log(
        PORTAL,
        vec![t.withdrawal_processed, USER.into_word(), TAG],
        &[TOKEN.into_word(), w64(40), w64(1)],
        B256::ZERO,
    );
    assert_eq!(decode_l1(&paid), Some(payout(40)));
    // Not the portal: ignored.
    assert_eq!(
        decode_l1(&log(ZONE_OUTBOX, paid.topics.clone(), &[], B256::ZERO)),
        None
    );
    let batch = log(
        PORTAL,
        vec![t.batch_submitted, w64(5), w64(2)],
        &[B256::ZERO, TAG, W, w64(4), w64(1)],
        B256::ZERO,
    );
    assert_eq!(
        decode_l1(&batch),
        Some(L1Event::Batch(ZoneBatch {
            index: 5,
            next_block_hash: TAG,
            withdrawal_queue_hash: W,
            last_processed_deposit: 4
        }))
    );
    let tx = B256::with_last_byte(0x42);
    let requested = log(
        ZONE_OUTBOX,
        vec![t.withdrawal_requested, w64(0), USER.into_word()],
        &[
            TOKEN.into_word(),
            USER.into_word(),
            w64(40),
            w64(1),
            B256::ZERO,
            w64(0),
            w64(9),
        ],
        tx,
    );
    let Some(ZoneEvent::Request(r)) = decode_zone(&requested) else {
        panic!("not decoded");
    };
    assert_eq!((r.amount, r.fallback_nonce, r.to), (u(40), 9, USER));
    assert_eq!(r.sender_tag, sender_tag(USER, tx, 9));
}

#[test]
fn sender_tag_is_packed_keccak() {
    let tx = B256::repeat_byte(0x11);
    let mut packed = USER.to_vec();
    packed.extend_from_slice(tx.as_slice());
    packed.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 2]);
    assert_eq!(sender_tag(USER, tx, 0x102), keccak256(packed));
}

fn proof_line(status: &str, replayed: Option<B256>) -> String {
    let r = ProofResult {
        batch_index: 1,
        l1_block: 3,
        next_block_hash: TAG,
        status: serde_json::from_value(serde_json::json!(status)).unwrap(),
        replayed_hash: replayed,
        zone_blocks: Some("1..=2 (2)".into()),
        secs: 0.5,
        max_rss_kb: 1000,
        error: String::new(),
    };
    format!("{PROVER_LINE}{}", serde_json::to_string(&r).unwrap())
}

#[test]
fn prover_results_cover_or_fail() {
    let mut o = ZonesOracle::new(60, 0).live_from_genesis();
    assert!(o.on_prover_line(&proof_line("ok", Some(TAG))).is_empty());
    let mut w = honest(60);
    assert!(covered(&o.tick(&mut w, 0)).contains(&"S/zones-batch-proven".into()));
    // A proof of a batch from before the oracle started is not coverage.
    let mut o = ZonesOracle::new(60, 0);
    o.on_prover_line(&proof_line("ok", Some(TAG)));
    assert!(!covered(&o.tick(&mut honest(60), 0)).contains(&"S/zones-batch-proven".into()));
    // The prover saw batch 1 commit TAG, the oracle saw zone block 2's hash.
    assert_eq!(
        failures(&o.on_prover_line(&proof_line("ok", Some(TAG)))),
        ["E12/zones-proof-replay-failed"]
    );
    // A settled batch whose honest replay produces another hash means the
    // portal advanced an invalid state.
    let mut o = ZonesOracle::new(60, 0);
    assert_eq!(
        failures(&o.on_prover_line(&proof_line("ok", Some(W)))),
        ["E12/zones-invalid-state-advanced"]
    );
    // A settled batch the SPF rejects should never have been submittable.
    let mut o = ZonesOracle::new(60, 0).live_from_genesis();
    assert_eq!(
        failures(&o.on_prover_line(&proof_line("spf-failed", None))),
        ["E12/zones-invalid-batch-submitted"]
    );
    assert!(o
        .on_prover_line(&proof_line("unavailable", None))
        .is_empty());
    assert!(o.on_prover_line("zone-prover: retrying").is_empty());
    let mut o = ZonesOracle::new(60, 0).live_from_genesis();
    assert_eq!(
        failures(&o.on_prover_line(&proof_line("ok", None))),
        ["E12/zones-invalid-state-advanced"]
    );
    let invalid = proof_line("ok", Some(TAG)).replace("\"ok\"", "\"unknown\"");
    assert_eq!(
        failures(&o.on_prover_line(&invalid)),
        ["E12/zones-proof-result-invalid"]
    );
}

#[test]
fn unproven_batches_fail_after_the_prover_slack() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(10, 0).live_from_genesis();
    run(&mut o, &mut w, 3);
    // Keep batches landing so only the prover lags.
    for (i, t) in [(2, 20), (3, 29)] {
        batch(&mut w, i, W);
        assert!(failures(&o.tick(&mut w, t * S)).is_empty());
    }
    let f = failures(&o.tick(&mut w, 31 * S));
    assert_eq!(f, ["E12/zones-batch-unproven"]);
}

#[test]
fn txgen_underbacked_report_fails() {
    let mut o = ZonesOracle::new(60, 0).live_from_genesis();
    let line =
        "[zone-property] FAIL seed=3 case=0 step=4 error=Portal is underbacked by 5 base units";
    assert_eq!(
        failures(&o.on_load_line(line)),
        ["E12/txgen-portal-underbacked"]
    );
    assert_eq!(
        covered(
            &o.on_load_line("[zone-property] terminal reason=withdrawal_paid lifecycle=x events=2")
        ),
        ["S/txgen-withdrawal-paid"]
    );
    assert!(o.on_load_line("unrelated").is_empty());
}

#[test]
fn zone_log_patterns_are_named_e12() {
    let v = scan_zone_line("thread 'main' panicked at crates/x.rs:1:1");
    assert_eq!(failures(&v), ["E12/zone-panic"]);
    assert!(scan_zone_line("2026 ERROR zone::l1: connection refused").is_empty());
}

/// A minimal but schema-complete witness JSON (camelCase) for mutation tests.
fn witness_json() -> serde_json::Value {
    serde_json::json!({
        "publicInputs": {
            "parentChainId": 1337,
            "zoneId": 1,
            "tempoBlockNumber": 100,
            "anchorBlockNumber": 100,
            "anchorBlockHash": "0xabc0",
            "expectedWithdrawalBatchIndex": 5,
        },
        "parentHeader": {"stateRoot": "0xdead0", "parentHash": "0xbeef0"},
        "zoneBlocks": [
            {"number": 10, "timestamp": 1000},
            {"number": 11, "timestamp": 1001},
        ],
        "zoneStateWitness": {"nodePool": ["0xaa00", "0xbb11"], "bytecodes": []},
        "tempoStateWitness": {"initialTempoHeaderRlp": "0xcc", "nodePool": ["0xdd22"]},
        "tempoAncestryHeaders": [],
    })
}

#[test]
fn every_mutation_kind_changes_the_witness() {
    use crate::zones_live::apply_mutation;
    let base = witness_json();
    for m in WitnessMutation::ALL {
        let out = apply_mutation(base.clone(), m).unwrap_or_else(|| panic!("{m:?} not applied"));
        assert_ne!(out, base, "{m:?} left the witness unchanged");
        // Value-only: the same top-level keys remain.
        assert_eq!(
            out.as_object().unwrap().keys().collect::<Vec<_>>(),
            base.as_object().unwrap().keys().collect::<Vec<_>>(),
            "{m:?} changed the schema",
        );
    }
    let seen: std::collections::BTreeSet<_> = (0..WitnessMutation::ALL.len() as u64)
        .map(WitnessMutation::of)
        .collect();
    assert_eq!(seen.len(), WitnessMutation::ALL.len());
}

#[test]
fn mutation_examples_hit_the_right_field() {
    use crate::zones_live::apply_mutation;
    let w = witness_json();
    let anchor = apply_mutation(w.clone(), WitnessMutation::WrongAnchorBlock).unwrap();
    assert_eq!(anchor["publicInputs"]["anchorBlockNumber"], 101);
    let drop = apply_mutation(w.clone(), WitnessMutation::DropZoneBlock).unwrap();
    assert_eq!(drop["zoneBlocks"].as_array().unwrap().len(), 1);
    let node = apply_mutation(w.clone(), WitnessMutation::DropStateNode).unwrap();
    assert_eq!(
        node["zoneStateWitness"]["nodePool"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let hash = apply_mutation(w.clone(), WitnessMutation::TamperAnchorHash).unwrap();
    assert_eq!(hash["publicInputs"]["anchorBlockHash"], "0xabc1");
    // A single-block batch cannot drop its only block: not applicable.
    let mut single = w;
    single["zoneBlocks"].as_array_mut().unwrap().pop();
    assert!(apply_mutation(single, WitnessMutation::DropZoneBlock).is_none());
}

fn mutation_line(
    mutation: WitnessMutation,
    outcome: MutationOutcome,
    replayed: Option<B256>,
) -> String {
    let m = MutationResult {
        batch_index: 2,
        l1_block: 7,
        committed_hash: TAG,
        mutation,
        outcome,
        replayed_hash: replayed,
        detail: String::new(),
    };
    format!("{MUTATION_LINE}{}", serde_json::to_string(&m).unwrap())
}

#[test]
fn accepted_mutation_is_a_soundness_failure() {
    let mut o = ZonesOracle::new(60, 0);
    // A reliably-invalidating mutation accepted by the SPF is a soundness bug.
    let v = o.on_mutation_line(&mutation_line(
        WitnessMutation::WrongAnchorBlock,
        MutationOutcome::Accepted,
        Some(TAG),
    ));
    assert_eq!(failures(&v), ["E12/zones-invalid-witness-accepted"]);
    // A node-pool mutation the batch never reads may be accepted without a
    // bug: inconclusive, no failure.
    assert!(o
        .on_mutation_line(&mutation_line(
            WitnessMutation::AlterStateNode,
            MutationOutcome::Accepted,
            Some(TAG),
        ))
        .is_empty());
}

#[test]
fn rejected_mutations_cover_once_per_kind() {
    let mut o = ZonesOracle::new(60, 0);
    let c = covered(&o.on_mutation_line(&mutation_line(
        WitnessMutation::WrongAnchorBlock,
        MutationOutcome::Rejected,
        None,
    )));
    assert!(c.contains(&"S/zones-witness-mutated".to_string()), "{c:?}");
    assert!(
        c.contains(&"S/zones-mutated-witness-rejected".to_string()),
        "{c:?}"
    );
    // A diverged replay is also a safe rejection; a new kind re-covers the
    // per-kind signal, the shared one is deduped.
    let c = covered(&o.on_mutation_line(&mutation_line(
        WitnessMutation::DropZoneBlock,
        MutationOutcome::Diverged,
        Some(W),
    )));
    assert_eq!(c, ["S/zones-mutated-witness-rejected"]);
    assert!(o
        .on_mutation_line(&mutation_line(
            WitnessMutation::WrongAnchorBlock,
            MutationOutcome::Rejected,
            None,
        ))
        .is_empty());
    // A skipped attempt is neither coverage nor failure; garbage is a failure.
    assert!(o
        .on_mutation_line(&mutation_line(
            WitnessMutation::AlterTempoNode,
            MutationOutcome::Skipped,
            None,
        ))
        .is_empty());
    assert_eq!(
        failures(&o.on_mutation_line(&format!("{MUTATION_LINE}{{}}"))),
        ["E12/zones-mutation-result-invalid"]
    );
}

fn l1fault_line(
    fault: L1Fault,
    faulted: bool,
    outcome: L1FaultOutcome,
    replayed: Option<B256>,
) -> String {
    let r = L1FaultResult {
        batch_index: 2,
        l1_block: 7,
        committed_hash: TAG,
        fault,
        faulted,
        outcome,
        replayed_hash: replayed,
        detail: String::new(),
    };
    format!("{L1FAULT_LINE}{}", serde_json::to_string(&r).unwrap())
}

#[test]
fn l1_fault_accepted_is_a_soundness_failure() {
    let mut o = ZonesOracle::new(60, 0);
    let v = o.on_l1fault_line(&l1fault_line(
        L1Fault::WrongStateRoot,
        true,
        L1FaultOutcome::Accepted,
        Some(TAG),
    ));
    assert_eq!(failures(&v), ["E12/zones-trusted-bad-l1-accepted"]);
    assert!(covered(&v).contains(&"S/zones-l1-response-faulted".to_string()));
    // A fabricated extra log the prover ignores is accepted without a bug.
    assert!(o
        .on_l1fault_line(&l1fault_line(
            L1Fault::FabricateDepositLog,
            true,
            L1FaultOutcome::Accepted,
            Some(TAG)
        ))
        .iter()
        .all(|v| !matches!(v, Verdict::Always(false, _))));
}

#[test]
fn l1_fault_detected_covers_once_per_kind() {
    let mut o = ZonesOracle::new(60, 0);
    let c = covered(&o.on_l1fault_line(&l1fault_line(
        L1Fault::StaleHead,
        true,
        L1FaultOutcome::Detected,
        None,
    )));
    assert!(
        c.contains(&"S/zones-l1-response-faulted".to_string()),
        "{c:?}"
    );
    assert!(
        c.contains(&"S/zones-l1-fault-detected".to_string()),
        "{c:?}"
    );
    // A new kind: response-faulted is globally deduped, the per-kind
    // detection re-covers.
    let c = covered(&o.on_l1fault_line(&l1fault_line(
        L1Fault::WrongBlockHash,
        true,
        L1FaultOutcome::Detected,
        None,
    )));
    assert_eq!(c, ["S/zones-l1-fault-detected"]);
    // The same kind again adds nothing.
    assert!(o
        .on_l1fault_line(&l1fault_line(
            L1Fault::StaleHead,
            true,
            L1FaultOutcome::Detected,
            None
        ))
        .is_empty());
    // The proxy never tampered (method not requested): no verdict at all.
    assert!(o
        .on_l1fault_line(&l1fault_line(
            L1Fault::DropDepositLogs,
            false,
            L1FaultOutcome::Skipped,
            None
        ))
        .is_empty());
    // `of` cycles through every fault kind.
    let seen: std::collections::BTreeSet<_> =
        (0..L1Fault::ALL.len() as u64).map(L1Fault::of).collect();
    assert_eq!(seen.len(), L1Fault::ALL.len());
    // A malformed line is a failure.
    assert_eq!(
        failures(&o.on_l1fault_line(&format!("{L1FAULT_LINE}{{}}"))),
        ["E12/zones-l1fault-result-invalid"]
    );
}

fn transfer_line(
    kind: &str,
    to: &str,
    amount: &str,
    landed: u8,
    sender: (&str, &str),
    recipient: (&str, &str),
    supply: (&str, &str),
) -> String {
    let v = serde_json::json!({
        "step": "transfer",
        "kind": kind,
        "to": to,
        "amount": amount,
        "landed": landed,
        "sender_before": sender.0,
        "sender_after": sender.1,
        "recipient_before": recipient.0,
        "recipient_after": recipient.1,
        "supply_before": supply.0,
        "supply_after": supply.1,
    });
    format!("{POLICY_LINE}{v}")
}

#[test]
fn policy_change_and_transfers_cover() {
    let mut o = ZonesOracle::new(60, 0);
    let c = covered(&o.on_policy_line(&format!(
        "{POLICY_LINE}{{\"step\":\"policy-created\",\"id\":7}}"
    )));
    assert_eq!(c, ["S/zones-policy-changed"]);
    assert!(o
        .on_policy_line(&format!(
            "{POLICY_LINE}{{\"step\":\"policy-switched\",\"id\":7,\"l1_block\":42}}"
        ))
        .is_empty()); // already covered
                      // A forbidden transfer that does not land, moving nothing: rejected.
    let c = covered(&o.on_policy_line(&transfer_line(
        "forbidden",
        "0xBAD",
        "1",
        0,
        ("100", "100"),
        ("0", "0"),
        ("1000", "1000"),
    )));
    assert_eq!(c, ["S/zones-transfer-rejected"]);
    // An allowed transfer that lands, recipient +amount, supply unchanged.
    let c = covered(&o.on_policy_line(&transfer_line(
        "allowed",
        "0x3",
        "1",
        1,
        ("100", "98"),
        ("0", "1"),
        ("1000", "1000"),
    )));
    assert_eq!(c, ["S/zones-transfer-allowed"]);
}

#[test]
fn forbidden_transfer_that_lands_is_not_enforced() {
    let mut o = ZonesOracle::new(60, 0);
    let f = failures(&o.on_policy_line(&transfer_line(
        "forbidden",
        "0xBAD",
        "5",
        1,
        ("100", "94"),
        ("0", "5"),
        ("1000", "1000"),
    )));
    assert_eq!(f, ["E12/zones-policy-not-enforced"]);
}

#[test]
fn unconserved_allowed_transfer_fails() {
    let mut o = ZonesOracle::new(60, 0);
    // Recipient gained less than the amount.
    let f = failures(&o.on_policy_line(&transfer_line(
        "allowed",
        "0x3",
        "10",
        1,
        ("100", "90"),
        ("0", "4"),
        ("1000", "1000"),
    )));
    assert_eq!(f, ["E12/zones-transfer-unconserved"]);
    // A concurrent deposit changed global supply between the snapshots, but
    // the recipient gained exactly the amount: conserved (supply is not
    // compared, since zones-load deposits mint concurrently).
    let mut o = ZonesOracle::new(60, 0);
    let c = covered(&o.on_policy_line(&transfer_line(
        "allowed",
        "0x3",
        "1",
        1,
        ("100", "98"),
        ("0", "1"),
        ("1000", "2000"),
    )));
    assert_eq!(c, ["S/zones-transfer-allowed"]);
    // A rejected transfer that credited the recipient is unconserved.
    let mut o = ZonesOracle::new(60, 0);
    let f = failures(&o.on_policy_line(&transfer_line(
        "forbidden",
        "0xBAD",
        "1",
        0,
        ("100", "99"),
        ("0", "1"),
        ("1000", "1000"),
    )));
    assert_eq!(f, ["E12/zones-transfer-unconserved"]);
}

#[test]
fn allowed_transfer_that_does_not_land_is_no_verdict() {
    let mut o = ZonesOracle::new(60, 0);
    let v = o.on_policy_line(&transfer_line(
        "allowed",
        "0x3",
        "1",
        0,
        ("100", "100"),
        ("0", "0"),
        ("1000", "1000"),
    ));
    assert!(v.is_empty());
    // A driver error yields nothing (required coverage then fails as C/missing).
    assert!(o
        .on_policy_line(&format!(
            "{POLICY_LINE}{{\"step\":\"error\",\"detail\":\"x\"}}"
        ))
        .is_empty());
    // A malformed line is a failure.
    assert_eq!(
        failures(&o.on_policy_line(&format!("{POLICY_LINE}{{}}"))),
        ["E12/zones-policy-result-invalid"]
    );
}

fn net(kind: &str, index: u64, settlement: bool, observer: bool) -> DstEvent {
    DstEvent {
        source: "network".into(),
        kind: kind.into(),
        container: None,
        guest_time_ns: 0,
        detail: serde_json::json!({
            "index": index, "kind": "l1-cut-followers", "nodes": [1, 2], "leader": 0,
            "excuse": {"settlement": settlement, "production": false, "observer": observer},
        }),
    }
}

#[test]
fn a_fault_without_a_quorum_excuses_settlement_until_it_heals() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(10, 0).live_from_genesis();
    assert!(failures(&run(&mut o, &mut w, 1)).is_empty());
    o.on_event(&net("fault-start", 0, true, true), 2 * S);
    // No batch for longer than the budget: excused.
    assert!(failures(&o.tick(&mut w, 40 * S)).is_empty());
    o.on_event(&net("fault-end", 0, true, true), 41 * S);
    assert!(failures(&o.tick(&mut w, 45 * S)).is_empty());
    // Still none 10s after the heal: settlement did not resume.
    assert_eq!(
        failures(&o.tick(&mut w, 52 * S)),
        ["E12/zones-cluster-settlement-not-resumed"]
    );
}

#[test]
fn a_batch_after_the_heal_regains_the_quorum() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(10, 0).live_from_genesis();
    run(&mut o, &mut w, 1);
    o.on_event(&net("fault-start", 0, true, true), 2 * S);
    o.tick(&mut w, 5 * S);
    o.on_event(&net("fault-end", 0, true, true), 6 * S);
    batch(&mut w, 2, W);
    let v = o.tick(&mut w, 7 * S);
    assert!(failures(&v).is_empty());
    assert!(covered(&v).contains(&"S/net-quorum-lost-and-regained".into()));
}

#[test]
fn a_healthy_quorum_must_keep_settling_during_a_fault() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(10, 0).live_from_genesis();
    run(&mut o, &mut w, 1);
    // One follower cut: 2-of-3 continues, nothing is excused.
    o.on_event(&net("fault-start", 3, false, false), 2 * S);
    batch(&mut w, 2, W);
    let v = o.tick(&mut w, 3 * S);
    assert!(covered(&v).contains(&"S/net-quorum-settled-during-fault".into()));
    assert_eq!(
        failures(&o.tick(&mut w, 20 * S)),
        ["E12/zones-cluster-quorum-settlement-stalled"]
    );
}

#[test]
fn deposits_made_during_a_fault_are_tracked_to_processing() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(10, 0).live_from_genesis();
    run(&mut o, &mut w, 3);
    o.on_event(&net("fault-start", 0, true, true), 4 * S);
    w.l1.push(
        vec![L1Event::Deposit {
            number: 2,
            token: TOKEN,
            net_amount: u(5),
        }],
        l1_state(65),
    );
    o.tick(&mut w, 5 * S);
    o.on_event(&net("fault-end", 0, true, true), 30 * S);
    batch(&mut w, 2, W);
    o.tick(&mut w, 31 * S);
    // Never processed after the heal: an outage deposit stuck.
    batch(&mut w, 3, W);
    assert_eq!(
        failures(&o.tick(&mut w, 42 * S)),
        ["E12/zones-cluster-outage-deposit-stuck"]
    );
    // Processed: covered instead.
    let mut w = honest(60);
    let mut o = ZonesOracle::new(10, 0).live_from_genesis();
    run(&mut o, &mut w, 3);
    o.on_event(&net("fault-start", 0, true, true), 4 * S);
    w.l1.push(
        vec![L1Event::Deposit {
            number: 2,
            token: TOKEN,
            net_amount: u(5),
        }],
        l1_state(65),
    );
    o.tick(&mut w, 5 * S);
    o.on_event(&net("fault-end", 0, true, true), 6 * S);
    w.zone.push(
        vec![ZoneEvent::DepositProcessed {
            token: TOKEN,
            amount: u(5),
            deposit_hash: B256::repeat_byte(0xd2),
        }],
        zone_state(5, 65, 2, 1),
    );
    let v = o.tick(&mut w, 7 * S);
    assert!(failures(&v).is_empty(), "{:?}", failures(&v));
    assert!(covered(&v).contains(&"S/net-outage-deposit-processed".into()));
}

#[test]
fn a_deposit_processed_twice_is_a_finding() {
    let mut w = honest(60);
    let mut o = ZonesOracle::new(60, 0).live_from_genesis();
    run(&mut o, &mut w, 3);
    w.zone.push(
        vec![ZoneEvent::DepositProcessed {
            token: TOKEN,
            amount: u(100),
            deposit_hash: B256::repeat_byte(0xd1),
        }],
        zone_state(5, 160, 1, 1),
    );
    let f = failures(&o.tick(&mut w, 4 * S));
    assert!(
        f.contains(&"E12/zones-deposit-processed-twice".into()),
        "{f:?}"
    );
}
