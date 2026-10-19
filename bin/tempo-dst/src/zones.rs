// SPDX-License-Identifier: GPL-2.0

//! Zones load (`--load zones`) and its oracle (E12).
//!
//! A [Tempo zone](https://github.com/tempoxyz/zones) settles to the Tempo L1
//! this harness runs. During warmup, compose service `zone` provisions zone
//! [`ZONE_ID`] (`tempo-zone dev`: `ZoneFactory.createZone` from dev account
//! 0, the factory owner in Tempo's dev genesis) and runs its sequencer: one
//! zone block per finalized L1 block, a batch every few blocks, each batch's
//! `SettlementAttestation` signed with the sequencer key and submitted to the
//! portal ([`PORTAL`], `submitBatch`), withdrawals paid out on L1
//! (`processWithdrawals`). Service `zone-prover` (`tempo-dst zone-prover`,
//! [`prover`]) replays every submitted batch through the stateless proof
//! function (`tempo-zone-prover-utils generate-input --block`). The driver
//! (`zones-load`) is txgen's zone-backing property campaign: encrypted portal
//! deposits and outbox withdrawals from dev account 1, with its own solvency
//! audit after each settled action.
//!
//! [`ZonesOracle`] follows both chains block by block (rebuilt blocks are
//! dropped and re-read) and checks:
//!
//! - **Outbox solvency** ([`liabilities`]): at every L1 block `B`, paired
//!   with the newest zone block `Z` that imported L1 blocks up to `B` only,
//!   the portal's L1 balance covers the zone's token supply at `Z`, deposits
//!   made by `B` that `Z` has not processed, withdrawals requested by `Z` and
//!   not paid out, bounced or refunded by `B`, and parked refunds (the
//!   accounting of zones' `zone-portal-backing`, which txgen's campaign
//!   audits with). The pairing makes the snapshot consistent: every deposit
//!   `Z` processed is on L1 by `B`, every withdrawal paid by `B` was
//!   requested by `Z`.
//! - **Exactly-once withdrawals**: each L1 `WithdrawalProcessed` matches one
//!   outbox `WithdrawalRequested` (by `senderTag`, recipient, token, amount),
//!   requested in a zone block a batch had settled, and its tag is paid once.
//! - **Batches**: `BatchSubmitted` indices are contiguous, the portal's
//!   `blockHash`/`withdrawalBatchIndex` follow them, each batch's block is a
//!   canonical zone block whose outbox `lastBatch` and inbox deposit cursor
//!   are what the batch committed to, settled blocks advance and stay
//!   canonical across restarts, and the prover's replay of each batch
//!   succeeds with the committed block hash.
//! - **Liveness**: batches keep landing, settled withdrawals are paid,
//!   imported deposits are processed, and the prover keeps up, each within
//!   `liveness_secs` while the L1, zone and prover are up (clocks restart at
//!   every restart, like E2).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use alloy_primitives::{address, keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};

use crate::{
    common::{BlockRef, FullLog},
    verdict::{finding, Verdict},
};

/// The zone `tempo-zone dev` creates on a fresh L1: the factory's first.
pub const ZONE_ID: u32 = 1;
/// `0x5ad0..` followed by the zone ID (TIP-1091 portal proxies).
pub const PORTAL: Address = address!("5ad0000000000000000000000000000000000001");
/// `(parent chain ID << 32) | zone ID`.
pub const ZONE_CHAIN_ID: u64 = (1337 << 32) | ZONE_ID as u64;
/// pathUSD, the zone's initial token on both chains.
pub const TOKEN: Address = address!("20c0000000000000000000000000000000000000");
/// Zone predeploys.
pub const TEMPO_STATE: Address = address!("1c00000000000000000000000000000000000000");
pub const ZONE_INBOX: Address = address!("1c00000000000000000000000000000000000001");
pub const ZONE_OUTBOX: Address = address!("1c00000000000000000000000000000000000002");
/// The zone node's unrestricted (operator) RPC.
pub const ZONE_RPC_URL: &str = "http://127.0.0.1:9545";
/// Its redacted (user) RPC.
pub const ZONE_PRIVATE_RPC_URL: &str = "http://127.0.0.1:8544";
pub const ZONE_CONTAINER: &str = "zone";
pub const PROVER_CONTAINER: &str = "zone-prover";
pub const LOAD_CONTAINER: &str = "zones-load";
pub const POLICY_CONTAINER: &str = "zones-policy";
/// Sequencer, prover and driver image (contrib/bedrock-dst/zones).
pub const IMAGE: &str = "bedrock/tempo-dst-zones:latest";
/// The driver's account: dev account 1 (mnemonic `test ... junk`).
pub const LOAD_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
/// Zone genesis written by `tempo-zone dev` in the zone's datadir.
pub const GENESIS_PATH: &str = "/data/zone/genesis.json";

/// The zone node the oracles, prover and driver talk to: the single
/// sequencer, or node 0 of the multi-sequencer cluster (which may be a
/// follower; followers forward transactions to the leader).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneEndpoints {
    /// Unrestricted (operator) RPC.
    pub rpc: &'static str,
    /// Redacted (user) RPC.
    pub private_rpc: &'static str,
    /// Zone genesis, as the prover sees it.
    pub genesis: &'static str,
}

impl ZoneEndpoints {
    /// The single `tempo-zone dev` sequencer on the guest host network.
    pub const SINGLE: ZoneEndpoints = ZoneEndpoints {
        rpc: ZONE_RPC_URL,
        private_rpc: ZONE_PRIVATE_RPC_URL,
        genesis: GENESIS_PATH,
    };
    /// Node 0 of the cluster, in its own podman network.
    pub const CLUSTER: ZoneEndpoints = ZoneEndpoints {
        rpc: "http://10.90.10.11:9545",
        private_rpc: "http://10.90.10.11:8544",
        genesis: "/shared/genesis.json",
    };

    /// The endpoints of the run configured by `cfg`.
    pub fn of(cfg: &crate::common::Config) -> ZoneEndpoints {
        if cfg.zone_cluster() {
            Self::CLUSTER
        } else {
            Self::SINGLE
        }
    }

    /// For a process without the run config (the prover service):
    /// `TEMPO_DST_ZONE_CLUSTER=1` selects the cluster.
    pub fn from_env() -> ZoneEndpoints {
        if std::env::var("TEMPO_DST_ZONE_CLUSTER").as_deref() == Ok("1") {
            Self::CLUSTER
        } else {
            Self::SINGLE
        }
    }
}
/// Prefix of the prover's result lines (see [`ProofResult`]).
pub const PROVER_LINE: &str = "tempo-dst-prover: ";
/// Prefix of the prover's witness-mutation result lines (see
/// [`MutationResult`]; the zones witness-fault family).
pub const MUTATION_LINE: &str = "tempo-dst-mutation: ";
/// Prefix of the prover's byzantine-L1 probe lines (see [`L1FaultResult`]; the
/// zones L1-fault family).
pub const L1FAULT_LINE: &str = "tempo-dst-l1fault: ";
/// Prefix of the policy driver's lines (see [`PolicyEvent`]; the zones
/// TIP-403 policy/transfer family).
pub const POLICY_LINE: &str = "tempo-dst-policy: ";

/// Blocks per side fetched per tick; a long outage catches up over ticks.
const BLOCKS_PER_TICK: u64 = 20;
/// Tracked blocks before the oracle's first head, per side; older events are
/// read once as final history.
const HISTORY_DEPTH: u64 = 64;
/// Solvency checks per tick; a larger backlog skips ahead.
const SOLVENCY_PER_TICK: u64 = 40;
const SOLVENCY_MAX_BACKLOG: u64 = 200;
/// Unchecked batches verified against the zone per tick.
const BATCHES_PER_TICK: usize = 8;
/// The prover may trail a batch by this many liveness periods.
const PROVER_SLACK: u64 = 3;

fn topic(signature: &str) -> B256 {
    keccak256(signature.as_bytes())
}

/// Event topics, by Solidity signature (crates/contracts/src/precompiles in
/// tempoxyz/zones).
struct Topics {
    deposit_made: B256,
    batch_submitted: B256,
    batch_submitted_legacy: B256,
    withdrawal_processed: B256,
    deposit_bounce_back: B256,
    deposit_bounce_back_pending: B256,
    refund_claimed: B256,
    withdrawal_requested: B256,
    bounce_back_processed: B256,
    bounce_back_pending: B256,
    deposit_processed: B256,
    deposit_failed: B256,
    deposit_rejected: B256,
}

fn topics() -> &'static Topics {
    static T: std::sync::OnceLock<Topics> = std::sync::OnceLock::new();
    T.get_or_init(|| Topics {
        deposit_made: topic("DepositMade(bytes32,address,address,uint128,uint128,uint256,bytes32,uint8,bytes,bytes12,bytes16,address,uint64)"),
        batch_submitted: topic("BatchSubmitted(uint64,uint256,bytes32,bytes32,bytes32,uint64,uint64)"),
        batch_submitted_legacy: topic("BatchSubmitted(uint64,uint256,bytes32,bytes32,bytes32,uint64)"),
        withdrawal_processed: topic("WithdrawalProcessed(address,bytes32,address,uint128,bool)"),
        deposit_bounce_back: topic("DepositBounceBack(address,address,uint128,uint128)"),
        deposit_bounce_back_pending: topic("DepositBounceBackPending(address,address,uint128,uint128)"),
        refund_claimed: topic("RefundClaimed(address,address,uint128)"),
        withdrawal_requested: topic("WithdrawalRequested(uint64,address,address,address,uint128,uint128,bytes32,uint64,uint64,bytes,bytes)"),
        bounce_back_processed: topic("WithdrawalBounceBackProcessed(address,address,uint128)"),
        bounce_back_pending: topic("WithdrawalBounceBackPending(address,address,uint128)"),
        deposit_processed: topic("DepositProcessed(bytes32,address,address,address,uint128,bytes32)"),
        deposit_failed: topic("DepositFailed(bytes32,address,address,uint128)"),
        deposit_rejected: topic("DepositRejected(bytes32,address,uint8,address,uint128,address)"),
    })
}

/// ABI word `i` of `data`.
fn word(data: &[u8], i: usize) -> Option<B256> {
    data.get(i * 32..(i + 1) * 32).map(B256::from_slice)
}

fn uint(data: &[u8], i: usize) -> Option<U256> {
    word(data, i).map(|w| U256::from_be_bytes(w.0))
}

fn uint64(data: &[u8], i: usize) -> Option<u64> {
    uint(data, i).and_then(|u| u64::try_from(u).ok())
}

fn addr(data: &[u8], i: usize) -> Option<Address> {
    word(data, i).map(Address::from_word)
}

/// A submitted batch, as `BatchSubmitted` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneBatch {
    pub index: u64,
    pub next_block_hash: B256,
    pub withdrawal_queue_hash: B256,
    pub last_processed_deposit: u64,
}

/// One L1 `WithdrawalProcessed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalPayout {
    pub sender_tag: B256,
    pub to: Address,
    pub token: Address,
    pub amount: U256,
    pub callback_success: bool,
}

/// Portal events the oracle uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L1Event {
    Deposit {
        number: u64,
        token: Address,
        net_amount: U256,
    },
    Batch(ZoneBatch),
    Payout(PortalPayout),
    /// A deposit bounce-back paid out: retires `amount + bouncebackFee`.
    DepositBounceBack {
        token: Address,
        retired: U256,
    },
    /// A deposit bounce-back parked as a portal refund.
    DepositBounceBackPending {
        token: Address,
        amount: U256,
        retired: U256,
    },
    RefundClaimed {
        token: Address,
        amount: U256,
    },
}

/// One outbox `WithdrawalRequested`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneWithdrawalRequest {
    pub index: u64,
    pub sender: Address,
    pub token: Address,
    pub to: Address,
    pub amount: U256,
    pub fallback_nonce: u64,
    /// `keccak256(sender || txHash || fallbackNonce)`, what the portal's
    /// `WithdrawalProcessed` carries.
    pub sender_tag: B256,
}

/// Zone inbox/outbox events the oracle uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneEvent {
    Request(ZoneWithdrawalRequest),
    BounceBackReminted {
        token: Address,
        amount: U256,
    },
    BounceBackPending {
        token: Address,
        amount: U256,
    },
    RefundClaimed {
        token: Address,
        amount: U256,
    },
    DepositProcessed {
        token: Address,
        amount: U256,
        /// The deposit's hash (topic 1): processed at most once.
        deposit_hash: B256,
    },
    DepositFailed,
    DepositRejected,
}

/// `senderTag = keccak256(abi.encodePacked(sender, txHash, fallbackNonce))`.
pub fn sender_tag(sender: Address, tx_hash: B256, fallback_nonce: u64) -> B256 {
    let mut packed = Vec::with_capacity(60);
    packed.extend_from_slice(sender.as_slice());
    packed.extend_from_slice(tx_hash.as_slice());
    packed.extend_from_slice(&fallback_nonce.to_be_bytes());
    keccak256(packed)
}

/// Decodes a portal log; `None` for other logs.
pub fn decode_l1(log: &FullLog) -> Option<L1Event> {
    let t = topics();
    if log.address != PORTAL {
        return None;
    }
    let d = &log.data[..];
    let t0 = *log.topics.first()?;
    if t0 == t.deposit_made {
        Some(L1Event::Deposit {
            token: addr(d, 0)?,
            net_amount: uint(d, 1)?,
            number: uint64(d, 10)?,
        })
    } else if t0 == t.batch_submitted || t0 == t.batch_submitted_legacy {
        Some(L1Event::Batch(ZoneBatch {
            index: u64::try_from(U256::from_be_bytes(log.topics.get(1)?.0)).ok()?,
            next_block_hash: word(d, 1)?,
            withdrawal_queue_hash: word(d, 2)?,
            last_processed_deposit: uint64(d, 3)?,
        }))
    } else if t0 == t.withdrawal_processed {
        Some(L1Event::Payout(PortalPayout {
            to: Address::from_word(*log.topics.get(1)?),
            sender_tag: *log.topics.get(2)?,
            token: addr(d, 0)?,
            amount: uint(d, 1)?,
            callback_success: !uint(d, 2)?.is_zero(),
        }))
    } else if t0 == t.deposit_bounce_back {
        Some(L1Event::DepositBounceBack {
            token: addr(d, 0)?,
            retired: uint(d, 1)? + uint(d, 2)?,
        })
    } else if t0 == t.deposit_bounce_back_pending {
        Some(L1Event::DepositBounceBackPending {
            token: addr(d, 0)?,
            amount: uint(d, 1)?,
            retired: uint(d, 1)? + uint(d, 2)?,
        })
    } else if t0 == t.refund_claimed {
        Some(L1Event::RefundClaimed {
            token: Address::from_word(*log.topics.get(2)?),
            amount: uint(d, 0)?,
        })
    } else {
        None
    }
}

/// Decodes a zone inbox/outbox log; `None` for other logs.
pub fn decode_zone(log: &FullLog) -> Option<ZoneEvent> {
    let t = topics();
    let d = &log.data[..];
    let t0 = *log.topics.first()?;
    if log.address == ZONE_OUTBOX && t0 == t.withdrawal_requested {
        let sender = Address::from_word(*log.topics.get(2)?);
        let fallback_nonce = uint64(d, 6)?;
        Some(ZoneEvent::Request(ZoneWithdrawalRequest {
            index: u64::try_from(U256::from_be_bytes(log.topics.get(1)?.0)).ok()?,
            sender,
            token: addr(d, 0)?,
            to: addr(d, 1)?,
            amount: uint(d, 2)?,
            fallback_nonce,
            sender_tag: sender_tag(sender, log.transaction_hash, fallback_nonce),
        }))
    } else if log.address != ZONE_INBOX {
        None
    } else if t0 == t.bounce_back_processed {
        Some(ZoneEvent::BounceBackReminted {
            token: addr(d, 0)?,
            amount: uint(d, 1)?,
        })
    } else if t0 == t.bounce_back_pending {
        Some(ZoneEvent::BounceBackPending {
            token: addr(d, 0)?,
            amount: uint(d, 1)?,
        })
    } else if t0 == t.refund_claimed {
        Some(ZoneEvent::RefundClaimed {
            token: Address::from_word(*log.topics.get(2)?),
            amount: uint(d, 0)?,
        })
    } else if t0 == t.deposit_processed {
        Some(ZoneEvent::DepositProcessed {
            token: addr(d, 0)?,
            amount: uint(d, 1)?,
            deposit_hash: *log.topics.get(1)?,
        })
    } else if t0 == t.deposit_failed {
        Some(ZoneEvent::DepositFailed)
    } else if t0 == t.deposit_rejected {
        Some(ZoneEvent::DepositRejected)
    } else {
        None
    }
}

/// What the portal owes the zone's holders at one consistent `(Z, B)` pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Liabilities {
    /// Zone `totalSupply` of [`TOKEN`] at `Z`.
    pub supply: U256,
    /// Deposits made by `B` that `Z` has not processed.
    pub pending_deposits: U256,
    /// Withdrawals requested by `Z`, not yet paid, re-minted or refunded.
    pub pending_withdrawals: U256,
    /// Parked deposit bounce-backs not yet claimed on L1.
    pub portal_refunds: U256,
    /// Parked withdrawal bounce-backs not yet claimed on the zone.
    pub inbox_refunds: U256,
}

impl Liabilities {
    /// The combined token liability represented by this snapshot.
    pub fn total(&self) -> U256 {
        self.supply
            + self.pending_deposits
            + self.pending_withdrawals
            + self.portal_refunds
            + self.inbox_refunds
    }
}

/// `(signature, detail)`.
pub type Failure = (&'static str, String);

/// The liabilities of [`TOKEN`] at a consistent pair: `l1` the portal events
/// up to `B`, `zone` the inbox/outbox events up to `Z`, `supply` and
/// `processed` (inbox `processedDepositNumber`) read at `Z`. Mirrors
/// tempoxyz/zones `zone-portal-backing`. `Err` when the event history is
/// impossible: more paid out than requested, more claimed than parked, or
/// deposits processed that the portal never recorded.
pub fn liabilities<'a>(
    l1: impl IntoIterator<Item = &'a L1Event>,
    zone: impl IntoIterator<Item = &'a ZoneEvent>,
    supply: U256,
    processed: u64,
) -> Result<Liabilities, Failure> {
    let (mut pending_deposits, mut paid, mut portal_parked, mut portal_parked_retired) =
        (U256::ZERO, U256::ZERO, U256::ZERO, U256::ZERO);
    let mut portal_claimed = U256::ZERO;
    let mut deposits_recorded = 0;
    for e in l1 {
        match e {
            L1Event::Deposit {
                number,
                token,
                net_amount,
            } => {
                deposits_recorded = deposits_recorded.max(*number);
                if *token == TOKEN && *number > processed {
                    pending_deposits += net_amount;
                }
            }
            L1Event::Payout(p) if p.token == TOKEN && p.callback_success => paid += p.amount,
            L1Event::DepositBounceBack { token, retired } if *token == TOKEN => paid += retired,
            L1Event::DepositBounceBackPending {
                token,
                amount,
                retired,
            } if *token == TOKEN => {
                portal_parked += amount;
                portal_parked_retired += retired;
            }
            L1Event::RefundClaimed { token, amount } if *token == TOKEN => portal_claimed += amount,
            _ => {}
        }
    }
    let (mut requested, mut reminted, mut inbox_parked, mut inbox_claimed) =
        (U256::ZERO, U256::ZERO, U256::ZERO, U256::ZERO);
    for e in zone {
        match e {
            ZoneEvent::Request(r) if r.token == TOKEN => requested += r.amount,
            ZoneEvent::BounceBackReminted { token, amount } if *token == TOKEN => {
                reminted += amount
            }
            ZoneEvent::BounceBackPending { token, amount } if *token == TOKEN => {
                inbox_parked += amount
            }
            ZoneEvent::RefundClaimed { token, amount } if *token == TOKEN => {
                inbox_claimed += amount
            }
            _ => {}
        }
    }
    if processed > deposits_recorded {
        return Err((
            "E12/zones-deposit-unbacked",
            format!("zone processed deposit {processed}, portal recorded {deposits_recorded}"),
        ));
    }
    let retired = paid + reminted + inbox_parked + portal_parked_retired;
    let pending_withdrawals = requested.checked_sub(retired).ok_or_else(|| {
        (
            "E12/zones-withdrawal-unbacked",
            format!(
                "requested {requested}, paid {paid}, re-minted {reminted}, refunded {}",
                inbox_parked + portal_parked_retired
            ),
        )
    })?;
    let refunds = |scope: &str, parked: U256, claimed: U256| {
        parked.checked_sub(claimed).ok_or_else(|| {
            (
                "E12/zones-refund-overclaimed",
                format!("{scope}: claimed {claimed}, parked {parked}"),
            )
        })
    };
    Ok(Liabilities {
        supply,
        pending_deposits,
        pending_withdrawals,
        portal_refunds: refunds("portal", portal_parked, portal_claimed)?,
        inbox_refunds: refunds("inbox", inbox_parked, inbox_claimed)?,
    })
}

/// Portal state at one L1 block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct L1State {
    /// [`TOKEN`] `balanceOf(PORTAL)`: the escrow.
    pub balance: U256,
    /// `blockHash()`: the last settled zone block.
    pub settled_hash: B256,
    pub batch_index: u64,
}

/// Zone state at one zone block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZoneState {
    /// TempoState `tempoBlockNumber()`: the L1 block imported last.
    pub tempo_block: u64,
    /// [`TOKEN`] `totalSupply()`.
    pub supply: U256,
    /// ZoneInbox `processedDepositNumber()`.
    pub processed_deposits: u64,
    /// ZoneOutbox `lastBatch()`.
    pub last_batch_hash: B256,
    pub last_batch_index: u64,
}

/// One chain's queries; `Err` while its node is unreachable.
pub trait Side {
    type Event;
    type State;
    /// The current canonical head number; returns Err while the chain is unavailable.
    fn head(&mut self) -> Result<u64, String>;
    /// Canonical block identity at the requested number, or None if unavailable in chain history.
    fn block(&mut self, number: u64) -> Result<Option<BlockRef>, String>;
    /// Decoded events of blocks `from..=to` as `(block hash, event)`, in
    /// chain order.
    fn events(&mut self, from: u64, to: u64) -> Result<Vec<(B256, Self::Event)>, String>;
    /// The chain-specific state snapshot at the exact block hash.
    fn state(&mut self, hash: B256) -> Result<Self::State, String>;
    /// Number of the block with `hash`, canonical or not, if the node has it.
    fn number_of(&mut self, hash: B256) -> Result<Option<u64>, String>;
}

/// Both chains.
pub trait ZonesChain {
    type L1: Side<Event = L1Event, State = L1State>;
    type Zone: Side<Event = ZoneEvent, State = ZoneState>;
    /// The L1 provider for portal history and state.
    fn l1(&mut self) -> &mut Self::L1;
    /// The zone provider for inbox/outbox history and state.
    fn zone(&mut self) -> &mut Self::Zone;
}

/// A canonical block with its events and state snapshot.
#[derive(Debug, Clone)]
struct Tracked<E, S> {
    pub block: BlockRef,
    pub events: Vec<E>,
    pub state: S,
}

/// One chain's canonical blocks since the oracle started, with their events
/// and state; events from before as final history.
#[derive(Debug, Clone)]
struct BlockLog<E, S> {
    history: Vec<E>,
    /// The first tracked block.
    base: Option<u64>,
    /// The head at the first sync: blocks after it were produced while the
    /// oracle ran (coverage counts only those).
    first_head: Option<u64>,
    blocks: Vec<Tracked<E, S>>,
}

impl<E, S> Default for BlockLog<E, S> {
    fn default() -> Self {
        BlockLog {
            history: Vec::new(),
            base: None,
            first_head: None,
            blocks: Vec::new(),
        }
    }
}

/// What one sync changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Synced {
    /// Blocks from this number on were replaced (or dropped by a rewind).
    pub rewound: Option<u64>,
    /// Numbers of blocks appended.
    pub appended: Vec<u64>,
}

impl<E: Clone, S> BlockLog<E, S> {
    /// The last tracked canonical block, if any.
    pub fn tip(&self) -> Option<&Tracked<E, S>> {
        self.blocks.last()
    }

    /// The tracked canonical block with this number, if present.
    pub fn get(&self, number: u64) -> Option<&Tracked<E, S>> {
        let i = number.checked_sub(self.base?)?;
        self.blocks.get(usize::try_from(i).ok()?)
    }

    /// History plus the events of tracked blocks up to `number`.
    pub fn events_to(&self, number: u64) -> impl Iterator<Item = &E> {
        self.history.iter().chain(
            self.blocks
                .iter()
                .take_while(move |b| b.block.number <= number)
                .flat_map(|b| b.events.iter()),
        )
    }

    /// Drops blocks the node no longer has on its canonical chain, then
    /// appends up to [`BLOCKS_PER_TICK`] new ones.
    pub fn sync(&mut self, side: &mut impl Side<Event = E, State = S>) -> Result<Synced, String> {
        let mut out = Synced::default();
        let head = side.head()?;
        let base = match self.base {
            Some(b) => b,
            None => {
                let base = head.saturating_sub(HISTORY_DEPTH);
                if base > 0 {
                    self.history = side.events(0, base - 1)?.into_iter().map(|e| e.1).collect();
                }
                self.base = Some(base);
                self.first_head = Some(head);
                base
            }
        };
        while let Some(tip) = self.blocks.last() {
            match side.block(tip.block.number)? {
                Some(b) if b.hash == tip.block.hash => break,
                _ => {
                    out.rewound = Some(tip.block.number);
                    self.blocks.pop();
                }
            }
        }
        let next = self.tip().map_or(base, |t| t.block.number + 1);
        if next > head {
            return Ok(out);
        }
        let end = head.min(next + BLOCKS_PER_TICK - 1);
        let mut refs = Vec::new();
        let mut parent = self.tip().map(|t| t.block.hash);
        for n in next..=end {
            let Some(b) = side.block(n)? else { break };
            if parent.is_some_and(|p| p != b.parent) {
                // Rebuilt under us; the next sync rewinds.
                break;
            }
            parent = Some(b.hash);
            refs.push(b);
        }
        let Some(last) = refs.last().map(|b| b.number) else {
            return Ok(out);
        };
        let mut events: BTreeMap<B256, Vec<E>> = BTreeMap::new();
        for (hash, e) in side.events(next, last)? {
            events.entry(hash).or_default().push(e);
        }
        let known: BTreeSet<B256> = refs.iter().map(|b| b.hash).collect();
        if events.keys().any(|h| !known.contains(h)) {
            // Logs of a block that is no longer canonical: retry next tick.
            return Ok(out);
        }
        for b in refs {
            let state = side.state(b.hash)?;
            out.appended.push(b.number);
            self.blocks.push(Tracked {
                events: events.remove(&b.hash).unwrap_or_default(),
                block: b,
                state,
            });
        }
        Ok(out)
    }
}

/// The terminal outcome of a submitted batch's SPF replay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofStatus {
    /// The SPF replay produced the committed block hash.
    Ok,
    /// The SPF rejected the batch or produced a different block hash.
    SpfFailed,
    /// No SPF result could be obtained.
    #[default]
    Unavailable,
}

/// One line of `tempo-dst zone-prover` output (after [`PROVER_LINE`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProofResult {
    pub batch_index: u64,
    pub l1_block: u64,
    /// The batch's committed block hash.
    pub next_block_hash: B256,
    /// `ok`, `spf-failed` (the SPF rejected the batch or replayed another
    /// block hash), or `unavailable` (witness generation kept failing, e.g.
    /// a node was down).
    pub status: ProofStatus,
    /// The SPF's replayed `nextBlockHash`, when it ran.
    #[serde(default)]
    pub replayed_hash: Option<B256>,
    #[serde(default)]
    pub zone_blocks: Option<String>,
    /// Guest seconds the replay took, and the prover's peak RSS.
    #[serde(default)]
    pub secs: f64,
    #[serde(default)]
    pub max_rss_kb: u64,
    #[serde(default)]
    pub error: String,
}

/// A typed mutation of a batch witness (`zones_witness_faults`): each one makes
/// the witness describe an invalid state transition, so an honest SPF must
/// reject it. Applied to the witness JSON `tempo-zone-prover-utils
/// generate-input --output` wrote; value-only, so the JSON stays schema-valid
/// and deserializes, but the transition it describes does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessMutation {
    /// Flip a byte in a Zone state trie node: an altered account balance or
    /// storage slot (the node's hash no longer matches its reference).
    AlterStateNode,
    /// Drop a Zone state trie node: a read the batch needs is now missing.
    DropStateNode,
    /// Flip a byte in a Tempo state trie node.
    AlterTempoNode,
    /// `anchorBlockNumber + 1`: the proof anchors to another Tempo block.
    WrongAnchorBlock,
    /// Flip a nibble in `anchorBlockHash`.
    TamperAnchorHash,
    /// Flip a byte in the RLP parent header (its hash/state root anchor).
    TamperParentHeader,
    /// `expectedWithdrawalBatchIndex + 1`.
    WrongWithdrawalBatchIndex,
    /// `tempoBlockNumber + 1`: the batch commits to another Tempo block.
    WrongTempoBlock,
    /// Drop the last Zone block: the batch no longer reaches the committed
    /// block hash.
    DropZoneBlock,
    /// `zoneBlocks[0].timestamp + 1`: the first block's hash diverges.
    BumpZoneTimestamp,
}

impl WitnessMutation {
    /// Every kind, for round-robin selection and tests.
    pub const ALL: [WitnessMutation; 10] = [
        WitnessMutation::AlterStateNode,
        WitnessMutation::DropStateNode,
        WitnessMutation::AlterTempoNode,
        WitnessMutation::WrongAnchorBlock,
        WitnessMutation::TamperAnchorHash,
        WitnessMutation::TamperParentHeader,
        WitnessMutation::WrongWithdrawalBatchIndex,
        WitnessMutation::WrongTempoBlock,
        WitnessMutation::DropZoneBlock,
        WitnessMutation::BumpZoneTimestamp,
    ];

    /// The mutation for draw `n` (e.g. a getrandom value).
    pub fn of(n: u64) -> WitnessMutation {
        WitnessMutation::ALL[(n % WitnessMutation::ALL.len() as u64) as usize]
    }

    /// Whether this mutation provably invalidates the committed transition, so
    /// the SPF *must* reject it and acceptance is a soundness failure. A
    /// state/Tempo trie-node mutation does not qualify: the witness over-
    /// provides nodes, so a corrupted or dropped node the batch never reads
    /// leaves the committed block hash unchanged and is accepted without a
    /// bug. Those mutations still cover rejection when the node is on a read
    /// path, but their acceptance is inconclusive.
    pub fn must_reject(self) -> bool {
        !matches!(
            self,
            WitnessMutation::AlterStateNode
                | WitnessMutation::DropStateNode
                | WitnessMutation::AlterTempoNode
        )
    }
}

/// How an honest SPF replay of a mutated witness turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationOutcome {
    /// The SPF rejected the mutated witness (what a sound prover must do).
    Rejected,
    /// The SPF ran but produced a different block hash than the batch
    /// committed: also a safe rejection (the batch would not validate).
    Diverged,
    /// The SPF reproduced the committed block hash from the mutated witness:
    /// a soundness failure (`E12/zones-invalid-witness-accepted`).
    Accepted,
    /// The mutation could not be applied, or the honest witness was
    /// unavailable: no verdict.
    Skipped,
}

/// One `tempo-dst zone-prover` witness-mutation line: a settled batch's
/// witness was mutated and replayed offline through the SPF (never submitted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationResult {
    pub batch_index: u64,
    pub l1_block: u64,
    /// The batch's committed (honest) block hash.
    pub committed_hash: B256,
    pub mutation: WitnessMutation,
    pub outcome: MutationOutcome,
    /// The SPF's replayed block hash, when it ran.
    #[serde(default)]
    pub replayed_hash: Option<B256>,
    #[serde(default)]
    pub detail: String,
}

/// A typed byzantine L1 fault for the `zones_l1_faults` family: the proxy in
/// `zones_l1_proxy` returns L1 state that disagrees with the real chain for one
/// of these, so a witness or proof built on it must not validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum L1Fault {
    /// `eth_blockNumber` reports a head below the probed batch's submission
    /// block, so the prover cannot find the batch (a head merely "behind" is
    /// immaterial for an older batch: every read is then honest).
    StaleHead,
    /// A returned block's `hash` is altered.
    WrongBlockHash,
    /// A returned block's `stateRoot` is altered.
    WrongStateRoot,
    /// An `eth_getStorageAt` / `eth_getProof` value is altered.
    AlterStorage,
    /// An `eth_call` return value is altered.
    AlterCall,
    /// Portal `DepositMade` logs are dropped from `eth_getLogs`.
    DropDepositLogs,
    /// A fabricated portal deposit log is added to `eth_getLogs`.
    FabricateDepositLog,
}

impl L1Fault {
    pub const ALL: [L1Fault; 7] = [
        L1Fault::StaleHead,
        L1Fault::WrongBlockHash,
        L1Fault::WrongStateRoot,
        L1Fault::AlterStorage,
        L1Fault::AlterCall,
        L1Fault::DropDepositLogs,
        L1Fault::FabricateDepositLog,
    ];

    /// The fault for draw `n` (e.g. a getrandom value).
    pub fn of(n: u64) -> L1Fault {
        L1Fault::ALL[(n % L1Fault::ALL.len() as u64) as usize]
    }

    /// Whether a correct prover must reject a witness built over this fault, so
    /// acceptance is a soundness bug. A fabricated extra log is not consumed by
    /// witness building (the zone already processed L1 deposits into its state;
    /// the prover reads the zone execution witness, not L1 deposit logs), so a
    /// correct prover ignores it and its acceptance is inconclusive, like an
    /// over-provided witness node.
    pub fn must_detect(self) -> bool {
        self != L1Fault::FabricateDepositLog
    }
}

/// How the prover's witness build over a byzantine L1 turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum L1FaultOutcome {
    /// The prover rejected the batch built on falsified L1 (its SPF/anchor
    /// check failed, or witness generation could not complete): the lie was
    /// detected, the expected result.
    Detected,
    /// The prover built a witness over falsified L1 that replayed to the
    /// batch's committed hash: it trusted bad L1 state
    /// (`E12/zones-trusted-bad-l1-accepted`).
    Accepted,
    /// The proxy never got to tamper (the faulted method was not requested),
    /// or the honest build was unavailable: no verdict.
    Skipped,
}

/// One `tempo-dst zone-prover` L1-fault probe line: a settled batch's witness
/// was rebuilt through a byzantine L1 proxy (a separate probe; the honest
/// replay is unaffected and never submitted to L1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1FaultResult {
    pub batch_index: u64,
    pub l1_block: u64,
    pub committed_hash: B256,
    pub fault: L1Fault,
    /// Whether the proxy actually tampered a response.
    pub faulted: bool,
    pub outcome: L1FaultOutcome,
    #[serde(default)]
    pub replayed_hash: Option<B256>,
    #[serde(default)]
    pub detail: String,
}

/// A step the zones TIP-403 policy driver (`policy.sh`, the `zones_policy`
/// family) reports: it creates a BLACKLIST policy on L1, switches pathUSD's
/// policy to it, then sends a forbidden and an allowed zone transfer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "step", rename_all = "kebab-case")]
pub enum PolicyEvent {
    /// A TIP-403 policy was created on L1.
    PolicyCreated { id: u64 },
    /// pathUSD's transfer policy was switched to `id` at L1 block `l1_block`.
    PolicySwitched { id: u64, l1_block: u64 },
    /// A zone transfer was attempted (see [`PolicyTransfer`]).
    Transfer(PolicyTransfer),
    /// The driver could not run the flow (e.g. funding failed): no verdict, so
    /// the run fails its required coverage (`C/missing`).
    Error { detail: String },
}

/// A zone transfer the policy driver attempted, with balances snapshotted
/// around it. `kind` is `forbidden` (recipient blacklisted; must not land) or
/// `allowed` (must land and conserve). Amounts are decimal base-unit strings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PolicyTransfer {
    pub kind: String,
    pub to: String,
    pub amount: String,
    /// 1 if the transfer landed (receipt status 1), 0 if reverted or rejected.
    pub landed: u8,
    pub sender_before: String,
    pub sender_after: String,
    pub recipient_before: String,
    pub recipient_after: String,
    pub supply_before: String,
    pub supply_after: String,
}

impl PolicyTransfer {
    fn amount(&self) -> Option<U256> {
        self.amount.parse().ok()
    }
    fn landed(&self) -> bool {
        self.landed != 0
    }
    fn recipient_delta(&self) -> Option<U256> {
        self.recipient_after
            .parse::<U256>()
            .ok()?
            .checked_sub(self.recipient_before.parse().ok()?)
    }
    fn recipient_unchanged(&self) -> bool {
        self.recipient_before == self.recipient_after
    }
}

#[derive(Debug, Clone)]
struct BatchRecord {
    batch: ZoneBatch,
    l1_block: u64,
    seen_ns: u64,
    /// Zone block number of `next_block_hash`, once verified.
    zone_number: Option<u64>,
    proven: bool,
}

#[derive(Debug, Clone)]
struct PayoutRecord {
    payout: PortalPayout,
    l1_block: u64,
    matched: bool,
}

#[derive(Debug, Clone)]
struct RequestRecord {
    request: ZoneWithdrawalRequest,
    zone_block: u64,
    /// Guest time a batch was first seen settling it.
    settled_ns: Option<u64>,
}

/// E12 (see the module docs). A pure state machine like [`crate::oracle::Oracle`].
#[derive(Debug)]
pub struct ZonesOracle {
    liveness_ns: u64,
    l1: BlockLog<L1Event, L1State>,
    zone: BlockLog<ZoneEvent, ZoneState>,
    /// Next L1 block the solvency check runs at.
    solvency_next: Option<u64>,
    batches: BTreeMap<u64, BatchRecord>,
    payouts: Vec<PayoutRecord>,
    requests: HashMap<B256, RequestRecord>,
    /// Deposit number -> (L1 block, guest time it became overdue).
    deposits: BTreeMap<u64, (u64, Option<u64>)>,
    proofs: BTreeMap<u64, ProofResult>,
    /// Containers killed and not yet restarted.
    down: BTreeSet<String>,
    /// Liveness clocks restart here (oracle start, every restart).
    clock_ns: u64,
    last_batch_ns: u64,
    /// A restart happened and no batch has landed since.
    restarted: bool,
    covered: BTreeSet<&'static str>,
    reported: BTreeSet<String>,
    /// Each side's pre-start history was replayed into the records.
    l1_history_loaded: bool,
    zone_history_loaded: bool,
    /// Coverage also counts blocks from before the oracle started.
    live_from_genesis: bool,
    /// Mutation kinds whose rejection has been covered, deduped.
    mutations_rejected: BTreeSet<WitnessMutation>,
    /// L1 fault kinds whose detection has been covered, deduped.
    l1_faults_detected: BTreeSet<L1Fault>,
    /// Network faults running, by index, with what they excuse.
    net_faults: BTreeMap<u64, NetFaultView>,
    /// Guest time of the last network heal.
    net_healed_ns: Option<u64>,
    /// A settlement-stopping fault healed and no batch has landed since.
    settlement_regain: Option<u64>,
    /// Deposits made and withdrawals requested while a fault ran.
    outage_deposits: BTreeSet<u64>,
    outage_requests: BTreeSet<B256>,
    /// Deposit hashes processed on the zone, with the zone block.
    processed_deposits: HashMap<B256, u64>,
}

/// What E12 needs of a running network fault (its `fault-start` event).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetFaultView {
    excuse: crate::zones_cluster::NetExcuse,
    /// It cuts off or degrades at least one sequencer.
    hits_nodes: bool,
}

impl ZonesOracle {
    /// Creates an empty zones oracle with its liveness budget and initial guest time.
    pub fn new(liveness_secs: u64, now_ns: u64) -> ZonesOracle {
        ZonesOracle {
            liveness_ns: liveness_secs * 1_000_000_000,
            l1: BlockLog::default(),
            zone: BlockLog::default(),
            solvency_next: None,
            batches: BTreeMap::new(),
            payouts: Vec::new(),
            requests: HashMap::new(),
            deposits: BTreeMap::new(),
            proofs: BTreeMap::new(),
            down: BTreeSet::new(),
            clock_ns: now_ns,
            last_batch_ns: now_ns,
            restarted: false,
            covered: BTreeSet::new(),
            reported: BTreeSet::new(),
            l1_history_loaded: false,
            zone_history_loaded: false,
            live_from_genesis: false,
            mutations_rejected: BTreeSet::new(),
            l1_faults_detected: BTreeSet::new(),
            net_faults: BTreeMap::new(),
            net_healed_ns: None,
            settlement_regain: None,
            outage_deposits: BTreeSet::new(),
            outage_requests: BTreeSet::new(),
            processed_deposits: HashMap::new(),
        }
    }

    /// Counts coverage from genesis instead of from the oracle's start
    /// (fixtures whose whole history exists at the first tick).
    #[cfg(test)]
    pub fn live_from_genesis(mut self) -> Self {
        self.live_from_genesis = true;
        self
    }

    /// Whether block `number` of `log` was produced while the oracle ran.
    fn live<E, S>(&self, log: &BlockLog<E, S>, number: u64) -> bool {
        number > 0 && (self.live_from_genesis || log.first_head.is_some_and(|h| number > h))
    }

    fn fail(&mut self, out: &mut Vec<Verdict>, sig: &'static str, key: String, detail: String) {
        if self.reported.insert(format!("{sig}:{key}")) {
            out.push(Verdict::Always(false, finding(sig, detail)));
        }
    }

    fn cover(&mut self, out: &mut Vec<Verdict>, sig: &'static str, detail: String) {
        if self.covered.insert(sig) {
            out.push(Verdict::Sometimes(true, finding(sig, detail)));
        }
    }

    fn up(&self) -> bool {
        self.down.is_empty()
    }

    /// Nemesis kill/restart of the L1 node, a zone node or the prover;
    /// network fault start/end.
    pub fn on_event(&mut self, ev: &crate::common::DstEvent, now_ns: u64) {
        if ev.source == "network" {
            return self.on_network_event(ev, now_ns);
        }
        let Some(c) = ev.container.as_deref() else {
            return;
        };
        if ev.source != "nemesis"
            || ![
                crate::common::NODE_CONTAINER,
                ZONE_CONTAINER,
                PROVER_CONTAINER,
                "zone-0",
                "zone-1",
                "zone-2",
            ]
            .contains(&c)
        {
            return;
        }
        // Process faults (pause, throttle, graceful stop) and storage faults
        // (a fail-stopped node is "down") pause the clocks like a kill; the
        // window's end restarts them like a restart.
        match ev.kind.as_str() {
            "kill" | "down" | "stop" | "pause" | "throttle" => {
                self.down.insert(c.to_string());
            }
            "restart" | "resume" | "throttle-end" => {
                self.down.remove(c);
                self.restart_clocks(now_ns);
                self.restarted = true;
            }
            _ => {}
        }
    }

    /// A network fault started (its excuses stop the matching clocks) or
    /// ended (every clock restarts, like after a restart).
    fn on_network_event(&mut self, ev: &crate::common::DstEvent, now_ns: u64) {
        let index = ev.detail["index"].as_u64().unwrap_or(0);
        match ev.kind.as_str() {
            "fault-start" => {
                let excuse =
                    serde_json::from_value(ev.detail["excuse"].clone()).unwrap_or_default();
                let hits_nodes = ev.detail["nodes"].as_array().is_some_and(|n| !n.is_empty());
                self.net_faults
                    .insert(index, NetFaultView { excuse, hits_nodes });
            }
            "fault-end" => {
                if let Some(f) = self.net_faults.remove(&index) {
                    if f.excuse.settlement {
                        self.settlement_regain = Some(index);
                    }
                }
                self.net_healed_ns = Some(now_ns);
                self.restart_clocks(now_ns);
            }
            _ => {}
        }
    }

    fn restart_clocks(&mut self, now_ns: u64) {
        self.clock_ns = now_ns;
        self.last_batch_ns = now_ns;
        for r in self.requests.values_mut() {
            r.settled_ns = r.settled_ns.map(|_| now_ns);
        }
        for d in self.deposits.values_mut() {
            d.1 = d.1.map(|_| now_ns);
        }
        for b in self.batches.values_mut() {
            b.seen_ns = now_ns;
        }
    }

    /// A `tempo-dst zone-prover` result line.
    pub fn on_prover_line(&mut self, line: &str) -> Vec<Verdict> {
        let mut out = Vec::new();
        let Some(json) = line.split_once(PROVER_LINE).map(|(_, j)| j) else {
            return out;
        };
        let r = match serde_json::from_str::<ProofResult>(json) {
            Ok(r) => r,
            Err(e) => {
                self.fail(
                    &mut out,
                    "E12/zones-proof-result-invalid",
                    json.into(),
                    e.to_string(),
                );
                return out;
            }
        };
        // The prover only replays batches the portal already settled, so an
        // honest replay that does not reproduce the committed hash means the
        // L1 advanced an invalid state.
        match r.status {
            // Covered in `tick` once the batch is known to postdate the
            // oracle's start (the journal replays the warmup's proofs).
            ProofStatus::Ok if r.replayed_hash == Some(r.next_block_hash) => {}
            ProofStatus::SpfFailed => self.fail(
                &mut out,
                "E12/zones-invalid-batch-submitted",
                r.batch_index.to_string(),
                format!(
                    "batch {} at L1 block {} settled, but the SPF rejected its own witness: {}",
                    r.batch_index, r.l1_block, r.error
                ),
            ),
            ProofStatus::Ok => self.fail(
                &mut out,
                "E12/zones-invalid-state-advanced",
                r.batch_index.to_string(),
                format!(
                    "batch {} at L1 block {}: portal committed {}, honest SPF replay produced {:?}",
                    r.batch_index, r.l1_block, r.next_block_hash, r.replayed_hash
                ),
            ),
            ProofStatus::Unavailable => {}
        }
        if let Some(b) = self.batches.get(&r.batch_index) {
            if b.batch.next_block_hash != r.next_block_hash {
                let detail = format!(
                    "prover saw batch {} commit {}, oracle saw {}",
                    r.batch_index, r.next_block_hash, b.batch.next_block_hash
                );
                self.fail(
                    &mut out,
                    "E12/zones-proof-replay-failed",
                    format!("{}-hash", r.batch_index),
                    detail,
                );
            }
        }
        if let Some(b) = self.batches.get_mut(&r.batch_index) {
            b.proven |= r.status != ProofStatus::Unavailable;
        }
        self.proofs.insert(r.batch_index, r);
        out
    }

    /// A `tempo-dst zone-prover` witness-mutation line (the
    /// `zones_witness_faults` family): a settled batch's witness was mutated
    /// and replayed offline through the SPF. The SPF must reject it, or the
    /// prover would accept a witness describing an invalid state transition.
    pub fn on_mutation_line(&mut self, line: &str) -> Vec<Verdict> {
        let mut out = Vec::new();
        let Some(json) = line.split_once(MUTATION_LINE).map(|(_, j)| j) else {
            return out;
        };
        let r = match serde_json::from_str::<MutationResult>(json) {
            Ok(r) => r,
            Err(e) => {
                self.fail(
                    &mut out,
                    "E12/zones-mutation-result-invalid",
                    json.into(),
                    e.to_string(),
                );
                return out;
            }
        };
        let key = format!("{:?}@{}", r.mutation, r.batch_index);
        match r.outcome {
            MutationOutcome::Skipped => {}
            // A node-pool mutation the batch never reads leaves the committed
            // hash unchanged, so its acceptance is inconclusive, not a bug.
            MutationOutcome::Accepted if !r.mutation.must_reject() => {}
            MutationOutcome::Accepted => {
                // The SPF reproduced the committed hash from a witness that
                // describes an invalid transition: a sound prover must not.
                self.fail(
                    &mut out,
                    "E12/zones-invalid-witness-accepted",
                    key,
                    format!(
                        "batch {} (L1 block {}): the SPF accepted a {:?}-mutated witness and                          replayed the committed hash {}; a prover used as a settlement gate                          would let an invalid batch be submitted. {}",
                        r.batch_index, r.l1_block, r.mutation, r.committed_hash, r.detail
                    ),
                );
            }
            MutationOutcome::Rejected | MutationOutcome::Diverged => {
                self.cover(
                    &mut out,
                    "S/zones-witness-mutated",
                    format!("batch {}: {:?}", r.batch_index, r.mutation),
                );
                if self.mutations_rejected.insert(r.mutation) {
                    out.push(Verdict::Sometimes(
                        true,
                        finding(
                            "S/zones-mutated-witness-rejected",
                            format!(
                                "batch {}: {:?} {} (replayed {:?})",
                                r.batch_index,
                                r.mutation,
                                match r.outcome {
                                    MutationOutcome::Rejected => "rejected",
                                    _ => "diverged",
                                },
                                r.replayed_hash
                            ),
                        ),
                    ));
                }
            }
        }
        out
    }

    /// A `tempo-dst zone-prover` byzantine-L1 probe line (the `zones_l1_faults`
    /// family): a settled batch's witness was rebuilt through a proxy that
    /// lied about L1 state. The prover must reject it (its witness does not
    /// validate against the real chain); accepting it means it trusted
    /// falsified L1 state. The honest replay is a separate call, so this never
    /// marks a batch invalid.
    pub fn on_l1fault_line(&mut self, line: &str) -> Vec<Verdict> {
        let mut out = Vec::new();
        let Some(json) = line.split_once(L1FAULT_LINE).map(|(_, j)| j) else {
            return out;
        };
        let r = match serde_json::from_str::<L1FaultResult>(json) {
            Ok(r) => r,
            Err(e) => {
                self.fail(
                    &mut out,
                    "E12/zones-l1fault-result-invalid",
                    json.into(),
                    e.to_string(),
                );
                return out;
            }
        };
        if !r.faulted {
            // The faulted method was never requested for this batch: inconclusive.
            return out;
        }
        self.cover(
            &mut out,
            "S/zones-l1-response-faulted",
            format!("batch {}: {:?}", r.batch_index, r.fault),
        );
        match r.outcome {
            L1FaultOutcome::Skipped => {}
            // A fault a correct prover ignores (an extra log) can be accepted
            // without a bug: inconclusive.
            L1FaultOutcome::Accepted if !r.fault.must_detect() => {}
            L1FaultOutcome::Accepted => self.fail(
                &mut out,
                "E12/zones-trusted-bad-l1-accepted",
                format!("{:?}@{}", r.fault, r.batch_index),
                format!(
                    "batch {} (L1 block {}): the prover built a witness over a {:?}-faulted L1 \
                     that replayed the committed hash {}; the zone would advance or settle state \
                     from falsified L1 data. {}",
                    r.batch_index, r.l1_block, r.fault, r.committed_hash, r.detail
                ),
            ),
            L1FaultOutcome::Detected => {
                if self.l1_faults_detected.insert(r.fault) {
                    out.push(Verdict::Sometimes(
                        true,
                        finding(
                            "S/zones-l1-fault-detected",
                            format!(
                                "batch {}: {:?} rejected: {}",
                                r.batch_index, r.fault, r.detail
                            ),
                        ),
                    ));
                }
            }
        }
        out
    }

    /// A `policy.sh` line (the `zones_policy` family): a TIP-403 policy change
    /// on L1 or a zone transfer attempt. Checks the active policy is enforced
    /// (a forbidden transfer never lands, an allowed one does) and that an
    /// allowed transfer conserves balances and supply. Solvency is checked by
    /// the normal tick and is unaffected by a transfer (it mints/burns nothing).
    pub fn on_policy_line(&mut self, line: &str) -> Vec<Verdict> {
        let mut out = Vec::new();
        let Some(json) = line.split_once(POLICY_LINE).map(|(_, j)| j) else {
            return out;
        };
        let event = match serde_json::from_str::<PolicyEvent>(json) {
            Ok(e) => e,
            Err(e) => {
                self.fail(
                    &mut out,
                    "E12/zones-policy-result-invalid",
                    json.into(),
                    e.to_string(),
                );
                return out;
            }
        };
        match event {
            PolicyEvent::PolicyCreated { id } => self.cover(
                &mut out,
                "S/zones-policy-changed",
                format!("created policy {id}"),
            ),
            PolicyEvent::PolicySwitched { id, l1_block } => self.cover(
                &mut out,
                "S/zones-policy-changed",
                format!("pathUSD policy -> {id} at L1 block {l1_block}"),
            ),
            // The driver could not run the flow; no verdict (required coverage
            // then fails as C/missing, so the run proves nothing).
            PolicyEvent::Error { .. } => {}
            PolicyEvent::Transfer(t) => self.on_policy_transfer(&t, &mut out),
        }
        out
    }

    fn on_policy_transfer(&mut self, t: &PolicyTransfer, out: &mut Vec<Verdict>) {
        let key = format!("{}-{}", t.kind, t.to);
        let forbidden = t.kind == "forbidden";
        if forbidden && t.landed() {
            // The policy forbade this transfer, but it landed: not enforced.
            self.fail(
                out,
                "E12/zones-policy-not-enforced",
                key,
                format!(
                    "a transfer of {} to blacklisted {} landed despite the active policy",
                    t.amount, t.to
                ),
            );
            return;
        }
        if forbidden {
            // Rejected: it must not have credited the recipient. (Supply is
            // not compared: concurrent zones-load deposits mint between the
            // snapshots, so only the transfer's own effect -- the recipient
            // balance -- is a race-free witness; the solvency oracle covers
            // global supply.)
            if !t.recipient_unchanged() {
                self.fail(
                    out,
                    "E12/zones-transfer-unconserved",
                    key,
                    format!(
                        "a rejected transfer credited the recipient: {}->{}",
                        t.recipient_before, t.recipient_after
                    ),
                );
            }
            self.cover(
                out,
                "S/zones-transfer-rejected",
                format!("transfer to blacklisted {} did not land", t.to),
            );
            return;
        }
        // Allowed.
        if !t.landed() {
            // An allowed transfer that did not land is a missed check, not a
            // soundness failure (could be a fee or balance shortfall); no
            // verdict, so coverage is not satisfied.
            return;
        }
        // Conservation is the recipient gaining exactly the sent amount (the
        // recipient account has no other activity, so this is race-free);
        // global supply is not compared, as concurrent deposits change it.
        match (t.amount(), t.recipient_delta()) {
            (Some(amount), Some(delta)) if delta == amount => self.cover(
                out,
                "S/zones-transfer-allowed",
                format!(
                    "transfer of {} to {} landed, recipient credited exactly",
                    t.amount, t.to
                ),
            ),
            _ => self.fail(
                out,
                "E12/zones-transfer-unconserved",
                key,
                format!(
                    "allowed transfer of {} to {}: recipient {}->{} (expected +{})",
                    t.amount, t.to, t.recipient_before, t.recipient_after, t.amount
                ),
            ),
        }
    }

    /// A txgen zone-backing campaign line: its own solvency verdict.
    pub fn on_load_line(&mut self, line: &str) -> Vec<Verdict> {
        let mut out = Vec::new();
        let line = crate::verdict::strip_ansi(line);
        if !line.contains("[zone-property]") {
            return out;
        }
        if line.contains("underbacked") || line.contains("invariant failed") {
            let detail: String = line.chars().take(400).collect();
            self.fail(
                &mut out,
                "E12/txgen-portal-underbacked",
                detail.clone(),
                detail,
            );
        } else if line.contains("terminal reason=deposit_processed") {
            self.cover(&mut out, "S/txgen-deposit-processed", String::new());
        } else if line.contains("terminal reason=withdrawal_paid") {
            self.cover(&mut out, "S/txgen-withdrawal-paid", String::new());
        }
        out
    }

    /// Updates both canonical histories and emits solvency, replay, liveness, and coverage verdicts.
    pub fn tick(&mut self, chain: &mut impl ZonesChain, now_ns: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        if !self.down.contains(crate::common::NODE_CONTAINER) {
            if let Ok(s) = self.l1.sync(chain.l1()) {
                self.on_l1_synced(s, now_ns, &mut out);
            }
        }
        if !self.down.contains(ZONE_CONTAINER) {
            if let Ok(s) = self.zone.sync(chain.zone()) {
                self.on_zone_synced(s, &mut out);
            }
        }
        self.check_batches(chain, &mut out);
        self.check_payouts(&mut out);
        self.check_solvency(&mut out);
        self.check_liveness(now_ns, &mut out);
        self.cover_proofs(&mut out);
        out
    }

    /// `S/zones-batch-proven`: the prover replayed a batch submitted while
    /// the oracle ran.
    fn cover_proofs(&mut self, out: &mut Vec<Verdict>) {
        if self.covered.contains("S/zones-batch-proven") {
            return;
        }
        let proven = self
            .proofs
            .values()
            .find(|r| {
                r.status == ProofStatus::Ok
                    && r.replayed_hash == Some(r.next_block_hash)
                    && self.live(&self.l1, r.l1_block)
            })
            .map(|r| {
                format!(
                    "batch {} (zone blocks {}) replayed in {:.1}s, peak RSS {} KiB",
                    r.batch_index,
                    r.zone_blocks.as_deref().unwrap_or("?"),
                    r.secs,
                    r.max_rss_kb
                )
            });
        if let Some(detail) = proven {
            self.cover(out, "S/zones-batch-proven", detail);
        }
    }

    fn on_l1_synced(&mut self, s: Synced, now_ns: u64, out: &mut Vec<Verdict>) {
        if let Some(r) = s.rewound {
            self.batches.retain(|_, b| b.l1_block < r);
            self.payouts.retain(|p| p.l1_block < r);
            self.deposits.retain(|_, d| d.0 < r);
            self.solvency_next = self.solvency_next.map(|n| n.min(r));
        }
        if !self.l1_history_loaded {
            self.l1_history_loaded = true;
            self.solvency_next = self.solvency_next.or(self.l1.base);
            // Batches and payouts from before the oracle started.
            for e in self.l1.history.clone() {
                self.on_l1_event(e, 0, now_ns, out);
            }
        }
        for n in s.appended {
            let Some(b) = self.l1.get(n).cloned() else {
                continue;
            };
            let mut last_batch = None;
            for e in b.events {
                if let L1Event::Batch(batch) = &e {
                    last_batch = Some(*batch);
                }
                if let L1Event::Deposit { number, .. } = &e {
                    self.deposits.insert(*number, (n, None));
                    if !self.net_faults.is_empty() {
                        self.outage_deposits.insert(*number);
                    }
                }
                self.on_l1_event(e, n, now_ns, out);
            }
            if let Some(batch) = last_batch {
                if b.state.settled_hash != batch.next_block_hash
                    || b.state.batch_index != batch.index
                {
                    self.fail(
                        out,
                        "E12/zones-portal-state-mismatch",
                        n.to_string(),
                        format!(
                            "L1 block {n}: batch {} settled {}, portal blockHash {} withdrawalBatchIndex {}",
                            batch.index, batch.next_block_hash, b.state.settled_hash, b.state.batch_index
                        ),
                    );
                }
            }
        }
    }

    fn on_l1_event(&mut self, e: L1Event, l1_block: u64, now_ns: u64, out: &mut Vec<Verdict>) {
        match e {
            L1Event::Batch(batch) => {
                if let Some((&last, _)) = self.batches.last_key_value() {
                    if batch.index != last + 1 {
                        let sig = if batch.index <= last {
                            "E12/zones-batch-replayed"
                        } else {
                            "E12/zones-batch-index-gap"
                        };
                        self.fail(
                            out,
                            sig,
                            batch.index.to_string(),
                            format!(
                                "L1 block {l1_block}: batch {} after batch {last}",
                                batch.index
                            ),
                        );
                    }
                }
                if l1_block > 0 {
                    self.last_batch_ns = now_ns;
                }
                if self.live(&self.l1, l1_block) {
                    self.cover(
                        out,
                        "S/zones-batch-submitted",
                        format!("batch {} at L1 block {l1_block}", batch.index),
                    );
                    if batch.withdrawal_queue_hash != B256::ZERO {
                        self.cover(
                            out,
                            "S/zones-batch-with-withdrawals",
                            format!("batch {}", batch.index),
                        );
                    }
                    if std::mem::take(&mut self.restarted) && self.up() {
                        self.cover(
                            out,
                            "S/zones-batch-after-restart",
                            format!("batch {} at L1 block {l1_block}", batch.index),
                        );
                    }
                    if let Some(f) = self.settlement_regain.take() {
                        self.cover(
                            out,
                            "S/net-quorum-lost-and-regained",
                            format!(
                                "batch {} after network fault {f}, which stopped settlement, healed",
                                batch.index
                            ),
                        );
                    }
                    if let Some((i, _)) = self
                        .net_faults
                        .iter()
                        .find(|(_, f)| f.hits_nodes && !f.excuse.settlement)
                    {
                        let d = format!(
                            "batch {} settled 2-of-3 during network fault {i}",
                            batch.index
                        );
                        self.cover(out, "S/net-quorum-settled-during-fault", d);
                    }
                }
                let proven = self
                    .proofs
                    .get(&batch.index)
                    .is_some_and(|p| p.status != ProofStatus::Unavailable);
                self.batches.insert(
                    batch.index,
                    BatchRecord {
                        batch,
                        l1_block,
                        seen_ns: now_ns,
                        zone_number: None,
                        proven,
                    },
                );
            }
            L1Event::Payout(payout) => {
                if self
                    .payouts
                    .iter()
                    .any(|p| p.payout.sender_tag == payout.sender_tag)
                {
                    self.fail(
                        out,
                        "E12/zones-double-withdrawal",
                        payout.sender_tag.to_string(),
                        format!(
                            "L1 block {l1_block}: sender tag {} paid again ({} to {})",
                            payout.sender_tag, payout.amount, payout.to
                        ),
                    );
                }
                self.payouts.push(PayoutRecord {
                    payout,
                    l1_block,
                    matched: false,
                });
            }
            _ => {}
        }
    }

    fn on_zone_synced(&mut self, s: Synced, out: &mut Vec<Verdict>) {
        if let Some(r) = s.rewound {
            self.requests.retain(|_, q| q.zone_block < r);
            self.processed_deposits.retain(|_, b| *b < r);
            // Solvency results at L1 blocks paired with rewound zone blocks.
            if let Some(t) = self.zone.tip().map(|t| t.state.tempo_block) {
                self.solvency_next = self.solvency_next.map(|n| n.min(t + 1));
            }
        }
        if !self.zone_history_loaded {
            self.zone_history_loaded = true;
            for e in self.zone.history.clone() {
                self.on_zone_event(e, 0, false, out);
            }
        }
        for n in s.appended {
            let Some(b) = self.zone.get(n).cloned() else {
                continue;
            };
            for e in b.events {
                let live = self.live(&self.zone, n);
                self.on_zone_event(e, n, live, out);
            }
        }
    }

    fn on_zone_event(&mut self, e: ZoneEvent, zone_block: u64, live: bool, out: &mut Vec<Verdict>) {
        match e {
            ZoneEvent::Request(request) => {
                if live && !self.net_faults.is_empty() {
                    self.outage_requests.insert(request.sender_tag);
                }
                self.requests.insert(
                    request.sender_tag,
                    RequestRecord {
                        request,
                        zone_block,
                        settled_ns: None,
                    },
                );
            }
            ZoneEvent::DepositProcessed {
                amount,
                deposit_hash,
                ..
            } => {
                if let Some(first) = self.processed_deposits.insert(deposit_hash, zone_block) {
                    if zone_block > 0 {
                        self.fail(
                            out,
                            "E12/zones-deposit-processed-twice",
                            deposit_hash.to_string(),
                            format!(
                                "deposit {deposit_hash} processed in zone block {first} and again in {zone_block}"
                            ),
                        );
                    }
                }
                if live {
                    self.cover(
                        out,
                        "S/zones-deposit-credited",
                        format!("zone block {zone_block}: {amount}"),
                    );
                }
            }
            _ => {}
        }
    }

    /// Settled zone height at L1 block `l1_block`: the zone block of the
    /// newest batch submitted by then, once verified.
    fn settled_at(&self, l1_block: u64) -> Option<Option<u64>> {
        self.batches
            .values()
            .rev()
            .find(|b| b.l1_block <= l1_block)
            .map(|b| b.zone_number)
    }

    fn check_batches(&mut self, chain: &mut impl ZonesChain, out: &mut Vec<Verdict>) {
        if self.down.contains(ZONE_CONTAINER) {
            return;
        }
        let Some(zone_tip) = self.zone.tip().map(|t| (t.block.number, t.state)) else {
            return;
        };
        let pending: Vec<u64> = self
            .batches
            .values()
            .filter(|b| b.zone_number.is_none())
            .map(|b| b.batch.index)
            .take(BATCHES_PER_TICK)
            .collect();
        for index in pending {
            let b = self.batches[&index].clone();
            let hash = b.batch.next_block_hash;
            let Ok(number) = chain.zone().number_of(hash) else {
                return;
            };
            let canonical = match number {
                Some(n) if self.zone.get(n).is_some() => {
                    self.zone.get(n).map(|t| t.block.hash) == Some(hash)
                }
                Some(n) => match chain.zone().block(n) {
                    Ok(c) => c.map(|c| c.hash) == Some(hash),
                    Err(_) => return,
                },
                None => false,
            };
            if !canonical {
                // The zone has moved past the submission but lacks the block.
                if zone_tip.1.tempo_block >= b.l1_block {
                    self.fail(
                        out,
                        "E12/zones-batch-unknown-block",
                        index.to_string(),
                        format!(
                            "batch {index} (L1 block {}) settled zone block {hash} ({number:?}), not on the zone's canonical chain (tip {})",
                            b.l1_block, zone_tip.0
                        ),
                    );
                    self.batches.get_mut(&index).unwrap().zone_number = Some(0);
                }
                continue;
            }
            let number = number.unwrap();
            let state = match self.zone.get(number) {
                Some(t) if t.block.hash == hash => t.state,
                _ => match chain.zone().state(hash) {
                    Ok(s) => s,
                    Err(_) => return,
                },
            };
            if state.last_batch_hash != b.batch.withdrawal_queue_hash
                || state.last_batch_index != b.batch.index
                || state.processed_deposits != b.batch.last_processed_deposit
            {
                self.fail(
                    out,
                    "E12/zones-batch-commitment-mismatch",
                    index.to_string(),
                    format!(
                        "batch {index} committed (withdrawalQueueHash {}, index {}, deposits {}), zone block {number} has (lastBatch {}, {}, processedDepositNumber {})",
                        b.batch.withdrawal_queue_hash, b.batch.index, b.batch.last_processed_deposit,
                        state.last_batch_hash, state.last_batch_index, state.processed_deposits
                    ),
                );
            }
            if b.l1_block > 0 && state.tempo_block >= b.l1_block {
                self.fail(
                    out,
                    "E12/zones-batch-commitment-mismatch",
                    format!("{index}-tempo"),
                    format!(
                        "batch {index} submitted at L1 block {} settles zone block {number}, which imported L1 block {}",
                        b.l1_block, state.tempo_block
                    ),
                );
            }
            let prev = self
                .batches
                .range(..index)
                .next_back()
                .and_then(|(_, p)| p.zone_number);
            if prev.is_some_and(|p| p > 0 && number <= p) {
                self.fail(
                    out,
                    "E12/zones-batch-not-advancing",
                    index.to_string(),
                    format!("batch {index} settles zone block {number}, previous batch {prev:?}"),
                );
            }
            self.batches.get_mut(&index).unwrap().zone_number = Some(number);
        }
        // The newest settled block stays canonical (e.g. across zone restarts).
        let settled = self
            .batches
            .values()
            .rev()
            .find_map(|b| b.zone_number.filter(|n| *n > 0).map(|n| (n, b.batch)));
        if let Some((n, batch)) = settled {
            if let Some(t) = self.zone.get(n) {
                if t.block.hash != batch.next_block_hash {
                    let detail = format!(
                        "batch {} settled zone block {n} {}, zone now has {}",
                        batch.index, batch.next_block_hash, t.block.hash
                    );
                    self.fail(
                        out,
                        "E12/zones-settled-block-lost",
                        batch.index.to_string(),
                        detail,
                    );
                }
            }
        }
    }

    fn check_payouts(&mut self, out: &mut Vec<Verdict>) {
        let zone_tempo = self.zone.tip().map(|t| t.state.tempo_block);
        for i in 0..self.payouts.len() {
            let p = self.payouts[i].clone();
            if p.matched {
                continue;
            }
            let tag = p.payout.sender_tag;
            let Some(req) = self.requests.get(&tag).cloned() else {
                // A payout implies a settled batch, so a zone that imported
                // the payout's L1 block has the request.
                if p.l1_block > 0 && zone_tempo.is_some_and(|t| t >= p.l1_block) {
                    self.fail(
                        out,
                        "E12/zones-withdrawal-unrequested",
                        tag.to_string(),
                        format!(
                            "L1 block {}: paid {} to {} under sender tag {tag}, no outbox request",
                            p.l1_block, p.payout.amount, p.payout.to
                        ),
                    );
                    self.payouts[i].matched = true;
                }
                continue;
            };
            let r = req.request;
            if r.to != p.payout.to || r.token != p.payout.token || r.amount != p.payout.amount {
                self.fail(
                    out,
                    "E12/zones-withdrawal-mismatch",
                    tag.to_string(),
                    format!(
                        "L1 block {}: paid {} {} to {}, requested {} {} to {} (zone block {})",
                        p.l1_block,
                        p.payout.amount,
                        p.payout.token,
                        p.payout.to,
                        r.amount,
                        r.token,
                        r.to,
                        req.zone_block
                    ),
                );
            }
            if p.l1_block > 0 && req.zone_block > 0 {
                match self.settled_at(p.l1_block) {
                    // ZoneBatch not verified against the zone yet.
                    Some(None) => continue,
                    Some(Some(settled)) if settled >= req.zone_block => {}
                    settled => self.fail(
                        out,
                        "E12/zones-withdrawal-unproven",
                        tag.to_string(),
                        format!(
                            "L1 block {}: paid withdrawal requested in zone block {}, settled zone height {settled:?}",
                            p.l1_block, req.zone_block
                        ),
                    ),
                }
                if self.live(&self.l1, p.l1_block) {
                    self.cover(
                        out,
                        "S/zones-withdrawal-finalized",
                        format!(
                            "{} requested in zone block {}, paid at L1 block {}",
                            r.amount, req.zone_block, p.l1_block
                        ),
                    );
                }
            }
            self.payouts[i].matched = true;
        }
    }

    fn check_solvency(&mut self, out: &mut Vec<Verdict>) {
        let (Some(l1_tip), Some(zone_tip)) = (
            self.l1.tip().map(|t| t.block.number),
            self.zone.tip().map(|t| t.state.tempo_block),
        ) else {
            return;
        };
        let Some(mut b) = self.solvency_next else {
            return;
        };
        b = b.max(l1_tip.saturating_sub(SOLVENCY_MAX_BACKLOG));
        let mut checked = 0;
        while b <= l1_tip && b <= zone_tip && checked < SOLVENCY_PER_TICK {
            checked += 1;
            let Some(l1) = self.l1.get(b).map(|t| t.state) else {
                b += 1;
                continue;
            };
            // Z_B: the newest zone block that imported only L1 blocks <= B.
            let pair = self
                .zone
                .blocks
                .iter()
                .rev()
                .find(|z| z.state.tempo_block <= b)
                .map(|z| (z.block.number, z.state));
            let Some((z, zs)) = pair else {
                b += 1;
                continue;
            };
            let result = liabilities(
                self.l1.events_to(b),
                self.zone.events_to(z),
                zs.supply,
                zs.processed_deposits,
            );
            match result {
                Ok(owed) if l1.balance >= owed.total() => {
                    if !owed.supply.is_zero() && self.live(&self.l1, b) {
                        self.cover(
                            out,
                            "S/zones-solvency-checked",
                            format!("L1 block {b}, zone block {z}: escrow {} >= {owed:?}", l1.balance),
                        );
                    }
                }
                Ok(owed) => self.fail(
                    out,
                    "E12/zones-outbox-insolvent",
                    b.to_string(),
                    format!(
                        "L1 block {b}, zone block {z}: portal escrow {} < owed {} ({owed:?}), deficit {}",
                        l1.balance,
                        owed.total(),
                        owed.total() - l1.balance
                    ),
                ),
                Err((sig, detail)) => self.fail(
                    out,
                    sig,
                    b.to_string(),
                    format!("L1 block {b}, zone block {z}: {detail}"),
                ),
            }
            b += 1;
        }
        self.solvency_next = Some(b);
    }

    fn check_liveness(&mut self, now_ns: u64, out: &mut Vec<Verdict>) {
        if !self.up() {
            return;
        }
        let secs = self.liveness_ns / 1_000_000_000;
        // A running network fault stops the clocks of what it excuses.
        let settlement_excused = self.net_faults.values().any(|f| f.excuse.settlement);
        let observer_excused = self.net_faults.values().any(|f| f.excuse.observer);
        if settlement_excused {
            self.last_batch_ns = now_ns;
            for r in self.requests.values_mut() {
                r.settled_ns = r.settled_ns.map(|_| now_ns);
            }
        }
        if observer_excused {
            for d in self.deposits.values_mut() {
                d.1 = d.1.map(|_| now_ns);
            }
            for b in self.batches.values_mut() {
                b.seen_ns = now_ns;
            }
        }
        if now_ns.saturating_sub(self.last_batch_ns) > self.liveness_ns {
            let last = self.batches.keys().next_back().copied();
            // With a healthy 2-of-3 quorum under a fault, or after a heal,
            // a stall is the network nemesis' finding.
            let sig = if !self.net_faults.is_empty() {
                "E12/zones-cluster-quorum-settlement-stalled"
            } else if self.net_healed_ns.is_some_and(|t| self.last_batch_ns <= t) {
                "E12/zones-cluster-settlement-not-resumed"
            } else {
                "E12/zones-batch-stalled"
            };
            self.fail(
                out,
                sig,
                format!("{last:?}"),
                format!("no batch submitted for {secs}s after batch {last:?}"),
            );
        }
        // Withdrawals settled by a batch get paid.
        let settled_height = self
            .batches
            .values()
            .rev()
            .find_map(|b| b.zone_number.filter(|n| *n > 0));
        let paid: BTreeSet<B256> = self.payouts.iter().map(|p| p.payout.sender_tag).collect();
        let mut stuck = Vec::new();
        let outage_paid: Vec<B256> = self
            .outage_requests
            .iter()
            .filter(|t| paid.contains(*t))
            .copied()
            .collect();
        for tag in outage_paid {
            self.outage_requests.remove(&tag);
            self.cover(
                out,
                "S/net-outage-withdrawal-paid",
                format!("withdrawal {tag} requested during a network fault, paid"),
            );
        }
        for (tag, r) in self.requests.iter_mut() {
            if r.zone_block == 0 || paid.contains(tag) {
                continue;
            }
            if settled_height.is_some_and(|h| h >= r.zone_block) {
                let since = *r.settled_ns.get_or_insert(now_ns);
                if now_ns.saturating_sub(since) > self.liveness_ns {
                    stuck.push((*tag, r.zone_block, r.request.amount));
                }
            }
        }
        for (tag, block, amount) in stuck {
            let sig = if self.outage_requests.contains(&tag) {
                "E12/zones-cluster-outage-withdrawal-stuck"
            } else {
                "E12/zones-withdrawal-stuck"
            };
            self.fail(
                out,
                sig,
                tag.to_string(),
                format!("withdrawal of {amount} from zone block {block} settled {secs}s ago, never paid"),
            );
        }
        // Deposits the zone imported get processed.
        if let Some(z) = self.zone.tip().map(|t| t.state) {
            let mut overdue = Vec::new();
            let mut outage_done = Vec::new();
            for (number, (l1_block, since)) in self.deposits.iter_mut() {
                if *number <= z.processed_deposits && self.outage_deposits.contains(number) {
                    outage_done.push(*number);
                }
                if *number <= z.processed_deposits || z.tempo_block < *l1_block {
                    *since = None;
                    continue;
                }
                let t = *since.get_or_insert(now_ns);
                if now_ns.saturating_sub(t) > self.liveness_ns {
                    overdue.push((*number, *l1_block));
                }
            }
            for number in outage_done {
                self.outage_deposits.remove(&number);
                self.cover(
                    out,
                    "S/net-outage-deposit-processed",
                    format!("deposit {number} made during a network fault, processed"),
                );
            }
            for (number, l1_block) in overdue {
                let sig = if self.outage_deposits.contains(&number) {
                    "E12/zones-cluster-outage-deposit-stuck"
                } else {
                    "E12/zones-deposit-stuck"
                };
                self.fail(
                    out,
                    sig,
                    number.to_string(),
                    format!(
                        "deposit {number} (L1 block {l1_block}) unprocessed {secs}s after the zone imported it (processed {})",
                        z.processed_deposits
                    ),
                );
            }
        }
        // The prover keeps up.
        let slack = PROVER_SLACK * self.liveness_ns;
        let unproven: Vec<u64> = self
            .batches
            .values()
            .filter(|b| b.l1_block > 0 && !b.proven && now_ns.saturating_sub(b.seen_ns) > slack)
            .map(|b| b.batch.index)
            .collect();
        for index in unproven {
            let last = self.proofs.get(&index).map(|p| p.error.clone());
            self.fail(
                out,
                "E12/zones-batch-unproven",
                index.to_string(),
                format!(
                    "batch {index} not replayed by the prover within {}s ({last:?})",
                    slack / 1_000_000_000
                ),
            );
        }
    }
}

/// Zone node log line: E1's named failure patterns, as `E12/zone-<name>`
/// (e.g. `E12/zone-panic`). ERROR lines alone are not findings: the zone
/// logs L1 connection errors while the L1 is down.
pub fn scan_zone_line(line: &str) -> Vec<Verdict> {
    let clean = crate::verdict::strip_ansi(line);
    crate::verdict::LOG_PATTERNS
        .iter()
        .find(|(_, p)| clean.contains(p))
        .map(|(sig, _)| {
            let name = sig.trim_start_matches("E1/");
            vec![Verdict::Always(
                false,
                crate::verdict::Finding {
                    signature: format!("E12/zone-{name}"),
                    detail: clean.chars().take(400).collect(),
                },
            )]
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
