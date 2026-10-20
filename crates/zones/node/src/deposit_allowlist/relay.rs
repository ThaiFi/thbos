//! Relays `zoneAdmin` allowlist requests from an RPC-only node to every sequencer over P2P.
//!
//! The RPC-only node serves the operator-facing RPC but holds no allowlist and no admin key. It
//! checks each write's admin signature and deadline, then sends the request unchanged to every
//! quorum member, which checks it again, applies it to its own persisted list, and acknowledges
//! it. The call returns only after
//! every member acknowledged, so a success means every sequencer will enforce the change on its
//! next block.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy_primitives::{Address, Bytes};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use zone_p2p::{MAX_ALLOWLIST_PAYLOAD_SIZE, P2pCommand, P2pEvent, P2pPeerId};

use super::{
    DepositAllowlist, DepositAllowlistAdmin, DepositAllowlistApiServer, DepositAllowlistError,
    SignedWrite, Write,
};

/// How long a relayed request waits for every sequencer before failing.
const RELAY_TIMEOUT: Duration = Duration::from_secs(10);
/// How often an unacknowledged request is resent to the sequencers still missing.
const RELAY_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Requests relayed at once; more fail fast so clients cannot flood the allowlist channel.
const MAX_IN_FLIGHT_RELAYS: usize = 4;

/// An allowlist request relayed over P2P, tagged so acknowledgements match their request.
#[derive(Debug, Serialize, Deserialize)]
struct Update {
    id: u64,
    request: Request,
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Write(SignedWrite),
    Get,
}

/// A sequencer's result for one relayed request, or the reason it was rejected.
#[derive(Debug, Serialize, Deserialize)]
struct Ack {
    id: u64,
    result: Result<Response, DepositAllowlistError>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Response {
    /// The write is persisted.
    Applied,
    /// The list, answering `Get`.
    Addresses(Vec<Address>),
}

type PendingAcks = Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<(P2pPeerId, Ack)>>>>;

/// Removes a request's acknowledgement route on every exit, including a cancelled RPC call.
struct PendingGuard<'a> {
    pending: &'a PendingAcks,
    id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.pending.lock().remove(&self.id);
    }
}

/// `zoneAdmin` API on an RPC-only node, relaying requests to the sequencers it lists.
#[derive(Clone)]
pub(crate) struct AllowlistRelay {
    sequencers: Vec<P2pPeerId>,
    commands: mpsc::Sender<P2pCommand>,
    /// Rejects writes the sequencers would reject before they use P2P bandwidth.
    admin: DepositAllowlistAdmin,
    in_flight: Arc<tokio::sync::Semaphore>,
    pending: PendingAcks,
    /// Starts at a random value so a sequencer's late acknowledgement for a request from before
    /// a restart cannot match a new request.
    next_id: Arc<AtomicU64>,
}

impl AllowlistRelay {
    /// Create a relay to `sequencers`. Feed received acknowledgements through
    /// [`Self::handle_event`].
    pub(crate) fn new(
        sequencers: Vec<P2pPeerId>,
        commands: mpsc::Sender<P2pCommand>,
        admin: DepositAllowlistAdmin,
    ) -> Self {
        Self {
            sequencers,
            commands,
            admin,
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_RELAYS)),
            pending: Default::default(),
            next_id: Arc::new(AtomicU64::new(rand::random())),
        }
    }

    /// Route an [`P2pEvent::AllowlistAckReceived`] to the request waiting for it.
    pub(crate) fn handle_event(&self, event: P2pEvent) {
        let P2pEvent::AllowlistAckReceived { peer, ack } = event else {
            return;
        };
        let ack: Ack = match serde_json::from_slice(&ack) {
            Ok(ack) => ack,
            Err(err) => {
                warn!(target: "zone::allowlist", %peer, %err, "Ignoring malformed allowlist acknowledgement");
                return;
            }
        };
        let id = ack.id;
        let Some(waiter) = self.pending.lock().get(&id).cloned() else {
            debug!(target: "zone::allowlist", %peer, id, "Ignoring allowlist acknowledgement for a finished request");
            return;
        };
        if waiter.send((peer, ack)).is_err() {
            debug!(target: "zone::allowlist", id, "Allowlist request finished before its acknowledgement arrived");
        }
    }

    /// Send `request` to every sequencer and return each one's result once all have answered.
    async fn relay(&self, request: Request) -> RpcResult<Vec<(P2pPeerId, Response)>> {
        let _permit = self
            .in_flight
            .try_acquire()
            .map_err(|_| DepositAllowlistError::Busy)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let update = serde_json::to_vec(&Update { id, request })
            .map_err(|err| relay_error(format!("failed to encode request: {err}")))?;
        if update.len() > MAX_ALLOWLIST_PAYLOAD_SIZE {
            return Err(relay_error(format!(
                "request encodes to {} bytes; the relay limit is {MAX_ALLOWLIST_PAYLOAD_SIZE}",
                update.len()
            )));
        }
        let (acks_tx, mut acks) = mpsc::unbounded_channel();
        self.pending.lock().insert(id, acks_tx);
        let _guard = PendingGuard {
            pending: &self.pending,
            id,
        };
        self.collect_acks(&update, &mut acks).await
    }

    async fn collect_acks(
        &self,
        update: &[u8],
        acks: &mut mpsc::UnboundedReceiver<(P2pPeerId, Ack)>,
    ) -> RpcResult<Vec<(P2pPeerId, Response)>> {
        let mut missing = self.sequencers.clone();
        let mut results = Vec::with_capacity(missing.len());
        let mut errors = Vec::new();
        let deadline = tokio::time::Instant::now() + RELAY_TIMEOUT;
        let mut retry = tokio::time::interval(RELAY_RETRY_INTERVAL);
        while !missing.is_empty() {
            tokio::select! {
                _ = retry.tick() => {
                    for peer in &missing {
                        self.commands
                            .send(P2pCommand::SendAllowlistUpdate { peer: peer.clone(), update: update.to_vec() })
                            .await
                            .map_err(|_| relay_error("P2P command channel closed".to_owned()))?;
                    }
                }
                Some((peer, ack)) = acks.recv() => {
                    if let Some(index) = missing.iter().position(|missing| *missing == peer) {
                        missing.swap_remove(index);
                        match ack.result {
                            Ok(response) => results.push((peer, response)),
                            Err(error) => errors.push(format!("{peer}: {error}")),
                        }
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    let missing = missing.iter().map(ToString::to_string).collect::<Vec<_>>();
                    errors.push(format!("no acknowledgement from sequencers {}", missing.join(", ")));
                    break;
                }
            }
        }
        if errors.is_empty() {
            Ok(results)
        } else {
            Err(relay_error(errors.join("; ")))
        }
    }

    async fn relay_write(&self, write: SignedWrite) -> RpcResult<()> {
        self.admin.authorize(&write)?;
        let unexpected = self
            .relay(Request::Write(write))
            .await?
            .into_iter()
            .filter(|(_, response)| *response != Response::Applied)
            .map(|(peer, _)| peer.to_string())
            .collect::<Vec<_>>();
        if unexpected.is_empty() {
            Ok(())
        } else {
            Err(relay_error(format!(
                "unexpected write acknowledgement from {}",
                unexpected.join(", ")
            )))
        }
    }
}

#[jsonrpsee::core::async_trait]
impl DepositAllowlistApiServer for AllowlistRelay {
    async fn set_deposit_allowed(
        &self,
        addresses: Vec<Address>,
        allowed: bool,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        let count = addresses.len();
        self.relay_write(SignedWrite {
            write: Write::Set { addresses, allowed },
            nonce,
            deadline,
            signature,
        })
        .await?;
        info!(target: "zone::allowlist", count, allowed, "Relayed deposit allowlist update to every sequencer");
        Ok(())
    }

    async fn replace_deposit_allowlist(
        &self,
        addresses: Vec<Address>,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        let count = addresses.len();
        self.relay_write(SignedWrite {
            write: Write::Replace { addresses },
            nonce,
            deadline,
            signature,
        })
        .await?;
        info!(target: "zone::allowlist", count, "Relayed deposit allowlist replacement to every sequencer");
        Ok(())
    }

    async fn get_deposit_allowlist(&self) -> RpcResult<Vec<Address>> {
        let mut results = Vec::new();
        for (peer, response) in self.relay(Request::Get).await? {
            let Response::Addresses(addresses) = response else {
                return Err(relay_error(format!(
                    "unexpected read acknowledgement from {peer}"
                )));
            };
            results.push((peer, addresses));
        }
        let mut results = results.into_iter();
        let Some((_, first)) = results.next() else {
            return Ok(Vec::new());
        };
        let diverged = results
            .filter(|(_, addresses)| *addresses != first)
            .map(|(peer, _)| peer.to_string())
            .collect::<Vec<_>>();
        if diverged.is_empty() {
            Ok(first)
        } else {
            Err(relay_error(format!(
                "sequencer allowlists differ; {} disagree with the first response",
                diverged.join(", ")
            )))
        }
    }
}

/// Apply relayed requests on a sequencer and acknowledge each one to its relayer.
///
/// A relayer resends a request until it is acknowledged, so the last acknowledgement sent to
/// each relayer is kept and resent for a repeated request instead of handling it again.
pub(crate) async fn apply_relayed_updates(
    allowlist: Option<DepositAllowlist>,
    mut events: mpsc::Receiver<P2pEvent>,
    commands: mpsc::Sender<P2pCommand>,
) {
    // Keyed by relayer, which routing limits to the manifest's RPC-only members.
    let mut last_acks: HashMap<P2pPeerId, (u64, Vec<u8>)> = HashMap::new();
    while let Some(event) = events.recv().await {
        let P2pEvent::AllowlistUpdateReceived { peer, update } = event else {
            continue;
        };
        let update: Update = match serde_json::from_slice(&update) {
            Ok(update) => update,
            Err(err) => {
                warn!(target: "zone::allowlist", %peer, %err, "Ignoring malformed allowlist update");
                continue;
            }
        };
        if let Some((id, ack)) = last_acks.get(&peer)
            && *id == update.id
        {
            let (peer, ack) = (peer.clone(), ack.clone());
            if commands
                .send(P2pCommand::SendAllowlistAck { peer, ack })
                .await
                .is_err()
            {
                return;
            }
            continue;
        }
        let result = match (&allowlist, update.request) {
            (None, _) => Err(DepositAllowlistError::Disabled),
            (Some(allowlist), Request::Get) => Ok(Response::Addresses(allowlist.addresses())),
            (Some(allowlist), Request::Write(write)) => {
                let result = allowlist.apply_signed_blocking(write).await;
                match &result {
                    Ok(()) => {
                        info!(target: "zone::allowlist", %peer, "Applied relayed deposit allowlist update")
                    }
                    Err(error) => {
                        warn!(target: "zone::allowlist", %peer, %error, "Rejected relayed deposit allowlist update")
                    }
                }
                result.map(|()| Response::Applied)
            }
        };
        let ack = match encode_ack(update.id, result) {
            Ok(ack) => ack,
            Err(err) => {
                warn!(target: "zone::allowlist", %peer, %err, "Failed to encode allowlist acknowledgement");
                continue;
            }
        };
        last_acks.insert(peer.clone(), (update.id, ack.clone()));
        if commands
            .send(P2pCommand::SendAllowlistAck { peer, ack })
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Encode an acknowledgement, replacing a result too large for one frame with an error so the
/// relayer is never blocked for an oversized frame.
fn encode_ack(
    id: u64,
    result: Result<Response, DepositAllowlistError>,
) -> serde_json::Result<Vec<u8>> {
    let ack = serde_json::to_vec(&Ack { id, result })?;
    if ack.len() <= MAX_ALLOWLIST_PAYLOAD_SIZE {
        return Ok(ack);
    }
    serde_json::to_vec(&Ack {
        id,
        result: Err(DepositAllowlistError::Internal(format!(
            "acknowledgement encodes to {} bytes; the relay limit is {MAX_ALLOWLIST_PAYLOAD_SIZE}",
            ack.len()
        ))),
    })
}

fn relay_error(message: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        jsonrpsee::types::error::INTERNAL_ERROR_CODE,
        message,
        None::<()>,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deposit_allowlist::MAX_DEPOSIT_ALLOWLIST_LEN;

    fn full_list() -> Vec<Address> {
        (0..MAX_DEPOSIT_ALLOWLIST_LEN)
            .map(|index| Address::left_padding_from(&u32::try_from(index).unwrap().to_be_bytes()))
            .collect()
    }

    #[test]
    fn a_full_list_fits_in_one_frame_both_ways() {
        let addresses = full_list();
        let ack = encode_ack(u64::MAX, Ok(Response::Addresses(addresses.clone()))).unwrap();
        let ack: Ack = serde_json::from_slice(&ack).unwrap();
        assert_eq!(ack.result, Ok(Response::Addresses(addresses.clone())));

        let replace = serde_json::to_vec(&Update {
            id: u64::MAX,
            request: Request::Write(SignedWrite {
                write: Write::Replace { addresses },
                nonce: u64::MAX,
                deadline: u64::MAX,
                signature: Bytes::from([0xff; 65]),
            }),
        })
        .unwrap();
        assert!(
            replace.len() <= MAX_ALLOWLIST_PAYLOAD_SIZE,
            "{}",
            replace.len()
        );
    }

    #[test]
    fn oversized_ack_becomes_an_error() {
        let mut addresses = full_list();
        addresses.extend(full_list());
        let ack = encode_ack(7, Ok(Response::Addresses(addresses))).unwrap();
        assert!(ack.len() <= MAX_ALLOWLIST_PAYLOAD_SIZE);
        let ack: Ack = serde_json::from_slice(&ack).unwrap();
        assert_eq!(ack.id, 7);
        assert!(matches!(
            ack.result,
            Err(DepositAllowlistError::Internal(_))
        ));
    }
}
