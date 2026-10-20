//! Relays `zoneAdmin` allowlist writes from an RPC-only node to every sequencer over P2P.
//!
//! The RPC-only node serves the operator-facing RPC but holds no allowlist. Each write is sent to
//! every quorum member, which applies it to its own persisted list and acknowledges it. The call
//! returns only after every member acknowledged, so a success means every sequencer will enforce
//! the change on its next block.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy_primitives::Address;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};
use zone_p2p::{P2pCommand, P2pEvent, P2pPeerId};

use super::{DepositAllowlist, DepositAllowlistApiServer, internal_error};

/// How long a relayed write waits for every sequencer before failing.
const RELAY_TIMEOUT: Duration = Duration::from_secs(10);
/// How often an unacknowledged update is resent to the sequencers still missing.
const RELAY_RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// An allowlist request relayed over P2P, tagged so acknowledgements match their request.
#[derive(Debug, Serialize, Deserialize)]
struct Update {
    id: u64,
    request: Request,
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Set {
        addresses: Vec<Address>,
        allowed: bool,
    },
    Replace {
        addresses: Vec<Address>,
    },
    Get,
}

/// A sequencer's result for one relayed request: the list for `Get`, empty once a write is
/// persisted, or the error that prevented it.
#[derive(Debug, Serialize, Deserialize)]
struct Ack {
    id: u64,
    result: Result<Vec<Address>, String>,
}

type PendingAcks = Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<(P2pPeerId, Ack)>>>>;

/// `zoneAdmin` API on an RPC-only node, relaying writes to the sequencers it lists.
#[derive(Clone)]
pub(crate) struct AllowlistRelay {
    sequencers: Vec<P2pPeerId>,
    commands: mpsc::Sender<P2pCommand>,
    pending: PendingAcks,
    next_id: Arc<AtomicU64>,
    /// One write at a time, so every sequencer applies writes in the same order.
    write_lock: Arc<tokio::sync::Mutex<()>>,
}

impl AllowlistRelay {
    /// Create a relay to `sequencers`. Feed received acknowledgements through
    /// [`Self::handle_event`].
    pub(crate) fn new(sequencers: Vec<P2pPeerId>, commands: mpsc::Sender<P2pCommand>) -> Self {
        Self {
            sequencers,
            commands,
            pending: Default::default(),
            next_id: Default::default(),
            write_lock: Default::default(),
        }
    }

    /// Route an [`P2pEvent::AllowlistAckReceived`] to the write waiting for it.
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
        if let Some(waiter) = self.pending.lock().get(&ack.id) {
            let _ = waiter.send((peer, ack));
        }
    }

    /// Send `request` to every sequencer and return each one's result once all have answered.
    async fn relay(&self, request: Request) -> RpcResult<Vec<(P2pPeerId, Vec<Address>)>> {
        let _serialized = self.write_lock.lock().await;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let update = serde_json::to_vec(&Update { id, request })
            .map_err(|err| internal_error(eyre::Report::new(err)))?;
        let (acks_tx, mut acks) = mpsc::unbounded_channel();
        self.pending.lock().insert(id, acks_tx);
        let result = self.collect_acks(&update, &mut acks).await;
        self.pending.lock().remove(&id);
        result
    }

    async fn collect_acks(
        &self,
        update: &[u8],
        acks: &mut mpsc::UnboundedReceiver<(P2pPeerId, Ack)>,
    ) -> RpcResult<Vec<(P2pPeerId, Vec<Address>)>> {
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
                            Ok(addresses) => results.push((peer, addresses)),
                            Err(error) => errors.push(format!("{peer}: {error}")),
                        }
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    let missing = missing.iter().map(ToString::to_string).collect::<Vec<_>>();
                    return Err(relay_error(format!(
                        "no acknowledgement from sequencers {}",
                        missing.join(", ")
                    )));
                }
            }
        }
        if errors.is_empty() {
            Ok(results)
        } else {
            Err(relay_error(errors.join("; ")))
        }
    }
}

#[jsonrpsee::core::async_trait]
impl DepositAllowlistApiServer for AllowlistRelay {
    async fn set_deposit_allowed(&self, addresses: Vec<Address>, allowed: bool) -> RpcResult<()> {
        let count = addresses.len();
        self.relay(Request::Set { addresses, allowed }).await?;
        info!(target: "zone::allowlist", count, allowed, "Relayed deposit allowlist update to every sequencer");
        Ok(())
    }

    async fn replace_deposit_allowlist(&self, addresses: Vec<Address>) -> RpcResult<()> {
        let count = addresses.len();
        self.relay(Request::Replace { addresses }).await?;
        info!(target: "zone::allowlist", count, "Relayed deposit allowlist replacement to every sequencer");
        Ok(())
    }

    async fn get_deposit_allowlist(&self) -> RpcResult<Vec<Address>> {
        let mut results = self.relay(Request::Get).await?.into_iter();
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

/// Apply relayed writes on a sequencer and acknowledge each one to its relayer.
///
/// Writes are idempotent, so a retried update that was already applied is applied again and
/// acknowledged again.
pub(crate) async fn apply_relayed_updates(
    allowlist: Option<DepositAllowlist>,
    mut events: mpsc::Receiver<P2pEvent>,
    commands: mpsc::Sender<P2pCommand>,
) {
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
        let result = match &allowlist {
            None => Err("deposit allowlist is not enabled on this sequencer".to_owned()),
            Some(allowlist) => {
                let allowlist = allowlist.clone();
                let is_write = !matches!(update.request, Request::Get);
                let result = tokio::task::spawn_blocking(move || match update.request {
                    Request::Set { addresses, allowed } => {
                        allowlist.set(&addresses, allowed).map(|()| Vec::new())
                    }
                    Request::Replace { addresses } => {
                        allowlist.replace(addresses).map(|()| Vec::new())
                    }
                    Request::Get => Ok(allowlist.addresses()),
                })
                .await;
                let result = match result {
                    Ok(result) => result.map_err(|err| format!("{err:#}")),
                    Err(err) => Err(format!("allowlist task failed: {err}")),
                };
                match &result {
                    Ok(_) if is_write => {
                        info!(target: "zone::allowlist", %peer, "Applied relayed deposit allowlist update")
                    }
                    Ok(_) => {}
                    Err(error) => {
                        warn!(target: "zone::allowlist", %peer, %error, "Failed to apply relayed deposit allowlist request")
                    }
                }
                result
            }
        };
        let ack = serde_json::to_vec(&Ack {
            id: update.id,
            result,
        })
        .expect("acknowledgements always serialize");
        if commands
            .send(P2pCommand::SendAllowlistAck { peer, ack })
            .await
            .is_err()
        {
            return;
        }
    }
}

fn relay_error(message: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        jsonrpsee::types::error::INTERNAL_ERROR_CODE,
        message,
        None::<()>,
    )
}
