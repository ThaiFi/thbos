//! The interface between the consensus layer and the execution layer.
//!
//! [`Inner`] implements [`commonware_consensus::Application`]. At startup the
//! engine wraps it in [`Application`], selecting inline or deferred verification per block
//! and sharing it with marshal's reporter and every epoch's simplex engine. The wrapper
//! owns everything between consensus and the block: it fetches the parent,
//! re-proposes epoch boundary blocks, checks epoch membership and parent
//! linkage, persists verified blocks, broadcasts proposals, and gates the
//! finalize vote on durability. What is left here is tempo's own view of a
//! block: how one is built through the executor, and which checks a
//! proposal must pass before this node votes for it.
//!

mod r#impl;
mod parent_state;

pub(super) use r#impl::Config;
pub(crate) use r#impl::Inner;
pub(super) use parent_state::TempoParentState;

use std::sync::Arc;

use alloy_consensus::BlockHeader as _;
use commonware_actor::Feedback;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay, Reporter,
    marshal::{
        Update,
        core::{DigestFallback, Mailbox},
        standard::{Deferred, Inline, Standard},
    },
    simplex::{Plan, scheme::bls12381_threshold::vrf::Scheme, types::Context},
    types::{FixedEpocher, Round},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{
    Clock, Spawner,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_utils::channel::{fallible::OneshotExt as _, oneshot};
use rand_core::Rng;
use tempo_chainspec::TempoChainSpec;
use tracing::Instrument as _;

use crate::{
    VerificationMode,
    consensus::{Digest, block::Block},
};

/// A shared application for marshal and every epoch's simplex engine.
pub(crate) enum Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    Deferred(Deferred<E, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>),
    Immediate(Inline<E, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>),
    Hardfork {
        deferred: Deferred<E, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>,
        immediate: Box<Inline<E, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>>,
        runtime: Arc<E>,
        marshal: Mailbox<Scheme<PublicKey, MinSig>, Standard<Block>>,
        chainspec: Arc<TempoChainSpec>,
        immediate_verifications: Counter,
        deferred_verifications: Counter,
    },
}

impl<E> Clone for Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    fn clone(&self) -> Self {
        match self {
            Self::Deferred(application) => Self::Deferred(application.clone()),
            Self::Immediate(application) => Self::Immediate(application.clone()),
            Self::Hardfork {
                deferred,
                immediate,
                runtime,
                marshal,
                chainspec,
                immediate_verifications,
                deferred_verifications,
            } => Self::Hardfork {
                deferred: deferred.clone(),
                immediate: immediate.clone(),
                runtime: runtime.clone(),
                marshal: marshal.clone(),
                chainspec: chainspec.clone(),
                immediate_verifications: immediate_verifications.clone(),
                deferred_verifications: deferred_verifications.clone(),
            },
        }
    }
}

impl<E> Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    pub(crate) fn new(
        context: E,
        inner: Inner,
        marshal: Mailbox<Scheme<PublicKey, MinSig>, Standard<Block>>,
        epocher: FixedEpocher,
        mode: VerificationMode,
        chainspec: Arc<TempoChainSpec>,
    ) -> Self {
        match mode {
            VerificationMode::Deferred => {
                Self::Deferred(Deferred::new(context, inner, marshal, epocher))
            }
            VerificationMode::Immediate => {
                Self::Immediate(Inline::new(context, inner, marshal, epocher))
            }
            VerificationMode::Hardfork => Self::Hardfork {
                deferred: Deferred::new(
                    context.child("deferred"),
                    inner.clone(),
                    marshal.clone(),
                    epocher.clone(),
                ),
                immediate: Box::new(Inline::new(
                    context.child("immediate"),
                    inner,
                    marshal.clone(),
                    epocher,
                )),
                immediate_verifications: context.counter(
                    "immediate_verifications",
                    "Proposals routed to immediate verification",
                ),
                deferred_verifications: context.counter(
                    "deferred_verifications",
                    "Proposals routed to deferred verification",
                ),
                runtime: Arc::new(context),
                marshal,
                chainspec,
            },
        }
    }
}

impl<E> Automaton for Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type Context = Context<Digest, PublicKey>;
    type Digest = Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        match self {
            Self::Deferred(application)
            | Self::Hardfork {
                deferred: application,
                ..
            } => {
                // Locally built proposals are already executed. Deferred's gate
                // also tracks their durability across the hardfork transition.
                application.propose(context).await
            }
            Self::Immediate(application) => application.propose(context).await,
        }
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        match self {
            Self::Deferred(application) => application.verify(context, payload).await,
            Self::Immediate(application) => application.verify(context, payload).await,
            Self::Hardfork {
                deferred,
                immediate,
                runtime,
                marshal,
                chainspec,
                immediate_verifications,
                deferred_verifications,
            } => {
                let block = marshal.subscribe_by_digest(payload, DigestFallback::Wait);
                let mut deferred = deferred.clone();
                let mut immediate = immediate.clone();
                let chainspec = chainspec.clone();
                let immediate_verifications = immediate_verifications.clone();
                let deferred_verifications = deferred_verifications.clone();
                let (mut tx, rx) = oneshot::channel();
                runtime.child("verify").spawn(move |_| {
                    async move {
                        let verification = async {
                            let Ok(block) = block.await else { return None };
                            let verdict = if VerificationMode::Hardfork
                                .is_deferred_at(&chainspec, block.header().timestamp())
                            {
                                deferred_verifications.metric().inc();
                                deferred.verify(context, payload).await
                            } else {
                                immediate_verifications.metric().inc();
                                immediate.verify(context, payload).await
                            };
                            let Ok(valid) = verdict.await else {
                                return None;
                            };
                            Some(valid)
                        };
                        commonware_macros::select! {
                            _ = tx.closed() => {},
                            verdict = verification => {
                                if let Some(valid) = verdict { tx.send_lossy(valid); }
                            },
                        }
                    }
                    .instrument(tracing::info_span!("hardfork_verify"))
                });
                rx
            }
        }
    }
}

impl<E> CertifiableAutomaton for Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        match self {
            Self::Deferred(application) => application.certify(round, payload).await,
            Self::Immediate(application) => application.certify(round, payload).await,
            Self::Hardfork {
                deferred,
                immediate,
                runtime,
                marshal,
                chainspec,
                ..
            } => {
                let block =
                    marshal.subscribe_by_digest(payload, DigestFallback::FetchByRound { round });
                let mut deferred = deferred.clone();
                let mut immediate = immediate.clone();
                let chainspec = chainspec.clone();
                let (mut tx, rx) = oneshot::channel();
                runtime.child("certify").spawn(move |_| {
                    async move {
                        let certification = async {
                            let Ok(block) = block.await else { return None };
                            // Local proposals are staged in deferred even before T14.
                            // Inline's recovery path persists those proposals before finalizing.
                            let verdict = if VerificationMode::Hardfork
                                .is_deferred_at(&chainspec, block.header().timestamp())
                            {
                                deferred.certify(round, payload).await
                            } else {
                                immediate.certify(round, payload).await
                            };
                            let Ok(valid) = verdict.await else {
                                return None;
                            };
                            Some(valid)
                        };
                        commonware_macros::select! {
                            _ = tx.closed() => {},
                            verdict = certification => {
                                if let Some(valid) = verdict { tx.send_lossy(valid); }
                            },
                        }
                    }
                    .instrument(tracing::info_span!("hardfork_certify"))
                });
                rx
            }
        }
    }
}

impl<E> Relay for Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type PublicKey = PublicKey;
    type Digest = Digest;
    type Plan = Plan<PublicKey>;

    fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> Feedback {
        match self {
            Self::Deferred(application)
            | Self::Hardfork {
                deferred: application,
                ..
            } => application.broadcast(payload, plan),
            Self::Immediate(application) => application.broadcast(payload, plan),
        }
    }
}

impl<E> Reporter for Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self {
            Self::Deferred(application) => application.report(activity),
            Self::Immediate(application) => application.report(activity),
            Self::Hardfork {
                deferred,
                immediate,
                ..
            } => {
                // Both wrappers must prune their gates, including pre-fork work
                // finalized after activation. Only Tip is duplicated; block acks
                // still reach Inner exactly once.
                if let Update::Tip(..) = &activity {
                    immediate.report(activity.clone());
                }
                deferred.report(activity)
            }
        }
    }
}
