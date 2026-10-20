//! The interface between the consensus layer and the execution layer.
//!
//! [`Inner`] implements [`commonware_consensus::Application`]. [`Application`]
//! shares inline and deferred wrappers with marshal's reporter. Each epoch's
//! simplex engine selects one wrapper using its preceding boundary timestamp.
//! The wrappers fetch parents, re-propose epoch boundary blocks, check epoch
//! membership and parent linkage, persist verified blocks, broadcast proposals,
//! and gate finalize votes on durability. [`Inner`] builds blocks through the
//! executor and checks proposals before this node votes for them.

mod r#impl;
mod parent_state;

pub(super) use r#impl::Config;
pub(crate) use r#impl::Inner;
pub(super) use parent_state::TempoParentState;

use commonware_actor::Feedback;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay, Reporter,
    marshal::{
        Update,
        core::Mailbox,
        standard::{Deferred, Inline, Standard},
    },
    simplex::{Plan, scheme::bls12381_threshold::vrf::Scheme, types::Context},
    types::{FixedEpocher, Round},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::channel::oneshot;
use rand_core::Rng;

use crate::consensus::{Digest, block::Block};

/// Shared verification wrappers and reporter for every epoch's simplex engine.
pub(crate) struct Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    deferred: Deferred<E, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>,
    immediate: Inline<E, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>,
}

impl<E> Clone for Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    fn clone(&self) -> Self {
        Self {
            deferred: self.deferred.clone(),
            immediate: self.immediate.clone(),
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
    ) -> Self {
        Self {
            deferred: Deferred::new(
                context.child("deferred"),
                inner.clone(),
                marshal.clone(),
                epocher.clone(),
            ),
            immediate: Inline::new(context.child("immediate"), inner, marshal, epocher),
        }
    }

    /// Selects a fixed verification wrapper for one epoch.
    pub(crate) fn for_epoch(&self, deferred: bool) -> EpochApplication<E> {
        if deferred {
            EpochApplication::Deferred(self.deferred.clone())
        } else {
            EpochApplication::Immediate(self.immediate.clone())
        }
    }
}

impl<E> Reporter for Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // Overlapping epochs can use different wrappers. Prune both gates,
        // but deliver each block acknowledgement to Inner exactly once.
        if let Update::Tip(..) = &activity {
            self.immediate.report(activity.clone());
        }
        self.deferred.report(activity)
    }
}

/// Verification policy fixed for the lifetime of a simplex epoch.
pub(crate) enum EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    Deferred(Deferred<E, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>),
    Immediate(Inline<E, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>),
}

impl<E> Clone for EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    fn clone(&self) -> Self {
        match self {
            Self::Deferred(application) => Self::Deferred(application.clone()),
            Self::Immediate(application) => Self::Immediate(application.clone()),
        }
    }
}

impl<E> Automaton for EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type Context = Context<Digest, PublicKey>;
    type Digest = Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        match self {
            Self::Deferred(application) => application.propose(context).await,
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
        }
    }
}

impl<E> CertifiableAutomaton for EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        match self {
            Self::Deferred(application) => application.certify(round, payload).await,
            Self::Immediate(application) => application.certify(round, payload).await,
        }
    }
}

impl<E> Relay for EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type PublicKey = PublicKey;
    type Digest = Digest;
    type Plan = Plan<PublicKey>;

    fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> Feedback {
        match self {
            Self::Deferred(application) => application.broadcast(payload, plan),
            Self::Immediate(application) => application.broadcast(payload, plan),
        }
    }
}
