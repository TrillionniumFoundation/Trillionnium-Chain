//! Durable, fail-closed owner around the pure SafetyRules kernel.
//!
//! The kernel deliberately returns comparison-only candidates.  This module
//! adds the next narrow authority boundary: a caller must provide a durable
//! store, and the successor state is not released (or installed in memory)
//! until that store has accepted the exact predecessor/candidate binding.
//! Persistence errors poison the owner because the process cannot know whether
//! the external write reached durable media.

use crate::{
    InertSafetyTransitionKindV1, InertSafetyTransitionV1, PureHotStuffSafetyKernelV1,
    SafetyRulesContextV1, SafetyRulesErrorV1, SafetyRulesStateV1,
};
use trnm_consensus_types::{
    CanonicalSignIntentV0, CanonicalSignPreimageV0, SignatureBytes, SignatureVerifier,
    SignedProposalV0, TimeoutVote, Vote,
};

/// Store boundary used by [`DurableSafetyRulesAuthorityV1`].
///
/// Implementations must compare-and-set the predecessor carried by the
/// transition and persist the complete transition before returning `Ok(())`.
/// The transition is the only input on purpose: accepting a second,
/// caller-supplied predecessor digest would create two CAS authorities that
/// an adapter could accidentally (or maliciously) bind differently.  An
/// external semantic watermark must bind the exact predecessor, successor,
/// canonical intent, fingerprint, signing root, and candidate digest as one
/// tuple, not merely an opaque hash selected by the caller.  The trait
/// intentionally does not expose a signing key or a mutable Core.
pub trait SafetyRulesDurableTransitionStoreV1 {
    type Error;

    fn persist_transition_v1(
        &mut self,
        transition: &InertSafetyTransitionV1,
    ) -> Result<(), Self::Error>;
}

/// Narrow signing seam used only after a SafetyRules transition has reached
/// the durable transition store.
///
/// The adapter must bind the complete [`CanonicalSignIntentV0`] to its own
/// durable journal/HSM boundary and return the exact Ed25519 bytes for that
/// intent.  This crate deliberately stores no key and supplies no default
/// implementation.  A caller that cannot provide a durable, idempotent
/// adapter must not use the signing methods below.
pub trait SafetyRulesSigningAdapterV1 {
    type Error;

    fn sign_intent_v1(
        &mut self,
        intent: &CanonicalSignIntentV0,
    ) -> Result<SignatureBytes, Self::Error>;
}

/// Errors from the durable owner.  A persistence error is returned unchanged
/// inside `Persistence` and permanently poisons the owner.
#[derive(Debug)]
pub enum DurableSafetyRulesAuthorityErrorV1<E> {
    Kernel(SafetyRulesErrorV1),
    Persistence(E),
    StaleInMemoryState,
    Poisoned,
}

/// Errors from the candidate transition-to-message signing seam.
#[derive(Debug)]
pub enum DurableSafetyRulesSigningErrorV1<SE, AE> {
    Authority(DurableSafetyRulesAuthorityErrorV1<SE>),
    Adapter(AE),
    MessageConstruction,
    InvalidProducedSignature,
}

impl<SE, AE> From<DurableSafetyRulesAuthorityErrorV1<SE>>
    for DurableSafetyRulesSigningErrorV1<SE, AE>
{
    fn from(value: DurableSafetyRulesAuthorityErrorV1<SE>) -> Self {
        Self::Authority(value)
    }
}

/// Typed consensus message emitted only after the corresponding SafetyRules
/// transition was durably accepted and the returned signature was verified
/// against the configured validator set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedSafetyMessageV1 {
    Vote(Vote),
    TimeoutVote(TimeoutVote),
}

impl SignedSafetyMessageV1 {
    pub const fn vote(&self) -> Option<&Vote> {
        match self {
            Self::Vote(value) => Some(value),
            Self::TimeoutVote(_) => None,
        }
    }

    pub const fn timeout_vote(&self) -> Option<&TimeoutVote> {
        match self {
            Self::Vote(_) => None,
            Self::TimeoutVote(value) => Some(value),
        }
    }

    pub const fn signature(&self) -> &SignatureBytes {
        match self {
            Self::Vote(value) => value.signature(),
            Self::TimeoutVote(value) => value.signature(),
        }
    }
}

/// The exact SafetyRules transition paired with its independently verified
/// signed message.  Keeping both values together prevents an adapter from
/// returning a valid signature for a different candidate than the one whose
/// successor state was installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSafetyTransitionV1 {
    transition: InertSafetyTransitionV1,
    message: SignedSafetyMessageV1,
}

impl SignedSafetyTransitionV1 {
    pub const fn transition(&self) -> &InertSafetyTransitionV1 {
        &self.transition
    }

    pub const fn message(&self) -> &SignedSafetyMessageV1 {
        &self.message
    }
}

impl<E> From<SafetyRulesErrorV1> for DurableSafetyRulesAuthorityErrorV1<E> {
    fn from(value: SafetyRulesErrorV1) -> Self {
        Self::Kernel(value)
    }
}

/// One process-owned SafetyRules state and its durable transition store.
///
/// The owner is deliberately not `Clone`; duplicating it would create two
/// in-memory state machines competing for the same signer/CAS namespace.
#[derive(Debug)]
pub struct DurableSafetyRulesAuthorityV1<S, V> {
    context: SafetyRulesContextV1,
    state: SafetyRulesStateV1,
    store: S,
    verifier: V,
    poisoned: bool,
}

impl<S, V> DurableSafetyRulesAuthorityV1<S, V>
where
    S: SafetyRulesDurableTransitionStoreV1,
    V: SignatureVerifier,
{
    /// Opens an owner only after revalidating the complete state digest and
    /// all retained QC signatures against the immutable context.
    pub fn new(
        context: SafetyRulesContextV1,
        state: SafetyRulesStateV1,
        store: S,
        verifier: V,
    ) -> Result<Self, DurableSafetyRulesAuthorityErrorV1<S::Error>> {
        state
            .validate_fresh(&context, &verifier)
            .map_err(DurableSafetyRulesAuthorityErrorV1::Kernel)?;
        Ok(Self {
            context,
            state,
            store,
            verifier,
            poisoned: false,
        })
    }

    pub const fn context(&self) -> &SafetyRulesContextV1 {
        &self.context
    }

    pub const fn state(&self) -> &SafetyRulesStateV1 {
        &self.state
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Evaluates and durably commits one proposal vote candidate.
    pub fn prepare_vote_and_persist<'a>(
        &mut self,
        ancestry: &[&'a SignedProposalV0],
        target: &'a SignedProposalV0,
    ) -> Result<InertSafetyTransitionV1, DurableSafetyRulesAuthorityErrorV1<S::Error>> {
        self.ensure_live()?;
        let transition = PureHotStuffSafetyKernelV1::prepare_vote_from_refs(
            &self.context,
            &self.state,
            ancestry,
            target,
            &self.verifier,
        )?;
        self.persist_and_install_v1(transition)
    }

    /// Evaluates and durably commits one timeout candidate.
    pub fn prepare_timeout_and_persist(
        &mut self,
    ) -> Result<InertSafetyTransitionV1, DurableSafetyRulesAuthorityErrorV1<S::Error>> {
        self.ensure_live()?;
        let transition = PureHotStuffSafetyKernelV1::prepare_timeout(
            &self.context,
            &self.state,
            &self.verifier,
        )?;
        self.persist_and_install_v1(transition)
    }

    /// Evaluates, durably commits, signs, and verifies one proposal vote.
    ///
    /// The store transition is completed before the adapter is called.  If
    /// signing or post-signature verification fails, the owner is poisoned:
    /// its Safety state has already advanced and silently retrying from a
    /// different producer could create an ambiguous signer lifecycle.
    pub fn prepare_vote_and_sign_v1<'a, A>(
        &mut self,
        ancestry: &[&'a SignedProposalV0],
        target: &'a SignedProposalV0,
        adapter: &mut A,
    ) -> Result<SignedSafetyTransitionV1, DurableSafetyRulesSigningErrorV1<S::Error, A::Error>>
    where
        A: SafetyRulesSigningAdapterV1,
    {
        let transition = self
            .prepare_vote_and_persist(ancestry, target)
            .map_err(DurableSafetyRulesSigningErrorV1::Authority)?;
        self.sign_persisted_transition_v1(transition, adapter)
    }

    /// Evaluates, durably commits, signs, and verifies one timeout vote.
    ///
    /// As with [`Self::prepare_vote_and_sign_v1`], any adapter or signature
    /// failure after durable state installation poisons this owner.
    pub fn prepare_timeout_and_sign_v1<A>(
        &mut self,
        adapter: &mut A,
    ) -> Result<SignedSafetyTransitionV1, DurableSafetyRulesSigningErrorV1<S::Error, A::Error>>
    where
        A: SafetyRulesSigningAdapterV1,
    {
        let transition = self
            .prepare_timeout_and_persist()
            .map_err(DurableSafetyRulesSigningErrorV1::Authority)?;
        self.sign_persisted_transition_v1(transition, adapter)
    }

    fn ensure_live(&self) -> Result<(), DurableSafetyRulesAuthorityErrorV1<S::Error>> {
        if self.poisoned {
            Err(DurableSafetyRulesAuthorityErrorV1::Poisoned)
        } else {
            Ok(())
        }
    }

    fn persist_and_install_v1(
        &mut self,
        transition: InertSafetyTransitionV1,
    ) -> Result<InertSafetyTransitionV1, DurableSafetyRulesAuthorityErrorV1<S::Error>> {
        if transition.predecessor_state_digest() != self.state.digest() {
            self.poisoned = true;
            return Err(DurableSafetyRulesAuthorityErrorV1::StaleInMemoryState);
        }
        if let Err(error) = self.store.persist_transition_v1(&transition) {
            self.poisoned = true;
            return Err(DurableSafetyRulesAuthorityErrorV1::Persistence(error));
        }
        self.state = transition.successor_state().clone();
        Ok(transition)
    }

    fn sign_persisted_transition_v1<A>(
        &mut self,
        transition: InertSafetyTransitionV1,
        adapter: &mut A,
    ) -> Result<SignedSafetyTransitionV1, DurableSafetyRulesSigningErrorV1<S::Error, A::Error>>
    where
        A: SafetyRulesSigningAdapterV1,
    {
        // The pure kernel already builds this intent, but revalidate at the
        // authority seam so a future transition producer cannot accidentally
        // bypass the immutable validator-set/context binding.
        if transition
            .canonical_intent()
            .validate(self.context.validator_set())
            .is_err()
        {
            self.poisoned = true;
            return Err(DurableSafetyRulesSigningErrorV1::MessageConstruction);
        }

        let signature = match adapter.sign_intent_v1(transition.canonical_intent()) {
            Ok(signature) => signature,
            Err(error) => {
                self.poisoned = true;
                return Err(DurableSafetyRulesSigningErrorV1::Adapter(error));
            }
        };
        let message = match (transition.kind(), transition.canonical_intent().preimage()) {
            (InertSafetyTransitionKindV1::Vote, CanonicalSignPreimageV0::Vote(preimage)) => {
                Vote::new(
                    transition.canonical_intent().chain_id(),
                    transition.canonical_intent().protocol_version(),
                    transition.canonical_intent().epoch(),
                    preimage.view(),
                    preimage.height(),
                    preimage.block_id(),
                    transition.canonical_intent().validator_set_id(),
                    transition.canonical_intent().author(),
                    signature,
                    self.context.validator_set(),
                )
                .map(SignedSafetyMessageV1::Vote)
            }
            (
                InertSafetyTransitionKindV1::TimeoutVote,
                CanonicalSignPreimageV0::TimeoutVote(preimage),
            ) => TimeoutVote::new(
                transition.canonical_intent().chain_id(),
                transition.canonical_intent().protocol_version(),
                transition.canonical_intent().epoch(),
                preimage.view(),
                transition.canonical_intent().validator_set_id(),
                preimage.high_qc(),
                transition.canonical_intent().author(),
                signature,
                self.context.validator_set(),
            )
            .map(SignedSafetyMessageV1::TimeoutVote),
            _ => Err(trnm_consensus_types::ValidationError::InvalidSignIntent(
                "SafetyRules transition kind does not match its canonical intent",
            )),
        }
        .map_err(|_| {
            self.poisoned = true;
            DurableSafetyRulesSigningErrorV1::MessageConstruction
        })?;

        let verified = match &message {
            SignedSafetyMessageV1::Vote(value) => {
                value.verify(self.context.validator_set(), &self.verifier)
            }
            SignedSafetyMessageV1::TimeoutVote(value) => {
                value.verify(self.context.validator_set(), &self.verifier)
            }
        };
        if verified.is_err() {
            self.poisoned = true;
            return Err(DurableSafetyRulesSigningErrorV1::InvalidProducedSignature);
        }

        Ok(SignedSafetyTransitionV1 {
            transition,
            message,
        })
    }
}
