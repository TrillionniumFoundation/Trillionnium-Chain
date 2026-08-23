//! Durable, fail-closed owner around the pure SafetyRules kernel.
//!
//! The kernel deliberately returns comparison-only candidates.  This module
//! adds the next narrow authority boundary: a caller must provide a durable
//! store, and the successor state is not released (or installed in memory)
//! until that store has accepted the exact predecessor/candidate binding.
//! Persistence errors poison the owner because the process cannot know whether
//! the external write reached durable media.

use crate::{
    InertSafetyTransitionV1, PureHotStuffSafetyKernelV1, SafetyRulesContextV1, SafetyRulesErrorV1,
    SafetyRulesStateDigestV1, SafetyRulesStateV1,
};
use trnm_consensus_types::{SignatureVerifier, SignedProposalV0};

/// Store boundary used by [`DurableSafetyRulesAuthorityV1`].
///
/// Implementations must compare-and-set the supplied predecessor digest and
/// persist the complete transition before returning `Ok(())`.  Passing the
/// complete transition (rather than only its successor/candidate digests) is
/// deliberate: an external semantic watermark must bind the exact canonical
/// intent, fingerprint, and signing root, not merely an opaque hash selected
/// by the caller.  The trait intentionally does not expose a signing key or a
/// mutable Core.
pub trait SafetyRulesDurableTransitionStoreV1 {
    type Error;

    fn persist_transition_v1(
        &mut self,
        predecessor: SafetyRulesStateDigestV1,
        transition: &InertSafetyTransitionV1,
    ) -> Result<(), Self::Error>;
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
        let predecessor = self.state.digest();
        if let Err(error) = self.store.persist_transition_v1(predecessor, &transition) {
            self.poisoned = true;
            return Err(DurableSafetyRulesAuthorityErrorV1::Persistence(error));
        }
        self.state = transition.successor_state().clone();
        Ok(transition)
    }
}
