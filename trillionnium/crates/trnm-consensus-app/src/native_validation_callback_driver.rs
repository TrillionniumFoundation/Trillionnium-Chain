//! App-private native validation callback driver.
//!
//! This module joins the one live owning lineage returned by the validation
//! journal to an exact, still-live Core obligation, crosses the real Core
//! safety-state persistence barrier, and advances the local callback journal
//! only through consuming phase owners.  The injected safety-state sink is a
//! persistence boundary, not a codec or WAL implementation; no production
//! durability or cross-crash obligation takeover is claimed here.

use std::sync::Arc;
use trnm_consensus_core::{
    BarrierId, Core, CoreError, Effect, Input, PayloadTerminalResult, PayloadValidationResult,
    PayloadValidationRouteV0, SafetyHalt, SafetyState, ValidationId,
};
use trnm_consensus_types::SignatureVerifier;

use super::{
    native_validation_request_fingerprint_v0, AckedNativeValidationInvalidCallbackV0,
    ApplicationStore, ConfirmedCoreInvalidCompletionV0, DeliveredNativeValidationInvalidCallbackV0,
    FailedBindConfirmedCoreInvalidCompletionV0, FailedNativeValidationInvalidAcknowledgementV0,
    FailedNativeValidationInvalidDeliveryV0, LiveNativeValidationInvalidCallbackV0,
};

/// App-private owner of the one live consensus Core, its verifier, the fixed
/// application-store identity, and the injected exact safety-state sink.
///
/// This type is deliberately non-`Clone` and exposes neither its `Core` nor
/// its sink as parts. The current tranche provides only a test constructor:
/// the repository still lacks a process-wide production Core owner and a
/// production SafetyState codec/WAL, so constructing this shape is not yet a
/// production durability claim.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "the callback driver owns the live Core and its persistence ordering"]
pub(crate) struct NativeValidationCallbackDriverV0<'a, V, S> {
    application_store: &'a ApplicationStore,
    core: Core,
    verifier: V,
    safety_sink: S,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
}

/// Unforgeable process-local identity for one driver instance. It is neither
/// serialized nor derived from Core/SafetyState bytes: identical Core clones
/// hosted by different drivers still receive distinct identities.
struct NativeValidationCallbackDriverAffinityV0;

/// Distinguishes a pre-side-effect foreign-driver rejection from the phase's
/// existing operation failure. `ForeignDriver` always returns the unchanged
/// phase owner so it can be retried only on its issuing driver. `Phase`
/// preserves the existing retry/quarantine contract of the operation itself.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a driver phase failure retains either affinity or operation context"]
pub(crate) enum NativeValidationCallbackDriverPhaseFailureV0<P, F> {
    ForeignDriver(P),
    Phase(F),
}

impl<P, F: std::fmt::Debug> std::fmt::Debug for NativeValidationCallbackDriverPhaseFailureV0<P, F> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignDriver(_) => formatter
                .debug_struct("ForeignDriver")
                .field("retains_unchanged_phase_owner", &true)
                .finish(),
            Self::Phase(failure) => formatter.debug_tuple("Phase").field(failure).finish(),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindLiveInvalidDeliveryFailureCauseV0 {
    IssuingStoreMismatch,
    MissingObligationOrCompletion,
    DuplicateCoreIdentity,
    RouteMismatch,
    RequestFingerprintDerivation,
    RequestFingerprintMismatch,
    CompletionResultMismatch,
    TerminalFactMismatch,
    CompletionLacksArtifactBinding,
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a failed Core binding retains the unique live callback owner"]
pub(crate) struct FailedBindLiveInvalidDeliveryV0 {
    owner: Box<LiveNativeValidationInvalidCallbackV0>,
    cause: BindLiveInvalidDeliveryFailureCauseV0,
}

impl std::fmt::Debug for FailedBindLiveInvalidDeliveryV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedBindLiveInvalidDeliveryV0")
            .field("cause", &self.cause)
            .field("retains_live_owner", &true)
            .finish()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl FailedBindLiveInvalidDeliveryV0 {
    pub(crate) const fn cause(&self) -> BindLiveInvalidDeliveryFailureCauseV0 {
        self.cause
    }

    pub(crate) fn into_owner_v0(self) -> Box<LiveNativeValidationInvalidCallbackV0> {
        self.owner
    }
}

/// A live journal lineage rebound to the exact current Core obligation.
/// Completion tombstones are deliberately insufficient: they omit the
/// artifact/callback payload checksum and therefore cannot authenticate the
/// application outbox lineage.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a Core-bound live callback must be stepped or returned intact"]
pub(crate) struct CoreBoundLiveInvalidDeliveryV0 {
    owner: Box<LiveNativeValidationInvalidCallbackV0>,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl CoreBoundLiveInvalidDeliveryV0 {
    pub(crate) const fn route(&self) -> PayloadValidationRouteV0 {
        self.owner.route()
    }

    pub(crate) const fn validation_id(&self) -> ValidationId {
        self.owner.validation_id()
    }

    pub(crate) const fn request_fingerprint(&self) -> [u8; 32] {
        self.owner.request_fingerprint()
    }

    pub(crate) const fn callback_payload_checksum(&self) -> [u8; 32] {
        self.owner.callback_payload_checksum()
    }

    fn affinity_v0(&self) -> &Arc<NativeValidationCallbackDriverAffinityV0> {
        &self.affinity
    }
}

/// Rebinds a live seal lineage to Core-owned signed-proposal/parent authority.
/// A same-ID opposite-route obligation or completion fails closed. A matching
/// completion is also refused because Core's tombstone does not bind the
/// artifact-bearing callback payload.
fn bind_live_invalid_delivery_v0(
    store: &ApplicationStore,
    core: &Core,
    owner: Box<LiveNativeValidationInvalidCallbackV0>,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
) -> Result<CoreBoundLiveInvalidDeliveryV0, Box<FailedBindLiveInvalidDeliveryV0>> {
    let fail = |owner, cause| Box::new(FailedBindLiveInvalidDeliveryV0 { owner, cause });
    if !owner.is_bound_to_store_v0(store) {
        return Err(fail(
            owner,
            BindLiveInvalidDeliveryFailureCauseV0::IssuingStoreMismatch,
        ));
    }

    let id = owner.validation_id();
    let same_id_obligations: Vec<_> = core
        .safety_state()
        .payload_validation_obligations()
        .iter()
        .filter(|obligation| obligation.id() == id)
        .collect();
    let same_id_completions: Vec<_> = core
        .safety_state()
        .payload_validation_completions()
        .iter()
        .filter(|completion| completion.id() == id)
        .collect();
    if same_id_obligations.len() > 1
        || same_id_completions.len() > 1
        || (!same_id_obligations.is_empty() && !same_id_completions.is_empty())
    {
        return Err(fail(
            owner,
            BindLiveInvalidDeliveryFailureCauseV0::DuplicateCoreIdentity,
        ));
    }

    if let Some(obligation) = same_id_obligations.first() {
        if obligation.route() != owner.route() {
            return Err(fail(
                owner,
                BindLiveInvalidDeliveryFailureCauseV0::RouteMismatch,
            ));
        }
        let fingerprint = match native_validation_request_fingerprint_v0(
            obligation.route(),
            obligation.id(),
            obligation.proposal().block(),
            obligation.parent(),
        ) {
            Ok(fingerprint) => fingerprint,
            Err(_) => {
                return Err(fail(
                    owner,
                    BindLiveInvalidDeliveryFailureCauseV0::RequestFingerprintDerivation,
                ));
            }
        };
        if fingerprint != owner.request_fingerprint() {
            return Err(fail(
                owner,
                BindLiveInvalidDeliveryFailureCauseV0::RequestFingerprintMismatch,
            ));
        }
        return Ok(CoreBoundLiveInvalidDeliveryV0 { owner, affinity });
    }

    if let Some(completion) = same_id_completions.first() {
        if completion.route() != owner.route() {
            return Err(fail(
                owner,
                BindLiveInvalidDeliveryFailureCauseV0::RouteMismatch,
            ));
        }
        if completion.result() != PayloadValidationResult::DeterministicallyInvalid {
            return Err(fail(
                owner,
                BindLiveInvalidDeliveryFailureCauseV0::CompletionResultMismatch,
            ));
        }
        if core.safety_state().payload_terminal_result(id.block_id())
            != Some(PayloadTerminalResult::DeterministicallyInvalid)
        {
            return Err(fail(
                owner,
                BindLiveInvalidDeliveryFailureCauseV0::TerminalFactMismatch,
            ));
        }
        return Err(fail(
            owner,
            BindLiveInvalidDeliveryFailureCauseV0::CompletionLacksArtifactBinding,
        ));
    }

    Err(fail(
        owner,
        BindLiveInvalidDeliveryFailureCauseV0::MissingObligationOrCompletion,
    ))
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoreInvalidDeliveryStepInvariantV0 {
    UnexpectedEffectSet,
    BarrierRevisionMismatch,
    PersistedStateMismatch,
    ObligationRetained,
    CompletionMissingOrChanged,
    CompletionRevisionMismatch,
    TerminalFactMismatch,
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "an accepted callback carries the exact Core barrier state"]
pub(crate) struct CoreAcceptedInvalidDeliveryV0 {
    owner: Box<LiveNativeValidationInvalidCallbackV0>,
    state: Box<SafetyState>,
    completion_revision: u64,
    barrier: BarrierId,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl CoreAcceptedInvalidDeliveryV0 {
    pub(crate) const fn route(&self) -> PayloadValidationRouteV0 {
        self.owner.route()
    }

    pub(crate) const fn validation_id(&self) -> ValidationId {
        self.owner.validation_id()
    }

    pub(crate) const fn callback_payload_checksum(&self) -> [u8; 32] {
        self.owner.callback_payload_checksum()
    }

    pub(crate) const fn state(&self) -> &SafetyState {
        &self.state
    }

    pub(crate) const fn completion_revision(&self) -> u64 {
        self.completion_revision
    }

    pub(crate) const fn barrier(&self) -> BarrierId {
        self.barrier
    }

    fn affinity_v0(&self) -> &Arc<NativeValidationCallbackDriverAffinityV0> {
        &self.affinity
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a rejected Core step retains the exact Core-bound owner"]
pub(crate) struct RejectedCoreInvalidDeliveryStepV0 {
    owner: CoreBoundLiveInvalidDeliveryV0,
    error: CoreError,
}

#[cfg_attr(not(test), allow(dead_code))]
impl RejectedCoreInvalidDeliveryStepV0 {
    pub(crate) const fn error(&self) -> &CoreError {
        &self.error
    }

    pub(crate) fn into_owner_v0(self) -> CoreBoundLiveInvalidDeliveryV0 {
        self.owner
    }
}

impl std::fmt::Debug for RejectedCoreInvalidDeliveryStepV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RejectedCoreInvalidDeliveryStepV0")
            .field("error", &self.error)
            .field("retains_bound_owner", &true)
            .finish()
    }
}

/// Core returned success and therefore may have consumed the obligation, but
/// its effect/state shape violated the driver contract.  This carrier keeps
/// the live owner and the observed durable image; it deliberately offers no
/// conversion back to a retryable pre-step owner.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a post-step invariant failure retains the mutated Core context"]
pub(crate) struct InvalidCoreAcceptedDeliveryV0 {
    owner: Box<LiveNativeValidationInvalidCallbackV0>,
    observed_state: SafetyState,
    observed_effects: Vec<Effect>,
    cause: CoreInvalidDeliveryStepInvariantV0,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl InvalidCoreAcceptedDeliveryV0 {
    pub(crate) const fn cause(&self) -> CoreInvalidDeliveryStepInvariantV0 {
        self.cause
    }

    pub(crate) const fn observed_state(&self) -> &SafetyState {
        &self.observed_state
    }

    pub(crate) fn observed_effects(&self) -> &[Effect] {
        &self.observed_effects
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum FailedCoreInvalidDeliveryStepV0 {
    Rejected(Box<RejectedCoreInvalidDeliveryStepV0>),
    AcceptedInvariant(Box<InvalidCoreAcceptedDeliveryV0>),
}

impl std::fmt::Debug for FailedCoreInvalidDeliveryStepV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(failure) => formatter.debug_tuple("Rejected").field(failure).finish(),
            Self::AcceptedInvariant(failure) => formatter
                .debug_struct("AcceptedInvariant")
                .field("cause", &failure.cause())
                .field("quarantines_post_step_owner", &true)
                .finish(),
        }
    }
}

fn exact_invalid_completion_v0(
    state: &SafetyState,
    route: PayloadValidationRouteV0,
    id: ValidationId,
) -> Option<u64> {
    let mut completions = state
        .payload_validation_completions()
        .iter()
        .filter(|completion| completion.id() == id);
    let completion = completions.next()?;
    if completions.next().is_some()
        || completion.route() != route
        || completion.result() != PayloadValidationResult::DeterministicallyInvalid
    {
        return None;
    }
    Some(completion.first_recorded_revision())
}

fn invalid_callback_input_v0(route: PayloadValidationRouteV0, id: ValidationId) -> Input {
    let result = PayloadValidationResult::DeterministicallyInvalid;
    match route {
        PayloadValidationRouteV0::Proposal => Input::PayloadValidated { id, result },
        PayloadValidationRouteV0::Synced => Input::SyncedPayloadValidated { id, result },
    }
}

/// Calls the real consensus Core with the route-specific deterministic-invalid
/// callback. The callback must yield exactly one safety persistence effect.
fn step_bound_invalid_delivery_v0<V: SignatureVerifier>(
    core: &mut Core,
    verifier: &V,
    bound: CoreBoundLiveInvalidDeliveryV0,
) -> Result<CoreAcceptedInvalidDeliveryV0, FailedCoreInvalidDeliveryStepV0> {
    let CoreBoundLiveInvalidDeliveryV0 { owner, affinity } = bound;
    let route = owner.route();
    let id = owner.validation_id();
    let effects = match core.step(invalid_callback_input_v0(route, id), verifier) {
        Ok(effects) => effects,
        Err(error) => {
            return Err(FailedCoreInvalidDeliveryStepV0::Rejected(Box::new(
                RejectedCoreInvalidDeliveryStepV0 {
                    owner: CoreBoundLiveInvalidDeliveryV0 { owner, affinity },
                    error,
                },
            )));
        }
    };

    let fail_after_step = |owner, affinity, cause, effects: Vec<Effect>, core: &Core| {
        FailedCoreInvalidDeliveryStepV0::AcceptedInvariant(Box::new(
            InvalidCoreAcceptedDeliveryV0 {
                owner,
                observed_state: core.safety_state().clone(),
                observed_effects: effects,
                cause,
                affinity,
            },
        ))
    };

    let Some(Effect::PersistSafetyState { barrier, state }) = effects.first() else {
        return Err(fail_after_step(
            owner,
            affinity,
            CoreInvalidDeliveryStepInvariantV0::UnexpectedEffectSet,
            effects,
            core,
        ));
    };
    if effects.len() != 1 {
        return Err(fail_after_step(
            owner,
            affinity,
            CoreInvalidDeliveryStepInvariantV0::UnexpectedEffectSet,
            effects,
            core,
        ));
    }
    let barrier = *barrier;
    let state = state.clone();
    if barrier.get() != state.revision() {
        return Err(fail_after_step(
            owner,
            affinity,
            CoreInvalidDeliveryStepInvariantV0::BarrierRevisionMismatch,
            effects,
            core,
        ));
    }
    if state.as_ref() != core.safety_state() {
        return Err(fail_after_step(
            owner,
            affinity,
            CoreInvalidDeliveryStepInvariantV0::PersistedStateMismatch,
            effects,
            core,
        ));
    }
    if state
        .payload_validation_obligations()
        .iter()
        .any(|obligation| obligation.id() == id)
    {
        return Err(fail_after_step(
            owner,
            affinity,
            CoreInvalidDeliveryStepInvariantV0::ObligationRetained,
            effects,
            core,
        ));
    }
    let Some(completion_revision) = exact_invalid_completion_v0(&state, route, id) else {
        return Err(fail_after_step(
            owner,
            affinity,
            CoreInvalidDeliveryStepInvariantV0::CompletionMissingOrChanged,
            effects,
            core,
        ));
    };
    if completion_revision != state.revision() {
        return Err(fail_after_step(
            owner,
            affinity,
            CoreInvalidDeliveryStepInvariantV0::CompletionRevisionMismatch,
            effects,
            core,
        ));
    }
    if state.payload_terminal_result(id.block_id())
        != Some(PayloadTerminalResult::DeterministicallyInvalid)
    {
        return Err(fail_after_step(
            owner,
            affinity,
            CoreInvalidDeliveryStepInvariantV0::TerminalFactMismatch,
            effects,
            core,
        ));
    }
    Ok(CoreAcceptedInvalidDeliveryV0 {
        owner,
        state,
        completion_revision,
        barrier,
        affinity,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a delivered callback still owns the exact Core barrier state"]
pub(crate) struct DeliveredCoreInvalidDeliveryV0 {
    owner: Box<DeliveredNativeValidationInvalidCallbackV0>,
    state: Box<SafetyState>,
    completion_revision: u64,
    barrier: BarrierId,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl DeliveredCoreInvalidDeliveryV0 {
    pub(crate) const fn state(&self) -> &SafetyState {
        &self.state
    }

    pub(crate) const fn completion_revision(&self) -> u64 {
        self.completion_revision
    }

    pub(crate) const fn barrier(&self) -> BarrierId {
        self.barrier
    }

    fn affinity_v0(&self) -> &Arc<NativeValidationCallbackDriverAffinityV0> {
        &self.affinity
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a failed Delivered transition retains the post-Core acceptance context"]
pub(crate) struct FailedMarkCoreInvalidDeliveryDeliveredV0 {
    store_failure: Box<FailedNativeValidationInvalidDeliveryV0>,
    state: Box<SafetyState>,
    completion_revision: u64,
    barrier: BarrierId,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
}

impl std::fmt::Debug for FailedMarkCoreInvalidDeliveryDeliveredV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedMarkCoreInvalidDeliveryDeliveredV0")
            .field("store_cause", self.store_failure.cause())
            .field("retains_accepted_owner", &true)
            .finish()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl FailedMarkCoreInvalidDeliveryDeliveredV0 {
    pub(crate) const fn store_failure(&self) -> &FailedNativeValidationInvalidDeliveryV0 {
        &self.store_failure
    }

    pub(crate) fn into_accepted_v0(self) -> CoreAcceptedInvalidDeliveryV0 {
        CoreAcceptedInvalidDeliveryV0 {
            owner: self.store_failure.into_owner_v0(),
            state: self.state,
            completion_revision: self.completion_revision,
            barrier: self.barrier,
            affinity: self.affinity,
        }
    }
}

/// Records Core acceptance before any safety-state sink write.  Failure is a
/// storage-only retry point: the Core callback must not be submitted again.
fn mark_core_invalid_delivery_delivered_v0(
    store: &ApplicationStore,
    accepted: CoreAcceptedInvalidDeliveryV0,
) -> Result<DeliveredCoreInvalidDeliveryV0, Box<FailedMarkCoreInvalidDeliveryDeliveredV0>> {
    let CoreAcceptedInvalidDeliveryV0 {
        owner,
        state,
        completion_revision,
        barrier,
        affinity,
    } = accepted;
    match store.mark_native_validation_invalid_callback_delivered_v0(owner) {
        Ok(owner) => Ok(DeliveredCoreInvalidDeliveryV0 {
            owner,
            state,
            completion_revision,
            barrier,
            affinity,
        }),
        Err(store_failure) => Err(Box::new(FailedMarkCoreInvalidDeliveryDeliveredV0 {
            store_failure,
            state,
            completion_revision,
            barrier,
            affinity,
        })),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactSafetyStateConfirmationV0 {
    Exact,
    Absent,
    Conflict,
}

/// Injected exact-state durability boundary.  Implementations must return
/// `Exact` only after the complete supplied state is durable and exact
/// readback has succeeded.  This trait intentionally does not define a
/// production SafetyState codec or WAL.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) trait DurableCoreSafetyStateSinkV0 {
    type Error;

    fn persist_exact_v0(
        &mut self,
        barrier: BarrierId,
        state: &SafetyState,
    ) -> Result<(), Self::Error>;

    fn confirm_exact_v0(
        &mut self,
        barrier: BarrierId,
        state: &SafetyState,
    ) -> Result<ExactSafetyStateConfirmationV0, Self::Error>;
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum RetryablePersistCoreInvalidSafetyCauseV0<E> {
    PersistUnconfirmed(E),
    PersistAndConfirmUnavailable { persist: E, confirm: E },
    Confirm(E),
    Absent,
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a retryable safety persistence failure retains its Delivered owner"]
pub(crate) struct RetryablePersistCoreInvalidSafetyV0<E> {
    owner: DeliveredCoreInvalidDeliveryV0,
    cause: RetryablePersistCoreInvalidSafetyCauseV0<E>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl<E> RetryablePersistCoreInvalidSafetyV0<E> {
    pub(crate) const fn cause(&self) -> &RetryablePersistCoreInvalidSafetyCauseV0<E> {
        &self.cause
    }

    pub(crate) fn into_owner_v0(self) -> DeliveredCoreInvalidDeliveryV0 {
        self.owner
    }
}

/// Exact readback contradicted the state supplied to the sink. The Delivered
/// owner is quarantined with the conflicting sink observation and has no
/// extractor back into the retryable delivery phase.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a safety-state conflict quarantines the Delivered owner"]
pub(crate) struct ConflictingPersistCoreInvalidSafetyV0<E> {
    owner: DeliveredCoreInvalidDeliveryV0,
    persist_error: Option<E>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl<E> ConflictingPersistCoreInvalidSafetyV0<E> {
    pub(crate) const fn state(&self) -> &SafetyState {
        self.owner.state()
    }

    pub(crate) const fn persist_error(&self) -> Option<&E> {
        self.persist_error.as_ref()
    }
}

/// Exact safety persistence succeeded, but the delivered store owner refused
/// the completion revision. This is an invariant quarantine, not retry.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a completion-binding invariant quarantines the persisted owner"]
pub(crate) struct InvalidPersistedCompletionBindingV0 {
    failure: Box<FailedBindConfirmedCoreInvalidCompletionV0>,
    state: Box<SafetyState>,
    barrier: BarrierId,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl InvalidPersistedCompletionBindingV0 {
    pub(crate) const fn state(&self) -> &SafetyState {
        &self.state
    }

    pub(crate) const fn barrier(&self) -> BarrierId {
        self.barrier
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum FailedPersistCoreInvalidSafetyV0<E> {
    Retryable(Box<RetryablePersistCoreInvalidSafetyV0<E>>),
    Conflict(Box<ConflictingPersistCoreInvalidSafetyV0<E>>),
    CompletionBinding(Box<InvalidPersistedCompletionBindingV0>),
}

impl<E: std::fmt::Debug> std::fmt::Debug for FailedPersistCoreInvalidSafetyV0<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retryable(failure) => formatter
                .debug_struct("Retryable")
                .field("cause", failure.cause())
                .field("retains_delivered_owner", &true)
                .finish(),
            Self::Conflict(failure) => formatter
                .debug_struct("Conflict")
                .field("persist_error", &failure.persist_error())
                .field("quarantines_delivered_owner", &true)
                .finish(),
            Self::CompletionBinding(failure) => formatter
                .debug_struct("CompletionBinding")
                .field("barrier", &failure.barrier())
                .field("quarantines_persisted_owner", &true)
                .finish(),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a confirmed callback must be acknowledged in the application journal"]
pub(crate) struct ConfirmedCoreInvalidDeliveryV0 {
    owner: Box<ConfirmedCoreInvalidCompletionV0>,
    state: Box<SafetyState>,
    completion_revision: u64,
    barrier: BarrierId,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
}

impl ConfirmedCoreInvalidDeliveryV0 {
    fn affinity_v0(&self) -> &Arc<NativeValidationCallbackDriverAffinityV0> {
        &self.affinity
    }
}

/// Persists and confirms the exact Core safety image, then binds the durable
/// completion revision into the consuming store acknowledgement owner.
fn persist_and_confirm_core_invalid_safety_v0<S: DurableCoreSafetyStateSinkV0>(
    sink: &mut S,
    delivered: DeliveredCoreInvalidDeliveryV0,
) -> Result<ConfirmedCoreInvalidDeliveryV0, Box<FailedPersistCoreInvalidSafetyV0<S::Error>>> {
    let barrier = delivered.barrier;
    let persist_error = sink.persist_exact_v0(barrier, &delivered.state).err();
    match (
        persist_error,
        sink.confirm_exact_v0(barrier, &delivered.state),
    ) {
        (persist_error, Ok(ExactSafetyStateConfirmationV0::Exact)) => {
            drop(persist_error);
        }
        (Some(persist), Err(confirm)) => {
            return Err(Box::new(FailedPersistCoreInvalidSafetyV0::Retryable(
                Box::new(RetryablePersistCoreInvalidSafetyV0 {
                    owner: delivered,
                    cause: RetryablePersistCoreInvalidSafetyCauseV0::PersistAndConfirmUnavailable {
                        persist,
                        confirm,
                    },
                }),
            )));
        }
        (None, Err(error)) => {
            return Err(Box::new(FailedPersistCoreInvalidSafetyV0::Retryable(
                Box::new(RetryablePersistCoreInvalidSafetyV0 {
                    owner: delivered,
                    cause: RetryablePersistCoreInvalidSafetyCauseV0::Confirm(error),
                }),
            )));
        }
        (persist_error, Ok(ExactSafetyStateConfirmationV0::Absent)) => {
            let cause = match persist_error {
                Some(error) => RetryablePersistCoreInvalidSafetyCauseV0::PersistUnconfirmed(error),
                None => RetryablePersistCoreInvalidSafetyCauseV0::Absent,
            };
            return Err(Box::new(FailedPersistCoreInvalidSafetyV0::Retryable(
                Box::new(RetryablePersistCoreInvalidSafetyV0 {
                    owner: delivered,
                    cause,
                }),
            )));
        }
        (persist_error, Ok(ExactSafetyStateConfirmationV0::Conflict)) => {
            return Err(Box::new(FailedPersistCoreInvalidSafetyV0::Conflict(
                Box::new(ConflictingPersistCoreInvalidSafetyV0 {
                    owner: delivered,
                    persist_error,
                }),
            )));
        }
    }

    let DeliveredCoreInvalidDeliveryV0 {
        owner,
        state,
        completion_revision,
        barrier,
        affinity,
    } = delivered;
    match owner.bind_confirmed_core_completion_v0(completion_revision) {
        Ok(owner) => Ok(ConfirmedCoreInvalidDeliveryV0 {
            owner,
            state,
            completion_revision,
            barrier,
            affinity,
        }),
        Err(failure) => Err(Box::new(
            FailedPersistCoreInvalidSafetyV0::CompletionBinding(Box::new(
                InvalidPersistedCompletionBindingV0 {
                    failure,
                    state,
                    barrier,
                    affinity,
                },
            )),
        )),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "an acknowledged callback still gates the exact Core StorageAck"]
pub(crate) struct AckedCoreInvalidDeliveryV0 {
    owner: Box<AckedNativeValidationInvalidCallbackV0>,
    state: Box<SafetyState>,
    barrier: BarrierId,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
}

impl AckedCoreInvalidDeliveryV0 {
    fn affinity_v0(&self) -> &Arc<NativeValidationCallbackDriverAffinityV0> {
        &self.affinity
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a failed application acknowledgement retains the confirmed owner"]
pub(crate) struct FailedAcknowledgeCoreInvalidDeliveryV0 {
    store_failure: Box<FailedNativeValidationInvalidAcknowledgementV0>,
    state: Box<SafetyState>,
    completion_revision: u64,
    barrier: BarrierId,
    affinity: Arc<NativeValidationCallbackDriverAffinityV0>,
}

impl std::fmt::Debug for FailedAcknowledgeCoreInvalidDeliveryV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedAcknowledgeCoreInvalidDeliveryV0")
            .field("store_cause", self.store_failure.cause())
            .field("retains_confirmed_owner", &true)
            .finish()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl FailedAcknowledgeCoreInvalidDeliveryV0 {
    pub(crate) const fn store_failure(&self) -> &FailedNativeValidationInvalidAcknowledgementV0 {
        &self.store_failure
    }

    pub(crate) fn into_owner_v0(self) -> ConfirmedCoreInvalidDeliveryV0 {
        ConfirmedCoreInvalidDeliveryV0 {
            owner: self.store_failure.into_owner_v0(),
            state: self.state,
            completion_revision: self.completion_revision,
            barrier: self.barrier,
            affinity: self.affinity,
        }
    }
}

fn acknowledge_core_invalid_delivery_v0(
    store: &ApplicationStore,
    confirmed: ConfirmedCoreInvalidDeliveryV0,
) -> Result<AckedCoreInvalidDeliveryV0, Box<FailedAcknowledgeCoreInvalidDeliveryV0>> {
    let ConfirmedCoreInvalidDeliveryV0 {
        owner,
        state,
        completion_revision,
        barrier,
        affinity,
    } = confirmed;
    match store.acknowledge_native_validation_invalid_callback_v0(owner) {
        Ok(owner) => Ok(AckedCoreInvalidDeliveryV0 {
            owner,
            state,
            barrier,
            affinity,
        }),
        Err(store_failure) => Err(Box::new(FailedAcknowledgeCoreInvalidDeliveryV0 {
            store_failure,
            state,
            completion_revision,
            barrier,
            affinity,
        })),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ReleasedCoreInvalidDeliveryV0 {
    Completed(Box<AckedNativeValidationInvalidCallbackV0>),
    SafetyHalted {
        owner: Box<AckedNativeValidationInvalidCallbackV0>,
        halt: Box<SafetyHalt>,
    },
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RejectedReleaseCoreInvalidDeliveryCauseV0 {
    Core(CoreError),
    CoreStateMismatch,
}

#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a rejected Core release retains the retryable acknowledged owner"]
pub(crate) struct RejectedReleaseCoreInvalidDeliveryV0 {
    owner: AckedCoreInvalidDeliveryV0,
    cause: RejectedReleaseCoreInvalidDeliveryCauseV0,
}

#[cfg_attr(not(test), allow(dead_code))]
impl RejectedReleaseCoreInvalidDeliveryV0 {
    pub(crate) const fn cause(&self) -> &RejectedReleaseCoreInvalidDeliveryCauseV0 {
        &self.cause
    }

    pub(crate) fn into_owner_v0(self) -> AckedCoreInvalidDeliveryV0 {
        self.owner
    }
}

/// `StorageAck` succeeded and therefore cannot be retried, but its released
/// effect set violated the callback-driver contract. The acknowledged owner
/// is quarantined inside this post-release carrier with the observed Core
/// image; there is intentionally no owner extractor.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a post-StorageAck invariant failure retains quarantined Core context"]
pub(crate) struct InvalidReleasedCoreInvalidDeliveryV0 {
    owner: AckedCoreInvalidDeliveryV0,
    observed_state: SafetyState,
    effects: Vec<Effect>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl InvalidReleasedCoreInvalidDeliveryV0 {
    pub(crate) const fn observed_state(&self) -> &SafetyState {
        &self.observed_state
    }

    pub(crate) fn effects(&self) -> &[Effect] {
        &self.effects
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum FailedReleaseCoreInvalidDeliveryV0 {
    Rejected(Box<RejectedReleaseCoreInvalidDeliveryV0>),
    ReleasedInvariant(Box<InvalidReleasedCoreInvalidDeliveryV0>),
}

impl std::fmt::Debug for FailedReleaseCoreInvalidDeliveryV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(failure) => formatter
                .debug_struct("Rejected")
                .field("cause", failure.cause())
                .field("retains_retryable_acked_owner", &true)
                .finish(),
            Self::ReleasedInvariant(failure) => formatter
                .debug_struct("ReleasedInvariant")
                .field("effects", &failure.effects())
                .field("quarantines_post_storage_ack_owner", &true)
                .finish(),
        }
    }
}

/// Releases Core only after both the exact safety image and application Acked
/// tombstone are durable.  No downstream effect is forwarded here: the only
/// permitted observable release is a typed SafetyHalted result.
fn release_acked_core_invalid_delivery_v0<V: SignatureVerifier>(
    core: &mut Core,
    verifier: &V,
    acked: AckedCoreInvalidDeliveryV0,
) -> Result<ReleasedCoreInvalidDeliveryV0, Box<FailedReleaseCoreInvalidDeliveryV0>> {
    if core.safety_state() != acked.state.as_ref() {
        return Err(Box::new(FailedReleaseCoreInvalidDeliveryV0::Rejected(
            Box::new(RejectedReleaseCoreInvalidDeliveryV0 {
                owner: acked,
                cause: RejectedReleaseCoreInvalidDeliveryCauseV0::CoreStateMismatch,
            }),
        )));
    }
    let barrier = acked.barrier;
    let effects = match core.step(Input::StorageAck { barrier }, verifier) {
        Ok(effects) => effects,
        Err(error) => {
            return Err(Box::new(FailedReleaseCoreInvalidDeliveryV0::Rejected(
                Box::new(RejectedReleaseCoreInvalidDeliveryV0 {
                    owner: acked,
                    cause: RejectedReleaseCoreInvalidDeliveryCauseV0::Core(error),
                }),
            )));
        }
    };
    if core.safety_state() != acked.state.as_ref() {
        return Err(Box::new(
            FailedReleaseCoreInvalidDeliveryV0::ReleasedInvariant(Box::new(
                InvalidReleasedCoreInvalidDeliveryV0 {
                    owner: acked,
                    observed_state: core.safety_state().clone(),
                    effects,
                },
            )),
        ));
    }
    if acked.state.safety_halt().is_none() && effects.is_empty() {
        return Ok(ReleasedCoreInvalidDeliveryV0::Completed(acked.owner));
    }
    if acked.state.safety_halt().is_some() && effects.len() == 1 {
        if let Effect::SafetyHalted(halt) = &effects[0] {
            if acked.state.safety_halt() == Some(halt.as_ref()) {
                return Ok(ReleasedCoreInvalidDeliveryV0::SafetyHalted {
                    owner: acked.owner,
                    halt: halt.clone(),
                });
            }
        }
    }
    Err(Box::new(
        FailedReleaseCoreInvalidDeliveryV0::ReleasedInvariant(Box::new(
            InvalidReleasedCoreInvalidDeliveryV0 {
                owner: acked,
                observed_state: core.safety_state().clone(),
                effects,
            },
        )),
    ))
}

#[cfg_attr(not(test), allow(dead_code))]
impl<'a, V: SignatureVerifier, S> NativeValidationCallbackDriverV0<'a, V, S> {
    /// Test-only assembly of the future host-owned driver shape.
    ///
    /// This does not install a process-wide Core owner and the supplied sink
    /// is not a production SafetyState codec/WAL. Production construction
    /// remains intentionally absent until those two host boundaries exist.
    #[cfg(test)]
    pub(crate) fn new_for_test_v0(
        application_store: &'a ApplicationStore,
        core: Core,
        verifier: V,
        safety_sink: S,
    ) -> Self {
        Self {
            application_store,
            core,
            verifier,
            safety_sink,
            affinity: Arc::new(NativeValidationCallbackDriverAffinityV0),
        }
    }

    pub(crate) fn bind_live_invalid_delivery_v0(
        &self,
        owner: Box<LiveNativeValidationInvalidCallbackV0>,
    ) -> Result<CoreBoundLiveInvalidDeliveryV0, Box<FailedBindLiveInvalidDeliveryV0>> {
        bind_live_invalid_delivery_v0(
            self.application_store,
            &self.core,
            owner,
            Arc::clone(&self.affinity),
        )
    }

    pub(crate) fn step_bound_invalid_delivery_v0(
        &mut self,
        bound: CoreBoundLiveInvalidDeliveryV0,
    ) -> Result<
        CoreAcceptedInvalidDeliveryV0,
        NativeValidationCallbackDriverPhaseFailureV0<
            CoreBoundLiveInvalidDeliveryV0,
            FailedCoreInvalidDeliveryStepV0,
        >,
    > {
        if !Arc::ptr_eq(&self.affinity, bound.affinity_v0()) {
            return Err(NativeValidationCallbackDriverPhaseFailureV0::ForeignDriver(
                bound,
            ));
        }
        step_bound_invalid_delivery_v0(&mut self.core, &self.verifier, bound)
            .map_err(NativeValidationCallbackDriverPhaseFailureV0::Phase)
    }

    pub(crate) fn mark_core_invalid_delivery_delivered_v0(
        &self,
        accepted: CoreAcceptedInvalidDeliveryV0,
    ) -> Result<
        DeliveredCoreInvalidDeliveryV0,
        NativeValidationCallbackDriverPhaseFailureV0<
            CoreAcceptedInvalidDeliveryV0,
            Box<FailedMarkCoreInvalidDeliveryDeliveredV0>,
        >,
    > {
        if !Arc::ptr_eq(&self.affinity, accepted.affinity_v0()) {
            return Err(NativeValidationCallbackDriverPhaseFailureV0::ForeignDriver(
                accepted,
            ));
        }
        mark_core_invalid_delivery_delivered_v0(self.application_store, accepted)
            .map_err(NativeValidationCallbackDriverPhaseFailureV0::Phase)
    }

    pub(crate) fn acknowledge_core_invalid_delivery_v0(
        &self,
        confirmed: ConfirmedCoreInvalidDeliveryV0,
    ) -> Result<
        AckedCoreInvalidDeliveryV0,
        NativeValidationCallbackDriverPhaseFailureV0<
            ConfirmedCoreInvalidDeliveryV0,
            Box<FailedAcknowledgeCoreInvalidDeliveryV0>,
        >,
    > {
        if !Arc::ptr_eq(&self.affinity, confirmed.affinity_v0()) {
            return Err(NativeValidationCallbackDriverPhaseFailureV0::ForeignDriver(
                confirmed,
            ));
        }
        acknowledge_core_invalid_delivery_v0(self.application_store, confirmed)
            .map_err(NativeValidationCallbackDriverPhaseFailureV0::Phase)
    }

    pub(crate) fn release_acked_core_invalid_delivery_v0(
        &mut self,
        acked: AckedCoreInvalidDeliveryV0,
    ) -> Result<
        ReleasedCoreInvalidDeliveryV0,
        NativeValidationCallbackDriverPhaseFailureV0<
            AckedCoreInvalidDeliveryV0,
            Box<FailedReleaseCoreInvalidDeliveryV0>,
        >,
    > {
        if !Arc::ptr_eq(&self.affinity, acked.affinity_v0()) {
            return Err(NativeValidationCallbackDriverPhaseFailureV0::ForeignDriver(
                acked,
            ));
        }
        release_acked_core_invalid_delivery_v0(&mut self.core, &self.verifier, acked)
            .map_err(NativeValidationCallbackDriverPhaseFailureV0::Phase)
    }

    /// Read-only test observation; this never exposes the owned Core itself.
    #[cfg(test)]
    pub(crate) const fn safety_state_for_test_v0(&self) -> &SafetyState {
        self.core.safety_state()
    }

    /// Read-only test observation of Core's pending validation count.
    #[cfg(test)]
    pub(crate) fn pending_validation_count_for_test_v0(&self) -> usize {
        self.core.pending_validation_count()
    }

    /// Probes the pending-persistence barrier without exposing `Core::step`.
    /// The probe succeeds only when Core rejects the callback transactionally
    /// and retains the exact same SafetyState image.
    #[cfg(test)]
    pub(crate) fn invalid_callback_retry_is_blocked_for_test_v0(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
    ) -> bool {
        let before = self.core.safety_state().clone();
        self.core
            .step(invalid_callback_input_v0(route, id), &self.verifier)
            .is_err()
            && self.core.safety_state() == &before
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl<'a, V: SignatureVerifier, S: DurableCoreSafetyStateSinkV0>
    NativeValidationCallbackDriverV0<'a, V, S>
{
    pub(crate) fn persist_and_confirm_core_invalid_safety_v0(
        &mut self,
        delivered: DeliveredCoreInvalidDeliveryV0,
    ) -> PersistAndConfirmCoreInvalidSafetyResultV0<S::Error> {
        if !Arc::ptr_eq(&self.affinity, delivered.affinity_v0()) {
            return Err(NativeValidationCallbackDriverPhaseFailureV0::ForeignDriver(
                delivered,
            ));
        }
        persist_and_confirm_core_invalid_safety_v0(&mut self.safety_sink, delivered)
            .map_err(NativeValidationCallbackDriverPhaseFailureV0::Phase)
    }
}

type PersistAndConfirmCoreInvalidSafetyResultV0<E> = Result<
    ConfirmedCoreInvalidDeliveryV0,
    NativeValidationCallbackDriverPhaseFailureV0<
        DeliveredCoreInvalidDeliveryV0,
        Box<FailedPersistCoreInvalidSafetyV0<E>>,
    >,
>;

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestSafetySinkFaultV0 {
    BeforeWrite,
    AfterWrite,
    ConfirmUnavailable,
    ConfirmAbsent,
    ConfirmConflict,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestSafetySinkErrorV0 {
    BarrierRevisionMismatch,
    NonMonotonicRevision,
    RevisionConflict,
    Injected(TestSafetySinkFaultV0),
}

/// In-memory exact-state oracle used only to test the driver's sequencing and
/// commit-uncertainty behavior.  It is intentionally not a production sink.
#[cfg(test)]
pub(crate) struct TestDurableCoreSafetyStateSinkV0 {
    states: std::collections::BTreeMap<u64, SafetyState>,
    next_fault: Option<TestSafetySinkFaultV0>,
}

#[cfg(test)]
impl TestDurableCoreSafetyStateSinkV0 {
    pub(crate) fn empty_v0() -> Self {
        Self {
            states: std::collections::BTreeMap::new(),
            next_fault: None,
        }
    }

    pub(crate) fn from_state_v0(state: SafetyState) -> Self {
        let mut value = Self::empty_v0();
        value.states.insert(state.revision(), state);
        value
    }

    pub(crate) fn fail_once_v0(&mut self, fault: TestSafetySinkFaultV0) {
        self.next_fault = Some(fault);
    }

    pub(crate) fn state_v0(&self, revision: u64) -> Option<&SafetyState> {
        self.states.get(&revision)
    }
}

#[cfg(test)]
impl<'a, V: SignatureVerifier>
    NativeValidationCallbackDriverV0<'a, V, TestDurableCoreSafetyStateSinkV0>
{
    /// Injects one test-only durability fault without exposing or replacing
    /// the owned sink.
    pub(crate) fn fail_safety_sink_once_for_test_v0(&mut self, fault: TestSafetySinkFaultV0) {
        self.safety_sink.fail_once_v0(fault);
    }

    /// Read-only test observation; the owned sink itself never escapes.
    pub(crate) fn safety_sink_state_for_test_v0(&self, revision: u64) -> Option<&SafetyState> {
        self.safety_sink.state_v0(revision)
    }
}

#[cfg(test)]
impl DurableCoreSafetyStateSinkV0 for TestDurableCoreSafetyStateSinkV0 {
    type Error = TestSafetySinkErrorV0;

    fn persist_exact_v0(
        &mut self,
        barrier: BarrierId,
        state: &SafetyState,
    ) -> Result<(), Self::Error> {
        if barrier.get() != state.revision() {
            return Err(TestSafetySinkErrorV0::BarrierRevisionMismatch);
        }
        if self.next_fault == Some(TestSafetySinkFaultV0::BeforeWrite) {
            self.next_fault = None;
            return Err(TestSafetySinkErrorV0::Injected(
                TestSafetySinkFaultV0::BeforeWrite,
            ));
        }
        match self.states.get(&state.revision()) {
            Some(existing) if existing != state => {
                return Err(TestSafetySinkErrorV0::RevisionConflict);
            }
            Some(_) => {}
            None => {
                if let Some(last) = self.states.keys().next_back() {
                    if state.revision() != last.saturating_add(1) {
                        return Err(TestSafetySinkErrorV0::NonMonotonicRevision);
                    }
                }
                self.states.insert(state.revision(), state.clone());
            }
        }
        if self.next_fault == Some(TestSafetySinkFaultV0::AfterWrite) {
            self.next_fault = None;
            return Err(TestSafetySinkErrorV0::Injected(
                TestSafetySinkFaultV0::AfterWrite,
            ));
        }
        Ok(())
    }

    fn confirm_exact_v0(
        &mut self,
        barrier: BarrierId,
        state: &SafetyState,
    ) -> Result<ExactSafetyStateConfirmationV0, Self::Error> {
        if barrier.get() != state.revision() {
            return Err(TestSafetySinkErrorV0::BarrierRevisionMismatch);
        }
        match self.next_fault.take() {
            Some(TestSafetySinkFaultV0::ConfirmUnavailable) => Err(
                TestSafetySinkErrorV0::Injected(TestSafetySinkFaultV0::ConfirmUnavailable),
            ),
            Some(TestSafetySinkFaultV0::ConfirmAbsent) => {
                Ok(ExactSafetyStateConfirmationV0::Absent)
            }
            Some(TestSafetySinkFaultV0::ConfirmConflict) => {
                Ok(ExactSafetyStateConfirmationV0::Conflict)
            }
            Some(
                fault @ (TestSafetySinkFaultV0::BeforeWrite | TestSafetySinkFaultV0::AfterWrite),
            ) => {
                self.next_fault = Some(fault);
                match self.states.get(&state.revision()) {
                    Some(existing) if existing == state => {
                        Ok(ExactSafetyStateConfirmationV0::Exact)
                    }
                    Some(_) => Ok(ExactSafetyStateConfirmationV0::Conflict),
                    None => Ok(ExactSafetyStateConfirmationV0::Absent),
                }
            }
            None => match self.states.get(&state.revision()) {
                Some(existing) if existing == state => Ok(ExactSafetyStateConfirmationV0::Exact),
                Some(_) => Ok(ExactSafetyStateConfirmationV0::Conflict),
                None => Ok(ExactSafetyStateConfirmationV0::Absent),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DurableCoreSafetyStateSinkV0, ExactSafetyStateConfirmationV0,
        TestDurableCoreSafetyStateSinkV0, TestSafetySinkFaultV0,
    };

    #[test]
    fn callback_driver_source_keeps_safety_sink_explicitly_non_production() {
        let source = include_str!("native_validation_callback_driver.rs");
        assert!(source.contains("not a codec or WAL implementation"));
        assert!(source.contains("struct NativeValidationCallbackDriverV0"));
        assert!(source.contains("process-wide production Core owner"));
        assert!(source.contains("trait DurableCoreSafetyStateSinkV0"));
        let forbidden_production_sink =
            ["impl DurableCoreSafetyStateSinkV0 for ", "ApplicationStore"].concat();
        assert!(!source.contains(&forbidden_production_sink));
        let forbidden_core_mut = ["pub(crate) fn core", "_mut"].concat();
        let forbidden_into_parts = ["pub(crate) fn into", "_parts"].concat();
        assert!(!source.contains(&forbidden_core_mut));
        assert!(!source.contains(&forbidden_into_parts));
        let forbidden_completion_variant = ["Exact", "Completion"].concat();
        assert!(!source.contains(&forbidden_completion_variant));
        assert!(source.contains("CompletionLacksArtifactBinding"));
        assert!(source.contains("affinity: Arc<NativeValidationCallbackDriverAffinityV0>"));
        assert!(source.contains("Arc::new(NativeValidationCallbackDriverAffinityV0)"));
        assert!(source.contains("Arc::ptr_eq(&self.affinity"));
        for exposed_affinity in [
            ["pub fn affinity", "_v0"].concat(),
            ["pub(super) fn affinity", "_v0"].concat(),
            ["pub(crate) fn affinity", "_v0"].concat(),
        ] {
            assert!(!source.contains(&exposed_affinity));
        }
        let forbidden_detached_bind = [
            "pub(crate) fn bind_live_invalid_delivery_v0(\n    ",
            "store:",
        ]
        .concat();
        let forbidden_detached_step =
            ["pub(crate) fn step_bound_invalid_delivery_v0", "<"].concat();
        assert!(!source.contains(&forbidden_detached_bind));
        assert!(!source.contains(&forbidden_detached_step));
    }

    #[test]
    fn callback_driver_is_store_nested_and_raw_journal_transitions_are_private() {
        let driver_source = include_str!("native_validation_callback_driver.rs");
        let store_source = include_str!("store.rs");
        let crate_source = include_str!("lib.rs");

        assert!(store_source.contains(
            "#[path = \"native_validation_callback_driver.rs\"]\npub(crate) mod native_validation_callback_driver;"
        ));
        assert!(!crate_source.contains("mod native_validation_callback_driver;"));

        for raw_transition in [
            "bind_confirmed_core_completion_v0",
            "mark_native_validation_invalid_callback_delivered_v0",
            "acknowledge_native_validation_invalid_callback_v0",
        ] {
            assert!(store_source.contains(&format!("    fn {raw_transition}(")));
            for exposed in ["pub fn", "pub(super) fn", "pub(crate) fn"] {
                assert!(
                    !store_source.contains(&format!("    {exposed} {raw_transition}(")),
                    "raw callback transition became sibling-callable: {raw_transition}"
                );
            }
        }

        let conflict_surface = driver_source
            .split_once("impl<E> ConflictingPersistCoreInvalidSafetyV0<E> {")
            .expect("conflicting safety persistence quarantine")
            .1
            .split_once("/// Exact safety persistence succeeded")
            .expect("conflicting safety persistence quarantine end")
            .0;
        assert!(!conflict_surface.contains("into_owner"));

        let retryable_surface = driver_source
            .split_once("impl<E> RetryablePersistCoreInvalidSafetyV0<E> {")
            .expect("retryable safety persistence owner")
            .1
            .split_once("/// Exact readback contradicted")
            .expect("retryable safety persistence owner end")
            .0;
        assert!(retryable_surface.contains("into_owner_v0"));
    }

    #[test]
    fn test_sink_faults_are_one_shot_and_never_claim_absent_as_exact() {
        // Behavioral SafetyState coverage is exercised by the live Core
        // integration tests.  This source guard keeps the uncertainty states
        // closed and prevents an absent readback from becoming success.
        let source = include_str!("native_validation_callback_driver.rs");
        assert!(source.contains("ExactSafetyStateConfirmationV0::Absent"));
        assert!(source.contains("ExactSafetyStateConfirmationV0::Conflict"));
        assert!(source.contains("TestSafetySinkFaultV0::AfterWrite"));
        let _trait_method = TestDurableCoreSafetyStateSinkV0::confirm_exact_v0;
        let _closed = ExactSafetyStateConfirmationV0::Exact;
        let _fault = TestSafetySinkFaultV0::BeforeWrite;
    }
}
