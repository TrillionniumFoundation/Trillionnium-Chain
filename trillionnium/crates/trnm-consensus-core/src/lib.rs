#![no_std]
#![forbid(unsafe_code)]
//! Deterministic PoCO-BFT v0 safety core.
//!
//! All nondeterministic work is represented as an [`Effect`] and returned to
//! the node driver. The driver feeds completion back as another [`Input`]. In
//! particular this crate never reads a clock, performs I/O, owns a private key,
//! or validates an application payload itself.
//!
//! Recovery emits `Effect::RequestSafetyReplay`. The driver must replay signed
//! proposals in parent-to-child order from the finalized tip through `high_qc`
//! (retrying a child if it arrived before its parent), then acknowledge with
//! `Input::SafetyReplayComplete`. Missing ancestry remains fail-closed.
//! After completing a recovered signing/finalization outbox, call `Resume`
//! again to continue replay/timer recovery.
//!
//! `Core::recover` remains fail-closed for every durable payload-validation
//! obligation.  The explicit `begin_payload_validation_obligation_recovery_v0`
//! session is a narrower trusted-host boundary for exactly one independently
//! reconciled deterministic-invalid job; it never exposes a live Core before
//! that reconciliation and fences all consensus progress until the exact
//! callback becomes a durable transition.
//!
//! A current SafetyStore codec-v0/tag-3 finalization-applied head has a
//! separate `begin_native_finalization_applied_recovery_v0` session. It
//! requires trusted-host reconciliation with the exact ApplicationStore
//! receipt/head readback, then makes the first `Resume` remint only the
//! recorded post-ack action without another SafetyState transition. No node or
//! ApplicationStore currently wires that reconciliation boundary, so this
//! library capability does not activate production consensus by itself.
//!
//! Schema v12 additionally supports a fresh-validator, epoch-zero h1
//! state-sync anchor. `prepare_h1_state_sync_bootstrap_v0` verifies the complete
//! genesis-anchored finality proof without inventing h1 execution history.
//! `begin_state_sync_anchor_recovery_v0` remains inert until a trusted host
//! reconciles the exact ApplicationStore base and a virgin signer namespace;
//! generic `Core::recover` rejects anchored namespaces. That legacy entry is
//! permanently replay-request-only. A separate
//! `begin_state_sync_anchor_successor_recovery_v0` session can authenticate
//! complete h2/h3 bodies and, after a trusted ApplicationStore reconciliation,
//! drive only the five canonical revision-0..4 successor phases. It exposes no
//! signing, timer, network, finalization, or generic Core input authority;
//! revision-1/3 crash cuts remain explicitly unrecoverable in v0. Canonical
//! H3Valid may then cross one manifest-bound revision-five persistence barrier
//! into an anchored-ordinary namespace. The h1 anchor and exact h2/h3 Valid
//! facts remain permanent provenance; generic Core authority is released only
//! after the promotion ACK or an authenticated promoted recovery join.
//!
//! An ordinary non-anchored current NativeValid completion has its own
//! `begin_native_valid_completion_recovery_v0` boundary. It accepts only one
//! exact current Valid completion and remains inert until a trusted host joins
//! the authenticated SafetyStore transition to a stable App Delivered or
//! Acked row. Activation exposes no generic Core input or live side effect: it
//! releases one linear comparison token naming the exact recorded action.
//!
//! Authenticated-genesis h1 revision-one obligations use a separate takeover
//! boundary. `begin_authenticated_genesis_application_h1_obligation_takeover_v0`
//! replays the complete durable signed empty h1 from prepared tag-5 revision
//! zero through the existing narrow admission owner and requires byte-for-byte
//! semantic equality with the durable revision-one state. The replay remains
//! behind barrier one. Only a session-affined attestation from a trusted live
//! SafetyStore join can unlock the real `StorageAck` and its sole Synced
//! validation request; no request, permit, or callback is reconstructed from a
//! persisted row. Generic construction, recovery, and step surfaces remain
//! fail-closed for the same authenticated application parent.

extern crate alloc;

/// Complete proposal bodies are retained only after the existing bounded
/// application-Valid transition. This data-only cache is the prerequisite for
/// a later safety-kernel shadow comparison.
pub const CORE_BOUNDED_EXACT_VALIDATED_PROPOSAL_RETENTION_V0: bool = true;

/// Proposal retention does not mint application-validity authority.
pub const CORE_PROPOSAL_RETENTION_APPLICATION_VALID_AUTHORITY_V0: bool = false;

/// Proposal retention does not mint finality authority.
pub const CORE_PROPOSAL_RETENTION_FINALITY_AUTHORITY_V0: bool = false;

/// Proposal retention is volatile and does not mint persistence authority.
pub const CORE_PROPOSAL_RETENTION_PERSISTENCE_AUTHORITY_V0: bool = false;

/// Proposal retention cannot authorize or request a signature.
pub const CORE_PROPOSAL_RETENTION_SIGNER_AUTHORITY_V0: bool = false;

mod block_tree;
mod core;
mod error;
mod model;
mod safety_state_record;

pub use crate::core::{
    leader_for, reconstruct_h1_state_sync_anchor_successor_prefix_v0, AnchoredOrdinaryActivatedV0,
    AnchoredOrdinaryArmViewTimerV0, AnchoredOrdinaryCheckpointedLinkClaimV0,
    AnchoredOrdinaryRehydrateChallengeV0, AnchoredOrdinaryRehydrateReconcilerV0,
    AnchoredOrdinaryRehydrateSessionV0, AnchoredOrdinaryRehydratedFactsV0,
    AnchoredOrdinaryRehydratedOwnerV0, AnchoredOrdinaryReplayArchivePlanV0,
    AnchoredOrdinarySignedReplayEntryV0, ApplicationNativeValidDeliveryFactsV0,
    ApplicationSealedNativeValidTransitionV0, AuthenticatedGenesisApplicationH1CompletedV0,
    AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
    AuthenticatedGenesisApplicationH1ObligationPersistenceV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverActivationBundleV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverChallengeV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverReboundActivationV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyAttestationV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyHeadFactsV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyRebindRegistrarV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverSafetyReconcilerV0,
    AuthenticatedGenesisApplicationH1ObligationTakeoverSessionV0,
    AuthenticatedGenesisApplicationH1OfflineActivationBundleV0,
    AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
    AuthenticatedGenesisApplicationH1OfflineApplicationRegistrarV0,
    AuthenticatedGenesisApplicationH1OfflineContextFactsV0,
    AuthenticatedGenesisApplicationH1OfflinePhaseV0,
    AuthenticatedGenesisApplicationH1OfflineSafetyPersistenceBindingV0,
    AuthenticatedGenesisApplicationH1OfflineValidationV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoveredFactsV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoveryAttestationV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoveryChallengeV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReconcilerV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoveryReplayV0,
    AuthenticatedGenesisApplicationH1StableNativeValidRecoverySessionV0,
    AuthenticatedGenesisApplicationH1StableNativeValidSafetyHeadFactsV0,
    AuthenticatedGenesisApplicationH1StateSyncPromotionCandidateV0,
    AuthenticatedGenesisApplicationH1ValidationRequestV0, Core, FinalizedChainRootV0,
    H1StateSyncAnchorSuccessorBundleV0, NativeFinalizationAppliedRecoveryActivationRejectionV0,
    NativeFinalizationAppliedRecoveryAttestationV0, NativeFinalizationAppliedRecoveryChallengeV0,
    NativeFinalizationAppliedRecoveryReconcilerV0, NativeFinalizationAppliedRecoverySessionV0,
    NativeValidCompletionRecoveredActionV0, NativeValidCompletionRecoveryAttestationV0,
    NativeValidCompletionRecoveryChallengeV0, NativeValidCompletionRecoveryReconcilerV0,
    NativeValidCompletionRecoveryReplayV0, NativeValidCompletionRecoverySessionV0,
    PayloadValidationRecoveryChallengeV0, PayloadValidationRecoveryDecisionV0,
    PayloadValidationRecoveryReconcilerV0, PayloadValidationRecoverySessionV0,
    PreparedAuthenticatedGenesisApplicationBootstrapV0, PreparedH1StateSyncBootstrapV0,
    StateSyncAnchorOrdinaryActivationV0, StateSyncAnchorOrdinaryRecoveryChallengeV0,
    StateSyncAnchorOrdinaryRecoveryReconcilerV0, StateSyncAnchorOrdinaryRecoverySessionV0,
    StateSyncAnchorRecoveryChallengeV0, StateSyncAnchorRecoveryReconcilerV0,
    StateSyncAnchorRecoverySessionV0, StateSyncAnchorSuccessorPhaseV0,
    StateSyncAnchorSuccessorRecoveryChallengeV0, StateSyncAnchorSuccessorRecoveryReconcilerV0,
    StateSyncAnchorSuccessorRecoverySessionV0, StateSyncAnchorSuccessorReplayV0,
    AUTHENTICATED_GENESIS_H1_COMPLETION_CARRIER_CHECKSUM_DOMAIN_V0,
};
pub use crate::error::{CoreError, Result};
pub use crate::model::{
    native_finalization_applied_checksum_v0, native_valid_result_checksum_v0,
    ApplicationFinalizationApplyReadbackV0, ApplicationFinalizationPermitRejectionV0,
    ApplicationFinalizationReceiptRejectionV0, ApplicationFinalizationReceiptV0,
    ApplicationSealedValidV0, AuthenticatedGenesisApplicationParentV0,
    AuthorizedPayloadValidationValidV0, BarrierId, BlockIdOverlayRefV0,
    ClaimedPayloadValidationRequestV0, CoreAcceptedApplicationValidDV0, CoreConfig,
    CoreIssuedApplicationFinalizationApplyAuthorityV0, CoreIssuedApplicationFinalizationPermitV0,
    CoreIssuedApplicationSealAuthorityV0, CoreIssuedValidPermitV0,
    DuplicatePayloadValidationRequestV0, DurableFinalizationV0,
    DurablePayloadValidationCompletionV0, DurablePayloadValidationObligationV0,
    DurablePayloadValidationResultV1, DurableStateSyncAnchorV0, DurableValidatedBlockCommitmentsV1,
    Effect, FinalizedTip, Input, InvalidPayloadReference, NativeFinalizationAppliedPersistenceV0,
    NativeFinalizationAppliedPostAckActionV0, NativeFinalizationAppliedRecoveryTransitionV0,
    NativeValidPostAckActionV0, OutboundMessage, PayloadTerminalFact, PayloadTerminalResult,
    PayloadValidationParentProvenanceV0, PayloadValidationParentV0, PayloadValidationRequest,
    PayloadValidationResult, PayloadValidationRouteV0, PendingStandaloneQcSync,
    PendingTcHighQcSync, SafetyHalt, SafetyState, SafetyStatePersistenceBindingV0,
    SafetyStatePersistenceV0, SignId, SignIntent, SignKind,
    StateSyncAnchorOrdinaryPromotionPersistenceV0, ValidatedPayloadArtifactRefV0, ValidationId,
    AUTHENTICATED_GENESIS_APPLICATION_PARENT_BINDING_DOMAIN_V0,
    NATIVE_FINALIZATION_APPLIED_CHECKSUM_DOMAIN_V0, NATIVE_VALID_RESULT_CHECKSUM_DOMAIN_V0,
    PAYLOAD_VALIDATION_PARENT_BINDING_DOMAIN_V0, SAFETY_STATE_SCHEMA_VERSION,
};
pub use crate::safety_state_record::{
    decode_safety_state_record_v0_exact, encode_safety_state_record_v0,
    minimum_safety_state_record_limits_v0, safety_state_record_config_ref_v0,
    SafetyStateRecordContextV0, SafetyStateRecordErrorV0, SafetyStateRecordLimitsV0,
    UnverifiedSafetyStateRecordV0, SAFETY_STATE_RECORD_CODEC_VERSION_V0,
    SAFETY_STATE_RECORD_SAFETY_SCHEMA_VERSION_V0,
};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
