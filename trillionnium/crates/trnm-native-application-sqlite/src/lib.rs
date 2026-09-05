#![forbid(unsafe_code)]
//! Durable native-application journals for proposal validation and candidate finalization history.
//!
//! This crate remains narrower than an application engine. It stores exact
//! proposal-validation bindings, complete canonical `NativeExecutedBlockV0`
//! artifacts, the ordered `P` -> `D` -> request-bound, `C`-shaped `K` recovery
//! journal, and content-addressed finalization readbacks. The `P` capability is
//! released only after an atomic write and fresh-connection exact artifact
//! readback. The finalization history records an application-produced readback;
//! it does not execute transactions, mint a Core/Safety permit, advance the
//! application head by itself, sign, broadcast, or decide consensus validity.

mod binding;
mod error;
mod finalization_history;
mod store;

pub use binding::{
    CoreDeliveryConfirmationV0, NonZeroDigestV0, ProposalRouteV0, ProposalValidationBindingV0,
    ProposalValidationOwnerIdV0, RequestBoundSafetyConfirmationV0, SafetyConfirmationReadRequestV0,
    SafetyConfirmationReadbackV0, UntrustedSafetyConfirmationReadbackV0, ValidationIdV0,
};
pub use error::{ValidationStoreErrorCodeV0, ValidationStoreErrorV0, ValidationStoreResultV0};
pub use finalization_history::{
    ConfirmedFinalizationHistoryAuditV0, ConfirmedFinalizationHistoryRecordV0,
    FinalizationHistoryAppendOutcomeV0, FinalizationHistoryScopeV0,
    SqliteNativeFinalizationHistoryV0, MAX_FINALIZATION_HISTORY_ENTRIES_V0,
};
pub use store::{
    AckTransitionOutcomeV0, AckedValidationV0, ActiveReplaySessionV0, AliasClosedReplayLinkKV0,
    CheckpointedReplayLinkV0, ConfirmedProposalValidationCheckpointFactsV0,
    ConfirmedProposalValidationTerminalAuditV0, ConfirmedReplayActivationReadyV0,
    ConfirmedReplayInventoryV0, CoreDeliveredReplayLinkDV0, DeliverTransitionOutcomeV0,
    DeliveredValidationV0, DurableReplayCompleteV0, DurableReplayLinkStageV0,
    DurableRequestBoundSafetyClosureFactV0, DurableValidationStageV0, ProposalValidationFactV0,
    ProposalValidationStoreScopeV0, ReplayActivationBindingV0, ReplayCheckpointReadRequestV0,
    ReplayCheckpointReadbackV0, ReplayLinkAliasCloseOutcomeV0, ReplayLinkCheckpointOutcomeV0,
    ReplayLinkDeliveryOutcomeV0, ReplayLinkFactsV0, ReplayLinkReservationOutcomeV0,
    ReplayLinkSafetyOutcomeV0, ReplaySessionFactsV0, ReplaySessionOpenOutcomeV0,
    ReplaySessionPlanV0, ReplaySessionPresenceV0, ReplaySessionResumeOutcomeV0,
    ReplaySourceHistoryReadRequestV0, ReplaySourceHistoryReadbackV0, ReservationOutcomeV0,
    ReservedReplayLinkPV0, ReservedValidationV0, SafetyClosedReplayLinkCV0,
    SqliteProposalValidationStoreV0, UntrustedReplayCheckpointReadbackV0,
    UntrustedReplaySourceHistoryReadbackV0,
};

#[cfg(test)]
mod tests;
