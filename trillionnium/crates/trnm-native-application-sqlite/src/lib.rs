#![forbid(unsafe_code)]
//! Durable proposal-validation journal owned by the native application lane.
//!
//! This crate is deliberately narrower than an application engine. It stores
//! exact proposal-validation bindings, complete canonical
//! `NativeExecutedBlockV0` artifacts, and the ordered `P` -> `D` ->
//! request-bound, `C`-shaped `K` recovery journal. The `P` capability is released only
//! after an atomic write and fresh-connection exact artifact readback. It does
//! not execute transactions, advance the committed
//! application head, sign, broadcast, or decide consensus validity.

mod binding;
mod error;
mod store;

pub use binding::{
    CoreDeliveryConfirmationV0, NonZeroDigestV0, ProposalRouteV0, ProposalValidationBindingV0,
    ProposalValidationOwnerIdV0, RequestBoundSafetyConfirmationV0, SafetyConfirmationReadRequestV0,
    SafetyConfirmationReadbackV0, UntrustedSafetyConfirmationReadbackV0, ValidationIdV0,
};
pub use error::{ValidationStoreErrorCodeV0, ValidationStoreErrorV0, ValidationStoreResultV0};
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
