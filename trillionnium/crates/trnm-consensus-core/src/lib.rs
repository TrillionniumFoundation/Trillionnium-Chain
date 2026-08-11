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

extern crate alloc;

mod block_tree;
mod core;
mod error;
mod model;

pub use crate::core::{leader_for, Core};
pub use crate::error::{CoreError, Result};
pub use crate::model::{
    BarrierId, ClaimedPayloadValidationRequestV0, CoreConfig, DuplicatePayloadValidationRequestV0,
    DurableFinalizationV0, DurablePayloadValidationCompletionV0,
    DurablePayloadValidationObligationV0, DurablePayloadValidationResultV1,
    DurableValidatedBlockCommitmentsV1, Effect, FinalizedTip, Input, InvalidPayloadReference,
    OutboundMessage, PayloadTerminalFact, PayloadTerminalResult, PayloadValidationParentV0,
    PayloadValidationRequest, PayloadValidationResult, PayloadValidationRouteV0,
    PendingStandaloneQcSync, PendingTcHighQcSync, SafetyHalt, SafetyState, SignId, SignIntent,
    SignKind, ValidationId, SAFETY_STATE_SCHEMA_VERSION,
};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
