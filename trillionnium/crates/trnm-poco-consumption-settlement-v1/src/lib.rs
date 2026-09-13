//! Candidate-only bilateral consumption-rollup and conserved-settlement kernel.
//!
//! The bounded kernel covers one asset, one final-valid result, and exactly one
//! rollup. Its bootstrap and order-finality facts are local verifier trust
//! inputs, not consensus objects or cross-kernel authority.
//!
//! Durable confirmations are store-bound, linear proof carriers:
//!
//! ```compile_fail
//! use trnm_poco_consumption_settlement_v1::ConfirmedConsumptionTransitionV1;
//! let _forged = ConfirmedConsumptionTransitionV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_consumption_settlement_v1::ConfirmedConsumptionTransitionV1;
//! fn duplicate(value: ConfirmedConsumptionTransitionV1) { let _copy = value.clone(); }
//! ```

#![forbid(unsafe_code)]

mod codec;
mod engine;
mod error;
mod store;
mod types;

pub use engine::{consumption_receipt_id_v1, consumption_rollup_id_v1, settlement_policy_hash_v1};
pub use error::{
    ConsumptionSettlementErrorCodeV1, ConsumptionSettlementErrorV1, ConsumptionSettlementResultV1,
};
pub use store::{
    ConfirmedConsumptionTransitionV1, ConsumptionSettlementFreshReadbackV1,
    ConsumptionSettlementOutcomeV1, ConsumptionSettlementPreVotePreviewV1,
    ConsumptionSettlementStoreConfigV1, ConsumptionSettlementStoreV1,
};
pub use types::*;

#[cfg(test)]
mod tests;
