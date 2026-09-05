//! Candidate-only deterministic object-MVCC and fee-delta kernel.
//!
//! The crate now contains a bounded in-process worker pool whose workers
//! speculate against one immutable parent snapshot. Canonical transaction-index
//! commit and deterministic conflict re-execution keep state, receipt and fee
//! roots invariant across worker counts. This is still candidate-only: it does
//! not implement global CEV1 authorization, a production state tree, Order
//! proof authority, Node runtime activation, settlement movement or PoCO
//! weight.
//!
//! A durable block confirmation is store-bound and cannot be forged or cloned:
//!
//! ```compile_fail
//! use trnm_poco_mvcc_fee_v1::ConfirmedMvccBlockV1;
//! let _forged = ConfirmedMvccBlockV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_mvcc_fee_v1::ConfirmedMvccBlockV1;
//! fn copy(value: ConfirmedMvccBlockV1) { let _copy = value.clone(); }
//! ```

#![forbid(unsafe_code)]

mod codec;
pub mod deterministic_parallel_v1;
mod engine;
mod error;
mod store;
mod types;

pub use engine::{derive_block_id_v1, derive_state_root_v1, derive_transaction_id_v1};
pub use error::{MvccFeeErrorCodeV1, MvccFeeErrorV1, MvccFeeResultV1};
pub use store::{
    ConfirmedMvccBlockV1, MvccBlockOutcomeV1, MvccFeeFreshReadbackV1, MvccFeePreVotePreviewV1,
    MvccFeeStoreV1,
};
pub use types::*;

#[cfg(test)]
mod tests;
