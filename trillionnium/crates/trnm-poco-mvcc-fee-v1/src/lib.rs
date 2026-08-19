//! Candidate-only deterministic object-MVCC and fee-delta kernel.
//!
//! This crate is deliberately non-normative. It does not implement global
//! CEV1 transaction authorization, a production state tree, Order proof
//! authority, a real parallel worker pool, Node integration, or activation.
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
