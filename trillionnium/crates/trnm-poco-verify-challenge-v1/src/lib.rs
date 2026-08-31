//! Candidate-only PoCO-Compute Verify/Challenge kernel.
//!
//! This crate is deliberately bounded and non-normative. Its durable receipt
//! carrier is store-owned and cannot be forged or cloned by downstream code.
//!
//! ```compile_fail
//! use trnm_poco_verify_challenge_v1::ConfirmedVerifyReceiptV1;
//! let _forged = ConfirmedVerifyReceiptV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_verify_challenge_v1::ConfirmedVerifyReceiptV1;
//! fn duplicate(value: ConfirmedVerifyReceiptV1) { let _copy = value.clone(); }
//! ```

#![forbid(unsafe_code)]

mod codec;
mod error;
#[rustfmt::skip]
pub mod profile_registry_v1;
mod store;
mod types;

pub use error::{VerifyChallengeErrorCodeV1, VerifyChallengeErrorV1, VerifyChallengeResultV1};
pub use store::{
    ConfirmedVerifyReceiptV1, VerifyChallengeExecutionOutcomeV1, VerifyChallengeFreshReadbackV1,
    VerifyChallengePreVotePreviewV1, VerifyChallengeStoreConfigV1, VerifyChallengeStoreV1,
};
pub use types::*;

#[cfg(test)]
mod tests;
