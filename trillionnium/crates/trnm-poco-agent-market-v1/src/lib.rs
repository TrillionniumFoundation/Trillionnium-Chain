//! Candidate-only PoCO-Agent + PoCO-Market local execution kernel.
//!
//! This crate is deliberately non-normative. It does not implement the global
//! `AgentTransactionV1` wire, identity/key lifecycle, a state tree, Node
//! integration, protocol activation, or production signing authority.
//!
//! A durable transition receipt is store-bound and cannot be forged or copied
//! into another store authority:
//!
//! ```compile_fail
//! use trnm_poco_agent_market_v1::ConfirmedKernelReceiptV1;
//! let _forged = ConfirmedKernelReceiptV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_agent_market_v1::ConfirmedKernelReceiptV1;
//! fn copy_receipt(receipt: ConfirmedKernelReceiptV1) {
//!     let _copy = receipt.clone();
//! }
//! ```

#![forbid(unsafe_code)]

mod codec;
mod error;
mod store;
mod types;

pub use error::{AgentMarketErrorCodeV1, AgentMarketErrorV1, AgentMarketResultV1};
pub use store::{
    AgentMarketFreshReadbackV1, AgentMarketPreVotePreviewV1, AgentMarketStoreConfigV1,
    ConfirmedKernelReceiptV1, KernelExecutionOutcomeV1, PocoAgentMarketStoreV1,
};
pub use types::*;

#[cfg(test)]
mod tests;
