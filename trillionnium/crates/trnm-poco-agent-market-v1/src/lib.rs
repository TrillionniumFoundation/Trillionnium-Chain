//! Candidate-only PoCO-Agent + PoCO-Market local execution kernel.
//!
//! This crate implements a bounded candidate `AgentTransactionV1` outer wire,
//! strict Ed25519 authorization, a durable local SQLite kernel, and a bounded
//! proof-preserving terminal TaskV1 archive planner. It does not provide
//! accepted protocol authority, production identity/key lifecycle, a canonical
//! application JMT, Node integration, storage-deletion authority, or activation.
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

mod agent_transaction_wire_v1;
mod archive;
mod archive_verifier;
mod codec;
mod error;
mod store;
mod types;

pub use agent_transaction_wire_v1::{
    AgentTransactionV1, AGENT_TRANSACTION_GLOBAL_STATE_AUTHORITY_V1, AGENT_TRANSACTION_MAGIC_V1,
    AGENT_TRANSACTION_PRODUCTION_ACTIVATION_V1, AGENT_TRANSACTION_WIRE_ACCEPTED_V1,
    AGENT_TRANSACTION_WIRE_VERSION_V1, MAX_AGENT_TRANSACTION_COMMAND_BYTES_V1,
};
pub use archive::{
    plan_task_archive_pruning_v1, TaskArchiveBatchV1, TaskArchiveInclusionProofV1,
    TaskArchivePlanV1, TaskArchivePolicyV1, TaskArchiveSealV1, TerminalTaskArchiveRecordV1,
    MAX_TASK_ARCHIVE_BATCH_RECORDS_V1, MAX_TASK_ARCHIVE_PROOF_DEPTH_V1,
    TASK_ARCHIVE_SCHEMA_VERSION_V1,
};
pub use archive_verifier::{
    verify_task_archive_batch_v1, verify_task_archive_inclusion_v1,
};
pub use error::{AgentMarketErrorCodeV1, AgentMarketErrorV1, AgentMarketResultV1};
pub use store::{
    AgentMarketFreshReadbackV1, AgentMarketPreVotePreviewV1, AgentMarketStoreConfigV1,
    ConfirmedKernelReceiptV1, KernelExecutionOutcomeV1, PocoAgentMarketStoreV1,
};
pub use types::*;

#[cfg(test)]
mod tests;
