//! Candidate-only global PoCO v1 execution owner for one pre-vote block.
//!
//! This crate closes a deliberately bounded process cut: a locally certified
//! DA batch is freshly authenticated and completely retrieved, all included
//! operations are previewed against the exact durable Agent/Market,
//! Verify/Challenge, MVCC/Fee and Consumption/Settlement parents, and the
//! resulting candidate composite root is durably joined to a monotonic
//! whole-node validation sequence before a vote-eligibility carrier can exist.
//! Once independent Order finality names that exact candidate, the prepared
//! intent drives exact-replayable application into all five source planes and
//! issues the linear terminal owner only after their fresh readbacks agree.
//!
//! The candidate composite root is **not** the draft protocol application JMT
//! root or an Order `post_state_root`.  The batch wire is **not** the frozen
//! `AgentTransactionV1` wire. A second, strictly local boundary can persist one
//! externally authenticated terminal-facts cut and final execution commitment
//! in the same SQLite successor CAS. Its sole normal-build issuer consumes the
//! exact prepared carrier plus verified Order finality; pre-vote facts cannot
//! masquerade as a Node permit or Order/state-membership proof. There is no
//! multi-level speculative overlay, state sync, Node process wiring,
//! activation or G2 truth promotion in this crate.
//!
//! The manifest-bound v2 path below never accepts a containing Order block ID
//! before preview. T0-A commits exact typed commands and manifest/DA/source
//! facts; T0-B fully retrieves the certified v2 batch, adapts the existing
//! five-source read-only previews into candidate-local receipts/roots, and
//! exact-joins all eight later-derived Order roots. It still does not promote
//! the legacy v1 preview, persist state, or issue vote eligibility.
//!
//! The vote-eligibility carrier cannot be forged or cloned:
//!
//! ```compile_fail
//! use trnm_poco_global_execution_v1::PreVoteExecutionReadyV1;
//! let _forged = PreVoteExecutionReadyV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_global_execution_v1::PreVoteExecutionReadyV1;
//! fn duplicate(value: PreVoteExecutionReadyV1) { let _copy = value.clone(); }
//! ```
//!
//! ```compile_fail
//! use trnm_poco_global_execution_v1::WholeNodeFinalizationOwnerV1;
//! let _forged = WholeNodeFinalizationOwnerV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_global_execution_v1::WholeNodeFinalizationOwnerV1;
//! fn duplicate(value: WholeNodeFinalizationOwnerV1) { let _copy = value.clone(); }
//! ```

#![forbid(unsafe_code)]

mod codec;
mod error;
mod manifest_bound_v2;
mod store;
mod types;

pub use error::{GlobalExecutionErrorCodeV1, GlobalExecutionErrorV1, GlobalExecutionResultV1};
pub use manifest_bound_v2::{
    G2CandidateLocalExecutionIdV2, G2CandidateLocalFinalizeJoinV2, G2CandidateLocalPlaneRootsV2,
    G2CandidateLocalPreviewBindingV2, G2CandidateLocalReceiptBodyV2,
    G2CandidateLocalReceiptPlaneV2, G2CandidateLocalReceiptV2, ManifestBoundFivePlanePreviewV2,
    ManifestBoundGlobalExecutionBatchV2, ManifestBoundGlobalExecutionInputV2,
};
pub use store::{
    GlobalExecutionCheckpointFactsV1, GlobalExecutionSourcesV1, PocoGlobalExecutionStoreV1,
    PreVoteExecutionReadyV1, WholeNodeFinalizationOwnerV1, WholeNodeFinalizedV1,
};
pub use types::{
    CandidateCompositeCommitmentV1, CandidateExecutionContextV1, GlobalExecutionBatchV1, Hash32V1,
    PreVoteProposalV1, WholeNodeFinalExecutionCommitmentV1,
};

#[cfg(test)]
mod tests;
