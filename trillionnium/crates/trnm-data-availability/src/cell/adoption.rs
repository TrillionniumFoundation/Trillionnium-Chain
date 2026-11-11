//! Node-local model selection, separate from candidate publication and release
//! authorization. Only a local operator/policy owner supplies this API's policy
//! and decisions. Neither peer input nor an evidence digest authenticates that
//! owner, an evaluator, a chain inclusion, or a claimed improvement.
//!
//! The fresh TCA1 SQLite namespace keeps candidate observations separate from
//! an append-only decision journal. Adopt/defer/retain/rollback all use a new
//! monotone local revision; chain reorganization never rewinds that journal.
//! Recovery requires a separately held minimum snapshot. Copying the database
//! and that snapshot together does not establish rollback resistance.
//! An independently approved complete version may bootstrap the owner even
//! when its earlier lineage is nonempty. That history stays committed, but
//! this owner does not claim to have independently reviewed the anchor's past.
//!
//! Selection is not FinalUse or a release-key grant. The ordinary execution
//! owner must retain its current authorization, revocation and resource guard.
//! The selected-use callback only excludes cooperating local decision writers;
//! it cannot recall copied bytes or preempt consumer computation.

mod files;
mod store;
mod types;

pub use store::CellAdoptionOwnerV1;
pub use types::{
    CellAdoptionActionV1, CellAdoptionPolicyV1, CellAdoptionReceiptV1, CellAdoptionSnapshotV1,
    CellCandidateEvidenceV1, CellCandidateObservationV1, CellProposalRetentionReceiptV1,
    MAX_CELL_ADOPTION_CANDIDATES_V1, MAX_CELL_ADOPTION_DECISIONS_V1,
};

#[cfg(test)]
mod tests;
