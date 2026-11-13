//! Thin standalone adapter for the exact M01 complete-relation source.
//!
//! Isolating it avoids importing unrelated Chain signature, storage or node
//! dependencies into the proof image. This crate creates no VerifiedWork.
mod parameters;
pub use parameters::{Hash, CELLS, N, PROOF_BYTES, Q, R};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkError {
    Length,
    Version,
    Field,
    Task,
    Transcript,
    Product,
    Target,
    NoiseBudget,
}

// This is the actual source reviewed and tested beside the native W1 kernels;
// there is no copied arithmetic, alternative trace or smaller work profile.
#[path = "../../../../src/pon_work/full_relation.rs"]
pub mod full_relation;
