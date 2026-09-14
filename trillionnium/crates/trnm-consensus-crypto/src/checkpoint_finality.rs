//! Strict pre-certificate checkpoint/two-seal verification.
//!
//! This boundary needs no joint handoff certificate: that certificate is a
//! later product of the two role-specific signer paths. Inputs for the sets,
//! parameters, commitment, expected checkpoint and parent must come from the
//! caller's authenticated context. This module does not prove their state
//! provenance, commit an application, permit a signature or activate an epoch.

use core::fmt;
use trnm_consensus_types::{
    decode_checkpoint_finality_proof_v0_exact_with_budget, validate_checkpoint_parent_header_v0,
    BlockHeader, Cev0AdmissionBudgetV0, CheckpointTwoSealKernelV0, ConsensusParametersV0,
    DecodeError, FinalityProofV0, NextEpochCommitmentV0, ValidationError, ValidatorSet,
};

use crate::{validate_validator_set_strict_ed25519_v0, StrictEd25519Verifier};

/// Only strict verification can construct this result. Its kernel may not be
/// substituted for application commitment, signing custody or an epoch anchor.
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictCheckpointFinalityV0;
/// fn duplicate(value: &StrictCheckpointFinalityV0) -> StrictCheckpointFinalityV0 {
///     (*value).clone()
/// }
/// ```
#[derive(Debug)]
pub struct StrictCheckpointFinalityV0 {
    proof: FinalityProofV0,
    kernel: CheckpointTwoSealKernelV0,
}

impl StrictCheckpointFinalityV0 {
    pub const fn proof(&self) -> &FinalityProofV0 {
        &self.proof
    }

    pub const fn kernel(&self) -> &CheckpointTwoSealKernelV0 {
        &self.kernel
    }
}

/// Local API errors; no new wire error enum or protocol byte layout.
#[derive(Debug)]
pub enum StrictCheckpointFinalityErrorV0 {
    TargetMismatch,
    ParentMismatch,
    Decode(DecodeError),
    Consensus(ValidationError),
}

impl fmt::Display for StrictCheckpointFinalityErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetMismatch => f.write_str("checkpoint proof targets another exact header"),
            Self::ParentMismatch => f.write_str("checkpoint proof has another authenticated parent"),
            Self::Decode(error) => write!(f, "checkpoint proof decode: {error}"),
            Self::Consensus(error) => write!(f, "checkpoint strict verification: {error}"),
        }
    }
}

impl core::error::Error for StrictCheckpointFinalityErrorV0 {}

/// Decode and reserve all proposal/QC/TC signature work before strict checking.
/// A later binding or signature failure does not refund admitted work. A
/// structural rejection before reservation leaves that work allowance intact.
/// The returned result authenticates exactly one old-set checkpoint/two-seal
/// proof under the supplied, separately validated old/new configuration.
#[allow(clippy::too_many_arguments)]
pub fn decode_verify_checkpoint_finality_strict_v0(
    bytes: &[u8],
    trusted_old_set: &ValidatorSet,
    trusted_old_parameters: &ConsensusParametersV0,
    next_epoch_commitment: &NextEpochCommitmentV0,
    trusted_new_set: &ValidatorSet,
    trusted_new_parameters: &ConsensusParametersV0,
    expected_checkpoint: &BlockHeader,
    authenticated_parent: &BlockHeader,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<StrictCheckpointFinalityV0, StrictCheckpointFinalityErrorV0> {
    budget
        .admit_root_bytes(bytes.len())
        .map_err(StrictCheckpointFinalityErrorV0::Decode)?;
    next_epoch_commitment
        .validate_same_version_context(
            trusted_old_set,
            trusted_old_parameters,
            trusted_new_set,
            trusted_new_parameters,
        )
        .map_err(StrictCheckpointFinalityErrorV0::Consensus)?;
    validate_validator_set_strict_ed25519_v0(trusted_old_set)
        .map_err(StrictCheckpointFinalityErrorV0::Consensus)?;
    validate_validator_set_strict_ed25519_v0(trusted_new_set)
        .map_err(StrictCheckpointFinalityErrorV0::Consensus)?;
    let proof = decode_checkpoint_finality_proof_v0_exact_with_budget(
        bytes,
        trusted_old_set,
        trusted_old_parameters,
        next_epoch_commitment,
        authenticated_parent.timestamp_ms(),
        budget,
    )
    .map_err(StrictCheckpointFinalityErrorV0::Decode)?;
    if proof.finalized_block().header() != expected_checkpoint {
        return Err(StrictCheckpointFinalityErrorV0::TargetMismatch);
    }
    validate_checkpoint_parent_header_v0(&proof, authenticated_parent)
        .map_err(|_| StrictCheckpointFinalityErrorV0::ParentMismatch)?;
    let kernel = proof
        .verify_checkpoint_two_seal_kernel(
            trusted_old_set,
            trusted_old_parameters,
            next_epoch_commitment,
            authenticated_parent.timestamp_ms(),
            &StrictEd25519Verifier,
        )
        .map_err(StrictCheckpointFinalityErrorV0::Consensus)?;
    Ok(StrictCheckpointFinalityV0 { proof, kernel })
}
