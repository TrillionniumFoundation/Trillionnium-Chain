//! M01: strict pre-certificate checkpoint context for both handoff roles.
//!
//! This verifier deliberately needs no handoff signature. Application commit
//! readback and durable signer custody remain separate prerequisites.

use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    validate_checkpoint_parent_header_v0, BlockHeader, BlockId, CertificateId,
    ConsensusParametersV0, FinalityProofV0, HandoffDescriptorV0, HandoffDescriptorV0Fields,
    NextEpochCommitmentHash, NextEpochCommitmentV0, Result, ValidationError, ValidatorSet, View,
};

use crate::{validate_validator_set_strict_ed25519_v0, StrictEd25519Verifier};

/// Opaque cryptographic context shared by old and new role admissions.
///
/// This is neither proof of application durability nor epoch activation. A
/// persisted binding cannot recreate it without repeating strict verification.
#[derive(Debug, PartialEq, Eq)]
pub struct StrictPreHandoffContextV1 {
    descriptor: HandoffDescriptorV0,
    old_validator_set: ValidatorSet,
    new_validator_set: ValidatorSet,
    old_consensus_parameters: ConsensusParametersV0,
    new_consensus_parameters: ConsensusParametersV0,
    checkpoint_finality_proof_id: CertificateId,
    checkpoint_parent_block_id: BlockId,
    checkpoint_parent_timestamp_ms: u64,
    next_epoch_commitment_digest: NextEpochCommitmentHash,
    binding_ref: [u8; 32],
}

impl StrictPreHandoffContextV1 {
    pub const fn descriptor(&self) -> &HandoffDescriptorV0 {
        &self.descriptor
    }
    pub const fn old_validator_set(&self) -> &ValidatorSet {
        &self.old_validator_set
    }
    pub const fn new_validator_set(&self) -> &ValidatorSet {
        &self.new_validator_set
    }
    pub const fn old_consensus_parameters(&self) -> &ConsensusParametersV0 {
        &self.old_consensus_parameters
    }
    pub const fn new_consensus_parameters(&self) -> &ConsensusParametersV0 {
        &self.new_consensus_parameters
    }
    pub const fn checkpoint_finality_proof_id(&self) -> CertificateId {
        self.checkpoint_finality_proof_id
    }
    pub const fn checkpoint_parent_block_id(&self) -> BlockId {
        self.checkpoint_parent_block_id
    }
    pub const fn checkpoint_parent_timestamp_ms(&self) -> u64 {
        self.checkpoint_parent_timestamp_ms
    }
    pub const fn next_epoch_commitment_digest(&self) -> NextEpochCommitmentHash {
        self.next_epoch_commitment_digest
    }
    pub const fn binding_ref(&self) -> [u8; 32] {
        self.binding_ref
    }
}

/// Verifies a proposed handoff descriptor before collecting either quorum.
///
/// The caller supplies independently trusted old context; the checkpoint's
/// signed commitment authenticates the new context. Every consensus key is
/// strictly admitted, including members absent from the supplied old QCs.
/// Snapshot selection/PoP provenance must additionally be joined by the native
/// application checkpoint receipt; a commitment is not that execution proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_pre_handoff_context_strict_v1(
    proof: &FinalityProofV0,
    commitment: &NextEpochCommitmentV0,
    descriptor: &HandoffDescriptorV0,
    old_set: &ValidatorSet,
    old_parameters: &ConsensusParametersV0,
    new_set: &ValidatorSet,
    new_parameters: &ConsensusParametersV0,
    authenticated_parent: &BlockHeader,
) -> Result<StrictPreHandoffContextV1> {
    validate_validator_set_strict_ed25519_v0(old_set)?;
    validate_validator_set_strict_ed25519_v0(new_set)?;
    commitment.validate_same_version_context(old_set, old_parameters, new_set, new_parameters)?;
    validate_checkpoint_parent_header_v0(proof, authenticated_parent).map_err(|_| {
        ValidationError::InvalidEpochTransition("checkpoint parent differs from signed ancestry")
    })?;
    let checkpoint = proof.verify_checkpoint_two_seal_kernel(
        old_set,
        old_parameters,
        commitment,
        authenticated_parent.timestamp_ms(),
        &StrictEd25519Verifier,
    )?;
    // Construct the complete expected descriptor, rather than checking only a
    // subset of fields (especially role versions, views and terminal QC).
    let expected = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
        genesis_hash: old_set.genesis_hash(),
        chain_id: old_set.chain_id(),
        old_epoch: old_set.epoch(),
        new_epoch: new_set.epoch(),
        old_protocol_version: old_set.protocol_version(),
        new_protocol_version: new_set.protocol_version(),
        old_validator_set_hash: old_set.id(),
        new_validator_set_hash: new_set.id(),
        old_consensus_parameters_hash: old_parameters.hash(),
        new_consensus_parameters_hash: new_parameters.hash(),
        checkpoint_height: checkpoint.checkpoint_height(),
        checkpoint_block_id: checkpoint.checkpoint_block_id(),
        checkpoint_state_root: checkpoint.checkpoint_state_root(),
        next_epoch_commitment_digest: checkpoint.next_epoch_commitment_digest(),
        terminal_old_height: checkpoint.terminal_old_height(),
        terminal_old_block_id: checkpoint.terminal_old_block_id(),
        terminal_old_qc_digest: checkpoint.terminal_old_qc_digest(),
        terminal_old_view: proof.grandchild().header().view(),
        activation_height: checkpoint.activation_height(),
        initial_new_view: View::new(1),
    })?;
    if descriptor != &expected {
        return Err(ValidationError::InvalidEpochTransition(
            "handoff descriptor differs from strictly verified checkpoint context",
        ));
    }
    let mut binding = Sha256::new();
    binding.update(b"trnm.poco-bft.pre-handoff-context.v1");
    // All components are fixed-width hashes of exact canonical preimages.
    for hash in [
        checkpoint.proof_id().as_bytes(),
        descriptor.id().as_bytes(),
        commitment.id().as_bytes(),
        old_set.id().as_bytes(),
        new_set.id().as_bytes(),
        old_parameters.hash().as_bytes(),
        new_parameters.hash().as_bytes(),
        authenticated_parent.id().as_bytes(),
    ] {
        binding.update(hash);
    }
    Ok(StrictPreHandoffContextV1 {
        descriptor: expected,
        old_validator_set: old_set.clone(),
        new_validator_set: new_set.clone(),
        old_consensus_parameters: *old_parameters,
        new_consensus_parameters: *new_parameters,
        checkpoint_finality_proof_id: checkpoint.proof_id(),
        checkpoint_parent_block_id: authenticated_parent.id(),
        checkpoint_parent_timestamp_ms: authenticated_parent.timestamp_ms(),
        next_epoch_commitment_digest: commitment.id(),
        binding_ref: binding.finalize().into(),
    })
}
