//! Pre-certificate successor checkpoint verification under retained authority.
use super::*;
use crate::{StrictSameVersionEpochActivationAuthorityV0, StrictSuccessorEpochActivationErrorV1};
use core::fmt;
use trnm_consensus_types::{
    decode_epoch_runtime_finality_proof_v1_exact_with_budget, Cev0AdmissionBudgetV0, DecodeError,
};

#[derive(Debug)]
#[non_exhaustive]
pub enum StrictSuccessorPreHandoffErrorV1 {
    Invalid(&'static str),
    Decode(DecodeError),
    Consensus(ValidationError),
    Ancestry(StrictSuccessorEpochActivationErrorV1),
}

impl fmt::Display for StrictSuccessorPreHandoffErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "successor pre-handoff: {reason}"),
            Self::Decode(error) => write!(f, "successor pre-handoff decoding: {error}"),
            Self::Consensus(error) => write!(f, "successor pre-handoff consensus: {error}"),
            Self::Ancestry(error) => write!(f, "successor pre-handoff ancestry: {error}"),
        }
    }
}
impl core::error::Error for StrictSuccessorPreHandoffErrorV1 {}

/// Verifies a successor checkpoint before either handoff role signs.
///
/// The complete retained ancestry includes the predecessor's terminal old seal
/// and the actual new checkpoint parent. Only the independently strict
/// predecessor supplies the outgoing configuration and synthetic anchor. No
/// handoff certificate is required or manufactured. The result establishes no
/// application durability, deterministic selection or signer custody.
///
/// The caller's meter is unchanged on structural refusal; once strict key or
/// signature verification starts, its one reserved proof charge is retained
/// even on failure. This never reparses or recharges the predecessor evidence.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn decode_verify_successor_pre_handoff_context_strict_v1(
    predecessor: &StrictSameVersionEpochActivationAuthorityV0,
    retained_ancestry: &[BlockHeader],
    raw_checkpoint_finality: &[u8],
    commitment: &NextEpochCommitmentV0,
    descriptor: &HandoffDescriptorV0,
    new_set: &ValidatorSet,
    new_parameters: &ConsensusParametersV0,
    budget: &mut Cev0AdmissionBudgetV0,
) -> core::result::Result<StrictPreHandoffContextV1, StrictSuccessorPreHandoffErrorV1> {
    use StrictSuccessorPreHandoffErrorV1 as Error;
    if retained_ancestry.first() != Some(predecessor.terminal_old_header()) {
        return Err(Error::Invalid(
            "ancestry must start at predecessor terminal seal",
        ));
    }
    crate::epoch_transition::validate_successor_ancestry_links_v1(predecessor, retained_ancestry)
        .map_err(Error::Ancestry)?;
    let parent = retained_ancestry
        .last()
        .ok_or(Error::Invalid("missing checkpoint parent"))?;
    let old_set = predecessor.new_validator_set();
    let old_parameters = predecessor.new_consensus_parameters();
    commitment
        .validate_same_version_context(old_set, old_parameters, new_set, new_parameters)
        .map_err(Error::Consensus)?;

    // Typed configuration roots have intrinsic constructor bounds. Screen the
    // complete transcript before allocating or parsing the untrusted proof.
    let roots = [
        commitment.try_cev0_bytes().map_err(Error::Consensus)?,
        descriptor.try_cev0_bytes().map_err(Error::Consensus)?,
        old_set.try_cev0_bytes().map_err(Error::Consensus)?,
        old_parameters.canonical_bytes(),
        new_set.try_cev0_bytes().map_err(Error::Consensus)?,
        new_parameters.canonical_bytes(),
    ];
    let mut aggregate = raw_checkpoint_finality.len();
    let mut binding = Sha256::new();
    binding.update(b"trnm.poco-bft.successor-pre-handoff-context.v1");
    binding.update(predecessor.binding_ref().as_bytes());
    binding.update((retained_ancestry.len() as u64).to_le_bytes());
    for header in retained_ancestry {
        let bytes = header.try_cev0_bytes().map_err(Error::Consensus)?;
        aggregate = aggregate
            .checked_add(bytes.len())
            .ok_or(Error::Invalid("byte overflow"))?;
        frame(&mut binding, &bytes);
    }
    for root in &roots {
        aggregate = aggregate
            .checked_add(root.len())
            .ok_or(Error::Invalid("byte overflow"))?;
    }
    budget.admit_root_bytes(aggregate).map_err(Error::Decode)?;
    frame(&mut binding, raw_checkpoint_finality);
    for root in &roots {
        frame(&mut binding, root);
    }
    let mut staged = *budget;
    let proof = decode_epoch_runtime_finality_proof_v1_exact_with_budget(
        raw_checkpoint_finality,
        predecessor.runtime_data_v1(),
        parent.timestamp_ms(),
        &mut staged,
    )
    .map_err(Error::Decode)?;
    validate_checkpoint_parent_header_v0(&proof, parent)
        .map_err(|_| Error::Invalid("checkpoint parent differs from retained ancestry"))?;
    proof
        .validate_checkpoint_two_seal_structure_v1(old_set, old_parameters, commitment)
        .map_err(Error::Consensus)?;
    let expected = expected_descriptor_v1(
        &proof,
        commitment,
        old_set,
        old_parameters,
        new_set,
        new_parameters,
    )
    .map_err(Error::Consensus)?;
    if descriptor != &expected {
        return Err(Error::Invalid("descriptor differs from checkpoint context"));
    }

    // Publish the one complete work reservation before any strict crypto. A
    // canonical but bad nested signature must not refund the caller's work.
    *budget = staged;
    validate_validator_set_strict_ed25519_v0(old_set).map_err(Error::Consensus)?;
    validate_validator_set_strict_ed25519_v0(new_set).map_err(Error::Consensus)?;
    crate::epoch_runtime_v1::verify_epoch_finality_precharged_v1(
        predecessor,
        &proof,
        parent.timestamp_ms(),
    )
    .map_err(Error::Consensus)?;
    Ok(StrictPreHandoffContextV1 {
        descriptor: expected,
        old_validator_set: old_set.clone(),
        new_validator_set: new_set.clone(),
        old_consensus_parameters: *old_parameters,
        new_consensus_parameters: *new_parameters,
        checkpoint_finality_proof_id: proof.id(),
        checkpoint_parent_block_id: parent.id(),
        checkpoint_parent_timestamp_ms: parent.timestamp_ms(),
        next_epoch_commitment_digest: commitment.id(),
        binding_ref: binding.finalize().into(),
    })
}

fn frame(binding: &mut Sha256, bytes: &[u8]) {
    binding.update((bytes.len() as u64).to_le_bytes());
    binding.update(bytes);
}
