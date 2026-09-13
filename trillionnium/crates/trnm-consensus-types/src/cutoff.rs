use crate::{
    BlockId, BlockKind, CertificateId, ConsensusParametersV0, Epoch, EpochGeometryV0,
    FinalityProofV0, Height, Result, SignatureVerifier, StateRoot, ValidationError, ValidatorSet,
};

/// Narrow evidence that the exact protocol-derived snapshot cutoff header was
/// accepted by the complete ordinary finality verifier.
///
/// This token authenticates only the header/finality relation. It is not a JMT
/// proof, snapshot namespace projection, runtime execution witness, or epoch
/// transition authorization. The verifier implementation itself is not
/// attested; production callers must supply `StrictEd25519Verifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedFinalizedCutoffHeaderV0 {
    proof_id: CertificateId,
    epoch: Epoch,
    cutoff_height: Height,
    cutoff_block_id: BlockId,
    cutoff_state_root: StateRoot,
}

impl AuthenticatedFinalizedCutoffHeaderV0 {
    pub const fn proof_id(&self) -> CertificateId {
        self.proof_id
    }
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub const fn cutoff_height(&self) -> Height {
        self.cutoff_height
    }
    pub const fn cutoff_block_id(&self) -> BlockId {
        self.cutoff_block_id
    }
    pub const fn cutoff_state_root(&self) -> StateRoot {
        self.cutoff_state_root
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_finalized_cutoff_header_v0<V: SignatureVerifier>(
    proof: &FinalityProofV0,
    active_validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    authenticated_cutoff_parent_timestamp_ms: u64,
    verifier: &V,
) -> Result<AuthenticatedFinalizedCutoffHeaderV0> {
    active_validator_set.validate_against_parameters(consensus_parameters)?;
    proof.verify(
        active_validator_set,
        None,
        consensus_parameters,
        authenticated_cutoff_parent_timestamp_ms,
        verifier,
    )?;
    let geometry = EpochGeometryV0::new(active_validator_set.epoch(), consensus_parameters)?;
    let cutoff = geometry
        .checkpoint_height()
        .get()
        .checked_sub(consensus_parameters.snapshot_lead_blocks())
        .map(Height::new)
        .ok_or(ValidationError::ArithmeticOverflow(
            "snapshot cutoff height",
        ))?;
    let header = proof.finalized_block().header();
    if header.height() != cutoff {
        return Err(ValidationError::InvalidFinalityProof(
            "finalized header is not the exact snapshot cutoff",
        ));
    }
    if header.block_kind() != BlockKind::Regular {
        return Err(ValidationError::InvalidFinalityProof(
            "snapshot cutoff header must be an ordinary block",
        ));
    }
    Ok(AuthenticatedFinalizedCutoffHeaderV0 {
        proof_id: proof.id(),
        epoch: active_validator_set.epoch(),
        cutoff_height: cutoff,
        cutoff_block_id: header.id(),
        cutoff_state_root: header.state_root(),
    })
}
