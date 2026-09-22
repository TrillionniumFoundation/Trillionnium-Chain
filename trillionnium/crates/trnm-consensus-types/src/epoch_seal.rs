//! Exact outgoing-epoch seal semantics. No signature or application authority.
use crate::{
    ApplicationPayloadV0, BlockHeader, BlockKind, ConsensusParametersV0, EpochGeometryV0,
    EvidenceRoot, Height, OrderedRootV0, PayloadDigest, ReceiptsRoot, Result, RootKind,
    SignedProposalV0, ValidationError,
};
use alloc::vec::Vec;

/// All immutable seal semantics, shared by live admission and recovery. The
/// caller separately verifies signature/QC/TC and proves application Valid for C.
pub fn validate_empty_epoch_seal_v1(
    proposal: &SignedProposalV0,
    parent: &BlockHeader,
    parameters: &ConsensusParametersV0,
) -> Result<()> {
    let block = proposal.block();
    let header = block.header();
    let geometry = EpochGeometryV0::new(header.epoch(), parameters)?;
    let expected_parent = match header.block_kind() {
        BlockKind::EpochSeal1 if header.height() == geometry.seal_1_height() => {
            BlockKind::EpochCheckpoint
        }
        BlockKind::EpochSeal2 if header.height() == geometry.seal_2_height() => {
            BlockKind::EpochSeal1
        }
        _ => {
            return Err(ValidationError::InvalidEpochTransition(
                "not the scheduled epoch seal",
            ))
        }
    };
    if parent.block_kind() != expected_parent
        || parent.epoch() != header.epoch()
        || parent.validator_set_id() != header.validator_set_id()
        || parent.consensus_parameters_hash() != header.consensus_parameters_hash()
        || header.parent_id() != parent.id()
        || header.height() != parent.height().checked_next()?
        || header.state_root() != parent.state_root()
        || header.next_epoch_commitment_hash().is_none()
        || header.next_epoch_commitment_hash() != parent.next_epoch_commitment_hash()
        || block.application_payload()
            != ApplicationPayloadV0::new(Vec::new())?
                .try_cev0_bytes()?
                .as_slice()
        || !block.evidence_objects().is_empty()
        || header.payload_root()
            != PayloadDigest::new(
                OrderedRootV0::from_items::<&[u8]>(RootKind::Payload, &[])?.digest(),
            )
        || header.receipts_root()
            != ReceiptsRoot::new(
                OrderedRootV0::from_items::<&[u8]>(RootKind::Receipts, &[])?.digest(),
            )
        || header.evidence_root()
            != EvidenceRoot::new(
                OrderedRootV0::from_items::<&[u8]>(RootKind::Evidence, &[])?.digest(),
            )
        || block.logical_block_size() > parameters.max_block_bytes() as usize
    {
        return Err(ValidationError::InvalidEpochTransition(
            "seal does not preserve the exact checkpoint state and empty body",
        ));
    }
    let justify = proposal.witness().justify_qc().qc_ref();
    if justify.block_id() != parent.id()
        || justify.height() != parent.height()
        || justify.view() != parent.view()
        || justify.epoch() != parent.epoch()
        || justify.validator_set_id() != parent.validator_set_id()
        || parent.height() == Height::new(0)
    {
        return Err(ValidationError::InvalidEpochTransition(
            "seal justification differs from its parent",
        ));
    }
    Ok(())
}
