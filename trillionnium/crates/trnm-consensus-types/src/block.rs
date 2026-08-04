use alloc::vec::Vec;

use crate::{
    canonical::{canonical_hash, try_canonical_bytes, Encoder, DOMAIN_BLOCK},
    BlockId, ChainId, ConsensusParametersHash, Epoch, EvidenceRoot, GenesisHash, Height,
    NextEpochCommitmentHash, PayloadDigest, ProtocolVersion, ReceiptsRoot, Result, StateRoot,
    ValidationError, ValidatorId, ValidatorSetId, View, SCHEMA_VERSION_V0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BlockKind {
    Regular = 0,
    EpochCheckpoint = 1,
    EpochSeal1 = 2,
    EpochSeal2 = 3,
    EpochHandoff = 4,
}

/// The exact frozen logical `BlockHeaderV0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    view: View,
    height: Height,
    block_kind: BlockKind,
    parent_id: BlockId,
    proposer_id: ValidatorId,
    validator_set_id: ValidatorSetId,
    consensus_parameters_hash: ConsensusParametersHash,
    payload_digest: PayloadDigest,
    state_root: StateRoot,
    receipts_root: ReceiptsRoot,
    evidence_root: EvidenceRoot,
    timestamp_ms: u64,
    next_epoch_commitment_hash: Option<NextEpochCommitmentHash>,
}

impl BlockHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        view: View,
        height: Height,
        block_kind: BlockKind,
        parent_id: BlockId,
        proposer_id: ValidatorId,
        validator_set_id: ValidatorSetId,
        consensus_parameters_hash: ConsensusParametersHash,
        payload_digest: PayloadDigest,
        state_root: StateRoot,
        receipts_root: ReceiptsRoot,
        evidence_root: EvidenceRoot,
        timestamp_ms: u64,
        next_epoch_commitment_hash: Option<NextEpochCommitmentHash>,
    ) -> Result<Self> {
        let value = Self {
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            view,
            height,
            block_kind,
            parent_id,
            proposer_id,
            validator_set_id,
            consensus_parameters_hash,
            payload_digest,
            state_root,
            receipts_root,
            evidence_root,
            timestamp_ms,
            next_epoch_commitment_hash,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_hash
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub const fn view(&self) -> View {
        self.view
    }

    pub const fn height(&self) -> Height {
        self.height
    }

    pub const fn block_kind(&self) -> BlockKind {
        self.block_kind
    }

    pub const fn parent_id(&self) -> BlockId {
        self.parent_id
    }

    pub const fn proposer_id(&self) -> ValidatorId {
        self.proposer_id
    }

    pub const fn payload_digest(&self) -> PayloadDigest {
        self.payload_digest
    }

    pub const fn payload_root(&self) -> PayloadDigest {
        self.payload_digest
    }

    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    pub const fn receipts_root(&self) -> ReceiptsRoot {
        self.receipts_root
    }

    pub const fn evidence_root(&self) -> EvidenceRoot {
        self.evidence_root
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn consensus_parameters_hash(&self) -> ConsensusParametersHash {
        self.consensus_parameters_hash
    }

    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub const fn next_epoch_commitment_hash(&self) -> Option<NextEpochCommitmentHash> {
        self.next_epoch_commitment_hash
    }

    pub fn id(&self) -> BlockId {
        BlockId::new(canonical_hash(DOMAIN_BLOCK, |encoder| {
            self.encode_cev0(encoder);
        }))
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.fixed(self.genesis_hash.as_bytes());
        encoder.consensus_string(self.chain_id.as_bytes());
        encoder.u32(self.protocol_version.get());
        encoder.u64(self.epoch.get());
        encoder.u64(self.view.get());
        encoder.u64(self.height.get());
        encoder.u8(self.block_kind as u8);
        encoder.fixed(self.parent_id.as_bytes());
        encoder.bytes(self.proposer_id.as_bytes());
        encoder.fixed(self.validator_set_id.as_bytes());
        encoder.fixed(self.consensus_parameters_hash.as_bytes());
        encoder.fixed(self.payload_digest.as_bytes());
        encoder.fixed(self.state_root.as_bytes());
        encoder.fixed(self.receipts_root.as_bytes());
        encoder.fixed(self.evidence_root.as_bytes());
        encoder.u64(self.timestamp_ms);
        encoder.optional_fixed(
            self.next_epoch_commitment_hash
                .as_ref()
                .map(NextEpochCommitmentHash::as_bytes),
        );
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if self.height.get() == 0 {
            return Err(ValidationError::InvalidBlock(
                "network block height must be positive",
            ));
        }
        if self.view.get() == 0 {
            return Err(ValidationError::InvalidBlock(
                "network block view must be positive",
            ));
        }
        if self.validator_set_id.is_zero() {
            return Err(ValidationError::ValidatorSetIdMismatch);
        }
        match self.block_kind {
            BlockKind::Regular | BlockKind::EpochHandoff => {
                if self.next_epoch_commitment_hash.is_some() {
                    return Err(ValidationError::InvalidBlock(
                        "regular/handoff block must not carry a next-epoch commitment",
                    ));
                }
            }
            BlockKind::EpochCheckpoint | BlockKind::EpochSeal1 | BlockKind::EpochSeal2 => {
                if self.next_epoch_commitment_hash.is_none() {
                    return Err(ValidationError::InvalidBlock(
                        "checkpoint/seal block must carry the next-epoch commitment",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A block body remains runtime-defined. Consensus types bind the body through
/// the already-computed roots in `BlockHeader`; deterministic runtime/root
/// validation occurs before voting in the host boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    header: BlockHeader,
    payload: Vec<u8>,
}

impl Block {
    pub fn new(header: BlockHeader, payload: Vec<u8>) -> Result<Self> {
        header.validate_shape()?;
        Ok(Self { header, payload })
    }

    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn id(&self) -> BlockId {
        self.header.id()
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.header.validate_shape()
    }
}
