use crate::{
    canonical::Encoder, ChainId, Epoch, GenesisHash, ProtocolVersion, Result, ValidationError,
    ValidatorSetId, View,
};

pub const SCHEMA_VERSION_V0: u16 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum MessageKind {
    Proposal = 0,
    Vote = 1,
    Timeout = 2,
    OldSetHandoffVote = 3,
    NewSetHandoffVote = 4,
}

/// The exact frozen prefix of every signed PoCO-BFT v0 consensus message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommonConsensusContextV0 {
    schema_version: u16,
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_hash: ValidatorSetId,
    view: View,
    message_kind: MessageKind,
}

impl CommonConsensusContextV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        schema_version: u16,
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set_hash: ValidatorSetId,
        view: View,
        message_kind: MessageKind,
    ) -> Result<Self> {
        if schema_version != SCHEMA_VERSION_V0 {
            return Err(ValidationError::InvalidSchemaVersion {
                actual: schema_version,
                expected: SCHEMA_VERSION_V0,
            });
        }
        if genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if validator_set_hash.is_zero() {
            return Err(ValidationError::ValidatorSetMismatch);
        }
        Ok(Self {
            schema_version,
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            validator_set_hash,
            view,
            message_kind,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set_hash: ValidatorSetId,
        view: View,
        message_kind: MessageKind,
    ) -> Result<Self> {
        Self::from_parts(
            SCHEMA_VERSION_V0,
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            validator_set_hash,
            view,
            message_kind,
        )
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
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

    pub const fn validator_set_hash(&self) -> ValidatorSetId {
        self.validator_set_hash
    }

    pub const fn view(&self) -> View {
        self.view
    }

    pub const fn message_kind(&self) -> MessageKind {
        self.message_kind
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.schema_version);
        encoder.fixed(self.genesis_hash.as_bytes());
        encoder.consensus_string(self.chain_id.as_bytes());
        encoder.u32(self.protocol_version.get());
        encoder.u64(self.epoch.get());
        encoder.fixed(self.validator_set_hash.as_bytes());
        encoder.u64(self.view.get());
        encoder.u8(self.message_kind as u8);
    }

    pub(crate) fn require_kind(&self, expected: MessageKind) -> Result<()> {
        if self.message_kind != expected {
            return Err(ValidationError::MessageKindMismatch {
                actual: self.message_kind as u8,
                expected: expected as u8,
            });
        }
        Ok(())
    }
}
