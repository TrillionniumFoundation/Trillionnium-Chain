use alloc::{boxed::Box, vec::Vec};

use crate::{
    canonical::{canonical_hash, try_canonical_bytes, Encoder, DOMAIN_QUORUM_CERTIFICATE},
    BlockId, CertificateId, ChainId, Epoch, GenesisHash, Height, ProtocolVersion, QcRef,
    QuorumCertificate, Result, ValidationError, ValidatorSet, ValidatorSetId, View,
    SCHEMA_VERSION_V0,
};

/// The one trusted, empty-signature QC reconstructed from the genesis
/// document. It is deliberately not a `QuorumCertificate`: it has no ordinary
/// QC verification method and cannot be used as a certifying QC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisQcV0 {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    validator_set_hash: ValidatorSetId,
}

impl GenesisQcV0 {
    pub fn new(
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        epoch_zero_validator_set: &ValidatorSet,
    ) -> Result<Self> {
        epoch_zero_validator_set.validate_shape()?;
        if genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if epoch_zero_validator_set.genesis_hash() != genesis_hash {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if epoch_zero_validator_set.chain_id() != chain_id {
            return Err(ValidationError::ChainIdMismatch);
        }
        if epoch_zero_validator_set.protocol_version() != ProtocolVersion::V0 {
            return Err(ValidationError::ProtocolVersionMismatch);
        }
        if epoch_zero_validator_set.epoch() != Epoch::new(0) {
            return Err(ValidationError::EpochMismatch);
        }
        Ok(Self {
            genesis_hash,
            chain_id,
            validator_set_hash: epoch_zero_validator_set.id(),
        })
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_hash
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::V0
    }

    pub const fn epoch(&self) -> Epoch {
        Epoch::new(0)
    }

    pub const fn validator_set_hash(&self) -> ValidatorSetId {
        self.validator_set_hash
    }

    pub const fn view(&self) -> View {
        View::new(0)
    }

    pub const fn height(&self) -> Height {
        Height::new(0)
    }

    pub const fn block_id(&self) -> BlockId {
        BlockId::new(*self.genesis_hash.as_bytes())
    }

    pub fn id(&self) -> CertificateId {
        CertificateId::new(canonical_hash(DOMAIN_QUORUM_CERTIFICATE, |encoder| {
            self.encode_cev0(encoder);
        }))
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    pub fn matches_trusted_set(&self, validator_set: &ValidatorSet) -> Result<()> {
        validator_set.validate_shape()?;
        if validator_set.genesis_hash() != self.genesis_hash {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if validator_set.chain_id() != self.chain_id {
            return Err(ValidationError::ChainIdMismatch);
        }
        if validator_set.protocol_version() != ProtocolVersion::V0 {
            return Err(ValidationError::ProtocolVersionMismatch);
        }
        if validator_set.epoch() != Epoch::new(0) {
            return Err(ValidationError::EpochMismatch);
        }
        if validator_set.id() != self.validator_set_hash {
            return Err(ValidationError::ValidatorSetMismatch);
        }
        Ok(())
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        encode_empty_signature_qc(
            encoder,
            self.genesis_hash,
            self.chain_id,
            ProtocolVersion::V0,
            Epoch::new(0),
            self.validator_set_hash,
            View::new(0),
            Height::new(0),
            self.block_id(),
        );
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        validator_set_hash: ValidatorSetId,
    ) -> Result<Self> {
        if genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if validator_set_hash.is_zero() {
            return Err(ValidationError::ValidatorSetMismatch);
        }
        Ok(Self {
            genesis_hash,
            chain_id,
            validator_set_hash,
        })
    }
}

/// The exact empty-signature QC reconstructed from a complete epoch handoff.
/// Fields are private and the only production constructor is the
/// `EpochAnchorAuthorizationV0` derivation path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochAnchorQcV0 {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_hash: ValidatorSetId,
    terminal_old_height: Height,
    terminal_old_block_id: BlockId,
}

impl EpochAnchorQcV0 {
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
        View::new(0)
    }

    pub const fn height(&self) -> Height {
        self.terminal_old_height
    }

    pub const fn block_id(&self) -> BlockId {
        self.terminal_old_block_id
    }

    pub fn id(&self) -> CertificateId {
        CertificateId::new(canonical_hash(DOMAIN_QUORUM_CERTIFICATE, |encoder| {
            self.encode_cev0(encoder);
        }))
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    pub(crate) fn from_handoff_parts(
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set_hash: ValidatorSetId,
        terminal_old_height: Height,
        terminal_old_block_id: BlockId,
    ) -> Self {
        Self {
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            validator_set_hash,
            terminal_old_height,
            terminal_old_block_id,
        }
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        encode_empty_signature_qc(
            encoder,
            self.genesis_hash,
            self.chain_id,
            self.protocol_version,
            self.epoch,
            self.validator_set_hash,
            View::new(0),
            self.terminal_old_height,
            self.terminal_old_block_id,
        );
    }
}

/// Synthetic QCs are usable only where the proposal/TC verifier supplies the
/// corresponding trusted context. They intentionally expose no ordinary-QC
/// `verify` method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextAuthorizedQcV0 {
    Genesis(GenesisQcV0),
    Epoch(EpochAnchorQcV0),
}

impl ContextAuthorizedQcV0 {
    pub fn id(&self) -> CertificateId {
        match self {
            Self::Genesis(value) => value.id(),
            Self::Epoch(value) => value.id(),
        }
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        match self {
            Self::Genesis(value) => value.genesis_hash(),
            Self::Epoch(value) => value.genesis_hash(),
        }
    }

    pub const fn chain_id(&self) -> ChainId {
        match self {
            Self::Genesis(value) => value.chain_id(),
            Self::Epoch(value) => value.chain_id(),
        }
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        match self {
            Self::Genesis(value) => value.protocol_version(),
            Self::Epoch(value) => value.protocol_version(),
        }
    }

    pub const fn epoch(&self) -> Epoch {
        match self {
            Self::Genesis(value) => value.epoch(),
            Self::Epoch(value) => value.epoch(),
        }
    }

    pub const fn validator_set_hash(&self) -> ValidatorSetId {
        match self {
            Self::Genesis(value) => value.validator_set_hash(),
            Self::Epoch(value) => value.validator_set_hash(),
        }
    }

    pub const fn view(&self) -> View {
        View::new(0)
    }

    pub const fn height(&self) -> Height {
        match self {
            Self::Genesis(value) => value.height(),
            Self::Epoch(value) => value.height(),
        }
    }

    pub const fn block_id(&self) -> BlockId {
        match self {
            Self::Genesis(value) => value.block_id(),
            Self::Epoch(value) => value.block_id(),
        }
    }

    pub fn qc_ref(&self) -> QcRef {
        QcRef::new(
            self.id(),
            self.epoch(),
            self.view(),
            self.height(),
            self.block_id(),
            self.validator_set_hash(),
        )
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        match self {
            Self::Genesis(value) => value.encode_cev0(encoder),
            Self::Epoch(value) => value.encode_cev0(encoder),
        }
    }
}

/// A full QC carried as a proposal justification or TC reference. The
/// certifying-QC field of `CertifiedHeaderV0` does not use this enum and thus
/// cannot contain a synthetic anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QcReferenceV0 {
    Ordinary(Box<QuorumCertificate>),
    Synthetic(Box<ContextAuthorizedQcV0>),
}

impl QcReferenceV0 {
    pub fn ordinary(certificate: QuorumCertificate) -> Self {
        Self::Ordinary(Box::new(certificate))
    }

    pub fn genesis_anchor(anchor: GenesisQcV0) -> Self {
        Self::Synthetic(Box::new(ContextAuthorizedQcV0::Genesis(anchor)))
    }

    pub fn epoch_anchor(anchor: EpochAnchorQcV0) -> Self {
        Self::Synthetic(Box::new(ContextAuthorizedQcV0::Epoch(anchor)))
    }

    pub fn id(&self) -> CertificateId {
        match self {
            Self::Ordinary(value) => value.id(),
            Self::Synthetic(value) => value.id(),
        }
    }

    pub fn qc_ref(&self) -> QcRef {
        match self {
            Self::Ordinary(value) => QcRef::from(value.as_ref()),
            Self::Synthetic(value) => value.qc_ref(),
        }
    }

    pub fn as_ordinary(&self) -> Option<&QuorumCertificate> {
        match self {
            Self::Ordinary(value) => Some(value.as_ref()),
            Self::Synthetic(_) => None,
        }
    }

    pub fn as_synthetic(&self) -> Option<&ContextAuthorizedQcV0> {
        match self {
            Self::Ordinary(_) => None,
            Self::Synthetic(value) => Some(value),
        }
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        match self {
            Self::Ordinary(value) => value.encode_cev0(encoder),
            Self::Synthetic(value) => value.encode_cev0(encoder),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_empty_signature_qc(
    encoder: &mut Encoder,
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_hash: ValidatorSetId,
    view: View,
    height: Height,
    block_id: BlockId,
) {
    encoder.u16(SCHEMA_VERSION_V0);
    encoder.fixed(genesis_hash.as_bytes());
    encoder.consensus_string(chain_id.as_bytes());
    encoder.u32(protocol_version.get());
    encoder.u64(epoch.get());
    encoder.fixed(validator_set_hash.as_bytes());
    encoder.u64(view.get());
    encoder.u64(height.get());
    encoder.fixed(block_id.as_bytes());
    encoder.list_len(0);
}
