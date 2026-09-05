use alloc::{boxed::Box, vec, vec::Vec};

use crate::{
    canonical::{
        canonical_hash, try_canonical_bytes, Encoder, DOMAIN_QUORUM_CERTIFICATE,
        DOMAIN_TIMEOUT_CERTIFICATE,
    },
    context::SCHEMA_VERSION_V0,
    message::encode_qc_ref,
    CertificateId, ChainId, Epoch, GenesisHash, Height, ProtocolVersion, QcRef, Result,
    SignatureVerifier, TimeoutVote, ValidationError, ValidatorId, ValidatorSet, ValidatorSetId,
    View, Vote,
};

#[cfg(test)]
use crate::{CommonConsensusContextV0, MessageKind, Signature64};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCertificate {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    view: View,
    height: Height,
    block_id: crate::BlockId,
    validator_set_id: ValidatorSetId,
    votes: Vec<Vote>,
}

impl QuorumCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        view: View,
        height: Height,
        block_id: crate::BlockId,
        validator_set_id: ValidatorSetId,
        votes: Vec<Vote>,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        validate_certificate_binding(
            chain_id,
            protocol_version,
            epoch,
            validator_set_id,
            validator_set,
        )?;
        let value = Self {
            genesis_hash: validator_set.genesis_hash(),
            chain_id,
            protocol_version,
            epoch,
            view,
            height,
            block_id,
            validator_set_id,
            votes,
        };
        value.validate_shape(validator_set)?;
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

    pub const fn block_id(&self) -> crate::BlockId {
        self.block_id
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub fn votes(&self) -> &[Vote] {
        &self.votes
    }

    pub fn id(&self) -> CertificateId {
        CertificateId::new(canonical_hash(DOMAIN_QUORUM_CERTIFICATE, |encoder| {
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
        encoder.fixed(self.validator_set_id.as_bytes());
        encoder.u64(self.view.get());
        encoder.u64(self.height.get());
        encoder.fixed(self.block_id.as_bytes());
        encoder.list_len(self.votes.len());
        for vote in &self.votes {
            encoder.bytes(vote.author().as_bytes());
            encoder.fixed(vote.signature().as_bytes());
        }
    }

    pub fn validate_shape(&self, validator_set: &ValidatorSet) -> Result<()> {
        validate_certificate_binding(
            self.chain_id,
            self.protocol_version,
            self.epoch,
            self.validator_set_id,
            validator_set,
        )?;
        if self.genesis_hash != validator_set.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if self.view == View::new(0) {
            return Err(ValidationError::InvalidCertificate(
                "ordinary QC view must be positive",
            ));
        }
        let mut previous = None;
        let mut signed_power = 0u128;
        for vote in &self.votes {
            vote.validate_shape(validator_set)?;
            if vote.context().genesis_hash() != self.genesis_hash
                || vote.chain_id() != self.chain_id
                || vote.protocol_version() != self.protocol_version
                || vote.epoch() != self.epoch
                || vote.view() != self.view
                || vote.height() != self.height
                || vote.block_id() != self.block_id
                || vote.validator_set_id() != self.validator_set_id
            {
                return Err(ValidationError::CertificateMismatch);
            }
            validate_signer_order(&mut previous, vote.author())?;
            signed_power =
                signed_power
                    .checked_add(validator_set.power_of(vote.author()).ok_or_else(|| {
                        ValidationError::UnknownValidator(Box::new(vote.author()))
                    })?)
                    .ok_or(ValidationError::ArithmeticOverflow("QC signed power"))?;
        }
        if signed_power < validator_set.quorum_power() {
            return Err(ValidationError::InsufficientQuorum {
                signed: signed_power,
                required: validator_set.quorum_power(),
            });
        }
        Ok(())
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape(validator_set)?;
        for vote in &self.votes {
            vote.verify(validator_set, verifier)?;
        }
        Ok(())
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts_for_test(
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        view: View,
        height: Height,
        block_id: crate::BlockId,
        validator_set_id: ValidatorSetId,
        signatures: Vec<(ValidatorId, Signature64)>,
    ) -> Result<Self> {
        if signatures.is_empty() {
            return Err(ValidationError::InvalidCertificate(
                "ordinary test QC must contain signatures",
            ));
        }
        let context = CommonConsensusContextV0::new(
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            validator_set_id,
            view,
            MessageKind::Vote,
        )?;
        let mut previous = None;
        let mut votes = Vec::with_capacity(signatures.len());
        for (author, signature) in signatures {
            validate_signer_order(&mut previous, author)?;
            votes.push(Vote::from_parts_for_test(
                context,
                height,
                block_id,
                validator_set_id,
                author,
                signature,
            )?);
        }
        Ok(Self {
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            view,
            height,
            block_id,
            validator_set_id,
            votes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutCertificate {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    view: View,
    validator_set_id: ValidatorSetId,
    referenced_qcs: Vec<QuorumCertificate>,
    selected_high_qc: QuorumCertificate,
    timeout_votes: Vec<TimeoutVote>,
}

impl TimeoutCertificate {
    /// Compatibility constructor for the common case in which all timeout
    /// entries reference the same high QC. It emits the exact frozen TC schema.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        view: View,
        validator_set_id: ValidatorSetId,
        high_qc: QuorumCertificate,
        timeout_votes: Vec<TimeoutVote>,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        let selected = high_qc.id();
        Self::new_with_referenced_qcs(
            chain_id,
            protocol_version,
            epoch,
            view,
            validator_set_id,
            vec![high_qc],
            selected,
            timeout_votes,
            validator_set,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_referenced_qcs(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        view: View,
        validator_set_id: ValidatorSetId,
        referenced_qcs: Vec<QuorumCertificate>,
        selected_high_qc_digest: CertificateId,
        timeout_votes: Vec<TimeoutVote>,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        validate_certificate_binding(
            chain_id,
            protocol_version,
            epoch,
            validator_set_id,
            validator_set,
        )?;
        let selected_high_qc = referenced_qcs
            .iter()
            .find(|qc| qc.id() == selected_high_qc_digest)
            .cloned()
            .ok_or(ValidationError::InvalidCertificate(
                "selected high QC is absent from referenced QCs",
            ))?;
        let value = Self {
            genesis_hash: validator_set.genesis_hash(),
            chain_id,
            protocol_version,
            epoch,
            view,
            validator_set_id,
            referenced_qcs,
            selected_high_qc,
            timeout_votes,
        };
        value.validate_shape(validator_set)?;
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

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn high_qc(&self) -> &QuorumCertificate {
        &self.selected_high_qc
    }

    pub fn referenced_qcs(&self) -> &[QuorumCertificate] {
        &self.referenced_qcs
    }

    pub fn timeout_votes(&self) -> &[TimeoutVote] {
        &self.timeout_votes
    }

    pub fn id(&self) -> CertificateId {
        CertificateId::new(canonical_hash(DOMAIN_TIMEOUT_CERTIFICATE, |encoder| {
            encoder.u16(SCHEMA_VERSION_V0);
            encoder.fixed(self.genesis_hash.as_bytes());
            encoder.consensus_string(self.chain_id.as_bytes());
            encoder.u32(self.protocol_version.get());
            encoder.u64(self.epoch.get());
            encoder.fixed(self.validator_set_id.as_bytes());
            encoder.u64(self.view.get());
            encoder.list_len(self.timeout_votes.len());
            for vote in &self.timeout_votes {
                encoder.bytes(vote.author().as_bytes());
                encode_qc_ref(encoder, vote.high_qc());
                encoder.fixed(vote.signature().as_bytes());
            }
            encoder.list_len(self.referenced_qcs.len());
            for qc in &self.referenced_qcs {
                qc.encode_cev0(encoder);
            }
            encoder.fixed(self.selected_high_qc.id().as_bytes());
        }))
    }

    pub fn validate_shape(&self, validator_set: &ValidatorSet) -> Result<()> {
        validate_certificate_binding(
            self.chain_id,
            self.protocol_version,
            self.epoch,
            self.validator_set_id,
            validator_set,
        )?;
        if self.genesis_hash != validator_set.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if self.referenced_qcs.is_empty() {
            return Err(ValidationError::InvalidCertificate(
                "TC must contain referenced QCs",
            ));
        }

        let mut previous_qc_id = None;
        for (index, qc) in self.referenced_qcs.iter().enumerate() {
            qc.validate_shape(validator_set)?;
            if qc.genesis_hash() != self.genesis_hash
                || qc.chain_id() != self.chain_id
                || qc.protocol_version() != self.protocol_version
                || qc.epoch() != self.epoch
                || qc.validator_set_id() != self.validator_set_id
                || qc.view() > self.view
            {
                return Err(ValidationError::CertificateMismatch);
            }
            let qc_id = qc.id();
            if previous_qc_id.is_some_and(|previous| previous >= qc_id) {
                return Err(ValidationError::NonCanonicalQcOrder);
            }
            previous_qc_id = Some(qc_id);
            for previous in &self.referenced_qcs[..index] {
                if previous.view() == qc.view() && previous.block_id() != qc.block_id() {
                    return Err(ValidationError::ConflictingSameViewQc);
                }
            }
        }

        let selected_ref = QcRef::from(&self.selected_high_qc);
        if !self
            .referenced_qcs
            .iter()
            .any(|qc| qc.id() == selected_ref.qc_digest())
        {
            return Err(ValidationError::InvalidCertificate(
                "selected high QC is absent from referenced QCs",
            ));
        }

        let mut referenced_by_entry = vec![false; self.referenced_qcs.len()];
        let mut previous_signer = None;
        let mut signed_power = 0u128;
        let mut maximum_entry_qc: Option<QcRef> = None;
        for vote in &self.timeout_votes {
            vote.validate_shape(validator_set)?;
            if vote.context().genesis_hash() != self.genesis_hash
                || vote.chain_id() != self.chain_id
                || vote.protocol_version() != self.protocol_version
                || vote.epoch() != self.epoch
                || vote.view() != self.view
                || vote.validator_set_id() != self.validator_set_id
            {
                return Err(ValidationError::CertificateMismatch);
            }
            let (index, referenced) = self
                .referenced_qcs
                .iter()
                .enumerate()
                .find(|(_, qc)| qc.id() == vote.high_qc().qc_digest())
                .ok_or(ValidationError::InvalidCertificate(
                    "timeout entry references an absent QC",
                ))?;
            if vote.high_qc() != QcRef::from(referenced) {
                return Err(ValidationError::CertificateMismatch);
            }
            referenced_by_entry[index] = true;
            maximum_entry_qc = match maximum_entry_qc {
                Some(current)
                    if (current.view(), current.block_id(), current.qc_digest())
                        >= (
                            vote.high_qc().view(),
                            vote.high_qc().block_id(),
                            vote.high_qc().qc_digest(),
                        ) =>
                {
                    Some(current)
                }
                _ => Some(vote.high_qc()),
            };
            validate_signer_order(&mut previous_signer, vote.author())?;
            signed_power =
                signed_power
                    .checked_add(validator_set.power_of(vote.author()).ok_or_else(|| {
                        ValidationError::UnknownValidator(Box::new(vote.author()))
                    })?)
                    .ok_or(ValidationError::ArithmeticOverflow("TC signed power"))?;
        }
        if referenced_by_entry.iter().any(|referenced| !referenced) {
            return Err(ValidationError::InvalidCertificate(
                "TC contains an unreferenced QC",
            ));
        }
        if maximum_entry_qc != Some(selected_ref) {
            return Err(ValidationError::InvalidCertificate(
                "TC selected high QC is not the deterministic maximum",
            ));
        }
        if signed_power < validator_set.quorum_power() {
            return Err(ValidationError::InsufficientQuorum {
                signed: signed_power,
                required: validator_set.quorum_power(),
            });
        }
        Ok(())
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape(validator_set)?;
        for qc in &self.referenced_qcs {
            qc.verify(validator_set, verifier)?;
        }
        for vote in &self.timeout_votes {
            vote.verify(validator_set, verifier)?;
        }
        Ok(())
    }
}

fn validate_certificate_binding(
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    validator_set: &ValidatorSet,
) -> Result<()> {
    validator_set.validate_shape()?;
    if chain_id != validator_set.chain_id() {
        return Err(ValidationError::ChainIdMismatch);
    }
    if protocol_version != validator_set.protocol_version() {
        return Err(ValidationError::ProtocolVersionMismatch);
    }
    if epoch != validator_set.epoch() {
        return Err(ValidationError::EpochMismatch);
    }
    if validator_set_id != validator_set.id() {
        return Err(ValidationError::ValidatorSetMismatch);
    }
    Ok(())
}

pub(crate) fn validate_signer_order(
    previous: &mut Option<ValidatorId>,
    current: ValidatorId,
) -> Result<()> {
    if let Some(previous_id) = *previous {
        if previous_id == current {
            return Err(ValidationError::DuplicateSigner(Box::new(current)));
        }
        if previous_id > current {
            return Err(ValidationError::NonCanonicalSignerOrder);
        }
    }
    *previous = Some(current);
    Ok(())
}
