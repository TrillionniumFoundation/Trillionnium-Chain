use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use crate::{
    canonical::{canonical_hash, try_canonical_bytes, Encoder, DOMAIN_TIMEOUT_CERTIFICATE},
    certificate::validate_signer_order,
    CertificateId, ChainId, ContextAuthorizedQcV0, Epoch, EpochAnchorAuthorizationV0, GenesisHash,
    ProtocolVersion, QcRef, QcReferenceV0, Result, Signature64, SignatureVerifier, TimeoutVote,
    ValidationError, ValidatorId, ValidatorSet, ValidatorSetId, View, SCHEMA_VERSION_V0,
};

/// Exact `TimeoutEntryV0` wire value. Consensus context is reconstructed from
/// the enclosing TC when the signature is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutEntryV0 {
    signer_id: ValidatorId,
    high_qc: QcRef,
    signature: Signature64,
}

impl TimeoutEntryV0 {
    pub fn new(signer_id: ValidatorId, high_qc: QcRef, signature: Signature64) -> Result<Self> {
        signature.validate_shape()?;
        Ok(Self {
            signer_id,
            high_qc,
            signature,
        })
    }

    pub const fn signer_id(&self) -> ValidatorId {
        self.signer_id
    }

    pub const fn high_qc(&self) -> QcRef {
        self.high_qc
    }

    pub const fn signature(&self) -> &Signature64 {
        &self.signature
    }

    fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.bytes(self.signer_id.as_bytes());
        encode_high_qc_summary(encoder, self.high_qc);
        encoder.fixed(self.signature.as_bytes());
    }
}

/// Corrected TC representation that can carry one exact, context-authorized
/// synthetic anchor. The legacy `TimeoutCertificate` remains the ordinary-QC
/// compatibility type used by the prototype core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutCertificateV0 {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_hash: ValidatorSetId,
    timed_out_view: View,
    entries: Vec<TimeoutEntryV0>,
    referenced_qcs: Vec<QcReferenceV0>,
    selected_high_qc_digest: CertificateId,
}

impl TimeoutCertificateV0 {
    pub fn new(
        timed_out_view: View,
        entries: Vec<TimeoutEntryV0>,
        referenced_qcs: Vec<QcReferenceV0>,
        selected_high_qc_digest: CertificateId,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        let value = Self {
            genesis_hash: validator_set.genesis_hash(),
            chain_id: validator_set.chain_id(),
            protocol_version: validator_set.protocol_version(),
            epoch: validator_set.epoch(),
            validator_set_hash: validator_set.id(),
            timed_out_view,
            entries,
            referenced_qcs,
            selected_high_qc_digest,
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

    pub const fn validator_set_hash(&self) -> ValidatorSetId {
        self.validator_set_hash
    }

    pub const fn timed_out_view(&self) -> View {
        self.timed_out_view
    }

    pub fn entries(&self) -> &[TimeoutEntryV0] {
        &self.entries
    }

    pub fn referenced_qcs(&self) -> &[QcReferenceV0] {
        &self.referenced_qcs
    }

    pub const fn selected_high_qc_digest(&self) -> CertificateId {
        self.selected_high_qc_digest
    }

    pub fn id(&self) -> CertificateId {
        CertificateId::new(canonical_hash(DOMAIN_TIMEOUT_CERTIFICATE, |encoder| {
            self.encode_cev0(encoder);
        }))
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    pub fn validate_shape(&self, validator_set: &ValidatorSet) -> Result<()> {
        validator_set.validate_shape()?;
        if self.entries.len() > validator_set.validators().len() {
            return Err(ValidationError::InvalidCertificate(
                "TC entry count exceeds the validator set",
            ));
        }
        if self.referenced_qcs.len() > self.entries.len() {
            return Err(ValidationError::InvalidCertificate(
                "TC referenced-QC count exceeds its timeout entries",
            ));
        }
        if self.genesis_hash != validator_set.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if self.chain_id != validator_set.chain_id() {
            return Err(ValidationError::ChainIdMismatch);
        }
        if self.protocol_version != validator_set.protocol_version() {
            return Err(ValidationError::ProtocolVersionMismatch);
        }
        if self.epoch != validator_set.epoch() {
            return Err(ValidationError::EpochMismatch);
        }
        if self.validator_set_hash != validator_set.id() {
            return Err(ValidationError::ValidatorSetMismatch);
        }
        self.validate_wire_relations()?;

        for referenced in &self.referenced_qcs {
            match referenced {
                QcReferenceV0::Ordinary(certificate) => {
                    certificate.validate_shape(validator_set)?;
                }
                QcReferenceV0::Synthetic(synthetic) => match synthetic.as_ref() {
                    ContextAuthorizedQcV0::Genesis(anchor) => {
                        anchor.matches_trusted_set(validator_set)?;
                    }
                    ContextAuthorizedQcV0::Epoch(_) => {
                        // Exact authorization is supplied and verified by the
                        // enclosing CertifiedHeaderV0 verification path.
                    }
                },
            }
        }

        let mut signed_power = 0u128;
        for entry in &self.entries {
            signed_power =
                signed_power
                    .checked_add(validator_set.power_of(entry.signer_id).ok_or_else(|| {
                        ValidationError::UnknownValidator(Box::new(entry.signer_id))
                    })?)
                    .ok_or(ValidationError::ArithmeticOverflow("TC signed power"))?;
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
        _epoch_authorization: Option<(&EpochAnchorAuthorizationV0, &ValidatorSet)>,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape(validator_set)?;
        for referenced in &self.referenced_qcs {
            match referenced {
                QcReferenceV0::Ordinary(certificate) => {
                    certificate.verify(validator_set, verifier)?;
                }
                QcReferenceV0::Synthetic(synthetic) => match synthetic.as_ref() {
                    ContextAuthorizedQcV0::Genesis(anchor) => {
                        anchor.matches_trusted_set(validator_set)?;
                    }
                    ContextAuthorizedQcV0::Epoch(_) => {
                        return Err(ValidationError::InvalidCertificate(
                            "complete trusted epoch-anchor authorization is not implemented",
                        ));
                    }
                },
            }
        }
        for entry in &self.entries {
            let validator = validator_set
                .validator(entry.signer_id)
                .ok_or_else(|| ValidationError::UnknownValidator(Box::new(entry.signer_id)))?;
            let root = TimeoutVote::signing_root_for_set(
                validator_set,
                self.timed_out_view,
                entry.high_qc,
            )?;
            if !verifier.verify(validator, &root, &entry.signature) {
                return Err(ValidationError::InvalidSignature(Box::new(entry.signer_id)));
            }
        }
        Ok(())
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.fixed(self.genesis_hash.as_bytes());
        encoder.consensus_string(self.chain_id.as_bytes());
        encoder.u32(self.protocol_version.get());
        encoder.u64(self.epoch.get());
        encoder.fixed(self.validator_set_hash.as_bytes());
        encoder.u64(self.timed_out_view.get());
        encoder.list_len(self.entries.len());
        for entry in &self.entries {
            entry.encode_cev0(encoder);
        }
        encoder.list_len(self.referenced_qcs.len());
        for qc in &self.referenced_qcs {
            qc.encode_cev0(encoder);
        }
        encoder.fixed(self.selected_high_qc_digest.as_bytes());
    }

    fn validate_wire_relations(&self) -> Result<()> {
        if self.referenced_qcs.is_empty() {
            return Err(ValidationError::InvalidCertificate(
                "TC must contain referenced QCs",
            ));
        }
        let mut previous_qc = None;
        let mut referenced_ids = BTreeSet::new();
        let mut coordinates = BTreeMap::new();
        let mut block_coordinates = BTreeMap::new();
        for referenced in &self.referenced_qcs {
            let summary = referenced.qc_ref();
            if summary.epoch() != self.epoch
                || summary.validator_set_id() != self.validator_set_hash
                || summary.view() > self.timed_out_view
            {
                return Err(ValidationError::CertificateMismatch);
            }
            let id = referenced.id();
            if previous_qc.is_some_and(|previous| previous >= id) {
                return Err(ValidationError::NonCanonicalQcOrder);
            }
            previous_qc = Some(id);
            referenced_ids.insert(id);
            let coordinate = (summary.epoch(), summary.view());
            let certified = (summary.height(), summary.block_id());
            if coordinates
                .insert(coordinate, certified)
                .is_some_and(|prior| prior != certified)
            {
                return Err(ValidationError::ConflictingSameViewQc);
            }
            let block_coordinate = (summary.epoch(), summary.view(), summary.height());
            if block_coordinates
                .insert(summary.block_id(), block_coordinate)
                .is_some_and(|prior| prior != block_coordinate)
            {
                return Err(ValidationError::InvalidCertificate(
                    "TC binds one block ID to multiple QC coordinates",
                ));
            }
        }

        let mut previous_signer = None;
        let mut maximum: Option<QcRef> = None;
        let mut used_references = BTreeSet::new();
        for entry in &self.entries {
            entry.signature.validate_shape()?;
            validate_signer_order(&mut previous_signer, entry.signer_id)?;
            if !self
                .referenced_qcs
                .iter()
                .any(|candidate| candidate.qc_ref() == entry.high_qc)
            {
                return Err(ValidationError::InvalidCertificate(
                    "timeout entry does not match an exact referenced QC",
                ));
            }
            used_references.insert(entry.high_qc.qc_digest());
            maximum = match maximum {
                Some(current)
                    if (current.view(), current.block_id(), current.qc_digest())
                        >= (
                            entry.high_qc.view(),
                            entry.high_qc.block_id(),
                            entry.high_qc.qc_digest(),
                        ) =>
                {
                    Some(current)
                }
                _ => Some(entry.high_qc),
            };
        }
        let maximum = maximum.ok_or(ValidationError::InvalidCertificate(
            "TC must contain timeout entries",
        ))?;
        if maximum.qc_digest() != self.selected_high_qc_digest {
            return Err(ValidationError::InvalidCertificate(
                "TC selected high QC is not the deterministic maximum",
            ));
        }
        if used_references != referenced_ids {
            return Err(ValidationError::InvalidCertificate(
                "TC carries a referenced QC that no timeout entry signed",
            ));
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
        validator_set_hash: ValidatorSetId,
        timed_out_view: View,
        entries: Vec<TimeoutEntryV0>,
        referenced_qcs: Vec<QcReferenceV0>,
        selected_high_qc_digest: CertificateId,
    ) -> Result<Self> {
        let value = Self {
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            validator_set_hash,
            timed_out_view,
            entries,
            referenced_qcs,
            selected_high_qc_digest,
        };
        value.validate_wire_relations()?;
        Ok(value)
    }
}

fn encode_high_qc_summary(encoder: &mut Encoder, value: QcRef) {
    encoder.fixed(value.qc_digest().as_bytes());
    encoder.u64(value.epoch().get());
    encoder.u64(value.view().get());
    encoder.u64(value.height().get());
    encoder.fixed(value.block_id().as_bytes());
}
