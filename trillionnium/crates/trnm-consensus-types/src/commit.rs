use crate::{
    canonical::{canonical_hash, DOMAIN_OBSOLETE_COMMIT_PROOF_INTERNAL},
    BlockHeader, CertificateId, QuorumCertificate, Result, SignatureVerifier, ValidationError,
    ValidatorSet,
};

/// Obsolete internal compatibility witness used only by the prototype core.
///
/// This is not `FinalityProofV0`, is not encoded under the frozen finality
/// domain, and must never be exported as a protocol or light-client proof.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitProof {
    committed: BlockHeader,
    child: BlockHeader,
    grandchild: BlockHeader,
    committed_qc: QuorumCertificate,
    child_qc: QuorumCertificate,
    grandchild_qc: QuorumCertificate,
}

impl CommitProof {
    pub fn new(
        committed: BlockHeader,
        child: BlockHeader,
        grandchild: BlockHeader,
        committed_qc: QuorumCertificate,
        child_qc: QuorumCertificate,
        grandchild_qc: QuorumCertificate,
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        let value = Self {
            committed,
            child,
            grandchild,
            committed_qc,
            child_qc,
            grandchild_qc,
        };
        value.validate_shape(validator_set)?;
        Ok(value)
    }

    pub const fn committed(&self) -> &BlockHeader {
        &self.committed
    }

    pub const fn child(&self) -> &BlockHeader {
        &self.child
    }

    pub const fn grandchild(&self) -> &BlockHeader {
        &self.grandchild
    }

    pub const fn committed_qc(&self) -> &QuorumCertificate {
        &self.committed_qc
    }

    pub const fn child_qc(&self) -> &QuorumCertificate {
        &self.child_qc
    }

    pub const fn grandchild_qc(&self) -> &QuorumCertificate {
        &self.grandchild_qc
    }

    pub fn id(&self) -> CertificateId {
        CertificateId::new(canonical_hash(
            DOMAIN_OBSOLETE_COMMIT_PROOF_INTERNAL,
            |encoder| {
                encoder.fixed(self.committed.id().as_bytes());
                encoder.fixed(self.child.id().as_bytes());
                encoder.fixed(self.grandchild.id().as_bytes());
                encoder.fixed(self.committed_qc.id().as_bytes());
                encoder.fixed(self.child_qc.id().as_bytes());
                encoder.fixed(self.grandchild_qc.id().as_bytes());
            },
        ))
    }

    pub fn validate_shape(&self, validator_set: &ValidatorSet) -> Result<()> {
        self.committed.validate_shape()?;
        self.child.validate_shape()?;
        self.grandchild.validate_shape()?;
        for header in [&self.committed, &self.child, &self.grandchild] {
            if header.chain_id() != validator_set.chain_id() {
                return Err(ValidationError::ChainIdMismatch);
            }
            if header.protocol_version() != validator_set.protocol_version() {
                return Err(ValidationError::ProtocolVersionMismatch);
            }
            if header.epoch() != validator_set.epoch() {
                return Err(ValidationError::EpochMismatch);
            }
            if header.validator_set_id() != validator_set.id() {
                return Err(ValidationError::ValidatorSetMismatch);
            }
            if header.genesis_hash() != validator_set.genesis_hash() {
                return Err(ValidationError::GenesisHashMismatch);
            }
            if header.consensus_parameters_hash() != validator_set.consensus_parameters_hash() {
                return Err(ValidationError::ConsensusParametersMismatch);
            }
        }
        if self.child.parent_id() != self.committed.id()
            || self.grandchild.parent_id() != self.child.id()
        {
            return Err(ValidationError::InvalidCommitProof(
                "headers do not form a direct three-block chain",
            ));
        }
        if self.child.height() != self.committed.height().checked_next()?
            || self.grandchild.height() != self.child.height().checked_next()?
        {
            return Err(ValidationError::InvalidCommitProof(
                "three-chain block heights are not consecutive",
            ));
        }
        if !(self.committed.view() < self.child.view()
            && self.child.view() < self.grandchild.view())
        {
            return Err(ValidationError::InvalidCommitProof(
                "three-chain views must be strictly increasing",
            ));
        }
        validate_qc_binding(&self.committed, &self.committed_qc, validator_set)?;
        validate_qc_binding(&self.child, &self.child_qc, validator_set)?;
        validate_qc_binding(&self.grandchild, &self.grandchild_qc, validator_set)
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape(validator_set)?;
        self.committed_qc.verify(validator_set, verifier)?;
        self.child_qc.verify(validator_set, verifier)?;
        self.grandchild_qc.verify(validator_set, verifier)
    }
}

fn validate_qc_binding(
    header: &BlockHeader,
    certificate: &QuorumCertificate,
    validator_set: &ValidatorSet,
) -> Result<()> {
    certificate.validate_shape(validator_set)?;
    if certificate.chain_id() != header.chain_id()
        || certificate.protocol_version() != header.protocol_version()
        || certificate.epoch() != header.epoch()
        || certificate.view() != header.view()
        || certificate.height() != header.height()
        || certificate.block_id() != header.id()
        || certificate.validator_set_id() != header.validator_set_id()
    {
        return Err(ValidationError::InvalidCommitProof(
            "QC does not certify its corresponding block header",
        ));
    }
    Ok(())
}
