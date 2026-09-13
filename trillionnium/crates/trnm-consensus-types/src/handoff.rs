use alloc::{boxed::Box, vec::Vec};

use crate::{
    canonical::{
        canonical_hash, signing_root, try_canonical_bytes, Encoder, DOMAIN_HANDOFF_CERTIFICATE,
        DOMAIN_HANDOFF_DESCRIPTOR, DOMAIN_HANDOFF_VOTE,
    },
    certificate::validate_signer_order,
    BlockHeader, BlockId, BlockKind, CertificateId, ChainId, ConsensusParametersHash, Epoch,
    EpochAnchorQcV0, GenesisHash, Height, MessageKind, NextEpochCommitmentHash, ProtocolVersion,
    QuorumCertificate, Result, Signature64, SignatureVerifier, SigningRoot, StateRoot,
    ValidationError, ValidatorId, ValidatorSet, ValidatorSetId, View, SCHEMA_VERSION_V0,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffDescriptorV0Fields {
    pub genesis_hash: GenesisHash,
    pub chain_id: ChainId,
    pub old_epoch: Epoch,
    pub new_epoch: Epoch,
    pub old_protocol_version: ProtocolVersion,
    pub new_protocol_version: ProtocolVersion,
    pub old_validator_set_hash: ValidatorSetId,
    pub new_validator_set_hash: ValidatorSetId,
    pub old_consensus_parameters_hash: ConsensusParametersHash,
    pub new_consensus_parameters_hash: ConsensusParametersHash,
    pub checkpoint_height: Height,
    pub checkpoint_block_id: BlockId,
    pub checkpoint_state_root: StateRoot,
    pub next_epoch_commitment_digest: NextEpochCommitmentHash,
    pub terminal_old_height: Height,
    pub terminal_old_block_id: BlockId,
    pub terminal_old_qc_digest: CertificateId,
    pub terminal_old_view: View,
    pub activation_height: Height,
    pub initial_new_view: View,
}

/// Exact frozen transition descriptor; its digest has a dedicated domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffDescriptorV0(HandoffDescriptorV0Fields);

impl HandoffDescriptorV0 {
    pub fn new(fields: HandoffDescriptorV0Fields) -> Result<Self> {
        let value = Self(fields);
        value.validate_shape()?;
        Ok(value)
    }

    pub const fn fields(&self) -> &HandoffDescriptorV0Fields {
        &self.0
    }

    pub fn id(&self) -> CertificateId {
        CertificateId::new(canonical_hash(DOMAIN_HANDOFF_DESCRIPTOR, |encoder| {
            self.encode_cev0(encoder);
        }))
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    /// Canonical signing root for the terminal old-set handoff role.
    ///
    /// This exposes only the deterministic message root needed by an actual
    /// signer. It does not validate a share, form a certificate, or authorize
    /// an epoch transition.
    pub fn old_set_signing_root(&self) -> SigningRoot {
        handoff_vote_signing_root(self, MessageKind::OldSetHandoffVote)
    }

    /// Canonical signing root for the initial new-set handoff role.
    ///
    /// Like [`Self::old_set_signing_root`], this is a pure serialization/hash
    /// helper and grants no handoff or activation authority.
    pub fn new_set_signing_root(&self) -> SigningRoot {
        handoff_vote_signing_root(self, MessageKind::NewSetHandoffVote)
    }

    pub fn validate_shape(&self) -> Result<()> {
        let fields = &self.0;
        if fields.genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if fields.old_validator_set_hash.is_zero() || fields.new_validator_set_hash.is_zero() {
            return Err(ValidationError::InvalidEpochTransition(
                "handoff validator-set hash is zero",
            ));
        }
        if fields.old_consensus_parameters_hash.is_zero()
            || fields.new_consensus_parameters_hash.is_zero()
        {
            return Err(ValidationError::InvalidEpochTransition(
                "handoff consensus-parameter hash is zero",
            ));
        }
        if fields.new_epoch != fields.old_epoch.checked_next()? {
            return Err(ValidationError::InvalidEpochTransition(
                "handoff epochs are not adjacent",
            ));
        }
        if fields.initial_new_view != View::new(1) {
            return Err(ValidationError::InvalidEpochTransition(
                "initial new view must be one",
            ));
        }
        if fields.activation_height != fields.terminal_old_height.checked_next()? {
            return Err(ValidationError::InvalidEpochTransition(
                "activation height must follow terminal old height",
            ));
        }
        if fields.checkpoint_height > fields.terminal_old_height {
            return Err(ValidationError::InvalidEpochTransition(
                "checkpoint height exceeds terminal old height",
            ));
        }
        if fields.checkpoint_block_id.is_zero()
            || fields.checkpoint_state_root.is_zero()
            || fields.next_epoch_commitment_digest.is_zero()
            || fields.terminal_old_block_id.is_zero()
            || fields.terminal_old_qc_digest.is_zero()
        {
            return Err(ValidationError::InvalidEpochTransition(
                "handoff descriptor contains a zero commitment",
            ));
        }
        Ok(())
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        let fields = &self.0;
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.fixed(fields.genesis_hash.as_bytes());
        encoder.consensus_string(fields.chain_id.as_bytes());
        encoder.u64(fields.old_epoch.get());
        encoder.u64(fields.new_epoch.get());
        encoder.u32(fields.old_protocol_version.get());
        encoder.u32(fields.new_protocol_version.get());
        encoder.fixed(fields.old_validator_set_hash.as_bytes());
        encoder.fixed(fields.new_validator_set_hash.as_bytes());
        encoder.fixed(fields.old_consensus_parameters_hash.as_bytes());
        encoder.fixed(fields.new_consensus_parameters_hash.as_bytes());
        encoder.u64(fields.checkpoint_height.get());
        encoder.fixed(fields.checkpoint_block_id.as_bytes());
        encoder.fixed(fields.checkpoint_state_root.as_bytes());
        encoder.fixed(fields.next_epoch_commitment_digest.as_bytes());
        encoder.u64(fields.terminal_old_height.get());
        encoder.fixed(fields.terminal_old_block_id.as_bytes());
        encoder.fixed(fields.terminal_old_qc_digest.as_bytes());
        encoder.u64(fields.terminal_old_view.get());
        encoder.u64(fields.activation_height.get());
        encoder.u64(fields.initial_new_view.get());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureShareV0 {
    validator_id: ValidatorId,
    signature: Signature64,
}

impl SignatureShareV0 {
    pub fn new(validator_id: ValidatorId, signature: Signature64) -> Result<Self> {
        signature.validate_shape()?;
        Ok(Self {
            validator_id,
            signature,
        })
    }

    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    pub const fn signature(&self) -> &Signature64 {
        &self.signature
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.bytes(self.validator_id.as_bytes());
        encoder.fixed(self.signature.as_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffCertificateV0 {
    descriptor: HandoffDescriptorV0,
    old_signatures: Vec<SignatureShareV0>,
    new_signatures: Vec<SignatureShareV0>,
}

impl HandoffCertificateV0 {
    pub fn new(
        descriptor: HandoffDescriptorV0,
        old_signatures: Vec<SignatureShareV0>,
        new_signatures: Vec<SignatureShareV0>,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<Self> {
        let value = Self {
            descriptor,
            old_signatures,
            new_signatures,
        };
        value.validate_shape(old_validator_set, new_validator_set)?;
        Ok(value)
    }

    pub const fn descriptor(&self) -> &HandoffDescriptorV0 {
        &self.descriptor
    }

    pub fn old_signatures(&self) -> &[SignatureShareV0] {
        &self.old_signatures
    }

    pub fn new_signatures(&self) -> &[SignatureShareV0] {
        &self.new_signatures
    }

    pub fn id(&self) -> CertificateId {
        CertificateId::new(canonical_hash(DOMAIN_HANDOFF_CERTIFICATE, |encoder| {
            self.encode_cev0(encoder);
        }))
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    pub fn validate_shape(
        &self,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<()> {
        self.descriptor.validate_shape()?;
        validate_descriptor_set_binding(&self.descriptor, old_validator_set, new_validator_set)?;
        validate_handoff_shares(&self.old_signatures, old_validator_set, "old")?;
        validate_handoff_shares(&self.new_signatures, new_validator_set, "new")
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape(old_validator_set, new_validator_set)?;
        verify_handoff_shares(
            &self.old_signatures,
            old_validator_set,
            handoff_vote_signing_root(&self.descriptor, MessageKind::OldSetHandoffVote),
            verifier,
        )?;
        verify_handoff_shares(
            &self.new_signatures,
            new_validator_set,
            handoff_vote_signing_root(&self.descriptor, MessageKind::NewSetHandoffVote),
            verifier,
        )
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.u16(SCHEMA_VERSION_V0);
        self.descriptor.encode_cev0(encoder);
        encoder.list_len(self.old_signatures.len());
        for share in &self.old_signatures {
            share.encode_cev0(encoder);
        }
        encoder.list_len(self.new_signatures.len());
        for share in &self.new_signatures {
            share.encode_cev0(encoder);
        }
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        descriptor: HandoffDescriptorV0,
        old_signatures: Vec<SignatureShareV0>,
        new_signatures: Vec<SignatureShareV0>,
    ) -> Result<Self> {
        descriptor.validate_shape()?;
        validate_share_order_only(&old_signatures)?;
        validate_share_order_only(&new_signatures)?;
        if old_signatures.is_empty() || new_signatures.is_empty() {
            return Err(ValidationError::InvalidJointCertificate(
                "handoff certificate omits one signer role",
            ));
        }
        Ok(Self {
            descriptor,
            old_signatures,
            new_signatures,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochAnchorAuthorizationV0 {
    terminal_old_header: BlockHeader,
    terminal_old_qc: QuorumCertificate,
    handoff_certificate: HandoffCertificateV0,
}

impl EpochAnchorAuthorizationV0 {
    pub(crate) fn new(
        terminal_old_header: BlockHeader,
        terminal_old_qc: QuorumCertificate,
        handoff_certificate: HandoffCertificateV0,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<Self> {
        let value = Self {
            terminal_old_header,
            terminal_old_qc,
            handoff_certificate,
        };
        value.validate_shape(old_validator_set, new_validator_set)?;
        Ok(value)
    }

    pub const fn terminal_old_header(&self) -> &BlockHeader {
        &self.terminal_old_header
    }

    pub const fn terminal_old_qc(&self) -> &QuorumCertificate {
        &self.terminal_old_qc
    }

    pub const fn handoff_certificate(&self) -> &HandoffCertificateV0 {
        &self.handoff_certificate
    }

    pub(crate) fn epoch_anchor_qc(&self) -> EpochAnchorQcV0 {
        let descriptor = self.handoff_certificate.descriptor.fields();
        EpochAnchorQcV0::from_handoff_parts(
            descriptor.genesis_hash,
            descriptor.chain_id,
            descriptor.new_protocol_version,
            descriptor.new_epoch,
            descriptor.new_validator_set_hash,
            descriptor.terminal_old_height,
            descriptor.terminal_old_block_id,
        )
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    pub fn validate_shape(
        &self,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
    ) -> Result<()> {
        self.handoff_certificate
            .validate_shape(old_validator_set, new_validator_set)?;
        self.terminal_old_qc.validate_shape(old_validator_set)?;
        validate_authorization_relations(
            &self.terminal_old_header,
            &self.terminal_old_qc,
            &self.handoff_certificate,
        )
    }

    /// Verifies only the certificate kernel and returns no authorization.
    ///
    /// Full epoch-transition authorization additionally requires authenticated
    /// checkpoint/two-seal ancestry and the committed next runtime/set context.
    /// Until that trusted capability exists, successful certificate checks
    /// must not mint or return an `EpochAnchorQcV0`.
    pub(crate) fn verify_certificate_kernel<V: SignatureVerifier>(
        &self,
        old_validator_set: &ValidatorSet,
        new_validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape(old_validator_set, new_validator_set)?;
        self.terminal_old_qc.verify(old_validator_set, verifier)?;
        self.handoff_certificate
            .verify(old_validator_set, new_validator_set, verifier)
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        self.terminal_old_header.encode_cev0(encoder);
        self.terminal_old_qc.encode_cev0(encoder);
        self.handoff_certificate.encode_cev0(encoder);
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        terminal_old_header: BlockHeader,
        terminal_old_qc: QuorumCertificate,
        handoff_certificate: HandoffCertificateV0,
    ) -> Result<Self> {
        validate_authorization_relations(
            &terminal_old_header,
            &terminal_old_qc,
            &handoff_certificate,
        )?;
        Ok(Self {
            terminal_old_header,
            terminal_old_qc,
            handoff_certificate,
        })
    }
}

fn validate_descriptor_set_binding(
    descriptor: &HandoffDescriptorV0,
    old_set: &ValidatorSet,
    new_set: &ValidatorSet,
) -> Result<()> {
    old_set.validate_shape()?;
    new_set.validate_shape()?;
    let fields = descriptor.fields();
    let old = (
        old_set.genesis_hash(),
        old_set.chain_id(),
        old_set.protocol_version(),
        old_set.epoch(),
        old_set.id(),
        old_set.consensus_parameters_hash(),
    );
    let expected_old = (
        fields.genesis_hash,
        fields.chain_id,
        fields.old_protocol_version,
        fields.old_epoch,
        fields.old_validator_set_hash,
        fields.old_consensus_parameters_hash,
    );
    if old != expected_old {
        return Err(ValidationError::InvalidEpochTransition(
            "old validator set does not match handoff descriptor",
        ));
    }
    let new = (
        new_set.genesis_hash(),
        new_set.chain_id(),
        new_set.protocol_version(),
        new_set.epoch(),
        new_set.id(),
        new_set.consensus_parameters_hash(),
    );
    let expected_new = (
        fields.genesis_hash,
        fields.chain_id,
        fields.new_protocol_version,
        fields.new_epoch,
        fields.new_validator_set_hash,
        fields.new_consensus_parameters_hash,
    );
    if new != expected_new {
        return Err(ValidationError::InvalidEpochTransition(
            "new validator set does not match handoff descriptor",
        ));
    }
    Ok(())
}

fn validate_handoff_shares(
    shares: &[SignatureShareV0],
    validator_set: &ValidatorSet,
    role: &'static str,
) -> Result<()> {
    let mut previous = None;
    let mut signed_power = 0u128;
    for share in shares {
        share.signature.validate_shape()?;
        validate_signer_order(&mut previous, share.validator_id)?;
        signed_power =
            signed_power
                .checked_add(validator_set.power_of(share.validator_id).ok_or_else(|| {
                    ValidationError::UnknownValidator(Box::new(share.validator_id))
                })?)
                .ok_or(ValidationError::ArithmeticOverflow("handoff signed power"))?;
    }
    if signed_power < validator_set.quorum_power() {
        return Err(ValidationError::InvalidJointCertificate(match role {
            "old" => "old-set handoff signatures do not reach quorum",
            _ => "new-set handoff signatures do not reach quorum",
        }));
    }
    Ok(())
}

#[cfg(test)]
fn validate_share_order_only(shares: &[SignatureShareV0]) -> Result<()> {
    let mut previous = None;
    for share in shares {
        share.signature.validate_shape()?;
        validate_signer_order(&mut previous, share.validator_id)?;
    }
    Ok(())
}

fn verify_handoff_shares<V: SignatureVerifier>(
    shares: &[SignatureShareV0],
    validator_set: &ValidatorSet,
    signing_root: SigningRoot,
    verifier: &V,
) -> Result<()> {
    for share in shares {
        let validator = validator_set
            .validator(share.validator_id)
            .ok_or_else(|| ValidationError::UnknownValidator(Box::new(share.validator_id)))?;
        if !verifier.verify(validator, &signing_root, &share.signature) {
            return Err(ValidationError::InvalidSignature(Box::new(
                share.validator_id,
            )));
        }
    }
    Ok(())
}

fn handoff_vote_signing_root(descriptor: &HandoffDescriptorV0, role: MessageKind) -> SigningRoot {
    let fields = descriptor.fields();
    let (version, epoch, set_hash, view) = match role {
        MessageKind::OldSetHandoffVote => (
            fields.old_protocol_version,
            fields.old_epoch,
            fields.old_validator_set_hash,
            fields.terminal_old_view,
        ),
        MessageKind::NewSetHandoffVote => (
            fields.new_protocol_version,
            fields.new_epoch,
            fields.new_validator_set_hash,
            fields.initial_new_view,
        ),
        _ => unreachable!("handoff signing root requires a handoff role"),
    };
    signing_root(DOMAIN_HANDOFF_VOTE, |encoder| {
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.fixed(fields.genesis_hash.as_bytes());
        encoder.consensus_string(fields.chain_id.as_bytes());
        encoder.u32(version.get());
        encoder.u64(epoch.get());
        encoder.fixed(set_hash.as_bytes());
        encoder.u64(view.get());
        encoder.u8(role as u8);
        encoder.fixed(descriptor.id().as_bytes());
    })
}

fn validate_authorization_relations(
    terminal_header: &BlockHeader,
    terminal_qc: &QuorumCertificate,
    handoff_certificate: &HandoffCertificateV0,
) -> Result<()> {
    terminal_header.validate_shape()?;
    if terminal_header.block_kind() != BlockKind::EpochSeal2 {
        return Err(ValidationError::InvalidEpochTransition(
            "terminal old block is not epoch_seal_2",
        ));
    }
    let fields = handoff_certificate.descriptor.fields();
    if terminal_header.genesis_hash() != fields.genesis_hash
        || terminal_header.chain_id() != fields.chain_id
        || terminal_header.protocol_version() != fields.old_protocol_version
        || terminal_header.epoch() != fields.old_epoch
        || terminal_header.validator_set_id() != fields.old_validator_set_hash
        || terminal_header.consensus_parameters_hash() != fields.old_consensus_parameters_hash
        || terminal_header.view() != fields.terminal_old_view
        || terminal_header.height() != fields.terminal_old_height
        || terminal_header.id() != fields.terminal_old_block_id
        || terminal_header.state_root() != fields.checkpoint_state_root
        || terminal_header.next_epoch_commitment_hash() != Some(fields.next_epoch_commitment_digest)
    {
        return Err(ValidationError::InvalidEpochTransition(
            "terminal old header does not match handoff descriptor",
        ));
    }
    if terminal_qc.genesis_hash() != terminal_header.genesis_hash()
        || terminal_qc.chain_id() != terminal_header.chain_id()
        || terminal_qc.protocol_version() != terminal_header.protocol_version()
        || terminal_qc.epoch() != terminal_header.epoch()
        || terminal_qc.validator_set_id() != terminal_header.validator_set_id()
        || terminal_qc.view() != terminal_header.view()
        || terminal_qc.height() != terminal_header.height()
        || terminal_qc.block_id() != terminal_header.id()
        || terminal_qc.id() != fields.terminal_old_qc_digest
    {
        return Err(ValidationError::InvalidEpochTransition(
            "terminal old QC does not certify the descriptor header",
        ));
    }
    Ok(())
}
