use alloc::vec::Vec;

use crate::{
    canonical::{canonical_hash, try_canonical_bytes, Encoder, DOMAIN_FINALITY_PROOF},
    BlockHeader, CertificateId, ChainId, ConsensusParametersHash, ConsensusParametersV0, Epoch,
    EpochAnchorAuthorizationV0, GenesisHash, ProposalWitnessV0, ProtocolVersion, QcReferenceV0,
    QuorumCertificate, Result, Signature64, SignatureVerifier, SignedProposalV0, SigningRoot,
    TimeoutCertificateV0, ValidationError, ValidatorSet, ValidatorSetId, SCHEMA_VERSION_V0,
};

/// Exact nested signed-header witness used by `FinalityProofV0`.
///
/// The certifying QC is intentionally an ordinary `QuorumCertificate`, while
/// the justify field uses `QcReferenceV0` so an explicitly contextual anchor
/// can appear only in the proposal position allowed by the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedHeaderV0 {
    header: BlockHeader,
    witness: ProposalWitnessV0,
    certifying_qc: QuorumCertificate,
}

impl CertifiedHeaderV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        header: BlockHeader,
        justify_qc: QcReferenceV0,
        timeout_certificate: Option<TimeoutCertificateV0>,
        epoch_anchor_authorization: Option<EpochAnchorAuthorizationV0>,
        proposer_signature: Signature64,
        certifying_qc: QuorumCertificate,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<Self> {
        let witness = ProposalWitnessV0::new(
            &header,
            justify_qc,
            timeout_certificate,
            epoch_anchor_authorization,
            proposer_signature,
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )?;
        Self::from_proposal_witness(
            header,
            witness,
            certifying_qc,
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )
    }

    /// Safely attaches an ordinary certifying QC to the exact proposal witness
    /// retained by the consensus core. The witness is revalidated against the
    /// supplied header; callers cannot substitute a different justification.
    #[allow(clippy::too_many_arguments)]
    pub fn from_proposal_witness(
        header: BlockHeader,
        witness: ProposalWitnessV0,
        certifying_qc: QuorumCertificate,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<Self> {
        let value = Self {
            header,
            witness,
            certifying_qc,
        };
        value.validate(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )?;
        Ok(value)
    }

    /// Drops the runtime payload while retaining the signed proposal witness
    /// verbatim, then validates the certifying QC against that exact header.
    #[allow(clippy::too_many_arguments)]
    pub fn from_signed_proposal(
        proposal: SignedProposalV0,
        certifying_qc: QuorumCertificate,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<Self> {
        let (block, witness) = proposal.into_parts();
        Self::from_proposal_witness(
            block.header().clone(),
            witness,
            certifying_qc,
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )
    }

    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub const fn witness(&self) -> &ProposalWitnessV0 {
        &self.witness
    }

    pub const fn justify_qc(&self) -> &QcReferenceV0 {
        self.witness.justify_qc()
    }

    pub fn timeout_certificate(&self) -> Option<&TimeoutCertificateV0> {
        self.witness.timeout_certificate()
    }

    pub fn epoch_anchor_authorization(&self) -> Option<&EpochAnchorAuthorizationV0> {
        self.witness.epoch_anchor_authorization()
    }

    pub const fn proposer_signature(&self) -> &Signature64 {
        self.witness.proposer_signature()
    }

    pub const fn certifying_qc(&self) -> &QuorumCertificate {
        &self.certifying_qc
    }

    pub fn proposal_signing_root(&self) -> SigningRoot {
        self.witness
            .signing_root_for_header(&self.header)
            .expect("CertifiedHeaderV0 stores a validated header and witness")
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    /// Performs bounded structural, certificate-shape, and set-binding checks.
    ///
    /// This is not the production consensus-validity entry point: it does not
    /// receive the committed parameter preimage, authenticate the scheduled
    /// leader, enforce the parent-relative maximum timestamp step, or verify
    /// signatures. Use [`Self::validate`] or [`Self::verify`] for those checks.
    pub fn validate_shape(
        &self,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
    ) -> Result<()> {
        self.validate_wire_relations()?;
        self.witness.validate_shape_for_header(
            &self.header,
            active_validator_set,
            old_validator_set,
        )?;
        self.certifying_qc.validate_shape(active_validator_set)?;
        Ok(())
    }

    /// Validates all deterministic proposal rules available to this semantic
    /// witness. `authenticated_parent_timestamp_ms` must come from the already
    /// authenticated parent header (or the trusted genesis document).
    pub fn validate(
        &self,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<()> {
        self.validate_wire_relations()?;
        self.certifying_qc.validate_shape(active_validator_set)?;
        self.witness.validate_for_header(
            &self.header,
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
        verifier: &V,
    ) -> Result<()> {
        self.validate(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )?;
        self.certifying_qc.verify(active_validator_set, verifier)?;
        self.witness.verify_for_header(
            &self.header,
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
            verifier,
        )
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        self.header.encode_cev0(encoder);
        self.witness.encode_certified_tail(encoder);
        self.certifying_qc.encode_cev0(encoder);
    }

    fn validate_wire_relations(&self) -> Result<()> {
        self.witness
            .validate_wire_relations_for_header(&self.header)?;
        if self.certifying_qc.votes().is_empty() {
            return Err(ValidationError::InvalidFinalityProof(
                "synthetic QC cannot certify a header",
            ));
        }
        validate_certifying_qc_binding(&self.header, &self.certifying_qc)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts_for_test(
        header: BlockHeader,
        justify_qc: QcReferenceV0,
        timeout_certificate: Option<TimeoutCertificateV0>,
        epoch_anchor_authorization: Option<EpochAnchorAuthorizationV0>,
        proposer_signature: Signature64,
        certifying_qc: QuorumCertificate,
    ) -> Result<Self> {
        let witness = ProposalWitnessV0::from_parts_for_test(
            justify_qc,
            timeout_certificate,
            epoch_anchor_authorization,
            proposer_signature,
        )?;
        Self::from_proposal_witness_for_test(header, witness, certifying_qc)
    }

    #[cfg(test)]
    pub(crate) fn from_proposal_witness_for_test(
        header: BlockHeader,
        witness: ProposalWitnessV0,
        certifying_qc: QuorumCertificate,
    ) -> Result<Self> {
        let value = Self {
            header,
            witness,
            certifying_qc,
        };
        value.validate_wire_relations()?;
        Ok(value)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts_unchecked_for_test(
        header: BlockHeader,
        justify_qc: QcReferenceV0,
        timeout_certificate: Option<TimeoutCertificateV0>,
        epoch_anchor_authorization: Option<EpochAnchorAuthorizationV0>,
        proposer_signature: Signature64,
        certifying_qc: QuorumCertificate,
    ) -> Self {
        let witness = ProposalWitnessV0::from_parts_unchecked_for_test(
            justify_qc,
            timeout_certificate,
            epoch_anchor_authorization,
            proposer_signature,
        );
        Self {
            header,
            witness,
            certifying_qc,
        }
    }
}

/// Exact frozen `FinalityProofV0`; unlike legacy `CommitProof`, it carries
/// complete signed proposal envelopes and exact nested certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityProofV0 {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_hash: ValidatorSetId,
    consensus_parameters_hash: ConsensusParametersHash,
    finalized_block: CertifiedHeaderV0,
    child: CertifiedHeaderV0,
    grandchild: CertifiedHeaderV0,
}

impl FinalityProofV0 {
    pub fn new(
        finalized_block: CertifiedHeaderV0,
        child: CertifiedHeaderV0,
        grandchild: CertifiedHeaderV0,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_finalized_parent_timestamp_ms: u64,
    ) -> Result<Self> {
        let header = finalized_block.header();
        let value = Self {
            genesis_hash: header.genesis_hash(),
            chain_id: header.chain_id(),
            protocol_version: header.protocol_version(),
            epoch: header.epoch(),
            validator_set_hash: header.validator_set_id(),
            consensus_parameters_hash: header.consensus_parameters_hash(),
            finalized_block,
            child,
            grandchild,
        };
        value.validate(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_finalized_parent_timestamp_ms,
        )?;
        Ok(value)
    }

    pub const fn finalized_block(&self) -> &CertifiedHeaderV0 {
        &self.finalized_block
    }

    pub const fn child(&self) -> &CertifiedHeaderV0 {
        &self.child
    }

    pub const fn grandchild(&self) -> &CertifiedHeaderV0 {
        &self.grandchild
    }

    pub fn id(&self) -> CertificateId {
        CertificateId::new(canonical_hash(DOMAIN_FINALITY_PROOF, |encoder| {
            self.encode_cev0(encoder);
        }))
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    /// Performs shape, set, and exact nested-wire relationship checks only.
    /// It deliberately does not authenticate the parameter preimage,
    /// scheduled leaders, maximum timestamp steps, or signatures. Production
    /// callers must use [`Self::validate`] or [`Self::verify`].
    pub fn validate_shape(
        &self,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
    ) -> Result<()> {
        if self.genesis_hash != active_validator_set.genesis_hash()
            || self.chain_id != active_validator_set.chain_id()
            || self.protocol_version != active_validator_set.protocol_version()
            || self.epoch != active_validator_set.epoch()
            || self.validator_set_hash != active_validator_set.id()
            || self.consensus_parameters_hash != active_validator_set.consensus_parameters_hash()
        {
            return Err(ValidationError::InvalidFinalityProof(
                "proof scope does not match active validator set",
            ));
        }
        self.finalized_block
            .validate_shape(active_validator_set, old_validator_set)?;
        self.child
            .validate_shape(active_validator_set, old_validator_set)?;
        self.grandchild
            .validate_shape(active_validator_set, old_validator_set)?;
        self.validate_wire_relations()
    }

    /// Validates the complete deterministic, same-epoch three-chain using the
    /// active parameter preimage and the authenticated parent timestamp of the
    /// first certified header.
    pub fn validate(
        &self,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_finalized_parent_timestamp_ms: u64,
    ) -> Result<()> {
        self.validate_shape(active_validator_set, old_validator_set)?;
        consensus_parameters.validate_safety_invariants()?;
        if consensus_parameters.hash() != self.consensus_parameters_hash
            || consensus_parameters.hash() != active_validator_set.consensus_parameters_hash()
        {
            return Err(ValidationError::ConsensusParametersMismatch);
        }
        if consensus_parameters.finality_certified_chain_length() != 3 {
            return Err(ValidationError::InvalidFinalityProof(
                "active parameters do not require a three-certified-header chain",
            ));
        }
        self.finalized_block.validate(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_finalized_parent_timestamp_ms,
        )?;
        self.child.validate(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            self.finalized_block.header.timestamp_ms(),
        )?;
        self.grandchild.validate(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            self.child.header.timestamp_ms(),
        )
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_finalized_parent_timestamp_ms: u64,
        verifier: &V,
    ) -> Result<()> {
        self.validate(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_finalized_parent_timestamp_ms,
        )?;
        self.finalized_block.verify(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_finalized_parent_timestamp_ms,
            verifier,
        )?;
        self.child.verify(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            self.finalized_block.header.timestamp_ms(),
            verifier,
        )?;
        self.grandchild.verify(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            self.child.header.timestamp_ms(),
            verifier,
        )
    }

    pub(crate) fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.fixed(self.genesis_hash.as_bytes());
        encoder.consensus_string(self.chain_id.as_bytes());
        encoder.u32(self.protocol_version.get());
        encoder.u64(self.epoch.get());
        encoder.fixed(self.validator_set_hash.as_bytes());
        encoder.fixed(self.consensus_parameters_hash.as_bytes());
        self.finalized_block.encode_cev0(encoder);
        self.child.encode_cev0(encoder);
        self.grandchild.encode_cev0(encoder);
    }

    fn validate_wire_relations(&self) -> Result<()> {
        let scope = (
            self.genesis_hash,
            self.chain_id,
            self.protocol_version,
            self.epoch,
            self.validator_set_hash,
            self.consensus_parameters_hash,
        );
        for certified in [&self.finalized_block, &self.child, &self.grandchild] {
            let header = certified.header();
            if (
                header.genesis_hash(),
                header.chain_id(),
                header.protocol_version(),
                header.epoch(),
                header.validator_set_id(),
                header.consensus_parameters_hash(),
            ) != scope
            {
                return Err(ValidationError::InvalidFinalityProof(
                    "certified header crosses the proof scope",
                ));
            }
        }
        if self.child.header.parent_id() != self.finalized_block.header.id()
            || self.grandchild.header.parent_id() != self.child.header.id()
        {
            return Err(ValidationError::InvalidFinalityProof(
                "headers do not form a direct three-block chain",
            ));
        }
        if self.child.header.height() != self.finalized_block.header.height().checked_next()?
            || self.grandchild.header.height() != self.child.header.height().checked_next()?
        {
            return Err(ValidationError::InvalidFinalityProof(
                "three-chain heights are not consecutive",
            ));
        }
        if self.child.justify_qc().id() != self.finalized_block.certifying_qc.id() {
            return Err(ValidationError::InvalidFinalityProof(
                "child justify-QC digest differs from finalized certifying QC",
            ));
        }
        if self.grandchild.justify_qc().id() != self.child.certifying_qc.id() {
            return Err(ValidationError::InvalidFinalityProof(
                "grandchild justify-QC digest differs from child certifying QC",
            ));
        }
        for certified in [&self.finalized_block, &self.child, &self.grandchild] {
            certified.validate_wire_relations()?;
        }
        let views = (
            self.finalized_block.certifying_qc.view(),
            self.child.certifying_qc.view(),
            self.grandchild.certifying_qc.view(),
        );
        if !(views.0 < views.1 && views.1 < views.2) {
            return Err(ValidationError::InvalidFinalityProof(
                "certifying QC views are not strictly increasing",
            ));
        }
        if self.child.header.timestamp_ms() <= self.finalized_block.header.timestamp_ms()
            || self.grandchild.header.timestamp_ms() <= self.child.header.timestamp_ms()
        {
            return Err(ValidationError::InvalidFinalityProof(
                "three-chain timestamps are not strictly increasing",
            ));
        }
        if let Some(authorization) = self.finalized_block.epoch_anchor_authorization() {
            if self.finalized_block.header.timestamp_ms()
                <= authorization.terminal_old_header().timestamp_ms()
            {
                return Err(ValidationError::InvalidFinalityProof(
                    "first epoch block timestamp does not exceed terminal old timestamp",
                ));
            }
        }
        if self.child.epoch_anchor_authorization().is_some()
            || self.grandchild.epoch_anchor_authorization().is_some()
        {
            return Err(ValidationError::InvalidFinalityProof(
                "epoch-anchor authorization repeats after the first proof header",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        finalized_block: CertifiedHeaderV0,
        child: CertifiedHeaderV0,
        grandchild: CertifiedHeaderV0,
    ) -> Result<Self> {
        let header = finalized_block.header();
        let value = Self {
            genesis_hash: header.genesis_hash(),
            chain_id: header.chain_id(),
            protocol_version: header.protocol_version(),
            epoch: header.epoch(),
            validator_set_hash: header.validator_set_id(),
            consensus_parameters_hash: header.consensus_parameters_hash(),
            finalized_block,
            child,
            grandchild,
        };
        value.validate_wire_relations()?;
        Ok(value)
    }
}

fn validate_certifying_qc_binding(
    header: &BlockHeader,
    certificate: &QuorumCertificate,
) -> Result<()> {
    if certificate.genesis_hash() != header.genesis_hash()
        || certificate.chain_id() != header.chain_id()
        || certificate.protocol_version() != header.protocol_version()
        || certificate.epoch() != header.epoch()
        || certificate.validator_set_id() != header.validator_set_id()
        || certificate.view() != header.view()
        || certificate.height() != header.height()
        || certificate.block_id() != header.id()
    {
        return Err(ValidationError::InvalidFinalityProof(
            "certifying QC does not authenticate its exact header",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod parameter_context_tests {
    use super::*;
    use crate::{
        proposal_v0::{
            validate_parameters_binding, validate_scheduled_leader, validate_timestamp_step,
        },
        BlockId, BlockKind, ConsensusPublicKey, EvidenceRoot, GenesisQcV0, Height, PayloadDigest,
        ReceiptsRoot, StateRoot, Validator, ValidatorId, View, VotingPower, SIGNATURE_BYTES,
    };

    const TEST_CHAIN: ChainId = ChainId::from_static("trnm-finality-test-0");

    #[test]
    fn full_validation_context_binds_parameters_leader_and_timestamp_step() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = test_set(&parameters);
        let certified = test_certified(&set, validator_id(b"validator-a"), 101);
        let scheduled = certified.header();

        validate_parameters_binding(scheduled, &set, &parameters).unwrap();
        validate_scheduled_leader(scheduled, &set, &parameters).unwrap();
        validate_timestamp_step(100, 101, &parameters).unwrap();
        validate_timestamp_step(100, 100 + parameters.max_block_time_step_ms(), &parameters)
            .unwrap();
        certified.validate(&set, None, &parameters, 100).unwrap();

        assert_eq!(
            validate_timestamp_step(100, 100, &parameters),
            Err(ValidationError::InvalidProposal(
                "block timestamp is outside the parent-relative deterministic bound"
            ))
        );
        assert_eq!(
            validate_timestamp_step(100, 101 + parameters.max_block_time_step_ms(), &parameters,),
            Err(ValidationError::InvalidProposal(
                "block timestamp is outside the parent-relative deterministic bound"
            ))
        );
        assert_eq!(
            validate_timestamp_step(u64::MAX - 1, u64::MAX, &parameters),
            Err(ValidationError::ArithmeticOverflow(
                "parent timestamp plus max block time step"
            ))
        );

        let wrong_leader = test_certified(&set, validator_id(b"validator-b"), 101);
        assert_eq!(
            wrong_leader.validate(&set, None, &parameters, 100),
            Err(ValidationError::InvalidProposal(
                "proposer is not the scheduled leader"
            ))
        );

        let mut other_fields = parameters.fields();
        other_fields.max_block_time_step_ms += 1;
        let other_parameters = ConsensusParametersV0::new(other_fields).unwrap();
        assert_eq!(
            certified.validate(&set, None, &other_parameters, 100),
            Err(ValidationError::ConsensusParametersMismatch)
        );

        let too_late = test_certified(
            &set,
            validator_id(b"validator-a"),
            101 + parameters.max_block_time_step_ms(),
        );
        assert_eq!(
            too_late.validate(&set, None, &parameters, 100),
            Err(ValidationError::InvalidProposal(
                "block timestamp is outside the parent-relative deterministic bound"
            ))
        );
        assert_eq!(
            certified.validate(&set, None, &parameters, u64::MAX - 1),
            Err(ValidationError::ArithmeticOverflow(
                "parent timestamp plus max block time step"
            ))
        );

        let mut invalid_finality_fields = parameters.fields();
        invalid_finality_fields.finality_certified_chain_length = 2;
        assert_eq!(
            ConsensusParametersV0::new(invalid_finality_fields),
            Err(ValidationError::InvalidConsensusParameters(
                "v0 finality requires a direct three-certified-block chain"
            ))
        );
    }

    fn test_set(parameters: &ConsensusParametersV0) -> ValidatorSet {
        let validators = [
            (b"validator-a".as_slice(), 1u8),
            (b"validator-b".as_slice(), 2u8),
            (b"validator-c".as_slice(), 3u8),
            (b"validator-d".as_slice(), 4u8),
        ]
        .into_iter()
        .map(|(id, key)| {
            Validator::new(
                validator_id(id),
                ConsensusPublicKey::new([key; 32]),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()
        })
        .collect();
        ValidatorSet::new(
            GenesisHash::new([9; 32]),
            TEST_CHAIN,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap()
    }

    fn test_header(
        set: &ValidatorSet,
        view: View,
        proposer_id: ValidatorId,
        timestamp_ms: u64,
    ) -> BlockHeader {
        BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            view,
            Height::new(1),
            BlockKind::Regular,
            BlockId::new(*set.genesis_hash().as_bytes()),
            proposer_id,
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new([7; 32]),
            StateRoot::new([6; 32]),
            ReceiptsRoot::new([5; 32]),
            EvidenceRoot::new([4; 32]),
            timestamp_ms,
            None,
        )
        .unwrap()
    }

    fn test_certified(
        set: &ValidatorSet,
        proposer_id: ValidatorId,
        timestamp_ms: u64,
    ) -> CertifiedHeaderV0 {
        let header = test_header(set, View::new(1), proposer_id, timestamp_ms);
        let signatures = set.validators()[..3]
            .iter()
            .map(|validator| {
                (
                    validator.id(),
                    Signature64::from_array([1; SIGNATURE_BYTES]),
                )
            })
            .collect();
        let certifying_qc = QuorumCertificate::from_parts_for_test(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            header.view(),
            header.height(),
            header.id(),
            set.id(),
            signatures,
        )
        .unwrap();
        let genesis_qc = GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).unwrap();
        CertifiedHeaderV0::from_parts_for_test(
            header,
            QcReferenceV0::genesis_anchor(genesis_qc),
            None,
            None,
            Signature64::from_array([2; SIGNATURE_BYTES]),
            certifying_qc,
        )
        .unwrap()
    }

    fn validator_id(value: &[u8]) -> ValidatorId {
        ValidatorId::from_bytes(value).unwrap()
    }
}
