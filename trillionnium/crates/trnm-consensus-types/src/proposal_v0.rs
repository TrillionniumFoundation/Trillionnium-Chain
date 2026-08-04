use alloc::boxed::Box;

use crate::{
    canonical::Encoder, message::proposal_signing_root_from_digests, Block, BlockHeader, BlockKind,
    CanonicalSignable, CommonConsensusContextV0, ConsensusParametersV0, ContextAuthorizedQcV0,
    Epoch, EpochAnchorAuthorizationV0, LeaderSchedule, MessageKind, QcReferenceV0, Result,
    Signature64, SignatureVerifier, SigningRoot, TimeoutCertificateV0, ValidationError,
    ValidatorId, ValidatorSet,
};

/// The exact proposal fields retained after a block payload is discarded.
///
/// This value deliberately has no independent wire encoding or digest domain.
/// Its fields are the shared signed-proposal tail embedded by
/// [`CertifiedHeaderV0`](crate::CertifiedHeaderV0), in the frozen CEV0 order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalWitnessV0 {
    justify_qc: QcReferenceV0,
    timeout_certificate: Option<TimeoutCertificateV0>,
    epoch_anchor_authorization: Option<EpochAnchorAuthorizationV0>,
    proposer_signature: Signature64,
}

impl ProposalWitnessV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        header: &BlockHeader,
        justify_qc: QcReferenceV0,
        timeout_certificate: Option<TimeoutCertificateV0>,
        epoch_anchor_authorization: Option<EpochAnchorAuthorizationV0>,
        proposer_signature: Signature64,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<Self> {
        let value = Self {
            justify_qc,
            timeout_certificate,
            epoch_anchor_authorization,
            proposer_signature,
        };
        value.validate_for_header(
            header,
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )?;
        Ok(value)
    }

    pub const fn justify_qc(&self) -> &QcReferenceV0 {
        &self.justify_qc
    }

    pub fn timeout_certificate(&self) -> Option<&TimeoutCertificateV0> {
        self.timeout_certificate.as_ref()
    }

    pub fn epoch_anchor_authorization(&self) -> Option<&EpochAnchorAuthorizationV0> {
        self.epoch_anchor_authorization.as_ref()
    }

    pub const fn proposer_signature(&self) -> &Signature64 {
        &self.proposer_signature
    }

    /// Computes the frozen `ProposalSignV0` root without introducing a second
    /// proposal context, proposer identifier, or certificate digest field.
    pub fn signing_root_for(
        header: &BlockHeader,
        justify_qc: &QcReferenceV0,
        timeout_certificate: Option<&TimeoutCertificateV0>,
        epoch_anchor_authorization: Option<&EpochAnchorAuthorizationV0>,
    ) -> Result<SigningRoot> {
        header.validate_shape()?;
        let context = CommonConsensusContextV0::new(
            header.genesis_hash(),
            header.chain_id(),
            header.protocol_version(),
            header.epoch(),
            header.validator_set_id(),
            header.view(),
            MessageKind::Proposal,
        )?;
        Ok(proposal_signing_root_from_digests(
            context,
            header.height(),
            header.id(),
            justify_qc.id(),
            timeout_certificate.map(TimeoutCertificateV0::id),
            epoch_anchor_authorization
                .map(|authorization| authorization.handoff_certificate().id()),
        ))
    }

    pub fn signing_root_for_header(&self, header: &BlockHeader) -> Result<SigningRoot> {
        Self::signing_root_for(
            header,
            &self.justify_qc,
            self.timeout_certificate.as_ref(),
            self.epoch_anchor_authorization.as_ref(),
        )
    }

    /// Performs bounded structural, certificate-shape, and set-binding checks.
    /// Production admission should use [`Self::validate_for_header`] or
    /// [`Self::verify_for_header`].
    pub fn validate_shape_for_header(
        &self,
        header: &BlockHeader,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
    ) -> Result<()> {
        active_validator_set.validate_shape()?;
        validate_header_set_binding(header, active_validator_set)?;
        self.validate_wire_relations_for_header(header)?;
        match &self.justify_qc {
            QcReferenceV0::Ordinary(certificate) => {
                certificate.validate_shape(active_validator_set)?;
            }
            QcReferenceV0::Synthetic(synthetic) => match synthetic.as_ref() {
                ContextAuthorizedQcV0::Genesis(anchor) => {
                    anchor.matches_trusted_set(active_validator_set)?;
                }
                ContextAuthorizedQcV0::Epoch(anchor) => {
                    let authorization = self.epoch_anchor_authorization.as_ref().ok_or(
                        ValidationError::InvalidProposal("epoch anchor lacks atomic authorization"),
                    )?;
                    let old_validator_set =
                        old_validator_set.ok_or(ValidationError::InvalidProposal(
                            "epoch anchor lacks the old validator set",
                        ))?;
                    authorization.validate_shape(old_validator_set, active_validator_set)?;
                    if &authorization.epoch_anchor_qc() != anchor {
                        return Err(ValidationError::InvalidProposal(
                            "justify epoch anchor differs from authorization",
                        ));
                    }
                }
            },
        }
        if let Some(certificate) = &self.timeout_certificate {
            certificate.validate_shape(active_validator_set)?;
        }
        Ok(())
    }

    /// Validates all deterministic proposal rules available to this witness.
    /// `authenticated_parent_timestamp_ms` must come from the authenticated
    /// parent header or the trusted genesis document.
    pub fn validate_for_header(
        &self,
        header: &BlockHeader,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<()> {
        self.validate_shape_for_header(header, active_validator_set, old_validator_set)?;
        validate_parameters_binding(header, active_validator_set, consensus_parameters)?;
        validate_scheduled_leader(header, active_validator_set, consensus_parameters)?;
        if let Some(authorization) = self.epoch_anchor_authorization() {
            if authenticated_parent_timestamp_ms
                != authorization.terminal_old_header().timestamp_ms()
            {
                return Err(ValidationError::InvalidProposal(
                    "authenticated parent timestamp differs from terminal old header",
                ));
            }
        }
        validate_timestamp_step(
            authenticated_parent_timestamp_ms,
            header.timestamp_ms(),
            consensus_parameters,
        )
    }

    pub fn verify_for_header<V: SignatureVerifier>(
        &self,
        header: &BlockHeader,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
        verifier: &V,
    ) -> Result<()> {
        self.validate_for_header(
            header,
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )?;
        match &self.justify_qc {
            QcReferenceV0::Ordinary(certificate) => {
                certificate.verify(active_validator_set, verifier)?;
            }
            QcReferenceV0::Synthetic(synthetic) => match synthetic.as_ref() {
                ContextAuthorizedQcV0::Genesis(anchor) => {
                    anchor.matches_trusted_set(active_validator_set)?;
                }
                ContextAuthorizedQcV0::Epoch(anchor) => {
                    let authorization = self.epoch_anchor_authorization.as_ref().ok_or(
                        ValidationError::InvalidProposal("epoch anchor lacks atomic authorization"),
                    )?;
                    let old_validator_set =
                        old_validator_set.ok_or(ValidationError::InvalidProposal(
                            "epoch anchor lacks the old validator set",
                        ))?;
                    if &authorization.verify(old_validator_set, active_validator_set, verifier)?
                        != anchor
                    {
                        return Err(ValidationError::InvalidProposal(
                            "verified authorization produced another epoch anchor",
                        ));
                    }
                }
            },
        }
        if let Some(certificate) = &self.timeout_certificate {
            let epoch_context = self
                .epoch_anchor_authorization
                .as_ref()
                .zip(old_validator_set);
            certificate.verify(active_validator_set, epoch_context, verifier)?;
        }
        let proposer = active_validator_set
            .validator(header.proposer_id())
            .ok_or_else(|| ValidationError::UnknownValidator(Box::new(header.proposer_id())))?;
        let signing_root = self.signing_root_for_header(header)?;
        if !verifier.verify(proposer, &signing_root, &self.proposer_signature) {
            return Err(ValidationError::InvalidSignature(Box::new(
                header.proposer_id(),
            )));
        }
        Ok(())
    }

    pub(crate) fn encode_certified_tail(&self, encoder: &mut Encoder) {
        self.justify_qc.encode_cev0(encoder);
        encoder.optional(self.timeout_certificate.is_some(), |encoder| {
            self.timeout_certificate
                .as_ref()
                .expect("optional tag is present")
                .encode_cev0(encoder);
        });
        encoder.optional(self.epoch_anchor_authorization.is_some(), |encoder| {
            self.epoch_anchor_authorization
                .as_ref()
                .expect("optional tag is present")
                .encode_cev0(encoder);
        });
        encoder.fixed(self.proposer_signature.as_bytes());
    }

    pub(crate) fn validate_wire_relations_for_header(&self, header: &BlockHeader) -> Result<()> {
        header.validate_shape()?;
        self.proposer_signature.validate_shape()?;

        let justify = self.justify_qc.qc_ref();
        match &self.justify_qc {
            QcReferenceV0::Ordinary(certificate) => {
                if certificate.votes().is_empty() {
                    return Err(ValidationError::InvalidProposal(
                        "ordinary justify QC has no signatures",
                    ));
                }
                if self.epoch_anchor_authorization.is_some() {
                    return Err(ValidationError::InvalidProposal(
                        "ordinary proposal carries epoch-anchor authorization",
                    ));
                }
                if header.block_kind() == BlockKind::EpochHandoff {
                    return Err(ValidationError::InvalidProposal(
                        "epoch-handoff block does not use EpochAnchorQC",
                    ));
                }
                validate_ordinary_parent(header, justify)?;
            }
            QcReferenceV0::Synthetic(synthetic) => match synthetic.as_ref() {
                ContextAuthorizedQcV0::Genesis(anchor) => {
                    if self.epoch_anchor_authorization.is_some()
                        || header.epoch() != Epoch::new(0)
                        || header.height().get() != 1
                        || header.parent_id() != anchor.block_id()
                        || header.block_kind() != BlockKind::Regular
                    {
                        return Err(ValidationError::InvalidProposal(
                            "GenesisQC is outside the genesis-first proposal context",
                        ));
                    }
                }
                ContextAuthorizedQcV0::Epoch(anchor) => {
                    let authorization = self.epoch_anchor_authorization.as_ref().ok_or(
                        ValidationError::InvalidProposal(
                            "EpochAnchorQC lacks atomic authorization",
                        ),
                    )?;
                    if &authorization.epoch_anchor_qc() != anchor {
                        return Err(ValidationError::InvalidProposal(
                            "EpochAnchorQC differs from atomic authorization",
                        ));
                    }
                    let descriptor = authorization.handoff_certificate().descriptor().fields();
                    if header.genesis_hash() != descriptor.genesis_hash
                        || header.chain_id() != descriptor.chain_id
                        || header.protocol_version() != descriptor.new_protocol_version
                        || header.epoch() != descriptor.new_epoch
                        || header.validator_set_id() != descriptor.new_validator_set_hash
                        || header.consensus_parameters_hash()
                            != descriptor.new_consensus_parameters_hash
                        || header.height() != descriptor.activation_height
                        || header.parent_id() != descriptor.terminal_old_block_id
                        || header.block_kind() != BlockKind::EpochHandoff
                    {
                        return Err(ValidationError::InvalidProposal(
                            "first epoch block does not match handoff descriptor",
                        ));
                    }
                }
            },
        }

        if header.view() <= justify.view() {
            return Err(ValidationError::InvalidProposal(
                "proposal view does not exceed justify-QC view",
            ));
        }
        match &self.timeout_certificate {
            None => {
                if header.view() != justify.view().checked_next()? {
                    return Err(ValidationError::InvalidProposal(
                        "proposal skips a view without a TC",
                    ));
                }
            }
            Some(certificate) => {
                if header.view() == justify.view().checked_next()? {
                    return Err(ValidationError::InvalidProposal(
                        "next-view proposal carries a redundant TC",
                    ));
                }
                if certificate.timed_out_view().checked_next()? != header.view() {
                    return Err(ValidationError::InvalidProposal(
                        "TC is not for proposal.view - 1",
                    ));
                }
                if certificate.selected_high_qc_digest() != self.justify_qc.id() {
                    return Err(ValidationError::InvalidProposal(
                        "TC does not select the exact justify QC",
                    ));
                }
                if !certificate
                    .referenced_qcs()
                    .iter()
                    .any(|candidate| candidate == &self.justify_qc)
                {
                    return Err(ValidationError::InvalidProposal(
                        "TC omits the exact justify QC",
                    ));
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        justify_qc: QcReferenceV0,
        timeout_certificate: Option<TimeoutCertificateV0>,
        epoch_anchor_authorization: Option<EpochAnchorAuthorizationV0>,
        proposer_signature: Signature64,
    ) -> Result<Self> {
        proposer_signature.validate_shape()?;
        Ok(Self {
            justify_qc,
            timeout_certificate,
            epoch_anchor_authorization,
            proposer_signature,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_parts_unchecked_for_test(
        justify_qc: QcReferenceV0,
        timeout_certificate: Option<TimeoutCertificateV0>,
        epoch_anchor_authorization: Option<EpochAnchorAuthorizationV0>,
        proposer_signature: Signature64,
    ) -> Self {
        Self {
            justify_qc,
            timeout_certificate,
            epoch_anchor_authorization,
            proposer_signature,
        }
    }
}

/// A full signed proposal carrying the runtime-defined block body and the one
/// exact proposal witness later retained in a finality proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProposalV0 {
    block: Block,
    witness: ProposalWitnessV0,
}

impl SignedProposalV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block: Block,
        witness: ProposalWitnessV0,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<Self> {
        let value = Self { block, witness };
        value.validate(
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )?;
        Ok(value)
    }

    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub const fn witness(&self) -> &ProposalWitnessV0 {
        &self.witness
    }

    pub const fn proposer(&self) -> ValidatorId {
        self.block.header().proposer_id()
    }

    pub fn proposal_signing_root(&self) -> SigningRoot {
        self.witness
            .signing_root_for_header(self.block.header())
            .expect("SignedProposalV0 stores a validated header and witness")
    }

    pub fn into_parts(self) -> (Block, ProposalWitnessV0) {
        (self.block, self.witness)
    }

    pub fn validate_shape(
        &self,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
    ) -> Result<()> {
        self.block.validate_shape()?;
        self.witness.validate_shape_for_header(
            self.block.header(),
            active_validator_set,
            old_validator_set,
        )
    }

    pub fn validate(
        &self,
        active_validator_set: &ValidatorSet,
        old_validator_set: Option<&ValidatorSet>,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<()> {
        self.block.validate_shape()?;
        self.witness.validate_for_header(
            self.block.header(),
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
        self.block.validate_shape()?;
        self.witness.verify_for_header(
            self.block.header(),
            active_validator_set,
            old_validator_set,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
            verifier,
        )
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        let left = self.block.header();
        let right = other.block.header();
        left.genesis_hash() == right.genesis_hash()
            && left.chain_id() == right.chain_id()
            && left.protocol_version() == right.protocol_version()
            && left.epoch() == right.epoch()
            && left.view() == right.view()
            && left.validator_set_id() == right.validator_set_id()
            && left.proposer_id() == right.proposer_id()
            && self.proposal_signing_root() != other.proposal_signing_root()
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(block: Block, witness: ProposalWitnessV0) -> Result<Self> {
        block.validate_shape()?;
        witness.validate_wire_relations_for_header(block.header())?;
        Ok(Self { block, witness })
    }
}

impl CanonicalSignable for SignedProposalV0 {
    fn signing_root(&self) -> SigningRoot {
        self.proposal_signing_root()
    }
}

pub(crate) fn validate_header_set_binding(header: &BlockHeader, set: &ValidatorSet) -> Result<()> {
    if header.genesis_hash() != set.genesis_hash() {
        return Err(ValidationError::GenesisHashMismatch);
    }
    if header.chain_id() != set.chain_id() {
        return Err(ValidationError::ChainIdMismatch);
    }
    if header.protocol_version() != set.protocol_version() {
        return Err(ValidationError::ProtocolVersionMismatch);
    }
    if header.epoch() != set.epoch() {
        return Err(ValidationError::EpochMismatch);
    }
    if header.validator_set_id() != set.id() {
        return Err(ValidationError::ValidatorSetMismatch);
    }
    if header.consensus_parameters_hash() != set.consensus_parameters_hash() {
        return Err(ValidationError::ConsensusParametersMismatch);
    }
    Ok(())
}

pub(crate) fn validate_parameters_binding(
    header: &BlockHeader,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> Result<()> {
    parameters.validate_safety_invariants()?;
    if parameters.hash() != set.consensus_parameters_hash()
        || parameters.hash() != header.consensus_parameters_hash()
    {
        return Err(ValidationError::ConsensusParametersMismatch);
    }
    if parameters.protocol_version() != header.protocol_version().get() {
        return Err(ValidationError::ProtocolVersionMismatch);
    }
    Ok(())
}

pub(crate) fn validate_scheduled_leader(
    header: &BlockHeader,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> Result<()> {
    let view_index = header
        .view()
        .get()
        .checked_sub(1)
        .ok_or(ValidationError::InvalidProposal(
            "network proposal view must be positive",
        ))?;
    let leader_index = match parameters.leader_schedule() {
        LeaderSchedule::CanonicalValidatorRoundRobin => {
            (view_index % set.validators().len() as u64) as usize
        }
    };
    if set.validators()[leader_index].id() != header.proposer_id() {
        return Err(ValidationError::InvalidProposal(
            "proposer is not the scheduled leader",
        ));
    }
    Ok(())
}

pub(crate) fn validate_timestamp_step(
    parent_timestamp_ms: u64,
    block_timestamp_ms: u64,
    parameters: &ConsensusParametersV0,
) -> Result<()> {
    let maximum = parent_timestamp_ms
        .checked_add(parameters.max_block_time_step_ms())
        .ok_or(ValidationError::ArithmeticOverflow(
            "parent timestamp plus max block time step",
        ))?;
    if block_timestamp_ms <= parent_timestamp_ms || block_timestamp_ms > maximum {
        return Err(ValidationError::InvalidProposal(
            "block timestamp is outside the parent-relative deterministic bound",
        ));
    }
    Ok(())
}

fn validate_ordinary_parent(header: &BlockHeader, justify: crate::QcRef) -> Result<()> {
    if justify.epoch() != header.epoch()
        || justify.validator_set_id() != header.validator_set_id()
        || justify.height().checked_next()? != header.height()
        || justify.block_id() != header.parent_id()
    {
        return Err(ValidationError::InvalidProposal(
            "ordinary justify QC does not certify the exact parent",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec, vec::Vec};

    use super::*;
    use crate::{
        BlockId, CertifiedHeaderV0, ConsensusPublicKey, EvidenceRoot, GenesisHash, GenesisQcV0,
        Height, PayloadDigest, ProtocolVersion, QuorumCertificate, ReceiptsRoot, SignatureBytes,
        StateRoot, TimeoutEntryV0, Validator, ValidatorSet, View, Vote, VotingPower,
        SIGNATURE_BYTES,
    };

    const TEST_CHAIN: crate::ChainId = crate::ChainId::from_static("trnm-proposal-v0-test");
    const PARENT_TIMESTAMP_MS: u64 = 100;

    #[test]
    fn genesis_anchor_view_one_round_trips_one_witness_into_certified_header() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = test_set(&parameters);
        let anchor = GenesisQcV0::new(set.genesis_hash(), set.chain_id(), &set).unwrap();
        let header = test_header(
            &set,
            View::new(1),
            Height::new(1),
            BlockId::new(*set.genesis_hash().as_bytes()),
            set.validators()[0].id(),
            PARENT_TIMESTAMP_MS + 1,
        );
        let block = Block::new(header.clone(), vec![1, 2, 3]).unwrap();
        let witness = ProposalWitnessV0::new(
            &header,
            QcReferenceV0::genesis_anchor(anchor),
            None,
            None,
            signature(9),
            &set,
            None,
            &parameters,
            PARENT_TIMESTAMP_MS,
        )
        .unwrap();
        let expected_root = witness.signing_root_for_header(&header).unwrap();
        let proposal = SignedProposalV0::new(
            block.clone(),
            witness.clone(),
            &set,
            None,
            &parameters,
            PARENT_TIMESTAMP_MS,
        )
        .unwrap();

        assert_eq!(proposal.signing_root(), expected_root);
        proposal
            .verify(
                &set,
                None,
                &parameters,
                PARENT_TIMESTAMP_MS,
                &AcceptAllSignatures,
            )
            .unwrap();
        assert_eq!(
            proposal.verify(
                &set,
                None,
                &parameters,
                PARENT_TIMESTAMP_MS,
                &RejectSignature(signature(9)),
            ),
            Err(ValidationError::InvalidSignature(Box::new(
                header.proposer_id()
            )))
        );

        let certified = CertifiedHeaderV0::from_signed_proposal(
            proposal.clone(),
            qc_for_header(&set, &header, 1),
            &set,
            None,
            &parameters,
            PARENT_TIMESTAMP_MS,
        )
        .unwrap();
        assert_eq!(certified.header(), &header);
        assert_eq!(certified.witness(), &witness);
        assert_eq!(certified.proposal_signing_root(), expected_root);
        certified
            .verify(
                &set,
                None,
                &parameters,
                PARENT_TIMESTAMP_MS,
                &AcceptAllSignatures,
            )
            .unwrap();

        let (round_trip_block, round_trip_witness) = proposal.into_parts();
        assert_eq!(round_trip_block, block);
        assert_eq!(round_trip_witness, witness);
    }

    #[test]
    fn skipped_genesis_view_requires_and_accepts_exact_anchor_tc() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = test_set(&parameters);
        let anchor = QcReferenceV0::genesis_anchor(
            GenesisQcV0::new(set.genesis_hash(), set.chain_id(), &set).unwrap(),
        );
        let header = test_header(
            &set,
            View::new(3),
            Height::new(1),
            BlockId::new(*set.genesis_hash().as_bytes()),
            set.validators()[2].id(),
            PARENT_TIMESTAMP_MS + 1,
        );

        assert_eq!(
            ProposalWitnessV0::new(
                &header,
                anchor.clone(),
                None,
                None,
                signature(9),
                &set,
                None,
                &parameters,
                PARENT_TIMESTAMP_MS,
            ),
            Err(ValidationError::InvalidProposal(
                "proposal skips a view without a TC"
            ))
        );

        let high_qc = anchor.qc_ref();
        let entries = set.validators()[..3]
            .iter()
            .map(|validator| TimeoutEntryV0::new(validator.id(), high_qc, signature(1)).unwrap())
            .collect();
        let timeout_certificate = TimeoutCertificateV0::new(
            View::new(2),
            entries,
            vec![anchor.clone()],
            anchor.id(),
            &set,
        )
        .unwrap();
        let witness = ProposalWitnessV0::new(
            &header,
            anchor,
            Some(timeout_certificate),
            None,
            signature(9),
            &set,
            None,
            &parameters,
            PARENT_TIMESTAMP_MS,
        )
        .unwrap();
        let proposal = SignedProposalV0::new(
            Block::new(header, vec![]).unwrap(),
            witness,
            &set,
            None,
            &parameters,
            PARENT_TIMESTAMP_MS,
        )
        .unwrap();
        proposal
            .verify(
                &set,
                None,
                &parameters,
                PARENT_TIMESTAMP_MS,
                &AcceptAllSignatures,
            )
            .unwrap();
    }

    #[test]
    fn ordinary_next_view_proposal_uses_its_exact_parent_qc() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = test_set(&parameters);
        let parent_header = test_header(
            &set,
            View::new(1),
            Height::new(1),
            BlockId::new(*set.genesis_hash().as_bytes()),
            set.validators()[0].id(),
            PARENT_TIMESTAMP_MS + 1,
        );
        let parent_qc = qc_for_header(&set, &parent_header, 1);
        let header = test_header(
            &set,
            View::new(2),
            Height::new(2),
            parent_header.id(),
            set.validators()[1].id(),
            PARENT_TIMESTAMP_MS + 2,
        );
        let witness = ProposalWitnessV0::new(
            &header,
            QcReferenceV0::ordinary(parent_qc.clone()),
            None,
            None,
            signature(9),
            &set,
            None,
            &parameters,
            parent_header.timestamp_ms(),
        )
        .unwrap();
        let proposal = SignedProposalV0::new(
            Block::new(header, vec![]).unwrap(),
            witness,
            &set,
            None,
            &parameters,
            parent_header.timestamp_ms(),
        )
        .unwrap();

        assert_eq!(
            proposal.witness().justify_qc().as_ordinary(),
            Some(&parent_qc)
        );
        proposal
            .verify(
                &set,
                None,
                &parameters,
                parent_header.timestamp_ms(),
                &AcceptAllSignatures,
            )
            .unwrap();
    }

    #[test]
    fn proposal_admission_fails_closed_on_leader_parameters_and_time() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = test_set(&parameters);
        let anchor = GenesisQcV0::new(set.genesis_hash(), set.chain_id(), &set).unwrap();
        let parent_id = BlockId::new(*set.genesis_hash().as_bytes());

        let wrong_leader = test_header(
            &set,
            View::new(1),
            Height::new(1),
            parent_id,
            set.validators()[1].id(),
            PARENT_TIMESTAMP_MS + 1,
        );
        assert_eq!(
            ProposalWitnessV0::new(
                &wrong_leader,
                QcReferenceV0::genesis_anchor(anchor.clone()),
                None,
                None,
                signature(9),
                &set,
                None,
                &parameters,
                PARENT_TIMESTAMP_MS,
            ),
            Err(ValidationError::InvalidProposal(
                "proposer is not the scheduled leader"
            ))
        );

        let valid_header = test_header(
            &set,
            View::new(1),
            Height::new(1),
            parent_id,
            set.validators()[0].id(),
            PARENT_TIMESTAMP_MS + 1,
        );
        let mut other_fields = parameters.fields();
        other_fields.max_block_time_step_ms += 1;
        let other_parameters = ConsensusParametersV0::new(other_fields).unwrap();
        assert_eq!(
            ProposalWitnessV0::new(
                &valid_header,
                QcReferenceV0::genesis_anchor(anchor.clone()),
                None,
                None,
                signature(9),
                &set,
                None,
                &other_parameters,
                PARENT_TIMESTAMP_MS,
            ),
            Err(ValidationError::ConsensusParametersMismatch)
        );

        let non_increasing_time = test_header(
            &set,
            View::new(1),
            Height::new(1),
            parent_id,
            set.validators()[0].id(),
            PARENT_TIMESTAMP_MS,
        );
        assert_eq!(
            ProposalWitnessV0::new(
                &non_increasing_time,
                QcReferenceV0::genesis_anchor(anchor),
                None,
                None,
                signature(9),
                &set,
                None,
                &parameters,
                PARENT_TIMESTAMP_MS,
            ),
            Err(ValidationError::InvalidProposal(
                "block timestamp is outside the parent-relative deterministic bound"
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
                crate::ValidatorId::from_bytes(id).unwrap(),
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
        height: Height,
        parent_id: BlockId,
        proposer_id: crate::ValidatorId,
        timestamp_ms: u64,
    ) -> BlockHeader {
        BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            view,
            height,
            BlockKind::Regular,
            parent_id,
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

    fn qc_for_header(
        set: &ValidatorSet,
        header: &BlockHeader,
        signature_byte: u8,
    ) -> QuorumCertificate {
        let votes = set.validators()[..3]
            .iter()
            .map(|validator| {
                Vote::new(
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    header.view(),
                    header.height(),
                    header.id(),
                    set.id(),
                    validator.id(),
                    signature(signature_byte),
                    set,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            header.view(),
            header.height(),
            header.id(),
            set.id(),
            votes,
            set,
        )
        .unwrap()
    }

    fn signature(byte: u8) -> Signature64 {
        Signature64::from_array([byte; SIGNATURE_BYTES])
    }

    struct AcceptAllSignatures;

    impl SignatureVerifier for AcceptAllSignatures {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            _signature: &SignatureBytes,
        ) -> bool {
            true
        }
    }

    struct RejectSignature(Signature64);

    impl SignatureVerifier for RejectSignature {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            signature: &SignatureBytes,
        ) -> bool {
            signature != &self.0
        }
    }
}
