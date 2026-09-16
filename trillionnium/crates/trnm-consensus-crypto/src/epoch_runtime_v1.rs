//! Strict complete-epoch verification context. No Core, storage or signer lease.
use crate::{StrictEd25519Verifier, StrictSameVersionEpochActivationAuthorityV0};
use trnm_consensus_types::{
    decode_double_vote_evidence_v0_exact, decode_epoch_activation_evidence_v0_exact,
    decode_epoch_runtime_finality_proof_v1_exact_with_budget,
    decode_epoch_runtime_qc_reference_v1_exact_with_budget,
    decode_epoch_runtime_timeout_certificate_v1_exact_with_budget, validate_empty_epoch_seal_v1,
    validate_root_bound_epoch_body_v1, validate_root_bound_regular_body_v0, BlockHeader, BlockKind,
    Cev0AdmissionBudgetV0, EpochActivationEvidenceBytesV0, EpochRuntimeContextDataV1,
    FinalityProofV0, QcReferenceV0, SignedProposalV0, TimeoutCertificateV0, ValidationError,
};

/// No-Clone strict context whose constructor consumes complete verified joint
/// activation evidence. Its anchor is scoped comparison data, not independent
/// activation authority. Concrete owners must additionally join storage and
/// custody before using this context to drive Core.
#[derive(Debug, PartialEq, Eq)]
pub struct StrictEpochRuntimeContextV1 {
    activation: StrictSameVersionEpochActivationAuthorityV0,
    data: EpochRuntimeContextDataV1,
    evidence: EpochActivationEvidenceBytesV0,
}
impl StrictEpochRuntimeContextV1 {
    pub fn from_activation_v1(
        activation: StrictSameVersionEpochActivationAuthorityV0,
    ) -> Result<Self, ValidationError> {
        let evidence = EpochActivationEvidenceBytesV0 {
            old_checkpoint_finality: activation.old_checkpoint_finality().try_cev0_bytes()?,
            next_epoch_commitment: activation.next_epoch_commitment().try_cev0_bytes()?,
            authorization_kernel: activation.authorization_cev0_bytes()?,
            old_validator_set: activation.old_validator_set().try_cev0_bytes()?,
            old_consensus_parameters: activation.old_consensus_parameters().canonical_bytes(),
            new_validator_set: activation.new_validator_set().try_cev0_bytes()?,
            new_consensus_parameters: activation.new_consensus_parameters().canonical_bytes(),
            authenticated_checkpoint_parent_header: activation
                .authenticated_checkpoint_parent_header()
                .try_cev0_bytes()?,
        };
        // A handoff can enlarge membership; old cardinality alone cannot bound
        // new-role shares. Keep the signed root ceiling and intrinsic complete-
        // context work cap, then meter actual old and new shares in the loader.
        let mut budget =
            Cev0AdmissionBudgetV0::for_parameters(activation.old_consensus_parameters());
        let decoded = decode_epoch_activation_evidence_v0_exact(
            evidence.as_preimages(),
            activation.old_validator_set(),
            activation.old_consensus_parameters(),
            &mut budget,
        )
        .map_err(|_| ValidationError::InvalidProposal("strict epoch context canonical evidence"))?;
        let data = EpochRuntimeContextDataV1::from_decoded_evidence_v1(&decoded)?;
        Ok(Self {
            activation,
            data,
            evidence,
        })
    }
    pub const fn activation(&self) -> &StrictSameVersionEpochActivationAuthorityV0 {
        &self.activation
    }
    pub const fn structural_context(&self) -> &EpochRuntimeContextDataV1 {
        &self.data
    }
    pub const fn evidence_bytes(&self) -> &EpochActivationEvidenceBytesV0 {
        &self.evidence
    }
    pub const fn anchor_reference(&self) -> &QcReferenceV0 {
        self.data.anchor_reference()
    }

    pub fn verify_qc_reference_v1(
        &self,
        reference: &QcReferenceV0,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<(), ValidationError> {
        budget
            .charge_qc_reference(reference)
            .map_err(|_| invalid("epoch QC work budget"))?;
        crate::strict_finality::verify_epoch_qc_reference(&self.activation, reference)
    }
    pub fn verify_timeout_certificate_v1(
        &self,
        certificate: &TimeoutCertificateV0,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<(), ValidationError> {
        budget
            .charge_timeout_certificate(certificate)
            .map_err(|_| invalid("epoch TC work budget"))?;
        crate::strict_finality::verify_epoch_timeout_certificate_strict_v1(
            &self.activation,
            certificate,
        )
    }
    pub fn decode_verify_qc_reference_v1(
        &self,
        raw: &[u8],
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<QcReferenceV0, ValidationError> {
        let reference =
            decode_epoch_runtime_qc_reference_v1_exact_with_budget(raw, &self.data, budget)
                .map_err(|_| invalid("epoch QC exact decoding"))?;
        crate::strict_finality::verify_epoch_qc_reference(&self.activation, &reference)?;
        Ok(reference)
    }
    pub fn decode_verify_timeout_certificate_v1(
        &self,
        raw: &[u8],
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<TimeoutCertificateV0, ValidationError> {
        let certificate =
            decode_epoch_runtime_timeout_certificate_v1_exact_with_budget(raw, &self.data, budget)
                .map_err(|_| invalid("epoch TC exact decoding"))?;
        crate::strict_finality::verify_epoch_timeout_certificate_strict_v1(
            &self.activation,
            &certificate,
        )?;
        Ok(certificate)
    }
    /// Strict preauthentication only: no timestamp/parent-state claim is made.
    /// Used solely to request a missing ordinary parent. Seals must wait for
    /// their exact parent roots; the first handoff already has its full parent.
    pub fn verify_proposal_without_parent_v1(
        &self,
        proposal: &SignedProposalV0,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<(), ValidationError> {
        let set = self.activation.new_validator_set();
        let parameters = self.activation.new_consensus_parameters();
        let header = proposal.block().header();
        proposal.validate_shape(set, Some(self.activation.old_validator_set()))?;
        let geometry = trnm_consensus_types::EpochGeometryV0::new(set.epoch(), parameters)?;
        if header.consensus_parameters_hash() != parameters.hash()
            || header.protocol_version().get() != parameters.protocol_version()
            || geometry.expected_block_kind(header.height())? != header.block_kind()
            || proposal.witness().epoch_anchor_authorization().is_some()
            || proposal.witness().justify_qc().as_ordinary().is_none()
        {
            return Err(invalid("missing-parent epoch proposal context"));
        }
        let index = header
            .view()
            .get()
            .checked_sub(1)
            .ok_or(invalid("zero proposal view"))?;
        if set.validators()[(index % set.validators().len() as u64) as usize].id()
            != header.proposer_id()
        {
            return Err(invalid("epoch proposal scheduled leader"));
        }
        let count = match header.block_kind() {
            BlockKind::Regular => {
                validate_root_bound_regular_body_v0(proposal.block(), set, parameters)
                    .map_err(|_| invalid("epoch regular body"))?
                    .evidence_count()
            }
            BlockKind::EpochCheckpoint => {
                validate_root_bound_epoch_body_v1(proposal.block(), set, parameters)
                    .map_err(|_| invalid("epoch checkpoint body"))?
                    .evidence_count()
            }
            _ => return Err(invalid("epoch seal/handoff requires exact parent")),
        };
        budget
            .admit_root_bytes(proposal.durable_validation_resource_size_v0()?)
            .map_err(|_| invalid("epoch proposal bytes"))?;
        let mut reserved = *budget;
        reserved
            .charge_qc_reference(proposal.witness().justify_qc())
            .map_err(|_| invalid("epoch QC work"))?;
        if let Some(tc) = proposal.witness().timeout_certificate() {
            reserved
                .charge_timeout_certificate(tc)
                .map_err(|_| invalid("epoch TC work"))?;
        }
        let work = (count as usize)
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(ValidationError::ArithmeticOverflow("epoch evidence work"))?;
        reserved
            .charge_signature_work(work)
            .map_err(|_| invalid("epoch signature work"))?;
        *budget = reserved;
        crate::strict_finality::verify_epoch_proposal_witness_strict_v1(
            &self.activation,
            header,
            proposal.witness(),
        )?;
        for raw in proposal.block().evidence_objects() {
            decode_double_vote_evidence_v0_exact(raw, set)
                .map_err(|_| invalid("epoch evidence"))?
                .verify(set, &StrictEd25519Verifier)?;
        }
        Ok(())
    }
    /// Full ordinary proposal check with a separately authenticated compact
    /// parent timestamp. Handoff and seals require the full-parent entry point.
    pub fn verify_proposal_at_parent_timestamp_v1(
        &self,
        proposal: &SignedProposalV0,
        parent_timestamp_ms: u64,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<(), ValidationError> {
        proposal.validate(
            self.activation.new_validator_set(),
            Some(self.activation.old_validator_set()),
            self.activation.new_consensus_parameters(),
            parent_timestamp_ms,
        )?;
        self.verify_proposal_without_parent_v1(proposal, budget)
    }
    pub fn verify_proposal_v1(
        &self,
        proposal: &SignedProposalV0,
        parent: &BlockHeader,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<(), ValidationError> {
        let header = proposal.block().header();
        if header.parent_id() != parent.id() || header.height() != parent.height().checked_next()? {
            return Err(invalid("epoch proposal exact parent"));
        }
        if header.block_kind() == BlockKind::EpochHandoff {
            if parent != self.activation.terminal_old_header() {
                return Err(invalid("first epoch parent substitution"));
            }
            crate::verify_first_epoch_proposal_strict_v1(
                &self.activation,
                proposal.clone(),
                budget,
            )?;
            return Ok(());
        }
        let set = self.activation.new_validator_set();
        let parameters = self.activation.new_consensus_parameters();
        if parent.epoch() != set.epoch()
            || parent.validator_set_id() != set.id()
            || parent.consensus_parameters_hash() != parameters.hash()
        {
            return Err(invalid("ordinary epoch parent context"));
        }
        budget
            .admit_root_bytes(proposal.durable_validation_resource_size_v0()?)
            .map_err(|_| invalid("epoch proposal byte budget"))?;
        proposal.validate(
            set,
            Some(self.activation.old_validator_set()),
            parameters,
            parent.timestamp_ms(),
        )?;
        let evidence_count = match header.block_kind() {
            BlockKind::Regular => {
                validate_root_bound_regular_body_v0(proposal.block(), set, parameters)
                    .map_err(|_| invalid("epoch regular body"))?
                    .evidence_count()
            }
            BlockKind::EpochCheckpoint => {
                validate_root_bound_epoch_body_v1(proposal.block(), set, parameters)
                    .map_err(|_| invalid("epoch checkpoint body"))?
                    .evidence_count()
            }
            BlockKind::EpochSeal1 | BlockKind::EpochSeal2 => {
                validate_empty_epoch_seal_v1(proposal, parent, parameters)?;
                0
            }
            BlockKind::EpochHandoff => unreachable!("first proposal handled above"),
        };
        let mut reserved = *budget;
        reserved
            .charge_qc_reference(proposal.witness().justify_qc())
            .map_err(|_| invalid("epoch proposal QC work"))?;
        if let Some(tc) = proposal.witness().timeout_certificate() {
            reserved
                .charge_timeout_certificate(tc)
                .map_err(|_| invalid("epoch proposal TC work"))?;
        }
        let work = (evidence_count as usize)
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(ValidationError::ArithmeticOverflow(
                "epoch proposal evidence work",
            ))?;
        reserved
            .charge_signature_work(work)
            .map_err(|_| invalid("epoch proposal signature work"))?;
        *budget = reserved;
        crate::strict_finality::verify_epoch_proposal_witness_strict_v1(
            &self.activation,
            header,
            proposal.witness(),
        )?;
        for raw in proposal.block().evidence_objects() {
            decode_double_vote_evidence_v0_exact(raw, set)
                .map_err(|_| invalid("epoch evidence decoding"))?
                .verify(set, &StrictEd25519Verifier)?;
        }
        Ok(())
    }
    pub fn verify_finality_v1(
        &self,
        proof: &FinalityProofV0,
        authenticated_parent_timestamp_ms: u64,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<(), ValidationError> {
        budget
            .admit_root_bytes(proof.try_cev0_bytes()?.len())
            .map_err(|_| invalid("epoch finality byte budget"))?;
        budget
            .charge_finality_proof(proof)
            .map_err(|_| invalid("epoch finality work budget"))?;
        self.verify_finality_precharged_v1(proof, authenticated_parent_timestamp_ms)
    }
    pub fn decode_verify_finality_v1(
        &self,
        raw: &[u8],
        authenticated_parent_timestamp_ms: u64,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<FinalityProofV0, ValidationError> {
        let proof = decode_epoch_runtime_finality_proof_v1_exact_with_budget(
            raw,
            &self.data,
            authenticated_parent_timestamp_ms,
            budget,
        )
        .map_err(|_| invalid("epoch finality exact decoding"))?;
        self.verify_finality_precharged_v1(&proof, authenticated_parent_timestamp_ms)?;
        Ok(proof)
    }
    fn verify_finality_precharged_v1(
        &self,
        proof: &FinalityProofV0,
        parent_timestamp: u64,
    ) -> Result<(), ValidationError> {
        proof.validate(
            self.activation.new_validator_set(),
            Some(self.activation.old_validator_set()),
            self.activation.new_consensus_parameters(),
            parent_timestamp,
        )?;
        if proof.finalized_block().header().block_kind() == BlockKind::EpochHandoff
            && parent_timestamp != self.activation.terminal_old_header().timestamp_ms()
        {
            return Err(invalid("epoch finality terminal timestamp"));
        }
        for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
            certified
                .certifying_qc()
                .verify(self.activation.new_validator_set(), &StrictEd25519Verifier)?;
            crate::strict_finality::verify_epoch_proposal_witness_strict_v1(
                &self.activation,
                certified.header(),
                certified.witness(),
            )?;
        }
        Ok(())
    }
}
fn invalid(reason: &'static str) -> ValidationError {
    ValidationError::InvalidProposal(reason)
}
