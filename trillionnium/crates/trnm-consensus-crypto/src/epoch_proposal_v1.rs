//! Complete first-block admission under an already strict eight-root handoff.
use crate::{StrictEd25519Verifier, StrictSameVersionEpochActivationAuthorityV0};
use trnm_consensus_types::{
    decode_double_vote_evidence_v0_exact, validate_root_bound_epoch_body_v1, BlockKind,
    Cev0AdmissionBudgetV0, RootBoundEpochBodyV1, SignedProposalV0, ValidationError,
};

/// Full signed proposal and root-bound canonical payload, including TC-before-
/// first-block admission. This records strict cryptographic verification only;
/// application execution, journal8, shared signer retirement and Core phase
/// activation remain separate consumers. There is no public constructor/Clone.
#[derive(Debug)]
pub struct StrictFirstEpochProposalV1 {
    proposal: SignedProposalV0,
    body: RootBoundEpochBodyV1,
    activation_binding: [u8; 32],
}
impl StrictFirstEpochProposalV1 {
    pub const fn proposal(&self) -> &SignedProposalV0 {
        &self.proposal
    }
    pub const fn body(&self) -> &RootBoundEpochBodyV1 {
        &self.body
    }
    pub const fn activation_binding(&self) -> [u8; 32] {
        self.activation_binding
    }
}

pub fn verify_first_epoch_proposal_strict_v1(
    activation: &StrictSameVersionEpochActivationAuthorityV0,
    proposal: SignedProposalV0,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<StrictFirstEpochProposalV1, ValidationError> {
    budget
        .admit_root_bytes(proposal.durable_validation_resource_size_v0()?)
        .map_err(|_| ValidationError::InvalidProposal("first epoch proposal byte budget"))?;
    let header = proposal.block().header();
    let descriptor = activation.handoff_certificate().descriptor().fields();
    if header.block_kind() != BlockKind::EpochHandoff
        || header.height() != descriptor.activation_height
        || header.parent_id() != descriptor.terminal_old_block_id
        || proposal.witness().justify_qc().as_synthetic().is_none()
        || proposal
            .witness()
            .epoch_anchor_authorization()
            .ok_or(ValidationError::InvalidProposal(
                "first proposal lacks complete epoch authorization",
            ))?
            .try_cev0_bytes()?
            != activation.authorization_cev0_bytes()?
    {
        return Err(ValidationError::InvalidProposal(
            "first proposal substitutes strict activation context",
        ));
    }
    proposal.validate(
        activation.new_validator_set(),
        Some(activation.old_validator_set()),
        activation.new_consensus_parameters(),
        activation.terminal_old_header().timestamp_ms(),
    )?;
    let body = validate_root_bound_epoch_body_v1(
        proposal.block(),
        activation.new_validator_set(),
        activation.new_consensus_parameters(),
    )
    .map_err(|_| {
        ValidationError::InvalidProposal("first proposal body differs from signed roots")
    })?;
    // Reserve all work atomically through the shared QC/TC meter, including
    // its independent nested-TC-share bound; rejection refunds no crypto work.
    let mut reserved = *budget;
    reserved
        .charge_qc_reference(proposal.witness().justify_qc())
        .map_err(|_| ValidationError::InvalidProposal("first proposal QC budget"))?;
    if let Some(tc) = proposal.witness().timeout_certificate() {
        reserved
            .charge_timeout_certificate(tc)
            .map_err(|_| ValidationError::InvalidProposal("first proposal TC budget"))?;
    }
    let evidence_work = (body.evidence_count() as usize)
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or(ValidationError::ArithmeticOverflow(
            "first proposal evidence work",
        ))?;
    reserved
        .charge_signature_work(evidence_work)
        .map_err(|_| ValidationError::InvalidProposal("first proposal signature budget"))?;
    *budget = reserved;
    crate::strict_finality::verify_epoch_proposal_witness_strict_v1(
        activation,
        header,
        proposal.witness(),
    )?;
    for raw in proposal.block().evidence_objects() {
        decode_double_vote_evidence_v0_exact(raw, activation.new_validator_set())
            .map_err(|_| ValidationError::InvalidProposal("first proposal evidence encoding"))?
            .verify(activation.new_validator_set(), &StrictEd25519Verifier)?;
    }
    Ok(StrictFirstEpochProposalV1 {
        proposal,
        body,
        activation_binding: *activation.binding_ref().as_bytes(),
    })
}
