//! Structurally joined epoch context, with no signature or runtime authority.
use crate::{
    ConsensusParametersV0, DecodedEpochActivationEvidenceV0, EpochAnchorAuthorizationV0,
    QcReferenceV0, Result, ValidatorSet,
};

/// Exact decoding context derived from the complete eight-root evidence loader.
/// This value is intentionally cryptographically inert. Core/signers must use
/// the separate strict consumer and actual durable-owner joins. A bare kernel
/// or caller-provided synthetic QC cannot construct it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRuntimeContextDataV1 {
    authorization: EpochAnchorAuthorizationV0,
    old_set: ValidatorSet,
    new_set: ValidatorSet,
    new_parameters: ConsensusParametersV0,
    anchor: QcReferenceV0,
}
impl EpochRuntimeContextDataV1 {
    pub fn from_decoded_evidence_v1(evidence: &DecodedEpochActivationEvidenceV0) -> Result<Self> {
        let kernel = evidence.authorization_kernel();
        let authorization = EpochAnchorAuthorizationV0::new(
            kernel.terminal_old_header().clone(),
            kernel.terminal_old_qc().clone(),
            kernel.handoff_certificate().clone(),
            evidence.old_validator_set(),
            evidence.new_validator_set(),
        )?;
        let anchor = QcReferenceV0::epoch_anchor(authorization.epoch_anchor_qc());
        Ok(Self {
            authorization,
            old_set: evidence.old_validator_set().clone(),
            new_set: evidence.new_validator_set().clone(),
            new_parameters: *evidence.new_consensus_parameters(),
            anchor,
        })
    }
    pub const fn authorization(&self) -> &EpochAnchorAuthorizationV0 {
        &self.authorization
    }
    pub const fn old_validator_set(&self) -> &ValidatorSet {
        &self.old_set
    }
    pub const fn new_validator_set(&self) -> &ValidatorSet {
        &self.new_set
    }
    pub const fn new_parameters(&self) -> &ConsensusParametersV0 {
        &self.new_parameters
    }
    pub const fn anchor_reference(&self) -> &QcReferenceV0 {
        &self.anchor
    }
}
