//! Strict successor activation using the already authenticated outgoing epoch.
use super::*;
use trnm_consensus_types::{
    decode_epoch_activation_evidence_with_context_v1_exact,
    derive_successor_epoch_joint_structure_v1, validate_historical_header_link_v1,
};

#[derive(Debug)]
#[non_exhaustive]
pub enum StrictSuccessorEpochActivationErrorV1 {
    Invalid(&'static str),
    Evidence(EpochActivationEvidenceErrorV0),
    Consensus(ValidationError),
    Joint(JointHandoffKernelError),
}

impl fmt::Display for StrictSuccessorEpochActivationErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "successor activation: {reason}"),
            Self::Evidence(error) => write!(f, "successor evidence: {error}"),
            Self::Consensus(error) => write!(f, "successor consensus: {error}"),
            Self::Joint(error) => write!(f, "successor joint relations: {error}"),
        }
    }
}
impl core::error::Error for StrictSuccessorEpochActivationErrorV1 {}

fn screen_ancestry(ancestry: &[BlockHeader]) -> Result<(), StrictSuccessorEpochActivationErrorV1> {
    use StrictSuccessorEpochActivationErrorV1 as Error;
    if !(2..=256).contains(&ancestry.len()) {
        return Err(Error::Invalid("retained ancestry count"));
    }
    let mut bytes = 0usize;
    for header in ancestry {
        let size = header.try_cev0_bytes().map_err(Error::Consensus)?.len();
        if size > 4096 {
            return Err(Error::Invalid("retained ancestry header size"));
        }
        bytes = bytes
            .checked_add(size)
            .ok_or(Error::Invalid("retained ancestry overflow"))?;
        if bytes > 1024 * 1024 {
            return Err(Error::Invalid("retained ancestry byte bound"));
        }
    }
    Ok(())
}

/// Shared by both public composition routes. Context and exact endpoint joins
/// remain the callers' responsibility; every retained edge uses the same full
/// historical rules after the same count and canonical-byte bounds.
pub(crate) fn validate_successor_ancestry_links_v1(
    predecessor: &StrictSameVersionEpochActivationAuthorityV0,
    ancestry: &[BlockHeader],
) -> Result<(), StrictSuccessorEpochActivationErrorV1> {
    screen_ancestry(ancestry)?;
    for pair in ancestry.windows(2) {
        validate_historical_header_link_v1(
            &pair[1],
            &pair[0],
            predecessor.new_validator_set(),
            predecessor.new_consensus_parameters(),
        )
        .map_err(StrictSuccessorEpochActivationErrorV1::Consensus)?;
    }
    Ok(())
}

/// Verify original successor evidence under an independently verified predecessor.
/// The ancestry includes the predecessor terminal seal and checkpoint parent.
/// This returns cryptographic facts only; it never enables a signer or Core.
pub fn decode_verify_successor_epoch_activation_strict_v1(
    predecessor: &StrictSameVersionEpochActivationAuthorityV0,
    retained_ancestry: &[BlockHeader],
    preimages: EpochActivationEvidencePreimagesV0<'_>,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<StrictSameVersionEpochActivationAuthorityV0, StrictSuccessorEpochActivationErrorV1> {
    screen_ancestry(retained_ancestry)?;
    let decoded = decode_epoch_activation_evidence_with_context_v1_exact(
        preimages,
        predecessor.runtime_data_v1(),
        budget,
    )
    .map_err(StrictSuccessorEpochActivationErrorV1::Evidence)?;
    verify_decoded_successor_epoch_activation_v1(predecessor, retained_ancestry, &decoded)
}

/// Internal shared consumer; the complete decoder has already reserved work.
/// Signature verification is still mandatory here, regardless of the caller.
pub(crate) fn verify_decoded_successor_epoch_activation_v1(
    predecessor: &StrictSameVersionEpochActivationAuthorityV0,
    retained_ancestry: &[BlockHeader],
    evidence: &DecodedEpochActivationEvidenceV0,
) -> Result<StrictSameVersionEpochActivationAuthorityV0, StrictSuccessorEpochActivationErrorV1> {
    use StrictSuccessorEpochActivationErrorV1 as Error;
    if evidence.old_validator_set() != predecessor.new_validator_set()
        || evidence.old_consensus_parameters() != predecessor.new_consensus_parameters()
        || retained_ancestry.first() != Some(predecessor.terminal_old_header())
        || retained_ancestry.last() != Some(evidence.authenticated_checkpoint_parent_header())
    {
        return Err(Error::Invalid("predecessor context or ancestry endpoints"));
    }
    validate_successor_ancestry_links_v1(predecessor, retained_ancestry)?;
    validate_validator_set_strict_ed25519_v0(evidence.old_validator_set())
        .map_err(Error::Consensus)?;
    validate_validator_set_strict_ed25519_v0(evidence.new_validator_set())
        .map_err(Error::Consensus)?;
    let joint = derive_successor_epoch_joint_structure_v1(evidence, predecessor.runtime_data_v1())
        .map_err(Error::Joint)?;
    crate::epoch_runtime_v1::verify_epoch_finality_precharged_v1(
        predecessor,
        evidence.old_checkpoint_finality(),
        evidence
            .authenticated_checkpoint_parent_header()
            .timestamp_ms(),
    )
    .map_err(Error::Consensus)?;
    evidence
        .authorization_kernel()
        .verify_certificate_kernel(
            evidence.old_validator_set(),
            evidence.new_validator_set(),
            &StrictEd25519Verifier,
        )
        .map_err(Error::Consensus)?;
    strict_authority_from_decoded_v1(evidence, joint).map_err(Error::Consensus)
}

/// Reverify a persisted successor using an independently recovered predecessor.
/// A stored binding is only an exact-byte expectation; it grants no authority.
/// Once structural admission reserves work, failed crypto/binding does not refund it.
pub fn recover_successor_epoch_activation_authority_strict_v1(
    predecessor: &StrictSameVersionEpochActivationAuthorityV0,
    retained_ancestry: &[BlockHeader],
    preimages: EpochActivationEvidencePreimagesV0<'_>,
    expected_binding: [u8; 32],
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<StrictSameVersionEpochActivationAuthorityV0, StrictSuccessorEpochActivationErrorV1> {
    use StrictSuccessorEpochActivationErrorV1 as Error;
    if expected_binding == [0; 32] {
        return Err(Error::Invalid("zero expected binding"));
    }
    let authority = decode_verify_successor_epoch_activation_strict_v1(
        predecessor,
        retained_ancestry,
        preimages,
        budget,
    )?;
    if authority.binding_ref().as_bytes() != &expected_binding {
        return Err(Error::Invalid("expected binding differs"));
    }
    Ok(authority)
}
