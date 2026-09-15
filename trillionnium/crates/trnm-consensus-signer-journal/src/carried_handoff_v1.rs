//! Strict pre-certificate admission for unchanged carried validator sets only.
//! New or rotated keys are deliberately outside this feature. Their finalized
//! registration/PoP and separate custody lifecycle remain unimplemented.
use crate::{
    hash::hash_domain, HandoffSignerJournalErrorV1, HandoffSignerJournalProfileV1,
    StrictOldSetHandoffAdmissionV1,
};
use trnm_consensus_types::{
    BlockHeader, CanonicalHandoffSignIntentV1, ConsensusParametersV0, FinalityProofV0,
    HandoffSignerRoleV1, NextEpochCommitmentV0, ValidatorSet,
};

/// Private proof of exact cryptographic context, not evidence of a stored
/// old-role signature. The journal independently requires that predecessor.
/// It does not grant an epoch anchor, Core authority or normal voting rights.
///
/// ```compile_fail
/// use trnm_consensus_signer_journal::StrictCarriedNewSetHandoffAdmissionV1;
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<StrictCarriedNewSetHandoffAdmissionV1>();
/// ```
#[derive(Debug)]
pub struct StrictCarriedNewSetHandoffAdmissionV1 {
    old_intent: CanonicalHandoffSignIntentV1,
    old_admission: StrictOldSetHandoffAdmissionV1,
    new_fingerprint: [u8; 32],
}

impl StrictCarriedNewSetHandoffAdmissionV1 {
    /// Recheck the full old checkpoint/two-seal proof and committed new set.
    /// Comparing complete member arrays admits only a carry, not membership,
    /// weight or key changes. The old trust context must be independently
    /// commissioned; this function cannot bootstrap it from peer-supplied data.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        intent: &CanonicalHandoffSignIntentV1,
        finality: &FinalityProofV0,
        commitment: &NextEpochCommitmentV0,
        old_set: &ValidatorSet,
        old_parameters: &ConsensusParametersV0,
        new_set: &ValidatorSet,
        new_parameters: &ConsensusParametersV0,
        authenticated_parent: &BlockHeader,
    ) -> Result<Self, HandoffSignerJournalErrorV1> {
        if intent.signer_role() != HandoffSignerRoleV1::NewSet
            || old_set.validators() != new_set.validators()
        {
            return Err(HandoffSignerJournalErrorV1::InvalidAdmission(
                "carried new-role admission requires unchanged ordered IDs, keys and weights",
            ));
        }
        intent
            .validate(old_set, new_set, old_parameters, new_parameters)
            .map_err(|_| HandoffSignerJournalErrorV1::InvalidAdmission("new-role intent"))?;
        let old_intent = CanonicalHandoffSignIntentV1::old_set(
            intent.preimage().descriptor(),
            old_set,
            new_set,
            old_parameters,
            new_parameters,
            intent.validator_id(),
        )
        .map_err(|_| HandoffSignerJournalErrorV1::InvalidAdmission("old-role counterpart"))?;
        // Uses strict full-set key admission and actual Ed25519 finality checks.
        // No joint handoff certificate is an input: there is no signing cycle.
        let old_admission = StrictOldSetHandoffAdmissionV1::verify(
            &old_intent,
            finality,
            commitment,
            old_set,
            old_parameters,
            new_set,
            new_parameters,
            authenticated_parent,
        )?;
        Ok(Self {
            old_intent,
            old_admission,
            new_fingerprint: *intent.fingerprint().as_bytes(),
        })
    }

    pub(crate) fn require_exact(
        &self,
        intent: &CanonicalHandoffSignIntentV1,
        profile: &HandoffSignerJournalProfileV1,
    ) -> Result<(), HandoffSignerJournalErrorV1> {
        if intent.signer_role() != HandoffSignerRoleV1::NewSet
            || self.new_fingerprint != *intent.fingerprint().as_bytes()
            || profile.old_validator_set().validators() != profile.new_validator_set().validators()
            || self.old_intent.preimage().descriptor() != intent.preimage().descriptor()
        {
            return Err(HandoffSignerJournalErrorV1::AdmissionMismatch(
                "carried-new context",
            ));
        }
        self.old_admission.require_exact(&self.old_intent, profile)
    }

    pub(crate) fn old_intent(&self) -> &CanonicalHandoffSignIntentV1 {
        &self.old_intent
    }
    pub(crate) fn old_admission(&self) -> &StrictOldSetHandoffAdmissionV1 {
        &self.old_admission
    }
    pub(crate) fn admission_digest(&self) -> [u8; 32] {
        hash_domain(
            "trnm.consensus-signer-journal.carried-new-admission.v1",
            &[
                &self.old_admission.admission_digest(),
                &self.new_fingerprint,
            ],
        )
    }
}
