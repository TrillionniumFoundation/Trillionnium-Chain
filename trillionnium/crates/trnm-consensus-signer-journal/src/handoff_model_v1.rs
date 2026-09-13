use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    validate_checkpoint_parent_header_v0, BlockHeader, CanonicalHandoffSignIntentV1,
    ConsensusParametersV0, FinalityProofV0, HandoffSignerRoleV1, NextEpochCommitmentV0,
    ProtocolVersion, SignatureBytes, SigningRoot, ValidatorId, ValidatorSet,
};

use crate::{hash::hash_domain, HandoffSignerJournalErrorV1, SignatureProducerErrorV0};

const PROFILE_DOMAIN_V1: &str = "trnm.consensus-signer-journal.handoff-profile.v1";
const MAXIMUM_INTENTS_HARD_V1: u64 = 1_000_000;
const MAXIMUM_INTENT_BYTES_HARD_V1: usize = 16 * 1024;
const DATABASE_OVERHEAD_BYTES_V1: usize = 16 * 1024 * 1024;

/// Exact schema1 profile for one old/new transition and one old-set signer.
///
/// The author must be present in the old set. A validator present only in the
/// new set cannot open this profile, so schema1 has no accidental new-epoch
/// normal-signing admission. Both parameter preimages must remain explicitly
/// non-production in this tranche.
///
/// This profile is not a SafetyRules capability. In particular, a canonical
/// Vote/Timeout intent's revision and shape do not prove locked-QC or proposal
/// ancestry safety. The explicit truth values exposed below therefore remain
/// `safety_rules_evaluation=false`, `safe_vote_authority=false`, and
/// `production_activation=false`.
#[derive(Debug, Clone)]
pub struct HandoffSignerJournalProfileV1 {
    old_validator_set: ValidatorSet,
    new_validator_set: ValidatorSet,
    old_consensus_parameters: ConsensusParametersV0,
    new_consensus_parameters: ConsensusParametersV0,
    author: ValidatorId,
    signer_profile_ref: [u8; 32],
    external_watermark_scope: [u8; 32],
    maximum_intents: u64,
    maximum_intent_bytes: usize,
    maximum_database_bytes: usize,
    profile_checksum: [u8; 32],
}

impl HandoffSignerJournalProfileV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        old_validator_set: ValidatorSet,
        new_validator_set: ValidatorSet,
        old_consensus_parameters: ConsensusParametersV0,
        new_consensus_parameters: ConsensusParametersV0,
        author: ValidatorId,
        signer_profile_ref: [u8; 32],
        external_watermark_scope: [u8; 32],
        maximum_intents: u64,
        maximum_intent_bytes: usize,
        maximum_database_bytes: usize,
    ) -> Result<Self, HandoffSignerJournalErrorV1> {
        old_validator_set
            .validate_against_parameters(&old_consensus_parameters)
            .map_err(|_| HandoffSignerJournalErrorV1::InvalidProfile("old validator profile"))?;
        new_validator_set
            .validate_against_parameters(&new_consensus_parameters)
            .map_err(|_| HandoffSignerJournalErrorV1::InvalidProfile("new validator profile"))?;
        if old_consensus_parameters.production_activation()
            || new_consensus_parameters.production_activation()
        {
            return Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "production activation remains closed",
            ));
        }
        if old_validator_set.protocol_version() != ProtocolVersion::V0
            || new_validator_set.protocol_version() != ProtocolVersion::V0
            || old_consensus_parameters.protocol_version() != ProtocolVersion::V0.get()
            || new_consensus_parameters.protocol_version() != ProtocolVersion::V0.get()
        {
            return Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "schema1 supports only protocol v0 same-version transitions",
            ));
        }
        if old_validator_set.genesis_hash() != new_validator_set.genesis_hash()
            || old_validator_set.chain_id() != new_validator_set.chain_id()
            || old_validator_set.epoch().checked_next().ok() != Some(new_validator_set.epoch())
        {
            return Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "old/new transition context",
            ));
        }
        if old_validator_set.validator(author).is_none() {
            return Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "new-set-only validator admission is closed",
            ));
        }
        if signer_profile_ref == [0; 32] || external_watermark_scope == [0; 32] {
            return Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "signer profile and external watermark scope must be nonzero",
            ));
        }
        if maximum_intents == 0 || maximum_intents > MAXIMUM_INTENTS_HARD_V1 {
            return Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "intent count bound",
            ));
        }
        if maximum_intent_bytes == 0 || maximum_intent_bytes > MAXIMUM_INTENT_BYTES_HARD_V1 {
            return Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "intent byte bound",
            ));
        }
        let retained_bytes = usize::try_from(maximum_intents)
            .ok()
            .and_then(|count| maximum_intent_bytes.checked_add(2048)?.checked_mul(count))
            .and_then(|bytes| bytes.checked_add(DATABASE_OVERHEAD_BYTES_V1))
            .ok_or(HandoffSignerJournalErrorV1::InvalidProfile(
                "database budget calculation overflow",
            ))?;
        if maximum_database_bytes < retained_bytes || maximum_database_bytes > i64::MAX as usize {
            return Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "database budget cannot retain declared append-only capacity",
            ));
        }

        let old_set_bytes = old_validator_set
            .try_cev0_bytes()
            .map_err(|_| HandoffSignerJournalErrorV1::InvalidProfile("encode old set"))?;
        let new_set_bytes = new_validator_set
            .try_cev0_bytes()
            .map_err(|_| HandoffSignerJournalErrorV1::InvalidProfile("encode new set"))?;
        let old_parameter_bytes = old_consensus_parameters.canonical_bytes();
        let new_parameter_bytes = new_consensus_parameters.canonical_bytes();
        let maximum_intents_be = maximum_intents.to_be_bytes();
        let maximum_intent_bytes_be = (maximum_intent_bytes as u64).to_be_bytes();
        let maximum_database_bytes_be = (maximum_database_bytes as u64).to_be_bytes();
        let profile_checksum = hash_domain(
            PROFILE_DOMAIN_V1,
            &[
                &old_set_bytes,
                &new_set_bytes,
                &old_parameter_bytes,
                &new_parameter_bytes,
                author.as_bytes(),
                &signer_profile_ref,
                &external_watermark_scope,
                &maximum_intents_be,
                &maximum_intent_bytes_be,
                &maximum_database_bytes_be,
            ],
        );
        Ok(Self {
            old_validator_set,
            new_validator_set,
            old_consensus_parameters,
            new_consensus_parameters,
            author,
            signer_profile_ref,
            external_watermark_scope,
            maximum_intents,
            maximum_intent_bytes,
            maximum_database_bytes,
            profile_checksum,
        })
    }

    pub const fn old_validator_set(&self) -> &ValidatorSet {
        &self.old_validator_set
    }

    pub const fn new_validator_set(&self) -> &ValidatorSet {
        &self.new_validator_set
    }

    pub const fn old_consensus_parameters(&self) -> &ConsensusParametersV0 {
        &self.old_consensus_parameters
    }

    pub const fn new_consensus_parameters(&self) -> &ConsensusParametersV0 {
        &self.new_consensus_parameters
    }

    pub const fn author(&self) -> ValidatorId {
        self.author
    }

    pub const fn signer_profile_ref(&self) -> [u8; 32] {
        self.signer_profile_ref
    }

    pub const fn external_watermark_scope(&self) -> [u8; 32] {
        self.external_watermark_scope
    }

    pub const fn maximum_intents(&self) -> u64 {
        self.maximum_intents
    }

    pub const fn maximum_intent_bytes(&self) -> usize {
        self.maximum_intent_bytes
    }

    pub const fn maximum_database_bytes(&self) -> usize {
        self.maximum_database_bytes
    }

    pub const fn profile_checksum(&self) -> [u8; 32] {
        self.profile_checksum
    }

    /// Schema1 does not evaluate locked-QC/preferred-round SafetyRules.
    pub const fn safety_rules_evaluation(&self) -> bool {
        false
    }

    /// Schema1 never turns canonical intent shape into safe-vote authority.
    pub const fn safe_vote_authority(&self) -> bool {
        false
    }

    /// This dormant create-new profile cannot activate a production runtime.
    pub const fn production_activation(&self) -> bool {
        false
    }
}

/// Opaque strict old-set handoff admission.
///
/// This capability can be minted only after strict Ed25519 verification of
/// the exact checkpoint plus two-seal finality proof and exact next-epoch
/// commitment relations. It is intentionally not `Clone` and exposes no raw
/// constructor. No corresponding new-set constructor exists in this tranche:
/// the new-set strict pre-certificate verifier (including committed
/// membership/PoP) has not yet been implemented and migrated, so that
/// producer path stays closed without waiting for a circular post-certificate
/// authority.
#[derive(Debug)]
pub struct StrictOldSetHandoffAdmissionV1 {
    intent_fingerprint: [u8; 32],
    descriptor_digest: [u8; 32],
    checkpoint_finality_proof_id: [u8; 32],
    checkpoint_parent_block_id: [u8; 32],
    checkpoint_parent_timestamp_ms: u64,
    next_epoch_commitment_digest: [u8; 32],
    old_validator_set_id: [u8; 32],
    new_validator_set_id: [u8; 32],
    old_parameters_hash: [u8; 32],
    new_parameters_hash: [u8; 32],
    author: ValidatorId,
}

impl StrictOldSetHandoffAdmissionV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        intent: &CanonicalHandoffSignIntentV1,
        old_checkpoint_finality: &FinalityProofV0,
        next_epoch_commitment: &NextEpochCommitmentV0,
        old_validator_set: &ValidatorSet,
        old_consensus_parameters: &ConsensusParametersV0,
        new_validator_set: &ValidatorSet,
        new_consensus_parameters: &ConsensusParametersV0,
        authenticated_checkpoint_parent_header: &BlockHeader,
    ) -> Result<Self, HandoffSignerJournalErrorV1> {
        if intent.signer_role() != HandoffSignerRoleV1::OldSet {
            return Err(HandoffSignerJournalErrorV1::InvalidAdmission(
                "old-set admission cannot authorize the new-set role",
            ));
        }
        intent
            .validate(
                old_validator_set,
                new_validator_set,
                old_consensus_parameters,
                new_consensus_parameters,
            )
            .map_err(|_| HandoffSignerJournalErrorV1::InvalidAdmission("canonical intent"))?;
        next_epoch_commitment
            .validate_same_version_context(
                old_validator_set,
                old_consensus_parameters,
                new_validator_set,
                new_consensus_parameters,
            )
            .map_err(|_| HandoffSignerJournalErrorV1::InvalidAdmission("epoch commitment"))?;
        validate_checkpoint_parent_header_v0(
            old_checkpoint_finality,
            authenticated_checkpoint_parent_header,
        )
        .map_err(|_| {
            HandoffSignerJournalErrorV1::InvalidAdmission("authenticated checkpoint-parent header")
        })?;
        let checkpoint = old_checkpoint_finality
            .verify_checkpoint_two_seal_kernel(
                old_validator_set,
                old_consensus_parameters,
                next_epoch_commitment,
                authenticated_checkpoint_parent_header.timestamp_ms(),
                &StrictEd25519Verifier,
            )
            .map_err(|_| {
                HandoffSignerJournalErrorV1::InvalidAdmission(
                    "strict checkpoint and two-seal finality",
                )
            })?;
        let descriptor = intent.preimage().descriptor();
        let fields = descriptor.fields();
        let terminal = old_checkpoint_finality.grandchild().header();
        if fields.genesis_hash != old_validator_set.genesis_hash()
            || fields.chain_id != old_validator_set.chain_id()
            || fields.old_epoch != checkpoint.old_epoch()
            || fields.new_epoch != checkpoint.new_epoch()
            || fields.old_validator_set_hash != old_validator_set.id()
            || fields.new_validator_set_hash != new_validator_set.id()
            || fields.old_consensus_parameters_hash != old_consensus_parameters.hash()
            || fields.new_consensus_parameters_hash != new_consensus_parameters.hash()
            || fields.checkpoint_height != checkpoint.checkpoint_height()
            || fields.checkpoint_block_id != checkpoint.checkpoint_block_id()
            || fields.checkpoint_state_root != checkpoint.checkpoint_state_root()
            || fields.next_epoch_commitment_digest != checkpoint.next_epoch_commitment_digest()
            || fields.terminal_old_height != checkpoint.terminal_old_height()
            || fields.terminal_old_block_id != checkpoint.terminal_old_block_id()
            || fields.terminal_old_qc_digest != checkpoint.terminal_old_qc_digest()
            || fields.terminal_old_view != terminal.view()
            || fields.activation_height != checkpoint.activation_height()
        {
            return Err(HandoffSignerJournalErrorV1::InvalidAdmission(
                "descriptor differs from verified checkpoint/two-seal facts",
            ));
        }
        Ok(Self {
            intent_fingerprint: *intent.fingerprint().as_bytes(),
            descriptor_digest: *intent.preimage().descriptor_digest().as_bytes(),
            checkpoint_finality_proof_id: *checkpoint.proof_id().as_bytes(),
            checkpoint_parent_block_id: *authenticated_checkpoint_parent_header.id().as_bytes(),
            checkpoint_parent_timestamp_ms: authenticated_checkpoint_parent_header.timestamp_ms(),
            next_epoch_commitment_digest: *checkpoint.next_epoch_commitment_digest().as_bytes(),
            old_validator_set_id: *old_validator_set.id().as_bytes(),
            new_validator_set_id: *new_validator_set.id().as_bytes(),
            old_parameters_hash: *old_consensus_parameters.hash().as_bytes(),
            new_parameters_hash: *new_consensus_parameters.hash().as_bytes(),
            author: intent.validator_id(),
        })
    }

    pub(crate) fn require_exact(
        &self,
        intent: &CanonicalHandoffSignIntentV1,
        profile: &HandoffSignerJournalProfileV1,
    ) -> Result<(), HandoffSignerJournalErrorV1> {
        if self.intent_fingerprint != *intent.fingerprint().as_bytes() {
            return Err(HandoffSignerJournalErrorV1::AdmissionMismatch(
                "intent fingerprint",
            ));
        }
        if self.descriptor_digest != *intent.preimage().descriptor_digest().as_bytes() {
            return Err(HandoffSignerJournalErrorV1::AdmissionMismatch(
                "descriptor digest",
            ));
        }
        if self.old_validator_set_id != *profile.old_validator_set().id().as_bytes()
            || self.new_validator_set_id != *profile.new_validator_set().id().as_bytes()
            || self.old_parameters_hash != *profile.old_consensus_parameters().hash().as_bytes()
            || self.new_parameters_hash != *profile.new_consensus_parameters().hash().as_bytes()
            || self.author != profile.author()
            || self.author != intent.validator_id()
        {
            return Err(HandoffSignerJournalErrorV1::AdmissionMismatch(
                "transition profile",
            ));
        }
        if self.checkpoint_finality_proof_id == [0; 32]
            || self.checkpoint_parent_block_id == [0; 32]
            || self.next_epoch_commitment_digest == [0; 32]
        {
            return Err(HandoffSignerJournalErrorV1::AdmissionMismatch(
                "verified finality commitments",
            ));
        }
        Ok(())
    }

    pub(crate) fn admission_digest(&self) -> [u8; 32] {
        let timestamp = self.checkpoint_parent_timestamp_ms.to_be_bytes();
        hash_domain(
            "trnm.consensus-signer-journal.old-handoff-admission.v1",
            &[
                &self.intent_fingerprint,
                &self.descriptor_digest,
                &self.checkpoint_finality_proof_id,
                &self.checkpoint_parent_block_id,
                &timestamp,
                &self.next_epoch_commitment_digest,
                &self.old_validator_set_id,
                &self.new_validator_set_id,
                &self.old_parameters_hash,
                &self.new_parameters_hash,
                self.author.as_bytes(),
            ],
        )
    }
}

/// Exact handoff request exposed to an injected key/HSM/KMS adapter only
/// after strict admission has been checked by schema1.
#[derive(Debug, Clone, Copy)]
pub struct HandoffSignatureRequestV1<'a> {
    intent: &'a CanonicalHandoffSignIntentV1,
    signer_profile_ref: [u8; 32],
}

impl<'a> HandoffSignatureRequestV1<'a> {
    pub(crate) const fn new(
        intent: &'a CanonicalHandoffSignIntentV1,
        signer_profile_ref: [u8; 32],
    ) -> Self {
        Self {
            intent,
            signer_profile_ref,
        }
    }

    pub const fn intent(&self) -> &'a CanonicalHandoffSignIntentV1 {
        self.intent
    }

    pub const fn author(&self) -> ValidatorId {
        self.intent.validator_id()
    }

    pub const fn signing_root(&self) -> SigningRoot {
        self.intent.signing_root()
    }

    pub const fn signer_profile_ref(&self) -> [u8; 32] {
        self.signer_profile_ref
    }
}

/// Injected handoff-signing boundary. This crate owns no private key.
pub trait HandoffSignatureProducerV1 {
    fn sign_handoff(
        &mut self,
        request: HandoffSignatureRequestV1<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0>;
}
