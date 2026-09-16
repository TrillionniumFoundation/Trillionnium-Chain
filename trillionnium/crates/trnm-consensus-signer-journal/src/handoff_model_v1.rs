use trnm_consensus_crypto::{verify_pre_handoff_context_strict_v1, StrictPreHandoffContextV1};
use trnm_consensus_types::{
    BlockHeader, CanonicalHandoffSignIntentV1, ConsensusParametersV0, FinalityProofV0,
    HandoffSignerRoleV1, NextEpochCommitmentV0, ProtocolVersion, SignatureBytes, SigningRoot,
    ValidatorId, ValidatorSet,
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
    new_set_handoff_enabled: bool,
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
        Self::new_with_role_policy(
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
            false,
        )
    }

    /// Explicit pre-certificate role-capable profile. This does not enable
    /// ordinary new-epoch signing or production custody. Its checksum is
    /// separate from the frozen old-only constructor, even for a dual member.
    #[allow(clippy::too_many_arguments)]
    pub fn for_epoch_handoff(
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
        Self::new_with_role_policy(
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
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_role_policy(
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
        new_set_handoff_enabled: bool,
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
        if old_validator_set.validator(author).is_none()
            && !(new_set_handoff_enabled && new_validator_set.validator(author).is_some())
        {
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
        let profile_checksum = if new_set_handoff_enabled {
            hash_domain(
                "trnm.consensus-signer-journal.epoch-role-profile.v1",
                &[&profile_checksum],
            )
        } else {
            profile_checksum
        };
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
            new_set_handoff_enabled,
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

    pub const fn new_set_handoff_enabled(&self) -> bool {
        self.new_set_handoff_enabled
    }

    pub(crate) fn permits_role(&self, role: HandoffSignerRoleV1) -> bool {
        match role {
            HandoffSignerRoleV1::OldSet => self.old_validator_set.validator(self.author).is_some(),
            HandoffSignerRoleV1::NewSet => {
                self.new_set_handoff_enabled
                    && self.new_validator_set.validator(self.author).is_some()
            }
        }
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
/// constructor. Both role verifiers share the same cryptographic checkpoint
/// context; the native owner separately confirms its pre-certificate committed
/// checkpoint/cutoff receipt before calling the signer boundary.
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
        let context = verify_pre_handoff_context_strict_v1(
            old_checkpoint_finality,
            next_epoch_commitment,
            intent.preimage().descriptor(),
            old_validator_set,
            old_consensus_parameters,
            new_validator_set,
            new_consensus_parameters,
            authenticated_checkpoint_parent_header,
        )
        .map_err(|_| {
            HandoffSignerJournalErrorV1::InvalidAdmission(
                "strict checkpoint and two-seal pre-handoff context",
            )
        })?;
        Self::from_verified_context(intent, &context)
    }

    pub fn from_verified_context(
        intent: &CanonicalHandoffSignIntentV1,
        context: &StrictPreHandoffContextV1,
    ) -> Result<Self, HandoffSignerJournalErrorV1> {
        if intent.signer_role() != HandoffSignerRoleV1::OldSet
            || intent.preimage().descriptor() != context.descriptor()
        {
            return Err(HandoffSignerJournalErrorV1::InvalidAdmission(
                "old-set context binding",
            ));
        }
        intent
            .validate(
                context.old_validator_set(),
                context.new_validator_set(),
                context.old_consensus_parameters(),
                context.new_consensus_parameters(),
            )
            .map_err(|_| {
                HandoffSignerJournalErrorV1::InvalidAdmission("canonical old-set intent")
            })?;
        Ok(Self {
            intent_fingerprint: *intent.fingerprint().as_bytes(),
            descriptor_digest: *intent.preimage().descriptor_digest().as_bytes(),
            checkpoint_finality_proof_id: *context.checkpoint_finality_proof_id().as_bytes(),
            checkpoint_parent_block_id: *context.checkpoint_parent_block_id().as_bytes(),
            checkpoint_parent_timestamp_ms: context.checkpoint_parent_timestamp_ms(),
            next_epoch_commitment_digest: *context.next_epoch_commitment_digest().as_bytes(),
            old_validator_set_id: *context.old_validator_set().id().as_bytes(),
            new_validator_set_id: *context.new_validator_set().id().as_bytes(),
            old_parameters_hash: *context.old_consensus_parameters().hash().as_bytes(),
            new_parameters_hash: *context.new_consensus_parameters().hash().as_bytes(),
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

/// Strict new-role admission derived before a joint handoff certificate exists.
/// The native owner must independently confirm its pre-handoff committed
/// checkpoint receipt; this capability establishes cryptographic facts only.
/// No public raw constructor or Clone implementation is provided.
#[derive(Debug)]
pub struct StrictNewSetHandoffAdmissionV1 {
    intent_fingerprint: [u8; 32],
    descriptor_digest: [u8; 32],
    context_binding: [u8; 32],
    author: ValidatorId,
}

impl StrictNewSetHandoffAdmissionV1 {
    pub fn from_verified_context(
        intent: &CanonicalHandoffSignIntentV1,
        context: &StrictPreHandoffContextV1,
    ) -> Result<Self, HandoffSignerJournalErrorV1> {
        if intent.signer_role() != HandoffSignerRoleV1::NewSet {
            return Err(HandoffSignerJournalErrorV1::InvalidAdmission(
                "new-set admission cannot authorize the old-set role",
            ));
        }
        intent
            .validate(
                context.old_validator_set(),
                context.new_validator_set(),
                context.old_consensus_parameters(),
                context.new_consensus_parameters(),
            )
            .map_err(|_| {
                HandoffSignerJournalErrorV1::InvalidAdmission("canonical new-set intent")
            })?;
        if intent.preimage().descriptor() != context.descriptor() {
            return Err(HandoffSignerJournalErrorV1::InvalidAdmission(
                "new-set descriptor differs from strict pre-handoff context",
            ));
        }
        Ok(Self {
            intent_fingerprint: *intent.fingerprint().as_bytes(),
            descriptor_digest: *intent.preimage().descriptor_digest().as_bytes(),
            context_binding: context.binding_ref(),
            author: intent.validator_id(),
        })
    }

    pub(crate) fn require_exact(
        &self,
        intent: &CanonicalHandoffSignIntentV1,
        profile: &HandoffSignerJournalProfileV1,
    ) -> Result<(), HandoffSignerJournalErrorV1> {
        if !profile.permits_role(HandoffSignerRoleV1::NewSet) {
            return Err(HandoffSignerJournalErrorV1::NewSetAdmissionUnavailable);
        }
        if intent.signer_role() != HandoffSignerRoleV1::NewSet
            || self.intent_fingerprint != *intent.fingerprint().as_bytes()
            || self.descriptor_digest != *intent.preimage().descriptor_digest().as_bytes()
            || self.author != intent.validator_id()
            || self.author != profile.author()
        {
            return Err(HandoffSignerJournalErrorV1::AdmissionMismatch(
                "new-set intent binding",
            ));
        }
        intent
            .validate(
                profile.old_validator_set(),
                profile.new_validator_set(),
                profile.old_consensus_parameters(),
                profile.new_consensus_parameters(),
            )
            .map_err(|_| {
                HandoffSignerJournalErrorV1::AdmissionMismatch("new-set transition profile")
            })
    }

    pub(crate) fn admission_digest(&self) -> [u8; 32] {
        hash_domain(
            "trnm.consensus-signer-journal.new-handoff-admission.v1",
            &[
                &self.intent_fingerprint,
                &self.descriptor_digest,
                &self.context_binding,
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
