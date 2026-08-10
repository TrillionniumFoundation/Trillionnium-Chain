//! Authenticated PoCO application-authority and cross-entry planning kernel.
//!
//! This module deliberately sits above the exact namespace-8 decoder and
//! below block-level JMT planning.  Callers supply one production projection,
//! one authenticated authority object, and the exact operation bytes in block
//! order.  The kernel derives every compare-and-set precondition from that
//! authenticated source, applies operations to one overlay, and seals one
//! canonical namespace rewrite including the successor kind-16 authority
//! entry.  No namespace-1 mirror is authoritative.
//!
//! A successful plan is application-write authority only.  It does not
//! authorize B2-G candidate reconstruction, handoff, activation, or a Core
//! epoch transition.  Namespace-8 `AuthWrite` construction remains behind the
//! permit in `poco_transition`; the private raw writes emitted here must be
//! converted only by that single JMT merger.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    poco_nullifier::{
        derive_poco_nullifier_key_v0, PocoNullifierAccumulatorV0, PocoNullifierFamilyV0,
        PocoNullifierProofV0,
    },
    poco_semantics::{
        GovernanceApprovalV0, LifecycleStateV0, MeasurementStateV0, RegistrationStateV0,
        RelationshipClassV0, SemanticFactV0, SettlementStateV0,
    },
    poco_snapshot::{
        poco_snapshot_entry_key, poco_snapshot_manifest_key, PocoSnapshotEntryKindV0,
        PocoSnapshotEntryV0, PocoSnapshotManifestV0, MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
        MAX_POCO_SNAPSHOT_ENTRIES,
    },
    poco_transition::{
        decode_poco_snapshot_value_parts_v0_exact, take_and_validate_production_poco_projection_v0,
        PocoSnapshotMutationV0, ProductionPocoProjectionV0, MAX_POCO_SEMANTIC_PAYLOAD_BYTES,
    },
};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_consumption_certificate_v0_exact,
    decode_validator_key_proof_of_possession_v0_exact, decode_validator_set_v0_exact, ChainId,
    ConsensusParametersV0, ConsensusPublicKey, ConsumptionCertificateBodyV0, Epoch,
    EpochGeometryV0, GenesisHash, Height, ValidatorId, ValidatorSet, SCHEMA_VERSION_V0,
};

#[path = "poco_authenticated_candidate.rs"]
mod authenticated_candidate;
#[cfg(test)]
pub(crate) use authenticated_candidate::authorize_authenticated_poco_cutoff_candidate_selection_v0;
pub(crate) use authenticated_candidate::{
    authorize_authenticated_poco_candidate_selection_v0, AuthenticatedPocoCandidateSelectionV0,
    AuthenticatedPocoCutoffCandidateSelectionV0,
};

pub(crate) const POCO_APPLICATION_AUTHORITY_SCHEMA_V0: &str = "trnm_poco_application_authority_v0";
pub(crate) const POCO_APPLICATION_OPERATION_SCHEMA_V0: &str = "trnm_poco_application_operation_v0";
pub(crate) const POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0: &str =
    "trnm.poco.application-operation.v0";
const POCO_APPLICATION_AUTHORITY_IDENTITY_V0: &[u8] = b"trnm.poco.application-authority.v0";
const MAX_APPLICATION_OPERATIONS_PER_BLOCK: usize = 32;
const MAX_APPLICATION_OPERATION_BYTES: usize = 1_048_576;
const MAX_OPAQUE_ID_BYTES: usize = 128;
const MAX_SEMANTIC_CHANGES_PER_OPERATION: usize = 32;
const MAX_CONSUMER_KEY_AUTHORITIES: usize = 4;
const MAX_NONCE_WATERMARKS_PER_KEY: usize = 8;
const MAX_TOTAL_NONCE_WATERMARKS: usize = 8;
const MAX_METER_POLICIES: usize = 4;
const MAX_TOTAL_USAGE_BUCKETS: usize = 32;
const MAX_FUNDED_UNUSED_RESERVATIONS: usize = 4;
// The frozen consensus parameter contract requires at least four validators.
// Fewer than four retained certificate authorities would make an
// authenticated reason-zero B2-G candidate structurally unreachable because
// every positive PoCO capacity needs at least one retained certificate.
const MAX_ACTIVE_CERTIFICATES: usize = 4;
const MAX_PENDING_CHALLENGES: usize = 2;
const MAX_PENDING_GOVERNANCE_PROPOSALS: usize = 2;
const MAX_FINALIZED_GOVERNANCE_APPROVALS: usize = 2;
const MAX_VALIDATOR_REGISTRATION_HISTORIES: usize = 4;
const MAX_FUTURE_CANDIDATE_REGISTRATIONS: usize = 4;
// Exact sum of all independently bounded record families. Keep this equal to
// the family-cap total so the aggregate guard does not silently admit slack.
const MAX_TOTAL_AUTHORITY_RECORDS: usize = 70;
const MAX_NULLIFIER_INSERTIONS_PER_OPERATION: usize = 16;
const APPLICATION_OPERATION_DOMAIN: &[u8] = b"trnm.poco-bft.application-operation.v0";
const APPLICATION_OPERATION_NODE_DOMAIN: &[u8] = b"trnm.poco-bft.application-operation-node.v0";
const APPLICATION_OPERATION_ROOT_DOMAIN: &[u8] = b"trnm.poco-bft.application-operation-root.v0";
const APPLICATION_MUTATION_DOMAIN: &[u8] = b"trnm.poco-bft.application-mutation.v0";
const APPLICATION_MUTATION_NODE_DOMAIN: &[u8] = b"trnm.poco-bft.application-mutation-node.v0";
const APPLICATION_MUTATION_ROOT_DOMAIN: &[u8] = b"trnm.poco-bft.application-mutation-root.v0";
const APPLICATION_DECISION_PREIMAGE_DOMAIN: &[u8] =
    b"trnm.poco-bft.application-decision-preimage.v0";
const APPLICATION_DECISION_ID_DOMAIN: &[u8] = b"trnm.poco-bft.application-decision-id.v0";
const APPLICATION_REGISTRATION_HISTORY_DOMAIN: &[u8] = b"trnm.poco-bft.registration-history.v0";
const FUTURE_CANDIDATE_POP_DIGEST_DOMAIN: &[u8] = b"trnm.poco-bft.future-candidate-pop.v0";
const SEMANTIC_IDENTITY_DOMAIN: &[u8] = b"trnm.poco-bft.snapshot-value-identity.v0";
const HASH_PREFIX: &[u8] = b"trnm.cev0.hash.v0";

/// A signed PoCO application operation that cannot be applied to the
/// authenticated parent projection under the frozen protocol rules.
/// Reasons are data-free so consensus disposition never depends on an error
/// message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PocoApplicationDeterministicInvalidV0 {
    PerBlockCapacity,
    TargetHeightMismatch,
    AuthorityRevisionMismatch,
    DuplicateOperation,
    SemanticTransition,
    MissingRequiredAuthorityFact,
    ProtocolWindowOrCap,
    NullifierProof,
    CryptographicProof,
    GovernanceRule,
    ValidatorRule,
    ChallengeNotPending,
    GovernanceApprovalMissing,
    ValidatorConsensusKeyAlreadyActive,
    NullifierNonMembershipRootMismatch,
}

/// A fail-stop condition while applying an operation to an authenticated
/// in-memory projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PocoApplicationInvariantV0 {
    RawOwnerBounds,
    DecodedRawOwnerMismatch,
    OperationReencode,
    AuthenticatedOverlay,
    PlannerArithmetic,
    ProtocolCounterExhausted,
    DerivedMutationPostcondition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PocoApplicationApplyFailureV0 {
    DeterministicallyInvalid(PocoApplicationDeterministicInvalidV0),
    Invariant(PocoApplicationInvariantV0),
}

impl std::fmt::Display for PocoApplicationApplyFailureV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ChallengeNotPending,
            ) => formatter.write_str("challenge is not pending"),
            Self::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::GovernanceApprovalMissing,
            ) => formatter.write_str("governance approval lacks authenticated proposal"),
            Self::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ValidatorConsensusKeyAlreadyActive,
            ) => formatter
                .write_str("validator consensus key is already active in registration history"),
            Self::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::NullifierNonMembershipRootMismatch,
            ) => formatter.write_str("PoCO nullifier non-membership root mismatch"),
            Self::DeterministicallyInvalid(reason) => {
                write!(
                    formatter,
                    "deterministically invalid PoCO operation: {reason:?}"
                )
            }
            Self::Invariant(reason) => {
                write!(formatter, "PoCO application invariant: {reason:?}")
            }
        }
    }
}

impl std::error::Error for PocoApplicationApplyFailureV0 {}

fn deterministic_application_error_v0(
    reason: PocoApplicationDeterministicInvalidV0,
) -> anyhow::Error {
    anyhow::Error::new(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
        reason,
    ))
}

fn invariant_application_error_v0(reason: PocoApplicationInvariantV0) -> anyhow::Error {
    anyhow::Error::new(PocoApplicationApplyFailureV0::Invariant(reason))
}

fn preserve_application_failure_or_deterministic_v0(
    error: anyhow::Error,
    fallback: PocoApplicationDeterministicInvalidV0,
) -> anyhow::Error {
    if error
        .downcast_ref::<PocoApplicationApplyFailureV0>()
        .is_some()
    {
        error
    } else {
        deterministic_application_error_v0(fallback)
    }
}

/// Decimal-string u128.  JSON numbers are intentionally avoided so a Node
/// consumer can reproduce the same value without IEEE-754 coercion.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct CanonicalU128V0(String);

impl CanonicalU128V0 {
    pub(crate) fn new(value: u128) -> Self {
        Self(value.to_string())
    }

    pub(crate) fn get(&self) -> Result<u128> {
        validate_decimal_u128(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MeterEvidencePolicyV0 {
    Required,
    Forbidden,
    Optional,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MeterAuthorityPolicyV0 {
    meter_id_hex: String,
    meter_version: u32,
    task_id_hex: String,
    output_commitment_hex: Option<String>,
    unit_scale: CanonicalU128V0,
    evidence_policy: MeterEvidencePolicyV0,
    per_certificate_cap: CanonicalU128V0,
    rolling_cap: CanonicalU128V0,
    rolling_epoch_span: u64,
    retention_blocks: u64,
    active_from_height: u64,
    retired_at_height: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumerKeyAuthorityV0 {
    consumer_id_hex: String,
    consumer_key_id_hex: String,
    public_key_hex: String,
    active_from_height: u64,
    authorization_decision_id_hex: String,
    revoked_at_height: Option<u64>,
    revocation_decision_id_hex: Option<String>,
    nonce_watermarks: Vec<ConsumerNonceWatermarkV0>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumerNonceWatermarkV0 {
    provider_id_hex: String,
    max_accepted_nonce: u64,
    logical_key_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MeterRollingUsageV0 {
    meter_id_hex: String,
    meter_version: u32,
    window_epoch: u64,
    consumed_units: CanonicalU128V0,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumerProviderRollingUsageV0 {
    consumer_id_hex: String,
    provider_id_hex: String,
    window_epoch: u64,
    consumed_units: CanonicalU128V0,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskProviderRollingUsageV0 {
    task_id_hex: String,
    provider_id_hex: String,
    window_epoch: u64,
    consumed_units: CanonicalU128V0,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderRollingUsageV0 {
    provider_id_hex: String,
    window_epoch: u64,
    consumed_units: CanonicalU128V0,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FundedUnusedReservationV0 {
    certificate_id_hex: String,
    settlement_commitment_hex: String,
    funding_decision_id_hex: String,
    finalized_height: u64,
    reserved_units: CanonicalU128V0,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SemanticKeyRefV0 {
    kind: u8,
    logical_key_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveCertificateAuthorityV0 {
    certificate_id_hex: String,
    consumer_id_hex: String,
    consumer_key_id_hex: String,
    provider_id_hex: String,
    task_id_hex: String,
    meter_id_hex: String,
    meter_version: u32,
    settlement_commitment_hex: String,
    settlement_finalized_height: u64,
    consumed_units: CanonicalU128V0,
    evidence_root_hex: Option<String>,
    relationship_class: u8,
    relationship_key_hex: String,
    provider_consensus_key_hex: String,
    provider_registration_nonce: u64,
    provider_proof_digest_hex: String,
    provider_registration_decision_id_hex: String,
    provider_registration_height: u64,
    provider_registration_history_head_hex: String,
    acceptance_decision_id_hex: String,
    funding_decision_id_hex: String,
    meter_decision_id_hex: String,
    evidence_decision_id_hex: String,
    accepted_height: u64,
    finalized_epoch: u64,
    tuple_key_hex: String,
    prunable_after_height: u64,
    lifecycle: CertificateAuthorityLifecycleV0,
    lifecycle_effective_height: u64,
    lifecycle_decision_id_hex: String,
    semantic_keys: Vec<SemanticKeyRefV0>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertificateAuthorityLifecycleV0 {
    Accepted,
    ChallengeRejected,
    ChallengeSustained,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingChallengeAuthorityV0 {
    challenge_id_hex: String,
    certificate_id_hex: String,
    opening_decision_id_hex: String,
    opened_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalizedGovernanceApprovalV0 {
    target_epoch: u64,
    phase: u8,
    proposal_decision_id_hex: String,
    proposed_height: u64,
    decision_id_hex: String,
    approval_height: u64,
    parameters_hash_hex: String,
    activation_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingGovernanceProposalV0 {
    target_epoch: u64,
    proposal_decision_id_hex: String,
    proposed_height: u64,
    phase: u8,
    parameters_hash_hex: String,
    activation_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValidatorRegistrationHistoryV0 {
    validator_id_hex: String,
    history_head_hex: String,
    max_registration_nonce: u64,
    consensus_key_hex: String,
    current_proof_digest_hex: String,
    previous_history_head_hex: String,
    registration_decision_id_hex: String,
    registration_height: u64,
    retired_key_count: u64,
    revoked_at_height: Option<u64>,
    revocation_decision_id_hex: Option<String>,
}

/// Append-only next-epoch candidate-key authority.
///
/// This is intentionally separate from the kind-9 active-provider
/// registration. Reinterpreting that frozen record for a future epoch would
/// invalidate current-epoch certificate provenance. The complete PoP bytes,
/// predecessor nonce/head, decision and admission height remain in the exact
/// kind-16 value so H3b2b2 can reconstruct a fresh B2-G transcript without a
/// caller-supplied history fact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FutureCandidateRegistrationV0 {
    validator_id_hex: String,
    target_epoch: u64,
    consensus_key_hex: String,
    registration_nonce: u64,
    previous_registration_nonce: Option<u64>,
    predecessor_history_head_hex: String,
    proof_cev0_hex: String,
    proof_digest_hex: String,
    registration_decision_id_hex: String,
    registration_height: u64,
}

/// The one persisted application-authority state.  Extra side objects are not
/// accepted because splitting these families would permit partial commits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PocoApplicationAuthorityStateV0 {
    schema: String,
    revision: u64,
    last_target_height: u64,
    nullifier_root_hex: String,
    nullifier_count: u64,
    consumer_keys: Vec<ConsumerKeyAuthorityV0>,
    meter_policies: Vec<MeterAuthorityPolicyV0>,
    meter_usage: Vec<MeterRollingUsageV0>,
    consumer_provider_usage: Vec<ConsumerProviderRollingUsageV0>,
    task_provider_usage: Vec<TaskProviderRollingUsageV0>,
    provider_usage: Vec<ProviderRollingUsageV0>,
    funded_unused_reservations: Vec<FundedUnusedReservationV0>,
    active_certificates: Vec<ActiveCertificateAuthorityV0>,
    pending_challenges: Vec<PendingChallengeAuthorityV0>,
    pending_governance_proposals: Vec<PendingGovernanceProposalV0>,
    finalized_governance_approvals: Vec<FinalizedGovernanceApprovalV0>,
    validator_registration_history: Vec<ValidatorRegistrationHistoryV0>,
    // Appended in H3b2b2a. Omitting an empty vector preserves the exact
    // canonical JSON bytes of every frozen H3b2b1 authority fixture.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    future_candidate_registrations: Vec<FutureCandidateRegistrationV0>,
}

impl PocoApplicationAuthorityStateV0 {
    pub(crate) fn empty() -> Self {
        let accumulator = PocoNullifierAccumulatorV0::empty();
        Self {
            schema: POCO_APPLICATION_AUTHORITY_SCHEMA_V0.to_string(),
            revision: 1,
            last_target_height: 0,
            nullifier_root_hex: hex::encode(accumulator.root()),
            nullifier_count: accumulator.count(),
            consumer_keys: Vec::new(),
            meter_policies: Vec::new(),
            meter_usage: Vec::new(),
            consumer_provider_usage: Vec::new(),
            task_provider_usage: Vec::new(),
            provider_usage: Vec::new(),
            funded_unused_reservations: Vec::new(),
            active_certificates: Vec::new(),
            pending_challenges: Vec::new(),
            pending_governance_proposals: Vec::new(),
            finalized_governance_approvals: Vec::new(),
            validator_registration_history: Vec::new(),
            future_candidate_registrations: Vec::new(),
        }
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn last_target_height(&self) -> u64 {
        self.last_target_height
    }

    pub(crate) fn encode_exact(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).context("encode PoCO application authority")?;
        ensure!(
            encoded.len() <= MAX_POCO_SEMANTIC_PAYLOAD_BYTES,
            "PoCO application authority exceeds semantic payload bound"
        );
        Ok(encoded)
    }

    pub(crate) fn decode_exact(encoded: &[u8]) -> Result<Self> {
        ensure!(
            !encoded.is_empty() && encoded.len() <= MAX_POCO_SEMANTIC_PAYLOAD_BYTES,
            "PoCO application authority byte length is outside bound"
        );
        let decoded: Self =
            serde_json::from_slice(encoded).context("decode PoCO application authority")?;
        decoded.validate()?;
        ensure!(
            serde_json::to_vec(&decoded).context("re-encode PoCO application authority")?
                == encoded,
            "PoCO application authority is not canonical JSON"
        );
        Ok(decoded)
    }

    pub(crate) fn nullifier_root(&self) -> Result<[u8; 32]> {
        exact_hash32_hex(&self.nullifier_root_hex)
    }

    pub(crate) const fn nullifier_count(&self) -> u64 {
        self.nullifier_count
    }

    fn accumulator(&self) -> Result<PocoNullifierAccumulatorV0> {
        PocoNullifierAccumulatorV0::from_authenticated_parts(
            self.nullifier_root()?,
            self.nullifier_count,
        )
    }

    fn set_accumulator(&mut self, accumulator: PocoNullifierAccumulatorV0) {
        self.nullifier_root_hex = hex::encode(accumulator.root());
        self.nullifier_count = accumulator.count();
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == POCO_APPLICATION_AUTHORITY_SCHEMA_V0,
            "PoCO application authority schema mismatch"
        );
        ensure!(self.revision > 0, "application authority revision is zero");
        ensure!(
            (self.revision == 1) == (self.last_target_height == 0),
            "application authority genesis revision/height mismatch"
        );
        self.accumulator()?;
        ensure_record_family_bounds(self)?;

        validate_strictly_sorted_unique_by(
            &self.consumer_keys,
            |item| {
                (
                    item.consumer_id_hex.clone(),
                    item.consumer_key_id_hex.clone(),
                )
            },
            "consumer-key authority",
        )?;
        for item in &self.consumer_keys {
            exact_opaque_hex(&item.consumer_id_hex)?;
            exact_opaque_hex(&item.consumer_key_id_hex)?;
            ensure!(
                exact_hash32_hex(&item.public_key_hex)? != [0; 32] && item.active_from_height > 0,
                "consumer-key authority key/activation is invalid"
            );
            exact_hash32_hex(&item.authorization_decision_id_hex)?;
            validate_recorded_business_height_v0(
                item.active_from_height,
                self.last_target_height,
                "consumer-key activation",
            )?;
            ensure!(
                item.revoked_at_height.is_some() == item.revocation_decision_id_hex.is_some(),
                "consumer-key revocation authority is incomplete"
            );
            if let (Some(revoked_at), Some(decision)) =
                (item.revoked_at_height, &item.revocation_decision_id_hex)
            {
                ensure!(
                    revoked_at > item.active_from_height,
                    "consumer-key revocation is not monotonic"
                );
                validate_recorded_business_height_v0(
                    revoked_at,
                    self.last_target_height,
                    "consumer-key revocation",
                )?;
                exact_hash32_hex(decision)?;
            }
            validate_strictly_sorted_unique_by(
                &item.nonce_watermarks,
                |watermark| watermark.provider_id_hex.clone(),
                "consumer nonce watermarks",
            )?;
            ensure!(
                item.nonce_watermarks.len() <= MAX_NONCE_WATERMARKS_PER_KEY,
                "consumer nonce watermark count exceeds atomic prune bound"
            );
            for watermark in &item.nonce_watermarks {
                exact_opaque_hex(&watermark.provider_id_hex)?;
                exact_hash32_hex(&watermark.logical_key_hex)?;
            }
        }

        validate_strictly_sorted_unique_by(
            &self.meter_policies,
            |item| (item.meter_id_hex.clone(), item.meter_version),
            "meter policies",
        )?;
        for item in &self.meter_policies {
            validate_meter_policy(item)?;
            validate_recorded_business_height_v0(
                item.active_from_height,
                self.last_target_height,
                "meter activation",
            )?;
            if let Some(retired_at) = item.retired_at_height {
                validate_recorded_business_height_v0(
                    retired_at,
                    self.last_target_height,
                    "meter retirement",
                )?;
            }
        }
        validate_strictly_sorted_unique_by(
            &self.meter_usage,
            |item| {
                (
                    item.meter_id_hex.clone(),
                    item.meter_version,
                    item.window_epoch,
                )
            },
            "meter usage",
        )?;
        for item in &self.meter_usage {
            exact_opaque_hex(&item.meter_id_hex)?;
            item.consumed_units.get()?;
        }
        validate_strictly_sorted_unique_by(
            &self.consumer_provider_usage,
            |item| {
                (
                    item.consumer_id_hex.clone(),
                    item.provider_id_hex.clone(),
                    item.window_epoch,
                )
            },
            "consumer-provider usage",
        )?;
        for item in &self.consumer_provider_usage {
            exact_opaque_hex(&item.consumer_id_hex)?;
            exact_opaque_hex(&item.provider_id_hex)?;
            item.consumed_units.get()?;
        }
        validate_strictly_sorted_unique_by(
            &self.task_provider_usage,
            |item| {
                (
                    item.task_id_hex.clone(),
                    item.provider_id_hex.clone(),
                    item.window_epoch,
                )
            },
            "task-provider usage",
        )?;
        for item in &self.task_provider_usage {
            exact_opaque_hex(&item.task_id_hex)?;
            exact_opaque_hex(&item.provider_id_hex)?;
            item.consumed_units.get()?;
        }
        validate_strictly_sorted_unique_by(
            &self.provider_usage,
            |item| (item.provider_id_hex.clone(), item.window_epoch),
            "provider usage",
        )?;
        for item in &self.provider_usage {
            exact_opaque_hex(&item.provider_id_hex)?;
            item.consumed_units.get()?;
        }
        ensure!(
            usage_bucket_count_v0(self)? <= MAX_TOTAL_USAGE_BUCKETS,
            "application authority usage bucket count exceeds hard cap"
        );
        validate_strictly_sorted_unique_by(
            &self.funded_unused_reservations,
            |item| item.certificate_id_hex.clone(),
            "funded-unused reservations",
        )?;
        for item in &self.funded_unused_reservations {
            exact_hash32_hex(&item.certificate_id_hex)?;
            exact_hash32_hex(&item.settlement_commitment_hex)?;
            ensure!(
                item.reserved_units.get()? > 0,
                "funded-unused reservation has zero units"
            );
            exact_hash32_hex(&item.funding_decision_id_hex)?;
            validate_recorded_business_height_v0(
                item.finalized_height,
                self.last_target_height,
                "settlement funding finalization",
            )?;
        }
        validate_strictly_sorted_unique_by(
            &self.active_certificates,
            |item| item.certificate_id_hex.clone(),
            "active certificate authority",
        )?;
        for item in &self.active_certificates {
            validate_active_certificate(item)?;
            validate_recorded_business_height_v0(
                item.settlement_finalized_height,
                self.last_target_height,
                "certificate settlement finalization",
            )?;
            validate_recorded_business_height_v0(
                item.accepted_height,
                self.last_target_height,
                "certificate acceptance",
            )?;
            validate_recorded_business_height_v0(
                item.lifecycle_effective_height,
                self.last_target_height,
                "certificate lifecycle",
            )?;
            validate_recorded_business_height_v0(
                item.provider_registration_height,
                self.last_target_height,
                "certificate provider registration",
            )?;
            ensure!(
                item.provider_registration_height <= item.accepted_height,
                "certificate predates its provider registration authority"
            );
        }
        validate_strictly_sorted_unique_by(
            &self.pending_challenges,
            |item| item.challenge_id_hex.clone(),
            "pending challenges",
        )?;
        for item in &self.pending_challenges {
            exact_hash32_hex(&item.challenge_id_hex)?;
            exact_hash32_hex(&item.certificate_id_hex)?;
            exact_hash32_hex(&item.opening_decision_id_hex)?;
            validate_recorded_business_height_v0(
                item.opened_height,
                self.last_target_height,
                "challenge opening",
            )?;
            let certificate = self
                .active_certificates
                .binary_search_by(|certificate| {
                    certificate
                        .certificate_id_hex
                        .as_str()
                        .cmp(item.certificate_id_hex.as_str())
                })
                .ok()
                .map(|index| &self.active_certificates[index])
                .context("pending challenge lacks active certificate authority")?;
            ensure!(
                certificate.lifecycle == CertificateAuthorityLifecycleV0::Accepted
                    && item.opened_height > certificate.accepted_height,
                "pending challenge is not monotonic from certificate acceptance"
            );
        }
        validate_strictly_sorted_unique_by(
            &self.pending_governance_proposals,
            |item| item.target_epoch,
            "pending governance proposals",
        )?;
        for item in &self.pending_governance_proposals {
            exact_hash32_hex(&item.proposal_decision_id_hex)?;
            exact_hash32_hex(&item.parameters_hash_hex)?;
            crate::poco_semantics::RolloutPhaseV0::try_from(item.phase)?;
            ensure!(
                item.proposed_height > 0 && item.activation_height > item.proposed_height,
                "governance proposal heights are invalid"
            );
            validate_recorded_business_height_v0(
                item.proposed_height,
                self.last_target_height,
                "governance proposal",
            )?;
        }
        validate_strictly_sorted_unique_by(
            &self.finalized_governance_approvals,
            |item| item.target_epoch,
            "governance approvals",
        )?;
        for item in &self.finalized_governance_approvals {
            crate::poco_semantics::RolloutPhaseV0::try_from(item.phase)?;
            exact_hash32_hex(&item.proposal_decision_id_hex)?;
            exact_hash32_hex(&item.decision_id_hex)?;
            exact_hash32_hex(&item.parameters_hash_hex)?;
            ensure!(
                item.proposed_height > 0
                    && item.proposed_height < item.approval_height
                    && item.approval_height < item.activation_height,
                "governance proposal/approval/activation heights are not monotonic"
            );
            validate_recorded_business_height_v0(
                item.proposed_height,
                self.last_target_height,
                "finalized governance proposal",
            )?;
            validate_recorded_business_height_v0(
                item.approval_height,
                self.last_target_height,
                "governance approval",
            )?;
            ensure!(
                self.pending_governance_proposals
                    .binary_search_by_key(&item.target_epoch, |proposal| proposal.target_epoch)
                    .is_err(),
                "governance epoch is both pending and finalized"
            );
        }
        validate_strictly_sorted_unique_by(
            &self.validator_registration_history,
            |item| item.validator_id_hex.clone(),
            "validator registration history",
        )?;
        let mut globally_used_registration_keys = BTreeSet::new();
        for item in &self.validator_registration_history {
            let validator_id = exact_opaque_hex(&item.validator_id_hex)?;
            let history_head = exact_hash32_hex(&item.history_head_hex)?;
            let consensus_key = exact_hash32_hex(&item.consensus_key_hex)?;
            let proof_digest = exact_hash32_hex(&item.current_proof_digest_hex)?;
            let previous_history_head = exact_hash32_hex(&item.previous_history_head_hex)?;
            let registration_decision = exact_hash32_hex(&item.registration_decision_id_hex)?;
            validate_recorded_business_height_v0(
                item.registration_height,
                self.last_target_height,
                "validator registration",
            )?;
            ensure!(
                globally_used_registration_keys.insert(item.consensus_key_hex.clone()),
                "validator consensus key is reused across registration histories"
            );
            ensure!(
                (item.retired_key_count == 0) == (previous_history_head == [0; 32]),
                "validator predecessor head/retired-key count mismatch"
            );
            ensure!(
                registration_history_head_v0(
                    previous_history_head,
                    &validator_id,
                    consensus_key,
                    item.max_registration_nonce,
                    proof_digest,
                    registration_decision,
                    item.registration_height,
                ) == history_head,
                "validator current history head is not exactly reconstructible"
            );
            ensure!(
                item.revoked_at_height.is_some() == item.revocation_decision_id_hex.is_some(),
                "validator history revocation fields are incomplete"
            );
            if let Some(decision_id) = &item.revocation_decision_id_hex {
                exact_hash32_hex(decision_id)?;
            }
            if let Some(revoked_at) = item.revoked_at_height {
                ensure!(
                    revoked_at > item.registration_height,
                    "validator revocation is not monotonic"
                );
                validate_recorded_business_height_v0(
                    revoked_at,
                    self.last_target_height,
                    "validator revocation",
                )?;
            }
        }
        validate_strictly_sorted_unique_by(
            &self.future_candidate_registrations,
            |item| (item.target_epoch, item.validator_id_hex.clone()),
            "future candidate registrations",
        )?;
        let mut future_keys = BTreeSet::new();
        for item in &self.future_candidate_registrations {
            let validator_id = exact_opaque_hex(&item.validator_id_hex)?;
            ensure!(
                item.target_epoch > 0,
                "future candidate target epoch is zero"
            );
            let consensus_key = exact_hash32_hex(&item.consensus_key_hex)?;
            ensure!(consensus_key != [0; 32], "future candidate key is zero");
            ensure!(
                !globally_used_registration_keys.contains(&item.consensus_key_hex),
                "future candidate consensus key reuses registration-history authority"
            );
            ensure!(
                future_keys.insert(item.consensus_key_hex.clone()),
                "future candidate consensus key is reused"
            );
            let predecessor = exact_hash32_hex(&item.predecessor_history_head_hex)?;
            ensure!(
                match item.previous_registration_nonce {
                    Some(previous) => {
                        predecessor != [0; 32] && item.registration_nonce > previous
                    }
                    None => predecessor == [0; 32],
                },
                "future candidate predecessor nonce/head is incomplete"
            );
            let proof_bytes = exact_hex(
                &item.proof_cev0_hex,
                1,
                MAX_POCO_SEMANTIC_PAYLOAD_BYTES,
                "future candidate proof of possession",
            )?;
            let proof = decode_validator_key_proof_of_possession_v0_exact(&proof_bytes)
                .map_err(|error| anyhow::anyhow!("decode future candidate PoP: {error:?}"))?;
            let fields = proof.fields();
            ensure!(
                fields.target_epoch.get() == item.target_epoch
                    && fields.validator_id.as_bytes() == validator_id
                    && fields.public_key.as_bytes() == &consensus_key
                    && fields.registration_nonce == item.registration_nonce
                    && domain_hash(FUTURE_CANDIDATE_POP_DIGEST_DOMAIN, &proof_bytes)
                        == exact_hash32_hex(&item.proof_digest_hex)?,
                "future candidate record diverges from exact PoP"
            );
            exact_hash32_hex(&item.registration_decision_id_hex)?;
            validate_recorded_business_height_v0(
                item.registration_height,
                self.last_target_height,
                "future candidate registration",
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSemanticChangeV0 {
    kind: u8,
    logical_key_hex: String,
    /// `None` is admitted only by the private prune operation.
    next_value_hex: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawNullifierInsertionV0 {
    family: u8,
    identifier_hex: String,
    proof_hex: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChallengeResolutionV0 {
    Rejected,
    Sustained,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PocoApplicationOperationBodyV0 {
    AuthorizeConsumerKey {
        consumer_id_hex: String,
        consumer_key_id_hex: String,
        public_key_hex: String,
        active_from_height: u64,
        decision_id_hex: String,
    },
    RevokeConsumerKey {
        consumer_id_hex: String,
        consumer_key_id_hex: String,
        public_key_hex: String,
        active_from_height: u64,
        revoked_at_height: u64,
        decision_id_hex: String,
    },
    PruneRevokedConsumerKey {
        consumer_id_hex: String,
        consumer_key_id_hex: String,
    },
    DefineMeterPolicy {
        policy: MeterAuthorityPolicyV0,
        decision_id_hex: String,
    },
    RetireMeterPolicy {
        meter_id_hex: String,
        meter_version: u32,
        retired_at_height: u64,
        decision_id_hex: String,
    },
    PruneRetiredMeter {
        meter_id_hex: String,
        meter_version: u32,
    },
    FundSettlement {
        certificate_id_hex: String,
        settlement_commitment_hex: String,
        reserved_units: CanonicalU128V0,
        funding_decision_id_hex: String,
    },
    AcceptCertificate {
        certificate_id_hex: String,
        funding_decision_id_hex: String,
        acceptance_decision_id_hex: String,
        meter_decision_id_hex: String,
        evidence_decision_id_hex: String,
    },
    ReleaseSettlement {
        certificate_id_hex: String,
        release_decision_id_hex: String,
    },
    OpenChallenge {
        certificate_id_hex: String,
        challenge_id_hex: String,
        opening_decision_id_hex: String,
    },
    ResolveChallenge {
        certificate_id_hex: String,
        challenge_id_hex: String,
        resolution: ChallengeResolutionV0,
        resolution_decision_id_hex: String,
    },
    ProposeGovernance {
        target_epoch: u64,
        phase: u8,
        parameters_hash_hex: String,
        activation_height: u64,
        proposal_decision_id_hex: String,
    },
    ApproveGovernance {
        target_epoch: u64,
        parameters_hash_hex: String,
        activation_height: u64,
        decision_id_hex: String,
    },
    RegisterValidator {
        validator_id_hex: String,
        target_epoch: u64,
        registration_decision_id_hex: String,
    },
    RotateValidator {
        validator_id_hex: String,
        target_epoch: u64,
        previous_history_head_hex: String,
        previous_registration_nonce: u64,
        registration_decision_id_hex: String,
    },
    RegisterFutureCandidate {
        validator_id_hex: String,
        target_epoch: u64,
        previous_registration_nonce: Option<u64>,
        predecessor_history_head_hex: String,
        proof_cev0_hex: String,
        registration_decision_id_hex: String,
    },
    RevokeValidator {
        validator_id_hex: String,
        revocation_decision_id_hex: String,
    },
    PruneRevokedValidatorHistory {
        validator_id_hex: String,
    },
    PruneExpiredCertificate {
        certificate_id_hex: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PocoApplicationOperationV0 {
    schema: String,
    target_height: u64,
    expected_state_revision: u64,
    body: PocoApplicationOperationBodyV0,
    semantic_changes: Vec<RawSemanticChangeV0>,
    nullifier_non_membership_checks: Vec<RawNullifierInsertionV0>,
    nullifier_insertions: Vec<RawNullifierInsertionV0>,
}

impl PocoApplicationOperationV0 {
    pub(crate) fn decode_exact(encoded: &[u8]) -> Result<Self> {
        ensure!(
            !encoded.is_empty() && encoded.len() <= MAX_APPLICATION_OPERATION_BYTES,
            "PoCO application operation byte length is outside bound"
        );
        let decoded: Self =
            serde_json::from_slice(encoded).context("decode PoCO application operation")?;
        decoded.validate_shape()?;
        ensure!(
            serde_json::to_vec(&decoded).context("re-encode PoCO application operation")?
                == encoded,
            "PoCO application operation is not canonical JSON"
        );
        Ok(decoded)
    }

    #[cfg(test)]
    pub(crate) const fn evidence_body(&self) -> &PocoApplicationOperationBodyV0 {
        &self.body
    }

    #[cfg(test)]
    pub(crate) const fn evidence_has_nullifier_non_membership_checks(&self) -> bool {
        !self.nullifier_non_membership_checks.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn evidence_has_nullifier_insertion(
        &self,
        family: u8,
        identifier_hex: &str,
    ) -> bool {
        self.nullifier_insertions
            .iter()
            .any(|item| item.family == family && item.identifier_hex == identifier_hex)
    }

    fn validate_shape(&self) -> Result<()> {
        ensure!(
            self.schema == POCO_APPLICATION_OPERATION_SCHEMA_V0,
            "PoCO application operation schema mismatch"
        );
        ensure!(self.target_height > 0, "operation target height is zero");
        let future_candidate_only = matches!(
            &self.body,
            PocoApplicationOperationBodyV0::RegisterFutureCandidate { .. }
        );
        ensure!(
            if future_candidate_only {
                self.semantic_changes.is_empty()
            } else {
                !self.semantic_changes.is_empty()
                    && self.semantic_changes.len() <= MAX_SEMANTIC_CHANGES_PER_OPERATION
            },
            "semantic change count is outside bound"
        );
        ensure!(
            self.nullifier_non_membership_checks.len() <= MAX_NULLIFIER_INSERTIONS_PER_OPERATION,
            "nullifier non-membership check count exceeds bound"
        );
        ensure!(
            self.nullifier_insertions.len() <= MAX_NULLIFIER_INSERTIONS_PER_OPERATION,
            "nullifier insertion count exceeds bound"
        );
        validate_raw_semantic_order(&self.semantic_changes)?;
        validate_raw_nullifier_order(&self.nullifier_non_membership_checks)?;
        validate_raw_nullifier_order(&self.nullifier_insertions)?;
        Ok(())
    }

    pub(crate) const fn target_height(&self) -> u64 {
        self.target_height
    }

    pub(crate) const fn expected_state_revision(&self) -> u64 {
        self.expected_state_revision
    }
}

/// Exact crate-internal operation identifier used by production replay
/// evidence. Invalid or non-canonical raw operations cannot acquire an ID.
pub(crate) fn poco_application_operation_id_v0(encoded: &[u8]) -> Result<[u8; 32]> {
    PocoApplicationOperationV0::decode_exact(encoded)?;
    Ok(domain_hash(APPLICATION_OPERATION_DOMAIN, encoded))
}

/// Runtime-authenticated context for one next-height overlay.  Construction is
/// crate-private; telemetry IDs and checkpoint events cannot construct it.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedPocoApplicationContextV0 {
    source_version: u64,
    source_root: [u8; 32],
    target_height: Height,
    chain_id: ChainId,
    genesis_hash: GenesisHash,
    active_epoch: Epoch,
    active_parameters: ConsensusParametersV0,
    authority_signer_commitment: [u8; 32],
}

impl AuthenticatedPocoApplicationContextV0 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        source_version: u64,
        source_root: [u8; 32],
        target_height: Height,
        chain_id: ChainId,
        genesis_hash: GenesisHash,
        active_epoch: Epoch,
        active_parameters: ConsensusParametersV0,
        authority_signer_commitment: [u8; 32],
    ) -> Result<Self> {
        ensure!(source_root != [0; 32], "zero authenticated source root");
        ensure!(
            authority_signer_commitment != [0; 32],
            "zero authenticated application-authority signer commitment"
        );
        ensure!(
            source_version.checked_add(1) == Some(target_height.get()),
            "PoCO application target is not the exact next height"
        );
        active_parameters
            .validate_safety_invariants()
            .map_err(|error| anyhow::anyhow!("invalid PoCO application parameters: {error:?}"))?;
        let geometry = EpochGeometryV0::new(active_epoch, &active_parameters)
            .map_err(|error| anyhow::anyhow!("invalid PoCO application epoch: {error:?}"))?;
        let cutoff = geometry
            .checkpoint_height()
            .get()
            .checked_sub(active_parameters.snapshot_lead_blocks())
            .context("scheduled PoCO cutoff height underflow")?;
        ensure!(
            target_height >= geometry.epoch_start() && target_height.get() <= cutoff,
            "PoCO business operation target is outside the active pre-cutoff epoch window"
        );
        Ok(Self {
            source_version,
            source_root,
            target_height,
            chain_id,
            genesis_hash,
            active_epoch,
            active_parameters,
            authority_signer_commitment,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SealedPocoNamespaceWriteV0 {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

/// Private output consumed by the one block/JMT merger.  It intentionally has
/// no public constructor and exposes no capability outside this crate.
pub(crate) struct SealedPocoApplicationPlanV0 {
    namespace_writes: Vec<SealedPocoNamespaceWriteV0>,
    source_version: u64,
    source_root: [u8; 32],
    target_height: Height,
    operation_root: [u8; 32],
    operation_count: u32,
    mutation_root: [u8; 32],
    mutation_count: u32,
    target_manifest: PocoSnapshotManifestV0,
}

impl SealedPocoApplicationPlanV0 {
    pub(crate) fn namespace_writes(&self) -> impl ExactSizeIterator<Item = (&[u8], Option<&[u8]>)> {
        self.namespace_writes
            .iter()
            .map(|write| (write.key.as_slice(), write.value.as_deref()))
    }

    pub(crate) const fn source_version(&self) -> u64 {
        self.source_version
    }

    pub(crate) const fn source_root(&self) -> [u8; 32] {
        self.source_root
    }

    pub(crate) const fn target_height(&self) -> Height {
        self.target_height
    }

    pub(crate) const fn operation_root(&self) -> [u8; 32] {
        self.operation_root
    }

    pub(crate) const fn operation_count(&self) -> u32 {
        self.operation_count
    }

    pub(crate) const fn mutation_root(&self) -> [u8; 32] {
        self.mutation_root
    }

    pub(crate) const fn mutation_count(&self) -> u32 {
        self.mutation_count
    }

    pub(crate) const fn target_manifest(&self) -> PocoSnapshotManifestV0 {
        self.target_manifest
    }
}

pub(crate) const fn poco_application_authority_identity_v0() -> &'static [u8] {
    POCO_APPLICATION_AUTHORITY_IDENTITY_V0
}

pub(crate) fn poco_application_authority_logical_key_v0() -> [u8; 32] {
    semantic_identity_digest_v0(
        PocoSnapshotEntryKindV0::ApplicationAuthorityState,
        POCO_APPLICATION_AUTHORITY_IDENTITY_V0,
    )
}

pub(crate) fn genesis_poco_application_authority_entry_v0() -> Result<PocoSnapshotEntryV0> {
    let state = PocoApplicationAuthorityStateV0::empty();
    let value = encode_application_authority_envelope_v0(&state)?;
    PocoSnapshotEntryV0::new(
        PocoSnapshotEntryKindV0::ApplicationAuthorityState,
        poco_application_authority_logical_key_v0().to_vec(),
        value,
    )
}

#[cfg(test)]
pub(crate) fn test_orphan_meter_authority_entry_v0() -> Result<PocoSnapshotEntryV0> {
    let mut state = PocoApplicationAuthorityStateV0::empty();
    state.revision = 2;
    state.last_target_height = 1;
    state.meter_policies.push(MeterAuthorityPolicyV0 {
        meter_id_hex: hex::encode(b"orphan-meter-v0"),
        meter_version: 1,
        task_id_hex: hex::encode(b"orphan-task-v0"),
        output_commitment_hex: None,
        unit_scale: CanonicalU128V0::new(1),
        evidence_policy: MeterEvidencePolicyV0::Optional,
        per_certificate_cap: CanonicalU128V0::new(1),
        rolling_cap: CanonicalU128V0::new(1),
        rolling_epoch_span: 1,
        retention_blocks: 1,
        active_from_height: 1,
        retired_at_height: None,
    });
    let value = encode_application_authority_envelope_v0(&state)?;
    PocoSnapshotEntryV0::new(
        PocoSnapshotEntryKindV0::ApplicationAuthorityState,
        poco_application_authority_logical_key_v0().to_vec(),
        value,
    )
}

struct ActiveProjectionContextV0 {
    validator_set: ValidatorSet,
    parameters: ConsensusParametersV0,
    geometry: EpochGeometryV0,
}

fn active_projection_context_v0(
    entries: &BTreeMap<(PocoSnapshotEntryKindV0, Vec<u8>), Vec<u8>>,
) -> Result<ActiveProjectionContextV0> {
    let mut active_set = None;
    for ((kind, logical_key), value) in entries {
        if *kind != PocoSnapshotEntryKindV0::ValidatorConfiguration {
            continue;
        }
        let parts = owned_semantic_parts(*kind, logical_key, value)?;
        if parts.identity.first().copied() != Some(1) {
            continue;
        }
        ensure!(
            active_set.is_none(),
            "projection has multiple active validator configurations"
        );
        active_set = Some(
            decode_validator_set_v0_exact(&parts.payload)
                .map_err(|error| anyhow::anyhow!("decode active validator set: {error:?}"))?,
        );
    }
    let validator_set = active_set.context("projection lacks active validator configuration")?;
    let mut parameter_identity = vec![1];
    parameter_identity.extend_from_slice(&validator_set.epoch().get().to_be_bytes());
    let parameter_parts = projection_parts_for_identity_v0(
        entries,
        PocoSnapshotEntryKindV0::ConsensusParameters,
        &parameter_identity,
    )?;
    let parameters = decode_consensus_parameters_v0_exact(&parameter_parts.payload)
        .map_err(|error| anyhow::anyhow!("decode active consensus parameters: {error:?}"))?;
    ensure!(
        validator_set.consensus_parameters_hash().as_bytes() == parameters.hash().as_bytes(),
        "active validator set/parameters hash mismatch"
    );
    let geometry = EpochGeometryV0::new(validator_set.epoch(), &parameters)
        .map_err(|error| anyhow::anyhow!("invalid active projection epoch: {error:?}"))?;
    Ok(ActiveProjectionContextV0 {
        validator_set,
        parameters,
        geometry,
    })
}

/// Cross-entry referential-integrity audit for the authenticated kind-16
/// authority. A legacy projection without kind 16 remains restorable, but the
/// application planner will stay inactive because `from_projection` requires
/// the authority entry after this audit.
fn relationship_authorizes_retained_certificate_v0(
    fact: &SemanticFactV0,
    relationship_class: u8,
    billing_end_height: u64,
    accepted_height: u64,
) -> bool {
    matches!(
        fact,
        SemanticFactV0::RelationshipClassification { class, expires_at }
            if *class as u8 == relationship_class
                && billing_end_height < *expires_at
                && accepted_height < *expires_at
    )
}

pub(crate) fn validate_application_authority_projection_v0(
    projection: &ProductionPocoProjectionV0,
) -> Result<()> {
    let entries = projection
        .entries()
        .iter()
        .map(|entry| ((entry.kind, entry.logical_key.clone()), entry.value.clone()))
        .collect::<BTreeMap<_, _>>();
    let authority_key = poco_application_authority_logical_key_v0().to_vec();
    let Some(authority_value) = entries.get(&(
        PocoSnapshotEntryKindV0::ApplicationAuthorityState,
        authority_key.clone(),
    )) else {
        return Ok(());
    };
    let authority_parts = owned_semantic_parts(
        PocoSnapshotEntryKindV0::ApplicationAuthorityState,
        &authority_key,
        authority_value,
    )?;
    ensure!(
        authority_parts.identity == POCO_APPLICATION_AUTHORITY_IDENTITY_V0,
        "application authority projection identity mismatch"
    );
    let authority = PocoApplicationAuthorityStateV0::decode_exact(&authority_parts.payload)?;
    ensure!(
        authority_parts.revision == authority.revision,
        "application authority projection revision mismatch"
    );
    ensure!(
        authority.last_target_height <= projection.manifest().cutoff_height().get(),
        "application authority target height is ahead of projection manifest"
    );
    let needs_active_context = !authority.active_certificates.is_empty()
        || usage_bucket_count_v0(&authority)? > 0
        || !authority.pending_governance_proposals.is_empty()
        || !authority.finalized_governance_approvals.is_empty()
        || !authority.validator_registration_history.is_empty()
        || !authority.future_candidate_registrations.is_empty();
    let active_context = needs_active_context
        .then(|| active_projection_context_v0(&entries))
        .transpose()?;

    let mut authority_consumer_key_entries = BTreeSet::new();
    let mut authority_nonce_entries = BTreeSet::new();
    for key_authority in &authority.consumer_keys {
        let consumer_id = exact_opaque_hex(&key_authority.consumer_id_hex)?;
        let consumer_key_id = exact_opaque_hex(&key_authority.consumer_key_id_hex)?;
        let identity = joined_identity(&[&consumer_id, &consumer_key_id]);
        let logical_key = semantic_identity_digest_v0(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            &identity,
        );
        authority_consumer_key_entries.insert(logical_key.to_vec());
        let fact = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            &identity,
        )?
        .fact;
        match fact {
            SemanticFactV0::ConsumerKeyAuthorization {
                public_key,
                active_from,
                revoked_at,
            } => ensure!(
                hex::encode(public_key) == key_authority.public_key_hex
                    && active_from == key_authority.active_from_height
                    && revoked_at == key_authority.revoked_at_height,
                "consumer-key authority diverges from exact kind-2 fact"
            ),
            _ => bail!("consumer-key authority references wrong semantic fact"),
        }
        for watermark in &key_authority.nonce_watermarks {
            let provider_id = exact_opaque_hex(&watermark.provider_id_hex)?;
            let nonce_identity = joined_identity(&[&consumer_id, &consumer_key_id, &provider_id]);
            let nonce_key = semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::ConsumerNonce,
                &nonce_identity,
            );
            ensure!(
                hex::encode(nonce_key) == watermark.logical_key_hex,
                "consumer nonce watermark logical key mismatch"
            );
            let nonce = projection_parts_for_identity_v0(
                &entries,
                PocoSnapshotEntryKindV0::ConsumerNonce,
                &nonce_identity,
            )?;
            ensure!(
                matches!(
                    nonce.fact,
                    SemanticFactV0::ConsumerNonce { max_accepted_nonce }
                        if max_accepted_nonce == watermark.max_accepted_nonce
                ),
                "consumer nonce watermark diverges from exact kind-3 fact"
            );
            authority_nonce_entries.insert(nonce_key.to_vec());
        }
    }
    ensure!(
        entries
            .keys()
            .filter(|(kind, _)| *kind == PocoSnapshotEntryKindV0::ConsumerKeyAuthorization)
            .all(|(_, key)| authority_consumer_key_entries.contains(key)),
        "orphan consumer-key semantic entry lacks authority companion"
    );
    ensure!(
        entries
            .keys()
            .filter(|(kind, _)| *kind == PocoSnapshotEntryKindV0::ConsumerNonce)
            .all(|(_, key)| authority_nonce_entries.contains(key)),
        "orphan consumer nonce semantic entry lacks authority watermark"
    );

    let mut authority_meter_entries = BTreeSet::new();
    for policy in &authority.meter_policies {
        let meter_id = exact_opaque_hex(&policy.meter_id_hex)?;
        let meter_identity = meter_identity(&meter_id, policy.meter_version);
        authority_meter_entries.insert(
            semantic_identity_digest_v0(PocoSnapshotEntryKindV0::MeterDefinition, &meter_identity)
                .to_vec(),
        );
        let fact = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::MeterDefinition,
            &meter_identity,
        )?
        .fact;
        match fact {
            SemanticFactV0::MeterDefinition {
                unit_scale,
                active_from,
                retired_at,
            } => ensure!(
                unit_scale == policy.unit_scale.get()?
                    && active_from == policy.active_from_height
                    && retired_at == policy.retired_at_height,
                "meter authority diverges from exact kind-5 fact"
            ),
            _ => bail!("meter authority references wrong semantic fact"),
        }
    }
    ensure!(
        entries
            .keys()
            .filter(|(kind, _)| *kind == PocoSnapshotEntryKindV0::MeterDefinition)
            .all(|(_, key)| authority_meter_entries.contains(key)),
        "orphan meter semantic entry lacks authority companion"
    );
    for usage in &authority.meter_usage {
        let policy_index = authority
            .meter_policies
            .binary_search_by(|policy| {
                (&policy.meter_id_hex, policy.meter_version)
                    .cmp(&(&usage.meter_id_hex, usage.meter_version))
            })
            .map_err(|_| anyhow::anyhow!("meter usage references absent policy"))?;
        let active_epoch = active_context
            .as_ref()
            .context("meter usage lacks active projection context")?
            .validator_set
            .epoch()
            .get();
        ensure!(
            usage.window_epoch
                == active_epoch / authority.meter_policies[policy_index].rolling_epoch_span,
            "meter usage window differs from active epoch/span"
        );
    }
    if usage_bucket_count_v0(&authority)? > 0 {
        let active_epoch = active_context
            .as_ref()
            .context("usage authority lacks active projection context")?
            .validator_set
            .epoch()
            .get();
        ensure!(
            authority
                .consumer_provider_usage
                .iter()
                .all(|usage| usage.window_epoch == active_epoch)
                && authority
                    .task_provider_usage
                    .iter()
                    .all(|usage| usage.window_epoch == active_epoch)
                && authority
                    .provider_usage
                    .iter()
                    .all(|usage| usage.window_epoch == active_epoch),
            "active-parameter usage window differs from active epoch"
        );
    }
    for reservation in &authority.funded_unused_reservations {
        let certificate_id = exact_hash32_hex(&reservation.certificate_id_hex)?;
        let fact = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::Settlement,
            &certificate_id,
        )?
        .fact;
        match fact {
            SemanticFactV0::Settlement {
                commitment,
                state: SettlementStateV0::FinalizedFundedUnused,
                finalized_height,
            } => ensure!(
                hex::encode(commitment) == reservation.settlement_commitment_hex
                    && finalized_height == reservation.finalized_height,
                "funded reservation diverges from exact settlement fact"
            ),
            _ => bail!("funded reservation references non-funded settlement"),
        }
    }
    for certificate in &authority.active_certificates {
        let certificate_id = exact_hash32_hex(&certificate.certificate_id_hex)?;
        let certificate_parts = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::ConsumptionCertificate,
            &certificate_id,
        )?;
        let decoded_certificate =
            decode_consumption_certificate_v0_exact(&certificate_parts.payload)
                .map_err(|error| anyhow::anyhow!("decode active certificate: {error:?}"))?;
        let body = decoded_certificate.body();
        ensure!(
            hex::encode(body.consumer_id().as_bytes()) == certificate.consumer_id_hex
                && hex::encode(body.consumer_key_id().as_bytes())
                    == certificate.consumer_key_id_hex
                && hex::encode(body.provider_id().as_bytes()) == certificate.provider_id_hex
                && hex::encode(body.task_id()) == certificate.task_id_hex
                && hex::encode(body.meter_id()) == certificate.meter_id_hex
                && body.meter_version() == certificate.meter_version
                && hex::encode(body.settlement_commitment().as_slice())
                    == certificate.settlement_commitment_hex
                && body.consumed_units() == certificate.consumed_units.get()?
                && body
                    .measurement_evidence_root()
                    .map(|root| hex::encode(root.as_slice()))
                    == certificate.evidence_root_hex,
            "active certificate authority diverges from exact certificate body"
        );
        let projection_context = active_context
            .as_ref()
            .context("active certificate lacks active projection context")?;
        ensure!(
            certificate.finalized_epoch <= projection_context.validator_set.epoch().get(),
            "certificate finalized epoch is ahead of the active epoch"
        );
        let finalized_geometry = EpochGeometryV0::new(
            Epoch::new(certificate.finalized_epoch),
            &projection_context.parameters,
        )
        .map_err(|error| anyhow::anyhow!("invalid certificate finalization epoch: {error:?}"))?;
        ensure!(
            certificate.accepted_height >= finalized_geometry.epoch_start().get()
                && certificate.accepted_height <= finalized_geometry.epoch_end().get(),
            "certificate accepted height does not reconstruct its finalized epoch"
        );
        let consumer_key_index = authority
            .consumer_keys
            .binary_search_by(|key| {
                (
                    key.consumer_id_hex.as_str(),
                    key.consumer_key_id_hex.as_str(),
                )
                    .cmp(&(
                        certificate.consumer_id_hex.as_str(),
                        certificate.consumer_key_id_hex.as_str(),
                    ))
            })
            .map_err(|_| anyhow::anyhow!("active certificate consumer key authority is absent"))?;
        let consumer_key_authority = &authority.consumer_keys[consumer_key_index];
        let consumer_id = exact_opaque_hex(&consumer_key_authority.consumer_id_hex)?;
        let consumer_key_id = exact_opaque_hex(&consumer_key_authority.consumer_key_id_hex)?;
        let consumer_key_identity = joined_identity(&[&consumer_id, &consumer_key_id]);
        let consumer_key_fact = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            &consumer_key_identity,
        )?;
        ensure!(
            matches!(
                consumer_key_fact.fact,
                SemanticFactV0::ConsumerKeyAuthorization {
                    public_key,
                    active_from,
                    revoked_at,
                } if hex::encode(public_key) == consumer_key_authority.public_key_hex
                    && active_from == consumer_key_authority.active_from_height
                    && revoked_at == consumer_key_authority.revoked_at_height
                    && body.billing_start_height().get() >= active_from
                    && certificate.accepted_height >= active_from
                    && revoked_at.is_none_or(|height| {
                        body.billing_end_height().get() < height
                            && certificate.accepted_height < height
                    })
            ),
            "active certificate consumer-key interval/public-key authority mismatch"
        );
        let consumer_public_key = exact_hash32_hex(&consumer_key_authority.public_key_hex)?;
        decoded_certificate
            .verify(
                projection_context.validator_set.genesis_hash(),
                projection_context.validator_set.chain_id(),
                &projection_context.parameters,
                Height::new(certificate.accepted_height),
                ConsensusPublicKey::new(consumer_public_key),
                &StrictEd25519Verifier,
            )
            .map_err(|error| {
                anyhow::anyhow!("invalid projected consumption certificate: {error:?}")
            })?;
        let provider_id_hex = hex::encode(body.provider_id().as_bytes());
        let watermark_index = consumer_key_authority
            .nonce_watermarks
            .binary_search_by(|watermark| watermark.provider_id_hex.cmp(&provider_id_hex))
            .map_err(|_| anyhow::anyhow!("active certificate lacks provider nonce watermark"))?;
        ensure!(
            consumer_key_authority.nonce_watermarks[watermark_index].max_accepted_nonce
                >= body.consumer_nonce(),
            "active certificate nonce exceeds authenticated provider watermark"
        );
        let meter_index = authority
            .meter_policies
            .binary_search_by(|policy| {
                (policy.meter_id_hex.as_str(), policy.meter_version)
                    .cmp(&(certificate.meter_id_hex.as_str(), certificate.meter_version))
            })
            .map_err(|_| anyhow::anyhow!("active certificate meter authority is absent"))?;
        let meter_policy = &authority.meter_policies[meter_index];
        ensure!(
            meter_policy.task_id_hex == certificate.task_id_hex
                && meter_policy
                    .output_commitment_hex
                    .as_deref()
                    .is_none_or(|output| {
                        exact_hash32_hex(output).is_ok_and(|hash| hash == *body.output_commitment())
                    }),
            "active certificate meter task/output authority mismatch"
        );
        let tuple_identity = consumption_tuple_identity(body);
        let tuple_key = semantic_identity_digest_v0(
            PocoSnapshotEntryKindV0::UniqueConsumptionTuple,
            &tuple_identity,
        );
        ensure!(
            hex::encode(tuple_key) == certificate.tuple_key_hex,
            "active certificate tuple key was not derived from raw certificate"
        );
        let tuple_value = entries
            .get(&(
                PocoSnapshotEntryKindV0::UniqueConsumptionTuple,
                tuple_key.to_vec(),
            ))
            .context("active certificate tuple entry is absent")?;
        let tuple = owned_semantic_parts(
            PocoSnapshotEntryKindV0::UniqueConsumptionTuple,
            &tuple_key,
            tuple_value,
        )?;
        validate_tuple_acceptance_authority_v0(
            &tuple.fact,
            certificate_id,
            certificate.accepted_height,
        )?;
        let settlement = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::Settlement,
            &certificate_id,
        )?;
        match settlement.fact {
            SemanticFactV0::Settlement {
                commitment,
                state: SettlementStateV0::Consumed,
                finalized_height,
            } => ensure!(
                hex::encode(commitment) == certificate.settlement_commitment_hex
                    && finalized_height == certificate.settlement_finalized_height
                    && finalized_height <= certificate.accepted_height,
                "active certificate settlement authority mismatch"
            ),
            _ => bail!("active certificate settlement is not consumed"),
        }
        let measurement = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::MeasurementEvidence,
            &certificate_id,
        )?;
        validate_measurement_policy(
            meter_policy.evidence_policy,
            body.measurement_evidence_root().copied(),
            Some(&measurement.fact),
        )?;
        match measurement.fact {
            SemanticFactV0::MeasurementEvidence {
                evidence_root,
                state: MeasurementStateV0::Verified,
            } => ensure!(
                evidence_root.map(hex::encode) == certificate.evidence_root_hex,
                "active certificate verified evidence root mismatch"
            ),
            SemanticFactV0::MeasurementEvidence {
                evidence_root: None,
                state: MeasurementStateV0::NotRequired,
            } => ensure!(
                certificate.evidence_root_hex.is_none(),
                "active certificate unexpected evidence authority"
            ),
            _ => bail!("active certificate measurement is not admissible"),
        }
        let relationship_provider = exact_opaque_hex(&certificate.provider_id_hex)?;
        let relationship_consumer = exact_opaque_hex(&certificate.consumer_id_hex)?;
        let relationship_task = exact_opaque_hex(&certificate.task_id_hex)?;
        let relationship_identity = joined_identity(&[
            &relationship_provider,
            &relationship_consumer,
            &relationship_task,
        ]);
        ensure!(
            hex::encode(semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::RelationshipClassification,
                &relationship_identity,
            )) == certificate.relationship_key_hex,
            "active certificate relationship key authority mismatch"
        );
        let relationship = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::RelationshipClassification,
            &relationship_identity,
        )?;
        ensure!(
            relationship_authorizes_retained_certificate_v0(
                &relationship.fact,
                certificate.relationship_class,
                body.billing_end_height().get(),
                certificate.accepted_height,
            ),
            "active certificate relationship authority mismatch"
        );
        let provider_id = exact_opaque_hex(&certificate.provider_id_hex)?;
        let registration = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            &provider_id,
        )?;
        ensure!(
            matches!(
                registration.fact,
                SemanticFactV0::ValidatorRegistration {
                    consensus_key,
                    registration_nonce,
                    proof_digest,
                    state: RegistrationStateV0::Active,
                } if hex::encode(consensus_key) == certificate.provider_consensus_key_hex
                    && registration_nonce == certificate.provider_registration_nonce
                    && authority.validator_registration_history.iter().any(|history| {
                        history.validator_id_hex == certificate.provider_id_hex
                            && history.current_proof_digest_hex == hex::encode(proof_digest)
                    })
            ),
            "active certificate provider registration authority mismatch"
        );
        let provider_history_index = authority
            .validator_registration_history
            .binary_search_by(|history| {
                history
                    .validator_id_hex
                    .as_str()
                    .cmp(certificate.provider_id_hex.as_str())
            })
            .map_err(|_| anyhow::anyhow!("active certificate provider history is absent"))?;
        let provider_history = &authority.validator_registration_history[provider_history_index];
        ensure!(
            provider_history.revoked_at_height.is_none()
                && provider_history.consensus_key_hex == certificate.provider_consensus_key_hex
                && provider_history.max_registration_nonce
                    == certificate.provider_registration_nonce
                && provider_history.current_proof_digest_hex
                    == certificate.provider_proof_digest_hex
                && provider_history.registration_decision_id_hex
                    == certificate.provider_registration_decision_id_hex
                && provider_history.registration_height == certificate.provider_registration_height
                && provider_history.history_head_hex
                    == certificate.provider_registration_history_head_hex,
            "active certificate provider registration provenance is substituted"
        );
        // A strictly registered compute provider is allowed to earn mature
        // PoCO capacity before it is admitted to the validator set. Requiring
        // old-set membership here would make a new validator candidate
        // circularly impossible. The exact kind-9 fact, kind-16 history and
        // strict active-epoch PoP above are the provider authority boundary.
        let lifecycle = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            &certificate_id,
        )?;
        let pending_challenge = authority
            .pending_challenges
            .iter()
            .find(|challenge| challenge.certificate_id_hex == certificate.certificate_id_hex);
        let (expected_lifecycle, expected_height, expected_decision_id) =
            match (certificate.lifecycle, pending_challenge) {
                (CertificateAuthorityLifecycleV0::Accepted, Some(challenge)) => (
                    LifecycleStateV0::ChallengePending,
                    challenge.opened_height,
                    challenge.opening_decision_id_hex.as_str(),
                ),
                (CertificateAuthorityLifecycleV0::Accepted, None) => (
                    LifecycleStateV0::Accepted,
                    certificate.lifecycle_effective_height,
                    certificate.lifecycle_decision_id_hex.as_str(),
                ),
                (CertificateAuthorityLifecycleV0::ChallengeRejected, None) => (
                    LifecycleStateV0::ChallengeRejected,
                    certificate.lifecycle_effective_height,
                    certificate.lifecycle_decision_id_hex.as_str(),
                ),
                (CertificateAuthorityLifecycleV0::ChallengeSustained, None) => (
                    LifecycleStateV0::ChallengeSustained,
                    certificate.lifecycle_effective_height,
                    certificate.lifecycle_decision_id_hex.as_str(),
                ),
                (
                    CertificateAuthorityLifecycleV0::ChallengeRejected
                    | CertificateAuthorityLifecycleV0::ChallengeSustained,
                    Some(_),
                ) => bail!("terminal certificate still has pending challenge authority"),
            };
        exact_hash32_hex(expected_decision_id)?;
        ensure!(
            matches!(
                lifecycle.fact,
                SemanticFactV0::RevocationOrChallenge { state, effective_height }
                    if state == expected_lifecycle && effective_height == expected_height
            ),
            "active certificate lifecycle height/authority/fact mismatch"
        );
        let actual_retained_keys = certificate
            .semantic_keys
            .iter()
            .map(|key| {
                Ok((
                    PocoSnapshotEntryKindV0::from_u8(key.kind)?,
                    exact_hash32_hex(&key.logical_key_hex)?.to_vec(),
                ))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let expected_retained_keys = BTreeSet::from([
            (
                PocoSnapshotEntryKindV0::ConsumptionCertificate,
                semantic_identity_digest_v0(
                    PocoSnapshotEntryKindV0::ConsumptionCertificate,
                    &certificate_id,
                )
                .to_vec(),
            ),
            (
                PocoSnapshotEntryKindV0::UniqueConsumptionTuple,
                tuple_key.to_vec(),
            ),
            (
                PocoSnapshotEntryKindV0::Settlement,
                semantic_identity_digest_v0(PocoSnapshotEntryKindV0::Settlement, &certificate_id)
                    .to_vec(),
            ),
            (
                PocoSnapshotEntryKindV0::MeasurementEvidence,
                semantic_identity_digest_v0(
                    PocoSnapshotEntryKindV0::MeasurementEvidence,
                    &certificate_id,
                )
                .to_vec(),
            ),
            (
                PocoSnapshotEntryKindV0::RevocationOrChallenge,
                semantic_identity_digest_v0(
                    PocoSnapshotEntryKindV0::RevocationOrChallenge,
                    &certificate_id,
                )
                .to_vec(),
            ),
        ]);
        ensure!(
            actual_retained_keys == expected_retained_keys
                && actual_retained_keys
                    .iter()
                    .all(|key| entries.contains_key(key)),
            "active certificate retained semantic set is substituted or incomplete"
        );
    }
    for challenge in &authority.pending_challenges {
        let certificate = authority
            .active_certificates
            .iter()
            .find(|certificate| certificate.certificate_id_hex == challenge.certificate_id_hex)
            .context("pending challenge lacks accepted certificate authority")?;
        ensure!(
            certificate.lifecycle == CertificateAuthorityLifecycleV0::Accepted
                && challenge.opened_height > certificate.accepted_height,
            "pending challenge is not monotonic from certificate acceptance"
        );
        let certificate_id = exact_hash32_hex(&challenge.certificate_id_hex)?;
        let lifecycle = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            &certificate_id,
        )?;
        ensure!(
            matches!(
                lifecycle.fact,
                SemanticFactV0::RevocationOrChallenge {
                    state: LifecycleStateV0::ChallengePending,
                    effective_height,
                } if effective_height == challenge.opened_height
            ),
            "pending challenge diverges from lifecycle fact"
        );
    }
    for proposal in &authority.pending_governance_proposals {
        let projection_context = active_context
            .as_ref()
            .context("pending governance lacks active projection context")?;
        let expected_target_epoch = projection_context
            .validator_set
            .epoch()
            .get()
            .checked_add(1)
            .context("active governance target epoch exhausted")?;
        let expected_activation_height = projection_context
            .geometry
            .epoch_end()
            .get()
            .checked_add(1)
            .context("active governance activation height exhausted")?;
        ensure!(
            proposal.target_epoch == expected_target_epoch
                && proposal.activation_height == expected_activation_height,
            "pending governance target epoch/activation is not the exact active successor"
        );
        let governance = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::RolloutOrGovernance,
            &proposal.target_epoch.to_be_bytes(),
        )?;
        ensure!(
            matches!(
                governance.fact,
                SemanticFactV0::RolloutOrGovernance {
                    target_epoch,
                    phase,
                    parameters_hash,
                    activation_height,
                    approval: GovernanceApprovalV0::Pending,
                } if target_epoch == proposal.target_epoch
                    && phase as u8 == proposal.phase
                    && hex::encode(parameters_hash) == proposal.parameters_hash_hex
                    && activation_height == proposal.activation_height
            ),
            "governance proposal diverges from exact kind-15 fact"
        );
        let next_parameters = validate_governance_parameters_companion_v0(
            &entries,
            proposal.target_epoch,
            &proposal.parameters_hash_hex,
        )?;
        let next_geometry =
            EpochGeometryV0::new(Epoch::new(proposal.target_epoch), &next_parameters)
                .map_err(|error| anyhow::anyhow!("invalid pending governance epoch: {error:?}"))?;
        ensure!(
            next_geometry.epoch_start().get() == proposal.activation_height,
            "pending governance parameters do not start at the authenticated activation height"
        );
        ensure!(
            u8::from(next_parameters.rollout_phase()) == proposal.phase,
            "pending governance phase differs from its parameters companion"
        );
    }
    for history in &authority.validator_registration_history {
        let validator_id = exact_opaque_hex(&history.validator_id_hex)?;
        let registration = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            &validator_id,
        )?;
        let (consensus_key, registration_nonce, proof_digest, state) = match &registration.fact {
            SemanticFactV0::ValidatorRegistration {
                consensus_key,
                registration_nonce,
                proof_digest,
                state,
            } => (*consensus_key, *registration_nonce, *proof_digest, *state),
            _ => bail!("validator history references wrong semantic fact"),
        };
        ensure!(
            hex::encode(consensus_key) == history.consensus_key_hex
                && registration_nonce == history.max_registration_nonce
                && hex::encode(proof_digest) == history.current_proof_digest_hex
                && state
                    == if history.revoked_at_height.is_some() {
                        RegistrationStateV0::Revoked
                    } else {
                        RegistrationStateV0::Active
                    },
            "validator history diverges from exact registration fact"
        );
        let proof_bytes = registration_proof_bytes(&registration.payload)?;
        let proof = decode_validator_key_proof_of_possession_v0_exact(proof_bytes)
            .map_err(|error| anyhow::anyhow!("decode projected validator PoP: {error:?}"))?;
        let validator_id = ValidatorId::from_bytes(&validator_id)
            .map_err(|error| anyhow::anyhow!("invalid projected validator ID: {error:?}"))?;
        let projection_context = active_context
            .as_ref()
            .context("validator history lacks active projection context")?;
        let proof_epoch = proof.fields().target_epoch;
        ensure!(
            proof_epoch <= projection_context.validator_set.epoch(),
            "active provider registration PoP is from a future epoch"
        );
        let registration_geometry =
            EpochGeometryV0::new(proof_epoch, &projection_context.parameters).map_err(|error| {
                anyhow::anyhow!("invalid provider registration epoch: {error:?}")
            })?;
        ensure!(
            history.registration_height >= registration_geometry.epoch_start().get()
                && history.registration_height <= registration_geometry.epoch_end().get(),
            "provider registration height does not reconstruct its PoP epoch"
        );
        proof
            .verify_for_registration(
                projection_context.validator_set.genesis_hash(),
                projection_context.validator_set.chain_id(),
                proof_epoch,
                validator_id,
                ConsensusPublicKey::new(consensus_key),
                &StrictEd25519Verifier,
            )
            .map_err(|error| {
                anyhow::anyhow!("invalid projected validator proof of possession: {error:?}")
            })?;
        ensure!(
            proof.fields().registration_nonce == registration_nonce,
            "projected validator PoP nonce differs from registration fact"
        );
    }
    for candidate in &authority.future_candidate_registrations {
        let projection_context = active_context
            .as_ref()
            .context("future candidate lacks active projection context")?;
        let target_epoch = projection_context
            .validator_set
            .epoch()
            .checked_next()
            .map_err(|error| anyhow::anyhow!("future candidate target epoch: {error:?}"))?;
        ensure!(
            candidate.target_epoch == target_epoch.get(),
            "future candidate is not registered for the exact active successor epoch"
        );
        ensure!(
            candidate.registration_height >= projection_context.geometry.epoch_start().get()
                && candidate.registration_height <= projection_context.geometry.epoch_end().get(),
            "future candidate registration height is outside its source active epoch"
        );
        let validator_id_bytes = exact_opaque_hex(&candidate.validator_id_hex)?;
        let validator_id = ValidatorId::from_bytes(&validator_id_bytes)
            .map_err(|error| anyhow::anyhow!("invalid future candidate ID: {error:?}"))?;
        let consensus_key =
            ConsensusPublicKey::new(exact_hash32_hex(&candidate.consensus_key_hex)?);
        let proof_bytes = exact_hex(
            &candidate.proof_cev0_hex,
            1,
            MAX_POCO_SEMANTIC_PAYLOAD_BYTES,
            "future candidate proof of possession",
        )?;
        let proof = decode_validator_key_proof_of_possession_v0_exact(&proof_bytes)
            .map_err(|error| anyhow::anyhow!("decode projected future candidate PoP: {error:?}"))?;
        proof
            .verify_for_registration(
                projection_context.validator_set.genesis_hash(),
                projection_context.validator_set.chain_id(),
                target_epoch,
                validator_id,
                consensus_key,
                &StrictEd25519Verifier,
            )
            .map_err(|error| {
                anyhow::anyhow!("invalid projected future candidate PoP: {error:?}")
            })?;
        ensure!(
            proof.fields().registration_nonce == candidate.registration_nonce,
            "future candidate PoP nonce differs from authority"
        );
        let predecessor = exact_hash32_hex(&candidate.predecessor_history_head_hex)?;
        match projection_context.validator_set.validator(validator_id) {
            Some(old) if old.consensus_key() != consensus_key => {
                let previous_nonce = candidate
                    .previous_registration_nonce
                    .context("changed-key future candidate lacks predecessor nonce")?;
                let history = authority
                    .validator_registration_history
                    .binary_search_by(|item| {
                        item.validator_id_hex
                            .as_str()
                            .cmp(candidate.validator_id_hex.as_str())
                    })
                    .ok()
                    .map(|index| &authority.validator_registration_history[index])
                    .context("changed-key future candidate lacks active registration history")?;
                ensure!(
                    history.revoked_at_height.is_none()
                        && exact_hash32_hex(&history.consensus_key_hex)?
                            == *old.consensus_key().as_bytes()
                        && history.max_registration_nonce == previous_nonce
                        && exact_hash32_hex(&history.history_head_hex)? == predecessor
                        && candidate.registration_nonce > previous_nonce,
                    "future candidate predecessor authority was substituted"
                );
            }
            Some(_) => {
                bail!("unchanged-key old validator must use canonical proof-free candidate carry")
            }
            None => ensure!(
                candidate.previous_registration_nonce.is_none() && predecessor == [0; 32],
                "future candidate supplied an unauthorized predecessor"
            ),
        }
        ensure!(
            projection_context
                .validator_set
                .validators()
                .iter()
                .all(|old| old.id() == validator_id || old.consensus_key() != consensus_key),
            "future candidate key belongs to another old validator"
        );
    }
    for approval in &authority.finalized_governance_approvals {
        let projection_context = active_context
            .as_ref()
            .context("finalized governance lacks active projection context")?;
        let expected_target_epoch = projection_context
            .validator_set
            .epoch()
            .get()
            .checked_add(1)
            .context("active governance target epoch exhausted")?;
        let expected_activation_height = projection_context
            .geometry
            .epoch_end()
            .get()
            .checked_add(1)
            .context("active governance activation height exhausted")?;
        ensure!(
            approval.target_epoch == expected_target_epoch
                && approval.activation_height == expected_activation_height,
            "finalized governance target epoch/activation is not the exact active successor"
        );
        let governance = projection_parts_for_identity_v0(
            &entries,
            PocoSnapshotEntryKindV0::RolloutOrGovernance,
            &approval.target_epoch.to_be_bytes(),
        )?;
        ensure!(
            matches!(
                governance.fact,
                SemanticFactV0::RolloutOrGovernance {
                    target_epoch,
                    phase,
                    parameters_hash,
                    activation_height,
                    approval: GovernanceApprovalV0::Approved,
                } if target_epoch == approval.target_epoch
                    && phase as u8 == approval.phase
                    && hex::encode(parameters_hash) == approval.parameters_hash_hex
                    && activation_height == approval.activation_height
            ),
            "governance approval diverges from exact kind-15 fact"
        );
        let next_parameters = validate_governance_parameters_companion_v0(
            &entries,
            approval.target_epoch,
            &approval.parameters_hash_hex,
        )?;
        let next_geometry =
            EpochGeometryV0::new(Epoch::new(approval.target_epoch), &next_parameters).map_err(
                |error| anyhow::anyhow!("invalid finalized governance epoch: {error:?}"),
            )?;
        ensure!(
            next_geometry.epoch_start().get() == approval.activation_height,
            "finalized governance parameters do not start at the authenticated activation height"
        );
        ensure!(
            u8::from(next_parameters.rollout_phase()) == approval.phase,
            "finalized governance phase differs from its parameters companion"
        );
    }
    let mut referenced = BTreeSet::new();
    referenced.extend(
        authority_consumer_key_entries
            .into_iter()
            .map(|key| (PocoSnapshotEntryKindV0::ConsumerKeyAuthorization, key)),
    );
    referenced.extend(
        authority_nonce_entries
            .into_iter()
            .map(|key| (PocoSnapshotEntryKindV0::ConsumerNonce, key)),
    );
    referenced.extend(
        authority_meter_entries
            .into_iter()
            .map(|key| (PocoSnapshotEntryKindV0::MeterDefinition, key)),
    );
    for reservation in &authority.funded_unused_reservations {
        let id = exact_hash32_hex(&reservation.certificate_id_hex)?;
        referenced.insert((
            PocoSnapshotEntryKindV0::Settlement,
            semantic_identity_digest_v0(PocoSnapshotEntryKindV0::Settlement, &id).to_vec(),
        ));
    }
    for certificate in &authority.active_certificates {
        for key in &certificate.semantic_keys {
            referenced.insert((
                PocoSnapshotEntryKindV0::from_u8(key.kind)?,
                exact_hash32_hex(&key.logical_key_hex)?.to_vec(),
            ));
        }
    }
    for history in &authority.validator_registration_history {
        let id = exact_opaque_hex(&history.validator_id_hex)?;
        referenced.insert((
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            semantic_identity_digest_v0(PocoSnapshotEntryKindV0::ValidatorRegistration, &id)
                .to_vec(),
        ));
    }
    for target_epoch in authority
        .pending_governance_proposals
        .iter()
        .map(|proposal| proposal.target_epoch)
        .chain(
            authority
                .finalized_governance_approvals
                .iter()
                .map(|approval| approval.target_epoch),
        )
    {
        referenced.insert((
            PocoSnapshotEntryKindV0::RolloutOrGovernance,
            semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::RolloutOrGovernance,
                &target_epoch.to_be_bytes(),
            )
            .to_vec(),
        ));
        let mut parameters_identity = vec![2];
        parameters_identity.extend_from_slice(&target_epoch.to_be_bytes());
        referenced.insert((
            PocoSnapshotEntryKindV0::ConsensusParameters,
            semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::ConsensusParameters,
                &parameters_identity,
            )
            .to_vec(),
        ));
    }
    for ((kind, logical_key), value) in &entries {
        let authority_managed = matches!(
            kind,
            PocoSnapshotEntryKindV0::ConsumptionCertificate
                | PocoSnapshotEntryKindV0::ConsumerKeyAuthorization
                | PocoSnapshotEntryKindV0::ConsumerNonce
                | PocoSnapshotEntryKindV0::UniqueConsumptionTuple
                | PocoSnapshotEntryKindV0::MeterDefinition
                | PocoSnapshotEntryKindV0::Settlement
                | PocoSnapshotEntryKindV0::MeasurementEvidence
                | PocoSnapshotEntryKindV0::ValidatorRegistration
                | PocoSnapshotEntryKindV0::RevocationOrChallenge
                | PocoSnapshotEntryKindV0::RolloutOrGovernance
        ) || if *kind == PocoSnapshotEntryKindV0::ConsensusParameters {
            owned_semantic_parts(*kind, logical_key, value)?
                .identity
                .first()
                .copied()
                == Some(2)
        } else {
            false
        };
        ensure!(
            !authority_managed || referenced.contains(&(*kind, logical_key.clone())),
            "orphan authority-managed semantic entry lacks kind-16 companion"
        );
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct PreparedSemanticChangeV0 {
    kind: PocoSnapshotEntryKindV0,
    logical_key: Vec<u8>,
    expected_value: Option<Vec<u8>>,
    next_value: Option<Vec<u8>>,
    expected_fact: Option<SemanticFactV0>,
    next_fact: Option<SemanticFactV0>,
    expected_identity: Option<Vec<u8>>,
    next_identity: Option<Vec<u8>>,
    expected_payload: Option<Vec<u8>>,
    next_payload: Option<Vec<u8>>,
    expected_revision: Option<u64>,
    next_revision: Option<u64>,
}

#[derive(Clone, Debug)]
struct OverlayMutationV0 {
    kind: PocoSnapshotEntryKindV0,
    logical_key: Vec<u8>,
    expected_value: Option<Vec<u8>>,
    next_value: Option<Vec<u8>>,
}

impl OverlayMutationV0 {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
        encoded.push(self.kind as u8);
        encode_bytes(&mut encoded, &self.logical_key);
        encode_optional_bytes(&mut encoded, self.expected_value.as_deref());
        encode_optional_bytes(&mut encoded, self.next_value.as_deref());
        encoded
    }
}

#[derive(Clone, Debug)]
struct PocoApplicationOverlayV0 {
    entries: BTreeMap<(PocoSnapshotEntryKindV0, Vec<u8>), Vec<u8>>,
    source_authority_value: Vec<u8>,
    authority: PocoApplicationAuthorityStateV0,
    accumulator: PocoNullifierAccumulatorV0,
    mutations: BTreeMap<(PocoSnapshotEntryKindV0, Vec<u8>), OverlayMutationV0>,
    operation_ids: BTreeSet<[u8; 32]>,
}

/// Incremental per-block overlay used by PrepareProposal, ProcessProposal and
/// FinalizeBlock.  A candidate operation is first bounded, then evaluated on a
/// clone, so rejection cannot leave partial in-memory authority changes.
#[derive(Clone, Debug)]
pub(crate) struct PocoApplicationBlockOverlayV0 {
    context: AuthenticatedPocoApplicationContextV0,
    overlay: PocoApplicationOverlayV0,
    raw_operations: Vec<Vec<u8>>,
    aggregate_operation_bytes: usize,
}

impl PocoApplicationBlockOverlayV0 {
    pub(crate) fn from_projection(
        context: AuthenticatedPocoApplicationContextV0,
        source_projection: &ProductionPocoProjectionV0,
    ) -> Result<Self> {
        let source_bytes = validate_source_projection_bound(source_projection)?;
        validate_application_authority_projection_v0(source_projection)?;
        ensure!(
            source_projection.manifest().cutoff_height().get() <= context.source_version,
            "PoCO source manifest is ahead of authenticated source version"
        );
        let mut entries = BTreeMap::new();
        for entry in source_projection.entries() {
            ensure!(
                entries
                    .insert((entry.kind, entry.logical_key.clone()), entry.value.clone())
                    .is_none(),
                "duplicate entry in production PoCO projection"
            );
        }
        let authority_key = poco_application_authority_logical_key_v0().to_vec();
        let source_authority_value = entries
            .get(&(
                PocoSnapshotEntryKindV0::ApplicationAuthorityState,
                authority_key,
            ))
            .context("production PoCO projection is missing application authority kind 16")?
            .clone();
        let authority_parts = decode_poco_snapshot_value_parts_v0_exact(
            PocoSnapshotEntryKindV0::ApplicationAuthorityState,
            &poco_application_authority_logical_key_v0(),
            &source_authority_value,
        )?;
        ensure!(
            authority_parts.identity == POCO_APPLICATION_AUTHORITY_IDENTITY_V0,
            "application authority identity mismatch"
        );
        let mut authority = PocoApplicationAuthorityStateV0::decode_exact(authority_parts.payload)?;
        ensure!(
            authority_parts.verified.revision() == authority.revision,
            "application authority envelope/state revision mismatch"
        );
        ensure!(
            authority.last_target_height < context.target_height.get(),
            "application authority target height is not monotonic"
        );
        compact_expired_usage_v0(&mut authority, &context)?;
        let accumulator = authority.accumulator()?;
        Ok(Self {
            context,
            overlay: PocoApplicationOverlayV0 {
                entries,
                source_authority_value,
                authority,
                accumulator,
                mutations: BTreeMap::new(),
                operation_ids: BTreeSet::new(),
            },
            raw_operations: Vec::new(),
            aggregate_operation_bytes: source_bytes,
        })
    }

    pub(crate) fn apply_raw(&mut self, raw: &[u8]) -> Result<()> {
        let operation = PocoApplicationOperationV0::decode_exact(raw)?;
        Ok(self.apply_decoded_exact(raw, &operation)?)
    }

    /// Applies an operation already obtained from `decode_exact` while
    /// retaining the committed raw bytes as the operation-ID preimage. The
    /// re-encode equality check prevents a decoded value from being paired
    /// with foreign bytes; all checks still precede the clone-and-swap update.
    pub(crate) fn apply_decoded_exact(
        &mut self,
        raw: &[u8],
        operation: &PocoApplicationOperationV0,
    ) -> std::result::Result<(), PocoApplicationApplyFailureV0> {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        if self.raw_operations.len() >= MAX_APPLICATION_OPERATIONS_PER_BLOCK {
            return Err(DeterministicallyInvalid(Invalid::PerBlockCapacity));
        }
        if raw.is_empty() || raw.len() > MAX_APPLICATION_OPERATION_BYTES {
            return Err(Invariant(InvariantReason::RawOwnerBounds));
        }
        let next_total = self
            .aggregate_operation_bytes
            .checked_add(raw.len())
            .ok_or(Invariant(InvariantReason::PlannerArithmetic))?;
        if next_total > MAX_POCO_SNAPSHOT_BUNDLE_BYTES {
            return Err(DeterministicallyInvalid(Invalid::PerBlockCapacity));
        }
        let reencoded = serde_json::to_vec(&operation)
            .map_err(|_| Invariant(InvariantReason::OperationReencode))?;
        if reencoded != raw {
            return Err(Invariant(InvariantReason::DecodedRawOwnerMismatch));
        }
        if operation.target_height != self.context.target_height.get() {
            return Err(DeterministicallyInvalid(Invalid::TargetHeightMismatch));
        }
        if operation.expected_state_revision != self.overlay.authority.revision {
            return Err(DeterministicallyInvalid(Invalid::AuthorityRevisionMismatch));
        }
        let operation_id = domain_hash(APPLICATION_OPERATION_DOMAIN, raw);
        if self.overlay.operation_ids.contains(&operation_id) {
            return Err(DeterministicallyInvalid(Invalid::DuplicateOperation));
        }
        let operation_has_preclone_field_admission = matches!(
            &operation.body,
            PocoApplicationOperationBodyV0::AuthorizeConsumerKey { .. }
                | PocoApplicationOperationBodyV0::DefineMeterPolicy { .. }
                | PocoApplicationOperationBodyV0::OpenChallenge { .. }
                | PocoApplicationOperationBodyV0::ProposeGovernance { .. }
        );
        if operation_has_preclone_field_admission {
            validate_operation_field_admission_v0(operation).map_err(|error| {
                error
                    .downcast_ref::<PocoApplicationApplyFailureV0>()
                    .copied()
                    .unwrap_or(Invariant(InvariantReason::AuthenticatedOverlay))
            })?;
        }
        let decision_preimage = decision_preimage_digest_v0(&self.context, operation)
            .map_err(|_| Invariant(InvariantReason::OperationReencode))?;
        let prepared = validate_operation_capacity_before_clone_v0(
            &self.context,
            &self.overlay,
            operation,
            decision_preimage,
        )
        .map_err(|error| {
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied()
                .unwrap_or({
                    DeterministicallyInvalid(match &operation.body {
                        PocoApplicationOperationBodyV0::ResolveChallenge { .. } => {
                            Invalid::ChallengeNotPending
                        }
                        PocoApplicationOperationBodyV0::ApproveGovernance { .. } => {
                            Invalid::GovernanceApprovalMissing
                        }
                        PocoApplicationOperationBodyV0::RegisterValidator { .. }
                        | PocoApplicationOperationBodyV0::RotateValidator { .. } => {
                            Invalid::ValidatorConsensusKeyAlreadyActive
                        }
                        _ => Invalid::ProtocolWindowOrCap,
                    })
                })
        })?;
        // Bounds and exact decoded-value/raw-byte binding above precede this
        // potentially large clone.
        let mut candidate = self.overlay.clone();
        candidate.operation_ids.insert(operation_id);
        apply_operation_v0(
            &self.context,
            &mut candidate,
            operation,
            decision_preimage,
            prepared,
        )
        .map_err(|error| {
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied()
                .unwrap_or(Invariant(InvariantReason::AuthenticatedOverlay))
        })?;
        self.overlay = candidate;
        self.raw_operations.push(raw.to_vec());
        self.aggregate_operation_bytes = next_total;
        Ok(())
    }

    pub(crate) const fn target_height(&self) -> Height {
        self.context.target_height
    }

    pub(crate) const fn source_version(&self) -> u64 {
        self.context.source_version
    }

    pub(crate) const fn source_root(&self) -> [u8; 32] {
        self.context.source_root
    }

    pub(crate) const fn expected_state_revision(&self) -> u64 {
        self.overlay.authority.revision
    }

    pub(crate) fn operation_count(&self) -> usize {
        self.raw_operations.len()
    }

    /// Builds one fully canonical operation for production-path integration
    /// tests without exporting any operation-authority constructor.
    #[cfg(test)]
    pub(crate) fn test_define_meter_operation_v0(&self) -> Result<Vec<u8>> {
        ensure!(
            self.overlay.accumulator.count() == 0
                && self.overlay.accumulator.root()
                    == crate::poco_nullifier::empty_poco_nullifier_root_v0(),
            "test define-meter helper requires the empty authenticated nullifier set"
        );
        let meter_id = b"integration-meter-v0".to_vec();
        let task_id = b"integration-task-v0".to_vec();
        let meter_version = 1u32;
        let policy = MeterAuthorityPolicyV0 {
            meter_id_hex: hex::encode(&meter_id),
            meter_version,
            task_id_hex: hex::encode(&task_id),
            output_commitment_hex: None,
            unit_scale: CanonicalU128V0::new(1),
            evidence_policy: MeterEvidencePolicyV0::Optional,
            per_certificate_cap: CanonicalU128V0::new(1),
            rolling_cap: CanonicalU128V0::new(1),
            rolling_epoch_span: 1,
            retention_blocks: 1,
            active_from_height: self.context.target_height.get(),
            retired_at_height: None,
        };
        let identity = meter_identity(&meter_id, meter_version);
        let mut payload = Vec::new();
        encode_bytes(&mut payload, &meter_id);
        payload.extend_from_slice(&meter_version.to_be_bytes());
        payload.extend_from_slice(&1u128.to_be_bytes());
        payload.extend_from_slice(&self.context.target_height.get().to_be_bytes());
        payload.push(0);
        let logical_key =
            semantic_identity_digest_v0(PocoSnapshotEntryKindV0::MeterDefinition, &identity);
        let next_value = encode_test_semantic_envelope_v0(
            PocoSnapshotEntryKindV0::MeterDefinition,
            1,
            &identity,
            &payload,
        );
        let mut operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: self.context.target_height.get(),
            expected_state_revision: self.overlay.authority.revision,
            body: PocoApplicationOperationBodyV0::DefineMeterPolicy {
                policy,
                decision_id_hex: "0".repeat(64),
            },
            semantic_changes: vec![RawSemanticChangeV0 {
                kind: PocoSnapshotEntryKindV0::MeterDefinition as u8,
                logical_key_hex: hex::encode(logical_key),
                next_value_hex: Some(hex::encode(next_value)),
            }],
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let preimage = decision_preimage_digest_v0(&self.context, &operation)?;
        let decision = derived_decision_id_v0(preimage, b"define-meter");
        if let PocoApplicationOperationBodyV0::DefineMeterPolicy {
            decision_id_hex, ..
        } = &mut operation.body
        {
            *decision_id_hex = hex::encode(decision);
        }
        let key = derive_poco_nullifier_key_v0(PocoNullifierFamilyV0::MeterDecision, decision);
        let siblings = std::array::from_fn(|level| {
            crate::poco_nullifier::poco_nullifier_default_hash_v0(level)
                .expect("fixed nullifier level is in range")
        });
        let proof = PocoNullifierProofV0::new(key, siblings);
        let identity_key =
            derive_poco_nullifier_key_v0(PocoNullifierFamilyV0::MeterIdentity, logical_key);
        let identity_proof =
            crate::poco_nullifier::test_proof_after_single_insertion_v0(key, identity_key)?;
        operation.nullifier_insertions = vec![
            RawNullifierInsertionV0 {
                family: PocoNullifierFamilyV0::MeterDecision.code(),
                identifier_hex: hex::encode(decision),
                proof_hex: hex::encode(proof.canonical_bytes()),
            },
            RawNullifierInsertionV0 {
                family: PocoNullifierFamilyV0::MeterIdentity.code(),
                identifier_hex: hex::encode(logical_key),
                proof_hex: hex::encode(identity_proof.canonical_bytes()),
            },
        ];
        let raw = serde_json::to_vec(&operation).context("encode test define-meter operation")?;
        ensure!(
            PocoApplicationOperationV0::decode_exact(&raw)? == operation,
            "test define-meter operation is not canonical"
        );
        Ok(raw)
    }

    pub(crate) fn seal(mut self) -> Result<SealedPocoApplicationPlanV0> {
        ensure!(
            !self.raw_operations.is_empty(),
            "empty application operation sequence has no authority transition"
        );
        let target_revision = self
            .overlay
            .authority
            .revision
            .checked_add(1)
            .context("application authority revision exhausted")?;
        self.overlay.authority.revision = target_revision;
        self.overlay.authority.last_target_height = self.context.target_height.get();
        self.overlay
            .authority
            .set_accumulator(self.overlay.accumulator);
        self.overlay.authority.validate()?;
        let target_authority_value =
            encode_application_authority_envelope_v0(&self.overlay.authority)?;
        let authority_change = PreparedSemanticChangeV0 {
            kind: PocoSnapshotEntryKindV0::ApplicationAuthorityState,
            logical_key: poco_application_authority_logical_key_v0().to_vec(),
            expected_value: Some(self.overlay.source_authority_value.clone()),
            next_value: Some(target_authority_value),
            expected_fact: None,
            next_fact: None,
            expected_identity: None,
            next_identity: None,
            expected_payload: None,
            next_payload: None,
            expected_revision: Some(target_revision - 1),
            next_revision: Some(target_revision),
        };
        apply_prepared_changes(&mut self.overlay, vec![authority_change], false)?;
        seal_overlay_v0(&self.context, &self.raw_operations, self.overlay)
    }
}

/// Plans a full block of application-authorized PoCO operations.
///
/// `source_projection` must already have been recovered from the authenticated
/// JMT source root.  Kind 16 inside that projection is the sole authority;
/// the namespace-1 mirror is never consulted.  Bounds are checked before the
/// projection or operation buffers are cloned, decoded, sorted, or hashed.
pub(crate) fn plan_poco_application_block_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    source_projection: &ProductionPocoProjectionV0,
    raw_operations: &[Vec<u8>],
) -> Result<SealedPocoApplicationPlanV0> {
    validate_block_admission_bounds(source_projection, raw_operations)?;
    let mut block =
        PocoApplicationBlockOverlayV0::from_projection(context.clone(), source_projection)?;
    for raw in raw_operations {
        block.apply_raw(raw)?;
    }
    block.seal()
}

fn seal_overlay_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    raw_operations: &[Vec<u8>],
    overlay: PocoApplicationOverlayV0,
) -> Result<SealedPocoApplicationPlanV0> {
    validate_overlay_projection_bounds_before_clone_v0(&overlay.entries)?;
    let target_entries = overlay
        .entries
        .iter()
        .map(|((kind, logical_key), value)| {
            PocoSnapshotEntryV0::new(*kind, logical_key.clone(), value.clone())
        })
        .collect::<Result<Vec<_>>>()?;
    validate_target_projection_bounds(&target_entries)?;
    let target_manifest =
        PocoSnapshotManifestV0::from_entries(context.target_height, &target_entries)?;

    // Rebuild the exact physical target namespace and pass it through the same
    // production restore/startup validator before emitting any sealed writes.
    // This keeps in-memory planning, JMT application, and SQLite recovery on
    // one cross-entry authority boundary.
    let mut target_live = BTreeMap::new();
    ensure!(
        target_live
            .insert(poco_snapshot_manifest_key()?, target_manifest.encode())
            .is_none(),
        "duplicate target PoCO manifest key"
    );
    for entry in &target_entries {
        ensure!(
            target_live
                .insert(
                    poco_snapshot_entry_key(entry.kind, &entry.logical_key)?,
                    entry.value.clone(),
                )
                .is_none(),
            "duplicate target PoCO physical entry key"
        );
    }
    let validated_target = take_and_validate_production_poco_projection_v0(
        context.target_height.get(),
        &mut target_live,
    )?
    .context("sealed PoCO target projection disappeared during validation")?;
    ensure!(
        target_live.is_empty()
            && validated_target.manifest() == target_manifest
            && validated_target.entries() == target_entries.as_slice(),
        "sealed PoCO target projection differs from production validation"
    );

    let mutations = overlay.mutations.into_values().collect::<Vec<_>>();
    let mut namespace_writes = Vec::with_capacity(mutations.len().saturating_add(1));
    for mutation in &mutations {
        namespace_writes.push(SealedPocoNamespaceWriteV0 {
            key: poco_snapshot_entry_key(mutation.kind, &mutation.logical_key)?,
            value: mutation.next_value.clone(),
        });
    }
    namespace_writes.push(SealedPocoNamespaceWriteV0 {
        key: poco_snapshot_manifest_key()?,
        value: Some(target_manifest.encode()),
    });
    Ok(SealedPocoApplicationPlanV0 {
        namespace_writes,
        source_version: context.source_version,
        source_root: context.source_root,
        target_height: context.target_height,
        operation_root: ordered_bytes_root(
            APPLICATION_OPERATION_DOMAIN,
            APPLICATION_OPERATION_NODE_DOMAIN,
            APPLICATION_OPERATION_ROOT_DOMAIN,
            raw_operations,
        ),
        operation_count: u32::try_from(raw_operations.len())
            .expect("application operation hard bound fits u32"),
        mutation_root: ordered_mutation_root(&mutations),
        mutation_count: u32::try_from(mutations.len())
            .expect("application mutation hard bound fits u32"),
        target_manifest,
    })
}

#[derive(Default)]
struct OperationRecordDeltaV0 {
    consumer_keys_added: usize,
    consumer_keys_removed: usize,
    nonce_watermarks_added: usize,
    nonce_watermarks_removed: usize,
    meter_policies_added: usize,
    meter_policies_removed: usize,
    usage_buckets_added: usize,
    reservations_added: usize,
    reservations_removed: usize,
    active_certificates_added: usize,
    active_certificates_removed: usize,
    pending_challenges_added: usize,
    pending_challenges_removed: usize,
    pending_governance_added: usize,
    pending_governance_removed: usize,
    finalized_governance_added: usize,
    validator_histories_added: usize,
    validator_histories_removed: usize,
    future_candidates_added: usize,
}

#[derive(Debug)]
enum PreparedCapacityOperationV0 {
    Deferred,
    AuthorizeConsumerKey(Box<PreparedAuthorizeConsumerKeyV0>),
    DefineMeter(Box<PreparedDefineMeterV0>),
    RetireMeter(Box<PreparedRetireMeterV0>),
    PruneRetiredMeter(Box<PreparedPruneRetiredMeterV0>),
    FundSettlement(Box<PreparedFundSettlementV0>),
    ReleaseSettlement(Box<PreparedReleaseSettlementV0>),
    OpenChallenge(Box<PreparedOpenChallengeV0>),
    ResolveChallenge(Box<PreparedResolveChallengeV0>),
    ProposeGovernance(Box<PreparedProposeGovernanceV0>),
    ApproveGovernance(Box<PreparedApproveGovernanceV0>),
    RegisterFutureCandidate(Box<PreparedFutureCandidateV0>),
    RegisterValidator(Box<PreparedRegisterValidatorV0>),
    RotateValidator(Box<PreparedRotateValidatorV0>),
    RevokeConsumerKey(Box<PreparedRevokeConsumerKeyV0>),
    PruneRevokedConsumerKey(Box<PreparedPruneRevokedConsumerKeyV0>),
}

#[derive(Debug)]
struct PreparedAuthorizeConsumerKeyV0 {
    authority: ConsumerKeyAuthorityV0,
    expected_nullifiers: [(PocoNullifierFamilyV0, [u8; 32]); 2],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedRevokeConsumerKeyV0 {
    authority_index: usize,
    expected_authority: ConsumerKeyAuthorityV0,
    successor_authority: ConsumerKeyAuthorityV0,
    expected_semantic_changes: Vec<RawSemanticChangeV0>,
    expected_nullifiers: [(PocoNullifierFamilyV0, [u8; 32]); 1],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedPruneRevokedConsumerKeyV0 {
    authority_index: usize,
    expected_authority: ConsumerKeyAuthorityV0,
    expected_semantic_changes: Vec<RawSemanticChangeV0>,
    expected_nullifiers: [(PocoNullifierFamilyV0, [u8; 32]); 1],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedDefineMeterV0 {
    policy: MeterAuthorityPolicyV0,
    expected_nullifiers: [(PocoNullifierFamilyV0, [u8; 32]); 2],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedRetireMeterV0 {
    policy_index: usize,
    expected_policy: MeterAuthorityPolicyV0,
    successor_policy: MeterAuthorityPolicyV0,
    expected_decision_id_hex: String,
    expected_semantic_changes: Vec<RawSemanticChangeV0>,
    expected_non_membership_checks: Vec<RawNullifierInsertionV0>,
    expected_nullifiers: [(PocoNullifierFamilyV0, [u8; 32]); 1],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedPruneRetiredMeterV0 {
    policy_index: usize,
    expected_policy: MeterAuthorityPolicyV0,
    expected_semantic_changes: Vec<RawSemanticChangeV0>,
    expected_non_membership_checks: Vec<RawNullifierInsertionV0>,
    expected_nullifier_insertions: Vec<RawNullifierInsertionV0>,
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedFundSettlementV0 {
    reservation: FundedUnusedReservationV0,
    expected_absences: [(PocoNullifierFamilyV0, [u8; 32]); 1],
    expected_insertions: [(PocoNullifierFamilyV0, [u8; 32]); 1],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedReleaseSettlementV0 {
    reservation_index: usize,
    expected_reservation: FundedUnusedReservationV0,
    expected_insertions: [(PocoNullifierFamilyV0, [u8; 32]); 2],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedOpenChallengeV0 {
    pending: PendingChallengeAuthorityV0,
    expected_nullifiers: [(PocoNullifierFamilyV0, [u8; 32]); 1],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedResolveChallengeV0 {
    pending_index: usize,
    expected_pending: PendingChallengeAuthorityV0,
    certificate_index: usize,
    expected_certificate: ActiveCertificateAuthorityV0,
    target_lifecycle: CertificateAuthorityLifecycleV0,
    target_height: u64,
    resolution_decision_id_hex: String,
    expected_nullifiers: [(PocoNullifierFamilyV0, [u8; 32]); 1],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedProposeGovernanceV0 {
    proposal: PendingGovernanceProposalV0,
    pending_insertion: usize,
    finalized_insertion: usize,
    expected_nullifiers: [(PocoNullifierFamilyV0, [u8; 32]); 1],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedApproveGovernanceV0 {
    proposal_index: usize,
    expected_proposal: PendingGovernanceProposalV0,
    finalized_insertion: usize,
    approval: FinalizedGovernanceApprovalV0,
    parameters_logical_key: Vec<u8>,
    expected_parameters_value: Vec<u8>,
    expected_nullifiers: [(PocoNullifierFamilyV0, [u8; 32]); 1],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedFutureCandidateV0 {
    record: FutureCandidateRegistrationV0,
    insertion: usize,
    expected_nullifiers: [(PocoNullifierFamilyV0, [u8; 32]); 2],
}

#[derive(Debug)]
struct PreparedRegisterValidatorV0 {
    history: ValidatorRegistrationHistoryV0,
    insertion: usize,
    expected_absences: [(PocoNullifierFamilyV0, [u8; 32]); 1],
    expected_insertions: [(PocoNullifierFamilyV0, [u8; 32]); 2],
    changes: Vec<PreparedSemanticChangeV0>,
}

#[derive(Debug)]
struct PreparedRotateValidatorV0 {
    history: ValidatorRegistrationHistoryV0,
    index: usize,
    expected_insertions: [(PocoNullifierFamilyV0, [u8; 32]); 2],
    changes: Vec<PreparedSemanticChangeV0>,
}

fn target_record_count_before_clone_v0(
    current: usize,
    removed: usize,
    added: usize,
    cap: usize,
    name: &str,
) -> Result<usize> {
    let target = current
        .checked_sub(removed)
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::DerivedMutationPostcondition)
        })?
        .checked_add(added)
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
        })?;
    let _ = name;
    if target > cap {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    Ok(target)
}

fn authenticated_certificate_lifecycle_companion_v0(
    overlay: &PocoApplicationOverlayV0,
    certificate: &ActiveCertificateAuthorityV0,
) -> Result<OwnedSemanticPartsV0> {
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    let certificate_id =
        exact_hash32_hex(&certificate.certificate_id_hex).map_err(|_| authenticated_overlay())?;
    exact_hash32_hex(&certificate.acceptance_decision_id_hex)
        .map_err(|_| authenticated_overlay())?;
    exact_hash32_hex(&certificate.lifecycle_decision_id_hex)
        .map_err(|_| authenticated_overlay())?;
    validate_certificate_lifecycle_authority_v0(
        certificate.lifecycle,
        certificate.lifecycle_effective_height,
        &certificate.lifecycle_decision_id_hex,
        certificate.accepted_height,
        &certificate.acceptance_decision_id_hex,
    )
    .map_err(|_| authenticated_overlay())?;
    let mut pending_iter = overlay
        .authority
        .pending_challenges
        .iter()
        .filter(|challenge| challenge.certificate_id_hex == certificate.certificate_id_hex);
    let pending = pending_iter.next();
    if pending_iter.next().is_some() {
        return Err(authenticated_overlay());
    }
    let (expected_state, expected_height) = match (certificate.lifecycle, pending) {
        (CertificateAuthorityLifecycleV0::Accepted, Some(challenge)) => {
            exact_hash32_hex(&challenge.challenge_id_hex).map_err(|_| authenticated_overlay())?;
            exact_hash32_hex(&challenge.opening_decision_id_hex)
                .map_err(|_| authenticated_overlay())?;
            if certificate.lifecycle_effective_height != certificate.accepted_height
                || challenge.opened_height <= certificate.accepted_height
            {
                return Err(authenticated_overlay());
            }
            (LifecycleStateV0::ChallengePending, challenge.opened_height)
        }
        (CertificateAuthorityLifecycleV0::Accepted, None) => {
            if certificate.lifecycle_effective_height != certificate.accepted_height {
                return Err(authenticated_overlay());
            }
            (
                LifecycleStateV0::Accepted,
                certificate.lifecycle_effective_height,
            )
        }
        (CertificateAuthorityLifecycleV0::ChallengeRejected, None) => (
            LifecycleStateV0::ChallengeRejected,
            certificate.lifecycle_effective_height,
        ),
        (CertificateAuthorityLifecycleV0::ChallengeSustained, None) => (
            LifecycleStateV0::ChallengeSustained,
            certificate.lifecycle_effective_height,
        ),
        (
            CertificateAuthorityLifecycleV0::ChallengeRejected
            | CertificateAuthorityLifecycleV0::ChallengeSustained,
            Some(_),
        ) => return Err(authenticated_overlay()),
    };
    let lifecycle = source_parts_for_identity(
        overlay,
        PocoSnapshotEntryKindV0::RevocationOrChallenge,
        &certificate_id,
    )
    .map_err(|_| authenticated_overlay())?;
    if !matches!(
        lifecycle.fact,
        SemanticFactV0::RevocationOrChallenge {
            state,
            effective_height,
        } if state == expected_state && effective_height == expected_height
    ) {
        return Err(authenticated_overlay());
    }
    Ok(lifecycle)
}

fn validate_validator_consensus_key_before_clone_v0(
    authority: &PocoApplicationAuthorityStateV0,
    operation: &PocoApplicationOperationV0,
) -> Result<()> {
    let validator_rule =
        || deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::ValidatorRule);
    let validator_id_hex = match &operation.body {
        PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex, ..
        }
        | PocoApplicationOperationBodyV0::RotateValidator {
            validator_id_hex, ..
        } => validator_id_hex,
        _ => return Err(validator_rule()),
    };
    let validator_id = exact_opaque_hex(validator_id_hex).map_err(|_| validator_rule())?;
    let [change] = operation.semantic_changes.as_slice() else {
        return Err(validator_rule());
    };
    if change.kind != PocoSnapshotEntryKindV0::ValidatorRegistration as u8 {
        return Err(validator_rule());
    }
    let Some(next_value_hex) = change.next_value_hex.as_deref() else {
        return Err(validator_rule());
    };
    let logical_key = exact_hex(
        &change.logical_key_hex,
        1,
        128,
        "validator semantic logical key",
    )
    .map_err(|_| validator_rule())?;
    let next_value = exact_hex(next_value_hex, 1, 65_536, "validator next semantic value")
        .map_err(|_| validator_rule())?;
    let parts = owned_semantic_parts(
        PocoSnapshotEntryKindV0::ValidatorRegistration,
        &logical_key,
        &next_value,
    )
    .map_err(|_| validator_rule())?;
    if parts.identity != validator_id {
        return Err(validator_rule());
    }
    let consensus_key = match parts.fact {
        SemanticFactV0::ValidatorRegistration {
            consensus_key,
            state: RegistrationStateV0::Active,
            ..
        } => consensus_key,
        _ => return Err(validator_rule()),
    };
    let consensus_key_hex = hex::encode(consensus_key);
    if authority
        .validator_registration_history
        .iter()
        .any(|history| history.consensus_key_hex == consensus_key_hex)
    {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ValidatorConsensusKeyAlreadyActive,
        ));
    }
    Ok(())
}

fn validate_operation_capacity_before_clone_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    decision_preimage: [u8; 32],
) -> Result<PreparedCapacityOperationV0> {
    let authority = &overlay.authority;
    let mut delta = OperationRecordDeltaV0::default();
    let mut prepared = PreparedCapacityOperationV0::Deferred;
    let mut future_candidate_insertion = None;
    let mut validator_history_insertion = None;
    let mut release_reservation_index = None;
    let mut resolve_pending_index = None;
    let mut resolve_certificate_index = None;
    let mut approval_proposal_index = None;
    let mut approval_finalized_insertion = None;
    let mut revoke_consumer_key_index = None;
    let mut prune_consumer_key_index = None;
    let mut retire_meter_index = None;
    let mut prune_meter_index = None;
    match &operation.body {
        PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
            public_key_hex,
            active_from_height,
            decision_id_hex,
        } => {
            prepared = PreparedCapacityOperationV0::AuthorizeConsumerKey(Box::new(
                prepare_authorize_consumer_key_v0(
                    context,
                    overlay,
                    operation,
                    decision_preimage,
                    consumer_id_hex,
                    consumer_key_id_hex,
                    public_key_hex,
                    *active_from_height,
                    decision_id_hex,
                )
                .map_err(|error| {
                    preserve_application_failure_or_deterministic_v0(
                        error,
                        PocoApplicationDeterministicInvalidV0::SemanticTransition,
                    )
                })?,
            ));
            delta.consumer_keys_added = 1;
        }
        PocoApplicationOperationBodyV0::PruneRevokedConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
        } => {
            exact_opaque_hex(consumer_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            exact_opaque_hex(consumer_key_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            let index = authority
                .consumer_keys
                .binary_search_by(|key| {
                    (
                        key.consumer_id_hex.as_str(),
                        key.consumer_key_id_hex.as_str(),
                    )
                        .cmp(&(consumer_id_hex.as_str(), consumer_key_id_hex.as_str()))
                })
                .map_err(|_| {
                    deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
                    )
                })?;
            prune_consumer_key_index = Some(index);
            delta.consumer_keys_removed = 1;
            delta.nonce_watermarks_removed = authority.consumer_keys[index].nonce_watermarks.len();
        }
        PocoApplicationOperationBodyV0::DefineMeterPolicy {
            policy,
            decision_id_hex,
        } => {
            prepared = PreparedCapacityOperationV0::DefineMeter(Box::new(
                prepare_define_meter_v0(
                    context,
                    overlay,
                    operation,
                    decision_preimage,
                    policy,
                    decision_id_hex,
                )
                .map_err(|error| {
                    preserve_application_failure_or_deterministic_v0(
                        error,
                        PocoApplicationDeterministicInvalidV0::SemanticTransition,
                    )
                })?,
            ));
            delta.meter_policies_added = 1;
        }
        PocoApplicationOperationBodyV0::PruneRetiredMeter {
            meter_id_hex,
            meter_version,
        } => {
            exact_opaque_hex(meter_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            prune_meter_index = Some(
                authority
                    .meter_policies
                    .binary_search_by(|policy| {
                        (policy.meter_id_hex.as_str(), policy.meter_version)
                            .cmp(&(meter_id_hex.as_str(), *meter_version))
                    })
                    .map_err(|_| {
                        deterministic_application_error_v0(
                            PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
                        )
                    })?,
            );
            delta.meter_policies_removed = 1;
        }
        PocoApplicationOperationBodyV0::RetireMeterPolicy {
            meter_id_hex,
            meter_version,
            ..
        } => {
            exact_opaque_hex(meter_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            retire_meter_index = Some(
                authority
                    .meter_policies
                    .binary_search_by(|policy| {
                        (policy.meter_id_hex.as_str(), policy.meter_version)
                            .cmp(&(meter_id_hex.as_str(), *meter_version))
                    })
                    .map_err(|_| {
                        deterministic_application_error_v0(
                            PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
                        )
                    })?,
            );
        }
        PocoApplicationOperationBodyV0::FundSettlement {
            certificate_id_hex,
            settlement_commitment_hex,
            reserved_units,
            funding_decision_id_hex,
        } => {
            prepared = PreparedCapacityOperationV0::FundSettlement(Box::new(
                prepare_fund_settlement_v0(
                    context,
                    overlay,
                    operation,
                    decision_preimage,
                    certificate_id_hex,
                    settlement_commitment_hex,
                    reserved_units,
                    funding_decision_id_hex,
                )
                .map_err(|error| {
                    preserve_application_failure_or_deterministic_v0(
                        error,
                        PocoApplicationDeterministicInvalidV0::SemanticTransition,
                    )
                })?,
            ));
            delta.reservations_added = 1;
        }
        PocoApplicationOperationBodyV0::AcceptCertificate {
            certificate_id_hex, ..
        } => {
            exact_hash32_hex(certificate_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            authority
                .funded_unused_reservations
                .binary_search_by(|reservation| {
                    reservation
                        .certificate_id_hex
                        .as_str()
                        .cmp(certificate_id_hex.as_str())
                })
                .map_err(|_| {
                    deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
                    )
                })?;
            if authority
                .active_certificates
                .binary_search_by(|certificate| {
                    certificate
                        .certificate_id_hex
                        .as_str()
                        .cmp(certificate_id_hex.as_str())
                })
                .is_ok()
            {
                return Err(deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                ));
            }
            let (new_nonce_watermarks, new_usage_buckets) =
                accept_capacity_additions_before_clone_v0(context, overlay, operation)?;
            delta.nonce_watermarks_added = new_nonce_watermarks;
            delta.usage_buckets_added = new_usage_buckets;
            delta.reservations_removed = 1;
            delta.active_certificates_added = 1;
        }
        PocoApplicationOperationBodyV0::ReleaseSettlement {
            certificate_id_hex, ..
        } => {
            exact_hash32_hex(certificate_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            let reservation_index = authority
                .funded_unused_reservations
                .binary_search_by(|reservation| {
                    reservation
                        .certificate_id_hex
                        .as_str()
                        .cmp(certificate_id_hex.as_str())
                })
                .map_err(|_| {
                    deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
                    )
                })?;
            release_reservation_index = Some(reservation_index);
            delta.reservations_removed = 1;
        }
        PocoApplicationOperationBodyV0::OpenChallenge {
            certificate_id_hex,
            challenge_id_hex,
            opening_decision_id_hex,
        } => {
            prepared = PreparedCapacityOperationV0::OpenChallenge(Box::new(
                prepare_open_challenge_v0(
                    context,
                    overlay,
                    operation,
                    decision_preimage,
                    certificate_id_hex,
                    challenge_id_hex,
                    opening_decision_id_hex,
                )
                .map_err(|error| {
                    preserve_application_failure_or_deterministic_v0(
                        error,
                        PocoApplicationDeterministicInvalidV0::SemanticTransition,
                    )
                })?,
            ));
            delta.pending_challenges_added = 1;
        }
        PocoApplicationOperationBodyV0::ResolveChallenge {
            certificate_id_hex,
            challenge_id_hex,
            ..
        } => {
            exact_hash32_hex(certificate_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            exact_hash32_hex(challenge_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            let pending_index = authority
                .pending_challenges
                .binary_search_by(|item| item.challenge_id_hex.as_str().cmp(challenge_id_hex))
                .map_err(|_| {
                    deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::ChallengeNotPending,
                    )
                })?;
            if authority.pending_challenges[pending_index]
                .certificate_id_hex
                .as_str()
                != certificate_id_hex.as_str()
            {
                return Err(deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                ));
            }
            let certificate_index = authority
                .active_certificates
                .binary_search_by(|certificate| {
                    certificate
                        .certificate_id_hex
                        .as_str()
                        .cmp(certificate_id_hex.as_str())
                })
                .map_err(|_| {
                    invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay)
                })?;
            if authority.active_certificates[certificate_index].lifecycle
                != CertificateAuthorityLifecycleV0::Accepted
            {
                return Err(invariant_application_error_v0(
                    PocoApplicationInvariantV0::AuthenticatedOverlay,
                ));
            }
            resolve_pending_index = Some(pending_index);
            resolve_certificate_index = Some(certificate_index);
            delta.pending_challenges_removed = 1;
        }
        PocoApplicationOperationBodyV0::ProposeGovernance {
            target_epoch,
            phase,
            parameters_hash_hex,
            activation_height,
            proposal_decision_id_hex,
        } => {
            prepared = PreparedCapacityOperationV0::ProposeGovernance(Box::new(
                prepare_propose_governance_v0(
                    context,
                    overlay,
                    operation,
                    decision_preimage,
                    *target_epoch,
                    *phase,
                    parameters_hash_hex,
                    *activation_height,
                    proposal_decision_id_hex,
                )
                .map_err(|error| {
                    preserve_application_failure_or_deterministic_v0(
                        error,
                        PocoApplicationDeterministicInvalidV0::GovernanceRule,
                    )
                })?,
            ));
            delta.pending_governance_added = 1;
        }
        PocoApplicationOperationBodyV0::ApproveGovernance {
            target_epoch,
            parameters_hash_hex,
            ..
        } => {
            exact_hash32_hex(parameters_hash_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::GovernanceRule,
                )
            })?;
            let expected_epoch = context.active_epoch.get().checked_add(1).ok_or_else(|| {
                invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
            })?;
            if *target_epoch != expected_epoch {
                return Err(deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::GovernanceRule,
                ));
            }
            let proposal_index = authority
                .pending_governance_proposals
                .binary_search_by_key(target_epoch, |proposal| proposal.target_epoch)
                .map_err(|_| {
                    deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::GovernanceApprovalMissing,
                    )
                })?;
            let finalized_insertion = match authority
                .finalized_governance_approvals
                .binary_search_by_key(target_epoch, |approval| approval.target_epoch)
            {
                Err(insertion) => insertion,
                Ok(_) => {
                    return Err(deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::GovernanceRule,
                    ));
                }
            };
            approval_proposal_index = Some(proposal_index);
            approval_finalized_insertion = Some(finalized_insertion);
            delta.pending_governance_removed = 1;
            delta.finalized_governance_added = 1;
        }
        PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex, ..
        } => {
            exact_opaque_hex(validator_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::ValidatorRule,
                )
            })?;
            let insertion = authority
                .validator_registration_history
                .binary_search_by(|history| history.validator_id_hex.as_str().cmp(validator_id_hex))
                .map_or_else(Ok, |_| {
                    Err(deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::ValidatorRule,
                    ))
                })?;
            validate_validator_consensus_key_before_clone_v0(authority, operation)?;
            validator_history_insertion = Some(insertion);
            delta.validator_histories_added = 1;
        }
        PocoApplicationOperationBodyV0::RegisterFutureCandidate {
            validator_id_hex,
            target_epoch,
            ..
        } => {
            exact_opaque_hex(validator_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::ValidatorRule,
                )
            })?;
            let insertion = authority
                .future_candidate_registrations
                .binary_search_by(|item| {
                    (item.target_epoch, item.validator_id_hex.as_str())
                        .cmp(&(*target_epoch, validator_id_hex.as_str()))
                })
                .map_or_else(Ok, |_| {
                    Err(deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::ValidatorRule,
                    ))
                })?;
            future_candidate_insertion = Some(insertion);
            delta.future_candidates_added = 1;
        }
        PocoApplicationOperationBodyV0::PruneRevokedValidatorHistory { validator_id_hex } => {
            exact_opaque_hex(validator_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::ValidatorRule,
                )
            })?;
            authority
                .validator_registration_history
                .binary_search_by(|history| history.validator_id_hex.as_str().cmp(validator_id_hex))
                .map_err(|_| {
                    deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
                    )
                })?;
            delta.validator_histories_removed = 1;
        }
        PocoApplicationOperationBodyV0::PruneExpiredCertificate { certificate_id_hex } => {
            exact_hash32_hex(certificate_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            authority
                .active_certificates
                .binary_search_by(|certificate| {
                    certificate
                        .certificate_id_hex
                        .as_str()
                        .cmp(certificate_id_hex)
                })
                .map_err(|_| {
                    deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
                    )
                })?;
            delta.active_certificates_removed = 1;
        }
        PocoApplicationOperationBodyV0::RotateValidator { .. } => {
            validate_validator_consensus_key_before_clone_v0(authority, operation)?;
        }
        PocoApplicationOperationBodyV0::RevokeConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
            ..
        } => {
            exact_opaque_hex(consumer_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            exact_opaque_hex(consumer_key_id_hex).map_err(|_| {
                deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::SemanticTransition,
                )
            })?;
            revoke_consumer_key_index = Some(
                authority
                    .consumer_keys
                    .binary_search_by(|item| {
                        (
                            item.consumer_id_hex.as_str(),
                            item.consumer_key_id_hex.as_str(),
                        )
                            .cmp(&(consumer_id_hex.as_str(), consumer_key_id_hex.as_str()))
                    })
                    .map_err(|_| {
                        deterministic_application_error_v0(
                            PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
                        )
                    })?,
            );
        }
        PocoApplicationOperationBodyV0::RevokeValidator { .. } => {}
    }

    let consumer_keys = target_record_count_before_clone_v0(
        authority.consumer_keys.len(),
        delta.consumer_keys_removed,
        delta.consumer_keys_added,
        MAX_CONSUMER_KEY_AUTHORITIES,
        "consumer keys",
    )?;
    let nonce_watermarks = target_record_count_before_clone_v0(
        total_nonce_watermarks_v0(authority)?,
        delta.nonce_watermarks_removed,
        delta.nonce_watermarks_added,
        MAX_TOTAL_NONCE_WATERMARKS,
        "consumer nonce watermarks",
    )?;
    let meter_policies = target_record_count_before_clone_v0(
        authority.meter_policies.len(),
        delta.meter_policies_removed,
        delta.meter_policies_added,
        MAX_METER_POLICIES,
        "meter policies",
    )?;
    let usage_buckets = target_record_count_before_clone_v0(
        usage_bucket_count_v0(authority)?,
        0,
        delta.usage_buckets_added,
        MAX_TOTAL_USAGE_BUCKETS,
        "usage buckets",
    )?;
    let reservations = target_record_count_before_clone_v0(
        authority.funded_unused_reservations.len(),
        delta.reservations_removed,
        delta.reservations_added,
        MAX_FUNDED_UNUSED_RESERVATIONS,
        "funded-unused reservations",
    )?;
    let active_certificates = target_record_count_before_clone_v0(
        authority.active_certificates.len(),
        delta.active_certificates_removed,
        delta.active_certificates_added,
        MAX_ACTIVE_CERTIFICATES,
        "active certificates",
    )?;
    let pending_challenges = target_record_count_before_clone_v0(
        authority.pending_challenges.len(),
        delta.pending_challenges_removed,
        delta.pending_challenges_added,
        MAX_PENDING_CHALLENGES,
        "pending challenges",
    )?;
    let pending_governance = target_record_count_before_clone_v0(
        authority.pending_governance_proposals.len(),
        delta.pending_governance_removed,
        delta.pending_governance_added,
        MAX_PENDING_GOVERNANCE_PROPOSALS,
        "pending governance proposals",
    )?;
    let finalized_governance = target_record_count_before_clone_v0(
        authority.finalized_governance_approvals.len(),
        0,
        delta.finalized_governance_added,
        MAX_FINALIZED_GOVERNANCE_APPROVALS,
        "finalized governance approvals",
    )?;
    let validator_histories = target_record_count_before_clone_v0(
        authority.validator_registration_history.len(),
        delta.validator_histories_removed,
        delta.validator_histories_added,
        MAX_VALIDATOR_REGISTRATION_HISTORIES,
        "validator registration histories",
    )?;
    let future_candidates = target_record_count_before_clone_v0(
        authority.future_candidate_registrations.len(),
        0,
        delta.future_candidates_added,
        MAX_FUTURE_CANDIDATE_REGISTRATIONS,
        "future candidate registrations",
    )?;
    let target_total = [
        consumer_keys,
        nonce_watermarks,
        meter_policies,
        usage_buckets,
        reservations,
        active_certificates,
        pending_challenges,
        pending_governance,
        finalized_governance,
        validator_histories,
        future_candidates,
    ]
    .into_iter()
    .try_fold(0usize, |total, count| {
        total.checked_add(count).ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
        })
    })?;
    if target_total > MAX_TOTAL_AUTHORITY_RECORDS {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    if matches!(
        &operation.body,
        PocoApplicationOperationBodyV0::RevokeConsumerKey { .. }
    ) {
        prepared = PreparedCapacityOperationV0::RevokeConsumerKey(Box::new(
            prepare_revoke_consumer_key_v0(
                context,
                overlay,
                operation,
                decision_preimage,
                revoke_consumer_key_index.ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )?,
        ));
    }
    if matches!(
        &operation.body,
        PocoApplicationOperationBodyV0::PruneRevokedConsumerKey { .. }
    ) {
        prepared = PreparedCapacityOperationV0::PruneRevokedConsumerKey(Box::new(
            prepare_prune_revoked_consumer_key_v0(
                context,
                overlay,
                operation,
                prune_consumer_key_index.ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )?,
        ));
    }
    if matches!(
        &operation.body,
        PocoApplicationOperationBodyV0::RetireMeterPolicy { .. }
    ) {
        prepared = PreparedCapacityOperationV0::RetireMeter(Box::new(prepare_retire_meter_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            retire_meter_index.ok_or_else(|| {
                invariant_application_error_v0(
                    PocoApplicationInvariantV0::DerivedMutationPostcondition,
                )
            })?,
        )?));
    }
    if matches!(
        &operation.body,
        PocoApplicationOperationBodyV0::PruneRetiredMeter { .. }
    ) {
        prepared = PreparedCapacityOperationV0::PruneRetiredMeter(Box::new(
            prepare_prune_retired_meter_v0(
                context,
                overlay,
                operation,
                prune_meter_index.ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )?,
        ));
    }
    if let PocoApplicationOperationBodyV0::ReleaseSettlement {
        certificate_id_hex,
        release_decision_id_hex,
    } = &operation.body
    {
        prepared = PreparedCapacityOperationV0::ReleaseSettlement(Box::new(
            prepare_release_settlement_v0(
                overlay,
                operation,
                decision_preimage,
                certificate_id_hex,
                release_decision_id_hex,
                release_reservation_index.ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )?,
        ));
    }
    if let PocoApplicationOperationBodyV0::ResolveChallenge {
        certificate_id_hex,
        challenge_id_hex,
        resolution,
        resolution_decision_id_hex,
    } = &operation.body
    {
        prepared =
            PreparedCapacityOperationV0::ResolveChallenge(Box::new(prepare_resolve_challenge_v0(
                context,
                overlay,
                operation,
                decision_preimage,
                certificate_id_hex,
                challenge_id_hex,
                *resolution,
                resolution_decision_id_hex,
                resolve_pending_index.ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
                resolve_certificate_index.ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )?));
    }
    if let PocoApplicationOperationBodyV0::ApproveGovernance {
        target_epoch,
        parameters_hash_hex,
        activation_height,
        decision_id_hex,
    } = &operation.body
    {
        prepared = PreparedCapacityOperationV0::ApproveGovernance(Box::new(
            prepare_approve_governance_v0(
                context,
                overlay,
                operation,
                decision_preimage,
                *target_epoch,
                parameters_hash_hex,
                *activation_height,
                decision_id_hex,
                approval_proposal_index.ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
                approval_finalized_insertion.ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )?,
        ));
    }
    if let PocoApplicationOperationBodyV0::RegisterValidator {
        validator_id_hex,
        target_epoch,
        registration_decision_id_hex,
    } = &operation.body
    {
        prepared = PreparedCapacityOperationV0::RegisterValidator(Box::new(
            prepare_register_validator_v0(
                context,
                overlay,
                operation,
                decision_preimage,
                validator_id_hex,
                *target_epoch,
                registration_decision_id_hex,
                validator_history_insertion.ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )?,
        ));
    }
    if let PocoApplicationOperationBodyV0::RotateValidator {
        validator_id_hex,
        target_epoch,
        previous_history_head_hex,
        previous_registration_nonce,
        registration_decision_id_hex,
    } = &operation.body
    {
        prepared =
            PreparedCapacityOperationV0::RotateValidator(Box::new(prepare_rotate_validator_v0(
                context,
                overlay,
                operation,
                decision_preimage,
                validator_id_hex,
                *target_epoch,
                previous_history_head_hex,
                *previous_registration_nonce,
                registration_decision_id_hex,
            )?));
    }
    if let PocoApplicationOperationBodyV0::RegisterFutureCandidate {
        validator_id_hex,
        target_epoch,
        previous_registration_nonce,
        predecessor_history_head_hex,
        proof_cev0_hex,
        registration_decision_id_hex,
    } = &operation.body
    {
        prepared = PreparedCapacityOperationV0::RegisterFutureCandidate(Box::new(
            prepare_register_future_candidate_v0(
                context,
                overlay,
                operation,
                decision_preimage,
                validator_id_hex,
                *target_epoch,
                *previous_registration_nonce,
                predecessor_history_head_hex,
                proof_cev0_hex,
                registration_decision_id_hex,
                future_candidate_insertion.ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )?,
        ));
    }
    Ok(prepared)
}

fn accept_capacity_additions_before_clone_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
) -> Result<(usize, usize)> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let missing_fact = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
        )
    };
    let PocoApplicationOperationBodyV0::AcceptCertificate {
        certificate_id_hex, ..
    } = &operation.body
    else {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    };
    let signed_certificate_id =
        exact_hash32_hex(certificate_id_hex).map_err(|_| signed_semantic())?;
    let mut certificate_changes = operation
        .semantic_changes
        .iter()
        .filter(|change| change.kind == PocoSnapshotEntryKindV0::ConsumptionCertificate as u8);
    let certificate_change = certificate_changes.next().ok_or_else(signed_semantic)?;
    if certificate_changes.next().is_some() {
        return Err(signed_semantic());
    }
    let logical_key =
        exact_hash32_hex(&certificate_change.logical_key_hex).map_err(|_| signed_semantic())?;
    let next_value = exact_hex(
        certificate_change
            .next_value_hex
            .as_deref()
            .ok_or_else(signed_semantic)?,
        1,
        MAX_POCO_SEMANTIC_PAYLOAD_BYTES,
        "certificate semantic value",
    )
    .map_err(|_| signed_semantic())?;
    let parts = decode_poco_snapshot_value_parts_v0_exact(
        PocoSnapshotEntryKindV0::ConsumptionCertificate,
        &logical_key,
        &next_value,
    )
    .map_err(|_| signed_semantic())?;
    let certificate = decode_consumption_certificate_v0_exact(parts.payload).map_err(|_| {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::CryptographicProof,
        )
    })?;
    if certificate.certificate_id().as_bytes() != &signed_certificate_id {
        return Err(signed_semantic());
    }
    let body = certificate.body();
    let consumer_id_hex = hex::encode(body.consumer_id().as_bytes());
    let consumer_key_id_hex = hex::encode(body.consumer_key_id().as_bytes());
    let provider_id_hex = hex::encode(body.provider_id().as_bytes());
    let key_index = overlay
        .authority
        .consumer_keys
        .binary_search_by(|key| {
            (
                key.consumer_id_hex.as_str(),
                key.consumer_key_id_hex.as_str(),
            )
                .cmp(&(consumer_id_hex.as_str(), consumer_key_id_hex.as_str()))
        })
        .map_err(|_| missing_fact())?;
    let key_authority = &overlay.authority.consumer_keys[key_index];
    let new_nonce_watermark = usize::from(
        key_authority
            .nonce_watermarks
            .binary_search_by(|watermark| watermark.provider_id_hex.cmp(&provider_id_hex))
            .is_err(),
    );
    let target_nonce_watermarks = key_authority
        .nonce_watermarks
        .len()
        .checked_add(new_nonce_watermark)
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
        })?;
    if target_nonce_watermarks > MAX_NONCE_WATERMARKS_PER_KEY {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }

    let meter_id_hex = hex::encode(body.meter_id());
    let policy_index = overlay
        .authority
        .meter_policies
        .binary_search_by(|policy| {
            (policy.meter_id_hex.as_str(), policy.meter_version)
                .cmp(&(meter_id_hex.as_str(), body.meter_version()))
        })
        .map_err(|_| missing_fact())?;
    let policy = &overlay.authority.meter_policies[policy_index];
    let meter_window = context
        .active_epoch
        .get()
        .checked_div(policy.rolling_epoch_span)
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay)
        })?;
    let parameter_window = context.active_epoch.get();
    let task_id_hex = hex::encode(body.task_id());
    let new_usage_buckets = [
        overlay
            .authority
            .meter_usage
            .binary_search_by(|usage| {
                (&usage.meter_id_hex, usage.meter_version, usage.window_epoch).cmp(&(
                    &meter_id_hex,
                    body.meter_version(),
                    meter_window,
                ))
            })
            .is_err(),
        overlay
            .authority
            .consumer_provider_usage
            .binary_search_by(|usage| {
                (
                    &usage.consumer_id_hex,
                    &usage.provider_id_hex,
                    usage.window_epoch,
                )
                    .cmp(&(&consumer_id_hex, &provider_id_hex, parameter_window))
            })
            .is_err(),
        overlay
            .authority
            .task_provider_usage
            .binary_search_by(|usage| {
                (
                    &usage.task_id_hex,
                    &usage.provider_id_hex,
                    usage.window_epoch,
                )
                    .cmp(&(&task_id_hex, &provider_id_hex, parameter_window))
            })
            .is_err(),
        overlay
            .authority
            .provider_usage
            .binary_search_by(|usage| {
                (&usage.provider_id_hex, usage.window_epoch)
                    .cmp(&(&provider_id_hex, parameter_window))
            })
            .is_err(),
    ]
    .into_iter()
    .filter(|missing| *missing)
    .count();
    Ok((new_nonce_watermark, new_usage_buckets))
}

fn validate_operation_field_admission_v0(operation: &PocoApplicationOperationV0) -> Result<()> {
    if !matches!(
        &operation.body,
        PocoApplicationOperationBodyV0::AcceptCertificate { .. }
            | PocoApplicationOperationBodyV0::FundSettlement { .. }
            | PocoApplicationOperationBodyV0::RegisterValidator { .. }
    ) && !operation.nullifier_non_membership_checks.is_empty()
    {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::NullifierProof,
        ));
    }
    Ok(())
}

fn apply_operation_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    decision_preimage: [u8; 32],
    prepared: PreparedCapacityOperationV0,
) -> Result<()> {
    let expected_prepared_tag = match &operation.body {
        PocoApplicationOperationBodyV0::AuthorizeConsumerKey { .. } => 1,
        PocoApplicationOperationBodyV0::DefineMeterPolicy { .. } => 2,
        PocoApplicationOperationBodyV0::FundSettlement { .. } => 3,
        PocoApplicationOperationBodyV0::OpenChallenge { .. } => 4,
        PocoApplicationOperationBodyV0::RegisterFutureCandidate { .. } => 5,
        PocoApplicationOperationBodyV0::RegisterValidator { .. } => 6,
        PocoApplicationOperationBodyV0::RotateValidator { .. } => 7,
        PocoApplicationOperationBodyV0::ReleaseSettlement { .. } => 8,
        PocoApplicationOperationBodyV0::ResolveChallenge { .. } => 9,
        PocoApplicationOperationBodyV0::ProposeGovernance { .. } => 10,
        PocoApplicationOperationBodyV0::ApproveGovernance { .. } => 11,
        PocoApplicationOperationBodyV0::RevokeConsumerKey { .. } => 12,
        PocoApplicationOperationBodyV0::PruneRevokedConsumerKey { .. } => 13,
        PocoApplicationOperationBodyV0::RetireMeterPolicy { .. } => 14,
        PocoApplicationOperationBodyV0::PruneRetiredMeter { .. } => 15,
        _ => 0,
    };
    let actual_prepared_tag = match &prepared {
        PreparedCapacityOperationV0::Deferred => 0,
        PreparedCapacityOperationV0::AuthorizeConsumerKey(_) => 1,
        PreparedCapacityOperationV0::DefineMeter(_) => 2,
        PreparedCapacityOperationV0::FundSettlement(_) => 3,
        PreparedCapacityOperationV0::OpenChallenge(_) => 4,
        PreparedCapacityOperationV0::RegisterFutureCandidate(_) => 5,
        PreparedCapacityOperationV0::RegisterValidator(_) => 6,
        PreparedCapacityOperationV0::RotateValidator(_) => 7,
        PreparedCapacityOperationV0::ReleaseSettlement(_) => 8,
        PreparedCapacityOperationV0::ResolveChallenge(_) => 9,
        PreparedCapacityOperationV0::ProposeGovernance(_) => 10,
        PreparedCapacityOperationV0::ApproveGovernance(_) => 11,
        PreparedCapacityOperationV0::RevokeConsumerKey(_) => 12,
        PreparedCapacityOperationV0::PruneRevokedConsumerKey(_) => 13,
        PreparedCapacityOperationV0::RetireMeter(_) => 14,
        PreparedCapacityOperationV0::PruneRetiredMeter(_) => 15,
    };
    if expected_prepared_tag != actual_prepared_tag {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    let field_admission_was_preclone = matches!(
        &operation.body,
        PocoApplicationOperationBodyV0::AuthorizeConsumerKey { .. }
            | PocoApplicationOperationBodyV0::DefineMeterPolicy { .. }
            | PocoApplicationOperationBodyV0::OpenChallenge { .. }
            | PocoApplicationOperationBodyV0::RegisterFutureCandidate { .. }
            | PocoApplicationOperationBodyV0::RegisterValidator { .. }
            | PocoApplicationOperationBodyV0::RotateValidator { .. }
            | PocoApplicationOperationBodyV0::ReleaseSettlement { .. }
            | PocoApplicationOperationBodyV0::ResolveChallenge { .. }
            | PocoApplicationOperationBodyV0::ProposeGovernance { .. }
            | PocoApplicationOperationBodyV0::ApproveGovernance { .. }
            | PocoApplicationOperationBodyV0::RevokeConsumerKey { .. }
            | PocoApplicationOperationBodyV0::PruneRevokedConsumerKey { .. }
            | PocoApplicationOperationBodyV0::RetireMeterPolicy { .. }
            | PocoApplicationOperationBodyV0::PruneRetiredMeter { .. }
    );
    if !field_admission_was_preclone {
        validate_operation_field_admission_v0(operation)?;
    }
    let mut prepared_prune_revoked_consumer_key = None;
    let mut prepared_retire_meter = None;
    let mut prepared_prune_retired_meter = None;
    let (
        mut prepared_authorize_consumer_key,
        mut prepared_define_meter,
        mut prepared_fund_settlement,
        mut prepared_release_settlement,
        mut prepared_open_challenge,
        mut prepared_resolve_challenge,
        mut prepared_propose_governance,
        mut prepared_approve_governance,
        mut prepared_future_candidate,
        mut prepared_register_validator,
        mut prepared_rotate_validator,
        mut prepared_revoke_consumer_key,
    ) = match prepared {
        PreparedCapacityOperationV0::Deferred => (
            None, None, None, None, None, None, None, None, None, None, None, None,
        ),
        PreparedCapacityOperationV0::AuthorizeConsumerKey(prepared) => (
            Some(*prepared),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        PreparedCapacityOperationV0::DefineMeter(prepared) => (
            None,
            Some(*prepared),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        PreparedCapacityOperationV0::FundSettlement(prepared) => (
            None,
            None,
            Some(*prepared),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        PreparedCapacityOperationV0::ReleaseSettlement(prepared) => (
            None,
            None,
            None,
            Some(*prepared),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        PreparedCapacityOperationV0::OpenChallenge(prepared) => (
            None,
            None,
            None,
            None,
            Some(*prepared),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        PreparedCapacityOperationV0::ResolveChallenge(prepared) => (
            None,
            None,
            None,
            None,
            None,
            Some(*prepared),
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        PreparedCapacityOperationV0::ProposeGovernance(prepared) => (
            None,
            None,
            None,
            None,
            None,
            None,
            Some(*prepared),
            None,
            None,
            None,
            None,
            None,
        ),
        PreparedCapacityOperationV0::ApproveGovernance(prepared) => (
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(*prepared),
            None,
            None,
            None,
            None,
        ),
        PreparedCapacityOperationV0::RegisterFutureCandidate(prepared) => (
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(*prepared),
            None,
            None,
            None,
        ),
        PreparedCapacityOperationV0::RegisterValidator(prepared) => (
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(*prepared),
            None,
            None,
        ),
        PreparedCapacityOperationV0::RotateValidator(prepared) => (
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(*prepared),
            None,
        ),
        PreparedCapacityOperationV0::RevokeConsumerKey(prepared) => (
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(*prepared),
        ),
        PreparedCapacityOperationV0::PruneRevokedConsumerKey(prepared) => {
            prepared_prune_revoked_consumer_key = Some(*prepared);
            (
                None, None, None, None, None, None, None, None, None, None, None, None,
            )
        }
        PreparedCapacityOperationV0::RetireMeter(prepared) => {
            prepared_retire_meter = Some(*prepared);
            (
                None, None, None, None, None, None, None, None, None, None, None, None,
            )
        }
        PreparedCapacityOperationV0::PruneRetiredMeter(prepared) => {
            prepared_prune_retired_meter = Some(*prepared);
            (
                None, None, None, None, None, None, None, None, None, None, None, None,
            )
        }
    };
    match &operation.body {
        PocoApplicationOperationBodyV0::AuthorizeConsumerKey { .. } => {
            apply_prepared_authorize_consumer_key_v0(
                overlay,
                operation,
                prepared_authorize_consumer_key.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::RevokeConsumerKey { .. } => {
            apply_prepared_revoke_consumer_key_v0(
                overlay,
                operation,
                prepared_revoke_consumer_key.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::PruneRevokedConsumerKey { .. } => {
            apply_prepared_prune_revoked_consumer_key_v0(
                overlay,
                operation,
                prepared_prune_revoked_consumer_key.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::DefineMeterPolicy {
            policy: _,
            decision_id_hex: _,
        } => apply_prepared_define_meter_v0(
            overlay,
            operation,
            prepared_define_meter.take().ok_or_else(|| {
                invariant_application_error_v0(
                    PocoApplicationInvariantV0::DerivedMutationPostcondition,
                )
            })?,
        ),
        PocoApplicationOperationBodyV0::RetireMeterPolicy { .. } => apply_prepared_retire_meter_v0(
            overlay,
            operation,
            prepared_retire_meter.take().ok_or_else(|| {
                invariant_application_error_v0(
                    PocoApplicationInvariantV0::DerivedMutationPostcondition,
                )
            })?,
        ),
        PocoApplicationOperationBodyV0::PruneRetiredMeter { .. } => {
            apply_prepared_prune_retired_meter_v0(
                overlay,
                operation,
                prepared_prune_retired_meter.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::FundSettlement { .. } => apply_prepared_fund_settlement_v0(
            overlay,
            operation,
            prepared_fund_settlement.take().ok_or_else(|| {
                invariant_application_error_v0(
                    PocoApplicationInvariantV0::DerivedMutationPostcondition,
                )
            })?,
        ),
        PocoApplicationOperationBodyV0::AcceptCertificate {
            certificate_id_hex,
            funding_decision_id_hex,
            acceptance_decision_id_hex,
            meter_decision_id_hex,
            evidence_decision_id_hex,
        } => apply_accept_certificate_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            certificate_id_hex,
            funding_decision_id_hex,
            acceptance_decision_id_hex,
            meter_decision_id_hex,
            evidence_decision_id_hex,
        ),
        PocoApplicationOperationBodyV0::ReleaseSettlement { .. } => {
            apply_prepared_release_settlement_v0(
                overlay,
                operation,
                prepared_release_settlement.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::OpenChallenge { .. } => apply_prepared_open_challenge_v0(
            overlay,
            operation,
            prepared_open_challenge.take().ok_or_else(|| {
                invariant_application_error_v0(
                    PocoApplicationInvariantV0::DerivedMutationPostcondition,
                )
            })?,
        ),
        PocoApplicationOperationBodyV0::ResolveChallenge { .. } => {
            apply_prepared_resolve_challenge_v0(
                overlay,
                operation,
                prepared_resolve_challenge.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::ProposeGovernance { .. } => {
            apply_prepared_propose_governance_v0(
                overlay,
                operation,
                prepared_propose_governance.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::ApproveGovernance { .. } => {
            apply_prepared_approve_governance_v0(
                overlay,
                operation,
                prepared_approve_governance.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::RegisterValidator { .. } => {
            apply_prepared_register_validator_v0(
                overlay,
                operation,
                prepared_register_validator.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::RotateValidator { .. } => {
            apply_prepared_rotate_validator_v0(
                overlay,
                operation,
                prepared_rotate_validator.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::RegisterFutureCandidate { .. } => {
            apply_prepared_future_candidate_v0(
                overlay,
                operation,
                prepared_future_candidate.take().ok_or_else(|| {
                    invariant_application_error_v0(
                        PocoApplicationInvariantV0::DerivedMutationPostcondition,
                    )
                })?,
            )
        }
        PocoApplicationOperationBodyV0::RevokeValidator {
            validator_id_hex,
            revocation_decision_id_hex,
        } => apply_revoke_validator_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            validator_id_hex,
            revocation_decision_id_hex,
        ),
        PocoApplicationOperationBodyV0::PruneRevokedValidatorHistory { validator_id_hex } => {
            apply_prune_revoked_validator_history_v0(context, overlay, operation, validator_id_hex)
        }
        PocoApplicationOperationBodyV0::PruneExpiredCertificate { certificate_id_hex } => {
            apply_prune_certificate_v0(context, overlay, operation, certificate_id_hex)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_authorize_consumer_key_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    consumer_id_hex: &str,
    consumer_key_id_hex: &str,
    public_key_hex: &str,
    active_from_height: u64,
    decision_id_hex: &str,
) -> Result<PreparedAuthorizeConsumerKeyV0> {
    ensure!(
        active_from_height == context.target_height.get(),
        "consumer-key activation height is not the authenticated target height"
    );
    let consumer_id = exact_opaque_hex(consumer_id_hex)?;
    let consumer_key_id = exact_opaque_hex(consumer_key_id_hex)?;
    let public_key = exact_hash32_hex(public_key_hex)?;
    ensure!(public_key != [0; 32], "zero consumer public key");
    let identity = joined_identity(&[&consumer_id, &consumer_key_id]);
    let decision =
        require_derived_decision_id(preimage, b"authorize-consumer-key", decision_id_hex)?;
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(
        &changes,
        &[PocoSnapshotEntryKindV0::ConsumerKeyAuthorization],
    )?;
    let change = &changes[0];
    ensure!(
        change.expected_value.is_none()
            && change.next_identity.as_deref() == Some(identity.as_slice()),
        "consumer-key authorization is not an exact create"
    );
    match change.next_fact.as_ref() {
        Some(SemanticFactV0::ConsumerKeyAuthorization {
            public_key: semantic_key,
            active_from,
            revoked_at,
        }) => ensure!(
            *semantic_key == public_key
                && *active_from == context.target_height.get()
                && revoked_at.is_none(),
            "consumer-key authorization semantic value mismatch"
        ),
        _ => bail!("authorize-consumer-key operation lacks exact key semantic fact"),
    }
    overlay.accumulator.count().checked_add(2).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    Ok(PreparedAuthorizeConsumerKeyV0 {
        authority: ConsumerKeyAuthorityV0 {
            consumer_id_hex: consumer_id_hex.to_string(),
            consumer_key_id_hex: consumer_key_id_hex.to_string(),
            public_key_hex: public_key_hex.to_string(),
            active_from_height,
            authorization_decision_id_hex: decision_id_hex.to_string(),
            revoked_at_height: None,
            revocation_decision_id_hex: None,
            nonce_watermarks: Vec::new(),
        },
        expected_nullifiers: [
            (PocoNullifierFamilyV0::ConsumerKeyDecision, decision),
            (
                PocoNullifierFamilyV0::ConsumerKeyIdentity,
                semantic_identity_digest_v0(
                    PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
                    &identity,
                ),
            ),
        ],
        changes,
    })
}

fn apply_prepared_authorize_consumer_key_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedAuthorizeConsumerKeyV0,
) -> Result<()> {
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_nullifiers,
    )?;
    overlay.authority.consumer_keys.push(prepared.authority);
    overlay.authority.consumer_keys.sort_by(|left, right| {
        (&left.consumer_id_hex, &left.consumer_key_id_hex)
            .cmp(&(&right.consumer_id_hex, &right.consumer_key_id_hex))
    });
    apply_prepared_changes(overlay, prepared.changes, false)
}

fn prepare_revoke_consumer_key_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    authority_index: usize,
) -> Result<PreparedRevokeConsumerKeyV0> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    validate_operation_field_admission_v0(operation)?;
    let PocoApplicationOperationBodyV0::RevokeConsumerKey {
        consumer_id_hex,
        consumer_key_id_hex,
        public_key_hex,
        active_from_height,
        revoked_at_height,
        decision_id_hex,
    } = &operation.body
    else {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    };
    if *revoked_at_height != context.target_height.get() {
        return Err(signed_semantic());
    }
    let consumer_id = exact_opaque_hex(consumer_id_hex).map_err(|_| signed_semantic())?;
    let consumer_key_id = exact_opaque_hex(consumer_key_id_hex).map_err(|_| signed_semantic())?;
    let public_key = exact_hash32_hex(public_key_hex).map_err(|_| signed_semantic())?;
    if public_key == [0; 32] {
        return Err(signed_semantic());
    }
    let identity = joined_identity(&[&consumer_id, &consumer_key_id]);
    let decision = require_derived_decision_id(preimage, b"revoke-consumer-key", decision_id_hex)
        .map_err(|_| signed_semantic())?;
    let expected_authority = overlay
        .authority
        .consumer_keys
        .get(authority_index)
        .filter(|item| {
            item.consumer_id_hex == *consumer_id_hex
                && item.consumer_key_id_hex == *consumer_key_id_hex
        })
        .cloned()
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::DerivedMutationPostcondition)
        })?;
    let authority_public_key = exact_hash32_hex(&expected_authority.public_key_hex)
        .map_err(|_| authenticated_overlay())?;
    let [raw_change] = operation.semantic_changes.as_slice() else {
        return Err(signed_semantic());
    };
    if raw_change.kind != PocoSnapshotEntryKindV0::ConsumerKeyAuthorization as u8 {
        return Err(signed_semantic());
    }
    let signed_logical_key = exact_hex(
        &raw_change.logical_key_hex,
        32,
        32,
        "consumer-key revocation logical key",
    )
    .map_err(|_| signed_semantic())?;
    let expected_logical_key =
        semantic_identity_digest_v0(PocoSnapshotEntryKindV0::ConsumerKeyAuthorization, &identity);
    if signed_logical_key != expected_logical_key {
        return Err(signed_semantic());
    }
    let predecessor_value = overlay
        .entries
        .get(&(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            expected_logical_key.to_vec(),
        ))
        .cloned()
        .ok_or_else(authenticated_overlay)?;
    let predecessor = owned_semantic_parts(
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
        &expected_logical_key,
        &predecessor_value,
    )
    .map_err(|_| authenticated_overlay())?;
    if predecessor.identity != identity {
        return Err(authenticated_overlay());
    }
    let (old_key, old_active, old_revoked_at) = match predecessor.fact {
        SemanticFactV0::ConsumerKeyAuthorization {
            public_key,
            active_from,
            revoked_at,
        } => (public_key, active_from, revoked_at),
        _ => return Err(authenticated_overlay()),
    };
    if old_key != authority_public_key
        || old_active != expected_authority.active_from_height
        || old_revoked_at != expected_authority.revoked_at_height
    {
        return Err(authenticated_overlay());
    }
    if public_key != authority_public_key
        || *active_from_height != expected_authority.active_from_height
        || old_revoked_at.is_some()
    {
        return Err(signed_semantic());
    }
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, false).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )
        })?;
    let change = &changes[0];
    if change.expected_value.as_ref() != Some(&predecessor_value)
        || change.expected_identity.as_deref() != Some(identity.as_slice())
    {
        return Err(authenticated_overlay());
    }
    if change.next_identity.as_deref() != Some(identity.as_slice()) {
        return Err(signed_semantic());
    }
    match change.next_fact.as_ref() {
        Some(SemanticFactV0::ConsumerKeyAuthorization {
            public_key: new_key,
            active_from: new_active,
            revoked_at: Some(revoked_at),
        }) if *new_key == public_key
            && *new_active == *active_from_height
            && *revoked_at == context.target_height.get() => {}
        _ => return Err(signed_semantic()),
    }
    overlay.accumulator.count().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    let mut successor_authority = expected_authority.clone();
    successor_authority.revoked_at_height = Some(context.target_height.get());
    successor_authority.revocation_decision_id_hex = Some(decision_id_hex.to_string());
    Ok(PreparedRevokeConsumerKeyV0 {
        authority_index,
        expected_authority,
        successor_authority,
        expected_semantic_changes: operation.semantic_changes.clone(),
        expected_nullifiers: [(PocoNullifierFamilyV0::ConsumerKeyDecision, decision)],
        changes,
    })
}

fn apply_prepared_revoke_consumer_key_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedRevokeConsumerKeyV0,
) -> Result<()> {
    let body_matches = match &operation.body {
        PocoApplicationOperationBodyV0::RevokeConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
            public_key_hex,
            active_from_height,
            revoked_at_height,
            decision_id_hex,
        } => {
            consumer_id_hex == &prepared.expected_authority.consumer_id_hex
                && consumer_key_id_hex == &prepared.expected_authority.consumer_key_id_hex
                && public_key_hex == &prepared.expected_authority.public_key_hex
                && *active_from_height == prepared.expected_authority.active_from_height
                && Some(*revoked_at_height) == prepared.successor_authority.revoked_at_height
                && prepared
                    .successor_authority
                    .revocation_decision_id_hex
                    .as_deref()
                    == Some(decision_id_hex.as_str())
        }
        _ => false,
    };
    let mut expected_successor = prepared.expected_authority.clone();
    expected_successor.revoked_at_height = prepared.successor_authority.revoked_at_height;
    expected_successor.revocation_decision_id_hex = prepared
        .successor_authority
        .revocation_decision_id_hex
        .clone();
    let source_row_matches = overlay
        .authority
        .consumer_keys
        .get(prepared.authority_index)
        == Some(&prepared.expected_authority);
    let semantic_owner_matches = operation.semantic_changes == prepared.expected_semantic_changes;
    let change_sources_match = prepared.changes.iter().all(|change| {
        let key = (change.kind, change.logical_key.clone());
        overlay.entries.get(&key) == change.expected_value.as_ref()
            && !overlay.mutations.contains_key(&key)
    });
    if !body_matches
        || expected_successor != prepared.successor_authority
        || !source_row_matches
        || !semantic_owner_matches
        || !change_sources_match
    {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_nullifiers,
    )?;
    overlay.authority.consumer_keys[prepared.authority_index] = prepared.successor_authority;
    apply_prepared_changes(overlay, prepared.changes, false)
}

fn consumer_key_authority_companion_keys_v0(
    overlay: &PocoApplicationOverlayV0,
    authority: &ConsumerKeyAuthorityV0,
) -> Result<BTreeSet<(PocoSnapshotEntryKindV0, Vec<u8>)>> {
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    let consumer_id =
        exact_opaque_hex(&authority.consumer_id_hex).map_err(|_| authenticated_overlay())?;
    let consumer_key_id =
        exact_opaque_hex(&authority.consumer_key_id_hex).map_err(|_| authenticated_overlay())?;
    let public_key =
        exact_hash32_hex(&authority.public_key_hex).map_err(|_| authenticated_overlay())?;
    let key_identity = joined_identity(&[&consumer_id, &consumer_key_id]);
    let key_logical_key = semantic_identity_digest_v0(
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
        &key_identity,
    );
    let key_value = overlay
        .entries
        .get(&(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            key_logical_key.to_vec(),
        ))
        .ok_or_else(authenticated_overlay)?;
    let key_parts = owned_semantic_parts(
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
        &key_logical_key,
        key_value,
    )
    .map_err(|_| authenticated_overlay())?;
    if key_parts.identity != key_identity
        || !matches!(
            key_parts.fact,
            SemanticFactV0::ConsumerKeyAuthorization {
                public_key: semantic_key,
                active_from,
                revoked_at,
            } if semantic_key == public_key
                && active_from == authority.active_from_height
                && revoked_at == authority.revoked_at_height
        )
    {
        return Err(authenticated_overlay());
    }

    let mut expected_keys = BTreeSet::new();
    expected_keys.insert((
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
        key_logical_key.to_vec(),
    ));
    for watermark in &authority.nonce_watermarks {
        let provider_id =
            exact_opaque_hex(&watermark.provider_id_hex).map_err(|_| authenticated_overlay())?;
        let nonce_identity = joined_identity(&[&consumer_id, &consumer_key_id, &provider_id]);
        let nonce_logical_key =
            semantic_identity_digest_v0(PocoSnapshotEntryKindV0::ConsumerNonce, &nonce_identity);
        if exact_hash32_hex(&watermark.logical_key_hex).map_err(|_| authenticated_overlay())?
            != nonce_logical_key
        {
            return Err(authenticated_overlay());
        }
        let nonce_value = overlay
            .entries
            .get(&(
                PocoSnapshotEntryKindV0::ConsumerNonce,
                nonce_logical_key.to_vec(),
            ))
            .ok_or_else(authenticated_overlay)?;
        let nonce_parts = owned_semantic_parts(
            PocoSnapshotEntryKindV0::ConsumerNonce,
            &nonce_logical_key,
            nonce_value,
        )
        .map_err(|_| authenticated_overlay())?;
        if nonce_parts.identity != nonce_identity
            || !matches!(
                nonce_parts.fact,
                SemanticFactV0::ConsumerNonce { max_accepted_nonce }
                    if max_accepted_nonce == watermark.max_accepted_nonce
            )
            || !expected_keys.insert((
                PocoSnapshotEntryKindV0::ConsumerNonce,
                nonce_logical_key.to_vec(),
            ))
        {
            return Err(authenticated_overlay());
        }
    }
    Ok(expected_keys)
}

fn prepare_prune_revoked_consumer_key_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    authority_index: usize,
) -> Result<PreparedPruneRevokedConsumerKeyV0> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let protocol_reject = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    validate_operation_field_admission_v0(operation)?;
    let PocoApplicationOperationBodyV0::PruneRevokedConsumerKey {
        consumer_id_hex,
        consumer_key_id_hex,
    } = &operation.body
    else {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    };
    let consumer_id = exact_opaque_hex(consumer_id_hex).map_err(|_| signed_semantic())?;
    let consumer_key_id = exact_opaque_hex(consumer_key_id_hex).map_err(|_| signed_semantic())?;
    let key_authority = overlay
        .authority
        .consumer_keys
        .get(authority_index)
        .filter(|item| {
            item.consumer_id_hex == *consumer_id_hex
                && item.consumer_key_id_hex == *consumer_key_id_hex
        })
        .cloned()
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::DerivedMutationPostcondition)
        })?;
    let revoked_at = key_authority
        .revoked_at_height
        .ok_or_else(protocol_reject)?;
    let boundary =
        protocol_retention_boundary_v0(revoked_at, &context.active_parameters).map_err(|_| {
            invariant_application_error_v0(PocoApplicationInvariantV0::PlannerArithmetic)
        })?;
    if !prune_target_is_strictly_after_boundary_v0(context.target_height.get(), boundary) {
        return Err(protocol_reject());
    }
    let active_reference = active_certificate_reference_exists_v0(overlay, |body| {
        body.consumer_id().as_bytes() == consumer_id.as_slice()
            && body.consumer_key_id().as_bytes() == consumer_key_id.as_slice()
    })
    .map_err(|_| authenticated_overlay())?;
    if active_reference {
        return Err(protocol_reject());
    }
    let expected_keys = consumer_key_authority_companion_keys_v0(overlay, &key_authority)?;
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, true).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )
        })?;
    if !changes.iter().all(|change| change.next_value.is_none()) {
        return Err(signed_semantic());
    }
    let actual_keys = changes
        .iter()
        .map(|change| (change.kind, change.logical_key.clone()))
        .collect::<BTreeSet<_>>();
    if actual_keys != expected_keys || actual_keys.len() != changes.len() {
        return Err(signed_semantic());
    }
    let nonce_summary =
        consumer_nonce_summary_digest_v0(&key_authority).map_err(|_| authenticated_overlay())?;
    overlay.accumulator.count().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    Ok(PreparedPruneRevokedConsumerKeyV0 {
        authority_index,
        expected_authority: key_authority,
        expected_semantic_changes: operation.semantic_changes.clone(),
        expected_nullifiers: [(PocoNullifierFamilyV0::ConsumerNonceSummary, nonce_summary)],
        changes,
    })
}

fn apply_prepared_prune_revoked_consumer_key_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedPruneRevokedConsumerKeyV0,
) -> Result<()> {
    let body_matches = matches!(
        &operation.body,
        PocoApplicationOperationBodyV0::PruneRevokedConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
        } if consumer_id_hex == &prepared.expected_authority.consumer_id_hex
            && consumer_key_id_hex == &prepared.expected_authority.consumer_key_id_hex
    );
    let source_row_matches = overlay
        .authority
        .consumer_keys
        .get(prepared.authority_index)
        == Some(&prepared.expected_authority);
    let semantic_owner_matches = operation.semantic_changes == prepared.expected_semantic_changes;
    let change_sources_match = prepared.changes.iter().all(|change| {
        let key = (change.kind, change.logical_key.clone());
        overlay.entries.get(&key) == change.expected_value.as_ref()
            && !overlay.mutations.contains_key(&key)
    });
    if !body_matches || !source_row_matches || !semantic_owner_matches || !change_sources_match {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_nullifiers,
    )?;
    overlay
        .authority
        .consumer_keys
        .remove(prepared.authority_index);
    apply_prepared_changes(overlay, prepared.changes, true)
}

fn prepare_define_meter_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    policy: &MeterAuthorityPolicyV0,
    decision_id_hex: &str,
) -> Result<PreparedDefineMeterV0> {
    validate_meter_policy(policy)?;
    if policy.per_certificate_cap.get()? > context.active_parameters.per_certificate_unit_cap() {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    if policy.rolling_cap.get()?
        > context
            .active_parameters
            .per_consumer_provider_epoch_unit_cap()
    {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    ensure!(
        policy.active_from_height == context.target_height.get()
            && policy.retired_at_height.is_none(),
        "new meter policy is not bound to authenticated target height"
    );
    let decision = require_derived_decision_id(preimage, b"define-meter", decision_id_hex)?;
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::MeterDefinition])?;
    let change = &changes[0];
    let meter_id = exact_opaque_hex(&policy.meter_id_hex)?;
    let identity = meter_identity(&meter_id, policy.meter_version);
    ensure!(
        change.next_identity.as_deref() == Some(identity.as_slice()),
        "meter policy semantic identity mismatch"
    );
    match change.next_fact.as_ref() {
        Some(SemanticFactV0::MeterDefinition {
            unit_scale,
            active_from,
            retired_at,
        }) => ensure!(
            *unit_scale == policy.unit_scale.get()?
                && *active_from == context.target_height.get()
                && retired_at.is_none(),
            "meter policy semantic value mismatch"
        ),
        _ => bail!("define-meter operation lacks exact meter semantic fact"),
    }
    ensure!(
        change.expected_value.is_none(),
        "meter policy already exists"
    );
    ensure!(
        overlay
            .authority
            .meter_policies
            .binary_search_by(|item| {
                (&item.meter_id_hex, item.meter_version)
                    .cmp(&(&policy.meter_id_hex, policy.meter_version))
            })
            .is_err(),
        "meter authority policy already exists"
    );
    overlay.accumulator.count().checked_add(2).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    Ok(PreparedDefineMeterV0 {
        policy: policy.clone(),
        expected_nullifiers: [
            (PocoNullifierFamilyV0::MeterDecision, decision),
            (
                PocoNullifierFamilyV0::MeterIdentity,
                semantic_identity_digest_v0(PocoSnapshotEntryKindV0::MeterDefinition, &identity),
            ),
        ],
        changes,
    })
}

fn apply_prepared_define_meter_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedDefineMeterV0,
) -> Result<()> {
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_nullifiers,
    )?;
    overlay.authority.meter_policies.push(prepared.policy);
    overlay.authority.meter_policies.sort_by(|left, right| {
        (&left.meter_id_hex, left.meter_version).cmp(&(&right.meter_id_hex, right.meter_version))
    });
    apply_prepared_changes(overlay, prepared.changes, false)
}

fn prepare_retire_meter_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    policy_index: usize,
) -> Result<PreparedRetireMeterV0> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    validate_operation_field_admission_v0(operation)?;
    let PocoApplicationOperationBodyV0::RetireMeterPolicy {
        meter_id_hex,
        meter_version,
        retired_at_height,
        decision_id_hex,
    } = &operation.body
    else {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    };
    let meter_id = exact_opaque_hex(meter_id_hex).map_err(|_| signed_semantic())?;
    if *retired_at_height != context.target_height.get() {
        return Err(signed_semantic());
    }
    let decision = require_derived_decision_id(preimage, b"retire-meter", decision_id_hex)
        .map_err(|_| signed_semantic())?;
    let expected_policy = overlay
        .authority
        .meter_policies
        .get(policy_index)
        .filter(|policy| {
            policy.meter_id_hex == *meter_id_hex && policy.meter_version == *meter_version
        })
        .cloned()
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::DerivedMutationPostcondition)
        })?;
    validate_meter_policy(&expected_policy).map_err(|_| authenticated_overlay())?;
    if expected_policy.retired_at_height.is_some() {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    let identity = meter_identity(&meter_id, *meter_version);
    let [raw_change] = operation.semantic_changes.as_slice() else {
        return Err(signed_semantic());
    };
    if raw_change.kind != PocoSnapshotEntryKindV0::MeterDefinition as u8 {
        return Err(signed_semantic());
    }
    let signed_logical_key = exact_hex(
        &raw_change.logical_key_hex,
        32,
        32,
        "meter retirement logical key",
    )
    .map_err(|_| signed_semantic())?;
    let expected_logical_key =
        semantic_identity_digest_v0(PocoSnapshotEntryKindV0::MeterDefinition, &identity);
    if signed_logical_key != expected_logical_key {
        return Err(signed_semantic());
    }
    let predecessor_value = overlay
        .entries
        .get(&(
            PocoSnapshotEntryKindV0::MeterDefinition,
            expected_logical_key.to_vec(),
        ))
        .cloned()
        .ok_or_else(authenticated_overlay)?;
    let predecessor = owned_semantic_parts(
        PocoSnapshotEntryKindV0::MeterDefinition,
        &expected_logical_key,
        &predecessor_value,
    )
    .map_err(|_| authenticated_overlay())?;
    if predecessor.identity != identity {
        return Err(authenticated_overlay());
    }
    let (old_scale, old_active, old_retired) = match predecessor.fact {
        SemanticFactV0::MeterDefinition {
            unit_scale,
            active_from,
            retired_at,
        } => (unit_scale, active_from, retired_at),
        _ => return Err(authenticated_overlay()),
    };
    let authority_scale = expected_policy
        .unit_scale
        .get()
        .map_err(|_| authenticated_overlay())?;
    if old_scale != authority_scale
        || old_active != expected_policy.active_from_height
        || old_retired != expected_policy.retired_at_height
    {
        return Err(authenticated_overlay());
    }
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, false).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )
        })?;
    let change = &changes[0];
    if change.expected_value.as_ref() != Some(&predecessor_value)
        || change.expected_identity.as_deref() != Some(identity.as_slice())
    {
        return Err(authenticated_overlay());
    }
    if change.next_identity.as_deref() != Some(identity.as_slice()) {
        return Err(signed_semantic());
    }
    match change.next_fact.as_ref() {
        Some(SemanticFactV0::MeterDefinition {
            unit_scale,
            active_from,
            retired_at: Some(retired),
        }) if *unit_scale == old_scale
            && *active_from == old_active
            && *retired == *retired_at_height => {}
        _ => return Err(signed_semantic()),
    }
    overlay.accumulator.count().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    let mut successor_policy = expected_policy.clone();
    successor_policy.retired_at_height = Some(*retired_at_height);
    Ok(PreparedRetireMeterV0 {
        policy_index,
        expected_policy,
        successor_policy,
        expected_decision_id_hex: decision_id_hex.clone(),
        expected_semantic_changes: operation.semantic_changes.clone(),
        expected_non_membership_checks: operation.nullifier_non_membership_checks.clone(),
        expected_nullifiers: [(PocoNullifierFamilyV0::MeterDecision, decision)],
        changes,
    })
}

fn apply_prepared_retire_meter_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedRetireMeterV0,
) -> Result<()> {
    let body_matches = match &operation.body {
        PocoApplicationOperationBodyV0::RetireMeterPolicy {
            meter_id_hex,
            meter_version,
            retired_at_height,
            decision_id_hex,
        } => {
            meter_id_hex == &prepared.expected_policy.meter_id_hex
                && *meter_version == prepared.expected_policy.meter_version
                && Some(*retired_at_height) == prepared.successor_policy.retired_at_height
                && decision_id_hex == &prepared.expected_decision_id_hex
        }
        _ => false,
    };
    let mut expected_successor = prepared.expected_policy.clone();
    expected_successor.retired_at_height = prepared.successor_policy.retired_at_height;
    let source_row_matches = overlay.authority.meter_policies.get(prepared.policy_index)
        == Some(&prepared.expected_policy);
    let semantic_owner_matches = operation.semantic_changes == prepared.expected_semantic_changes;
    let field_owner_matches =
        operation.nullifier_non_membership_checks == prepared.expected_non_membership_checks;
    let change_sources_match = prepared.changes.iter().all(|change| {
        let key = (change.kind, change.logical_key.clone());
        overlay.entries.get(&key) == change.expected_value.as_ref()
            && !overlay.mutations.contains_key(&key)
    });
    if !body_matches
        || expected_successor != prepared.successor_policy
        || !source_row_matches
        || !semantic_owner_matches
        || !field_owner_matches
        || !change_sources_match
    {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_nullifiers,
    )?;
    overlay.authority.meter_policies[prepared.policy_index] = prepared.successor_policy;
    apply_prepared_changes(overlay, prepared.changes, false)
}

fn prepare_prune_retired_meter_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    policy_index: usize,
) -> Result<PreparedPruneRetiredMeterV0> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let protocol_reject = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    validate_operation_field_admission_v0(operation)?;
    if !operation.nullifier_insertions.is_empty() {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::NullifierProof,
        ));
    }
    let PocoApplicationOperationBodyV0::PruneRetiredMeter {
        meter_id_hex,
        meter_version,
    } = &operation.body
    else {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    };
    let meter_id = exact_opaque_hex(meter_id_hex).map_err(|_| signed_semantic())?;
    let policy = overlay
        .authority
        .meter_policies
        .get(policy_index)
        .filter(|policy| {
            policy.meter_id_hex == *meter_id_hex && policy.meter_version == *meter_version
        })
        .cloned()
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::DerivedMutationPostcondition)
        })?;
    validate_meter_policy(&policy).map_err(|_| authenticated_overlay())?;
    let retired_at = policy.retired_at_height.ok_or_else(protocol_reject)?;
    let protocol_boundary = protocol_retention_boundary_v0(retired_at, &context.active_parameters)
        .map_err(|_| {
            invariant_application_error_v0(PocoApplicationInvariantV0::PlannerArithmetic)
        })?;
    let meter_boundary = retired_at
        .checked_add(policy.retention_blocks)
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::PlannerArithmetic)
        })?;
    if context.target_height.get() <= protocol_boundary.max(meter_boundary) {
        return Err(protocol_reject());
    }
    let active_reference = active_certificate_reference_exists_v0(overlay, |body| {
        body.meter_id() == meter_id.as_slice() && body.meter_version() == *meter_version
    })
    .map_err(|_| authenticated_overlay())?;
    if active_reference {
        return Err(protocol_reject());
    }
    if !overlay
        .authority
        .meter_usage
        .iter()
        .all(|usage| usage.meter_id_hex != *meter_id_hex || usage.meter_version != *meter_version)
    {
        return Err(protocol_reject());
    }
    let identity = meter_identity(&meter_id, *meter_version);
    let expected_logical_key =
        semantic_identity_digest_v0(PocoSnapshotEntryKindV0::MeterDefinition, &identity);
    let predecessor_value = overlay
        .entries
        .get(&(
            PocoSnapshotEntryKindV0::MeterDefinition,
            expected_logical_key.to_vec(),
        ))
        .cloned()
        .ok_or_else(authenticated_overlay)?;
    let predecessor = owned_semantic_parts(
        PocoSnapshotEntryKindV0::MeterDefinition,
        &expected_logical_key,
        &predecessor_value,
    )
    .map_err(|_| authenticated_overlay())?;
    if predecessor.identity != identity {
        return Err(authenticated_overlay());
    }
    let authority_scale = policy
        .unit_scale
        .get()
        .map_err(|_| authenticated_overlay())?;
    if !matches!(
        predecessor.fact,
        SemanticFactV0::MeterDefinition {
            unit_scale,
            active_from,
            retired_at: Some(semantic_retired_at),
        } if unit_scale == authority_scale
            && active_from == policy.active_from_height
            && semantic_retired_at == retired_at
    ) {
        return Err(authenticated_overlay());
    }
    let [raw_change] = operation.semantic_changes.as_slice() else {
        return Err(signed_semantic());
    };
    if raw_change.kind != PocoSnapshotEntryKindV0::MeterDefinition as u8 {
        return Err(signed_semantic());
    }
    let signed_logical_key = exact_hex(
        &raw_change.logical_key_hex,
        32,
        32,
        "meter prune logical key",
    )
    .map_err(|_| signed_semantic())?;
    if signed_logical_key != expected_logical_key || raw_change.next_value_hex.is_some() {
        return Err(signed_semantic());
    }
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, true).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )
        })?;
    let change = &changes[0];
    if change.expected_value.as_ref() != Some(&predecessor_value)
        || change.expected_identity.as_deref() != Some(identity.as_slice())
        || change.next_value.is_some()
    {
        return Err(authenticated_overlay());
    }
    Ok(PreparedPruneRetiredMeterV0 {
        policy_index,
        expected_policy: policy,
        expected_semantic_changes: operation.semantic_changes.clone(),
        expected_non_membership_checks: operation.nullifier_non_membership_checks.clone(),
        expected_nullifier_insertions: operation.nullifier_insertions.clone(),
        changes,
    })
}

fn apply_prepared_prune_retired_meter_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedPruneRetiredMeterV0,
) -> Result<()> {
    let body_matches = matches!(
        &operation.body,
        PocoApplicationOperationBodyV0::PruneRetiredMeter {
            meter_id_hex,
            meter_version,
        } if meter_id_hex == &prepared.expected_policy.meter_id_hex
            && *meter_version == prepared.expected_policy.meter_version
    );
    let source_row_matches = overlay.authority.meter_policies.get(prepared.policy_index)
        == Some(&prepared.expected_policy);
    let semantic_owner_matches = operation.semantic_changes == prepared.expected_semantic_changes;
    let field_owner_matches = operation.nullifier_non_membership_checks
        == prepared.expected_non_membership_checks
        && operation.nullifier_insertions == prepared.expected_nullifier_insertions;
    let change_sources_match = prepared.changes.iter().all(|change| {
        let key = (change.kind, change.logical_key.clone());
        overlay.entries.get(&key) == change.expected_value.as_ref()
            && !overlay.mutations.contains_key(&key)
    });
    if !body_matches
        || !source_row_matches
        || !semantic_owner_matches
        || !field_owner_matches
        || !change_sources_match
    {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    overlay
        .authority
        .meter_policies
        .remove(prepared.policy_index);
    apply_prepared_changes(overlay, prepared.changes, true)
}

#[allow(clippy::too_many_arguments)]
fn prepare_fund_settlement_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    certificate_id_hex: &str,
    settlement_commitment_hex: &str,
    reserved_units: &CanonicalU128V0,
    funding_decision_id_hex: &str,
) -> Result<PreparedFundSettlementV0> {
    let certificate_id = exact_hash32_hex(certificate_id_hex)?;
    let commitment = exact_hash32_hex(settlement_commitment_hex)?;
    let reserved_units_value = reserved_units.get()?;
    ensure!(
        reserved_units_value > 0,
        "settlement reserved units are zero"
    );
    let funding_decision =
        require_derived_decision_id(preimage, b"fund-settlement", funding_decision_id_hex)?;
    ensure!(
        overlay
            .authority
            .funded_unused_reservations
            .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
            .is_err(),
        "funded-unused reservation already exists"
    );
    ensure!(
        overlay
            .authority
            .active_certificates
            .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
            .is_err(),
        "cannot fund an already accepted certificate"
    );
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::Settlement])?;
    let change = &changes[0];
    ensure!(
        change.expected_value.is_none()
            && change.next_identity.as_deref() == Some(certificate_id.as_slice()),
        "fund-settlement semantic identity is not a new certificate"
    );
    match change.next_fact.as_ref() {
        Some(SemanticFactV0::Settlement {
            commitment: semantic_commitment,
            state: SettlementStateV0::FinalizedFundedUnused,
            finalized_height,
        }) => ensure!(
            *semantic_commitment == commitment && *finalized_height == context.target_height.get(),
            "funded settlement fact is not target-bound"
        ),
        _ => bail!("fund-settlement operation lacks funded-unused semantic fact"),
    }
    overlay.accumulator.count().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    Ok(PreparedFundSettlementV0 {
        reservation: FundedUnusedReservationV0 {
            certificate_id_hex: certificate_id_hex.to_string(),
            settlement_commitment_hex: settlement_commitment_hex.to_string(),
            funding_decision_id_hex: funding_decision_id_hex.to_string(),
            finalized_height: context.target_height.get(),
            reserved_units: CanonicalU128V0::new(reserved_units_value),
        },
        expected_absences: fund_certificate_absence_subjects_v0(certificate_id),
        expected_insertions: [(PocoNullifierFamilyV0::SettlementDecision, funding_decision)],
        changes,
    })
}

fn apply_prepared_fund_settlement_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedFundSettlementV0,
) -> Result<()> {
    verify_nullifier_absences(
        overlay,
        &operation.nullifier_non_membership_checks,
        &prepared.expected_absences,
    )?;
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_insertions,
    )?;
    overlay
        .authority
        .funded_unused_reservations
        .push(prepared.reservation);
    overlay
        .authority
        .funded_unused_reservations
        .sort_by(|left, right| left.certificate_id_hex.cmp(&right.certificate_id_hex));
    apply_prepared_changes(overlay, prepared.changes, false)
}

#[allow(clippy::too_many_arguments)]
fn apply_accept_certificate_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    certificate_id_hex: &str,
    funding_decision_id_hex: &str,
    acceptance_decision_id_hex: &str,
    meter_decision_id_hex: &str,
    evidence_decision_id_hex: &str,
) -> Result<()> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let protocol_reject = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    let certificate_id = exact_hash32_hex(certificate_id_hex).map_err(|_| signed_semantic())?;
    let funding_decision =
        exact_hash32_hex(funding_decision_id_hex).map_err(|_| signed_semantic())?;
    let acceptance_decision =
        require_derived_decision_id(preimage, b"accept-certificate", acceptance_decision_id_hex)?;
    let meter_decision =
        require_derived_decision_id(preimage, b"meter-certificate", meter_decision_id_hex)?;
    let evidence_decision =
        require_derived_decision_id(preimage, b"evidence-certificate", evidence_decision_id_hex)?;
    if acceptance_decision == meter_decision
        || acceptance_decision == evidence_decision
        || meter_decision == evidence_decision
    {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    if overlay
        .authority
        .active_certificates
        .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
        .is_ok()
    {
        return Err(signed_semantic());
    }

    let reservation_index = overlay
        .authority
        .funded_unused_reservations
        .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    let reservation = overlay.authority.funded_unused_reservations[reservation_index].clone();
    let reserved_funding_decision = exact_hash32_hex(&reservation.funding_decision_id_hex)
        .map_err(|_| authenticated_overlay())?;
    if reserved_funding_decision != funding_decision {
        return Err(signed_semantic());
    }

    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(
        &changes,
        &[
            PocoSnapshotEntryKindV0::ConsumptionCertificate,
            PocoSnapshotEntryKindV0::ConsumerNonce,
            PocoSnapshotEntryKindV0::UniqueConsumptionTuple,
            PocoSnapshotEntryKindV0::Settlement,
            PocoSnapshotEntryKindV0::MeasurementEvidence,
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
        ],
    )?;
    let certificate_change =
        change_for_kind(&changes, PocoSnapshotEntryKindV0::ConsumptionCertificate)?;
    if certificate_change.expected_value.is_some()
        || certificate_change.next_identity.as_deref() != Some(certificate_id.as_slice())
    {
        return Err(signed_semantic());
    }
    let certificate_payload = certificate_change
        .next_payload
        .as_deref()
        .ok_or_else(signed_semantic)?;
    let certificate =
        decode_consumption_certificate_v0_exact(certificate_payload).map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::CryptographicProof,
            )
        })?;
    if certificate.certificate_id().as_bytes() != &certificate_id {
        return Err(signed_semantic());
    }
    let body = certificate.body();
    let reserved_units = reservation
        .reserved_units
        .get()
        .map_err(|_| authenticated_overlay())?;
    validate_reserved_units_exact_v0(reserved_units, body.consumed_units())
        .map_err(|_| signed_semantic())?;

    let consumer_id = body.consumer_id();
    let consumer_key_id = body.consumer_key_id();
    let provider_id = body.provider_id();
    let consumer = consumer_id.as_bytes();
    let consumer_key = consumer_key_id.as_bytes();
    let provider = provider_id.as_bytes();
    let consumer_id_hex = hex::encode(consumer);
    let provider_id_hex = hex::encode(provider);
    let task_id_hex = hex::encode(body.task_id());
    let key_identity = joined_identity(&[consumer, consumer_key]);
    let key_parts = source_parts_for_identity(
        overlay,
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
        &key_identity,
    )
    .map_err(|_| authenticated_overlay())?;
    let public_key = match key_parts.fact {
        SemanticFactV0::ConsumerKeyAuthorization {
            public_key,
            active_from,
            revoked_at,
        } => {
            if body.billing_start_height().get() < active_from
                || context.target_height.get() < active_from
                || revoked_at.is_some_and(|height| {
                    body.billing_end_height().get() >= height
                        || context.target_height.get() >= height
                })
            {
                return Err(protocol_reject());
            }
            public_key
        }
        _ => return Err(authenticated_overlay()),
    };
    let consumer_hex = hex::encode(consumer);
    let consumer_key_hex = hex::encode(consumer_key);
    let key_authority_index = overlay
        .authority
        .consumer_keys
        .binary_search_by(|item| {
            (&item.consumer_id_hex, &item.consumer_key_id_hex)
                .cmp(&(&consumer_hex, &consumer_key_hex))
        })
        .map_err(|_| authenticated_overlay())?;
    let key_authority = &overlay.authority.consumer_keys[key_authority_index];
    let authority_public_key =
        exact_hash32_hex(&key_authority.public_key_hex).map_err(|_| authenticated_overlay())?;
    if authority_public_key != public_key {
        return Err(authenticated_overlay());
    }
    if key_authority.active_from_height > context.target_height.get()
        || key_authority.revoked_at_height.is_some_and(|height| {
            body.billing_end_height().get() >= height || context.target_height.get() >= height
        })
    {
        return Err(protocol_reject());
    }
    certificate
        .verify(
            context.genesis_hash,
            context.chain_id,
            &context.active_parameters,
            context.target_height,
            ConsensusPublicKey::new(public_key),
            &StrictEd25519Verifier,
        )
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::CryptographicProof,
            )
        })?;

    let nonce_change = change_for_kind(&changes, PocoSnapshotEntryKindV0::ConsumerNonce)?;
    let nonce_identity = joined_identity(&[consumer, consumer_key, provider]);
    if nonce_change.next_identity.as_deref() != Some(nonce_identity.as_slice()) {
        return Err(signed_semantic());
    }
    let next_nonce = match nonce_change.next_fact.as_ref() {
        Some(SemanticFactV0::ConsumerNonce { max_accepted_nonce }) => *max_accepted_nonce,
        _ => return Err(signed_semantic()),
    };
    if next_nonce != body.consumer_nonce() {
        return Err(signed_semantic());
    }
    if let Some(expected) = nonce_change.expected_fact.as_ref() {
        match expected {
            SemanticFactV0::ConsumerNonce { max_accepted_nonce } => {
                if next_nonce <= *max_accepted_nonce {
                    return Err(protocol_reject());
                }
            }
            _ => return Err(authenticated_overlay()),
        }
    }
    let nonce_provider_hex = hex::encode(provider);
    let nonce_watermark_search = overlay.authority.consumer_keys[key_authority_index]
        .nonce_watermarks
        .binary_search_by(|watermark| {
            watermark
                .provider_id_hex
                .as_str()
                .cmp(nonce_provider_hex.as_str())
        });
    match (nonce_change.expected_fact.as_ref(), nonce_watermark_search) {
        (None, Err(_)) => {
            if overlay.authority.consumer_keys[key_authority_index]
                .nonce_watermarks
                .len()
                >= MAX_NONCE_WATERMARKS_PER_KEY
            {
                return Err(protocol_reject());
            }
        }
        (Some(SemanticFactV0::ConsumerNonce { max_accepted_nonce }), Ok(index)) => {
            let watermark =
                &overlay.authority.consumer_keys[key_authority_index].nonce_watermarks[index];
            let authority_logical_key = exact_hash32_hex(&watermark.logical_key_hex)
                .map_err(|_| authenticated_overlay())?;
            if watermark.max_accepted_nonce != *max_accepted_nonce
                || authority_logical_key.as_slice() != nonce_change.logical_key.as_slice()
            {
                return Err(authenticated_overlay());
            }
        }
        _ => return Err(authenticated_overlay()),
    }

    let tuple_identity = consumption_tuple_identity(body);
    let tuple_change = change_for_kind(&changes, PocoSnapshotEntryKindV0::UniqueConsumptionTuple)?;
    if tuple_change.expected_value.is_some() {
        return Err(protocol_reject());
    }
    if tuple_change.next_identity.as_deref() != Some(tuple_identity.as_slice()) {
        return Err(signed_semantic());
    }
    validate_tuple_acceptance_authority_v0(
        tuple_change
            .next_fact
            .as_ref()
            .ok_or_else(signed_semantic)?,
        certificate_id,
        context.target_height.get(),
    )
    .map_err(|_| signed_semantic())?;
    let tuple_key: [u8; 32] = tuple_change
        .logical_key
        .as_slice()
        .try_into()
        .map_err(|_| signed_semantic())?;

    let meter_id_hex = hex::encode(body.meter_id());
    let meter_index = overlay
        .authority
        .meter_policies
        .binary_search_by(|item| {
            (&item.meter_id_hex, item.meter_version).cmp(&(&meter_id_hex, body.meter_version()))
        })
        .map_err(|_| authenticated_overlay())?;
    let meter_policy = overlay.authority.meter_policies[meter_index].clone();
    if meter_policy.active_from_height > body.billing_start_height().get()
        || meter_policy.active_from_height > context.target_height.get()
        || meter_policy.retired_at_height.is_some_and(|height| {
            body.billing_end_height().get() >= height || context.target_height.get() >= height
        })
    {
        return Err(protocol_reject());
    }
    let meter_task =
        exact_opaque_hex(&meter_policy.task_id_hex).map_err(|_| authenticated_overlay())?;
    if meter_task.as_slice() != body.task_id() {
        return Err(protocol_reject());
    }
    if let Some(expected_output) = &meter_policy.output_commitment_hex {
        let expected_output =
            exact_hash32_hex(expected_output).map_err(|_| authenticated_overlay())?;
        if expected_output != *body.output_commitment() {
            return Err(protocol_reject());
        }
    }
    let meter_semantic_identity = meter_identity(body.meter_id(), body.meter_version());
    let meter_parts = source_parts_for_identity(
        overlay,
        PocoSnapshotEntryKindV0::MeterDefinition,
        &meter_semantic_identity,
    )
    .map_err(|_| authenticated_overlay())?;
    match meter_parts.fact {
        SemanticFactV0::MeterDefinition {
            unit_scale,
            active_from,
            retired_at,
        } => {
            let authority_scale = meter_policy
                .unit_scale
                .get()
                .map_err(|_| authenticated_overlay())?;
            if unit_scale != authority_scale
                || active_from != meter_policy.active_from_height
                || retired_at != meter_policy.retired_at_height
            {
                return Err(authenticated_overlay());
            }
        }
        _ => return Err(authenticated_overlay()),
    }
    let meter_cap = meter_policy
        .per_certificate_cap
        .get()
        .map_err(|_| authenticated_overlay())?;
    if body.consumed_units() > meter_cap
        || body.consumed_units() > context.active_parameters.per_certificate_unit_cap()
    {
        return Err(protocol_reject());
    }
    body.consumed_units()
        .checked_mul(
            meter_policy
                .unit_scale
                .get()
                .map_err(|_| authenticated_overlay())?,
        )
        .ok_or_else(protocol_reject)?;

    let settlement_change = change_for_kind(&changes, PocoSnapshotEntryKindV0::Settlement)?;
    if settlement_change.expected_identity.as_deref() != Some(certificate_id.as_slice()) {
        return Err(authenticated_overlay());
    }
    if settlement_change.next_identity.as_deref() != Some(certificate_id.as_slice()) {
        return Err(signed_semantic());
    }
    let (old_commitment, old_height) = match settlement_change.expected_fact.as_ref() {
        Some(SemanticFactV0::Settlement {
            commitment,
            state: SettlementStateV0::FinalizedFundedUnused,
            finalized_height,
        }) => (commitment, finalized_height),
        _ => return Err(authenticated_overlay()),
    };
    if hex::encode(old_commitment) != reservation.settlement_commitment_hex
        || *old_height != reservation.finalized_height
    {
        return Err(authenticated_overlay());
    }
    if *old_height > context.target_height.get() {
        return Err(protocol_reject());
    }
    match settlement_change.next_fact.as_ref() {
        Some(SemanticFactV0::Settlement {
            commitment: new_commitment,
            state: SettlementStateV0::Consumed,
            finalized_height: new_height,
        }) if old_commitment == new_commitment
            && *new_commitment == *body.settlement_commitment()
            && new_height == old_height => {}
        _ => return Err(signed_semantic()),
    }

    let measurement_change =
        change_for_kind(&changes, PocoSnapshotEntryKindV0::MeasurementEvidence)?;
    if measurement_change.expected_value.is_some()
        || measurement_change.next_identity.as_deref() != Some(certificate_id.as_slice())
    {
        return Err(signed_semantic());
    }
    validate_measurement_policy(
        meter_policy.evidence_policy,
        body.measurement_evidence_root().copied(),
        measurement_change.next_fact.as_ref(),
    )
    .map_err(|_| signed_semantic())?;

    let relationship_identity = joined_identity(&[provider, consumer, body.task_id()]);
    let relationship_parts = source_parts_for_identity(
        overlay,
        PocoSnapshotEntryKindV0::RelationshipClassification,
        &relationship_identity,
    )?;
    let (relationship_class, relationship_expires_at) = match relationship_parts.fact {
        SemanticFactV0::RelationshipClassification { class, expires_at } => {
            if class == RelationshipClassV0::Unresolved || context.target_height.get() >= expires_at
            {
                return Err(protocol_reject());
            }
            (class, expires_at)
        }
        _ => return Err(authenticated_overlay()),
    };
    if body.billing_end_height().get() >= relationship_expires_at {
        return Err(protocol_reject());
    }

    let registration_parts = source_parts_for_identity(
        overlay,
        PocoSnapshotEntryKindV0::ValidatorRegistration,
        provider,
    )?;
    let (registered_key, registration_nonce, registration_proof_digest) =
        match registration_parts.fact {
            SemanticFactV0::ValidatorRegistration {
                consensus_key,
                registration_nonce,
                proof_digest,
                state: RegistrationStateV0::Active,
            } => (consensus_key, registration_nonce, proof_digest),
            _ => return Err(authenticated_overlay()),
        };
    let history_index = overlay
        .authority
        .validator_registration_history
        .binary_search_by(|item| item.validator_id_hex.as_str().cmp(&provider_id_hex))
        .map_err(|_| authenticated_overlay())?;
    let registration_history = &overlay.authority.validator_registration_history[history_index];
    let authority_consensus_key = exact_hash32_hex(&registration_history.consensus_key_hex)
        .map_err(|_| authenticated_overlay())?;
    let authority_proof_digest = exact_hash32_hex(&registration_history.current_proof_digest_hex)
        .map_err(|_| authenticated_overlay())?;
    if authority_consensus_key != registered_key
        || registration_history.max_registration_nonce != registration_nonce
        || authority_proof_digest != registration_proof_digest
    {
        return Err(authenticated_overlay());
    }
    let provider_registration_provenance = (
        registration_history.current_proof_digest_hex.clone(),
        registration_history.registration_decision_id_hex.clone(),
        registration_history.registration_height,
        registration_history.history_head_hex.clone(),
    );

    let lifecycle_change =
        change_for_kind(&changes, PocoSnapshotEntryKindV0::RevocationOrChallenge)?;
    if lifecycle_change.expected_value.is_some()
        || lifecycle_change.next_identity.as_deref() != Some(certificate_id.as_slice())
    {
        return Err(signed_semantic());
    }
    match lifecycle_change.next_fact.as_ref() {
        Some(SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::Accepted,
            effective_height,
        }) if *effective_height == context.target_height.get() => {}
        _ => return Err(signed_semantic()),
    }

    let usage_window = context
        .active_epoch
        .get()
        .checked_div(meter_policy.rolling_epoch_span)
        .ok_or_else(authenticated_overlay)?;
    let usage_key = (&meter_id_hex, body.meter_version(), usage_window);
    let usage_index = overlay.authority.meter_usage.binary_search_by(|item| {
        (&item.meter_id_hex, item.meter_version, item.window_epoch).cmp(&usage_key)
    });
    let previous_usage = match usage_index {
        Ok(index) => overlay.authority.meter_usage[index]
            .consumed_units
            .get()
            .map_err(|_| authenticated_overlay())?,
        Err(_) => 0,
    };
    let next_usage = checked_usage_after_v0(
        previous_usage,
        body.consumed_units(),
        meter_policy
            .rolling_cap
            .get()
            .map_err(|_| authenticated_overlay())?,
        "meter rolling",
    )?;

    // Active-parameter caps are global across meter definitions.  Their
    // canonical authority records intentionally omit meter identity, so
    // splitting one workload across several meters cannot reset a cap.
    let parameter_window = context.active_epoch.get();
    let consumer_provider_key = (&consumer_id_hex, &provider_id_hex, parameter_window);
    let consumer_provider_index =
        overlay
            .authority
            .consumer_provider_usage
            .binary_search_by(|item| {
                (
                    &item.consumer_id_hex,
                    &item.provider_id_hex,
                    item.window_epoch,
                )
                    .cmp(&consumer_provider_key)
            });
    let consumer_provider_previous = match consumer_provider_index {
        Ok(index) => overlay.authority.consumer_provider_usage[index]
            .consumed_units
            .get()
            .map_err(|_| authenticated_overlay())?,
        Err(_) => 0,
    };
    let consumer_provider_next = checked_usage_after_v0(
        consumer_provider_previous,
        body.consumed_units(),
        context
            .active_parameters
            .per_consumer_provider_epoch_unit_cap(),
        "consumer-provider epoch",
    )?;

    let task_provider_key = (&task_id_hex, &provider_id_hex, parameter_window);
    let task_provider_index = overlay
        .authority
        .task_provider_usage
        .binary_search_by(|item| {
            (&item.task_id_hex, &item.provider_id_hex, item.window_epoch).cmp(&task_provider_key)
        });
    let task_provider_previous = match task_provider_index {
        Ok(index) => overlay.authority.task_provider_usage[index]
            .consumed_units
            .get()
            .map_err(|_| authenticated_overlay())?,
        Err(_) => 0,
    };
    let task_provider_next = checked_usage_after_v0(
        task_provider_previous,
        body.consumed_units(),
        context.active_parameters.per_task_provider_epoch_unit_cap(),
        "task-provider epoch",
    )?;

    let provider_key = (&provider_id_hex, parameter_window);
    let provider_index = overlay
        .authority
        .provider_usage
        .binary_search_by(|item| (&item.provider_id_hex, item.window_epoch).cmp(&provider_key));
    let provider_previous = match provider_index {
        Ok(index) => overlay.authority.provider_usage[index]
            .consumed_units
            .get()
            .map_err(|_| authenticated_overlay())?,
        Err(_) => 0,
    };
    let provider_next = checked_usage_after_v0(
        provider_previous,
        body.consumed_units(),
        context.active_parameters.per_provider_epoch_unit_cap(),
        "provider epoch",
    )?;

    let new_usage_buckets = [
        usage_index.is_err(),
        consumer_provider_index.is_err(),
        task_provider_index.is_err(),
        provider_index.is_err(),
    ]
    .into_iter()
    .filter(|missing| *missing)
    .count();
    validate_usage_bucket_admission_v0(
        usage_bucket_count_v0(&overlay.authority)?,
        new_usage_buckets,
    )?;

    verify_nullifier_absences(
        overlay,
        &operation.nullifier_non_membership_checks,
        &[
            (PocoNullifierFamilyV0::Certificate, certificate_id),
            (PocoNullifierFamilyV0::Tuple, tuple_key),
        ],
    )?;
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[
            (
                PocoNullifierFamilyV0::SettlementDecision,
                acceptance_decision,
            ),
            (PocoNullifierFamilyV0::MeterDecision, meter_decision),
            (PocoNullifierFamilyV0::EvidenceDecision, evidence_decision),
        ],
    )?;
    match usage_index {
        Ok(index) => {
            overlay.authority.meter_usage[index].consumed_units = CanonicalU128V0::new(next_usage)
        }
        Err(index) => overlay.authority.meter_usage.insert(
            index,
            MeterRollingUsageV0 {
                meter_id_hex: meter_id_hex.clone(),
                meter_version: body.meter_version(),
                window_epoch: usage_window,
                consumed_units: CanonicalU128V0::new(next_usage),
            },
        ),
    }
    match consumer_provider_index {
        Ok(index) => {
            overlay.authority.consumer_provider_usage[index].consumed_units =
                CanonicalU128V0::new(consumer_provider_next)
        }
        Err(index) => overlay.authority.consumer_provider_usage.insert(
            index,
            ConsumerProviderRollingUsageV0 {
                consumer_id_hex: consumer_id_hex.clone(),
                provider_id_hex: provider_id_hex.clone(),
                window_epoch: parameter_window,
                consumed_units: CanonicalU128V0::new(consumer_provider_next),
            },
        ),
    }
    match task_provider_index {
        Ok(index) => {
            overlay.authority.task_provider_usage[index].consumed_units =
                CanonicalU128V0::new(task_provider_next)
        }
        Err(index) => overlay.authority.task_provider_usage.insert(
            index,
            TaskProviderRollingUsageV0 {
                task_id_hex: task_id_hex.clone(),
                provider_id_hex: provider_id_hex.clone(),
                window_epoch: parameter_window,
                consumed_units: CanonicalU128V0::new(task_provider_next),
            },
        ),
    }
    match provider_index {
        Ok(index) => {
            overlay.authority.provider_usage[index].consumed_units =
                CanonicalU128V0::new(provider_next)
        }
        Err(index) => overlay.authority.provider_usage.insert(
            index,
            ProviderRollingUsageV0 {
                provider_id_hex: provider_id_hex.clone(),
                window_epoch: parameter_window,
                consumed_units: CanonicalU128V0::new(provider_next),
            },
        ),
    }
    let next_watermark = ConsumerNonceWatermarkV0 {
        provider_id_hex: nonce_provider_hex,
        max_accepted_nonce: next_nonce,
        logical_key_hex: hex::encode(&nonce_change.logical_key),
    };
    match nonce_watermark_search {
        Ok(index) => {
            overlay.authority.consumer_keys[key_authority_index].nonce_watermarks[index] =
                next_watermark
        }
        Err(index) => overlay.authority.consumer_keys[key_authority_index]
            .nonce_watermarks
            .insert(index, next_watermark),
    }
    overlay
        .authority
        .funded_unused_reservations
        .remove(reservation_index);
    let prunable_after_height = derive_safe_prune_boundary_v0(
        context.target_height.get(),
        &context.active_parameters,
        &meter_policy,
    )?;
    let mut semantic_keys = changes
        .iter()
        .filter(|change| {
            matches!(
                change.kind,
                PocoSnapshotEntryKindV0::ConsumptionCertificate
                    | PocoSnapshotEntryKindV0::UniqueConsumptionTuple
                    | PocoSnapshotEntryKindV0::Settlement
                    | PocoSnapshotEntryKindV0::MeasurementEvidence
                    | PocoSnapshotEntryKindV0::RevocationOrChallenge
            )
        })
        .map(|change| SemanticKeyRefV0 {
            kind: change.kind as u8,
            logical_key_hex: hex::encode(&change.logical_key),
        })
        .collect::<Vec<_>>();
    semantic_keys.sort();
    overlay
        .authority
        .active_certificates
        .push(ActiveCertificateAuthorityV0 {
            certificate_id_hex: certificate_id_hex.to_string(),
            consumer_id_hex,
            consumer_key_id_hex: consumer_key_hex,
            provider_id_hex,
            task_id_hex,
            meter_id_hex,
            meter_version: body.meter_version(),
            settlement_commitment_hex: reservation.settlement_commitment_hex.clone(),
            settlement_finalized_height: reservation.finalized_height,
            consumed_units: CanonicalU128V0::new(body.consumed_units()),
            evidence_root_hex: body
                .measurement_evidence_root()
                .map(|root| hex::encode(root.as_slice())),
            relationship_class: relationship_class as u8,
            relationship_key_hex: hex::encode(semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::RelationshipClassification,
                &relationship_identity,
            )),
            provider_consensus_key_hex: hex::encode(registered_key),
            provider_registration_nonce: registration_nonce,
            provider_proof_digest_hex: provider_registration_provenance.0,
            provider_registration_decision_id_hex: provider_registration_provenance.1,
            provider_registration_height: provider_registration_provenance.2,
            provider_registration_history_head_hex: provider_registration_provenance.3,
            acceptance_decision_id_hex: acceptance_decision_id_hex.to_string(),
            funding_decision_id_hex: funding_decision_id_hex.to_string(),
            meter_decision_id_hex: meter_decision_id_hex.to_string(),
            evidence_decision_id_hex: evidence_decision_id_hex.to_string(),
            accepted_height: context.target_height.get(),
            finalized_epoch: context.active_epoch.get(),
            tuple_key_hex: hex::encode(tuple_key),
            prunable_after_height,
            lifecycle: CertificateAuthorityLifecycleV0::Accepted,
            lifecycle_effective_height: context.target_height.get(),
            lifecycle_decision_id_hex: acceptance_decision_id_hex.to_string(),
            semantic_keys,
        });
    overlay
        .authority
        .active_certificates
        .sort_by(|left, right| left.certificate_id_hex.cmp(&right.certificate_id_hex));
    apply_prepared_changes(overlay, changes, false)
}

fn prepare_release_settlement_v0(
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    certificate_id_hex: &str,
    release_decision_id_hex: &str,
    reservation_index: usize,
) -> Result<PreparedReleaseSettlementV0> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    validate_operation_field_admission_v0(operation)?;
    let certificate_id = exact_hash32_hex(certificate_id_hex).map_err(|_| signed_semantic())?;
    let release_decision =
        require_derived_decision_id(preimage, b"release-settlement", release_decision_id_hex)?;
    let expected_reservation = overlay
        .authority
        .funded_unused_reservations
        .get(reservation_index)
        .filter(|reservation| reservation.certificate_id_hex == certificate_id_hex)
        .cloned()
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::DerivedMutationPostcondition)
        })?;
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, true)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::Settlement])
        .map_err(|_| signed_semantic())?;
    let change = &changes[0];
    if change.next_value.is_some() {
        return Err(signed_semantic());
    }
    if change.expected_identity.as_deref() != Some(certificate_id.as_slice()) {
        return Err(authenticated_overlay());
    }
    match change.expected_fact.as_ref() {
        Some(SemanticFactV0::Settlement {
            commitment,
            state: SettlementStateV0::FinalizedFundedUnused,
            finalized_height,
        }) if hex::encode(commitment) == expected_reservation.settlement_commitment_hex
            && *finalized_height == expected_reservation.finalized_height => {}
        _ => return Err(authenticated_overlay()),
    }
    overlay.accumulator.count().checked_add(2).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    Ok(PreparedReleaseSettlementV0 {
        reservation_index,
        expected_reservation,
        expected_insertions: release_nullifier_subjects_v0(certificate_id, release_decision),
        changes,
    })
}

fn apply_prepared_release_settlement_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedReleaseSettlementV0,
) -> Result<()> {
    let body_matches = match &operation.body {
        PocoApplicationOperationBodyV0::ReleaseSettlement {
            certificate_id_hex,
            release_decision_id_hex,
        } => {
            certificate_id_hex == &prepared.expected_reservation.certificate_id_hex
                && exact_hash32_hex(release_decision_id_hex).ok()
                    == Some(prepared.expected_insertions[1].1)
        }
        _ => false,
    };
    let reservation_matches = overlay
        .authority
        .funded_unused_reservations
        .get(prepared.reservation_index)
        == Some(&prepared.expected_reservation);
    if !body_matches || !reservation_matches {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_insertions,
    )?;
    overlay
        .authority
        .funded_unused_reservations
        .remove(prepared.reservation_index);
    // Funding and release decision nullifiers remain in kind 16 permanently;
    // deleting the rich leaf in this same transition cannot reopen replay.
    apply_prepared_changes(overlay, prepared.changes, true)
}

#[allow(clippy::too_many_arguments)]
fn prepare_open_challenge_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    certificate_id_hex: &str,
    challenge_id_hex: &str,
    opening_decision_id_hex: &str,
) -> Result<PreparedOpenChallengeV0> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let protocol_reject = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    let certificate_id = exact_hash32_hex(certificate_id_hex).map_err(|_| signed_semantic())?;
    require_derived_decision_id(preimage, b"challenge-id", challenge_id_hex)?;
    let decision =
        require_derived_decision_id(preimage, b"open-challenge", opening_decision_id_hex)?;
    let [raw_change] = operation.semantic_changes.as_slice() else {
        return Err(signed_semantic());
    };
    if raw_change.kind != PocoSnapshotEntryKindV0::RevocationOrChallenge as u8 {
        return Err(signed_semantic());
    }
    let signed_logical_key =
        exact_hash32_hex(&raw_change.logical_key_hex).map_err(|_| signed_semantic())?;
    let expected_logical_key = semantic_identity_digest_v0(
        PocoSnapshotEntryKindV0::RevocationOrChallenge,
        &certificate_id,
    );
    if signed_logical_key != expected_logical_key {
        return Err(signed_semantic());
    }
    let certificate_index = overlay
        .authority
        .active_certificates
        .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    let certificate = overlay.authority.active_certificates[certificate_index].clone();
    let predecessor = authenticated_certificate_lifecycle_companion_v0(overlay, &certificate)?;
    for pending in overlay
        .authority
        .pending_challenges
        .iter()
        .filter(|pending| {
            pending.challenge_id_hex == challenge_id_hex
                && pending.certificate_id_hex != certificate_id_hex
        })
    {
        let pending_certificate = overlay
            .authority
            .active_certificates
            .binary_search_by(|certificate| {
                certificate
                    .certificate_id_hex
                    .as_str()
                    .cmp(pending.certificate_id_hex.as_str())
            })
            .map(|index| &overlay.authority.active_certificates[index])
            .map_err(|_| authenticated_overlay())?;
        authenticated_certificate_lifecycle_companion_v0(overlay, pending_certificate)?;
    }
    if certificate.lifecycle != CertificateAuthorityLifecycleV0::Accepted {
        return Err(protocol_reject());
    }
    if overlay.authority.pending_challenges.iter().any(|item| {
        item.challenge_id_hex == challenge_id_hex || item.certificate_id_hex == certificate_id_hex
    }) {
        return Err(protocol_reject());
    }
    if !matches!(
        predecessor.fact,
        SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::Accepted,
            effective_height,
        } if effective_height == certificate.lifecycle_effective_height
    ) {
        return Err(authenticated_overlay());
    }
    if context.target_height.get() <= certificate.lifecycle_effective_height
        || context.target_height.get() > certificate.prunable_after_height
    {
        return Err(protocol_reject());
    }
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, false).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )
        })?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::RevocationOrChallenge])?;
    let change = &changes[0];
    if change.expected_identity.as_deref() != Some(certificate_id.as_slice()) {
        return Err(authenticated_overlay());
    }
    if change.next_identity.as_deref() != Some(certificate_id.as_slice()) {
        return Err(signed_semantic());
    }
    if !matches!(
        change.expected_fact.as_ref(),
        Some(SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::Accepted,
            effective_height,
        }) if *effective_height == certificate.lifecycle_effective_height
    ) {
        return Err(authenticated_overlay());
    }
    match change.next_fact.as_ref() {
        Some(SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::ChallengePending,
            effective_height,
        }) if *effective_height == context.target_height.get() => {}
        _ => return Err(signed_semantic()),
    }
    overlay.accumulator.count().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    Ok(PreparedOpenChallengeV0 {
        pending: PendingChallengeAuthorityV0 {
            challenge_id_hex: challenge_id_hex.to_string(),
            certificate_id_hex: certificate_id_hex.to_string(),
            opening_decision_id_hex: opening_decision_id_hex.to_string(),
            opened_height: context.target_height.get(),
        },
        expected_nullifiers: [(PocoNullifierFamilyV0::ChallengeDecision, decision)],
        changes,
    })
}

fn apply_prepared_open_challenge_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedOpenChallengeV0,
) -> Result<()> {
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_nullifiers,
    )?;
    overlay.authority.pending_challenges.push(prepared.pending);
    overlay
        .authority
        .pending_challenges
        .sort_by(|left, right| left.challenge_id_hex.cmp(&right.challenge_id_hex));
    apply_prepared_changes(overlay, prepared.changes, false)
}

#[allow(clippy::too_many_arguments)]
fn prepare_resolve_challenge_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    certificate_id_hex: &str,
    challenge_id_hex: &str,
    resolution: ChallengeResolutionV0,
    resolution_decision_id_hex: &str,
    pending_index: usize,
    certificate_index: usize,
) -> Result<PreparedResolveChallengeV0> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    validate_operation_field_admission_v0(operation)?;
    let certificate_id = exact_hash32_hex(certificate_id_hex).map_err(|_| signed_semantic())?;
    exact_hash32_hex(challenge_id_hex).map_err(|_| signed_semantic())?;
    let decision =
        require_derived_decision_id(preimage, b"resolve-challenge", resolution_decision_id_hex)?;
    let expected_pending = overlay
        .authority
        .pending_challenges
        .get(pending_index)
        .filter(|pending| {
            pending.challenge_id_hex == challenge_id_hex
                && pending.certificate_id_hex == certificate_id_hex
        })
        .cloned()
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::DerivedMutationPostcondition)
        })?;
    let expected_certificate = overlay
        .authority
        .active_certificates
        .get(certificate_index)
        .filter(|certificate| {
            certificate.certificate_id_hex == certificate_id_hex
                && certificate.lifecycle == CertificateAuthorityLifecycleV0::Accepted
        })
        .cloned()
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::DerivedMutationPostcondition)
        })?;
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, false).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )
        })?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::RevocationOrChallenge])
        .map_err(|_| signed_semantic())?;
    let change = &changes[0];
    if change.expected_identity.as_deref() != Some(certificate_id.as_slice()) {
        return Err(authenticated_overlay());
    }
    if change.next_identity.as_deref() != Some(certificate_id.as_slice()) {
        return Err(signed_semantic());
    }
    let expected_state = match resolution {
        ChallengeResolutionV0::Rejected => LifecycleStateV0::ChallengeRejected,
        ChallengeResolutionV0::Sustained => LifecycleStateV0::ChallengeSustained,
    };
    let pending_height = match change.expected_fact.as_ref() {
        Some(SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::ChallengePending,
            effective_height,
        }) => *effective_height,
        _ => return Err(authenticated_overlay()),
    };
    if pending_height != expected_pending.opened_height {
        return Err(authenticated_overlay());
    }
    if context.target_height.get() <= expected_pending.opened_height {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    match change.next_fact.as_ref() {
        Some(SemanticFactV0::RevocationOrChallenge {
            state,
            effective_height,
        }) if *state == expected_state && *effective_height == context.target_height.get() => {}
        _ => return Err(signed_semantic()),
    }
    overlay.accumulator.count().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    Ok(PreparedResolveChallengeV0 {
        pending_index,
        expected_pending,
        certificate_index,
        expected_certificate,
        target_lifecycle: match resolution {
            ChallengeResolutionV0::Rejected => CertificateAuthorityLifecycleV0::ChallengeRejected,
            ChallengeResolutionV0::Sustained => CertificateAuthorityLifecycleV0::ChallengeSustained,
        },
        target_height: context.target_height.get(),
        resolution_decision_id_hex: resolution_decision_id_hex.to_string(),
        expected_nullifiers: [(PocoNullifierFamilyV0::ChallengeDecision, decision)],
        changes,
    })
}

fn apply_prepared_resolve_challenge_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedResolveChallengeV0,
) -> Result<()> {
    let body_matches = match &operation.body {
        PocoApplicationOperationBodyV0::ResolveChallenge {
            certificate_id_hex,
            challenge_id_hex,
            resolution,
            resolution_decision_id_hex,
        } => {
            let target_lifecycle = match resolution {
                ChallengeResolutionV0::Rejected => {
                    CertificateAuthorityLifecycleV0::ChallengeRejected
                }
                ChallengeResolutionV0::Sustained => {
                    CertificateAuthorityLifecycleV0::ChallengeSustained
                }
            };
            certificate_id_hex == &prepared.expected_pending.certificate_id_hex
                && challenge_id_hex == &prepared.expected_pending.challenge_id_hex
                && target_lifecycle == prepared.target_lifecycle
                && resolution_decision_id_hex == &prepared.resolution_decision_id_hex
        }
        _ => false,
    };
    let pending_matches = overlay
        .authority
        .pending_challenges
        .get(prepared.pending_index)
        == Some(&prepared.expected_pending);
    let certificate_matches = overlay
        .authority
        .active_certificates
        .get(prepared.certificate_index)
        == Some(&prepared.expected_certificate);
    if !body_matches || !pending_matches || !certificate_matches {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_nullifiers,
    )?;
    overlay
        .authority
        .pending_challenges
        .remove(prepared.pending_index);
    let certificate = &mut overlay.authority.active_certificates[prepared.certificate_index];
    certificate.lifecycle = prepared.target_lifecycle;
    certificate.lifecycle_effective_height = prepared.target_height;
    certificate.lifecycle_decision_id_hex = prepared.resolution_decision_id_hex;
    apply_prepared_changes(overlay, prepared.changes, false)
}

#[allow(clippy::too_many_arguments)]
fn prepare_propose_governance_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    target_epoch: u64,
    phase: u8,
    parameters_hash_hex: &str,
    activation_height: u64,
    proposal_decision_id_hex: &str,
) -> Result<PreparedProposeGovernanceV0> {
    validate_operation_field_admission_v0(operation)?;
    let expected_epoch = context.active_epoch.get().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    if target_epoch != expected_epoch {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::GovernanceRule,
        ));
    }
    let phase = crate::poco_semantics::RolloutPhaseV0::try_from(phase).map_err(|_| {
        deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::GovernanceRule)
    })?;
    let current_geometry = EpochGeometryV0::new(context.active_epoch, &context.active_parameters)
        .map_err(|_| {
        invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay)
    })?;
    let expected_activation = current_geometry
        .epoch_end()
        .get()
        .checked_add(1)
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::PlannerArithmetic)
        })?;
    if activation_height != expected_activation {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::GovernanceRule,
        ));
    }
    let parameters_hash = exact_hash32_hex(parameters_hash_hex).map_err(|_| {
        deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::GovernanceRule)
    })?;
    let decision =
        require_derived_decision_id(preimage, b"propose-governance", proposal_decision_id_hex)?;
    let pending_insertion = match overlay
        .authority
        .pending_governance_proposals
        .binary_search_by_key(&target_epoch, |proposal| proposal.target_epoch)
    {
        Err(insertion) => insertion,
        Ok(_) => bail!("governance target already has proposal authority"),
    };
    let finalized_insertion = match overlay
        .authority
        .finalized_governance_approvals
        .binary_search_by_key(&target_epoch, |approval| approval.target_epoch)
    {
        Err(insertion) => insertion,
        Ok(_) => bail!("governance target already has approval authority"),
    };
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(
        &changes,
        &[
            PocoSnapshotEntryKindV0::ConsensusParameters,
            PocoSnapshotEntryKindV0::RolloutOrGovernance,
        ],
    )?;
    let parameters_change =
        change_for_kind(&changes, PocoSnapshotEntryKindV0::ConsensusParameters)?;
    let mut expected_parameters_identity = vec![2];
    expected_parameters_identity.extend_from_slice(&target_epoch.to_be_bytes());
    ensure!(
        parameters_change.expected_value.is_none()
            && parameters_change.next_identity.as_deref()
                == Some(expected_parameters_identity.as_slice()),
        "governance proposal next-parameters identity is not role=2/target epoch"
    );
    let next_parameters = decode_consensus_parameters_v0_exact(
        parameters_change
            .next_payload
            .as_deref()
            .context("governance proposal lacks exact next parameters")?,
    )
    .map_err(|error| anyhow::anyhow!("decode governance next parameters: {error:?}"))?;
    ensure!(
        next_parameters.hash().as_bytes() == &parameters_hash,
        "governance proposal parameters hash/preimage mismatch"
    );
    let next_geometry = EpochGeometryV0::new(Epoch::new(target_epoch), &next_parameters)
        .map_err(|error| anyhow::anyhow!("invalid governance target geometry: {error:?}"))?;
    ensure!(
        next_geometry.epoch_start().get() == activation_height,
        "next parameters do not preserve the approved activation boundary"
    );
    let governance_change =
        change_for_kind(&changes, PocoSnapshotEntryKindV0::RolloutOrGovernance)?;
    ensure!(
        governance_change.expected_value.is_none()
            && governance_change.next_identity.as_deref()
                == Some(target_epoch.to_be_bytes().as_slice()),
        "governance proposal semantic identity is not an exact create"
    );
    match governance_change.next_fact.as_ref() {
        Some(SemanticFactV0::RolloutOrGovernance {
            target_epoch: semantic_epoch,
            phase: semantic_phase,
            parameters_hash: semantic_hash,
            activation_height: semantic_activation,
            approval: GovernanceApprovalV0::Pending,
        }) => ensure!(
            *semantic_epoch == target_epoch
                && *semantic_phase == phase
                && *semantic_hash == parameters_hash
                && *semantic_activation == activation_height,
            "governance proposal differs from exact semantic facts"
        ),
        _ => bail!("governance proposal lacks pending semantic fact"),
    }
    overlay.accumulator.count().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    Ok(PreparedProposeGovernanceV0 {
        proposal: PendingGovernanceProposalV0 {
            target_epoch,
            proposal_decision_id_hex: proposal_decision_id_hex.to_string(),
            proposed_height: context.target_height.get(),
            phase: phase as u8,
            parameters_hash_hex: parameters_hash_hex.to_string(),
            activation_height,
        },
        pending_insertion,
        finalized_insertion,
        expected_nullifiers: [(PocoNullifierFamilyV0::GovernanceDecision, decision)],
        changes,
    })
}

fn apply_prepared_propose_governance_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedProposeGovernanceV0,
) -> Result<()> {
    let body_matches = match &operation.body {
        PocoApplicationOperationBodyV0::ProposeGovernance {
            target_epoch,
            phase,
            parameters_hash_hex,
            activation_height,
            proposal_decision_id_hex,
        } => {
            *target_epoch == prepared.proposal.target_epoch
                && *phase == prepared.proposal.phase
                && parameters_hash_hex == &prepared.proposal.parameters_hash_hex
                && *activation_height == prepared.proposal.activation_height
                && proposal_decision_id_hex == &prepared.proposal.proposal_decision_id_hex
        }
        _ => false,
    };
    let pending_matches = overlay
        .authority
        .pending_governance_proposals
        .binary_search_by_key(&prepared.proposal.target_epoch, |proposal| {
            proposal.target_epoch
        })
        == Err(prepared.pending_insertion);
    let finalized_matches = overlay
        .authority
        .finalized_governance_approvals
        .binary_search_by_key(&prepared.proposal.target_epoch, |approval| {
            approval.target_epoch
        })
        == Err(prepared.finalized_insertion);
    if !body_matches || !pending_matches || !finalized_matches {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_nullifiers,
    )?;
    overlay
        .authority
        .pending_governance_proposals
        .insert(prepared.pending_insertion, prepared.proposal);
    apply_prepared_changes(overlay, prepared.changes, false)
}

#[allow(clippy::too_many_arguments)]
fn prepare_approve_governance_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    target_epoch: u64,
    parameters_hash_hex: &str,
    activation_height: u64,
    decision_id_hex: &str,
    proposal_index: usize,
    finalized_insertion: usize,
) -> Result<PreparedApproveGovernanceV0> {
    let governance_reject = || {
        deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::GovernanceRule)
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    validate_operation_field_admission_v0(operation)?;
    let parameters_hash = exact_hash32_hex(parameters_hash_hex).map_err(|_| governance_reject())?;
    let expected_epoch = context.active_epoch.get().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    if target_epoch != expected_epoch {
        return Err(governance_reject());
    }
    let expected_proposal = overlay
        .authority
        .pending_governance_proposals
        .get(proposal_index)
        .filter(|proposal| proposal.target_epoch == target_epoch)
        .cloned()
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::DerivedMutationPostcondition)
        })?;
    if expected_proposal.parameters_hash_hex != parameters_hash_hex
        || expected_proposal.activation_height != activation_height
    {
        return Err(governance_reject());
    }
    if expected_proposal.proposed_height >= context.target_height.get() {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    let mut parameters_identity = vec![2];
    parameters_identity.extend_from_slice(&target_epoch.to_be_bytes());
    let parameters_logical_key = semantic_identity_digest_v0(
        PocoSnapshotEntryKindV0::ConsensusParameters,
        &parameters_identity,
    )
    .to_vec();
    let expected_parameters_value = overlay
        .entries
        .get(&(
            PocoSnapshotEntryKindV0::ConsensusParameters,
            parameters_logical_key.clone(),
        ))
        .cloned()
        .ok_or_else(authenticated_overlay)?;
    let parameters_parts = source_parts_for_identity(
        overlay,
        PocoSnapshotEntryKindV0::ConsensusParameters,
        &parameters_identity,
    )
    .map_err(|_| authenticated_overlay())?;
    let next_parameters = decode_consensus_parameters_v0_exact(&parameters_parts.payload)
        .map_err(|_| authenticated_overlay())?;
    if next_parameters.hash().as_bytes() != &parameters_hash {
        return Err(authenticated_overlay());
    }
    let decision = require_derived_decision_id(preimage, b"approve-governance", decision_id_hex)
        .map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::GovernanceRule,
            )
        })?;
    if overlay
        .authority
        .finalized_governance_approvals
        .binary_search_by_key(&target_epoch, |item| item.target_epoch)
        != Err(finalized_insertion)
    {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::RolloutOrGovernance])?;
    let change = &changes[0];
    if change.expected_identity.as_deref() != Some(target_epoch.to_be_bytes().as_slice()) {
        return Err(authenticated_overlay());
    }
    if change.next_identity.as_deref() != Some(target_epoch.to_be_bytes().as_slice()) {
        return Err(governance_reject());
    }
    let (old_epoch, old_phase, old_hash, old_activation) = match change.expected_fact.as_ref() {
        Some(SemanticFactV0::RolloutOrGovernance {
            target_epoch,
            phase,
            parameters_hash,
            activation_height,
            approval: GovernanceApprovalV0::Pending,
        }) => (*target_epoch, *phase, *parameters_hash, *activation_height),
        _ => return Err(authenticated_overlay()),
    };
    if old_epoch != target_epoch
        || old_phase as u8 != expected_proposal.phase
        || old_hash != parameters_hash
        || old_activation != activation_height
    {
        return Err(authenticated_overlay());
    }
    match change.next_fact.as_ref() {
        Some(SemanticFactV0::RolloutOrGovernance {
            target_epoch: new_epoch,
            phase: new_phase,
            parameters_hash: new_hash,
            activation_height: new_activation,
            approval: GovernanceApprovalV0::Approved,
        }) if *new_epoch == old_epoch
            && *new_phase == old_phase
            && *new_hash == old_hash
            && *new_activation == old_activation => {}
        _ => return Err(governance_reject()),
    }
    overlay.accumulator.count().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    Ok(PreparedApproveGovernanceV0 {
        proposal_index,
        approval: FinalizedGovernanceApprovalV0 {
            target_epoch,
            phase: expected_proposal.phase,
            proposal_decision_id_hex: expected_proposal.proposal_decision_id_hex.clone(),
            proposed_height: expected_proposal.proposed_height,
            decision_id_hex: decision_id_hex.to_string(),
            approval_height: context.target_height.get(),
            parameters_hash_hex: parameters_hash_hex.to_string(),
            activation_height,
        },
        expected_proposal,
        finalized_insertion,
        parameters_logical_key,
        expected_parameters_value,
        expected_nullifiers: [(PocoNullifierFamilyV0::GovernanceDecision, decision)],
        changes,
    })
}

fn apply_prepared_approve_governance_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedApproveGovernanceV0,
) -> Result<()> {
    let body_matches = match &operation.body {
        PocoApplicationOperationBodyV0::ApproveGovernance {
            target_epoch,
            parameters_hash_hex,
            activation_height,
            decision_id_hex,
        } => {
            *target_epoch == prepared.approval.target_epoch
                && parameters_hash_hex == &prepared.approval.parameters_hash_hex
                && *activation_height == prepared.approval.activation_height
                && decision_id_hex == &prepared.approval.decision_id_hex
        }
        _ => false,
    };
    let proposal_matches = overlay
        .authority
        .pending_governance_proposals
        .get(prepared.proposal_index)
        == Some(&prepared.expected_proposal);
    let finalized_matches = overlay
        .authority
        .finalized_governance_approvals
        .binary_search_by_key(&prepared.approval.target_epoch, |approval| {
            approval.target_epoch
        })
        == Err(prepared.finalized_insertion);
    let parameters_key = (
        PocoSnapshotEntryKindV0::ConsensusParameters,
        prepared.parameters_logical_key.clone(),
    );
    let parameters_match = overlay.entries.get(&parameters_key)
        == Some(&prepared.expected_parameters_value)
        && !overlay.mutations.contains_key(&parameters_key);
    let change_sources_match = prepared.changes.iter().all(|change| {
        let key = (change.kind, change.logical_key.clone());
        overlay.entries.get(&key) == change.expected_value.as_ref()
            && !overlay.mutations.contains_key(&key)
    });
    if !body_matches
        || !proposal_matches
        || !finalized_matches
        || !parameters_match
        || !change_sources_match
    {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_nullifiers,
    )?;
    overlay
        .authority
        .finalized_governance_approvals
        .insert(prepared.finalized_insertion, prepared.approval);
    overlay
        .authority
        .pending_governance_proposals
        .remove(prepared.proposal_index);
    apply_prepared_changes(overlay, prepared.changes, false)
}

#[allow(clippy::too_many_arguments)]
fn prepare_register_validator_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    validator_id_hex: &str,
    target_epoch: u64,
    registration_decision_id_hex: &str,
    insertion: usize,
) -> Result<PreparedRegisterValidatorV0> {
    let validator_rule =
        || deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::ValidatorRule);
    validate_operation_field_admission_v0(operation)?;
    overlay.accumulator.count().checked_add(2).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    let validator_id_bytes = exact_opaque_hex(validator_id_hex).map_err(|_| validator_rule())?;
    if target_epoch != context.active_epoch.get() {
        return Err(validator_rule());
    }
    let decision = require_derived_decision_id(
        preimage,
        b"register-validator",
        registration_decision_id_hex,
    )?;
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, false).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::ValidatorRule,
            )
        })?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::ValidatorRegistration])
        .map_err(|_| validator_rule())?;
    let change = &changes[0];
    if change.next_identity.as_deref() != Some(validator_id_bytes.as_slice()) {
        return Err(validator_rule());
    }
    let next_fact = match change.next_fact.as_ref() {
        Some(SemanticFactV0::ValidatorRegistration {
            consensus_key,
            registration_nonce,
            proof_digest,
            state: RegistrationStateV0::Active,
        }) => (*consensus_key, *registration_nonce, *proof_digest),
        _ => return Err(validator_rule()),
    };
    let next_consensus_key_hex = hex::encode(next_fact.0);
    if overlay
        .authority
        .validator_registration_history
        .iter()
        .any(|history| history.consensus_key_hex == next_consensus_key_hex)
    {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ValidatorConsensusKeyAlreadyActive,
        ));
    }
    let proof_bytes =
        registration_proof_bytes(change.next_payload.as_deref().ok_or_else(|| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::CryptographicProof,
            )
        })?)
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::CryptographicProof,
            )
        })?;
    let proof = decode_validator_key_proof_of_possession_v0_exact(proof_bytes).map_err(|_| {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::CryptographicProof,
        )
    })?;
    let validator_id =
        ValidatorId::from_bytes(&validator_id_bytes).map_err(|_| validator_rule())?;
    proof
        .verify_for_registration(
            context.genesis_hash,
            context.chain_id,
            Epoch::new(target_epoch),
            validator_id,
            ConsensusPublicKey::new(next_fact.0),
            &StrictEd25519Verifier,
        )
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::CryptographicProof,
            )
        })?;
    if proof.fields().registration_nonce != next_fact.1 {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::CryptographicProof,
        ));
    }
    match overlay
        .authority
        .validator_registration_history
        .binary_search_by(|item| item.validator_id_hex.as_str().cmp(validator_id_hex))
    {
        Ok(_) => return Err(validator_rule()),
        Err(actual_insertion) if actual_insertion != insertion => {
            return Err(invariant_application_error_v0(
                PocoApplicationInvariantV0::DerivedMutationPostcondition,
            ));
        }
        Err(_) => {}
    }
    if change.expected_value.is_some() {
        return Err(validator_rule());
    }
    let previous_head = [0; 32];
    let next_history_head = registration_history_head_v0(
        previous_head,
        &validator_id_bytes,
        next_fact.0,
        next_fact.1,
        next_fact.2,
        decision,
        context.target_height.get(),
    );
    Ok(PreparedRegisterValidatorV0 {
        history: ValidatorRegistrationHistoryV0 {
            validator_id_hex: validator_id_hex.to_string(),
            history_head_hex: hex::encode(next_history_head),
            max_registration_nonce: next_fact.1,
            consensus_key_hex: next_consensus_key_hex,
            current_proof_digest_hex: hex::encode(next_fact.2),
            previous_history_head_hex: hex::encode(previous_head),
            registration_decision_id_hex: registration_decision_id_hex.to_string(),
            registration_height: context.target_height.get(),
            retired_key_count: 0,
            revoked_at_height: None,
            revocation_decision_id_hex: None,
        },
        insertion,
        expected_absences: [(
            PocoNullifierFamilyV0::ValidatorIdentity,
            semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::ValidatorRegistration,
                &validator_id_bytes,
            ),
        )],
        expected_insertions: [
            (PocoNullifierFamilyV0::RegistrationDecision, decision),
            (PocoNullifierFamilyV0::ValidatorConsensusKey, next_fact.0),
        ],
        changes,
    })
}

fn apply_prepared_register_validator_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedRegisterValidatorV0,
) -> Result<()> {
    verify_nullifier_absences(
        overlay,
        &operation.nullifier_non_membership_checks,
        &prepared.expected_absences,
    )?;
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_insertions,
    )?;
    overlay
        .authority
        .validator_registration_history
        .insert(prepared.insertion, prepared.history);
    apply_prepared_changes(overlay, prepared.changes, false)
}

#[allow(clippy::too_many_arguments)]
fn prepare_rotate_validator_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    validator_id_hex: &str,
    target_epoch: u64,
    previous_history_head_hex: &str,
    previous_registration_nonce: u64,
    registration_decision_id_hex: &str,
) -> Result<PreparedRotateValidatorV0> {
    let validator_rule =
        || deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::ValidatorRule);
    let protocol_reject = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    validate_operation_field_admission_v0(operation)?;
    let validator_id_bytes = exact_opaque_hex(validator_id_hex).map_err(|_| validator_rule())?;
    ensure_validator_has_no_active_certificate_references_v0(&overlay.authority, validator_id_hex)
        .map_err(|_| protocol_reject())?;
    let index = overlay
        .authority
        .validator_registration_history
        .binary_search_by(|item| item.validator_id_hex.as_str().cmp(validator_id_hex))
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    let history = &overlay.authority.validator_registration_history[index];
    if history.revoked_at_height.is_some() {
        return Err(protocol_reject());
    }
    let retired_key_count = history.retired_key_count.checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    overlay.accumulator.count().checked_add(2).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    if target_epoch != context.active_epoch.get() {
        return Err(validator_rule());
    }
    let decision =
        require_derived_decision_id(preimage, b"rotate-validator", registration_decision_id_hex)?;
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, false).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::ValidatorRule,
            )
        })?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::ValidatorRegistration])
        .map_err(|_| validator_rule())?;
    let change = &changes[0];
    if change.next_identity.as_deref() != Some(validator_id_bytes.as_slice()) {
        return Err(validator_rule());
    }
    let next_fact = match change.next_fact.as_ref() {
        Some(SemanticFactV0::ValidatorRegistration {
            consensus_key,
            registration_nonce,
            proof_digest,
            state: RegistrationStateV0::Active,
        }) => (*consensus_key, *registration_nonce, *proof_digest),
        _ => return Err(validator_rule()),
    };
    let next_consensus_key_hex = hex::encode(next_fact.0);
    if overlay
        .authority
        .validator_registration_history
        .iter()
        .any(|history| history.consensus_key_hex == next_consensus_key_hex)
    {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ValidatorConsensusKeyAlreadyActive,
        ));
    }
    let proof_bytes =
        registration_proof_bytes(change.next_payload.as_deref().ok_or_else(|| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::CryptographicProof,
            )
        })?)
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::CryptographicProof,
            )
        })?;
    let proof = decode_validator_key_proof_of_possession_v0_exact(proof_bytes).map_err(|_| {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::CryptographicProof,
        )
    })?;
    let validator_id = ValidatorId::from_bytes(&validator_id_bytes).map_err(|_| {
        deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::ValidatorRule)
    })?;
    proof
        .verify_for_registration(
            context.genesis_hash,
            context.chain_id,
            Epoch::new(target_epoch),
            validator_id,
            ConsensusPublicKey::new(next_fact.0),
            &StrictEd25519Verifier,
        )
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::CryptographicProof,
            )
        })?;
    if proof.fields().registration_nonce != next_fact.1 {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::CryptographicProof,
        ));
    }
    if history.history_head_hex != previous_history_head_hex
        || history.max_registration_nonce != previous_registration_nonce
        || next_fact.1 <= history.max_registration_nonce
        || next_consensus_key_hex == history.consensus_key_hex
    {
        return Err(validator_rule());
    }
    match change.expected_fact.as_ref() {
        Some(SemanticFactV0::ValidatorRegistration {
            consensus_key,
            registration_nonce,
            proof_digest,
            state: RegistrationStateV0::Active,
        }) if hex::encode(consensus_key) == history.consensus_key_hex
            && *registration_nonce == history.max_registration_nonce
            && hex::encode(proof_digest) == history.current_proof_digest_hex => {}
        _ => return Err(authenticated_overlay()),
    }
    let previous_head =
        exact_hash32_hex(&history.history_head_hex).map_err(|_| authenticated_overlay())?;
    let next_history_head = registration_history_head_v0(
        previous_head,
        &validator_id_bytes,
        next_fact.0,
        next_fact.1,
        next_fact.2,
        decision,
        context.target_height.get(),
    );
    Ok(PreparedRotateValidatorV0 {
        history: ValidatorRegistrationHistoryV0 {
            validator_id_hex: validator_id_hex.to_string(),
            history_head_hex: hex::encode(next_history_head),
            max_registration_nonce: next_fact.1,
            consensus_key_hex: next_consensus_key_hex,
            current_proof_digest_hex: hex::encode(next_fact.2),
            previous_history_head_hex: hex::encode(previous_head),
            registration_decision_id_hex: registration_decision_id_hex.to_string(),
            registration_height: context.target_height.get(),
            retired_key_count,
            revoked_at_height: None,
            revocation_decision_id_hex: None,
        },
        index,
        expected_insertions: [
            (PocoNullifierFamilyV0::RegistrationDecision, decision),
            (PocoNullifierFamilyV0::ValidatorConsensusKey, next_fact.0),
        ],
        changes,
    })
}

fn apply_prepared_rotate_validator_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedRotateValidatorV0,
) -> Result<()> {
    let Some(current) = overlay
        .authority
        .validator_registration_history
        .get(prepared.index)
    else {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    };
    if current.validator_id_hex != prepared.history.validator_id_hex
        || current.history_head_hex != prepared.history.previous_history_head_hex
    {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::DerivedMutationPostcondition,
        ));
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_insertions,
    )?;
    overlay.authority.validator_registration_history[prepared.index] = prepared.history;
    apply_prepared_changes(overlay, prepared.changes, false)
}

#[allow(clippy::too_many_arguments)]
fn prepare_register_future_candidate_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    validator_id_hex: &str,
    target_epoch: u64,
    previous_registration_nonce: Option<u64>,
    predecessor_history_head_hex: &str,
    proof_cev0_hex: &str,
    registration_decision_id_hex: &str,
    insertion: usize,
) -> Result<PreparedFutureCandidateV0> {
    let validator_rule =
        || deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::ValidatorRule);
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    if !operation.semantic_changes.is_empty() {
        return Err(validator_rule());
    }
    validate_operation_field_admission_v0(operation)?;
    overlay.accumulator.count().checked_add(2).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    let expected_target_epoch = context.active_epoch.get().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    if target_epoch != expected_target_epoch {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ValidatorRule,
        ));
    }
    let validator_id_bytes = exact_opaque_hex(validator_id_hex).map_err(|_| {
        deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::ValidatorRule)
    })?;
    let validator_id = ValidatorId::from_bytes(&validator_id_bytes).map_err(|_| {
        deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::ValidatorRule)
    })?;
    let proof_bytes = exact_hex(
        proof_cev0_hex,
        1,
        MAX_POCO_SEMANTIC_PAYLOAD_BYTES,
        "future candidate proof of possession",
    )
    .map_err(|_| {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::CryptographicProof,
        )
    })?;
    let proof = decode_validator_key_proof_of_possession_v0_exact(&proof_bytes).map_err(|_| {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::CryptographicProof,
        )
    })?;
    let proof_fields = proof.fields();
    proof
        .verify_for_registration(
            context.genesis_hash,
            context.chain_id,
            Epoch::new(target_epoch),
            validator_id,
            proof_fields.public_key,
            &StrictEd25519Verifier,
        )
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::CryptographicProof,
            )
        })?;

    let active =
        active_projection_context_v0(&overlay.entries).map_err(|_| authenticated_overlay())?;
    if active.validator_set.epoch() != context.active_epoch {
        return Err(authenticated_overlay());
    }
    let predecessor_head =
        exact_hash32_hex(predecessor_history_head_hex).map_err(|_| validator_rule())?;
    match active.validator_set.validator(validator_id) {
        Some(old) if old.consensus_key() != proof_fields.public_key => {
            let previous_nonce = previous_registration_nonce.ok_or_else(validator_rule)?;
            let history = overlay
                .authority
                .validator_registration_history
                .binary_search_by(|item| item.validator_id_hex.as_str().cmp(validator_id_hex))
                .ok()
                .map(|index| &overlay.authority.validator_registration_history[index])
                .ok_or_else(authenticated_overlay)?;
            let history_consensus_key = exact_hash32_hex(&history.consensus_key_hex)
                .map_err(|_| authenticated_overlay())?;
            let history_head =
                exact_hash32_hex(&history.history_head_hex).map_err(|_| authenticated_overlay())?;
            if history.revoked_at_height.is_some()
                || history_consensus_key != *old.consensus_key().as_bytes()
                || history.max_registration_nonce != previous_nonce
                || history_head != predecessor_head
            {
                return Err(authenticated_overlay());
            }
            if proof_fields.registration_nonce <= previous_nonce {
                return Err(validator_rule());
            }
        }
        Some(_) => return Err(validator_rule()),
        None => {
            if previous_registration_nonce.is_some() || predecessor_head != [0; 32] {
                return Err(validator_rule());
            }
        }
    }

    let consensus_key_hex = hex::encode(proof_fields.public_key.as_bytes());
    if overlay
        .authority
        .future_candidate_registrations
        .iter()
        .any(|item| item.consensus_key_hex == consensus_key_hex)
    {
        return Err(validator_rule());
    }
    for old in active.validator_set.validators() {
        if old.id() != validator_id && old.consensus_key() == proof_fields.public_key {
            return Err(validator_rule());
        }
    }

    let decision = require_derived_decision_id(
        preimage,
        b"register-future-candidate",
        registration_decision_id_hex,
    )?;
    let expected_nullifiers = [
        (PocoNullifierFamilyV0::RegistrationDecision, decision),
        (
            PocoNullifierFamilyV0::ValidatorConsensusKey,
            *proof_fields.public_key.as_bytes(),
        ),
    ];
    let proof_digest = domain_hash(FUTURE_CANDIDATE_POP_DIGEST_DOMAIN, &proof_bytes);
    let record = FutureCandidateRegistrationV0 {
        validator_id_hex: validator_id_hex.to_string(),
        target_epoch,
        consensus_key_hex,
        registration_nonce: proof_fields.registration_nonce,
        previous_registration_nonce,
        predecessor_history_head_hex: predecessor_history_head_hex.to_string(),
        proof_cev0_hex: proof_cev0_hex.to_string(),
        proof_digest_hex: hex::encode(proof_digest),
        registration_decision_id_hex: registration_decision_id_hex.to_string(),
        registration_height: context.target_height.get(),
    };
    Ok(PreparedFutureCandidateV0 {
        record,
        insertion,
        expected_nullifiers,
    })
}

fn apply_prepared_future_candidate_v0(
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    prepared: PreparedFutureCandidateV0,
) -> Result<()> {
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &prepared.expected_nullifiers,
    )?;
    overlay
        .authority
        .future_candidate_registrations
        .insert(prepared.insertion, prepared.record);
    Ok(())
}

fn apply_revoke_validator_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    validator_id_hex: &str,
    revocation_decision_id_hex: &str,
) -> Result<()> {
    let validator_rule =
        || deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::ValidatorRule);
    let protocol_reject = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    let validator_id = exact_opaque_hex(validator_id_hex).map_err(|_| validator_rule())?;
    ensure_validator_has_no_active_certificate_references_v0(&overlay.authority, validator_id_hex)
        .map_err(|_| protocol_reject())?;
    let decision =
        require_derived_decision_id(preimage, b"revoke-validator", revocation_decision_id_hex)?;
    let history_index = overlay
        .authority
        .validator_registration_history
        .binary_search_by(|history| history.validator_id_hex.as_str().cmp(validator_id_hex))
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    if overlay.authority.validator_registration_history[history_index]
        .revoked_at_height
        .is_some()
    {
        return Err(protocol_reject());
    }
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, false).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::ValidatorRule,
            )
        })?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::ValidatorRegistration])
        .map_err(|_| validator_rule())?;
    let change = &changes[0];
    if change.expected_identity.as_deref() != Some(validator_id.as_slice()) {
        return Err(authenticated_overlay());
    }
    if change.next_identity.as_deref() != Some(validator_id.as_slice()) {
        return Err(validator_rule());
    }
    let history = &overlay.authority.validator_registration_history[history_index];
    let (old_key, old_nonce, old_proof) = match change.expected_fact.as_ref() {
        Some(SemanticFactV0::ValidatorRegistration {
            consensus_key,
            registration_nonce,
            proof_digest,
            state: RegistrationStateV0::Active,
        }) if hex::encode(consensus_key) == history.consensus_key_hex
            && *registration_nonce == history.max_registration_nonce
            && hex::encode(proof_digest) == history.current_proof_digest_hex =>
        {
            (consensus_key, registration_nonce, proof_digest)
        }
        _ => return Err(authenticated_overlay()),
    };
    match change.next_fact.as_ref() {
        Some(SemanticFactV0::ValidatorRegistration {
            consensus_key,
            registration_nonce,
            proof_digest,
            state: RegistrationStateV0::Revoked,
        }) if consensus_key == old_key
            && registration_nonce == old_nonce
            && proof_digest == old_proof => {}
        _ => return Err(validator_rule()),
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[
            (PocoNullifierFamilyV0::RegistrationDecision, decision),
            (
                PocoNullifierFamilyV0::ValidatorIdentity,
                semantic_identity_digest_v0(
                    PocoSnapshotEntryKindV0::ValidatorRegistration,
                    &validator_id,
                ),
            ),
        ],
    )?;
    let history = &mut overlay.authority.validator_registration_history[history_index];
    history.revoked_at_height = Some(context.target_height.get());
    history.revocation_decision_id_hex = Some(revocation_decision_id_hex.to_string());
    apply_prepared_changes(overlay, changes, false)
}

fn apply_prune_revoked_validator_history_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    validator_id_hex: &str,
) -> Result<()> {
    let validator_rule =
        || deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::ValidatorRule);
    let protocol_reject = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    if !operation.nullifier_insertions.is_empty() {
        return Err(validator_rule());
    }
    let validator_id = exact_opaque_hex(validator_id_hex).map_err(|_| validator_rule())?;
    let history_index = overlay
        .authority
        .validator_registration_history
        .binary_search_by(|history| history.validator_id_hex.as_str().cmp(validator_id_hex))
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    let history = overlay.authority.validator_registration_history[history_index].clone();
    let revoked_at = history.revoked_at_height.ok_or_else(protocol_reject)?;
    let boundary =
        protocol_retention_boundary_v0(revoked_at, &context.active_parameters).map_err(|_| {
            invariant_application_error_v0(PocoApplicationInvariantV0::PlannerArithmetic)
        })?;
    if context.target_height.get() <= boundary {
        return Err(protocol_reject());
    }
    let active_reference = active_certificate_reference_exists_v0(overlay, |body| {
        body.provider_id().as_bytes() == validator_id.as_slice()
    })
    .map_err(|_| authenticated_overlay())?;
    if active_reference {
        return Err(protocol_reject());
    }
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, true).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::ValidatorRule,
            )
        })?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::ValidatorRegistration])
        .map_err(|_| validator_rule())?;
    let change = &changes[0];
    if change.expected_identity.as_deref() != Some(validator_id.as_slice()) {
        return Err(validator_rule());
    }
    match change.expected_fact.as_ref() {
        Some(SemanticFactV0::ValidatorRegistration {
            consensus_key,
            registration_nonce,
            proof_digest,
            state: RegistrationStateV0::Revoked,
        }) if hex::encode(consensus_key) == history.consensus_key_hex
            && *registration_nonce == history.max_registration_nonce
            && hex::encode(proof_digest) == history.current_proof_digest_hex => {}
        _ => return Err(authenticated_overlay()),
    }
    if change.next_value.is_some() {
        return Err(validator_rule());
    }
    overlay
        .authority
        .validator_registration_history
        .remove(history_index);
    apply_prepared_changes(overlay, changes, true)
}

fn apply_prune_certificate_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    certificate_id_hex: &str,
) -> Result<()> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let protocol_reject = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    let certificate_id = exact_hash32_hex(certificate_id_hex).map_err(|_| signed_semantic())?;
    let certificate_index = overlay
        .authority
        .active_certificates
        .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    let certificate = overlay.authority.active_certificates[certificate_index].clone();
    if !prune_target_is_strictly_after_boundary_v0(
        context.target_height.get(),
        certificate.prunable_after_height,
    ) {
        return Err(protocol_reject());
    }
    if overlay
        .authority
        .pending_challenges
        .iter()
        .any(|item| item.certificate_id_hex == certificate_id_hex)
        || overlay
            .authority
            .funded_unused_reservations
            .iter()
            .any(|item| item.certificate_id_hex == certificate_id_hex)
    {
        return Err(protocol_reject());
    }
    let changes =
        prepare_semantic_changes(overlay, &operation.semantic_changes, true).map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )
        })?;
    if changes.iter().any(|change| change.next_value.is_some()) {
        return Err(signed_semantic());
    }
    let actual_keys = changes
        .iter()
        .map(|change| SemanticKeyRefV0 {
            kind: change.kind as u8,
            logical_key_hex: hex::encode(&change.logical_key),
        })
        .collect::<Vec<_>>();
    if actual_keys != certificate.semantic_keys {
        return Err(signed_semantic());
    }
    let settlement_change = change_for_kind(&changes, PocoSnapshotEntryKindV0::Settlement)
        .map_err(|_| authenticated_overlay())?;
    if !matches!(
        settlement_change.expected_fact.as_ref(),
        Some(SemanticFactV0::Settlement {
            state: SettlementStateV0::Consumed,
            ..
        })
    ) {
        return Err(authenticated_overlay());
    }
    let lifecycle_change =
        change_for_kind(&changes, PocoSnapshotEntryKindV0::RevocationOrChallenge)
            .map_err(|_| authenticated_overlay())?;
    let expected_terminal_lifecycle = match certificate.lifecycle {
        CertificateAuthorityLifecycleV0::ChallengeRejected => LifecycleStateV0::ChallengeRejected,
        CertificateAuthorityLifecycleV0::ChallengeSustained => LifecycleStateV0::ChallengeSustained,
        CertificateAuthorityLifecycleV0::Accepted => LifecycleStateV0::Accepted,
    };
    if !matches!(
        lifecycle_change.expected_fact.as_ref(),
        Some(SemanticFactV0::RevocationOrChallenge { state, .. })
            if *state == expected_terminal_lifecycle
    ) {
        return Err(authenticated_overlay());
    }
    let tuple_key =
        exact_hash32_hex(&certificate.tuple_key_hex).map_err(|_| authenticated_overlay())?;
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[
            (PocoNullifierFamilyV0::Certificate, certificate_id),
            (PocoNullifierFamilyV0::Tuple, tuple_key),
        ],
    )?;
    overlay
        .authority
        .active_certificates
        .remove(certificate_index);
    apply_prepared_changes(overlay, changes, true)
}

fn prepare_semantic_changes(
    overlay: &PocoApplicationOverlayV0,
    raw_changes: &[RawSemanticChangeV0],
    allow_prune_deletes: bool,
) -> Result<Vec<PreparedSemanticChangeV0>> {
    let mut prepared = Vec::with_capacity(raw_changes.len());
    for raw in raw_changes {
        let deterministic_semantic = || {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )
        };
        let kind =
            PocoSnapshotEntryKindV0::from_u8(raw.kind).map_err(|_| deterministic_semantic())?;
        if kind == PocoSnapshotEntryKindV0::ApplicationAuthorityState {
            return Err(deterministic_semantic());
        }
        let logical_key = exact_hex(&raw.logical_key_hex, 1, 128, "semantic logical key")
            .map_err(|_| deterministic_semantic())?;
        let map_key = (kind, logical_key.clone());
        if overlay.mutations.contains_key(&map_key) {
            return Err(deterministic_semantic());
        }
        let expected_value = overlay.entries.get(&map_key).cloned();
        let expected = expected_value
            .as_deref()
            .map(|value| owned_semantic_parts(kind, &logical_key, value))
            .transpose()
            .map_err(|_| {
                invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay)
            })?;
        let next_value = raw
            .next_value_hex
            .as_deref()
            .map(|value| exact_hex(value, 1, 65_536, "next semantic value"))
            .transpose()
            .map_err(|_| deterministic_semantic())?;
        let next = next_value
            .as_deref()
            .map(|value| owned_semantic_parts(kind, &logical_key, value))
            .transpose()
            .map_err(|_| deterministic_semantic())?;
        if expected_value == next_value {
            return Err(deterministic_semantic());
        }
        match (&expected, &next) {
            (None, Some(next)) if next.revision == 1 => {}
            (Some(expected), Some(next))
                if expected.revision.checked_add(1) == Some(next.revision) => {}
            (Some(_), None) if allow_prune_deletes => {}
            _ => return Err(deterministic_semantic()),
        }
        prepared.push(PreparedSemanticChangeV0 {
            kind,
            logical_key,
            expected_value,
            next_value,
            expected_fact: expected.as_ref().map(|parts| parts.fact.clone()),
            next_fact: next.as_ref().map(|parts| parts.fact.clone()),
            expected_identity: expected.as_ref().map(|parts| parts.identity.clone()),
            next_identity: next.as_ref().map(|parts| parts.identity.clone()),
            expected_payload: expected.as_ref().map(|parts| parts.payload.clone()),
            next_payload: next.as_ref().map(|parts| parts.payload.clone()),
            expected_revision: expected.as_ref().map(|parts| parts.revision),
            next_revision: next.as_ref().map(|parts| parts.revision),
        });
    }
    Ok(prepared)
}

fn apply_prepared_changes(
    overlay: &mut PocoApplicationOverlayV0,
    changes: Vec<PreparedSemanticChangeV0>,
    prune_authorized: bool,
) -> Result<()> {
    for change in changes {
        let postcondition = || {
            invariant_application_error_v0(PocoApplicationInvariantV0::DerivedMutationPostcondition)
        };
        if change.next_value.is_none() && !prune_authorized {
            return Err(postcondition());
        }
        if change.kind == PocoSnapshotEntryKindV0::ApplicationAuthorityState && prune_authorized {
            return Err(postcondition());
        }
        let map_key = (change.kind, change.logical_key.clone());
        if overlay.entries.get(&map_key) != change.expected_value.as_ref()
            || overlay.mutations.contains_key(&map_key)
        {
            return Err(postcondition());
        }
        match &change.next_value {
            Some(value) => {
                overlay.entries.insert(map_key.clone(), value.clone());
            }
            None => {
                overlay.entries.remove(&map_key);
            }
        }
        overlay.mutations.insert(
            map_key,
            OverlayMutationV0 {
                kind: change.kind,
                logical_key: change.logical_key,
                expected_value: change.expected_value,
                next_value: change.next_value,
            },
        );
    }
    Ok(())
}

fn ensure_change_kinds(
    changes: &[PreparedSemanticChangeV0],
    expected: &[PocoSnapshotEntryKindV0],
) -> Result<()> {
    let actual = changes.iter().map(|item| item.kind).collect::<Vec<_>>();
    if actual != expected {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        ));
    }
    Ok(())
}

fn change_for_kind(
    changes: &[PreparedSemanticChangeV0],
    kind: PocoSnapshotEntryKindV0,
) -> Result<&PreparedSemanticChangeV0> {
    let mut matches = changes.iter().filter(|change| change.kind == kind);
    let result = matches.next().ok_or_else(|| {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
        )
    })?;
    if matches.next().is_some() {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        ));
    }
    Ok(result)
}

fn insert_nullifiers(
    overlay: &mut PocoApplicationOverlayV0,
    raw_insertions: &[RawNullifierInsertionV0],
    expected: &[(PocoNullifierFamilyV0, [u8; 32])],
) -> Result<()> {
    let malformed_proof = || {
        deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::NullifierProof)
    };
    let wrong_root = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::NullifierNonMembershipRootMismatch,
        )
    };
    if raw_insertions.len() != expected.len() {
        return Err(malformed_proof());
    }
    let mut expected_ordered = expected.to_vec();
    expected_ordered.sort();
    for (raw, (expected_family, expected_identifier)) in raw_insertions.iter().zip(expected_ordered)
    {
        let family = PocoNullifierFamilyV0::from_u8(raw.family).map_err(|_| malformed_proof())?;
        let identifier = exact_hash32_hex(&raw.identifier_hex).map_err(|_| malformed_proof())?;
        if family != expected_family || identifier != expected_identifier {
            return Err(malformed_proof());
        }
        let proof_bytes = exact_hex(
            &raw.proof_hex,
            crate::poco_nullifier::POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0,
            crate::poco_nullifier::POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0,
            "nullifier proof",
        )
        .map_err(|_| malformed_proof())?;
        let proof =
            PocoNullifierProofV0::decode_exact(&proof_bytes).map_err(|_| malformed_proof())?;
        let key = derive_poco_nullifier_key_v0(family, identifier);
        if proof.key() != key {
            return Err(malformed_proof());
        }
        if overlay.accumulator.count() == u64::MAX {
            return Err(invariant_application_error_v0(
                PocoApplicationInvariantV0::ProtocolCounterExhausted,
            ));
        }
        let insertion = overlay
            .accumulator
            .verify_non_membership_and_compute_insertion(key, &proof)
            .map_err(|_| wrong_root())?;
        overlay.accumulator = insertion.target_accumulator().map_err(|_| {
            anyhow::Error::new(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::DerivedMutationPostcondition,
            ))
        })?;
    }
    Ok(())
}

fn verify_nullifier_absences(
    overlay: &PocoApplicationOverlayV0,
    raw_checks: &[RawNullifierInsertionV0],
    expected: &[(PocoNullifierFamilyV0, [u8; 32])],
) -> Result<()> {
    let malformed_proof = || {
        deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::NullifierProof)
    };
    let wrong_root = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::NullifierNonMembershipRootMismatch,
        )
    };
    if raw_checks.len() != expected.len() {
        return Err(malformed_proof());
    }
    let mut expected_ordered = expected.to_vec();
    expected_ordered.sort();
    for (raw, (expected_family, expected_identifier)) in raw_checks.iter().zip(expected_ordered) {
        let family = PocoNullifierFamilyV0::from_u8(raw.family).map_err(|_| malformed_proof())?;
        let identifier = exact_hash32_hex(&raw.identifier_hex).map_err(|_| malformed_proof())?;
        if family != expected_family || identifier != expected_identifier {
            return Err(malformed_proof());
        }
        let proof_bytes = exact_hex(
            &raw.proof_hex,
            crate::poco_nullifier::POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0,
            crate::poco_nullifier::POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0,
            "nullifier proof",
        )
        .map_err(|_| malformed_proof())?;
        let proof =
            PocoNullifierProofV0::decode_exact(&proof_bytes).map_err(|_| malformed_proof())?;
        let key = derive_poco_nullifier_key_v0(family, identifier);
        if proof.key() != key {
            return Err(malformed_proof());
        }
        overlay
            .accumulator
            .verify_non_membership(key, &proof)
            .map_err(|_| wrong_root())?;
    }
    Ok(())
}

#[derive(Clone)]
struct OwnedSemanticPartsV0 {
    revision: u64,
    identity: Vec<u8>,
    payload: Vec<u8>,
    fact: SemanticFactV0,
}

fn owned_semantic_parts(
    kind: PocoSnapshotEntryKindV0,
    logical_key: &[u8],
    value: &[u8],
) -> Result<OwnedSemanticPartsV0> {
    let parts = decode_poco_snapshot_value_parts_v0_exact(kind, logical_key, value)?;
    Ok(OwnedSemanticPartsV0 {
        revision: parts.verified.revision(),
        identity: parts.identity.to_vec(),
        payload: parts.payload.to_vec(),
        fact: parts.fact,
    })
}

fn source_parts_for_identity(
    overlay: &PocoApplicationOverlayV0,
    kind: PocoSnapshotEntryKindV0,
    identity: &[u8],
) -> Result<OwnedSemanticPartsV0> {
    let logical_key = semantic_identity_digest_v0(kind, identity);
    let value = overlay
        .entries
        .get(&(kind, logical_key.to_vec()))
        .ok_or_else(|| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    let parts = owned_semantic_parts(kind, &logical_key, value).map_err(|_| {
        invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay)
    })?;
    if parts.identity != identity {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::AuthenticatedOverlay,
        ));
    }
    Ok(parts)
}

fn projection_parts_for_identity_v0(
    entries: &BTreeMap<(PocoSnapshotEntryKindV0, Vec<u8>), Vec<u8>>,
    kind: PocoSnapshotEntryKindV0,
    identity: &[u8],
) -> Result<OwnedSemanticPartsV0> {
    let logical_key = semantic_identity_digest_v0(kind, identity);
    let value = entries
        .get(&(kind, logical_key.to_vec()))
        .context("application authority references absent semantic entry")?;
    let parts = owned_semantic_parts(kind, &logical_key, value)?;
    ensure!(
        parts.identity == identity,
        "application authority semantic identity digest collision"
    );
    Ok(parts)
}

fn validate_governance_parameters_companion_v0(
    entries: &BTreeMap<(PocoSnapshotEntryKindV0, Vec<u8>), Vec<u8>>,
    target_epoch: u64,
    expected_hash_hex: &str,
) -> Result<ConsensusParametersV0> {
    let mut identity = vec![2];
    identity.extend_from_slice(&target_epoch.to_be_bytes());
    let parts = projection_parts_for_identity_v0(
        entries,
        PocoSnapshotEntryKindV0::ConsensusParameters,
        &identity,
    )?;
    let parameters = decode_consensus_parameters_v0_exact(&parts.payload)
        .map_err(|error| anyhow::anyhow!("decode governance parameters companion: {error:?}"))?;
    ensure!(
        hex::encode(parameters.hash().as_bytes()) == expected_hash_hex,
        "governance parameters companion hash mismatch"
    );
    Ok(parameters)
}

fn validate_measurement_policy(
    policy: MeterEvidencePolicyV0,
    certificate_root: Option<[u8; 32]>,
    next: Option<&SemanticFactV0>,
) -> Result<()> {
    match (policy, certificate_root, next) {
        (
            MeterEvidencePolicyV0::Required,
            Some(root),
            Some(SemanticFactV0::MeasurementEvidence {
                evidence_root: Some(actual),
                state: MeasurementStateV0::Verified,
            }),
        ) if root == *actual => Ok(()),
        (
            MeterEvidencePolicyV0::Forbidden,
            None,
            Some(SemanticFactV0::MeasurementEvidence {
                evidence_root: None,
                state: MeasurementStateV0::NotRequired,
            }),
        ) => Ok(()),
        (
            MeterEvidencePolicyV0::Optional,
            Some(root),
            Some(SemanticFactV0::MeasurementEvidence {
                evidence_root: Some(actual),
                state: MeasurementStateV0::Verified,
            }),
        ) if root == *actual => Ok(()),
        (
            MeterEvidencePolicyV0::Optional,
            None,
            Some(SemanticFactV0::MeasurementEvidence {
                evidence_root: None,
                state: MeasurementStateV0::NotRequired,
            }),
        ) => Ok(()),
        _ => bail!("measurement evidence does not satisfy meter policy"),
    }
}

fn validate_decimal_u128(value: &str) -> Result<u128> {
    ensure!(!value.is_empty(), "empty canonical u128");
    ensure!(
        value == "0" || !value.starts_with('0'),
        "canonical u128 has leading zero"
    );
    ensure!(
        value.bytes().all(|byte| byte.is_ascii_digit()),
        "canonical u128 contains non-decimal digit"
    );
    value.parse().context("canonical u128 exceeds range")
}

fn validate_meter_policy(policy: &MeterAuthorityPolicyV0) -> Result<()> {
    exact_opaque_hex(&policy.meter_id_hex)?;
    exact_opaque_hex(&policy.task_id_hex)?;
    if let Some(output) = &policy.output_commitment_hex {
        exact_hash32_hex(output)?;
    }
    ensure!(policy.unit_scale.get()? > 0, "meter unit scale is zero");
    ensure!(
        policy.per_certificate_cap.get()? > 0,
        "meter per-certificate cap is zero"
    );
    ensure!(policy.rolling_cap.get()? > 0, "meter rolling cap is zero");
    ensure!(
        policy.per_certificate_cap.get()? <= policy.rolling_cap.get()?,
        "meter per-certificate cap exceeds rolling cap"
    );
    ensure!(
        policy.rolling_epoch_span > 0,
        "meter rolling epoch span is zero"
    );
    ensure!(policy.retention_blocks > 0, "meter retention is zero");
    ensure!(
        policy
            .retired_at_height
            .is_none_or(|height| height > policy.active_from_height),
        "meter authority interval is invalid"
    );
    Ok(())
}

fn checked_usage_after_v0(previous: u128, delta: u128, cap: u128, label: &str) -> Result<u128> {
    let _ = label;
    let next = previous.checked_add(delta).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    if next > cap {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    Ok(next)
}

fn checked_usage_bucket_total_v0(counts: [usize; 4]) -> Result<usize> {
    counts.into_iter().try_fold(0usize, |total, count| {
        total.checked_add(count).ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
        })
    })
}

fn usage_bucket_count_v0(state: &PocoApplicationAuthorityStateV0) -> Result<usize> {
    checked_usage_bucket_total_v0([
        state.meter_usage.len(),
        state.consumer_provider_usage.len(),
        state.task_provider_usage.len(),
        state.provider_usage.len(),
    ])
}

fn total_nonce_watermarks_v0(state: &PocoApplicationAuthorityStateV0) -> Result<usize> {
    state.consumer_keys.iter().try_fold(0usize, |total, key| {
        total
            .checked_add(key.nonce_watermarks.len())
            .ok_or_else(|| {
                invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
            })
    })
}

fn authority_record_count_v0(state: &PocoApplicationAuthorityStateV0) -> Result<usize> {
    let counts = [
        state.consumer_keys.len(),
        total_nonce_watermarks_v0(state)?,
        state.meter_policies.len(),
        usage_bucket_count_v0(state)?,
        state.funded_unused_reservations.len(),
        state.active_certificates.len(),
        state.pending_challenges.len(),
        state.pending_governance_proposals.len(),
        state.finalized_governance_approvals.len(),
        state.validator_registration_history.len(),
        state.future_candidate_registrations.len(),
    ];
    counts.into_iter().try_fold(0usize, |total, count| {
        total.checked_add(count).ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
        })
    })
}

fn validate_usage_bucket_admission_v0(current: usize, new_buckets: usize) -> Result<usize> {
    let target = current.checked_add(new_buckets).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    if target > MAX_TOTAL_USAGE_BUCKETS {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    Ok(target)
}

fn validate_recorded_business_height_v0(
    height: u64,
    last_target_height: u64,
    name: &str,
) -> Result<()> {
    ensure!(
        height > 0 && height <= last_target_height,
        "{name} height is outside authenticated authority history"
    );
    Ok(())
}

const fn fund_certificate_absence_subjects_v0(
    certificate_id: [u8; 32],
) -> [(PocoNullifierFamilyV0, [u8; 32]); 1] {
    [(PocoNullifierFamilyV0::Certificate, certificate_id)]
}

const fn release_nullifier_subjects_v0(
    certificate_id: [u8; 32],
    release_decision_id: [u8; 32],
) -> [(PocoNullifierFamilyV0, [u8; 32]); 2] {
    [
        (PocoNullifierFamilyV0::Certificate, certificate_id),
        (
            PocoNullifierFamilyV0::SettlementDecision,
            release_decision_id,
        ),
    ]
}

fn protocol_retention_boundary_v0(
    start_height: u64,
    parameters: &ConsensusParametersV0,
) -> Result<u64> {
    parameters
        .validate_safety_invariants()
        .map_err(|error| anyhow::anyhow!("invalid retention parameters: {error:?}"))?;
    let epochs = parameters
        .maturity_epochs()
        .checked_add(parameters.max_certificate_age_epochs())
        .context("retention maturity+age overflow")?
        .max(parameters.evidence_window_epochs());
    let blocks = epochs
        .checked_mul(parameters.epoch_length_blocks())
        .context("retention block window overflow")?;
    start_height
        .checked_add(blocks)
        .context("retention boundary overflow")
}

fn active_certificate_reference_exists_v0(
    overlay: &PocoApplicationOverlayV0,
    mut predicate: impl FnMut(&ConsumptionCertificateBodyV0) -> bool,
) -> Result<bool> {
    for certificate in &overlay.authority.active_certificates {
        let certificate_id = exact_hash32_hex(&certificate.certificate_id_hex)?;
        let parts = source_parts_for_identity(
            overlay,
            PocoSnapshotEntryKindV0::ConsumptionCertificate,
            &certificate_id,
        )?;
        let decoded = decode_consumption_certificate_v0_exact(&parts.payload)
            .map_err(|error| anyhow::anyhow!("decode active certificate reference: {error:?}"))?;
        let body = decoded.body();
        ensure!(
            decoded.certificate_id().as_bytes() == &certificate_id
                && hex::encode(body.consumer_id().as_bytes()) == certificate.consumer_id_hex
                && hex::encode(body.consumer_key_id().as_bytes())
                    == certificate.consumer_key_id_hex
                && hex::encode(body.provider_id().as_bytes()) == certificate.provider_id_hex
                && hex::encode(body.task_id()) == certificate.task_id_hex
                && hex::encode(body.meter_id()) == certificate.meter_id_hex
                && body.meter_version() == certificate.meter_version
                && hex::encode(body.settlement_commitment().as_slice())
                    == certificate.settlement_commitment_hex
                && body.consumed_units() == certificate.consumed_units.get()?
                && body
                    .measurement_evidence_root()
                    .map(|root| hex::encode(root.as_slice()))
                    == certificate.evidence_root_hex,
            "active certificate reference diverges from authority owner"
        );
        if predicate(body) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn consumer_nonce_summary_digest_v0(authority: &ConsumerKeyAuthorityV0) -> Result<[u8; 32]> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    // Owner identity is mandatory: distinct never-used keys both have empty
    // watermark rows and still require distinct permanent replay subjects.
    encode_bytes(&mut encoded, &exact_opaque_hex(&authority.consumer_id_hex)?);
    encode_bytes(
        &mut encoded,
        &exact_opaque_hex(&authority.consumer_key_id_hex)?,
    );
    encoded.extend_from_slice(
        &u32::try_from(authority.nonce_watermarks.len())
            .context("nonce summary count exceeds u32")?
            .to_be_bytes(),
    );
    for watermark in &authority.nonce_watermarks {
        encode_bytes(&mut encoded, &exact_opaque_hex(&watermark.provider_id_hex)?);
        encoded.extend_from_slice(&watermark.max_accepted_nonce.to_be_bytes());
        encoded.extend_from_slice(&exact_hash32_hex(&watermark.logical_key_hex)?);
    }
    Ok(domain_hash(
        b"trnm.poco-bft.consumer-nonce-summary.v0",
        &encoded,
    ))
}

fn compact_expired_usage_v0(
    authority: &mut PocoApplicationAuthorityStateV0,
    context: &AuthenticatedPocoApplicationContextV0,
) -> Result<()> {
    let active_epoch = context.active_epoch.get();
    let meter_policies = authority.meter_policies.clone();
    authority.meter_usage.retain(|usage| {
        meter_policies
            .binary_search_by(|policy| {
                (&policy.meter_id_hex, policy.meter_version)
                    .cmp(&(&usage.meter_id_hex, usage.meter_version))
            })
            .ok()
            .is_some_and(|index| {
                let span = meter_policies[index].rolling_epoch_span;
                span > 0 && usage.window_epoch >= active_epoch / span
            })
    });
    authority
        .consumer_provider_usage
        .retain(|usage| usage.window_epoch >= active_epoch);
    authority
        .task_provider_usage
        .retain(|usage| usage.window_epoch >= active_epoch);
    authority
        .provider_usage
        .retain(|usage| usage.window_epoch >= active_epoch);
    authority.validate()
}

fn validate_tuple_acceptance_authority_v0(
    fact: &SemanticFactV0,
    certificate_id: [u8; 32],
    target_height: u64,
) -> Result<()> {
    match fact {
        SemanticFactV0::UniqueConsumptionTuple {
            certificate_id: tuple_certificate_id,
            accepted_height,
        } => ensure!(
            *tuple_certificate_id == certificate_id && *accepted_height == target_height,
            "consumption tuple certificate/accepted-height authority mismatch"
        ),
        _ => bail!("certificate operation has wrong tuple semantic fact"),
    }
    Ok(())
}

fn validate_reserved_units_exact_v0(reserved_units: u128, consumed_units: u128) -> Result<()> {
    ensure!(
        reserved_units > 0 && reserved_units == consumed_units,
        "funded reservation units do not exactly match certificate consumption"
    );
    Ok(())
}

/// Returns the last height at which rich certificate state must still be
/// retained.  Prune is allowed only at a target height strictly greater than
/// this boundary.
fn derive_safe_prune_boundary_v0(
    accepted_height: u64,
    parameters: &ConsensusParametersV0,
    meter_policy: &MeterAuthorityPolicyV0,
) -> Result<u64> {
    parameters.validate_safety_invariants().map_err(|_| {
        invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay)
    })?;
    validate_meter_policy(meter_policy).map_err(|_| {
        invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay)
    })?;
    let weight_epochs = parameters
        .maturity_epochs()
        .checked_add(parameters.max_certificate_age_epochs())
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
        })?;
    let protocol_epochs = weight_epochs.max(parameters.evidence_window_epochs());
    let protocol_blocks = protocol_epochs
        .checked_mul(parameters.epoch_length_blocks())
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
        })?;
    let rolling_blocks = meter_policy
        .rolling_epoch_span
        .checked_mul(parameters.epoch_length_blocks())
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
        })?;
    let retention_blocks = protocol_blocks
        .max(rolling_blocks)
        .max(meter_policy.retention_blocks);
    if retention_blocks == 0 {
        return Err(invariant_application_error_v0(
            PocoApplicationInvariantV0::AuthenticatedOverlay,
        ));
    }
    accepted_height
        .checked_add(retention_blocks)
        .ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
        })
}

const fn prune_target_is_strictly_after_boundary_v0(target: u64, boundary: u64) -> bool {
    target > boundary
}

fn validate_active_certificate(item: &ActiveCertificateAuthorityV0) -> Result<()> {
    exact_hash32_hex(&item.certificate_id_hex)?;
    exact_opaque_hex(&item.consumer_id_hex)?;
    exact_opaque_hex(&item.consumer_key_id_hex)?;
    exact_opaque_hex(&item.provider_id_hex)?;
    exact_opaque_hex(&item.task_id_hex)?;
    exact_opaque_hex(&item.meter_id_hex)?;
    exact_hash32_hex(&item.settlement_commitment_hex)?;
    ensure!(
        item.settlement_finalized_height > 0
            && item.settlement_finalized_height <= item.accepted_height,
        "certificate settlement finalization height is invalid"
    );
    ensure!(
        item.consumed_units.get()? > 0,
        "certificate consumed units are zero"
    );
    if let Some(root) = &item.evidence_root_hex {
        exact_hash32_hex(root)?;
    }
    RelationshipClassV0::try_from(item.relationship_class)?;
    exact_hash32_hex(&item.relationship_key_hex)?;
    exact_hash32_hex(&item.provider_consensus_key_hex)?;
    exact_hash32_hex(&item.provider_proof_digest_hex)?;
    exact_hash32_hex(&item.provider_registration_decision_id_hex)?;
    exact_hash32_hex(&item.provider_registration_history_head_hex)?;
    exact_hash32_hex(&item.acceptance_decision_id_hex)?;
    exact_hash32_hex(&item.funding_decision_id_hex)?;
    exact_hash32_hex(&item.meter_decision_id_hex)?;
    exact_hash32_hex(&item.evidence_decision_id_hex)?;
    exact_hash32_hex(&item.lifecycle_decision_id_hex)?;
    exact_hash32_hex(&item.tuple_key_hex)?;
    ensure!(
        item.accepted_height > 0,
        "certificate acceptance height is zero"
    );
    validate_certificate_lifecycle_authority_v0(
        item.lifecycle,
        item.lifecycle_effective_height,
        &item.lifecycle_decision_id_hex,
        item.accepted_height,
        &item.acceptance_decision_id_hex,
    )?;
    ensure!(
        item.prunable_after_height > item.accepted_height,
        "certificate prune height does not follow acceptance"
    );
    ensure!(
        item.semantic_keys.len() == 5,
        "certificate retained semantic-key count is not exact"
    );
    validate_strictly_sorted_unique_by(
        &item.semantic_keys,
        |key| (key.kind, key.logical_key_hex.clone()),
        "certificate retained semantic keys",
    )?;
    for key in &item.semantic_keys {
        let kind = PocoSnapshotEntryKindV0::from_u8(key.kind)?;
        ensure!(
            matches!(
                kind,
                PocoSnapshotEntryKindV0::ConsumptionCertificate
                    | PocoSnapshotEntryKindV0::UniqueConsumptionTuple
                    | PocoSnapshotEntryKindV0::Settlement
                    | PocoSnapshotEntryKindV0::MeasurementEvidence
                    | PocoSnapshotEntryKindV0::RevocationOrChallenge
            ),
            "certificate retained key kind is not prune-authorized"
        );
        exact_hash32_hex(&key.logical_key_hex)?;
    }
    Ok(())
}

fn validate_certificate_lifecycle_authority_v0(
    lifecycle: CertificateAuthorityLifecycleV0,
    effective_height: u64,
    lifecycle_decision_id_hex: &str,
    accepted_height: u64,
    acceptance_decision_id_hex: &str,
) -> Result<()> {
    match lifecycle {
        CertificateAuthorityLifecycleV0::Accepted => ensure!(
            effective_height == accepted_height
                && lifecycle_decision_id_hex == acceptance_decision_id_hex,
            "accepted certificate lifecycle authority is substituted"
        ),
        CertificateAuthorityLifecycleV0::ChallengeRejected
        | CertificateAuthorityLifecycleV0::ChallengeSustained => ensure!(
            effective_height > accepted_height,
            "terminal certificate lifecycle is not monotonic"
        ),
    }
    Ok(())
}

fn ensure_record_family_bounds(state: &PocoApplicationAuthorityStateV0) -> Result<()> {
    ensure!(
        state.consumer_keys.len() <= MAX_CONSUMER_KEY_AUTHORITIES,
        "consumer keys exceed authority record bound"
    );
    ensure!(
        total_nonce_watermarks_v0(state)? <= MAX_TOTAL_NONCE_WATERMARKS,
        "consumer nonce watermarks exceed global authority record bound"
    );
    ensure!(
        state.meter_policies.len() <= MAX_METER_POLICIES,
        "meter policies exceed authority record bound"
    );
    ensure!(
        usage_bucket_count_v0(state)? <= MAX_TOTAL_USAGE_BUCKETS,
        "usage buckets exceed authority record bound"
    );
    ensure!(
        state.funded_unused_reservations.len() <= MAX_FUNDED_UNUSED_RESERVATIONS,
        "funded-unused reservations exceed authority record bound"
    );
    ensure!(
        state.active_certificates.len() <= MAX_ACTIVE_CERTIFICATES,
        "active certificates exceed authority record bound"
    );
    ensure!(
        state.pending_challenges.len() <= MAX_PENDING_CHALLENGES,
        "pending challenges exceed authority record bound"
    );
    ensure!(
        state.pending_governance_proposals.len() <= MAX_PENDING_GOVERNANCE_PROPOSALS,
        "pending governance proposals exceed authority record bound"
    );
    ensure!(
        state.finalized_governance_approvals.len() <= MAX_FINALIZED_GOVERNANCE_APPROVALS,
        "governance approvals exceed authority record bound"
    );
    ensure!(
        state.validator_registration_history.len() <= MAX_VALIDATOR_REGISTRATION_HISTORIES,
        "validator history exceeds authority record bound"
    );
    ensure!(
        state.future_candidate_registrations.len() <= MAX_FUTURE_CANDIDATE_REGISTRATIONS,
        "future candidate registrations exceed authority record bound"
    );
    ensure!(
        authority_record_count_v0(state)? <= MAX_TOTAL_AUTHORITY_RECORDS,
        "application authority total record count exceeds hard cap"
    );
    let mut challenged_certificates = BTreeSet::new();
    for item in &state.pending_challenges {
        ensure!(
            challenged_certificates.insert(&item.certificate_id_hex),
            "certificate has multiple pending challenges"
        );
    }
    Ok(())
}

fn ensure_validator_has_no_active_certificate_references_v0(
    state: &PocoApplicationAuthorityStateV0,
    validator_id_hex: &str,
) -> Result<()> {
    ensure!(
        state
            .active_certificates
            .iter()
            .all(|certificate| certificate.provider_id_hex != validator_id_hex),
        "validator registration is referenced by an active certificate"
    );
    Ok(())
}

fn validate_strictly_sorted_unique_by<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    family: &str,
) -> Result<()> {
    for pair in values.windows(2) {
        ensure!(
            key(&pair[0]) < key(&pair[1]),
            "{family} are not strictly sorted and unique"
        );
    }
    Ok(())
}

fn validate_raw_semantic_order(changes: &[RawSemanticChangeV0]) -> Result<()> {
    let mut previous = None;
    for change in changes {
        let kind = PocoSnapshotEntryKindV0::from_u8(change.kind)?;
        ensure!(
            kind != PocoSnapshotEntryKindV0::ApplicationAuthorityState,
            "raw operation may not name application authority kind 16"
        );
        let logical_key = exact_hex(&change.logical_key_hex, 1, 128, "semantic logical key")?;
        if let Some(value) = &change.next_value_hex {
            exact_hex(value, 1, 65_536, "next semantic value")?;
        }
        let identity = (kind, logical_key);
        if let Some(previous) = previous {
            ensure!(
                previous < identity,
                "raw semantic changes are not canonical and unique"
            );
        }
        previous = Some(identity);
    }
    Ok(())
}

fn validate_raw_nullifier_order(insertions: &[RawNullifierInsertionV0]) -> Result<()> {
    let mut previous = None;
    for insertion in insertions {
        let family = PocoNullifierFamilyV0::from_u8(insertion.family)?;
        let identifier = exact_hash32_hex(&insertion.identifier_hex)?;
        let proof_bytes = exact_hex(
            &insertion.proof_hex,
            crate::poco_nullifier::POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0,
            crate::poco_nullifier::POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0,
            "nullifier proof",
        )?;
        let proof = PocoNullifierProofV0::decode_exact(&proof_bytes)?;
        ensure!(
            proof.key() == derive_poco_nullifier_key_v0(family, identifier),
            "nullifier proof key differs from family/identifier"
        );
        let identity = (family, identifier);
        if let Some(previous) = previous {
            ensure!(
                previous < identity,
                "raw nullifier insertions are not canonical and unique"
            );
        }
        previous = Some(identity);
    }
    Ok(())
}

fn validate_source_projection_bound(projection: &ProductionPocoProjectionV0) -> Result<usize> {
    ensure!(
        projection.entries().len() <= MAX_POCO_SNAPSHOT_ENTRIES,
        "production PoCO projection exceeds entry bound"
    );
    let mut total = projection.manifest().encode().len();
    for entry in projection.entries() {
        total = total
            .checked_add(entry.logical_key.len())
            .and_then(|size| size.checked_add(entry.value.len()))
            .context("production PoCO projection size overflow")?;
        ensure!(
            total <= MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
            "production PoCO projection exceeds 8 MiB"
        );
    }
    Ok(total)
}

fn validate_block_admission_bounds(
    projection: &ProductionPocoProjectionV0,
    raw_operations: &[Vec<u8>],
) -> Result<()> {
    let mut total = validate_source_projection_bound(projection)?;
    ensure!(
        !raw_operations.is_empty() && raw_operations.len() <= MAX_APPLICATION_OPERATIONS_PER_BLOCK,
        "application operation count is outside bound"
    );
    for raw in raw_operations {
        ensure!(
            !raw.is_empty() && raw.len() <= MAX_APPLICATION_OPERATION_BYTES,
            "application operation byte length is outside bound"
        );
        total = total
            .checked_add(raw.len())
            .context("application block admission size overflow")?;
        ensure!(
            total <= MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
            "application source plus operations exceed 8 MiB"
        );
    }
    Ok(())
}

fn validate_target_projection_bounds(entries: &[PocoSnapshotEntryV0]) -> Result<()> {
    ensure!(
        entries.len() <= MAX_POCO_SNAPSHOT_ENTRIES,
        "application target projection exceeds entry bound"
    );
    let mut total = 0usize;
    for entry in entries {
        total = total
            .checked_add(entry.logical_key.len())
            .and_then(|size| size.checked_add(entry.value.len()))
            .context("application target projection size overflow")?;
        ensure!(
            total <= MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
            "application target projection exceeds 8 MiB"
        );
    }
    Ok(())
}

fn validate_overlay_projection_bounds_before_clone_v0(
    entries: &BTreeMap<(PocoSnapshotEntryKindV0, Vec<u8>), Vec<u8>>,
) -> Result<()> {
    ensure!(
        entries.len() <= MAX_POCO_SNAPSHOT_ENTRIES,
        "application target projection exceeds entry bound before clone"
    );
    let mut total = 0usize;
    for ((_, logical_key), value) in entries {
        total = total
            .checked_add(logical_key.len())
            .and_then(|size| size.checked_add(value.len()))
            .context("application target projection size overflow before clone")?;
        ensure!(
            total <= MAX_POCO_SNAPSHOT_BUNDLE_BYTES,
            "application target projection exceeds 8 MiB before clone"
        );
    }
    Ok(())
}

fn decision_preimage_digest_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    operation: &PocoApplicationOperationV0,
) -> Result<[u8; 32]> {
    let mut normalized = operation.clone();
    normalized.nullifier_non_membership_checks.clear();
    normalized.nullifier_insertions.clear();
    let zero = "0".repeat(64);
    match &mut normalized.body {
        PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            decision_id_hex, ..
        }
        | PocoApplicationOperationBodyV0::RevokeConsumerKey {
            decision_id_hex, ..
        }
        | PocoApplicationOperationBodyV0::DefineMeterPolicy {
            decision_id_hex, ..
        }
        | PocoApplicationOperationBodyV0::RetireMeterPolicy {
            decision_id_hex, ..
        }
        | PocoApplicationOperationBodyV0::ApproveGovernance {
            decision_id_hex, ..
        } => *decision_id_hex = zero.clone(),
        PocoApplicationOperationBodyV0::FundSettlement {
            funding_decision_id_hex,
            ..
        } => *funding_decision_id_hex = zero.clone(),
        PocoApplicationOperationBodyV0::AcceptCertificate {
            acceptance_decision_id_hex,
            meter_decision_id_hex,
            evidence_decision_id_hex,
            ..
        } => {
            *acceptance_decision_id_hex = zero.clone();
            *meter_decision_id_hex = zero.clone();
            *evidence_decision_id_hex = zero.clone();
        }
        PocoApplicationOperationBodyV0::ReleaseSettlement {
            release_decision_id_hex,
            ..
        } => *release_decision_id_hex = zero.clone(),
        PocoApplicationOperationBodyV0::OpenChallenge {
            challenge_id_hex,
            opening_decision_id_hex,
            ..
        } => {
            *challenge_id_hex = zero.clone();
            *opening_decision_id_hex = zero.clone();
        }
        PocoApplicationOperationBodyV0::ResolveChallenge {
            resolution_decision_id_hex,
            ..
        } => *resolution_decision_id_hex = zero.clone(),
        PocoApplicationOperationBodyV0::ProposeGovernance {
            proposal_decision_id_hex,
            ..
        } => *proposal_decision_id_hex = zero.clone(),
        PocoApplicationOperationBodyV0::RegisterValidator {
            registration_decision_id_hex,
            ..
        }
        | PocoApplicationOperationBodyV0::RotateValidator {
            registration_decision_id_hex,
            ..
        }
        | PocoApplicationOperationBodyV0::RegisterFutureCandidate {
            registration_decision_id_hex,
            ..
        } => *registration_decision_id_hex = zero,
        PocoApplicationOperationBodyV0::RevokeValidator {
            revocation_decision_id_hex,
            ..
        } => *revocation_decision_id_hex = zero,
        PocoApplicationOperationBodyV0::PruneRevokedConsumerKey { .. }
        | PocoApplicationOperationBodyV0::PruneRetiredMeter { .. }
        | PocoApplicationOperationBodyV0::PruneRevokedValidatorHistory { .. }
        | PocoApplicationOperationBodyV0::PruneExpiredCertificate { .. } => {}
    }
    let normalized_bytes =
        serde_json::to_vec(&normalized).context("encode normalized decision preimage")?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    encode_bytes(&mut encoded, context.genesis_hash.as_bytes());
    encode_bytes(&mut encoded, context.chain_id.as_bytes());
    encoded.extend_from_slice(&context.source_version.to_be_bytes());
    encoded.extend_from_slice(&context.source_root);
    encoded.extend_from_slice(&context.target_height.get().to_be_bytes());
    encoded.extend_from_slice(&context.active_epoch.get().to_be_bytes());
    encoded.extend_from_slice(context.active_parameters.hash().as_bytes());
    encoded.extend_from_slice(&context.authority_signer_commitment);
    encode_bytes(&mut encoded, &normalized_bytes);
    Ok(domain_hash(APPLICATION_DECISION_PREIMAGE_DOMAIN, &encoded))
}

fn require_derived_decision_id(
    preimage: [u8; 32],
    label: &[u8],
    claimed_hex: &str,
) -> Result<[u8; 32]> {
    let claimed = exact_hash32_hex(claimed_hex).map_err(|_| {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    })?;
    let expected = derived_decision_id_v0(preimage, label);
    if claimed != expected {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        ));
    }
    Ok(expected)
}

fn derived_decision_id_v0(preimage: [u8; 32], label: &[u8]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(38 + label.len());
    encoded.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    encode_bytes(&mut encoded, label);
    encoded.extend_from_slice(&preimage);
    domain_hash(APPLICATION_DECISION_ID_DOMAIN, &encoded)
}

#[cfg(test)]
fn encode_test_semantic_envelope_v0(
    kind: PocoSnapshotEntryKindV0,
    revision: u64,
    identity: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    value.push(kind as u8);
    value.extend_from_slice(&revision.to_be_bytes());
    encode_bytes(&mut value, identity);
    encode_bytes(&mut value, payload);
    value
}

fn encode_application_authority_envelope_v0(
    state: &PocoApplicationAuthorityStateV0,
) -> Result<Vec<u8>> {
    let payload = state.encode_exact()?;
    let identity = POCO_APPLICATION_AUTHORITY_IDENTITY_V0;
    let length = 19usize
        .checked_add(identity.len())
        .and_then(|size| size.checked_add(payload.len()))
        .context("application authority envelope size overflow")?;
    ensure!(
        length <= crate::poco_snapshot::MAX_POCO_SNAPSHOT_VALUE_BYTES,
        "application authority envelope exceeds snapshot value bound"
    );
    let mut value = Vec::with_capacity(length);
    value.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    value.push(PocoSnapshotEntryKindV0::ApplicationAuthorityState as u8);
    value.extend_from_slice(&state.revision.to_be_bytes());
    encode_bytes(&mut value, identity);
    encode_bytes(&mut value, &payload);
    let logical_key = poco_application_authority_logical_key_v0();
    let decoded = decode_poco_snapshot_value_parts_v0_exact(
        PocoSnapshotEntryKindV0::ApplicationAuthorityState,
        &logical_key,
        &value,
    )?;
    ensure!(
        decoded.verified.revision() == state.revision
            && decoded.identity == identity
            && decoded.payload == payload,
        "application authority envelope self-check failed"
    );
    Ok(value)
}

fn semantic_identity_digest_v0(kind: PocoSnapshotEntryKindV0, identity: &[u8]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(identity.len().saturating_add(7));
    encoded.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    encoded.push(kind as u8);
    encode_bytes(&mut encoded, identity);
    domain_hash(SEMANTIC_IDENTITY_DOMAIN, &encoded)
}

fn joined_identity(parts: &[&[u8]]) -> Vec<u8> {
    let capacity = parts.iter().fold(0usize, |total, item| {
        total.saturating_add(4).saturating_add(item.len())
    });
    let mut identity = Vec::with_capacity(capacity);
    for part in parts {
        encode_bytes(&mut identity, part);
    }
    identity
}

fn meter_identity(meter_id: &[u8], meter_version: u32) -> Vec<u8> {
    let mut identity = Vec::with_capacity(meter_id.len().saturating_add(8));
    encode_bytes(&mut identity, meter_id);
    identity.extend_from_slice(&meter_version.to_be_bytes());
    identity
}

fn consumption_tuple_identity(body: &ConsumptionCertificateBodyV0) -> Vec<u8> {
    let mut identity = joined_identity(&[
        body.consumer_id().as_bytes(),
        body.provider_id().as_bytes(),
        body.task_id(),
    ]);
    identity.extend_from_slice(body.output_commitment());
    identity.extend_from_slice(&body.billing_start_height().get().to_be_bytes());
    identity.extend_from_slice(&body.billing_end_height().get().to_be_bytes());
    identity.extend_from_slice(&body.consumer_nonce().to_be_bytes());
    identity
}

pub(crate) fn registration_proof_bytes(payload: &[u8]) -> Result<&[u8]> {
    let mut cursor = SliceCursor::new(payload);
    cursor.bytes(MAX_OPAQUE_ID_BYTES)?;
    cursor.fixed(32)?;
    cursor.fixed(8)?;
    cursor.fixed(1)?;
    let proof = cursor.bytes(MAX_POCO_SEMANTIC_PAYLOAD_BYTES)?;
    cursor.finish()?;
    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
fn registration_history_head_v0(
    previous_head: [u8; 32],
    validator_id: &[u8],
    consensus_key: [u8; 32],
    nonce: u64,
    proof_digest: [u8; 32],
    decision_id: [u8; 32],
    target_height: u64,
) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    encoded.extend_from_slice(&previous_head);
    encode_bytes(&mut encoded, validator_id);
    encoded.extend_from_slice(&consensus_key);
    encoded.extend_from_slice(&nonce.to_be_bytes());
    encoded.extend_from_slice(&proof_digest);
    encoded.extend_from_slice(&decision_id);
    encoded.extend_from_slice(&target_height.to_be_bytes());
    domain_hash(APPLICATION_REGISTRATION_HISTORY_DOMAIN, &encoded)
}

fn ordered_mutation_root(mutations: &[OverlayMutationV0]) -> [u8; 32] {
    let bytes = mutations
        .iter()
        .map(OverlayMutationV0::canonical_bytes)
        .collect::<Vec<_>>();
    ordered_bytes_root(
        APPLICATION_MUTATION_DOMAIN,
        APPLICATION_MUTATION_NODE_DOMAIN,
        APPLICATION_MUTATION_ROOT_DOMAIN,
        &bytes,
    )
}

/// Recomputes the exact application mutation root from the exported canonical
/// compare-and-set mutations. This is a read-only conformance helper over the
/// same production domains and ordered-root implementation used by `seal`.
pub(crate) fn poco_application_mutation_root_v0(mutations: &[PocoSnapshotMutationV0]) -> [u8; 32] {
    let bytes = mutations
        .iter()
        .map(PocoSnapshotMutationV0::canonical_bytes)
        .collect::<Vec<_>>();
    ordered_bytes_root(
        APPLICATION_MUTATION_DOMAIN,
        APPLICATION_MUTATION_NODE_DOMAIN,
        APPLICATION_MUTATION_ROOT_DOMAIN,
        &bytes,
    )
}

fn ordered_bytes_root(
    leaf_domain: &[u8],
    node_domain: &[u8],
    root_domain: &[u8],
    items: &[Vec<u8>],
) -> [u8; 32] {
    let mut layer = items
        .iter()
        .map(|item| domain_hash(leaf_domain, item))
        .collect::<Vec<_>>();
    let mut level = 0u32;
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            let mut encoded = Vec::with_capacity(70);
            encoded.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
            encoded.extend_from_slice(&level.to_be_bytes());
            encoded.extend_from_slice(&left);
            encoded.extend_from_slice(&right);
            next.push(domain_hash(node_domain, &encoded));
        }
        layer = next;
        level = level.checked_add(1).expect("bounded Merkle level");
    }
    let mut encoded = Vec::with_capacity(39);
    encoded.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(items.len())
            .expect("application hard bound fits u32")
            .to_be_bytes(),
    );
    match layer.first() {
        Some(root) => {
            encoded.push(1);
            encoded.extend_from_slice(root);
        }
        None => encoded.push(0),
    }
    domain_hash(root_domain, &encoded)
}

fn domain_hash(domain: &[u8], encoded: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for frame in [HASH_PREFIX, domain, encoded] {
        hasher.update(
            u32::try_from(frame.len())
                .expect("bounded hash frame fits u32")
                .to_be_bytes(),
        );
        hasher.update(frame);
    }
    hasher.finalize().into()
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("bounded byte frame fits u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

fn encode_optional_bytes(output: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            output.push(1);
            encode_bytes(output, value);
        }
        None => output.push(0),
    }
}

fn exact_hash32_hex(value: &str) -> Result<[u8; 32]> {
    exact_hex(value, 32, 32, "Hash32")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Hash32 length mismatch"))
}

fn exact_opaque_hex(value: &str) -> Result<Vec<u8>> {
    exact_hex(value, 1, MAX_OPAQUE_ID_BYTES, "opaque ID")
}

fn exact_hex(value: &str, minimum: usize, maximum: usize, field: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len().is_multiple_of(2),
        "{field} hex has odd character count"
    );
    let bytes = hex::decode(value).with_context(|| format!("decode {field} hex"))?;
    ensure!(
        bytes.len() >= minimum && bytes.len() <= maximum,
        "{field} byte length is outside bound"
    );
    ensure!(hex::encode(&bytes) == value, "{field} hex is not canonical");
    Ok(bytes)
}

struct SliceCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn fixed(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .context("semantic payload offset overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("semantic payload is truncated")?;
        self.offset = end;
        Ok(value)
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let length =
            u32::from_be_bytes(self.fixed(4)?.try_into().expect("fixed byte length prefix"))
                as usize;
        ensure!(length <= maximum, "semantic byte field exceeds bound");
        self.fixed(length)
    }

    fn finish(self) -> Result<()> {
        ensure!(
            self.offset == self.bytes.len(),
            "semantic payload has trailing bytes"
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "poco_application_fixture_authoring.rs"]
pub(crate) mod fixture_authoring;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        poco_snapshot::{poco_snapshot_entry_key, poco_snapshot_manifest_key},
        poco_transition::take_and_validate_production_poco_projection_v0,
    };

    fn genesis_projection() -> ProductionPocoProjectionV0 {
        let entry = genesis_poco_application_authority_entry_v0().unwrap();
        let manifest =
            PocoSnapshotManifestV0::from_entries(Height::new(1), std::slice::from_ref(&entry))
                .unwrap();
        let mut live = BTreeMap::new();
        live.insert(
            poco_snapshot_entry_key(entry.kind, &entry.logical_key).unwrap(),
            entry.value,
        );
        live.insert(poco_snapshot_manifest_key().unwrap(), manifest.encode());
        take_and_validate_production_poco_projection_v0(1, &mut live)
            .unwrap()
            .unwrap()
    }

    fn minimal_operation() -> PocoApplicationOperationV0 {
        PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::PruneExpiredCertificate {
                certificate_id_hex: "11".repeat(32),
            },
            semantic_changes: vec![RawSemanticChangeV0 {
                kind: PocoSnapshotEntryKindV0::ConsumptionCertificate as u8,
                logical_key_hex: "22".repeat(32),
                next_value_hex: None,
            }],
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        }
    }

    fn context_at(target_height: u64) -> Result<AuthenticatedPocoApplicationContextV0> {
        AuthenticatedPocoApplicationContextV0::new(
            target_height - 1,
            [7; 32],
            Height::new(target_height),
            ChainId::from_static("trnm-poco-application-test"),
            GenesisHash::new([8; 32]),
            Epoch::new(0),
            ConsensusParametersV0::reference_shadow_v0(),
            [9; 32],
        )
    }

    fn validate_capacity_test_v0(
        context: &AuthenticatedPocoApplicationContextV0,
        overlay: &PocoApplicationOverlayV0,
        operation: &PocoApplicationOperationV0,
    ) -> Result<PreparedCapacityOperationV0> {
        let decision_preimage = decision_preimage_digest_v0(context, operation)?;
        validate_operation_capacity_before_clone_v0(context, overlay, operation, decision_preimage)
    }

    fn sequence_target_projection(
        target: &serde_json::Value,
    ) -> (u64, [u8; 32], ProductionPocoProjectionV0) {
        let source_version = target["version"].as_u64().unwrap();
        let source_root = hex::decode(target["jmt_root_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut live = BTreeMap::new();
        for entry in target["entries"].as_array().unwrap() {
            let kind = PocoSnapshotEntryKindV0::from_u8(
                u8::try_from(entry["kind"].as_u64().unwrap()).unwrap(),
            )
            .unwrap();
            let logical_key = hex::decode(entry["logical_key_hex"].as_str().unwrap()).unwrap();
            let value = hex::decode(entry["value_hex"].as_str().unwrap()).unwrap();
            assert!(live
                .insert(poco_snapshot_entry_key(kind, &logical_key).unwrap(), value)
                .is_none());
        }
        assert!(live
            .insert(
                poco_snapshot_manifest_key().unwrap(),
                hex::decode(target["manifest_hex"].as_str().unwrap()).unwrap(),
            )
            .is_none());
        let projection = take_and_validate_production_poco_projection_v0(source_version, &mut live)
            .unwrap()
            .unwrap();
        assert!(live.is_empty());
        (source_version, source_root, projection)
    }

    fn sequence_step_vector_fixture(
        sequence_id: &str,
        step_index: usize,
    ) -> (
        AuthenticatedPocoApplicationContextV0,
        ProductionPocoProjectionV0,
        Vec<u8>,
        PocoApplicationOperationV0,
    ) {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/protocol/poco-bft-v0/vectors/\
             poco-application-operation-sequences-v0.json"
        ))
        .unwrap();
        let sequence = vector["sequences"]
            .as_array()
            .unwrap()
            .iter()
            .find(|sequence| sequence["id"] == sequence_id)
            .unwrap();
        let steps = sequence["steps"].as_array().unwrap();
        let step = &steps[step_index];
        let (source_version, source_root, projection) = if step_index == 0 {
            let (_, source_version, source_root, projection) =
                crate::poco_application_evidence::authenticated_tree_from_sequence_initial_v0(
                    &sequence["initial"],
                );
            (source_version, source_root, projection)
        } else {
            sequence_target_projection(&steps[step_index - 1]["rust_event"]["target"])
        };
        let raw = crate::poco_application_evidence::application_sequence_raw_operations_v0(step)
            .into_iter()
            .next()
            .unwrap();
        let operation = PocoApplicationOperationV0::decode_exact(&raw).unwrap();
        let vector_context = &step["context"];
        assert_eq!(
            vector_context["source_version"].as_u64(),
            Some(source_version)
        );
        assert_eq!(
            vector_context["source_root_hex"].as_str().unwrap(),
            hex::encode(source_root),
        );
        let parameters = decode_consensus_parameters_v0_exact(
            &hex::decode(
                vector_context["active_parameters_cev0_hex"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let context = AuthenticatedPocoApplicationContextV0::new(
            source_version,
            source_root,
            Height::new(vector_context["target_height"].as_u64().unwrap()),
            ChainId::new(vector_context["chain_id_utf8"].as_str().unwrap()).unwrap(),
            GenesisHash::new(
                hex::decode(vector_context["genesis_hash_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            Epoch::new(vector_context["active_epoch"].as_u64().unwrap()),
            parameters,
            hex::decode(
                vector_context["authority_signer_commitment_hex"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap(),
        )
        .unwrap();
        (context, projection, raw, operation)
    }

    fn sequence_vector_fixture(
        sequence_id: &str,
    ) -> (
        AuthenticatedPocoApplicationContextV0,
        ProductionPocoProjectionV0,
        Vec<u8>,
        PocoApplicationOperationV0,
    ) {
        sequence_step_vector_fixture(sequence_id, 0)
    }

    fn assert_block_overlay_unchanged(
        actual: &PocoApplicationBlockOverlayV0,
        expected: &PocoApplicationBlockOverlayV0,
    ) {
        assert_eq!(
            actual.context.source_version,
            expected.context.source_version
        );
        assert_eq!(actual.context.source_root, expected.context.source_root);
        assert_eq!(actual.context.target_height, expected.context.target_height);
        assert_eq!(actual.context.chain_id, expected.context.chain_id);
        assert_eq!(actual.context.genesis_hash, expected.context.genesis_hash);
        assert_eq!(actual.context.active_epoch, expected.context.active_epoch);
        assert_eq!(
            actual.context.active_parameters,
            expected.context.active_parameters
        );
        assert_eq!(
            actual.context.authority_signer_commitment,
            expected.context.authority_signer_commitment
        );
        assert_eq!(actual.overlay.entries, expected.overlay.entries);
        assert_eq!(
            actual.overlay.source_authority_value,
            expected.overlay.source_authority_value
        );
        assert_eq!(actual.overlay.authority, expected.overlay.authority);
        assert_eq!(actual.overlay.accumulator, expected.overlay.accumulator);
        let actual_mutations = actual
            .overlay
            .mutations
            .iter()
            .map(|(key, mutation)| (key.clone(), mutation.canonical_bytes()))
            .collect::<Vec<_>>();
        let expected_mutations = expected
            .overlay
            .mutations
            .iter()
            .map(|(key, mutation)| (key.clone(), mutation.canonical_bytes()))
            .collect::<Vec<_>>();
        assert_eq!(actual_mutations, expected_mutations);
        assert_eq!(actual.overlay.operation_ids, expected.overlay.operation_ids);
        assert_eq!(actual.raw_operations, expected.raw_operations);
        assert_eq!(
            actual.aggregate_operation_bytes,
            expected.aggregate_operation_bytes
        );
    }

    fn consumer_key_semantic_payload(
        consumer_id: &[u8],
        consumer_key_id: &[u8],
        public_key: [u8; 32],
        active_from_height: u64,
        revoked_at_height: Option<u64>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        encode_bytes(&mut payload, consumer_id);
        encode_bytes(&mut payload, consumer_key_id);
        payload.extend_from_slice(&public_key);
        payload.extend_from_slice(&active_from_height.to_be_bytes());
        match revoked_at_height {
            Some(height) => {
                payload.push(1);
                payload.extend_from_slice(&height.to_be_bytes());
            }
            None => payload.push(0),
        }
        payload
    }

    fn bind_consumer_key_revocation_decision_v0(
        context: &AuthenticatedPocoApplicationContextV0,
        operation: &mut PocoApplicationOperationV0,
    ) {
        operation.nullifier_insertions.clear();
        let preimage = decision_preimage_digest_v0(context, operation).unwrap();
        let decision = derived_decision_id_v0(preimage, b"revoke-consumer-key");
        let PocoApplicationOperationBodyV0::RevokeConsumerKey {
            decision_id_hex, ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *decision_id_hex = hex::encode(decision);
        let key =
            derive_poco_nullifier_key_v0(PocoNullifierFamilyV0::ConsumerKeyDecision, decision);
        let siblings = std::array::from_fn(|level| {
            crate::poco_nullifier::poco_nullifier_default_hash_v0(level)
                .expect("fixed nullifier level is in range")
        });
        let proof = PocoNullifierProofV0::new(key, siblings);
        operation.nullifier_insertions = vec![RawNullifierInsertionV0 {
            family: PocoNullifierFamilyV0::ConsumerKeyDecision.code(),
            identifier_hex: hex::encode(decision),
            proof_hex: hex::encode(proof.canonical_bytes()),
        }];
    }

    fn bind_open_challenge_decisions_v0(
        context: &AuthenticatedPocoApplicationContextV0,
        operation: &mut PocoApplicationOperationV0,
    ) {
        operation.nullifier_insertions.clear();
        let preimage = decision_preimage_digest_v0(context, operation).unwrap();
        let challenge_id = derived_decision_id_v0(preimage, b"challenge-id");
        let opening_decision = derived_decision_id_v0(preimage, b"open-challenge");
        let PocoApplicationOperationBodyV0::OpenChallenge {
            challenge_id_hex,
            opening_decision_id_hex,
            ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *challenge_id_hex = hex::encode(challenge_id);
        *opening_decision_id_hex = hex::encode(opening_decision);
    }

    fn bind_define_meter_decision_v0(
        context: &AuthenticatedPocoApplicationContextV0,
        operation: &mut PocoApplicationOperationV0,
    ) {
        let preimage = decision_preimage_digest_v0(context, operation).unwrap();
        let decision = derived_decision_id_v0(preimage, b"define-meter");
        let PocoApplicationOperationBodyV0::DefineMeterPolicy {
            decision_id_hex, ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *decision_id_hex = hex::encode(decision);
    }

    fn bind_fund_settlement_decision_v0(
        context: &AuthenticatedPocoApplicationContextV0,
        operation: &mut PocoApplicationOperationV0,
    ) {
        let preimage = decision_preimage_digest_v0(context, operation).unwrap();
        let decision = derived_decision_id_v0(preimage, b"fund-settlement");
        let PocoApplicationOperationBodyV0::FundSettlement {
            funding_decision_id_hex,
            ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *funding_decision_id_hex = hex::encode(decision);
    }

    fn define_meter_capacity_fixture(
        meter_policy_count: usize,
    ) -> (PocoApplicationBlockOverlayV0, PocoApplicationOperationV0) {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let operation = PocoApplicationOperationV0::decode_exact(
            &block.test_define_meter_operation_v0().unwrap(),
        )
        .unwrap();
        let mut meter_policies = max_capacity_authority_state().meter_policies;
        meter_policies.truncate(meter_policy_count);
        block.overlay.authority.meter_policies = meter_policies;
        (block, operation)
    }

    fn authorize_consumer_key_capacity_fixture(
        consumer_key_count: usize,
    ) -> (PocoApplicationBlockOverlayV0, PocoApplicationOperationV0) {
        let (context, projection, _, operation) =
            sequence_vector_fixture("certificate_challenge_rejected");
        let PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
            ..
        } = &operation.body
        else {
            unreachable!();
        };
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let mut consumer_keys = max_capacity_authority_state().consumer_keys;
        consumer_keys.truncate(consumer_key_count);
        assert!(consumer_keys.iter().all(|authority| {
            authority.consumer_id_hex != *consumer_id_hex
                || authority.consumer_key_id_hex != *consumer_key_id_hex
        }));
        block.overlay.authority.consumer_keys = consumer_keys;
        (block, operation)
    }

    fn fund_settlement_capacity_fixture(
        reservation_count: usize,
    ) -> (PocoApplicationBlockOverlayV0, PocoApplicationOperationV0) {
        let (context, projection, _, operation) = sequence_vector_fixture("release_refund_replay");
        assert!(matches!(
            &operation.body,
            PocoApplicationOperationBodyV0::FundSettlement { .. }
        ));
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let mut reservations = max_capacity_authority_state().funded_unused_reservations;
        reservations.truncate(reservation_count);
        let PocoApplicationOperationBodyV0::FundSettlement {
            certificate_id_hex, ..
        } = &operation.body
        else {
            unreachable!();
        };
        assert!(reservations
            .iter()
            .all(|reservation| reservation.certificate_id_hex != *certificate_id_hex));
        block.overlay.authority.funded_unused_reservations = reservations;
        (block, operation)
    }

    fn open_challenge_capacity_fixture(
        pending_count: usize,
    ) -> (PocoApplicationBlockOverlayV0, PocoApplicationOperationV0) {
        let (context, projection, _, operation) =
            sequence_step_vector_fixture("certificate_challenge_rejected", 2);
        let PocoApplicationOperationBodyV0::OpenChallenge {
            certificate_id_hex,
            challenge_id_hex,
            ..
        } = &operation.body
        else {
            unreachable!();
        };
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        assert!(block
            .overlay
            .authority
            .active_certificates
            .iter()
            .any(|certificate| certificate.certificate_id_hex == *certificate_id_hex));
        let mut pending = max_capacity_authority_state().pending_challenges;
        pending.truncate(pending_count);
        assert!(pending.iter().all(|item| {
            item.challenge_id_hex != *challenge_id_hex
                && item.certificate_id_hex != *certificate_id_hex
        }));
        block.overlay.authority.pending_challenges = pending;
        (block, operation)
    }

    fn propose_governance_capacity_fixture(
        pending_count: usize,
    ) -> (PocoApplicationBlockOverlayV0, PocoApplicationOperationV0) {
        let (context, projection, _, operation) =
            sequence_step_vector_fixture("governance_propose_approve", 0);
        let PocoApplicationOperationBodyV0::ProposeGovernance { target_epoch, .. } =
            &operation.body
        else {
            unreachable!();
        };
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let mut pending = max_capacity_authority_state().pending_governance_proposals;
        pending.truncate(pending_count);
        assert!(pending
            .iter()
            .all(|proposal| proposal.target_epoch != *target_epoch));
        block.overlay.authority.pending_governance_proposals = pending;
        (block, operation)
    }

    fn bind_propose_governance_decision_v0(
        context: &AuthenticatedPocoApplicationContextV0,
        operation: &mut PocoApplicationOperationV0,
    ) {
        let preimage = decision_preimage_digest_v0(context, operation).unwrap();
        let decision = derived_decision_id_v0(preimage, b"propose-governance");
        let PocoApplicationOperationBodyV0::ProposeGovernance {
            proposal_decision_id_hex,
            ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *proposal_decision_id_hex = hex::encode(decision);
    }

    fn approve_governance_capacity_fixture(
        finalized_count: usize,
    ) -> (PocoApplicationBlockOverlayV0, PocoApplicationOperationV0) {
        let (context, projection, _, operation) =
            sequence_step_vector_fixture("governance_propose_approve", 1);
        let PocoApplicationOperationBodyV0::ApproveGovernance { target_epoch, .. } =
            &operation.body
        else {
            unreachable!();
        };
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let mut finalized = max_capacity_authority_state().finalized_governance_approvals;
        finalized.truncate(finalized_count);
        assert!(finalized
            .iter()
            .all(|approval| approval.target_epoch != *target_epoch));
        block.overlay.authority.finalized_governance_approvals = finalized;
        (block, operation)
    }

    fn bind_approve_governance_decision_v0(
        context: &AuthenticatedPocoApplicationContextV0,
        operation: &mut PocoApplicationOperationV0,
    ) {
        let preimage = decision_preimage_digest_v0(context, operation).unwrap();
        let decision = derived_decision_id_v0(preimage, b"approve-governance");
        let PocoApplicationOperationBodyV0::ApproveGovernance {
            decision_id_hex, ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *decision_id_hex = hex::encode(decision);
    }

    fn poison_raw_nullifier_roots_v0(raw: &mut [RawNullifierInsertionV0]) {
        for raw in raw {
            let family = PocoNullifierFamilyV0::from_u8(raw.family).unwrap();
            let identifier = exact_hash32_hex(&raw.identifier_hex).unwrap();
            let key = derive_poco_nullifier_key_v0(family, identifier);
            raw.proof_hex =
                hex::encode(PocoNullifierProofV0::new(key, [[0x55; 32]; 256]).canonical_bytes());
        }
    }

    fn poison_nullifier_roots_v0(operation: &mut PocoApplicationOperationV0) {
        poison_raw_nullifier_roots_v0(&mut operation.nullifier_non_membership_checks);
        poison_raw_nullifier_roots_v0(&mut operation.nullifier_insertions);
    }

    fn consumer_key_revocation_fixture(
    ) -> (PocoApplicationBlockOverlayV0, PocoApplicationOperationV0) {
        let (context, projection, _, _) = sequence_vector_fixture("consumer_key_prune_replay");
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        assert_eq!(block.overlay.authority.consumer_keys.len(), 1);
        let key_authority = block.overlay.authority.consumer_keys[0].clone();
        let consumer_id = exact_opaque_hex(&key_authority.consumer_id_hex).unwrap();
        let consumer_key_id = exact_opaque_hex(&key_authority.consumer_key_id_hex).unwrap();
        let public_key = exact_hash32_hex(&key_authority.public_key_hex).unwrap();
        let identity = joined_identity(&[&consumer_id, &consumer_key_id]);
        let logical_key = semantic_identity_digest_v0(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            &identity,
        );
        let map_key = (
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            logical_key.to_vec(),
        );
        let current = owned_semantic_parts(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            &logical_key,
            block.overlay.entries.get(&map_key).unwrap(),
        )
        .unwrap();
        let active_payload = consumer_key_semantic_payload(
            &consumer_id,
            &consumer_key_id,
            public_key,
            key_authority.active_from_height,
            None,
        );
        let active_value = encode_test_semantic_envelope_v0(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            current.revision,
            &identity,
            &active_payload,
        );
        block.overlay.entries.insert(map_key, active_value);
        block.overlay.authority.consumer_keys[0].revoked_at_height = None;
        block.overlay.authority.consumer_keys[0].revocation_decision_id_hex = None;
        let empty_accumulator = PocoNullifierAccumulatorV0::empty();
        block.overlay.accumulator = empty_accumulator;
        block.overlay.authority.set_accumulator(empty_accumulator);
        assert!(block.context.target_height.get() > key_authority.active_from_height);

        let revoked_payload = consumer_key_semantic_payload(
            &consumer_id,
            &consumer_key_id,
            public_key,
            key_authority.active_from_height,
            Some(block.context.target_height.get()),
        );
        let next_value = encode_test_semantic_envelope_v0(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            current.revision + 1,
            &identity,
            &revoked_payload,
        );
        let mut operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: block.context.target_height.get(),
            expected_state_revision: block.overlay.authority.revision,
            body: PocoApplicationOperationBodyV0::RevokeConsumerKey {
                consumer_id_hex: key_authority.consumer_id_hex,
                consumer_key_id_hex: key_authority.consumer_key_id_hex,
                public_key_hex: key_authority.public_key_hex,
                active_from_height: key_authority.active_from_height,
                revoked_at_height: block.context.target_height.get(),
                decision_id_hex: "00".repeat(32),
            },
            semantic_changes: vec![RawSemanticChangeV0 {
                kind: PocoSnapshotEntryKindV0::ConsumerKeyAuthorization as u8,
                logical_key_hex: hex::encode(logical_key),
                next_value_hex: Some(hex::encode(next_value)),
            }],
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        bind_consumer_key_revocation_decision_v0(&block.context, &mut operation);
        (block, operation)
    }

    fn meter_policy() -> MeterAuthorityPolicyV0 {
        MeterAuthorityPolicyV0 {
            meter_id_hex: "01".to_string(),
            meter_version: 1,
            task_id_hex: "02".to_string(),
            output_commitment_hex: None,
            unit_scale: CanonicalU128V0::new(1),
            evidence_policy: MeterEvidencePolicyV0::Optional,
            per_certificate_cap: CanonicalU128V0::new(100),
            rolling_cap: CanonicalU128V0::new(1_000),
            rolling_epoch_span: 1,
            retention_blocks: 1,
            active_from_height: 1,
            retired_at_height: None,
        }
    }

    fn max_opaque_hex(tag: u16) -> String {
        let mut value = [0xff; MAX_OPAQUE_ID_BYTES];
        value[..2].copy_from_slice(&tag.to_be_bytes());
        hex::encode(value)
    }

    fn tagged_hash_hex(tag: u16) -> String {
        let mut value = [0xff; 32];
        value[..2].copy_from_slice(&tag.to_be_bytes());
        hex::encode(value)
    }

    fn max_validator_history(tag: u16) -> ValidatorRegistrationHistoryV0 {
        let validator_id = exact_opaque_hex(&max_opaque_hex(tag)).unwrap();
        let previous_head = exact_hash32_hex(&tagged_hash_hex(tag + 100)).unwrap();
        let consensus_key = exact_hash32_hex(&tagged_hash_hex(tag + 200)).unwrap();
        let proof_digest = exact_hash32_hex(&tagged_hash_hex(tag + 300)).unwrap();
        let decision_id = exact_hash32_hex(&tagged_hash_hex(tag + 400)).unwrap();
        let history_head = registration_history_head_v0(
            previous_head,
            &validator_id,
            consensus_key,
            u64::MAX,
            proof_digest,
            decision_id,
            1,
        );
        ValidatorRegistrationHistoryV0 {
            validator_id_hex: hex::encode(validator_id),
            history_head_hex: hex::encode(history_head),
            max_registration_nonce: u64::MAX,
            consensus_key_hex: hex::encode(consensus_key),
            current_proof_digest_hex: hex::encode(proof_digest),
            previous_history_head_hex: hex::encode(previous_head),
            registration_decision_id_hex: hex::encode(decision_id),
            registration_height: 1,
            retired_key_count: u64::MAX,
            revoked_at_height: None,
            revocation_decision_id_hex: None,
        }
    }

    fn max_active_certificate(
        certificate_tag: u16,
        consumer_tag: u16,
        history: &ValidatorRegistrationHistoryV0,
    ) -> ActiveCertificateAuthorityV0 {
        let acceptance_decision_id_hex = tagged_hash_hex(certificate_tag + 1_000);
        ActiveCertificateAuthorityV0 {
            certificate_id_hex: tagged_hash_hex(certificate_tag),
            consumer_id_hex: max_opaque_hex(consumer_tag),
            consumer_key_id_hex: max_opaque_hex(consumer_tag + 100),
            provider_id_hex: history.validator_id_hex.clone(),
            task_id_hex: max_opaque_hex(consumer_tag + 200),
            meter_id_hex: max_opaque_hex(consumer_tag + 300),
            meter_version: u32::MAX,
            settlement_commitment_hex: tagged_hash_hex(certificate_tag + 1),
            settlement_finalized_height: 1,
            consumed_units: CanonicalU128V0::new(u128::MAX),
            evidence_root_hex: Some(tagged_hash_hex(certificate_tag + 2)),
            relationship_class: RelationshipClassV0::Reciprocal as u8,
            relationship_key_hex: tagged_hash_hex(certificate_tag + 3),
            provider_consensus_key_hex: history.consensus_key_hex.clone(),
            provider_registration_nonce: history.max_registration_nonce,
            provider_proof_digest_hex: history.current_proof_digest_hex.clone(),
            provider_registration_decision_id_hex: history.registration_decision_id_hex.clone(),
            provider_registration_height: history.registration_height,
            provider_registration_history_head_hex: history.history_head_hex.clone(),
            acceptance_decision_id_hex: acceptance_decision_id_hex.clone(),
            funding_decision_id_hex: tagged_hash_hex(certificate_tag + 4),
            meter_decision_id_hex: tagged_hash_hex(certificate_tag + 5),
            evidence_decision_id_hex: tagged_hash_hex(certificate_tag + 6),
            accepted_height: 2,
            finalized_epoch: u64::MAX,
            tuple_key_hex: tagged_hash_hex(certificate_tag + 7),
            prunable_after_height: u64::MAX,
            lifecycle: CertificateAuthorityLifecycleV0::Accepted,
            lifecycle_effective_height: 2,
            lifecycle_decision_id_hex: acceptance_decision_id_hex,
            semantic_keys: [
                PocoSnapshotEntryKindV0::ConsumptionCertificate,
                PocoSnapshotEntryKindV0::UniqueConsumptionTuple,
                PocoSnapshotEntryKindV0::Settlement,
                PocoSnapshotEntryKindV0::MeasurementEvidence,
                PocoSnapshotEntryKindV0::RevocationOrChallenge,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, kind)| SemanticKeyRefV0 {
                kind: kind as u8,
                logical_key_hex: tagged_hash_hex(certificate_tag + 20 + index as u16),
            })
            .collect(),
        }
    }

    fn max_capacity_authority_state() -> PocoApplicationAuthorityStateV0 {
        let mut state = PocoApplicationAuthorityStateV0::empty();
        state.revision = u64::MAX;
        state.last_target_height = u64::MAX;
        for index in 0..MAX_CONSUMER_KEY_AUTHORITIES {
            let consumer_tag = 10 + index as u16;
            let mut nonce_watermarks = Vec::new();
            for provider_offset in 0..2u16 {
                nonce_watermarks.push(ConsumerNonceWatermarkV0 {
                    provider_id_hex: max_opaque_hex(50 + (index as u16 * 2) + provider_offset),
                    max_accepted_nonce: u64::MAX,
                    logical_key_hex: tagged_hash_hex(100 + (index as u16 * 2) + provider_offset),
                });
            }
            state.consumer_keys.push(ConsumerKeyAuthorityV0 {
                consumer_id_hex: max_opaque_hex(consumer_tag),
                consumer_key_id_hex: max_opaque_hex(consumer_tag + 100),
                public_key_hex: tagged_hash_hex(consumer_tag + 200),
                active_from_height: 1,
                authorization_decision_id_hex: tagged_hash_hex(consumer_tag + 300),
                revoked_at_height: Some(u64::MAX),
                revocation_decision_id_hex: Some(tagged_hash_hex(consumer_tag + 400)),
                nonce_watermarks,
            });
        }
        for index in 0..MAX_METER_POLICIES {
            state.meter_policies.push(MeterAuthorityPolicyV0 {
                meter_id_hex: max_opaque_hex(200 + index as u16),
                meter_version: u32::MAX,
                task_id_hex: max_opaque_hex(300 + index as u16),
                output_commitment_hex: Some(tagged_hash_hex(400 + index as u16)),
                unit_scale: CanonicalU128V0::new(u128::MAX),
                evidence_policy: MeterEvidencePolicyV0::Required,
                per_certificate_cap: CanonicalU128V0::new(u128::MAX),
                rolling_cap: CanonicalU128V0::new(u128::MAX),
                rolling_epoch_span: u64::MAX,
                retention_blocks: u64::MAX,
                active_from_height: 1,
                retired_at_height: Some(u64::MAX),
            });
            for window in [u64::MAX - 1, u64::MAX] {
                state.meter_usage.push(MeterRollingUsageV0 {
                    meter_id_hex: max_opaque_hex(200 + index as u16),
                    meter_version: u32::MAX,
                    window_epoch: window,
                    consumed_units: CanonicalU128V0::new(u128::MAX),
                });
            }
        }
        for index in 0..8u16 {
            state
                .consumer_provider_usage
                .push(ConsumerProviderRollingUsageV0 {
                    consumer_id_hex: max_opaque_hex(1_000 + index),
                    provider_id_hex: max_opaque_hex(1_100 + index),
                    window_epoch: u64::MAX,
                    consumed_units: CanonicalU128V0::new(u128::MAX),
                });
            state.task_provider_usage.push(TaskProviderRollingUsageV0 {
                task_id_hex: max_opaque_hex(1_200 + index),
                provider_id_hex: max_opaque_hex(1_300 + index),
                window_epoch: u64::MAX,
                consumed_units: CanonicalU128V0::new(u128::MAX),
            });
            state.provider_usage.push(ProviderRollingUsageV0 {
                provider_id_hex: max_opaque_hex(1_400 + index),
                window_epoch: u64::MAX,
                consumed_units: CanonicalU128V0::new(u128::MAX),
            });
        }
        for index in 0..MAX_FUNDED_UNUSED_RESERVATIONS {
            state
                .funded_unused_reservations
                .push(FundedUnusedReservationV0 {
                    certificate_id_hex: tagged_hash_hex(2_000 + index as u16),
                    settlement_commitment_hex: tagged_hash_hex(2_100 + index as u16),
                    funding_decision_id_hex: tagged_hash_hex(2_200 + index as u16),
                    finalized_height: 1,
                    reserved_units: CanonicalU128V0::new(u128::MAX),
                });
        }
        for index in 0..MAX_VALIDATOR_REGISTRATION_HISTORIES {
            state
                .validator_registration_history
                .push(max_validator_history(3_000 + index as u16));
        }
        for index in 0..MAX_ACTIVE_CERTIFICATES {
            state.active_certificates.push(max_active_certificate(
                4_000 + index as u16,
                4_100 + index as u16,
                &state.validator_registration_history[index],
            ));
        }
        for index in 0..MAX_PENDING_CHALLENGES {
            state.pending_challenges.push(PendingChallengeAuthorityV0 {
                challenge_id_hex: tagged_hash_hex(5_000 + index as u16),
                certificate_id_hex: state.active_certificates[index].certificate_id_hex.clone(),
                opening_decision_id_hex: tagged_hash_hex(5_100 + index as u16),
                opened_height: 3,
            });
        }
        for index in 0..MAX_PENDING_GOVERNANCE_PROPOSALS {
            state
                .pending_governance_proposals
                .push(PendingGovernanceProposalV0 {
                    target_epoch: u64::MAX - 3 + index as u64,
                    proposal_decision_id_hex: tagged_hash_hex(6_000 + index as u16),
                    proposed_height: 1,
                    phase: crate::poco_semantics::RolloutPhaseV0::Full as u8,
                    parameters_hash_hex: tagged_hash_hex(6_100 + index as u16),
                    activation_height: u64::MAX,
                });
        }
        for index in 0..MAX_FINALIZED_GOVERNANCE_APPROVALS {
            state
                .finalized_governance_approvals
                .push(FinalizedGovernanceApprovalV0 {
                    target_epoch: u64::MAX - 1 + index as u64,
                    phase: crate::poco_semantics::RolloutPhaseV0::Full as u8,
                    proposal_decision_id_hex: tagged_hash_hex(6_200 + index as u16),
                    proposed_height: 1,
                    decision_id_hex: tagged_hash_hex(6_300 + index as u16),
                    approval_height: 2,
                    parameters_hash_hex: tagged_hash_hex(6_400 + index as u16),
                    activation_height: u64::MAX,
                });
        }
        state.validate().unwrap();
        state
    }

    fn overlay_with_authority(
        authority: PocoApplicationAuthorityStateV0,
    ) -> PocoApplicationOverlayV0 {
        PocoApplicationOverlayV0 {
            entries: BTreeMap::new(),
            source_authority_value: Vec::new(),
            accumulator: authority.accumulator().unwrap(),
            authority,
            mutations: BTreeMap::new(),
            operation_ids: BTreeSet::new(),
        }
    }

    #[test]
    fn authority_state_and_genesis_entry_are_exact_and_canonical() {
        let state = PocoApplicationAuthorityStateV0::empty();
        assert_eq!(state.revision(), 1);
        assert_eq!(state.last_target_height(), 0);
        assert_eq!(state.nullifier_count(), 0);
        assert_eq!(
            state.nullifier_root().unwrap(),
            PocoNullifierAccumulatorV0::empty().root()
        );
        let encoded = state.encode_exact().unwrap();
        assert_eq!(
            PocoApplicationAuthorityStateV0::decode_exact(&encoded).unwrap(),
            state
        );
        let mut trailing = encoded.clone();
        trailing.push(b'\n');
        assert!(PocoApplicationAuthorityStateV0::decode_exact(&trailing).is_err());
        let mut with_unknown: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        with_unknown["unknown"] = serde_json::json!(1);
        assert!(PocoApplicationAuthorityStateV0::decode_exact(
            &serde_json::to_vec(&with_unknown).unwrap()
        )
        .is_err());
        assert!(PocoApplicationAuthorityStateV0::decode_exact(&vec![
            b' ';
            MAX_POCO_SEMANTIC_PAYLOAD_BYTES
                + 1
        ])
        .is_err());

        let entry = genesis_poco_application_authority_entry_v0().unwrap();
        assert_eq!(
            entry.kind,
            PocoSnapshotEntryKindV0::ApplicationAuthorityState
        );
        assert_eq!(
            entry.logical_key,
            poco_application_authority_logical_key_v0()
        );
        let parts =
            decode_poco_snapshot_value_parts_v0_exact(entry.kind, &entry.logical_key, &entry.value)
                .unwrap();
        assert_eq!(parts.verified.revision(), 1);
        assert_eq!(parts.identity, poco_application_authority_identity_v0());
    }

    #[test]
    fn operation_codec_rejects_noncanonical_and_unknown_fields() {
        let operation = minimal_operation();
        let encoded = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            PocoApplicationOperationV0::decode_exact(&encoded).unwrap(),
            operation
        );
        let mut trailing = encoded.clone();
        trailing.push(b' ');
        assert!(PocoApplicationOperationV0::decode_exact(&trailing).is_err());
        let mut unknown: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        unknown["unknown"] = serde_json::json!(true);
        assert!(
            PocoApplicationOperationV0::decode_exact(&serde_json::to_vec(&unknown).unwrap())
                .is_err()
        );
    }

    #[test]
    fn prune_capacity_preflight_preserves_typed_negative_facts_before_clone() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let missing_certificate = minimal_operation();
        let missing_certificate_raw = serde_json::to_vec(&missing_certificate).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&missing_certificate_raw, &missing_certificate),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );

        let mut malformed_certificate = missing_certificate.clone();
        let PocoApplicationOperationBodyV0::PruneExpiredCertificate { certificate_id_hex } =
            &mut malformed_certificate.body
        else {
            unreachable!();
        };
        *certificate_id_hex = "0".to_string();
        let malformed_certificate_raw = serde_json::to_vec(&malformed_certificate).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&malformed_certificate_raw, &malformed_certificate),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );

        let mut missing_validator = missing_certificate.clone();
        missing_validator.body = PocoApplicationOperationBodyV0::PruneRevokedValidatorHistory {
            validator_id_hex: hex::encode(b"missing-validator"),
        };
        let missing_validator_raw = serde_json::to_vec(&missing_validator).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&missing_validator_raw, &missing_validator),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );

        let mut malformed_validator = missing_validator.clone();
        let PocoApplicationOperationBodyV0::PruneRevokedValidatorHistory { validator_id_hex } =
            &mut malformed_validator.body
        else {
            unreachable!();
        };
        *validator_id_hex = "0".to_string();
        let malformed_validator_raw = serde_json::to_vec(&malformed_validator).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&malformed_validator_raw, &malformed_validator),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ValidatorRule,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn validator_registration_semantics_precede_capacity_and_clone() {
        let authority = max_capacity_authority_state();
        let overlay = overlay_with_authority(authority.clone());
        let mut operation = minimal_operation();
        operation.body = PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex: authority.validator_registration_history[0]
                .validator_id_hex
                .clone(),
            target_epoch: 0,
            registration_decision_id_hex: "11".repeat(32),
        };
        let error = validate_capacity_test_v0(&context_at(2).unwrap(), &overlay, &operation)
            .expect_err("duplicate validator identity must precede capacity");
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ValidatorRule,
            )),
        );
        assert_eq!(overlay.authority, authority);
        assert!(overlay.operation_ids.is_empty());
        assert!(overlay.mutations.is_empty());

        let mut wrong_semantic_kind = operation;
        let PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex, ..
        } = &mut wrong_semantic_kind.body
        else {
            unreachable!();
        };
        *validator_id_hex = hex::encode(b"fresh-validator-at-full-capacity");
        let error =
            validate_capacity_test_v0(&context_at(2).unwrap(), &overlay, &wrong_semantic_kind)
                .expect_err("wrong validator semantic kind must precede capacity");
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ValidatorRule,
            )),
        );
        assert_eq!(overlay.authority, authority);
        assert!(overlay.operation_ids.is_empty());
        assert!(overlay.mutations.is_empty());
    }

    #[test]
    fn register_validator_capacity_prepares_crypto_and_late_proofs() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (saturated, saturated_raw, saturated_operation) =
            fixture_authoring::register_validator_capacity_fixture_v0(
                MAX_VALIDATOR_REGISTRATION_HISTORIES,
            )
            .unwrap();
        assert_eq!(
            saturated
                .overlay
                .authority
                .validator_registration_history
                .len(),
            MAX_VALIDATOR_REGISTRATION_HISTORIES,
        );
        assert_eq!(
            saturated.operation_count(),
            MAX_VALIDATOR_REGISTRATION_HISTORIES,
        );
        let mut canonical_cap = saturated.clone();
        let before = canonical_cap.clone();
        assert_eq!(
            canonical_cap.apply_decoded_exact(&saturated_raw, &saturated_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&canonical_cap, &before);

        let (below_cap, below_cap_raw, below_cap_operation) =
            fixture_authoring::register_validator_capacity_fixture_v0(
                MAX_VALIDATOR_REGISTRATION_HISTORIES - 1,
            )
            .unwrap();
        assert_eq!(
            below_cap
                .overlay
                .authority
                .validator_registration_history
                .len(),
            MAX_VALIDATOR_REGISTRATION_HISTORIES - 1,
        );

        let rebind_decision =
            |context: &AuthenticatedPocoApplicationContextV0,
             operation: &mut PocoApplicationOperationV0| {
                let preimage = decision_preimage_digest_v0(context, operation).unwrap();
                let PocoApplicationOperationBodyV0::RegisterValidator {
                    registration_decision_id_hex,
                    ..
                } = &mut operation.body
                else {
                    unreachable!();
                };
                *registration_decision_id_hex =
                    hex::encode(derived_decision_id_v0(preimage, b"register-validator"));
            };
        let poison_strict_pop =
            |context: &AuthenticatedPocoApplicationContextV0,
             operation: &mut PocoApplicationOperationV0| {
                let raw_change = &mut operation.semantic_changes[0];
                let kind = PocoSnapshotEntryKindV0::from_u8(raw_change.kind).unwrap();
                let logical_key = exact_hash32_hex(&raw_change.logical_key_hex).unwrap();
                let next_value =
                    hex::decode(raw_change.next_value_hex.as_deref().unwrap()).unwrap();
                let next = owned_semantic_parts(kind, &logical_key, &next_value).unwrap();
                let mut payload = next.payload;
                *payload.last_mut().unwrap() ^= 1;
                raw_change.next_value_hex = Some(hex::encode(encode_test_semantic_envelope_v0(
                    kind,
                    next.revision,
                    &next.identity,
                    &payload,
                )));
                rebind_decision(context, operation);
            };

        let mut saturated_bad_pop = saturated.clone();
        let mut bad_pop_operation = saturated_operation.clone();
        poison_strict_pop(&saturated_bad_pop.context, &mut bad_pop_operation);
        let bad_pop_raw = serde_json::to_vec(&bad_pop_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_pop_raw).unwrap();
        let before = saturated_bad_pop.clone();
        assert_eq!(
            saturated_bad_pop.apply_decoded_exact(&bad_pop_raw, &bad_pop_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_pop, &before);

        let mut below_cap_bad_pop = below_cap.clone();
        let mut bad_pop_operation = below_cap_operation.clone();
        poison_strict_pop(&below_cap_bad_pop.context, &mut bad_pop_operation);
        let bad_pop_raw = serde_json::to_vec(&bad_pop_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_pop_raw).unwrap();
        let before = below_cap_bad_pop.clone();
        assert_eq!(
            below_cap_bad_pop.apply_decoded_exact(&bad_pop_raw, &bad_pop_operation),
            Err(DeterministicallyInvalid(Invalid::CryptographicProof)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_pop, &before);

        let mutate_epoch = |operation: &mut PocoApplicationOperationV0| {
            let PocoApplicationOperationBodyV0::RegisterValidator { target_epoch, .. } =
                &mut operation.body
            else {
                unreachable!();
            };
            *target_epoch = target_epoch.checked_add(1).unwrap();
        };
        let mut saturated_bad_epoch = saturated.clone();
        let mut bad_epoch_operation = saturated_operation.clone();
        mutate_epoch(&mut bad_epoch_operation);
        let bad_epoch_raw = serde_json::to_vec(&bad_epoch_operation).unwrap();
        let before = saturated_bad_epoch.clone();
        assert_eq!(
            saturated_bad_epoch.apply_decoded_exact(&bad_epoch_raw, &bad_epoch_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_epoch, &before);

        let mut below_cap_bad_epoch = below_cap.clone();
        let mut bad_epoch_operation = below_cap_operation.clone();
        mutate_epoch(&mut bad_epoch_operation);
        let bad_epoch_raw = serde_json::to_vec(&bad_epoch_operation).unwrap();
        let before = below_cap_bad_epoch.clone();
        assert_eq!(
            below_cap_bad_epoch.apply_decoded_exact(&bad_epoch_raw, &bad_epoch_operation),
            Err(DeterministicallyInvalid(Invalid::ValidatorRule)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_epoch, &before);

        let mutate_decision = |operation: &mut PocoApplicationOperationV0| {
            let PocoApplicationOperationBodyV0::RegisterValidator {
                registration_decision_id_hex,
                ..
            } = &mut operation.body
            else {
                unreachable!();
            };
            *registration_decision_id_hex = "aa".repeat(32);
        };
        let mut saturated_bad_decision = saturated.clone();
        let mut bad_decision_operation = saturated_operation.clone();
        mutate_decision(&mut bad_decision_operation);
        let bad_decision_raw = serde_json::to_vec(&bad_decision_operation).unwrap();
        let before = saturated_bad_decision.clone();
        assert_eq!(
            saturated_bad_decision.apply_decoded_exact(&bad_decision_raw, &bad_decision_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_decision, &before);

        let mut below_cap_bad_decision = below_cap.clone();
        let mut bad_decision_operation = below_cap_operation.clone();
        mutate_decision(&mut bad_decision_operation);
        let bad_decision_raw = serde_json::to_vec(&bad_decision_operation).unwrap();
        let before = below_cap_bad_decision.clone();
        assert_eq!(
            below_cap_bad_decision.apply_decoded_exact(&bad_decision_raw, &bad_decision_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_decision, &before);

        let mut duplicate = saturated.clone();
        let mut duplicate_operation = saturated_operation.clone();
        let PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex, ..
        } = &mut duplicate_operation.body
        else {
            unreachable!();
        };
        *validator_id_hex = duplicate.overlay.authority.validator_registration_history[0]
            .validator_id_hex
            .clone();
        let duplicate_raw = serde_json::to_vec(&duplicate_operation).unwrap();
        let before = duplicate.clone();
        assert_eq!(
            duplicate.apply_decoded_exact(&duplicate_raw, &duplicate_operation),
            Err(DeterministicallyInvalid(Invalid::ValidatorRule)),
        );
        assert_block_overlay_unchanged(&duplicate, &before);

        let mut malformed_id = saturated.clone();
        let mut malformed_id_operation = saturated_operation.clone();
        let PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex, ..
        } = &mut malformed_id_operation.body
        else {
            unreachable!();
        };
        *validator_id_hex = "0".to_string();
        let malformed_id_raw = serde_json::to_vec(&malformed_id_operation).unwrap();
        let before = malformed_id.clone();
        assert_eq!(
            malformed_id.apply_decoded_exact(&malformed_id_raw, &malformed_id_operation),
            Err(DeterministicallyInvalid(Invalid::ValidatorRule)),
        );
        assert_block_overlay_unchanged(&malformed_id, &before);

        let mut saturated_exhausted = saturated.clone();
        saturated_exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        saturated_exhausted
            .overlay
            .authority
            .set_accumulator(saturated_exhausted.overlay.accumulator);
        let mut bad_pop_operation = saturated_operation.clone();
        poison_strict_pop(&saturated_exhausted.context, &mut bad_pop_operation);
        let bad_pop_raw = serde_json::to_vec(&bad_pop_operation).unwrap();
        let before = saturated_exhausted.clone();
        assert_eq!(
            saturated_exhausted.apply_decoded_exact(&bad_pop_raw, &bad_pop_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_exhausted, &before);

        let mut below_cap_exhausted = below_cap.clone();
        below_cap_exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        below_cap_exhausted
            .overlay
            .authority
            .set_accumulator(below_cap_exhausted.overlay.accumulator);
        let mut bad_pop_operation = below_cap_operation.clone();
        poison_strict_pop(&below_cap_exhausted.context, &mut bad_pop_operation);
        let bad_pop_raw = serde_json::to_vec(&bad_pop_operation).unwrap();
        let before = below_cap_exhausted.clone();
        assert_eq!(
            below_cap_exhausted.apply_decoded_exact(&bad_pop_raw, &bad_pop_operation),
            Err(Invariant(InvariantReason::ProtocolCounterExhausted)),
        );
        assert_block_overlay_unchanged(&below_cap_exhausted, &before);

        let mut saturated_bad_absence_shape = saturated.clone();
        let mut bad_absence_shape_operation = saturated_operation.clone();
        bad_absence_shape_operation
            .nullifier_non_membership_checks
            .clear();
        let bad_absence_shape_raw = serde_json::to_vec(&bad_absence_shape_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_absence_shape_raw).unwrap();
        let before = saturated_bad_absence_shape.clone();
        assert_eq!(
            saturated_bad_absence_shape
                .apply_decoded_exact(&bad_absence_shape_raw, &bad_absence_shape_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_absence_shape, &before);

        let mut below_cap_bad_absence_shape = below_cap.clone();
        let mut bad_absence_shape_operation = below_cap_operation.clone();
        bad_absence_shape_operation
            .nullifier_non_membership_checks
            .clear();
        let bad_absence_shape_raw = serde_json::to_vec(&bad_absence_shape_operation).unwrap();
        let before = below_cap_bad_absence_shape.clone();
        assert_eq!(
            below_cap_bad_absence_shape
                .apply_decoded_exact(&bad_absence_shape_raw, &bad_absence_shape_operation),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_absence_shape, &before);

        let mutate_subject = |raw: &mut RawNullifierInsertionV0,
                              family: PocoNullifierFamilyV0,
                              identifier: [u8; 32]| {
            raw.family = family.code();
            raw.identifier_hex = hex::encode(identifier);
            let key = derive_poco_nullifier_key_v0(family, identifier);
            raw.proof_hex =
                hex::encode(PocoNullifierProofV0::new(key, [[0x55; 32]; 256]).canonical_bytes());
        };
        let mut saturated_bad_absence_subject = saturated.clone();
        let mut bad_absence_subject_operation = saturated_operation.clone();
        mutate_subject(
            &mut bad_absence_subject_operation.nullifier_non_membership_checks[0],
            PocoNullifierFamilyV0::MeterDecision,
            [0xab; 32],
        );
        let bad_absence_subject_raw = serde_json::to_vec(&bad_absence_subject_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_absence_subject_raw).unwrap();
        let before = saturated_bad_absence_subject.clone();
        assert_eq!(
            saturated_bad_absence_subject
                .apply_decoded_exact(&bad_absence_subject_raw, &bad_absence_subject_operation,),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_absence_subject, &before);

        let mut below_cap_bad_absence_subject = below_cap.clone();
        let mut bad_absence_subject_operation = below_cap_operation.clone();
        mutate_subject(
            &mut bad_absence_subject_operation.nullifier_non_membership_checks[0],
            PocoNullifierFamilyV0::MeterDecision,
            [0xab; 32],
        );
        let bad_absence_subject_raw = serde_json::to_vec(&bad_absence_subject_operation).unwrap();
        let before = below_cap_bad_absence_subject.clone();
        assert_eq!(
            below_cap_bad_absence_subject
                .apply_decoded_exact(&bad_absence_subject_raw, &bad_absence_subject_operation,),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_absence_subject, &before);

        let mut below_cap_bad_absence_root = below_cap.clone();
        let mut bad_absence_root_operation = below_cap_operation.clone();
        poison_raw_nullifier_roots_v0(
            &mut bad_absence_root_operation.nullifier_non_membership_checks,
        );
        let bad_absence_root_raw = serde_json::to_vec(&bad_absence_root_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_absence_root_raw).unwrap();
        let before = below_cap_bad_absence_root.clone();
        assert_eq!(
            below_cap_bad_absence_root
                .apply_decoded_exact(&bad_absence_root_raw, &bad_absence_root_operation),
            Err(DeterministicallyInvalid(
                Invalid::NullifierNonMembershipRootMismatch,
            )),
        );
        assert_block_overlay_unchanged(&below_cap_bad_absence_root, &before);

        let mut saturated_bad_insertion_shape = saturated.clone();
        let mut bad_insertion_shape_operation = saturated_operation.clone();
        bad_insertion_shape_operation.nullifier_insertions.pop();
        let bad_insertion_shape_raw = serde_json::to_vec(&bad_insertion_shape_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_insertion_shape_raw).unwrap();
        let before = saturated_bad_insertion_shape.clone();
        assert_eq!(
            saturated_bad_insertion_shape
                .apply_decoded_exact(&bad_insertion_shape_raw, &bad_insertion_shape_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_insertion_shape, &before);

        let mut below_cap_bad_insertion_shape = below_cap.clone();
        let mut bad_insertion_shape_operation = below_cap_operation.clone();
        bad_insertion_shape_operation.nullifier_insertions.pop();
        let bad_insertion_shape_raw = serde_json::to_vec(&bad_insertion_shape_operation).unwrap();
        let before = below_cap_bad_insertion_shape.clone();
        assert_eq!(
            below_cap_bad_insertion_shape
                .apply_decoded_exact(&bad_insertion_shape_raw, &bad_insertion_shape_operation),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_insertion_shape, &before);

        let mut below_cap_bad_insertion_subject = below_cap.clone();
        let mut bad_insertion_subject_operation = below_cap_operation.clone();
        mutate_subject(
            &mut bad_insertion_subject_operation.nullifier_insertions[1],
            PocoNullifierFamilyV0::ValidatorIdentity,
            [0xcd; 32],
        );
        let bad_insertion_subject_raw =
            serde_json::to_vec(&bad_insertion_subject_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_insertion_subject_raw).unwrap();
        let before = below_cap_bad_insertion_subject.clone();
        assert_eq!(
            below_cap_bad_insertion_subject
                .apply_decoded_exact(&bad_insertion_subject_raw, &bad_insertion_subject_operation,),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_insertion_subject, &before);

        let mut saturated_bad_second_root = saturated.clone();
        let mut bad_second_root_operation = saturated_operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_second_root_operation.nullifier_insertions[1..]);
        let bad_second_root_raw = serde_json::to_vec(&bad_second_root_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_second_root_raw).unwrap();
        let before = saturated_bad_second_root.clone();
        assert_eq!(
            saturated_bad_second_root
                .apply_decoded_exact(&bad_second_root_raw, &bad_second_root_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_second_root, &before);

        let mut below_cap_bad_second_root = below_cap.clone();
        let mut bad_second_root_operation = below_cap_operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_second_root_operation.nullifier_insertions[1..]);
        let bad_second_root_raw = serde_json::to_vec(&bad_second_root_operation).unwrap();
        let before = below_cap_bad_second_root.clone();
        assert_eq!(
            below_cap_bad_second_root
                .apply_decoded_exact(&bad_second_root_raw, &bad_second_root_operation),
            Err(DeterministicallyInvalid(
                Invalid::NullifierNonMembershipRootMismatch,
            )),
        );
        assert_block_overlay_unchanged(&below_cap_bad_second_root, &before);

        let mut operation_full = saturated.clone();
        operation_full.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let before = operation_full.clone();
        assert_eq!(
            operation_full.apply_decoded_exact(&saturated_raw, &saturated_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&operation_full, &before);

        let mut byte_full = saturated.clone();
        byte_full.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        let before = byte_full.clone();
        assert_eq!(
            byte_full.apply_decoded_exact(&saturated_raw, &saturated_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&byte_full, &before);

        let (tag_block, _, operation) =
            fixture_authoring::register_validator_capacity_fixture_v0(0).unwrap();
        let decision_preimage =
            decision_preimage_digest_v0(&tag_block.context, &operation).unwrap();
        let prepared = validate_operation_capacity_before_clone_v0(
            &tag_block.context,
            &tag_block.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut mismatched_operation = operation;
        mismatched_operation.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        let mut candidate = tag_block.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &tag_block.context,
            &mut candidate,
            &mismatched_operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(
            candidate.source_authority_value,
            before.source_authority_value
        );
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(candidate.operation_ids.is_empty());

        let mut exact_boundary = below_cap;
        let accumulator_before = exact_boundary.overlay.accumulator.count();
        let PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex, ..
        } = &below_cap_operation.body
        else {
            unreachable!();
        };
        let validator_id = exact_opaque_hex(validator_id_hex).unwrap();
        exact_boundary
            .apply_decoded_exact(&below_cap_raw, &below_cap_operation)
            .unwrap();
        assert_eq!(
            exact_boundary
                .overlay
                .authority
                .validator_registration_history
                .len(),
            MAX_VALIDATOR_REGISTRATION_HISTORIES,
        );
        assert_eq!(
            exact_boundary.overlay.accumulator.count(),
            accumulator_before + 2,
        );
        assert!(exact_boundary
            .overlay
            .authority
            .validator_registration_history
            .windows(2)
            .all(|pair| pair[0].validator_id_hex < pair[1].validator_id_hex));
        assert!(exact_boundary.overlay.entries.contains_key(&(
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::ValidatorRegistration,
                &validator_id,
            )
            .to_vec(),
        )));
        assert_eq!(
            exact_boundary.seal().unwrap().operation_count(),
            u32::try_from(MAX_VALIDATOR_REGISTRATION_HISTORIES).unwrap(),
        );
    }

    #[test]
    fn rotate_validator_preparation_freezes_two_counters_and_late_proofs() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (baseline, raw, operation) =
            fixture_authoring::rotate_validator_full_history_fixture_v0().unwrap();
        assert_eq!(
            baseline
                .overlay
                .authority
                .validator_registration_history
                .len(),
            MAX_VALIDATOR_REGISTRATION_HISTORIES,
        );
        assert_eq!(baseline.operation_count(), 0);
        assert_eq!(
            PocoApplicationOperationV0::decode_exact(&raw).unwrap(),
            operation
        );

        let PocoApplicationOperationBodyV0::RotateValidator {
            validator_id_hex, ..
        } = &operation.body
        else {
            unreachable!();
        };
        let validator_id_hex = validator_id_hex.clone();
        let validator_id = exact_opaque_hex(&validator_id_hex).unwrap();
        let source_index = baseline
            .overlay
            .authority
            .validator_registration_history
            .binary_search_by(|history| history.validator_id_hex.cmp(&validator_id_hex))
            .unwrap();
        let source_history =
            baseline.overlay.authority.validator_registration_history[source_index].clone();
        let accumulator_before = baseline.overlay.accumulator.count();

        let mut canonical = baseline.clone();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        assert_eq!(
            canonical
                .overlay
                .authority
                .validator_registration_history
                .len(),
            MAX_VALIDATOR_REGISTRATION_HISTORIES,
        );
        assert!(canonical
            .overlay
            .authority
            .validator_registration_history
            .windows(2)
            .all(|pair| pair[0].validator_id_hex < pair[1].validator_id_hex));
        assert_eq!(
            canonical.overlay.accumulator.count(),
            accumulator_before + 2
        );
        let rotated = &canonical.overlay.authority.validator_registration_history[source_index];
        assert_eq!(rotated.validator_id_hex, validator_id_hex);
        assert_eq!(rotated.max_registration_nonce, 2);
        assert_eq!(
            rotated.retired_key_count,
            source_history.retired_key_count + 1,
        );
        assert_eq!(
            rotated.previous_history_head_hex,
            source_history.history_head_hex,
        );
        assert_ne!(rotated.history_head_hex, source_history.history_head_hex);
        assert_ne!(rotated.consensus_key_hex, source_history.consensus_key_hex);
        assert_eq!(
            rotated.registration_height,
            canonical.context.target_height.get()
        );
        assert!(canonical.overlay.entries.contains_key(&(
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::ValidatorRegistration,
                &validator_id,
            )
            .to_vec(),
        )));
        assert_eq!(canonical.seal().unwrap().operation_count(), 1);

        let rebind_decision =
            |context: &AuthenticatedPocoApplicationContextV0,
             operation: &mut PocoApplicationOperationV0| {
                let preimage = decision_preimage_digest_v0(context, operation).unwrap();
                let PocoApplicationOperationBodyV0::RotateValidator {
                    registration_decision_id_hex,
                    ..
                } = &mut operation.body
                else {
                    unreachable!();
                };
                *registration_decision_id_hex =
                    hex::encode(derived_decision_id_v0(preimage, b"rotate-validator"));
            };
        let poison_strict_pop =
            |context: &AuthenticatedPocoApplicationContextV0,
             operation: &mut PocoApplicationOperationV0| {
                let raw_change = &mut operation.semantic_changes[0];
                let kind = PocoSnapshotEntryKindV0::from_u8(raw_change.kind).unwrap();
                let logical_key = exact_hash32_hex(&raw_change.logical_key_hex).unwrap();
                let next_value =
                    hex::decode(raw_change.next_value_hex.as_deref().unwrap()).unwrap();
                let next = owned_semantic_parts(kind, &logical_key, &next_value).unwrap();
                let mut payload = next.payload;
                *payload.last_mut().unwrap() ^= 1;
                raw_change.next_value_hex = Some(hex::encode(encode_test_semantic_envelope_v0(
                    kind,
                    next.revision,
                    &next.identity,
                    &payload,
                )));
                rebind_decision(context, operation);
            };
        let assert_failure =
            |mut candidate: PocoApplicationBlockOverlayV0,
             candidate_operation: PocoApplicationOperationV0,
             expected: PocoApplicationApplyFailureV0| {
                let candidate_raw = serde_json::to_vec(&candidate_operation).unwrap();
                PocoApplicationOperationV0::decode_exact(&candidate_raw).unwrap();
                let before = candidate.clone();
                assert_eq!(
                    candidate.apply_decoded_exact(&candidate_raw, &candidate_operation),
                    Err(expected),
                );
                assert_block_overlay_unchanged(&candidate, &before);
            };

        let mut unsupported_candidate = baseline.clone();
        unsupported_candidate
            .overlay
            .authority
            .active_certificates
            .push(max_active_certificate(6_800, 6_900, &source_history));
        unsupported_candidate
            .overlay
            .authority
            .validator_registration_history
            .remove(source_index);
        unsupported_candidate.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        unsupported_candidate
            .overlay
            .authority
            .set_accumulator(unsupported_candidate.overlay.accumulator);
        let mut unsupported = operation.clone();
        unsupported.nullifier_non_membership_checks =
            vec![unsupported.nullifier_insertions[0].clone()];
        assert_failure(
            unsupported_candidate,
            unsupported,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut active_reference = baseline.clone();
        active_reference
            .overlay
            .authority
            .active_certificates
            .push(max_active_certificate(7_000, 7_100, &source_history));
        active_reference.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        active_reference
            .overlay
            .authority
            .set_accumulator(active_reference.overlay.accumulator);
        let mut later_bad_pop = operation.clone();
        poison_strict_pop(&active_reference.context, &mut later_bad_pop);
        let PocoApplicationOperationBodyV0::RotateValidator { target_epoch, .. } =
            &mut later_bad_pop.body
        else {
            unreachable!();
        };
        *target_epoch = target_epoch.checked_add(1).unwrap();
        assert_failure(
            active_reference,
            later_bad_pop,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut missing_history = baseline.clone();
        missing_history
            .overlay
            .authority
            .validator_registration_history
            .remove(source_index);
        let mut later_bad_pop = operation.clone();
        poison_strict_pop(&missing_history.context, &mut later_bad_pop);
        assert_failure(
            missing_history,
            later_bad_pop,
            DeterministicallyInvalid(Invalid::MissingRequiredAuthorityFact),
        );

        let mut revoked_history = baseline.clone();
        revoked_history
            .overlay
            .authority
            .validator_registration_history[source_index]
            .revoked_at_height = Some(1);
        let mut later_bad_pop = operation.clone();
        poison_strict_pop(&revoked_history.context, &mut later_bad_pop);
        assert_failure(
            revoked_history,
            later_bad_pop,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut retired_counter_exhausted = baseline.clone();
        retired_counter_exhausted
            .overlay
            .authority
            .validator_registration_history[source_index]
            .retired_key_count = u64::MAX;
        retired_counter_exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        retired_counter_exhausted
            .overlay
            .authority
            .set_accumulator(retired_counter_exhausted.overlay.accumulator);
        let mut later_faults = operation.clone();
        poison_strict_pop(&retired_counter_exhausted.context, &mut later_faults);
        let PocoApplicationOperationBodyV0::RotateValidator { target_epoch, .. } =
            &mut later_faults.body
        else {
            unreachable!();
        };
        *target_epoch = target_epoch.checked_add(1).unwrap();
        assert_failure(
            retired_counter_exhausted,
            later_faults,
            Invariant(InvariantReason::ProtocolCounterExhausted),
        );

        let mut accumulator_exhausted = baseline.clone();
        accumulator_exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        accumulator_exhausted
            .overlay
            .authority
            .set_accumulator(accumulator_exhausted.overlay.accumulator);
        let mut later_faults = operation.clone();
        poison_strict_pop(&accumulator_exhausted.context, &mut later_faults);
        let PocoApplicationOperationBodyV0::RotateValidator { target_epoch, .. } =
            &mut later_faults.body
        else {
            unreachable!();
        };
        *target_epoch = target_epoch.checked_add(1).unwrap();
        assert_failure(
            accumulator_exhausted,
            later_faults,
            Invariant(InvariantReason::ProtocolCounterExhausted),
        );

        let mut bad_epoch = operation.clone();
        poison_strict_pop(&baseline.context, &mut bad_epoch);
        let PocoApplicationOperationBodyV0::RotateValidator { target_epoch, .. } =
            &mut bad_epoch.body
        else {
            unreachable!();
        };
        *target_epoch = target_epoch.checked_add(1).unwrap();
        let PocoApplicationOperationBodyV0::RotateValidator {
            registration_decision_id_hex,
            ..
        } = &mut bad_epoch.body
        else {
            unreachable!();
        };
        *registration_decision_id_hex = "aa".repeat(32);
        assert_failure(
            baseline.clone(),
            bad_epoch,
            DeterministicallyInvalid(Invalid::ValidatorRule),
        );

        let mut bad_decision = operation.clone();
        poison_strict_pop(&baseline.context, &mut bad_decision);
        let PocoApplicationOperationBodyV0::RotateValidator {
            registration_decision_id_hex,
            ..
        } = &mut bad_decision.body
        else {
            unreachable!();
        };
        *registration_decision_id_hex = "aa".repeat(32);
        assert_failure(
            baseline.clone(),
            bad_decision,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let raw_change = &operation.semantic_changes[0];
        let kind = PocoSnapshotEntryKindV0::from_u8(raw_change.kind).unwrap();
        let logical_key = exact_hash32_hex(&raw_change.logical_key_hex).unwrap();
        let next_value = hex::decode(raw_change.next_value_hex.as_deref().unwrap()).unwrap();
        let next_consensus_key = match owned_semantic_parts(kind, &logical_key, &next_value)
            .unwrap()
            .fact
        {
            SemanticFactV0::ValidatorRegistration { consensus_key, .. } => consensus_key,
            _ => unreachable!(),
        };
        let mut active_key_collision = baseline.clone();
        let collision_index = if source_index == 0 { 1 } else { 0 };
        active_key_collision
            .overlay
            .authority
            .validator_registration_history[collision_index]
            .consensus_key_hex = hex::encode(next_consensus_key);
        assert_failure(
            active_key_collision,
            operation.clone(),
            DeterministicallyInvalid(Invalid::ValidatorConsensusKeyAlreadyActive),
        );

        let mut bad_previous_head = operation.clone();
        let PocoApplicationOperationBodyV0::RotateValidator {
            previous_history_head_hex,
            ..
        } = &mut bad_previous_head.body
        else {
            unreachable!();
        };
        *previous_history_head_hex = "bb".repeat(32);
        rebind_decision(&baseline.context, &mut bad_previous_head);
        assert_failure(
            baseline.clone(),
            bad_previous_head,
            DeterministicallyInvalid(Invalid::ValidatorRule),
        );

        let mut bad_previous_nonce = operation.clone();
        let PocoApplicationOperationBodyV0::RotateValidator {
            previous_registration_nonce,
            ..
        } = &mut bad_previous_nonce.body
        else {
            unreachable!();
        };
        *previous_registration_nonce = previous_registration_nonce.checked_add(1).unwrap();
        rebind_decision(&baseline.context, &mut bad_previous_nonce);
        assert_failure(
            baseline.clone(),
            bad_previous_nonce,
            DeterministicallyInvalid(Invalid::ValidatorRule),
        );

        let mut bad_pop = operation.clone();
        poison_strict_pop(&baseline.context, &mut bad_pop);
        assert_failure(
            baseline.clone(),
            bad_pop,
            DeterministicallyInvalid(Invalid::CryptographicProof),
        );

        let mut pop_before_predecessor = operation.clone();
        poison_strict_pop(&baseline.context, &mut pop_before_predecessor);
        let PocoApplicationOperationBodyV0::RotateValidator {
            previous_history_head_hex,
            ..
        } = &mut pop_before_predecessor.body
        else {
            unreachable!();
        };
        *previous_history_head_hex = "cc".repeat(32);
        rebind_decision(&baseline.context, &mut pop_before_predecessor);
        assert_failure(
            baseline.clone(),
            pop_before_predecessor,
            DeterministicallyInvalid(Invalid::CryptographicProof),
        );

        let map_key = (
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::ValidatorRegistration,
                &validator_id,
            )
            .to_vec(),
        );
        let mut corrupted_predecessor = baseline.clone();
        let current = owned_semantic_parts(
            map_key.0,
            &map_key.1,
            corrupted_predecessor.overlay.entries.get(&map_key).unwrap(),
        )
        .unwrap();
        let mut payload = current.payload;
        *payload.last_mut().unwrap() ^= 1;
        corrupted_predecessor.overlay.entries.insert(
            map_key,
            encode_test_semantic_envelope_v0(
                PocoSnapshotEntryKindV0::ValidatorRegistration,
                current.revision,
                &current.identity,
                &payload,
            ),
        );
        assert_failure(
            corrupted_predecessor,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut malformed_predecessor = baseline.clone();
        malformed_predecessor.overlay.entries.insert(
            (
                PocoSnapshotEntryKindV0::ValidatorRegistration,
                semantic_identity_digest_v0(
                    PocoSnapshotEntryKindV0::ValidatorRegistration,
                    &validator_id,
                )
                .to_vec(),
            ),
            vec![0xff],
        );
        let mut later_bad_pop = operation.clone();
        poison_strict_pop(&malformed_predecessor.context, &mut later_bad_pop);
        assert_failure(
            malformed_predecessor,
            later_bad_pop,
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut bad_insertion_shape = operation.clone();
        bad_insertion_shape.nullifier_insertions.pop();
        assert_failure(
            baseline.clone(),
            bad_insertion_shape,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_insertion_subject = operation.clone();
        let family = PocoNullifierFamilyV0::ValidatorIdentity;
        let identifier = [0xcd; 32];
        let key = derive_poco_nullifier_key_v0(family, identifier);
        bad_insertion_subject.nullifier_insertions[1] = RawNullifierInsertionV0 {
            family: family.code(),
            identifier_hex: hex::encode(identifier),
            proof_hex: hex::encode(
                PocoNullifierProofV0::new(key, [[0x55; 32]; 256]).canonical_bytes(),
            ),
        };
        assert_failure(
            baseline.clone(),
            bad_insertion_subject,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_second_root = operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_second_root.nullifier_insertions[1..]);
        assert_failure(
            baseline.clone(),
            bad_second_root,
            DeterministicallyInvalid(Invalid::NullifierNonMembershipRootMismatch),
        );

        let mut structural_later_fault = operation.clone();
        poison_strict_pop(&baseline.context, &mut structural_later_fault);
        let structural_later_fault_raw = serde_json::to_vec(&structural_later_fault).unwrap();
        let mut operation_full = baseline.clone();
        operation_full.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let before = operation_full.clone();
        assert_eq!(
            operation_full
                .apply_decoded_exact(&structural_later_fault_raw, &structural_later_fault),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&operation_full, &before);

        let mut byte_full = baseline.clone();
        byte_full.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        let before = byte_full.clone();
        assert_eq!(
            byte_full.apply_decoded_exact(&structural_later_fault_raw, &structural_later_fault),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&byte_full, &before);

        let decision_preimage = decision_preimage_digest_v0(&baseline.context, &operation).unwrap();
        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut mismatched_operation = operation;
        mismatched_operation.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        let mut candidate = baseline.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &mismatched_operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(
            candidate.source_authority_value,
            before.source_authority_value
        );
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(candidate.operation_ids.is_empty());
    }

    #[test]
    fn release_settlement_preparation_freezes_decrement_and_late_proofs() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (baseline, raw, operation) =
            fixture_authoring::release_settlement_full_capacity_fixture_v0().unwrap();
        assert_eq!(
            baseline.overlay.authority.funded_unused_reservations.len(),
            MAX_FUNDED_UNUSED_RESERVATIONS,
        );
        assert_eq!(baseline.operation_count(), 0);
        assert_eq!(
            PocoApplicationOperationV0::decode_exact(&raw).unwrap(),
            operation,
        );
        let PocoApplicationOperationBodyV0::ReleaseSettlement {
            certificate_id_hex, ..
        } = &operation.body
        else {
            unreachable!();
        };
        let certificate_id_hex = certificate_id_hex.clone();
        let certificate_id = exact_hash32_hex(&certificate_id_hex).unwrap();
        let reservation_index = baseline
            .overlay
            .authority
            .funded_unused_reservations
            .binary_search_by(|reservation| {
                reservation
                    .certificate_id_hex
                    .as_str()
                    .cmp(certificate_id_hex.as_str())
            })
            .unwrap();
        let settlement_key = (
            PocoSnapshotEntryKindV0::Settlement,
            semantic_identity_digest_v0(PocoSnapshotEntryKindV0::Settlement, &certificate_id)
                .to_vec(),
        );
        assert!(baseline.overlay.entries.contains_key(&settlement_key));
        let accumulator_before = baseline.overlay.accumulator.count();

        let mut canonical = baseline.clone();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        assert_eq!(
            canonical.overlay.authority.funded_unused_reservations.len(),
            MAX_FUNDED_UNUSED_RESERVATIONS - 1,
        );
        assert!(canonical
            .overlay
            .authority
            .funded_unused_reservations
            .iter()
            .all(|reservation| reservation.certificate_id_hex != certificate_id_hex));
        assert_eq!(
            canonical.overlay.accumulator.count(),
            accumulator_before + 2,
        );
        assert!(!canonical.overlay.entries.contains_key(&settlement_key));
        assert_eq!(canonical.seal().unwrap().operation_count(), 1);

        let (context, projection, shared_raw, shared_operation) =
            sequence_step_vector_fixture("release_refund_replay", 1);
        let mut shared =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        shared
            .apply_decoded_exact(&shared_raw, &shared_operation)
            .unwrap();
        assert_eq!(shared.seal().unwrap().operation_count(), 1);

        let rebind_decision =
            |context: &AuthenticatedPocoApplicationContextV0,
             operation: &mut PocoApplicationOperationV0| {
                let preimage = decision_preimage_digest_v0(context, operation).unwrap();
                let PocoApplicationOperationBodyV0::ReleaseSettlement {
                    release_decision_id_hex,
                    ..
                } = &mut operation.body
                else {
                    unreachable!();
                };
                *release_decision_id_hex =
                    hex::encode(derived_decision_id_v0(preimage, b"release-settlement"));
            };
        let assert_failure =
            |mut candidate: PocoApplicationBlockOverlayV0,
             candidate_operation: PocoApplicationOperationV0,
             expected: PocoApplicationApplyFailureV0| {
                let candidate_raw = serde_json::to_vec(&candidate_operation).unwrap();
                PocoApplicationOperationV0::decode_exact(&candidate_raw).unwrap();
                let before = candidate.clone();
                assert_eq!(
                    candidate.apply_decoded_exact(&candidate_raw, &candidate_operation),
                    Err(expected),
                );
                assert_block_overlay_unchanged(&candidate, &before);
            };

        let mut malformed_id = operation.clone();
        let PocoApplicationOperationBodyV0::ReleaseSettlement {
            certificate_id_hex, ..
        } = &mut malformed_id.body
        else {
            unreachable!();
        };
        *certificate_id_hex = "0".to_string();
        assert_failure(
            baseline.clone(),
            malformed_id,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut missing_reservation = baseline.clone();
        missing_reservation
            .overlay
            .authority
            .funded_unused_reservations
            .remove(reservation_index);
        let mut later_unsupported = operation.clone();
        later_unsupported.nullifier_non_membership_checks =
            vec![later_unsupported.nullifier_insertions[0].clone()];
        assert_failure(
            missing_reservation,
            later_unsupported,
            DeterministicallyInvalid(Invalid::MissingRequiredAuthorityFact),
        );

        let mut unsupported_candidate = baseline.clone();
        unsupported_candidate.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        unsupported_candidate
            .overlay
            .authority
            .set_accumulator(unsupported_candidate.overlay.accumulator);
        let mut unsupported = operation.clone();
        unsupported.nullifier_non_membership_checks =
            vec![unsupported.nullifier_insertions[0].clone()];
        let PocoApplicationOperationBodyV0::ReleaseSettlement {
            release_decision_id_hex,
            ..
        } = &mut unsupported.body
        else {
            unreachable!();
        };
        *release_decision_id_hex = "aa".repeat(32);
        assert_failure(
            unsupported_candidate,
            unsupported,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_decision = operation.clone();
        let PocoApplicationOperationBodyV0::ReleaseSettlement {
            release_decision_id_hex,
            ..
        } = &mut bad_decision.body
        else {
            unreachable!();
        };
        *release_decision_id_hex = "aa".repeat(32);
        assert_failure(
            baseline.clone(),
            bad_decision,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut signed_non_delete = operation.clone();
        let current_settlement = owned_semantic_parts(
            settlement_key.0,
            &settlement_key.1,
            baseline.overlay.entries.get(&settlement_key).unwrap(),
        )
        .unwrap();
        signed_non_delete.semantic_changes[0].next_value_hex =
            Some(hex::encode(encode_test_semantic_envelope_v0(
                settlement_key.0,
                current_settlement.revision.checked_add(1).unwrap(),
                &current_settlement.identity,
                &current_settlement.payload,
            )));
        rebind_decision(&baseline.context, &mut signed_non_delete);
        assert_failure(
            baseline.clone(),
            signed_non_delete,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut companion_drift = baseline.clone();
        companion_drift.overlay.authority.funded_unused_reservations[reservation_index]
            .settlement_commitment_hex = "bb".repeat(32);
        assert_failure(
            companion_drift,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut malformed_predecessor = baseline.clone();
        malformed_predecessor
            .overlay
            .entries
            .insert(settlement_key.clone(), vec![0xff]);
        assert_failure(
            malformed_predecessor,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut exhausted = baseline.clone();
        exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        exhausted
            .overlay
            .authority
            .set_accumulator(exhausted.overlay.accumulator);
        let mut later_bad_root = operation.clone();
        poison_raw_nullifier_roots_v0(&mut later_bad_root.nullifier_insertions);
        assert_failure(
            exhausted,
            later_bad_root,
            Invariant(InvariantReason::ProtocolCounterExhausted),
        );

        let mut bad_insertion_shape = operation.clone();
        bad_insertion_shape.nullifier_insertions.pop();
        assert_failure(
            baseline.clone(),
            bad_insertion_shape,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mutate_subject = |raw: &mut RawNullifierInsertionV0,
                              family: PocoNullifierFamilyV0,
                              identifier: [u8; 32]| {
            let key = derive_poco_nullifier_key_v0(family, identifier);
            *raw = RawNullifierInsertionV0 {
                family: family.code(),
                identifier_hex: hex::encode(identifier),
                proof_hex: hex::encode(
                    PocoNullifierProofV0::new(key, [[0x55; 32]; 256]).canonical_bytes(),
                ),
            };
        };
        let mut bad_first_subject = operation.clone();
        mutate_subject(
            &mut bad_first_subject.nullifier_insertions[0],
            PocoNullifierFamilyV0::Tuple,
            [0xc1; 32],
        );
        assert_failure(
            baseline.clone(),
            bad_first_subject,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_second_subject = operation.clone();
        mutate_subject(
            &mut bad_second_subject.nullifier_insertions[1],
            PocoNullifierFamilyV0::MeterDecision,
            [0xc2; 32],
        );
        assert_failure(
            baseline.clone(),
            bad_second_subject,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_first_root = operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_first_root.nullifier_insertions[..1]);
        assert_failure(
            baseline.clone(),
            bad_first_root,
            DeterministicallyInvalid(Invalid::NullifierNonMembershipRootMismatch),
        );

        let mut bad_second_root = operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_second_root.nullifier_insertions[1..]);
        assert_failure(
            baseline.clone(),
            bad_second_root.clone(),
            DeterministicallyInvalid(Invalid::NullifierNonMembershipRootMismatch),
        );

        let later_fault_raw = serde_json::to_vec(&bad_second_root).unwrap();
        let mut operation_full = baseline.clone();
        operation_full.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let before = operation_full.clone();
        assert_eq!(
            operation_full.apply_decoded_exact(&later_fault_raw, &bad_second_root),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&operation_full, &before);

        let mut byte_full = baseline.clone();
        byte_full.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        let before = byte_full.clone();
        assert_eq!(
            byte_full.apply_decoded_exact(&later_fault_raw, &bad_second_root),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&byte_full, &before);

        let decision_preimage = decision_preimage_digest_v0(&baseline.context, &operation).unwrap();
        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut cross_family = operation.clone();
        cross_family.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        let mut candidate = baseline.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &cross_family,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut same_family_decision = operation.clone();
        let PocoApplicationOperationBodyV0::ReleaseSettlement {
            release_decision_id_hex,
            ..
        } = &mut same_family_decision.body
        else {
            unreachable!();
        };
        *release_decision_id_hex = "33".repeat(32);
        let mut candidate = baseline.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &same_family_decision,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut candidate = baseline.overlay.clone();
        candidate.authority.funded_unused_reservations[reservation_index].funding_decision_id_hex =
            "44".repeat(32);
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut same_family = operation.clone();
        let PocoApplicationOperationBodyV0::ReleaseSettlement {
            certificate_id_hex, ..
        } = &mut same_family.body
        else {
            unreachable!();
        };
        *certificate_id_hex = "22".repeat(32);
        let mut candidate = baseline.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &same_family,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut candidate = baseline.overlay.clone();
        candidate
            .authority
            .funded_unused_reservations
            .remove(reservation_index);
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
    }

    #[test]
    fn resolve_challenge_preparation_freezes_decrement_and_late_proof() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (baseline, raw, operation) =
            fixture_authoring::resolve_challenge_full_capacity_fixture_v0().unwrap();
        assert_eq!(
            baseline.overlay.authority.pending_challenges.len(),
            MAX_PENDING_CHALLENGES,
        );
        assert_eq!(baseline.operation_count(), 0);
        assert_eq!(
            PocoApplicationOperationV0::decode_exact(&raw).unwrap(),
            operation,
        );
        let PocoApplicationOperationBodyV0::ResolveChallenge {
            certificate_id_hex,
            challenge_id_hex,
            resolution_decision_id_hex,
            ..
        } = &operation.body
        else {
            unreachable!();
        };
        let certificate_id_hex = certificate_id_hex.clone();
        let challenge_id_hex = challenge_id_hex.clone();
        let resolution_decision_id_hex = resolution_decision_id_hex.clone();
        let certificate_id = exact_hash32_hex(&certificate_id_hex).unwrap();
        let pending_index = baseline
            .overlay
            .authority
            .pending_challenges
            .binary_search_by(|pending| {
                pending
                    .challenge_id_hex
                    .as_str()
                    .cmp(challenge_id_hex.as_str())
            })
            .unwrap();
        let certificate_index = baseline
            .overlay
            .authority
            .active_certificates
            .binary_search_by(|certificate| {
                certificate
                    .certificate_id_hex
                    .as_str()
                    .cmp(certificate_id_hex.as_str())
            })
            .unwrap();
        let lifecycle_key = (
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::RevocationOrChallenge,
                &certificate_id,
            )
            .to_vec(),
        );
        let accumulator_before = baseline.overlay.accumulator.count();

        let mut canonical = baseline.clone();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        assert_eq!(
            canonical.overlay.authority.pending_challenges.len(),
            MAX_PENDING_CHALLENGES - 1,
        );
        assert!(canonical
            .overlay
            .authority
            .pending_challenges
            .iter()
            .all(|pending| pending.challenge_id_hex != challenge_id_hex));
        let certificate = canonical
            .overlay
            .authority
            .active_certificates
            .iter()
            .find(|certificate| certificate.certificate_id_hex == certificate_id_hex)
            .unwrap();
        assert_eq!(
            certificate.lifecycle,
            CertificateAuthorityLifecycleV0::ChallengeRejected,
        );
        assert_eq!(
            certificate.lifecycle_effective_height,
            baseline.context.target_height.get(),
        );
        assert_eq!(
            certificate.lifecycle_decision_id_hex,
            resolution_decision_id_hex,
        );
        assert_eq!(
            canonical.overlay.accumulator.count(),
            accumulator_before + 1,
        );
        assert_eq!(canonical.seal().unwrap().operation_count(), 1);

        for sequence in [
            "certificate_challenge_rejected",
            "certificate_challenge_sustained",
        ] {
            let (context, projection, shared_raw, shared_operation) =
                sequence_step_vector_fixture(sequence, 3);
            let mut shared =
                PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
            shared
                .apply_decoded_exact(&shared_raw, &shared_operation)
                .unwrap();
            assert_eq!(shared.seal().unwrap().operation_count(), 1);
        }

        let rebind_decision =
            |context: &AuthenticatedPocoApplicationContextV0,
             operation: &mut PocoApplicationOperationV0| {
                let preimage = decision_preimage_digest_v0(context, operation).unwrap();
                let PocoApplicationOperationBodyV0::ResolveChallenge {
                    resolution_decision_id_hex,
                    ..
                } = &mut operation.body
                else {
                    unreachable!();
                };
                *resolution_decision_id_hex =
                    hex::encode(derived_decision_id_v0(preimage, b"resolve-challenge"));
            };
        let assert_failure =
            |mut candidate: PocoApplicationBlockOverlayV0,
             candidate_operation: PocoApplicationOperationV0,
             expected: PocoApplicationApplyFailureV0| {
                let candidate_raw = serde_json::to_vec(&candidate_operation).unwrap();
                PocoApplicationOperationV0::decode_exact(&candidate_raw).unwrap();
                let before = candidate.clone();
                assert_eq!(
                    candidate.apply_decoded_exact(&candidate_raw, &candidate_operation),
                    Err(expected),
                );
                assert_block_overlay_unchanged(&candidate, &before);
            };

        let mut malformed_id = operation.clone();
        let PocoApplicationOperationBodyV0::ResolveChallenge {
            certificate_id_hex, ..
        } = &mut malformed_id.body
        else {
            unreachable!();
        };
        *certificate_id_hex = "0".to_string();
        malformed_id.nullifier_non_membership_checks =
            vec![malformed_id.nullifier_insertions[0].clone()];
        assert_failure(
            baseline.clone(),
            malformed_id,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut missing_pending = baseline.clone();
        missing_pending
            .overlay
            .authority
            .pending_challenges
            .remove(pending_index);
        let mut later_unsupported = operation.clone();
        later_unsupported.nullifier_non_membership_checks =
            vec![later_unsupported.nullifier_insertions[0].clone()];
        assert_failure(
            missing_pending,
            later_unsupported,
            DeterministicallyInvalid(Invalid::ChallengeNotPending),
        );

        let mut pending_mismatch = baseline.clone();
        pending_mismatch.overlay.authority.pending_challenges[pending_index].certificate_id_hex =
            "aa".repeat(32);
        assert_failure(
            pending_mismatch,
            operation.clone(),
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut missing_certificate = baseline.clone();
        missing_certificate
            .overlay
            .authority
            .active_certificates
            .remove(certificate_index);
        assert_failure(
            missing_certificate,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut lifecycle_drift = baseline.clone();
        lifecycle_drift.overlay.authority.active_certificates[certificate_index].lifecycle =
            CertificateAuthorityLifecycleV0::ChallengeRejected;
        assert_failure(
            lifecycle_drift,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut record_over_cap = baseline.clone();
        record_over_cap
            .overlay
            .authority
            .finalized_governance_approvals =
            max_capacity_authority_state().finalized_governance_approvals;
        let extra = record_over_cap
            .overlay
            .authority
            .finalized_governance_approvals
            .last()
            .cloned()
            .unwrap();
        record_over_cap
            .overlay
            .authority
            .finalized_governance_approvals
            .push(extra);
        let mut after_cap_fault = operation.clone();
        after_cap_fault.nullifier_non_membership_checks =
            vec![after_cap_fault.nullifier_insertions[0].clone()];
        assert_failure(
            record_over_cap,
            after_cap_fault,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut unsupported = operation.clone();
        unsupported.nullifier_non_membership_checks =
            vec![unsupported.nullifier_insertions[0].clone()];
        let PocoApplicationOperationBodyV0::ResolveChallenge {
            resolution_decision_id_hex,
            ..
        } = &mut unsupported.body
        else {
            unreachable!();
        };
        *resolution_decision_id_hex = "aa".repeat(32);
        assert_failure(
            baseline.clone(),
            unsupported,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_decision = operation.clone();
        let PocoApplicationOperationBodyV0::ResolveChallenge {
            resolution_decision_id_hex,
            ..
        } = &mut bad_decision.body
        else {
            unreachable!();
        };
        *resolution_decision_id_hex = "aa".repeat(32);
        assert_failure(
            baseline.clone(),
            bad_decision,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut too_early = baseline.clone();
        let opened_height =
            too_early.overlay.authority.pending_challenges[pending_index].opened_height;
        too_early.context.target_height = Height::new(opened_height);
        let mut too_early_operation = operation.clone();
        too_early_operation.target_height = opened_height;
        rebind_decision(&too_early.context, &mut too_early_operation);
        assert_failure(
            too_early,
            too_early_operation,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut wrong_resolution = operation.clone();
        let PocoApplicationOperationBodyV0::ResolveChallenge { resolution, .. } =
            &mut wrong_resolution.body
        else {
            unreachable!();
        };
        *resolution = ChallengeResolutionV0::Sustained;
        rebind_decision(&baseline.context, &mut wrong_resolution);
        assert_failure(
            baseline.clone(),
            wrong_resolution,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut predecessor_drift = baseline.clone();
        let current = owned_semantic_parts(
            lifecycle_key.0,
            &lifecycle_key.1,
            predecessor_drift
                .overlay
                .entries
                .get(&lifecycle_key)
                .unwrap(),
        )
        .unwrap();
        let mut payload = current.payload;
        let height_offset = payload.len() - std::mem::size_of::<u64>();
        let wrong_height = baseline.overlay.authority.pending_challenges[pending_index]
            .opened_height
            .checked_add(1)
            .unwrap();
        payload[height_offset..].copy_from_slice(&wrong_height.to_be_bytes());
        predecessor_drift.overlay.entries.insert(
            lifecycle_key.clone(),
            encode_test_semantic_envelope_v0(
                lifecycle_key.0,
                current.revision,
                &current.identity,
                &payload,
            ),
        );
        assert_failure(
            predecessor_drift,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut exhausted = baseline.clone();
        exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX).unwrap();
        exhausted
            .overlay
            .authority
            .set_accumulator(exhausted.overlay.accumulator);
        let mut later_bad_root = operation.clone();
        poison_raw_nullifier_roots_v0(&mut later_bad_root.nullifier_insertions);
        assert_failure(
            exhausted,
            later_bad_root,
            Invariant(InvariantReason::ProtocolCounterExhausted),
        );

        let mut bad_insertion_shape = operation.clone();
        bad_insertion_shape.nullifier_insertions.pop();
        assert_failure(
            baseline.clone(),
            bad_insertion_shape,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_subject = operation.clone();
        let family = PocoNullifierFamilyV0::Tuple;
        let identifier = [0xc3; 32];
        let key = derive_poco_nullifier_key_v0(family, identifier);
        bad_subject.nullifier_insertions[0] = RawNullifierInsertionV0 {
            family: family.code(),
            identifier_hex: hex::encode(identifier),
            proof_hex: hex::encode(
                PocoNullifierProofV0::new(key, [[0x55; 32]; 256]).canonical_bytes(),
            ),
        };
        assert_failure(
            baseline.clone(),
            bad_subject,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_root = operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_root.nullifier_insertions);
        assert_failure(
            baseline.clone(),
            bad_root.clone(),
            DeterministicallyInvalid(Invalid::NullifierNonMembershipRootMismatch),
        );

        let later_fault_raw = serde_json::to_vec(&bad_root).unwrap();
        let mut operation_full = baseline.clone();
        operation_full.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let before = operation_full.clone();
        assert_eq!(
            operation_full.apply_decoded_exact(&later_fault_raw, &bad_root),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&operation_full, &before);

        let mut byte_full = baseline.clone();
        byte_full.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        let before = byte_full.clone();
        assert_eq!(
            byte_full.apply_decoded_exact(&later_fault_raw, &bad_root),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&byte_full, &before);

        let decision_preimage = decision_preimage_digest_v0(&baseline.context, &operation).unwrap();
        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut cross_family = operation.clone();
        cross_family.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        let mut candidate = baseline.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &cross_family,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut same_family = operation.clone();
        let PocoApplicationOperationBodyV0::ResolveChallenge { resolution, .. } =
            &mut same_family.body
        else {
            unreachable!();
        };
        *resolution = ChallengeResolutionV0::Sustained;
        let mut candidate = baseline.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &same_family,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut candidate = baseline.overlay.clone();
        candidate.authority.pending_challenges[pending_index].opening_decision_id_hex =
            "44".repeat(32);
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut candidate = baseline.overlay.clone();
        candidate.authority.active_certificates[certificate_index].lifecycle_decision_id_hex =
            "55".repeat(32);
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
    }

    #[test]
    fn certificate_prune_leaf_provenance_is_typed_and_non_mutating() {
        let (context, projection, raw, operation) =
            sequence_vector_fixture("certificate_prune_replay");
        let mut canonical =
            PocoApplicationBlockOverlayV0::from_projection(context.clone(), &projection).unwrap();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);

        let mut signed_delete_drift = operation.clone();
        signed_delete_drift.semantic_changes.pop();
        let signed_delete_raw = serde_json::to_vec(&signed_delete_drift).unwrap();
        let signed_delete_drift =
            PocoApplicationOperationV0::decode_exact(&signed_delete_raw).unwrap();
        let mut signed_block =
            PocoApplicationBlockOverlayV0::from_projection(context.clone(), &projection).unwrap();
        let signed_before = signed_block.clone();
        assert_eq!(
            signed_block.apply_decoded_exact(&signed_delete_raw, &signed_delete_drift),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );
        assert_block_overlay_unchanged(&signed_block, &signed_before);

        let mut corrupted =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let settlement_change = operation
            .semantic_changes
            .iter()
            .find(|change| change.kind == PocoSnapshotEntryKindV0::Settlement as u8)
            .unwrap();
        let logical_key = hex::decode(&settlement_change.logical_key_hex).unwrap();
        let map_key = (PocoSnapshotEntryKindV0::Settlement, logical_key.clone());
        let parts = owned_semantic_parts(
            PocoSnapshotEntryKindV0::Settlement,
            &logical_key,
            corrupted.overlay.entries.get(&map_key).unwrap(),
        )
        .unwrap();
        let mut payload = parts.payload;
        assert_eq!(payload.len(), 73);
        payload[64] = SettlementStateV0::FinalizedFundedUnused as u8;
        let substituted = encode_test_semantic_envelope_v0(
            PocoSnapshotEntryKindV0::Settlement,
            parts.revision,
            &parts.identity,
            &payload,
        );
        corrupted.overlay.entries.insert(map_key, substituted);
        let corrupted_before = corrupted.clone();
        assert_eq!(
            corrupted.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&corrupted, &corrupted_before);
    }

    #[test]
    fn validator_history_prune_rebinds_revoked_semantic_predecessor() {
        let (context, projection, raw, operation) =
            sequence_vector_fixture("validator_prune_replay");
        let mut canonical =
            PocoApplicationBlockOverlayV0::from_projection(context.clone(), &projection).unwrap();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);

        let mut corrupted =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let registration_change = operation
            .semantic_changes
            .iter()
            .find(|change| change.kind == PocoSnapshotEntryKindV0::ValidatorRegistration as u8)
            .unwrap();
        let logical_key = hex::decode(&registration_change.logical_key_hex).unwrap();
        let map_key = (
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            logical_key.clone(),
        );
        let parts = owned_semantic_parts(
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            &logical_key,
            corrupted.overlay.entries.get(&map_key).unwrap(),
        )
        .unwrap();
        let mut payload = parts.payload;
        let state_offset = 4usize
            .checked_add(parts.identity.len())
            .and_then(|offset| offset.checked_add(32 + 8))
            .unwrap();
        assert_eq!(payload[state_offset], RegistrationStateV0::Revoked as u8);
        payload[state_offset] = RegistrationStateV0::Active as u8;
        let substituted = encode_test_semantic_envelope_v0(
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            parts.revision,
            &parts.identity,
            &payload,
        );
        corrupted.overlay.entries.insert(map_key, substituted);
        let corrupted_before = corrupted.clone();
        assert_eq!(
            corrupted.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&corrupted, &corrupted_before);
    }

    #[test]
    fn validator_history_prune_signed_identity_mismatch_is_deterministic() {
        let (context, projection, _, operation) = sequence_vector_fixture("validator_prune_replay");
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let mut foreign_history = block.overlay.authority.validator_registration_history[0].clone();
        let foreign_validator_id_hex = hex::encode(b"validator-prune-foreign");
        foreign_history.validator_id_hex = foreign_validator_id_hex.clone();
        block
            .overlay
            .authority
            .validator_registration_history
            .push(foreign_history);
        block
            .overlay
            .authority
            .validator_registration_history
            .sort_by(|left, right| left.validator_id_hex.cmp(&right.validator_id_hex));

        let mut mismatched = operation;
        let PocoApplicationOperationBodyV0::PruneRevokedValidatorHistory { validator_id_hex } =
            &mut mismatched.body
        else {
            unreachable!();
        };
        *validator_id_hex = foreign_validator_id_hex;
        let mismatched_raw = serde_json::to_vec(&mismatched).unwrap();
        let mismatched = PocoApplicationOperationV0::decode_exact(&mismatched_raw).unwrap();
        let before = block.clone();
        assert_eq!(
            block.apply_decoded_exact(&mismatched_raw, &mismatched),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ValidatorRule,
            )),
        );
        assert_block_overlay_unchanged(&block, &before);
    }

    #[test]
    fn exact_replay_precedes_state_dependent_preflight_without_mutation() {
        for sequence_id in [
            "validator_register_rotate",
            "validator_prune_replay",
            "certificate_prune_replay",
        ] {
            let (context, projection, raw, operation) = sequence_vector_fixture(sequence_id);
            let mut block =
                PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
            block.apply_decoded_exact(&raw, &operation).unwrap();
            let before_replay = block.clone();
            assert_eq!(
                block.apply_decoded_exact(&raw, &operation),
                Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                    PocoApplicationDeterministicInvalidV0::DuplicateOperation,
                )),
                "exact replay precedence for {sequence_id}",
            );
            assert_block_overlay_unchanged(&block, &before_replay);
        }
    }

    #[test]
    fn operation_count_bound_is_exact_before_decode_or_clone() {
        let projection = genesis_projection();
        let exact = vec![vec![b'x']; MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        assert!(validate_block_admission_bounds(&projection, &exact).is_ok());
        let over = vec![vec![b'x']; MAX_APPLICATION_OPERATIONS_PER_BLOCK + 1];
        assert!(validate_block_admission_bounds(&projection, &over).is_err());
    }

    #[test]
    fn incremental_overlay_aggregate_includes_source_projection() {
        let projection = genesis_projection();
        let source_bytes = validate_source_projection_bound(&projection).unwrap();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        assert_eq!(block.aggregate_operation_bytes, source_bytes);
        block.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        assert!(block.apply_raw(b"x").is_err());
        assert!(block.raw_operations.is_empty());
    }

    #[test]
    fn test_define_meter_helper_builds_a_real_overlay_transition() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let raw = block.test_define_meter_operation_v0().unwrap();
        block.apply_raw(&raw).unwrap();
        let sealed = block.seal().unwrap();
        assert_eq!(sealed.operation_count(), 1);
        assert!(sealed.mutation_count() >= 2);
    }

    #[test]
    fn meter_define_shape_cap_and_prune_negative_fact_are_typed_without_mutation() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let mut bad_shape = PocoApplicationOperationV0::decode_exact(
            &block.test_define_meter_operation_v0().unwrap(),
        )
        .unwrap();
        let PocoApplicationOperationBodyV0::DefineMeterPolicy { policy, .. } = &mut bad_shape.body
        else {
            unreachable!();
        };
        policy.active_from_height = 3;
        let bad_shape_raw = serde_json::to_vec(&bad_shape).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&bad_shape_raw, &bad_shape),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );

        let mut over_cap = PocoApplicationOperationV0::decode_exact(
            &block.test_define_meter_operation_v0().unwrap(),
        )
        .unwrap();
        let PocoApplicationOperationBodyV0::DefineMeterPolicy { policy, .. } = &mut over_cap.body
        else {
            unreachable!();
        };
        let over_protocol_cap = block.context.active_parameters.per_certificate_unit_cap() + 1;
        policy.per_certificate_cap = CanonicalU128V0::new(over_protocol_cap);
        policy.rolling_cap = CanonicalU128V0::new(over_protocol_cap);
        let over_cap_raw = serde_json::to_vec(&over_cap).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&over_cap_raw, &over_cap),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
            )),
        );

        let prune = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::PruneRetiredMeter {
                meter_id_hex: "01".to_string(),
                meter_version: 1,
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let prune_raw = serde_json::to_vec(&prune).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&prune_raw, &prune),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );
        let mut malformed_prune = prune.clone();
        let PocoApplicationOperationBodyV0::PruneRetiredMeter { meter_id_hex, .. } =
            &mut malformed_prune.body
        else {
            unreachable!();
        };
        *meter_id_hex = "0".to_string();
        let malformed_raw = serde_json::to_vec(&malformed_prune).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&malformed_raw, &malformed_prune),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn authorize_consumer_key_preparation_freezes_capacity_and_late_proof_priority() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (mut canonical, operation) = authorize_consumer_key_capacity_fixture(0);
        let raw = serde_json::to_vec(&operation).unwrap();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        let sealed = canonical.seal().unwrap();
        assert_eq!(sealed.operation_count, 1);

        let (mut saturated, operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
        let raw = serde_json::to_vec(&operation).unwrap();
        let before = saturated.clone();
        assert_eq!(
            saturated.apply_decoded_exact(&raw, &operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated, &before);

        let (mut bad_height, mut bad_height_operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
        let PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            active_from_height, ..
        } = &mut bad_height_operation.body
        else {
            unreachable!();
        };
        *active_from_height = bad_height.context.target_height.get() + 1;
        let bad_height_raw = serde_json::to_vec(&bad_height_operation).unwrap();
        let before = bad_height.clone();
        assert_eq!(
            bad_height.apply_decoded_exact(&bad_height_raw, &bad_height_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&bad_height, &before);

        let (mut zero_key, mut zero_key_operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
        let PocoApplicationOperationBodyV0::AuthorizeConsumerKey { public_key_hex, .. } =
            &mut zero_key_operation.body
        else {
            unreachable!();
        };
        *public_key_hex = "00".repeat(32);
        let zero_key_raw = serde_json::to_vec(&zero_key_operation).unwrap();
        let before = zero_key.clone();
        assert_eq!(
            zero_key.apply_decoded_exact(&zero_key_raw, &zero_key_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&zero_key, &before);

        let (mut wrong_decision, mut wrong_decision_operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
        let PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            decision_id_hex, ..
        } = &mut wrong_decision_operation.body
        else {
            unreachable!();
        };
        *decision_id_hex = "ee".repeat(32);
        let wrong_decision_raw = serde_json::to_vec(&wrong_decision_operation).unwrap();
        let before = wrong_decision.clone();
        assert_eq!(
            wrong_decision.apply_decoded_exact(&wrong_decision_raw, &wrong_decision_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&wrong_decision, &before);

        let (mut unsupported_field, mut unsupported_field_operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
        let PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            active_from_height, ..
        } = &mut unsupported_field_operation.body
        else {
            unreachable!();
        };
        *active_from_height = unsupported_field.context.target_height.get() + 1;
        unsupported_field_operation.nullifier_non_membership_checks =
            vec![unsupported_field_operation.nullifier_insertions[0].clone()];
        let unsupported_field_raw = serde_json::to_vec(&unsupported_field_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&unsupported_field_raw).unwrap();
        let before = unsupported_field.clone();
        assert_eq!(
            unsupported_field
                .apply_decoded_exact(&unsupported_field_raw, &unsupported_field_operation),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&unsupported_field, &before);

        let (mut corrupted_semantic, corrupted_semantic_operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
        let raw_change = &corrupted_semantic_operation.semantic_changes[0];
        let kind = PocoSnapshotEntryKindV0::from_u8(raw_change.kind).unwrap();
        let logical_key = exact_hash32_hex(&raw_change.logical_key_hex).unwrap();
        corrupted_semantic
            .overlay
            .entries
            .insert((kind, logical_key.to_vec()), vec![0xff]);
        let corrupted_semantic_raw = serde_json::to_vec(&corrupted_semantic_operation).unwrap();
        let before = corrupted_semantic.clone();
        assert_eq!(
            corrupted_semantic
                .apply_decoded_exact(&corrupted_semantic_raw, &corrupted_semantic_operation),
            Err(Invariant(InvariantReason::AuthenticatedOverlay)),
        );
        assert_block_overlay_unchanged(&corrupted_semantic, &before);

        for count in [u64::MAX - 1, u64::MAX] {
            let (mut exhausted, operation) =
                authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
            exhausted.overlay.accumulator =
                PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], count).unwrap();
            exhausted
                .overlay
                .authority
                .set_accumulator(exhausted.overlay.accumulator);
            let raw = serde_json::to_vec(&operation).unwrap();
            let before = exhausted.clone();
            assert_eq!(
                exhausted.apply_decoded_exact(&raw, &operation),
                Err(Invariant(InvariantReason::ProtocolCounterExhausted)),
            );
            assert_block_overlay_unchanged(&exhausted, &before);
        }

        let (mut counter_boundary, operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
        counter_boundary.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 2).unwrap();
        counter_boundary
            .overlay
            .authority
            .set_accumulator(counter_boundary.overlay.accumulator);
        let raw = serde_json::to_vec(&operation).unwrap();
        let before = counter_boundary.clone();
        assert_eq!(
            counter_boundary.apply_decoded_exact(&raw, &operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&counter_boundary, &before);

        let (mut saturated_bad_shape, mut bad_shape_operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
        bad_shape_operation.nullifier_insertions.pop();
        let bad_shape_raw = serde_json::to_vec(&bad_shape_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_shape_raw).unwrap();
        let before = saturated_bad_shape.clone();
        assert_eq!(
            saturated_bad_shape.apply_decoded_exact(&bad_shape_raw, &bad_shape_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_shape, &before);

        let (mut below_cap_bad_shape, mut bad_shape_operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES - 1);
        bad_shape_operation.nullifier_insertions.pop();
        let bad_shape_raw = serde_json::to_vec(&bad_shape_operation).unwrap();
        let before = below_cap_bad_shape.clone();
        assert_eq!(
            below_cap_bad_shape.apply_decoded_exact(&bad_shape_raw, &bad_shape_operation),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_shape, &before);

        for subject_fault in 0..2 {
            let mutate_subject = |operation: &mut PocoApplicationOperationV0| {
                let raw = &mut operation.nullifier_insertions[0];
                match subject_fault {
                    0 => raw.identifier_hex = "ab".repeat(32),
                    1 => raw.family = PocoNullifierFamilyV0::MeterDecision.code(),
                    _ => unreachable!(),
                }
                let family = PocoNullifierFamilyV0::from_u8(raw.family).unwrap();
                let identifier = exact_hash32_hex(&raw.identifier_hex).unwrap();
                let key = derive_poco_nullifier_key_v0(family, identifier);
                raw.proof_hex = hex::encode(
                    PocoNullifierProofV0::new(key, [[0x55; 32]; 256]).canonical_bytes(),
                );
            };

            let (mut saturated_bad_subject, mut bad_subject_operation) =
                authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
            mutate_subject(&mut bad_subject_operation);
            let bad_subject_raw = serde_json::to_vec(&bad_subject_operation).unwrap();
            PocoApplicationOperationV0::decode_exact(&bad_subject_raw).unwrap();
            let before = saturated_bad_subject.clone();
            assert_eq!(
                saturated_bad_subject.apply_decoded_exact(&bad_subject_raw, &bad_subject_operation),
                Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
            );
            assert_block_overlay_unchanged(&saturated_bad_subject, &before);

            let (mut below_cap_bad_subject, mut bad_subject_operation) =
                authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES - 1);
            mutate_subject(&mut bad_subject_operation);
            let bad_subject_raw = serde_json::to_vec(&bad_subject_operation).unwrap();
            PocoApplicationOperationV0::decode_exact(&bad_subject_raw).unwrap();
            let before = below_cap_bad_subject.clone();
            assert_eq!(
                below_cap_bad_subject.apply_decoded_exact(&bad_subject_raw, &bad_subject_operation),
                Err(DeterministicallyInvalid(Invalid::NullifierProof)),
            );
            assert_block_overlay_unchanged(&below_cap_bad_subject, &before);
        }

        for decode_fault in 0..2 {
            let (_, mut decode_fault_operation) = authorize_consumer_key_capacity_fixture(0);
            let raw = &mut decode_fault_operation.nullifier_insertions[0];
            match decode_fault {
                0 => {
                    raw.proof_hex = hex::encode(
                        PocoNullifierProofV0::new([0x44; 32], [[0x55; 32]; 256]).canonical_bytes(),
                    );
                }
                1 => raw.proof_hex = "00".to_string(),
                _ => unreachable!(),
            }
            let decode_fault_raw = serde_json::to_vec(&decode_fault_operation).unwrap();
            assert!(PocoApplicationOperationV0::decode_exact(&decode_fault_raw).is_err());
        }

        for insertion_index in 0..2 {
            let (mut saturated_bad_root, mut bad_root_operation) =
                authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
            poison_raw_nullifier_roots_v0(
                &mut bad_root_operation.nullifier_insertions[insertion_index..=insertion_index],
            );
            let bad_root_raw = serde_json::to_vec(&bad_root_operation).unwrap();
            PocoApplicationOperationV0::decode_exact(&bad_root_raw).unwrap();
            let before = saturated_bad_root.clone();
            assert_eq!(
                saturated_bad_root.apply_decoded_exact(&bad_root_raw, &bad_root_operation),
                Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
            );
            assert_block_overlay_unchanged(&saturated_bad_root, &before);

            let (mut below_cap_bad_root, mut bad_root_operation) =
                authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES - 1);
            poison_raw_nullifier_roots_v0(
                &mut bad_root_operation.nullifier_insertions[insertion_index..=insertion_index],
            );
            let bad_root_raw = serde_json::to_vec(&bad_root_operation).unwrap();
            let before = below_cap_bad_root.clone();
            assert_eq!(
                below_cap_bad_root.apply_decoded_exact(&bad_root_raw, &bad_root_operation),
                Err(DeterministicallyInvalid(
                    Invalid::NullifierNonMembershipRootMismatch,
                )),
            );
            assert_block_overlay_unchanged(&below_cap_bad_root, &before);
        }

        let (mut below_cap, operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES - 1);
        let accumulator_count_before = below_cap.overlay.accumulator.count();
        let raw = serde_json::to_vec(&operation).unwrap();
        below_cap.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(below_cap.operation_count(), 1);
        assert_eq!(
            below_cap.overlay.authority.consumer_keys.len(),
            MAX_CONSUMER_KEY_AUTHORITIES,
        );
        assert_eq!(
            below_cap.overlay.accumulator.count(),
            accumulator_count_before + 2,
        );
        assert!(below_cap
            .overlay
            .authority
            .consumer_keys
            .windows(2)
            .all(|pair| {
                (&pair[0].consumer_id_hex, &pair[0].consumer_key_id_hex)
                    < (&pair[1].consumer_id_hex, &pair[1].consumer_key_id_hex)
            }));
        assert!(below_cap.overlay.mutations.values().any(|mutation| {
            mutation.kind == PocoSnapshotEntryKindV0::ConsumerKeyAuthorization
        }));

        let (mut operation_full, mut malformed_operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
        let PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            active_from_height, ..
        } = &mut malformed_operation.body
        else {
            unreachable!();
        };
        *active_from_height = operation_full.context.target_height.get() + 1;
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        operation_full.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let before = operation_full.clone();
        assert_eq!(
            operation_full.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&operation_full, &before);

        let (mut byte_full, mut malformed_operation) =
            authorize_consumer_key_capacity_fixture(MAX_CONSUMER_KEY_AUTHORITIES);
        let PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            active_from_height, ..
        } = &mut malformed_operation.body
        else {
            unreachable!();
        };
        *active_from_height = byte_full.context.target_height.get() + 1;
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        byte_full.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        let before = byte_full.clone();
        assert_eq!(
            byte_full.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&byte_full, &before);

        let (tag_block, operation) = authorize_consumer_key_capacity_fixture(0);
        let decision_preimage =
            decision_preimage_digest_v0(&tag_block.context, &operation).unwrap();
        let prepared = validate_operation_capacity_before_clone_v0(
            &tag_block.context,
            &tag_block.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut mismatched_operation = operation;
        mismatched_operation.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        let mut candidate = tag_block.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &tag_block.context,
            &mut candidate,
            &mismatched_operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(
            candidate.source_authority_value,
            before.source_authority_value
        );
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(candidate.operation_ids.is_empty());
    }

    #[test]
    fn define_meter_preparation_freezes_capacity_and_late_proof_priority() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (mut saturated, operation) = define_meter_capacity_fixture(MAX_METER_POLICIES);
        let raw = serde_json::to_vec(&operation).unwrap();
        let before = saturated.clone();
        assert_eq!(
            saturated.apply_decoded_exact(&raw, &operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated, &before);

        let (mut malformed, mut malformed_operation) =
            define_meter_capacity_fixture(MAX_METER_POLICIES);
        let PocoApplicationOperationBodyV0::DefineMeterPolicy { policy, .. } =
            &mut malformed_operation.body
        else {
            unreachable!();
        };
        policy.active_from_height = 3;
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        let before = malformed.clone();
        assert_eq!(
            malformed.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&malformed, &before);

        let (mut unsupported_field, mut unsupported_field_operation) =
            define_meter_capacity_fixture(MAX_METER_POLICIES);
        unsupported_field_operation.nullifier_non_membership_checks =
            vec![unsupported_field_operation.nullifier_insertions[0].clone()];
        let unsupported_field_raw = serde_json::to_vec(&unsupported_field_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&unsupported_field_raw).unwrap();
        let before = unsupported_field.clone();
        assert_eq!(
            unsupported_field
                .apply_decoded_exact(&unsupported_field_raw, &unsupported_field_operation),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&unsupported_field, &before);

        let (mut foreign_semantic, mut foreign_semantic_operation) =
            define_meter_capacity_fixture(MAX_METER_POLICIES);
        foreign_semantic_operation.semantic_changes[0].logical_key_hex = "ab".repeat(32);
        bind_define_meter_decision_v0(&foreign_semantic.context, &mut foreign_semantic_operation);
        let foreign_semantic_raw = serde_json::to_vec(&foreign_semantic_operation).unwrap();
        let before = foreign_semantic.clone();
        assert_eq!(
            foreign_semantic
                .apply_decoded_exact(&foreign_semantic_raw, &foreign_semantic_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&foreign_semantic, &before);

        let (mut saturated_bad_proof, mut bad_proof_operation) =
            define_meter_capacity_fixture(MAX_METER_POLICIES);
        poison_nullifier_roots_v0(&mut bad_proof_operation);
        let bad_proof_raw = serde_json::to_vec(&bad_proof_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_proof_raw).unwrap();
        let before = saturated_bad_proof.clone();
        assert_eq!(
            saturated_bad_proof.apply_decoded_exact(&bad_proof_raw, &bad_proof_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_proof, &before);

        let (mut below_cap_bad_proof, mut bad_proof_operation) =
            define_meter_capacity_fixture(MAX_METER_POLICIES - 1);
        poison_nullifier_roots_v0(&mut bad_proof_operation);
        let bad_proof_raw = serde_json::to_vec(&bad_proof_operation).unwrap();
        let before = below_cap_bad_proof.clone();
        assert_eq!(
            below_cap_bad_proof.apply_decoded_exact(&bad_proof_raw, &bad_proof_operation),
            Err(DeterministicallyInvalid(
                Invalid::NullifierNonMembershipRootMismatch,
            )),
        );
        assert_block_overlay_unchanged(&below_cap_bad_proof, &before);

        let (mut below_cap, operation) = define_meter_capacity_fixture(MAX_METER_POLICIES - 1);
        let raw = serde_json::to_vec(&operation).unwrap();
        below_cap.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(below_cap.operation_count(), 1);
        assert_eq!(
            below_cap.overlay.authority.meter_policies.len(),
            MAX_METER_POLICIES,
        );

        let (mut operation_full, mut malformed_operation) =
            define_meter_capacity_fixture(MAX_METER_POLICIES);
        let PocoApplicationOperationBodyV0::DefineMeterPolicy { policy, .. } =
            &mut malformed_operation.body
        else {
            unreachable!();
        };
        policy.active_from_height = 3;
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        operation_full.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let before = operation_full.clone();
        assert_eq!(
            operation_full.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&operation_full, &before);

        let (mut byte_full, mut malformed_operation) =
            define_meter_capacity_fixture(MAX_METER_POLICIES);
        let PocoApplicationOperationBodyV0::DefineMeterPolicy { policy, .. } =
            &mut malformed_operation.body
        else {
            unreachable!();
        };
        policy.active_from_height = 3;
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        byte_full.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        let before = byte_full.clone();
        assert_eq!(
            byte_full.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&byte_full, &before);

        for exhausted_count in [u64::MAX - 1, u64::MAX] {
            let (mut exhausted, operation) = define_meter_capacity_fixture(MAX_METER_POLICIES);
            exhausted.overlay.accumulator =
                PocoNullifierAccumulatorV0::from_authenticated_parts([1; 32], exhausted_count)
                    .unwrap();
            exhausted
                .overlay
                .authority
                .set_accumulator(exhausted.overlay.accumulator);
            let raw = serde_json::to_vec(&operation).unwrap();
            let before = exhausted.clone();
            assert_eq!(
                exhausted.apply_decoded_exact(&raw, &operation),
                Err(Invariant(InvariantReason::ProtocolCounterExhausted)),
            );
            assert_block_overlay_unchanged(&exhausted, &before);
        }
    }

    #[test]
    fn define_meter_preclone_field_admission_does_not_reorder_deferred_families() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let mut operation = minimal_operation();
        let mut define_meter = PocoApplicationOperationV0::decode_exact(
            &block.test_define_meter_operation_v0().unwrap(),
        )
        .unwrap();
        operation.nullifier_non_membership_checks =
            vec![define_meter.nullifier_insertions.remove(0)];
        let raw = serde_json::to_vec(&operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&raw).unwrap();
        let before = block.clone();

        assert_eq!(
            block.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );
        assert_block_overlay_unchanged(&block, &before);
    }

    #[test]
    fn fund_settlement_preparation_freezes_capacity_and_late_proof_priority() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (mut saturated, operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        let raw = serde_json::to_vec(&operation).unwrap();
        let before = saturated.clone();
        assert_eq!(
            saturated.apply_decoded_exact(&raw, &operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated, &before);

        let (mut malformed, mut malformed_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        let PocoApplicationOperationBodyV0::FundSettlement { reserved_units, .. } =
            &mut malformed_operation.body
        else {
            unreachable!();
        };
        *reserved_units = CanonicalU128V0::new(0);
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        let before = malformed.clone();
        assert_eq!(
            malformed.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&malformed, &before);

        let (mut wrong_decision, mut wrong_decision_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        let PocoApplicationOperationBodyV0::FundSettlement {
            funding_decision_id_hex,
            ..
        } = &mut wrong_decision_operation.body
        else {
            unreachable!();
        };
        *funding_decision_id_hex = "ee".repeat(32);
        let wrong_decision_raw = serde_json::to_vec(&wrong_decision_operation).unwrap();
        let before = wrong_decision.clone();
        assert_eq!(
            wrong_decision.apply_decoded_exact(&wrong_decision_raw, &wrong_decision_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&wrong_decision, &before);

        let (mut duplicate, duplicate_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        let PocoApplicationOperationBodyV0::FundSettlement {
            certificate_id_hex, ..
        } = &duplicate_operation.body
        else {
            unreachable!();
        };
        duplicate.overlay.authority.funded_unused_reservations[0].certificate_id_hex =
            certificate_id_hex.clone();
        duplicate
            .overlay
            .authority
            .funded_unused_reservations
            .sort_by(|left, right| left.certificate_id_hex.cmp(&right.certificate_id_hex));
        let duplicate_raw = serde_json::to_vec(&duplicate_operation).unwrap();
        let before = duplicate.clone();
        assert_eq!(
            duplicate.apply_decoded_exact(&duplicate_raw, &duplicate_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&duplicate, &before);

        let (mut foreign_semantic, mut foreign_semantic_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        foreign_semantic_operation.semantic_changes[0].logical_key_hex = "cd".repeat(32);
        bind_fund_settlement_decision_v0(
            &foreign_semantic.context,
            &mut foreign_semantic_operation,
        );
        let foreign_semantic_raw = serde_json::to_vec(&foreign_semantic_operation).unwrap();
        let before = foreign_semantic.clone();
        assert_eq!(
            foreign_semantic
                .apply_decoded_exact(&foreign_semantic_raw, &foreign_semantic_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&foreign_semantic, &before);

        let (mut corrupted_semantic, corrupted_semantic_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        let raw_change = &corrupted_semantic_operation.semantic_changes[0];
        let kind = PocoSnapshotEntryKindV0::from_u8(raw_change.kind).unwrap();
        let logical_key = exact_hash32_hex(&raw_change.logical_key_hex).unwrap();
        corrupted_semantic
            .overlay
            .entries
            .insert((kind, logical_key.to_vec()), vec![0xff]);
        let corrupted_semantic_raw = serde_json::to_vec(&corrupted_semantic_operation).unwrap();
        let before = corrupted_semantic.clone();
        assert_eq!(
            corrupted_semantic
                .apply_decoded_exact(&corrupted_semantic_raw, &corrupted_semantic_operation,),
            Err(Invariant(InvariantReason::AuthenticatedOverlay)),
        );
        assert_block_overlay_unchanged(&corrupted_semantic, &before);

        let (mut saturated_bad_proof, mut bad_proof_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        poison_nullifier_roots_v0(&mut bad_proof_operation);
        let bad_proof_raw = serde_json::to_vec(&bad_proof_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_proof_raw).unwrap();
        let before = saturated_bad_proof.clone();
        assert_eq!(
            saturated_bad_proof.apply_decoded_exact(&bad_proof_raw, &bad_proof_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_proof, &before);

        let (mut below_cap_bad_proof, mut bad_proof_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS - 1);
        poison_nullifier_roots_v0(&mut bad_proof_operation);
        let bad_proof_raw = serde_json::to_vec(&bad_proof_operation).unwrap();
        let before = below_cap_bad_proof.clone();
        assert_eq!(
            below_cap_bad_proof.apply_decoded_exact(&bad_proof_raw, &bad_proof_operation),
            Err(DeterministicallyInvalid(
                Invalid::NullifierNonMembershipRootMismatch,
            )),
        );
        assert_block_overlay_unchanged(&below_cap_bad_proof, &before);

        let (mut saturated_bad_insertion, mut bad_insertion_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        poison_raw_nullifier_roots_v0(&mut bad_insertion_operation.nullifier_insertions);
        let bad_insertion_raw = serde_json::to_vec(&bad_insertion_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_insertion_raw).unwrap();
        let before = saturated_bad_insertion.clone();
        assert_eq!(
            saturated_bad_insertion
                .apply_decoded_exact(&bad_insertion_raw, &bad_insertion_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_insertion, &before);

        let (mut below_cap_bad_insertion, mut bad_insertion_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS - 1);
        poison_raw_nullifier_roots_v0(&mut bad_insertion_operation.nullifier_insertions);
        let bad_insertion_raw = serde_json::to_vec(&bad_insertion_operation).unwrap();
        let before = below_cap_bad_insertion.clone();
        assert_eq!(
            below_cap_bad_insertion
                .apply_decoded_exact(&bad_insertion_raw, &bad_insertion_operation),
            Err(DeterministicallyInvalid(
                Invalid::NullifierNonMembershipRootMismatch,
            )),
        );
        assert_block_overlay_unchanged(&below_cap_bad_insertion, &before);

        let (mut saturated_bad_shape, mut bad_shape_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        bad_shape_operation.nullifier_non_membership_checks.clear();
        let bad_shape_raw = serde_json::to_vec(&bad_shape_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_shape_raw).unwrap();
        let before = saturated_bad_shape.clone();
        assert_eq!(
            saturated_bad_shape.apply_decoded_exact(&bad_shape_raw, &bad_shape_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_shape, &before);

        let (mut below_cap_bad_shape, mut bad_shape_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS - 1);
        bad_shape_operation.nullifier_non_membership_checks.clear();
        let bad_shape_raw = serde_json::to_vec(&bad_shape_operation).unwrap();
        let before = below_cap_bad_shape.clone();
        assert_eq!(
            below_cap_bad_shape.apply_decoded_exact(&bad_shape_raw, &bad_shape_operation),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_shape, &before);

        let (mut below_cap, operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS - 1);
        let accumulator_count_before = below_cap.overlay.accumulator.count();
        let raw = serde_json::to_vec(&operation).unwrap();
        below_cap.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(below_cap.operation_count(), 1);
        assert_eq!(
            below_cap.overlay.authority.funded_unused_reservations.len(),
            MAX_FUNDED_UNUSED_RESERVATIONS,
        );
        assert_eq!(
            below_cap.overlay.accumulator.count(),
            accumulator_count_before + 1,
        );
        assert!(below_cap
            .overlay
            .mutations
            .values()
            .any(|mutation| mutation.kind == PocoSnapshotEntryKindV0::Settlement));

        let (mut operation_full, mut malformed_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        let PocoApplicationOperationBodyV0::FundSettlement { reserved_units, .. } =
            &mut malformed_operation.body
        else {
            unreachable!();
        };
        *reserved_units = CanonicalU128V0::new(0);
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        operation_full.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let before = operation_full.clone();
        assert_eq!(
            operation_full.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&operation_full, &before);

        let (mut byte_full, mut malformed_operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        let PocoApplicationOperationBodyV0::FundSettlement { reserved_units, .. } =
            &mut malformed_operation.body
        else {
            unreachable!();
        };
        *reserved_units = CanonicalU128V0::new(0);
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        byte_full.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        let before = byte_full.clone();
        assert_eq!(
            byte_full.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&byte_full, &before);

        let (mut exhausted, operation) =
            fund_settlement_capacity_fixture(MAX_FUNDED_UNUSED_RESERVATIONS);
        exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX).unwrap();
        exhausted
            .overlay
            .authority
            .set_accumulator(exhausted.overlay.accumulator);
        let raw = serde_json::to_vec(&operation).unwrap();
        let before = exhausted.clone();
        assert_eq!(
            exhausted.apply_decoded_exact(&raw, &operation),
            Err(Invariant(InvariantReason::ProtocolCounterExhausted)),
        );
        assert_block_overlay_unchanged(&exhausted, &before);
    }

    #[test]
    fn open_challenge_preparation_freezes_capacity_and_late_proof_priority() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (mut saturated, operation) = open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        let raw = serde_json::to_vec(&operation).unwrap();
        let before = saturated.clone();
        assert_eq!(
            saturated.apply_decoded_exact(&raw, &operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated, &before);

        let (mut unsupported_field, mut unsupported_field_operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        let PocoApplicationOperationBodyV0::OpenChallenge {
            opening_decision_id_hex,
            ..
        } = &mut unsupported_field_operation.body
        else {
            unreachable!();
        };
        *opening_decision_id_hex = "ee".repeat(32);
        unsupported_field_operation.nullifier_non_membership_checks =
            vec![unsupported_field_operation.nullifier_insertions[0].clone()];
        let unsupported_field_raw = serde_json::to_vec(&unsupported_field_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&unsupported_field_raw).unwrap();
        let before = unsupported_field.clone();
        assert_eq!(
            unsupported_field
                .apply_decoded_exact(&unsupported_field_raw, &unsupported_field_operation),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&unsupported_field, &before);

        for decision_fault in 0..2 {
            let (mut malformed, mut malformed_operation) =
                open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
            let PocoApplicationOperationBodyV0::OpenChallenge {
                challenge_id_hex,
                opening_decision_id_hex,
                ..
            } = &mut malformed_operation.body
            else {
                unreachable!();
            };
            if decision_fault == 0 {
                *challenge_id_hex = "dd".repeat(32);
            } else {
                *opening_decision_id_hex = "ee".repeat(32);
            }
            let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
            PocoApplicationOperationV0::decode_exact(&malformed_raw).unwrap();
            let before = malformed.clone();
            assert_eq!(
                malformed.apply_decoded_exact(&malformed_raw, &malformed_operation),
                Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
            );
            assert_block_overlay_unchanged(&malformed, &before);
        }

        let (mut foreign_semantic, mut foreign_semantic_operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        foreign_semantic_operation.semantic_changes[0].logical_key_hex = "ab".repeat(32);
        bind_open_challenge_decisions_v0(
            &foreign_semantic.context,
            &mut foreign_semantic_operation,
        );
        let foreign_semantic_raw = serde_json::to_vec(&foreign_semantic_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&foreign_semantic_raw).unwrap();
        let before = foreign_semantic.clone();
        assert_eq!(
            foreign_semantic
                .apply_decoded_exact(&foreign_semantic_raw, &foreign_semantic_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&foreign_semantic, &before);

        let (mut malformed_next, mut malformed_next_operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        let raw_change = &mut malformed_next_operation.semantic_changes[0];
        let kind = PocoSnapshotEntryKindV0::from_u8(raw_change.kind).unwrap();
        let logical_key = exact_hash32_hex(&raw_change.logical_key_hex).unwrap();
        let next_value = hex::decode(raw_change.next_value_hex.as_deref().unwrap()).unwrap();
        let next = owned_semantic_parts(kind, &logical_key, &next_value).unwrap();
        let mut malformed_next_payload = next.payload.clone();
        let height_offset = malformed_next_payload.len() - std::mem::size_of::<u64>();
        malformed_next_payload[height_offset..]
            .copy_from_slice(&(malformed_next.context.target_height.get() + 1).to_be_bytes());
        raw_change.next_value_hex = Some(hex::encode(encode_test_semantic_envelope_v0(
            kind,
            next.revision,
            &next.identity,
            &malformed_next_payload,
        )));
        bind_open_challenge_decisions_v0(&malformed_next.context, &mut malformed_next_operation);
        let malformed_next_raw = serde_json::to_vec(&malformed_next_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&malformed_next_raw).unwrap();
        let before = malformed_next.clone();
        assert_eq!(
            malformed_next.apply_decoded_exact(&malformed_next_raw, &malformed_next_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&malformed_next, &before);

        let (mut corrupted_semantic, corrupted_semantic_operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        let raw_change = &corrupted_semantic_operation.semantic_changes[0];
        let kind = PocoSnapshotEntryKindV0::from_u8(raw_change.kind).unwrap();
        let logical_key = exact_hash32_hex(&raw_change.logical_key_hex).unwrap();
        corrupted_semantic
            .overlay
            .entries
            .insert((kind, logical_key.to_vec()), vec![0xff]);
        let corrupted_semantic_raw = serde_json::to_vec(&corrupted_semantic_operation).unwrap();
        let before = corrupted_semantic.clone();
        assert_eq!(
            corrupted_semantic
                .apply_decoded_exact(&corrupted_semantic_raw, &corrupted_semantic_operation),
            Err(Invariant(InvariantReason::AuthenticatedOverlay)),
        );
        assert_block_overlay_unchanged(&corrupted_semantic, &before);

        let (mut exhausted, operation) = open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX).unwrap();
        exhausted
            .overlay
            .authority
            .set_accumulator(exhausted.overlay.accumulator);
        let raw = serde_json::to_vec(&operation).unwrap();
        let before = exhausted.clone();
        assert_eq!(
            exhausted.apply_decoded_exact(&raw, &operation),
            Err(Invariant(InvariantReason::ProtocolCounterExhausted)),
        );
        assert_block_overlay_unchanged(&exhausted, &before);

        let (mut counter_boundary, operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        counter_boundary.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        counter_boundary
            .overlay
            .authority
            .set_accumulator(counter_boundary.overlay.accumulator);
        let raw = serde_json::to_vec(&operation).unwrap();
        let before = counter_boundary.clone();
        assert_eq!(
            counter_boundary.apply_decoded_exact(&raw, &operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&counter_boundary, &before);

        let (mut saturated_bad_shape, mut bad_shape_operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        bad_shape_operation.nullifier_insertions.clear();
        let bad_shape_raw = serde_json::to_vec(&bad_shape_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_shape_raw).unwrap();
        let before = saturated_bad_shape.clone();
        assert_eq!(
            saturated_bad_shape.apply_decoded_exact(&bad_shape_raw, &bad_shape_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_shape, &before);

        let (mut below_cap_bad_shape, mut bad_shape_operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES - 1);
        bad_shape_operation.nullifier_insertions.clear();
        let bad_shape_raw = serde_json::to_vec(&bad_shape_operation).unwrap();
        let before = below_cap_bad_shape.clone();
        assert_eq!(
            below_cap_bad_shape.apply_decoded_exact(&bad_shape_raw, &bad_shape_operation),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_shape, &before);

        for subject_fault in 0..2 {
            let mutate_subject = |operation: &mut PocoApplicationOperationV0| {
                let raw = &mut operation.nullifier_insertions[0];
                match subject_fault {
                    0 => raw.identifier_hex = "ab".repeat(32),
                    1 => raw.family = PocoNullifierFamilyV0::MeterDecision.code(),
                    _ => unreachable!(),
                }
                let family = PocoNullifierFamilyV0::from_u8(raw.family).unwrap();
                let identifier = exact_hash32_hex(&raw.identifier_hex).unwrap();
                let key = derive_poco_nullifier_key_v0(family, identifier);
                raw.proof_hex = hex::encode(
                    PocoNullifierProofV0::new(key, [[0x55; 32]; 256]).canonical_bytes(),
                );
            };

            let (mut saturated_bad_subject, mut bad_subject_operation) =
                open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
            mutate_subject(&mut bad_subject_operation);
            let bad_subject_raw = serde_json::to_vec(&bad_subject_operation).unwrap();
            PocoApplicationOperationV0::decode_exact(&bad_subject_raw).unwrap();
            let before = saturated_bad_subject.clone();
            assert_eq!(
                saturated_bad_subject.apply_decoded_exact(&bad_subject_raw, &bad_subject_operation),
                Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
            );
            assert_block_overlay_unchanged(&saturated_bad_subject, &before);

            let (mut below_cap_bad_subject, mut bad_subject_operation) =
                open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES - 1);
            mutate_subject(&mut bad_subject_operation);
            let bad_subject_raw = serde_json::to_vec(&bad_subject_operation).unwrap();
            PocoApplicationOperationV0::decode_exact(&bad_subject_raw).unwrap();
            let before = below_cap_bad_subject.clone();
            assert_eq!(
                below_cap_bad_subject.apply_decoded_exact(&bad_subject_raw, &bad_subject_operation),
                Err(DeterministicallyInvalid(Invalid::NullifierProof)),
            );
            assert_block_overlay_unchanged(&below_cap_bad_subject, &before);
        }

        let (mut saturated_bad_root, mut bad_root_operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        poison_raw_nullifier_roots_v0(&mut bad_root_operation.nullifier_insertions);
        let bad_root_raw = serde_json::to_vec(&bad_root_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_root_raw).unwrap();
        let before = saturated_bad_root.clone();
        assert_eq!(
            saturated_bad_root.apply_decoded_exact(&bad_root_raw, &bad_root_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_root, &before);

        let (mut below_cap_bad_root, mut bad_root_operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES - 1);
        poison_raw_nullifier_roots_v0(&mut bad_root_operation.nullifier_insertions);
        let bad_root_raw = serde_json::to_vec(&bad_root_operation).unwrap();
        let before = below_cap_bad_root.clone();
        assert_eq!(
            below_cap_bad_root.apply_decoded_exact(&bad_root_raw, &bad_root_operation),
            Err(DeterministicallyInvalid(
                Invalid::NullifierNonMembershipRootMismatch,
            )),
        );
        assert_block_overlay_unchanged(&below_cap_bad_root, &before);

        let (mut below_cap, operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES - 1);
        let accumulator_count_before = below_cap.overlay.accumulator.count();
        let raw = serde_json::to_vec(&operation).unwrap();
        below_cap.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(below_cap.operation_count(), 1);
        assert_eq!(
            below_cap.overlay.authority.pending_challenges.len(),
            MAX_PENDING_CHALLENGES,
        );
        assert_eq!(
            below_cap.overlay.accumulator.count(),
            accumulator_count_before + 1,
        );
        assert!(below_cap
            .overlay
            .authority
            .pending_challenges
            .windows(2)
            .all(|pair| pair[0].challenge_id_hex < pair[1].challenge_id_hex));
        assert!(below_cap
            .overlay
            .mutations
            .values()
            .any(|mutation| { mutation.kind == PocoSnapshotEntryKindV0::RevocationOrChallenge }));

        let (mut operation_full, mut malformed_operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        let PocoApplicationOperationBodyV0::OpenChallenge {
            challenge_id_hex, ..
        } = &mut malformed_operation.body
        else {
            unreachable!();
        };
        *challenge_id_hex = "dd".repeat(32);
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        operation_full.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let before = operation_full.clone();
        assert_eq!(
            operation_full.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&operation_full, &before);

        let (mut byte_full, mut malformed_operation) =
            open_challenge_capacity_fixture(MAX_PENDING_CHALLENGES);
        let PocoApplicationOperationBodyV0::OpenChallenge {
            challenge_id_hex, ..
        } = &mut malformed_operation.body
        else {
            unreachable!();
        };
        *challenge_id_hex = "dd".repeat(32);
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        byte_full.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        let before = byte_full.clone();
        assert_eq!(
            byte_full.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&byte_full, &before);

        let (tag_block, operation) = open_challenge_capacity_fixture(0);
        let decision_preimage =
            decision_preimage_digest_v0(&tag_block.context, &operation).unwrap();
        let prepared = validate_operation_capacity_before_clone_v0(
            &tag_block.context,
            &tag_block.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut mismatched_operation = operation;
        mismatched_operation.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        let mut candidate = tag_block.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &tag_block.context,
            &mut candidate,
            &mismatched_operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(
            candidate.source_authority_value,
            before.source_authority_value
        );
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(candidate.operation_ids.is_empty());
    }

    #[test]
    fn future_candidate_capacity_precedes_crypto_and_prepares_late_proofs() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (saturated, saturated_raw, saturated_operation) =
            fixture_authoring::future_candidate_capacity_fixture_v0(
                MAX_FUTURE_CANDIDATE_REGISTRATIONS,
            )
            .unwrap();
        assert_eq!(
            saturated
                .overlay
                .authority
                .future_candidate_registrations
                .len(),
            MAX_FUTURE_CANDIDATE_REGISTRATIONS,
        );
        assert_eq!(
            saturated.operation_count(),
            MAX_FUTURE_CANDIDATE_REGISTRATIONS,
        );
        let mut canonical_cap = saturated.clone();
        let before = canonical_cap.clone();
        assert_eq!(
            canonical_cap.apply_decoded_exact(&saturated_raw, &saturated_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&canonical_cap, &before);

        let (below_cap, below_cap_raw, below_cap_operation) =
            fixture_authoring::future_candidate_capacity_fixture_v0(
                MAX_FUTURE_CANDIDATE_REGISTRATIONS - 1,
            )
            .unwrap();
        assert_eq!(
            below_cap
                .overlay
                .authority
                .future_candidate_registrations
                .len(),
            MAX_FUTURE_CANDIDATE_REGISTRATIONS - 1,
        );

        let poison_pop = |operation: &mut PocoApplicationOperationV0| {
            let PocoApplicationOperationBodyV0::RegisterFutureCandidate { proof_cev0_hex, .. } =
                &mut operation.body
            else {
                unreachable!();
            };
            *proof_cev0_hex = "00".to_string();
        };

        let mut saturated_bad_pop = saturated.clone();
        let mut bad_pop_operation = saturated_operation.clone();
        poison_pop(&mut bad_pop_operation);
        let bad_pop_raw = serde_json::to_vec(&bad_pop_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_pop_raw).unwrap();
        let before = saturated_bad_pop.clone();
        assert_eq!(
            saturated_bad_pop.apply_decoded_exact(&bad_pop_raw, &bad_pop_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_pop, &before);

        let mut below_cap_bad_pop = below_cap.clone();
        let mut bad_pop_operation = below_cap_operation.clone();
        poison_pop(&mut bad_pop_operation);
        let bad_pop_raw = serde_json::to_vec(&bad_pop_operation).unwrap();
        let before = below_cap_bad_pop.clone();
        assert_eq!(
            below_cap_bad_pop.apply_decoded_exact(&bad_pop_raw, &bad_pop_operation),
            Err(DeterministicallyInvalid(Invalid::CryptographicProof)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_pop, &before);

        let mut saturated_unsupported = saturated.clone();
        let mut unsupported_operation = saturated_operation.clone();
        unsupported_operation.nullifier_non_membership_checks =
            vec![unsupported_operation.nullifier_insertions[0].clone()];
        let unsupported_raw = serde_json::to_vec(&unsupported_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&unsupported_raw).unwrap();
        let before = saturated_unsupported.clone();
        assert_eq!(
            saturated_unsupported.apply_decoded_exact(&unsupported_raw, &unsupported_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_unsupported, &before);

        let mut below_cap_unsupported = below_cap.clone();
        let mut unsupported_operation = below_cap_operation.clone();
        unsupported_operation.nullifier_non_membership_checks =
            vec![unsupported_operation.nullifier_insertions[0].clone()];
        let unsupported_raw = serde_json::to_vec(&unsupported_operation).unwrap();
        let before = below_cap_unsupported.clone();
        assert_eq!(
            below_cap_unsupported.apply_decoded_exact(&unsupported_raw, &unsupported_operation),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&below_cap_unsupported, &before);

        let mutate_target_epoch = |operation: &mut PocoApplicationOperationV0| {
            let PocoApplicationOperationBodyV0::RegisterFutureCandidate { target_epoch, .. } =
                &mut operation.body
            else {
                unreachable!();
            };
            *target_epoch = target_epoch.checked_add(1).unwrap();
        };
        let mut saturated_bad_epoch = saturated.clone();
        let mut bad_epoch_operation = saturated_operation.clone();
        mutate_target_epoch(&mut bad_epoch_operation);
        let bad_epoch_raw = serde_json::to_vec(&bad_epoch_operation).unwrap();
        let before = saturated_bad_epoch.clone();
        assert_eq!(
            saturated_bad_epoch.apply_decoded_exact(&bad_epoch_raw, &bad_epoch_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_epoch, &before);

        let mut below_cap_bad_epoch = below_cap.clone();
        let mut bad_epoch_operation = below_cap_operation.clone();
        mutate_target_epoch(&mut bad_epoch_operation);
        let bad_epoch_raw = serde_json::to_vec(&bad_epoch_operation).unwrap();
        let before = below_cap_bad_epoch.clone();
        assert_eq!(
            below_cap_bad_epoch.apply_decoded_exact(&bad_epoch_raw, &bad_epoch_operation),
            Err(DeterministicallyInvalid(Invalid::ValidatorRule)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_epoch, &before);

        let mutate_predecessor = |operation: &mut PocoApplicationOperationV0| {
            let PocoApplicationOperationBodyV0::RegisterFutureCandidate {
                predecessor_history_head_hex,
                ..
            } = &mut operation.body
            else {
                unreachable!();
            };
            *predecessor_history_head_hex = "01".repeat(32);
        };
        let mut saturated_bad_predecessor = saturated.clone();
        let mut bad_predecessor_operation = saturated_operation.clone();
        mutate_predecessor(&mut bad_predecessor_operation);
        let bad_predecessor_raw = serde_json::to_vec(&bad_predecessor_operation).unwrap();
        let before = saturated_bad_predecessor.clone();
        assert_eq!(
            saturated_bad_predecessor
                .apply_decoded_exact(&bad_predecessor_raw, &bad_predecessor_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_predecessor, &before);

        let mut below_cap_bad_predecessor = below_cap.clone();
        let mut bad_predecessor_operation = below_cap_operation.clone();
        mutate_predecessor(&mut bad_predecessor_operation);
        let bad_predecessor_raw = serde_json::to_vec(&bad_predecessor_operation).unwrap();
        let before = below_cap_bad_predecessor.clone();
        assert_eq!(
            below_cap_bad_predecessor
                .apply_decoded_exact(&bad_predecessor_raw, &bad_predecessor_operation),
            Err(DeterministicallyInvalid(Invalid::ValidatorRule)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_predecessor, &before);

        let mutate_decision = |operation: &mut PocoApplicationOperationV0| {
            let PocoApplicationOperationBodyV0::RegisterFutureCandidate {
                registration_decision_id_hex,
                ..
            } = &mut operation.body
            else {
                unreachable!();
            };
            *registration_decision_id_hex = "aa".repeat(32);
        };
        let mut saturated_bad_decision = saturated.clone();
        let mut bad_decision_operation = saturated_operation.clone();
        mutate_decision(&mut bad_decision_operation);
        let bad_decision_raw = serde_json::to_vec(&bad_decision_operation).unwrap();
        let before = saturated_bad_decision.clone();
        assert_eq!(
            saturated_bad_decision.apply_decoded_exact(&bad_decision_raw, &bad_decision_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_decision, &before);

        let mut below_cap_bad_decision = below_cap.clone();
        let mut bad_decision_operation = below_cap_operation.clone();
        mutate_decision(&mut bad_decision_operation);
        let bad_decision_raw = serde_json::to_vec(&bad_decision_operation).unwrap();
        let before = below_cap_bad_decision.clone();
        assert_eq!(
            below_cap_bad_decision.apply_decoded_exact(&bad_decision_raw, &bad_decision_operation),
            Err(DeterministicallyInvalid(Invalid::SemanticTransition)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_decision, &before);

        let mut duplicate = saturated.clone();
        let mut duplicate_operation = saturated_operation.clone();
        let existing = &duplicate.overlay.authority.future_candidate_registrations[0];
        let PocoApplicationOperationBodyV0::RegisterFutureCandidate {
            validator_id_hex,
            target_epoch,
            ..
        } = &mut duplicate_operation.body
        else {
            unreachable!();
        };
        *validator_id_hex = existing.validator_id_hex.clone();
        *target_epoch = existing.target_epoch;
        let duplicate_raw = serde_json::to_vec(&duplicate_operation).unwrap();
        let before = duplicate.clone();
        assert_eq!(
            duplicate.apply_decoded_exact(&duplicate_raw, &duplicate_operation),
            Err(DeterministicallyInvalid(Invalid::ValidatorRule)),
        );
        assert_block_overlay_unchanged(&duplicate, &before);

        let mut malformed_id = saturated.clone();
        let mut malformed_id_operation = saturated_operation.clone();
        let PocoApplicationOperationBodyV0::RegisterFutureCandidate {
            validator_id_hex, ..
        } = &mut malformed_id_operation.body
        else {
            unreachable!();
        };
        *validator_id_hex = "0".to_string();
        let malformed_id_raw = serde_json::to_vec(&malformed_id_operation).unwrap();
        let before = malformed_id.clone();
        assert_eq!(
            malformed_id.apply_decoded_exact(&malformed_id_raw, &malformed_id_operation),
            Err(DeterministicallyInvalid(Invalid::ValidatorRule)),
        );
        assert_block_overlay_unchanged(&malformed_id, &before);

        let mut saturated_exhausted = saturated.clone();
        saturated_exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        saturated_exhausted
            .overlay
            .authority
            .set_accumulator(saturated_exhausted.overlay.accumulator);
        let mut bad_pop_operation = saturated_operation.clone();
        poison_pop(&mut bad_pop_operation);
        let bad_pop_raw = serde_json::to_vec(&bad_pop_operation).unwrap();
        let before = saturated_exhausted.clone();
        assert_eq!(
            saturated_exhausted.apply_decoded_exact(&bad_pop_raw, &bad_pop_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_exhausted, &before);

        let mut below_cap_exhausted = below_cap.clone();
        below_cap_exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX - 1).unwrap();
        below_cap_exhausted
            .overlay
            .authority
            .set_accumulator(below_cap_exhausted.overlay.accumulator);
        let mut bad_pop_operation = below_cap_operation.clone();
        poison_pop(&mut bad_pop_operation);
        let bad_pop_raw = serde_json::to_vec(&bad_pop_operation).unwrap();
        let before = below_cap_exhausted.clone();
        assert_eq!(
            below_cap_exhausted.apply_decoded_exact(&bad_pop_raw, &bad_pop_operation),
            Err(Invariant(InvariantReason::ProtocolCounterExhausted)),
        );
        assert_block_overlay_unchanged(&below_cap_exhausted, &before);

        let mut missing_active_context = below_cap.clone();
        let active_key = missing_active_context
            .overlay
            .entries
            .keys()
            .find(|(kind, _)| *kind == PocoSnapshotEntryKindV0::ValidatorConfiguration)
            .cloned()
            .unwrap();
        missing_active_context.overlay.entries.remove(&active_key);
        let before = missing_active_context.clone();
        assert_eq!(
            missing_active_context.apply_decoded_exact(&below_cap_raw, &below_cap_operation),
            Err(Invariant(InvariantReason::AuthenticatedOverlay)),
        );
        assert_block_overlay_unchanged(&missing_active_context, &before);

        let mut saturated_bad_shape = saturated.clone();
        let mut bad_shape_operation = saturated_operation.clone();
        bad_shape_operation.nullifier_insertions.clear();
        let bad_shape_raw = serde_json::to_vec(&bad_shape_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_shape_raw).unwrap();
        let before = saturated_bad_shape.clone();
        assert_eq!(
            saturated_bad_shape.apply_decoded_exact(&bad_shape_raw, &bad_shape_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_shape, &before);

        let mut below_cap_bad_shape = below_cap.clone();
        let mut bad_shape_operation = below_cap_operation.clone();
        bad_shape_operation.nullifier_insertions.clear();
        let bad_shape_raw = serde_json::to_vec(&bad_shape_operation).unwrap();
        let before = below_cap_bad_shape.clone();
        assert_eq!(
            below_cap_bad_shape.apply_decoded_exact(&bad_shape_raw, &bad_shape_operation),
            Err(DeterministicallyInvalid(Invalid::NullifierProof)),
        );
        assert_block_overlay_unchanged(&below_cap_bad_shape, &before);

        for subject_fault in 0..2 {
            let mutate_subject = |operation: &mut PocoApplicationOperationV0| {
                let raw = &mut operation.nullifier_insertions[0];
                match subject_fault {
                    0 => raw.identifier_hex = "ab".repeat(32),
                    1 => raw.family = PocoNullifierFamilyV0::MeterDecision.code(),
                    _ => unreachable!(),
                }
                let family = PocoNullifierFamilyV0::from_u8(raw.family).unwrap();
                let identifier = exact_hash32_hex(&raw.identifier_hex).unwrap();
                let key = derive_poco_nullifier_key_v0(family, identifier);
                raw.proof_hex = hex::encode(
                    PocoNullifierProofV0::new(key, [[0x55; 32]; 256]).canonical_bytes(),
                );
            };

            let mut saturated_bad_subject = saturated.clone();
            let mut bad_subject_operation = saturated_operation.clone();
            mutate_subject(&mut bad_subject_operation);
            let bad_subject_raw = serde_json::to_vec(&bad_subject_operation).unwrap();
            PocoApplicationOperationV0::decode_exact(&bad_subject_raw).unwrap();
            let before = saturated_bad_subject.clone();
            assert_eq!(
                saturated_bad_subject
                    .apply_decoded_exact(&bad_subject_raw, &bad_subject_operation,),
                Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
            );
            assert_block_overlay_unchanged(&saturated_bad_subject, &before);

            let mut below_cap_bad_subject = below_cap.clone();
            let mut bad_subject_operation = below_cap_operation.clone();
            mutate_subject(&mut bad_subject_operation);
            let bad_subject_raw = serde_json::to_vec(&bad_subject_operation).unwrap();
            let before = below_cap_bad_subject.clone();
            assert_eq!(
                below_cap_bad_subject
                    .apply_decoded_exact(&bad_subject_raw, &bad_subject_operation,),
                Err(DeterministicallyInvalid(Invalid::NullifierProof)),
            );
            assert_block_overlay_unchanged(&below_cap_bad_subject, &before);
        }

        let mut saturated_bad_root = saturated.clone();
        let mut bad_root_operation = saturated_operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_root_operation.nullifier_insertions);
        let bad_root_raw = serde_json::to_vec(&bad_root_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_root_raw).unwrap();
        let before = saturated_bad_root.clone();
        assert_eq!(
            saturated_bad_root.apply_decoded_exact(&bad_root_raw, &bad_root_operation),
            Err(DeterministicallyInvalid(Invalid::ProtocolWindowOrCap)),
        );
        assert_block_overlay_unchanged(&saturated_bad_root, &before);

        let mut below_cap_bad_root = below_cap.clone();
        let mut bad_root_operation = below_cap_operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_root_operation.nullifier_insertions);
        let bad_root_raw = serde_json::to_vec(&bad_root_operation).unwrap();
        let before = below_cap_bad_root.clone();
        assert_eq!(
            below_cap_bad_root.apply_decoded_exact(&bad_root_raw, &bad_root_operation),
            Err(DeterministicallyInvalid(
                Invalid::NullifierNonMembershipRootMismatch,
            )),
        );
        assert_block_overlay_unchanged(&below_cap_bad_root, &before);

        let mut below_cap_bad_second_root = below_cap.clone();
        let mut bad_second_root_operation = below_cap_operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_second_root_operation.nullifier_insertions[1..]);
        let bad_second_root_raw = serde_json::to_vec(&bad_second_root_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&bad_second_root_raw).unwrap();
        let before = below_cap_bad_second_root.clone();
        assert_eq!(
            below_cap_bad_second_root
                .apply_decoded_exact(&bad_second_root_raw, &bad_second_root_operation),
            Err(DeterministicallyInvalid(
                Invalid::NullifierNonMembershipRootMismatch,
            )),
        );
        assert_block_overlay_unchanged(&below_cap_bad_second_root, &before);

        let mut operation_full = saturated.clone();
        let mut malformed_operation = saturated_operation.clone();
        poison_pop(&mut malformed_operation);
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        operation_full.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let before = operation_full.clone();
        assert_eq!(
            operation_full.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&operation_full, &before);

        let mut byte_full = saturated.clone();
        let mut malformed_operation = saturated_operation.clone();
        poison_pop(&mut malformed_operation);
        let malformed_raw = serde_json::to_vec(&malformed_operation).unwrap();
        byte_full.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        let before = byte_full.clone();
        assert_eq!(
            byte_full.apply_decoded_exact(&malformed_raw, &malformed_operation),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&byte_full, &before);

        let (tag_block, _, operation) =
            fixture_authoring::future_candidate_capacity_fixture_v0(0).unwrap();
        let decision_preimage =
            decision_preimage_digest_v0(&tag_block.context, &operation).unwrap();
        let prepared = validate_operation_capacity_before_clone_v0(
            &tag_block.context,
            &tag_block.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut mismatched_operation = operation;
        mismatched_operation.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        let mut candidate = tag_block.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &tag_block.context,
            &mut candidate,
            &mismatched_operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(
            candidate.source_authority_value,
            before.source_authority_value
        );
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(candidate.operation_ids.is_empty());

        let mut exact_boundary = below_cap;
        let accumulator_before = exact_boundary.overlay.accumulator.count();
        exact_boundary
            .apply_decoded_exact(&below_cap_raw, &below_cap_operation)
            .unwrap();
        assert_eq!(
            exact_boundary
                .overlay
                .authority
                .future_candidate_registrations
                .len(),
            MAX_FUTURE_CANDIDATE_REGISTRATIONS,
        );
        assert_eq!(
            exact_boundary.overlay.accumulator.count(),
            accumulator_before + 2,
        );
        assert!(exact_boundary
            .overlay
            .authority
            .future_candidate_registrations
            .windows(2)
            .all(|pair| {
                (pair[0].target_epoch, pair[0].validator_id_hex.as_str())
                    < (pair[1].target_epoch, pair[1].validator_id_hex.as_str())
            }));
        assert_eq!(
            exact_boundary.seal().unwrap().operation_count(),
            u32::try_from(MAX_FUTURE_CANDIDATE_REGISTRATIONS).unwrap(),
        );
    }

    #[test]
    fn meter_retire_negative_fact_is_typed_without_mutation() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let mut operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::RetireMeterPolicy {
                meter_id_hex: "01".to_string(),
                meter_version: 1,
                retired_at_height: 3,
                decision_id_hex: "00".repeat(32),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let wrong_height_raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&wrong_height_raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );
        let PocoApplicationOperationBodyV0::RetireMeterPolicy {
            retired_at_height, ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *retired_at_height = 2;
        let preimage = decision_preimage_digest_v0(&block.context, &operation).unwrap();
        let decision_id = derived_decision_id_v0(preimage, b"retire-meter");
        let PocoApplicationOperationBodyV0::RetireMeterPolicy {
            decision_id_hex, ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *decision_id_hex = hex::encode(decision_id);
        assert_eq!(
            decision_preimage_digest_v0(&block.context, &operation).unwrap(),
            preimage,
        );
        let raw = serde_json::to_vec(&operation).unwrap();

        assert_eq!(
            block.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn meter_prune_active_policy_and_unauthorized_nullifier_are_typed_without_mutation() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let define_raw = block.test_define_meter_operation_v0().unwrap();
        block.apply_raw(&define_raw).unwrap();
        let authority_before = block.overlay.authority.clone();
        let mutations_before = block
            .overlay
            .mutations
            .values()
            .map(OverlayMutationV0::canonical_bytes)
            .collect::<Vec<_>>();
        let operation_ids_before = block.overlay.operation_ids.clone();
        let accumulator_root_before = block.overlay.accumulator.root();
        let accumulator_count_before = block.overlay.accumulator.count();

        let prune = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: block.overlay.authority.revision,
            body: PocoApplicationOperationBodyV0::PruneRetiredMeter {
                meter_id_hex: hex::encode(b"integration-meter-v0"),
                meter_version: 1,
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let prune_raw = serde_json::to_vec(&prune).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&prune_raw, &prune),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
            )),
        );

        let mut unauthorized = prune.clone();
        unauthorized.nullifier_insertions = vec![RawNullifierInsertionV0 {
            family: PocoNullifierFamilyV0::MeterDecision.code(),
            identifier_hex: "07".repeat(32),
            proof_hex: String::new(),
        }];
        let unauthorized_raw = serde_json::to_vec(&unauthorized).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&unauthorized_raw, &unauthorized),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::NullifierProof,
            )),
        );

        assert_eq!(block.operation_count(), 1);
        assert_eq!(block.overlay.authority, authority_before);
        assert_eq!(
            block
                .overlay
                .mutations
                .values()
                .map(OverlayMutationV0::canonical_bytes)
                .collect::<Vec<_>>(),
            mutations_before,
        );
        assert_eq!(block.overlay.operation_ids, operation_ids_before);
        assert_eq!(block.overlay.accumulator.root(), accumulator_root_before);
        assert_eq!(block.overlay.accumulator.count(), accumulator_count_before);
    }

    #[test]
    fn fund_settlement_signed_shape_is_deterministic_without_mutation() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::FundSettlement {
                certificate_id_hex: "01".repeat(32),
                settlement_commitment_hex: "02".repeat(32),
                reserved_units: CanonicalU128V0::new(0),
                funding_decision_id_hex: "03".repeat(32),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let raw = serde_json::to_vec(&operation).unwrap();

        assert_eq!(
            block.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn release_settlement_signed_shape_and_negative_fact_are_typed_without_mutation() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let mut operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::ReleaseSettlement {
                certificate_id_hex: "0".to_string(),
                release_decision_id_hex: "00".repeat(32),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let malformed_raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&malformed_raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );

        let PocoApplicationOperationBodyV0::ReleaseSettlement {
            certificate_id_hex, ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *certificate_id_hex = "01".repeat(32);
        let preimage = decision_preimage_digest_v0(&block.context, &operation).unwrap();
        let decision_id = derived_decision_id_v0(preimage, b"release-settlement");
        let PocoApplicationOperationBodyV0::ReleaseSettlement {
            release_decision_id_hex,
            ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *release_decision_id_hex = hex::encode(decision_id);
        assert_eq!(
            decision_preimage_digest_v0(&block.context, &operation).unwrap(),
            preimage,
        );
        let raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn open_challenge_signed_shape_and_negative_fact_are_typed_before_clone() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::OpenChallenge {
                certificate_id_hex: "0".to_string(),
                challenge_id_hex: "02".repeat(32),
                opening_decision_id_hex: "03".repeat(32),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let malformed_raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&malformed_raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );

        let (context, projection, _, mut missing_operation) =
            sequence_step_vector_fixture("certificate_challenge_rejected", 2);
        let missing_certificate_id = [0x01; 32];
        let PocoApplicationOperationBodyV0::OpenChallenge {
            certificate_id_hex, ..
        } = &mut missing_operation.body
        else {
            unreachable!();
        };
        *certificate_id_hex = hex::encode(missing_certificate_id);
        missing_operation.semantic_changes[0].logical_key_hex =
            hex::encode(semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::RevocationOrChallenge,
                &missing_certificate_id,
            ));
        bind_open_challenge_decisions_v0(&context, &mut missing_operation);
        let mut missing =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        assert!(missing.overlay.authority.active_certificates.iter().all(
            |certificate| certificate.certificate_id_hex != hex::encode(missing_certificate_id)
        ));
        let raw = serde_json::to_vec(&missing_operation).unwrap();
        PocoApplicationOperationV0::decode_exact(&raw).unwrap();
        assert_eq!(
            missing.apply_decoded_exact(&raw, &missing_operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );
        assert_eq!(missing.operation_count(), 0);
        assert!(missing.overlay.operation_ids.is_empty());
        assert!(missing.overlay.mutations.is_empty());
    }

    #[test]
    fn open_challenge_binds_exact_authenticated_predecessor_and_monotonic_height() {
        let fixture = || sequence_step_vector_fixture("certificate_challenge_rejected", 2);

        let (context, projection, raw, operation) = fixture();
        let mut canonical =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.seal().unwrap().operation_count(), 1);

        let certificate_id = match &operation.body {
            PocoApplicationOperationBodyV0::OpenChallenge {
                certificate_id_hex, ..
            } => exact_hash32_hex(certificate_id_hex).unwrap(),
            _ => unreachable!(),
        };
        let logical_key = semantic_identity_digest_v0(
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            &certificate_id,
        );
        let map_key = (
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            logical_key.to_vec(),
        );

        let (context, projection, raw, operation) = fixture();
        let mut corrupted =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let predecessor = owned_semantic_parts(
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            &logical_key,
            corrupted.overlay.entries.get(&map_key).unwrap(),
        )
        .unwrap();
        let effective_height = match &predecessor.fact {
            SemanticFactV0::RevocationOrChallenge {
                state: LifecycleStateV0::Accepted,
                effective_height,
            } => *effective_height,
            _ => unreachable!(),
        };
        let mut corrupted_payload = predecessor.payload.clone();
        let height_offset = corrupted_payload.len() - std::mem::size_of::<u64>();
        corrupted_payload[height_offset..].copy_from_slice(&(effective_height + 1).to_be_bytes());
        let corrupted_value = encode_test_semantic_envelope_v0(
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            predecessor.revision,
            &predecessor.identity,
            &corrupted_payload,
        );
        assert!(matches!(
            owned_semantic_parts(
                PocoSnapshotEntryKindV0::RevocationOrChallenge,
                &logical_key,
                &corrupted_value,
            )
            .unwrap()
            .fact,
            SemanticFactV0::RevocationOrChallenge {
                state: LifecycleStateV0::Accepted,
                effective_height: height,
            } if height == effective_height + 1
        ));
        corrupted
            .overlay
            .entries
            .insert(map_key.clone(), corrupted_value);
        let corrupted_before = corrupted.clone();
        assert_eq!(
            corrupted.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&corrupted, &corrupted_before);

        let (context, projection, raw, operation) = fixture();
        let mut missing =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        missing.overlay.entries.remove(&map_key);
        let missing_before = missing.clone();
        assert_eq!(
            missing.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&missing, &missing_before);

        let (context, projection, raw, operation) = fixture();
        let mut substituted_decision =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        substituted_decision.overlay.authority.active_certificates[0].lifecycle_decision_id_hex =
            "aa".repeat(32);
        let substituted_before = substituted_decision.clone();
        assert_eq!(
            substituted_decision.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&substituted_decision, &substituted_before);

        let (context, projection, raw, operation) = fixture();
        let mut nonmonotonic_terminal =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let accepted_height =
            nonmonotonic_terminal.overlay.authority.active_certificates[0].accepted_height;
        {
            let certificate = &mut nonmonotonic_terminal.overlay.authority.active_certificates[0];
            certificate.lifecycle = CertificateAuthorityLifecycleV0::ChallengeRejected;
            certificate.lifecycle_effective_height = accepted_height;
            certificate.lifecycle_decision_id_hex = "bb".repeat(32);
        }
        let terminal_predecessor = owned_semantic_parts(
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            &logical_key,
            nonmonotonic_terminal.overlay.entries.get(&map_key).unwrap(),
        )
        .unwrap();
        let mut terminal_payload = terminal_predecessor.payload.clone();
        let state_offset = terminal_payload.len() - std::mem::size_of::<u64>() - 1;
        terminal_payload[state_offset] = LifecycleStateV0::ChallengeRejected as u8;
        terminal_payload[state_offset + 1..].copy_from_slice(&accepted_height.to_be_bytes());
        nonmonotonic_terminal.overlay.entries.insert(
            map_key.clone(),
            encode_test_semantic_envelope_v0(
                PocoSnapshotEntryKindV0::RevocationOrChallenge,
                terminal_predecessor.revision,
                &terminal_predecessor.identity,
                &terminal_payload,
            ),
        );
        let terminal_before = nonmonotonic_terminal.clone();
        assert_eq!(
            nonmonotonic_terminal.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&nonmonotonic_terminal, &terminal_before);

        let (context, projection, raw, operation) = fixture();
        let mut terminal_with_foreign_missing =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let terminal_height = terminal_with_foreign_missing
            .overlay
            .authority
            .active_certificates[0]
            .accepted_height
            + 1;
        {
            let certificate = &mut terminal_with_foreign_missing
                .overlay
                .authority
                .active_certificates[0];
            certificate.lifecycle = CertificateAuthorityLifecycleV0::ChallengeRejected;
            certificate.lifecycle_effective_height = terminal_height;
            certificate.lifecycle_decision_id_hex = "bb".repeat(32);
        }
        let terminal_predecessor = owned_semantic_parts(
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            &logical_key,
            terminal_with_foreign_missing
                .overlay
                .entries
                .get(&map_key)
                .unwrap(),
        )
        .unwrap();
        let mut terminal_payload = terminal_predecessor.payload.clone();
        let state_offset = terminal_payload.len() - std::mem::size_of::<u64>() - 1;
        terminal_payload[state_offset] = LifecycleStateV0::ChallengeRejected as u8;
        terminal_payload[state_offset + 1..].copy_from_slice(&terminal_height.to_be_bytes());
        terminal_with_foreign_missing.overlay.entries.insert(
            map_key.clone(),
            encode_test_semantic_envelope_v0(
                PocoSnapshotEntryKindV0::RevocationOrChallenge,
                terminal_predecessor.revision,
                &terminal_predecessor.identity,
                &terminal_payload,
            ),
        );
        authenticated_certificate_lifecycle_companion_v0(
            &terminal_with_foreign_missing.overlay,
            &terminal_with_foreign_missing
                .overlay
                .authority
                .active_certificates[0],
        )
        .unwrap();
        let mut terminal_only = terminal_with_foreign_missing.clone();
        let terminal_only_before = terminal_only.clone();
        assert_eq!(
            terminal_only.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
            )),
        );
        assert_block_overlay_unchanged(&terminal_only, &terminal_only_before);
        let (challenge_id_hex, opening_decision_id_hex) = match &operation.body {
            PocoApplicationOperationBodyV0::OpenChallenge {
                challenge_id_hex,
                opening_decision_id_hex,
                ..
            } => (challenge_id_hex.clone(), opening_decision_id_hex.clone()),
            _ => unreachable!(),
        };
        terminal_with_foreign_missing
            .overlay
            .authority
            .pending_challenges
            .push(PendingChallengeAuthorityV0 {
                challenge_id_hex,
                certificate_id_hex: "fe".repeat(32),
                opening_decision_id_hex,
                opened_height: terminal_with_foreign_missing.context.target_height.get(),
            });
        let before = terminal_with_foreign_missing.clone();
        assert_eq!(
            terminal_with_foreign_missing.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&terminal_with_foreign_missing, &before);

        let duplicate_fixture = || {
            let (context, projection, raw, operation) = fixture();
            let mut block =
                PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
            block.apply_decoded_exact(&raw, &operation).unwrap();
            let mut duplicate = operation;
            duplicate.expected_state_revision = block.overlay.authority.revision;
            bind_open_challenge_decisions_v0(&block.context, &mut duplicate);
            let raw = serde_json::to_vec(&duplicate).unwrap();
            (block, raw, duplicate)
        };

        let (mut duplicate, raw, operation) = duplicate_fixture();
        let duplicate_before = duplicate.clone();
        assert_eq!(
            duplicate.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
            )),
        );
        assert_block_overlay_unchanged(&duplicate, &duplicate_before);

        let (mut duplicate_corrupted, raw, operation) = duplicate_fixture();
        let pending = owned_semantic_parts(
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            &logical_key,
            duplicate_corrupted.overlay.entries.get(&map_key).unwrap(),
        )
        .unwrap();
        let pending_height = match &pending.fact {
            SemanticFactV0::RevocationOrChallenge {
                state: LifecycleStateV0::ChallengePending,
                effective_height,
            } => *effective_height,
            _ => unreachable!(),
        };
        let mut pending_payload = pending.payload.clone();
        let height_offset = pending_payload.len() - std::mem::size_of::<u64>();
        pending_payload[height_offset..].copy_from_slice(&(pending_height + 1).to_be_bytes());
        duplicate_corrupted.overlay.entries.insert(
            map_key.clone(),
            encode_test_semantic_envelope_v0(
                PocoSnapshotEntryKindV0::RevocationOrChallenge,
                pending.revision,
                &pending.identity,
                &pending_payload,
            ),
        );
        let duplicate_corrupted_before = duplicate_corrupted.clone();
        assert_eq!(
            duplicate_corrupted.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&duplicate_corrupted, &duplicate_corrupted_before);

        let (mut duplicate_missing, raw, operation) = duplicate_fixture();
        duplicate_missing.overlay.entries.remove(&map_key);
        let duplicate_missing_before = duplicate_missing.clone();
        assert_eq!(
            duplicate_missing.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&duplicate_missing, &duplicate_missing_before);

        let (context, projection, _, mut foreign_operation) = fixture();
        let mut foreign =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let foreign_key = [0xab; 32];
        foreign_operation.semantic_changes[0].logical_key_hex = hex::encode(foreign_key);
        foreign.overlay.entries.insert(
            (
                PocoSnapshotEntryKindV0::RevocationOrChallenge,
                foreign_key.to_vec(),
            ),
            vec![0],
        );
        bind_open_challenge_decisions_v0(&foreign.context, &mut foreign_operation);
        let foreign_raw = serde_json::to_vec(&foreign_operation).unwrap();
        let foreign_before = foreign.clone();
        assert_eq!(
            foreign.apply_decoded_exact(&foreign_raw, &foreign_operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );
        assert_block_overlay_unchanged(&foreign, &foreign_before);

        let (context, projection, _, mut same_height_operation) = fixture();
        let mut same_height =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        same_height.context.target_height = Height::new(effective_height);
        same_height_operation.target_height = effective_height;
        let next_value = hex::decode(
            same_height_operation.semantic_changes[0]
                .next_value_hex
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        let next = owned_semantic_parts(
            PocoSnapshotEntryKindV0::RevocationOrChallenge,
            &logical_key,
            &next_value,
        )
        .unwrap();
        let mut same_height_payload = next.payload.clone();
        let height_offset = same_height_payload.len() - std::mem::size_of::<u64>();
        same_height_payload[height_offset..].copy_from_slice(&effective_height.to_be_bytes());
        same_height_operation.semantic_changes[0].next_value_hex =
            Some(hex::encode(encode_test_semantic_envelope_v0(
                PocoSnapshotEntryKindV0::RevocationOrChallenge,
                next.revision,
                &next.identity,
                &same_height_payload,
            )));
        bind_open_challenge_decisions_v0(&same_height.context, &mut same_height_operation);
        let same_height_raw = serde_json::to_vec(&same_height_operation).unwrap();
        let same_height_before = same_height.clone();
        assert_eq!(
            same_height.apply_decoded_exact(&same_height_raw, &same_height_operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
            )),
        );
        assert_block_overlay_unchanged(&same_height, &same_height_before);
    }

    #[test]
    fn resolve_challenge_signed_shape_and_not_pending_are_typed_before_clone() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let mut operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::ResolveChallenge {
                certificate_id_hex: "0".to_string(),
                challenge_id_hex: "02".repeat(32),
                resolution: ChallengeResolutionV0::Rejected,
                resolution_decision_id_hex: "03".repeat(32),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let malformed_raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&malformed_raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );

        let PocoApplicationOperationBodyV0::ResolveChallenge {
            certificate_id_hex, ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *certificate_id_hex = "01".repeat(32);
        let raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ChallengeNotPending,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn governance_rule_and_missing_proposal_are_typed_before_clone() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let proposal = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::ProposeGovernance {
                target_epoch: 2,
                phase: crate::poco_semantics::RolloutPhaseV0::Full as u8,
                parameters_hash_hex: "01".repeat(32),
                activation_height: 3,
                proposal_decision_id_hex: "02".repeat(32),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let proposal_raw = serde_json::to_vec(&proposal).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&proposal_raw, &proposal),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::GovernanceRule,
            )),
        );

        let mut approval = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::ApproveGovernance {
                target_epoch: 1,
                parameters_hash_hex: "0".to_string(),
                activation_height: 3,
                decision_id_hex: "03".repeat(32),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let malformed_raw = serde_json::to_vec(&approval).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&malformed_raw, &approval),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::GovernanceRule,
            )),
        );
        let PocoApplicationOperationBodyV0::ApproveGovernance {
            parameters_hash_hex,
            ..
        } = &mut approval.body
        else {
            unreachable!();
        };
        *parameters_hash_hex = "01".repeat(32);
        let approval_raw = serde_json::to_vec(&approval).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&approval_raw, &approval),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::GovernanceApprovalMissing,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn propose_governance_preparation_freezes_capacity_and_late_proof_priority() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let assert_failure =
            |mut block: PocoApplicationBlockOverlayV0,
             operation: PocoApplicationOperationV0,
             expected: PocoApplicationApplyFailureV0| {
                let raw = serde_json::to_vec(&operation).unwrap();
                PocoApplicationOperationV0::decode_exact(&raw).unwrap();
                let before = block.clone();
                assert_eq!(block.apply_decoded_exact(&raw, &operation), Err(expected));
                assert_block_overlay_unchanged(&block, &before);
            };
        let (context, projection, raw, operation) =
            sequence_step_vector_fixture("governance_propose_approve", 0);
        let mut canonical =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let accumulator_before = canonical.overlay.accumulator.count();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        assert_eq!(
            canonical
                .overlay
                .authority
                .pending_governance_proposals
                .len(),
            1,
        );
        assert_eq!(
            canonical.overlay.accumulator.count(),
            accumulator_before + 1
        );
        assert_eq!(canonical.seal().unwrap().operation_count(), 1);

        let (saturated, operation) =
            propose_governance_capacity_fixture(MAX_PENDING_GOVERNANCE_PROPOSALS);
        assert_failure(
            saturated.clone(),
            operation.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut unsupported = operation.clone();
        unsupported.nullifier_non_membership_checks =
            vec![unsupported.nullifier_insertions[0].clone()];
        assert_failure(
            saturated.clone(),
            unsupported,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        for fault in 0..5 {
            let mut malformed = operation.clone();
            let PocoApplicationOperationBodyV0::ProposeGovernance {
                target_epoch,
                phase,
                parameters_hash_hex,
                activation_height,
                proposal_decision_id_hex,
            } = &mut malformed.body
            else {
                unreachable!();
            };
            match fault {
                0 => *target_epoch = target_epoch.checked_add(1).unwrap(),
                1 => *phase = u8::MAX,
                2 => *parameters_hash_hex = "0".to_string(),
                3 => *activation_height = activation_height.checked_add(1).unwrap(),
                4 => *proposal_decision_id_hex = "aa".repeat(32),
                _ => unreachable!(),
            }
            if fault != 4 {
                bind_propose_governance_decision_v0(&saturated.context, &mut malformed);
            }
            assert_failure(
                saturated.clone(),
                malformed,
                DeterministicallyInvalid(if fault == 4 {
                    Invalid::SemanticTransition
                } else {
                    Invalid::GovernanceRule
                }),
            );
        }

        let mut malformed_change = operation.clone();
        malformed_change.semantic_changes[0].next_value_hex = Some("00".to_string());
        bind_propose_governance_decision_v0(&saturated.context, &mut malformed_change);
        assert_failure(
            saturated.clone(),
            malformed_change,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut hash_mismatch = operation.clone();
        let PocoApplicationOperationBodyV0::ProposeGovernance {
            parameters_hash_hex,
            ..
        } = &mut hash_mismatch.body
        else {
            unreachable!();
        };
        *parameters_hash_hex = "aa".repeat(32);
        bind_propose_governance_decision_v0(&saturated.context, &mut hash_mismatch);
        assert_failure(
            saturated.clone(),
            hash_mismatch,
            DeterministicallyInvalid(Invalid::GovernanceRule),
        );

        let mut duplicate = saturated.clone();
        let PocoApplicationOperationBodyV0::ProposeGovernance { target_epoch, .. } =
            &operation.body
        else {
            unreachable!();
        };
        duplicate.overlay.authority.pending_governance_proposals[0].target_epoch = *target_epoch;
        duplicate
            .overlay
            .authority
            .pending_governance_proposals
            .sort_by_key(|proposal| proposal.target_epoch);
        assert_failure(
            duplicate,
            operation.clone(),
            DeterministicallyInvalid(Invalid::GovernanceRule),
        );

        let mut finalized_duplicate = saturated.clone();
        let mut approval = max_capacity_authority_state().finalized_governance_approvals[0].clone();
        approval.target_epoch = *target_epoch;
        finalized_duplicate
            .overlay
            .authority
            .finalized_governance_approvals
            .push(approval);
        finalized_duplicate
            .overlay
            .authority
            .finalized_governance_approvals
            .sort_by_key(|approval| approval.target_epoch);
        assert_failure(
            finalized_duplicate,
            operation.clone(),
            DeterministicallyInvalid(Invalid::GovernanceRule),
        );

        let mut exhausted = saturated.clone();
        exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX).unwrap();
        exhausted
            .overlay
            .authority
            .set_accumulator(exhausted.overlay.accumulator);
        assert_failure(
            exhausted,
            operation.clone(),
            Invariant(InvariantReason::ProtocolCounterExhausted),
        );

        let mut saturated_bad_shape = saturated.clone();
        let mut bad_shape_operation = operation.clone();
        bad_shape_operation.nullifier_insertions.clear();
        assert_failure(
            saturated_bad_shape.clone(),
            bad_shape_operation.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );
        saturated_bad_shape.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        assert_failure(
            saturated_bad_shape,
            bad_shape_operation,
            DeterministicallyInvalid(Invalid::PerBlockCapacity),
        );

        let (below_cap_bad_shape, mut bad_shape_operation) =
            propose_governance_capacity_fixture(MAX_PENDING_GOVERNANCE_PROPOSALS - 1);
        bad_shape_operation.nullifier_insertions.clear();
        assert_failure(
            below_cap_bad_shape,
            bad_shape_operation,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut saturated_bad_root = saturated.clone();
        let mut bad_root_operation = operation.clone();
        poison_nullifier_roots_v0(&mut bad_root_operation);
        assert_failure(
            saturated_bad_root.clone(),
            bad_root_operation.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );
        saturated_bad_root.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        assert_failure(
            saturated_bad_root,
            bad_root_operation,
            DeterministicallyInvalid(Invalid::PerBlockCapacity),
        );

        let (below_cap_bad_root, mut bad_root_operation) =
            propose_governance_capacity_fixture(MAX_PENDING_GOVERNANCE_PROPOSALS - 1);
        poison_nullifier_roots_v0(&mut bad_root_operation);
        assert_failure(
            below_cap_bad_root,
            bad_root_operation,
            DeterministicallyInvalid(Invalid::NullifierNonMembershipRootMismatch),
        );

        let (mut boundary, boundary_operation) =
            propose_governance_capacity_fixture(MAX_PENDING_GOVERNANCE_PROPOSALS - 1);
        let boundary_raw = serde_json::to_vec(&boundary_operation).unwrap();
        let boundary_accumulator = boundary.overlay.accumulator.count();
        boundary
            .apply_decoded_exact(&boundary_raw, &boundary_operation)
            .unwrap();
        assert_eq!(boundary.operation_count(), 1);
        assert_eq!(
            boundary
                .overlay
                .authority
                .pending_governance_proposals
                .len(),
            MAX_PENDING_GOVERNANCE_PROPOSALS,
        );
        assert_eq!(
            boundary.overlay.accumulator.count(),
            boundary_accumulator + 1
        );

        let (baseline, operation) = propose_governance_capacity_fixture(0);
        let decision_preimage = decision_preimage_digest_v0(&baseline.context, &operation).unwrap();
        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut mismatched_operation = operation.clone();
        let PocoApplicationOperationBodyV0::ProposeGovernance { phase, .. } =
            &mut mismatched_operation.body
        else {
            unreachable!();
        };
        *phase = crate::poco_semantics::RolloutPhaseV0::Full as u8;
        let mut candidate = baseline.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &mismatched_operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut candidate = baseline.overlay.clone();
        let mut row = max_capacity_authority_state().pending_governance_proposals[0].clone();
        row.target_epoch = 0;
        candidate.authority.pending_governance_proposals.push(row);
        candidate
            .authority
            .pending_governance_proposals
            .sort_by_key(|proposal| proposal.target_epoch);
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &operation,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
    }

    #[test]
    fn approve_governance_preparation_freezes_replacement_capacity_and_late_proofs() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let assert_failure =
            |mut block: PocoApplicationBlockOverlayV0,
             operation: PocoApplicationOperationV0,
             expected: PocoApplicationApplyFailureV0| {
                let raw = serde_json::to_vec(&operation).unwrap();
                PocoApplicationOperationV0::decode_exact(&raw).unwrap();
                let before = block.clone();
                assert_eq!(block.apply_decoded_exact(&raw, &operation), Err(expected));
                assert_block_overlay_unchanged(&block, &before);
            };

        let replace_insertion_subject =
            |operation: &mut PocoApplicationOperationV0,
             family: PocoNullifierFamilyV0,
             identifier: [u8; 32]| {
                let key = derive_poco_nullifier_key_v0(family, identifier);
                let siblings = std::array::from_fn(|level| {
                    crate::poco_nullifier::poco_nullifier_default_hash_v0(level)
                        .expect("fixed nullifier level is in range")
                });
                operation.nullifier_insertions = vec![RawNullifierInsertionV0 {
                    family: family.code(),
                    identifier_hex: hex::encode(identifier),
                    proof_hex: hex::encode(
                        PocoNullifierProofV0::new(key, siblings).canonical_bytes(),
                    ),
                }];
            };

        let (context, projection, raw, operation) =
            sequence_step_vector_fixture("governance_propose_approve", 1);
        let mut canonical =
            PocoApplicationBlockOverlayV0::from_projection(context, &projection).unwrap();
        let accumulator_before = canonical.overlay.accumulator.count();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        assert!(canonical
            .overlay
            .authority
            .pending_governance_proposals
            .is_empty());
        assert_eq!(
            canonical
                .overlay
                .authority
                .finalized_governance_approvals
                .len(),
            1,
        );
        assert_eq!(
            canonical.overlay.accumulator.count(),
            accumulator_before + 1
        );
        assert_eq!(canonical.seal().unwrap().operation_count(), 1);

        let (saturated, operation) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS);
        assert_failure(
            saturated.clone(),
            operation.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut malformed_hash = operation.clone();
        malformed_hash.nullifier_non_membership_checks =
            vec![malformed_hash.nullifier_insertions[0].clone()];
        let PocoApplicationOperationBodyV0::ApproveGovernance {
            parameters_hash_hex,
            ..
        } = &mut malformed_hash.body
        else {
            unreachable!();
        };
        *parameters_hash_hex = "0".to_string();
        assert_failure(
            saturated.clone(),
            malformed_hash,
            DeterministicallyInvalid(Invalid::GovernanceRule),
        );

        let mut wrong_epoch = operation.clone();
        wrong_epoch.nullifier_non_membership_checks =
            vec![wrong_epoch.nullifier_insertions[0].clone()];
        let PocoApplicationOperationBodyV0::ApproveGovernance { target_epoch, .. } =
            &mut wrong_epoch.body
        else {
            unreachable!();
        };
        *target_epoch = target_epoch.checked_add(1).unwrap();
        assert_failure(
            saturated.clone(),
            wrong_epoch,
            DeterministicallyInvalid(Invalid::GovernanceRule),
        );

        let mut missing_proposal = saturated.clone();
        missing_proposal
            .overlay
            .authority
            .pending_governance_proposals
            .clear();
        let mut later_unsupported = operation.clone();
        later_unsupported.nullifier_non_membership_checks =
            vec![later_unsupported.nullifier_insertions[0].clone()];
        assert_failure(
            missing_proposal,
            later_unsupported,
            DeterministicallyInvalid(Invalid::GovernanceApprovalMissing),
        );

        let PocoApplicationOperationBodyV0::ApproveGovernance { target_epoch, .. } =
            &operation.body
        else {
            unreachable!();
        };
        let mut duplicate_approval = saturated.clone();
        duplicate_approval
            .overlay
            .authority
            .finalized_governance_approvals[0]
            .target_epoch = *target_epoch;
        duplicate_approval
            .overlay
            .authority
            .finalized_governance_approvals
            .sort_by_key(|approval| approval.target_epoch);
        let mut later_unsupported = operation.clone();
        later_unsupported.nullifier_non_membership_checks =
            vec![later_unsupported.nullifier_insertions[0].clone()];
        assert_failure(
            duplicate_approval,
            later_unsupported,
            DeterministicallyInvalid(Invalid::GovernanceRule),
        );

        let mut unsupported = operation.clone();
        unsupported.nullifier_non_membership_checks =
            vec![unsupported.nullifier_insertions[0].clone()];
        assert_failure(
            saturated.clone(),
            unsupported.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );
        let (below_cap, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        assert_failure(
            below_cap,
            unsupported,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        for fault in 0..3 {
            let mut malformed = operation.clone();
            let PocoApplicationOperationBodyV0::ApproveGovernance {
                parameters_hash_hex,
                activation_height,
                decision_id_hex,
                ..
            } = &mut malformed.body
            else {
                unreachable!();
            };
            match fault {
                0 => *parameters_hash_hex = "aa".repeat(32),
                1 => *activation_height = activation_height.checked_add(1).unwrap(),
                2 => *decision_id_hex = "bb".repeat(32),
                _ => unreachable!(),
            }
            if fault != 2 {
                bind_approve_governance_decision_v0(&saturated.context, &mut malformed);
            }
            assert_failure(
                saturated.clone(),
                malformed.clone(),
                DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
            );
            let (below_cap, _) =
                approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
            assert_failure(
                below_cap,
                malformed,
                DeterministicallyInvalid(if fault == 2 {
                    Invalid::SemanticTransition
                } else {
                    Invalid::GovernanceRule
                }),
            );
        }

        let mut malformed_change = operation.clone();
        malformed_change.semantic_changes[0].next_value_hex = Some("00".to_string());
        bind_approve_governance_decision_v0(&saturated.context, &mut malformed_change);
        assert_failure(
            saturated.clone(),
            malformed_change.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );
        let (below_cap, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        assert_failure(
            below_cap,
            malformed_change,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut parameters_identity = vec![2];
        parameters_identity.extend_from_slice(&target_epoch.to_be_bytes());
        let parameters_key = (
            PocoSnapshotEntryKindV0::ConsensusParameters,
            semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::ConsensusParameters,
                &parameters_identity,
            )
            .to_vec(),
        );
        let mut saturated_bad_parameters = saturated.clone();
        saturated_bad_parameters
            .overlay
            .entries
            .insert(parameters_key.clone(), vec![0xff]);
        assert_failure(
            saturated_bad_parameters,
            operation.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );
        let (mut below_cap_bad_parameters, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        below_cap_bad_parameters
            .overlay
            .entries
            .insert(parameters_key, vec![0xff]);
        assert_failure(
            below_cap_bad_parameters,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let governance_change = &operation.semantic_changes[0];
        let governance_key = (
            PocoSnapshotEntryKindV0::RolloutOrGovernance,
            exact_hash32_hex(&governance_change.logical_key_hex)
                .unwrap()
                .to_vec(),
        );
        let mut saturated_bad_governance = saturated.clone();
        saturated_bad_governance
            .overlay
            .entries
            .insert(governance_key.clone(), vec![0xff]);
        assert_failure(
            saturated_bad_governance,
            operation.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );
        let (mut below_cap_bad_governance, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        below_cap_bad_governance
            .overlay
            .entries
            .insert(governance_key, vec![0xff]);
        assert_failure(
            below_cap_bad_governance,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut saturated_exhausted = saturated.clone();
        saturated_exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX).unwrap();
        saturated_exhausted
            .overlay
            .authority
            .set_accumulator(saturated_exhausted.overlay.accumulator);
        assert_failure(
            saturated_exhausted,
            operation.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );
        let (mut below_cap_exhausted, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        below_cap_exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX).unwrap();
        below_cap_exhausted
            .overlay
            .authority
            .set_accumulator(below_cap_exhausted.overlay.accumulator);
        assert_failure(
            below_cap_exhausted,
            operation.clone(),
            Invariant(InvariantReason::ProtocolCounterExhausted),
        );

        let mut bad_shape = operation.clone();
        bad_shape.nullifier_insertions.clear();
        assert_failure(
            saturated.clone(),
            bad_shape.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );
        let (below_cap, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        assert_failure(
            below_cap,
            bad_shape,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_root = operation.clone();
        poison_nullifier_roots_v0(&mut bad_root);
        assert_failure(
            saturated.clone(),
            bad_root.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );
        let (below_cap, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        assert_failure(
            below_cap,
            bad_root,
            DeterministicallyInvalid(Invalid::NullifierNonMembershipRootMismatch),
        );

        let mut wrong_family = operation.clone();
        replace_insertion_subject(
            &mut wrong_family,
            PocoNullifierFamilyV0::SettlementDecision,
            [0x77; 32],
        );
        let (below_cap, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        assert_failure(
            below_cap,
            wrong_family,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut wrong_subject = operation.clone();
        replace_insertion_subject(
            &mut wrong_subject,
            PocoNullifierFamilyV0::GovernanceDecision,
            [0x88; 32],
        );
        let (below_cap, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        assert_failure(
            below_cap,
            wrong_subject.clone(),
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut saturated_too_early = saturated.clone();
        saturated_too_early
            .overlay
            .authority
            .pending_governance_proposals[0]
            .proposed_height = saturated_too_early.context.target_height.get();
        assert_failure(
            saturated_too_early,
            wrong_subject.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let (mut below_cap_too_early, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        below_cap_too_early
            .overlay
            .authority
            .pending_governance_proposals[0]
            .proposed_height = below_cap_too_early.context.target_height.get();
        assert_failure(
            below_cap_too_early,
            wrong_subject.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let (mut below_cap_too_early, mut unsupported_too_early) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        below_cap_too_early
            .overlay
            .authority
            .pending_governance_proposals[0]
            .proposed_height = below_cap_too_early.context.target_height.get();
        unsupported_too_early.nullifier_non_membership_checks =
            vec![unsupported_too_early.nullifier_insertions[0].clone()];
        assert_failure(
            below_cap_too_early,
            unsupported_too_early,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let (mut exhausted_with_wrong_subject, _) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        exhausted_with_wrong_subject.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX).unwrap();
        exhausted_with_wrong_subject
            .overlay
            .authority
            .set_accumulator(exhausted_with_wrong_subject.overlay.accumulator);
        assert_failure(
            exhausted_with_wrong_subject,
            wrong_subject,
            Invariant(InvariantReason::ProtocolCounterExhausted),
        );

        let mut structural = saturated.clone();
        structural.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let mut malformed = operation.clone();
        malformed.nullifier_non_membership_checks = vec![malformed.nullifier_insertions[0].clone()];
        assert_failure(
            structural,
            malformed,
            DeterministicallyInvalid(Invalid::PerBlockCapacity),
        );

        let (mut boundary, boundary_operation) =
            approve_governance_capacity_fixture(MAX_FINALIZED_GOVERNANCE_APPROVALS - 1);
        let boundary_raw = serde_json::to_vec(&boundary_operation).unwrap();
        let boundary_accumulator = boundary.overlay.accumulator.count();
        boundary
            .apply_decoded_exact(&boundary_raw, &boundary_operation)
            .unwrap();
        assert!(boundary
            .overlay
            .authority
            .pending_governance_proposals
            .is_empty());
        assert_eq!(
            boundary
                .overlay
                .authority
                .finalized_governance_approvals
                .len(),
            MAX_FINALIZED_GOVERNANCE_APPROVALS,
        );
        assert_eq!(
            boundary.overlay.accumulator.count(),
            boundary_accumulator + 1
        );

        let (baseline, operation) = approve_governance_capacity_fixture(0);
        let decision_preimage = decision_preimage_digest_v0(&baseline.context, &operation).unwrap();
        let prepare = || {
            validate_operation_capacity_before_clone_v0(
                &baseline.context,
                &baseline.overlay,
                &operation,
                decision_preimage,
            )
            .unwrap()
        };
        let assert_carrier_drift =
            |mut candidate: PocoApplicationOverlayV0,
             candidate_operation: &PocoApplicationOperationV0,
             prepared: PreparedCapacityOperationV0| {
                let before = candidate.clone();
                let error = apply_operation_v0(
                    &baseline.context,
                    &mut candidate,
                    candidate_operation,
                    decision_preimage,
                    prepared,
                )
                .unwrap_err();
                assert_eq!(
                    error
                        .downcast_ref::<PocoApplicationApplyFailureV0>()
                        .copied(),
                    Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
                );
                assert_eq!(candidate.entries, before.entries);
                assert_eq!(candidate.authority, before.authority);
                assert_eq!(candidate.accumulator, before.accumulator);
                assert!(candidate.mutations.is_empty());
            };

        let mut mismatched_operation = operation.clone();
        let PocoApplicationOperationBodyV0::ApproveGovernance {
            decision_id_hex, ..
        } = &mut mismatched_operation.body
        else {
            unreachable!();
        };
        *decision_id_hex = "cc".repeat(32);
        assert_carrier_drift(baseline.overlay.clone(), &mismatched_operation, prepare());

        let mut proposal_drift = baseline.overlay.clone();
        proposal_drift.authority.pending_governance_proposals[0].phase =
            crate::poco_semantics::RolloutPhaseV0::Full as u8;
        assert_carrier_drift(proposal_drift, &operation, prepare());

        let mut finalized_slot_drift = baseline.overlay.clone();
        let mut approval = max_capacity_authority_state().finalized_governance_approvals[0].clone();
        approval.target_epoch = 0;
        finalized_slot_drift
            .authority
            .finalized_governance_approvals
            .push(approval);
        assert_carrier_drift(finalized_slot_drift, &operation, prepare());

        let mut parameters_drift = baseline.overlay.clone();
        let mut parameters_identity = vec![2];
        parameters_identity.extend_from_slice(&target_epoch.to_be_bytes());
        let parameters_key = (
            PocoSnapshotEntryKindV0::ConsensusParameters,
            semantic_identity_digest_v0(
                PocoSnapshotEntryKindV0::ConsensusParameters,
                &parameters_identity,
            )
            .to_vec(),
        );
        parameters_drift.entries.insert(parameters_key, vec![0xff]);
        assert_carrier_drift(parameters_drift, &operation, prepare());

        let mut semantic_drift = baseline.overlay.clone();
        let raw_change = &operation.semantic_changes[0];
        let semantic_key = (
            PocoSnapshotEntryKindV0::RolloutOrGovernance,
            exact_hash32_hex(&raw_change.logical_key_hex)
                .unwrap()
                .to_vec(),
        );
        semantic_drift.entries.insert(semantic_key, vec![0xff]);
        assert_carrier_drift(semantic_drift, &operation, prepare());
    }

    #[test]
    fn certificate_acceptance_signed_id_and_reservation_fact_are_typed_before_clone() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let mut operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::AcceptCertificate {
                certificate_id_hex: "0".to_string(),
                funding_decision_id_hex: "01".repeat(32),
                acceptance_decision_id_hex: "02".repeat(32),
                meter_decision_id_hex: "03".repeat(32),
                evidence_decision_id_hex: "04".repeat(32),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let malformed_raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&malformed_raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );
        let PocoApplicationOperationBodyV0::AcceptCertificate {
            certificate_id_hex, ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *certificate_id_hex = "05".repeat(32);
        let raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn decoded_operation_cannot_be_spliced_to_foreign_raw_bytes_or_mutate_overlay() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let raw = block.test_define_meter_operation_v0().unwrap();
        let decoded = PocoApplicationOperationV0::decode_exact(&raw).unwrap();
        let mut foreign_raw = raw.clone();
        foreign_raw.push(b' ');
        assert_eq!(
            block.apply_decoded_exact(&foreign_raw, &decoded),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::DecodedRawOwnerMismatch,
            ))
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
        block.apply_decoded_exact(&raw, &decoded).unwrap();
        assert_eq!(block.operation_count(), 1);
    }

    #[test]
    fn consumer_key_signed_shape_rejects_deterministically_without_mutation() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
                consumer_id_hex: "01".to_string(),
                consumer_key_id_hex: "02".to_string(),
                public_key_hex: "03".repeat(32),
                active_from_height: 3,
                decision_id_hex: "04".repeat(32),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let raw = serde_json::to_vec(&operation).unwrap();

        assert_eq!(
            block.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );
        let mut unauthorized_proof = operation.clone();
        unauthorized_proof.nullifier_non_membership_checks = vec![RawNullifierInsertionV0 {
            family: PocoNullifierFamilyV0::ConsumerKeyDecision.code(),
            identifier_hex: "05".repeat(32),
            proof_hex: "06".repeat(crate::poco_nullifier::POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0),
        }];
        let unauthorized_raw = serde_json::to_vec(&unauthorized_proof).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&unauthorized_raw, &unauthorized_proof),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::NullifierProof,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn consumer_key_missing_authority_fact_rejects_deterministically_without_mutation() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let mut operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::RevokeConsumerKey {
                consumer_id_hex: "01".to_string(),
                consumer_key_id_hex: "02".to_string(),
                public_key_hex: "03".repeat(32),
                active_from_height: 1,
                revoked_at_height: 2,
                decision_id_hex: "00".repeat(32),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let preimage = decision_preimage_digest_v0(&block.context, &operation).unwrap();
        let decision_id = derived_decision_id_v0(preimage, b"revoke-consumer-key");
        let PocoApplicationOperationBodyV0::RevokeConsumerKey {
            decision_id_hex, ..
        } = &mut operation.body
        else {
            unreachable!();
        };
        *decision_id_hex = hex::encode(decision_id);
        assert_eq!(
            decision_preimage_digest_v0(&block.context, &operation).unwrap(),
            preimage,
        );
        let raw = serde_json::to_vec(&operation).unwrap();

        assert_eq!(
            block.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn retire_meter_preparation_freezes_zero_delta_capacity_and_late_proof() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (baseline, raw, operation) =
            fixture_authoring::retire_meter_full_capacity_fixture_v0().unwrap();
        assert_eq!(
            PocoApplicationOperationV0::decode_exact(&raw).unwrap(),
            operation,
        );
        assert_eq!(serde_json::to_vec(&operation).unwrap(), raw);
        assert_eq!(
            baseline.overlay.authority.meter_policies.len(),
            MAX_METER_POLICIES,
        );
        assert_eq!(baseline.operation_count(), 0);
        let PocoApplicationOperationBodyV0::RetireMeterPolicy {
            meter_id_hex,
            meter_version,
            retired_at_height,
            decision_id_hex: _,
        } = &operation.body
        else {
            unreachable!();
        };
        let target_index = baseline
            .overlay
            .authority
            .meter_policies
            .binary_search_by(|policy| {
                (policy.meter_id_hex.as_str(), policy.meter_version)
                    .cmp(&(meter_id_hex.as_str(), *meter_version))
            })
            .unwrap();
        let source_rows = baseline.overlay.authority.meter_policies.clone();
        let source_target = source_rows[target_index].clone();
        assert_eq!(source_target.retired_at_height, None);
        let semantic_key = (
            PocoSnapshotEntryKindV0::MeterDefinition,
            exact_hash32_hex(&operation.semantic_changes[0].logical_key_hex)
                .unwrap()
                .to_vec(),
        );
        let source_semantic = owned_semantic_parts(
            semantic_key.0,
            &semantic_key.1,
            baseline.overlay.entries.get(&semantic_key).unwrap(),
        )
        .unwrap();
        let accumulator_before = baseline.overlay.accumulator.count();

        let mut canonical = baseline.clone();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        assert_eq!(
            canonical.overlay.authority.meter_policies.len(),
            MAX_METER_POLICIES,
        );
        assert!(canonical
            .overlay
            .authority
            .meter_policies
            .windows(2)
            .all(|pair| {
                (&pair[0].meter_id_hex, pair[0].meter_version)
                    < (&pair[1].meter_id_hex, pair[1].meter_version)
            }));
        for (index, row) in canonical
            .overlay
            .authority
            .meter_policies
            .iter()
            .enumerate()
        {
            if index == target_index {
                let mut expected = source_target.clone();
                expected.retired_at_height = Some(*retired_at_height);
                assert_eq!(row, &expected);
            } else {
                assert_eq!(row, &source_rows[index]);
            }
        }
        assert_eq!(
            canonical.overlay.accumulator.count(),
            accumulator_before + 1,
        );
        let target_semantic = owned_semantic_parts(
            semantic_key.0,
            &semantic_key.1,
            canonical.overlay.entries.get(&semantic_key).unwrap(),
        )
        .unwrap();
        assert_eq!(
            target_semantic.revision,
            source_semantic.revision.checked_add(1).unwrap(),
        );
        assert_eq!(target_semantic.identity, source_semantic.identity);
        assert!(matches!(
            target_semantic.fact,
            SemanticFactV0::MeterDefinition {
                unit_scale: 1,
                active_from: 1,
                retired_at: Some(height),
            } if height == *retired_at_height
        ));
        assert_eq!(canonical.seal().unwrap().operation_count(), 1);

        let assert_failure =
            |mut candidate: PocoApplicationBlockOverlayV0,
             candidate_operation: PocoApplicationOperationV0,
             expected: PocoApplicationApplyFailureV0| {
                let candidate_raw = serde_json::to_vec(&candidate_operation).unwrap();
                let before = candidate.clone();
                assert_eq!(
                    candidate.apply_decoded_exact(&candidate_raw, &candidate_operation),
                    Err(expected),
                );
                assert_block_overlay_unchanged(&candidate, &before);
            };

        let mut malformed = operation.clone();
        let PocoApplicationOperationBodyV0::RetireMeterPolicy {
            meter_id_hex: malformed_meter_id_hex,
            ..
        } = &mut malformed.body
        else {
            unreachable!();
        };
        *malformed_meter_id_hex = "0".to_string();
        poison_raw_nullifier_roots_v0(&mut malformed.nullifier_insertions);
        assert_failure(
            baseline.clone(),
            malformed,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut missing = baseline.clone();
        missing
            .overlay
            .authority
            .meter_policies
            .remove(target_index);
        let mut later_bad_height = operation.clone();
        let PocoApplicationOperationBodyV0::RetireMeterPolicy {
            retired_at_height, ..
        } = &mut later_bad_height.body
        else {
            unreachable!();
        };
        *retired_at_height = baseline.context.target_height.get() + 1;
        later_bad_height.nullifier_insertions.clear();
        assert_failure(
            missing,
            later_bad_height,
            DeterministicallyInvalid(Invalid::MissingRequiredAuthorityFact),
        );

        let mut synthetic_over_capacity = baseline.clone();
        let mut fifth = source_rows.last().unwrap().clone();
        fifth.meter_id_hex = format!("{}01", "ff".repeat(31));
        synthetic_over_capacity
            .overlay
            .authority
            .meter_policies
            .push(fifth);
        synthetic_over_capacity
            .overlay
            .authority
            .meter_policies
            .sort_by(|left, right| {
                (&left.meter_id_hex, left.meter_version)
                    .cmp(&(&right.meter_id_hex, right.meter_version))
            });
        assert_eq!(
            synthetic_over_capacity
                .overlay
                .authority
                .meter_policies
                .len(),
            MAX_METER_POLICIES + 1,
        );
        let mut malformed_over_capacity = operation.clone();
        let PocoApplicationOperationBodyV0::RetireMeterPolicy {
            meter_id_hex: malformed_meter_id_hex,
            ..
        } = &mut malformed_over_capacity.body
        else {
            unreachable!();
        };
        *malformed_meter_id_hex = "0".to_string();
        assert_failure(
            synthetic_over_capacity.clone(),
            malformed_over_capacity,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut missing_over_capacity = synthetic_over_capacity.clone();
        missing_over_capacity
            .overlay
            .authority
            .meter_policies
            .retain(|policy| {
                policy.meter_id_hex != *meter_id_hex || policy.meter_version != *meter_version
            });
        let mut extra = source_rows.last().unwrap().clone();
        extra.meter_id_hex = format!("{}02", "ff".repeat(31));
        missing_over_capacity
            .overlay
            .authority
            .meter_policies
            .push(extra);
        missing_over_capacity
            .overlay
            .authority
            .meter_policies
            .sort_by(|left, right| {
                (&left.meter_id_hex, left.meter_version)
                    .cmp(&(&right.meter_id_hex, right.meter_version))
            });
        assert_eq!(
            missing_over_capacity.overlay.authority.meter_policies.len(),
            MAX_METER_POLICIES + 1,
        );
        assert_failure(
            missing_over_capacity,
            operation.clone(),
            DeterministicallyInvalid(Invalid::MissingRequiredAuthorityFact),
        );

        let mut later_fault = operation.clone();
        later_fault.nullifier_non_membership_checks =
            vec![later_fault.nullifier_insertions[0].clone()];
        poison_raw_nullifier_roots_v0(&mut later_fault.nullifier_insertions);
        assert_failure(
            synthetic_over_capacity,
            later_fault,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut unsupported = operation.clone();
        unsupported.nullifier_non_membership_checks =
            vec![unsupported.nullifier_insertions[0].clone()];
        let PocoApplicationOperationBodyV0::RetireMeterPolicy {
            retired_at_height, ..
        } = &mut unsupported.body
        else {
            unreachable!();
        };
        *retired_at_height = baseline.context.target_height.get() + 1;
        assert_failure(
            baseline.clone(),
            unsupported,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut wrong_height = operation.clone();
        let PocoApplicationOperationBodyV0::RetireMeterPolicy {
            retired_at_height, ..
        } = &mut wrong_height.body
        else {
            unreachable!();
        };
        *retired_at_height = baseline.context.target_height.get() + 1;
        poison_raw_nullifier_roots_v0(&mut wrong_height.nullifier_insertions);
        assert_failure(
            baseline.clone(),
            wrong_height,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut wrong_decision = operation.clone();
        let PocoApplicationOperationBodyV0::RetireMeterPolicy {
            decision_id_hex, ..
        } = &mut wrong_decision.body
        else {
            unreachable!();
        };
        *decision_id_hex = "ee".repeat(32);
        assert_failure(
            baseline.clone(),
            wrong_decision,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut already_retired = baseline.clone();
        already_retired.overlay.authority.meter_policies[target_index].retired_at_height =
            Some(baseline.context.target_height.get());
        let mut bad_root = operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_root.nullifier_insertions);
        assert_failure(
            already_retired,
            bad_root.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut malformed_authority = baseline.clone();
        malformed_authority.overlay.authority.meter_policies[target_index].rolling_epoch_span = 0;
        assert_failure(
            malformed_authority,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut missing_predecessor = baseline.clone();
        missing_predecessor.overlay.entries.remove(&semantic_key);
        assert_failure(
            missing_predecessor,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut authority_semantic_drift = baseline.clone();
        authority_semantic_drift.overlay.authority.meter_policies[target_index].unit_scale =
            CanonicalU128V0::new(2);
        assert_failure(
            authority_semantic_drift,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let bind_retirement_decision = |candidate: &mut PocoApplicationOperationV0| {
            let preimage = decision_preimage_digest_v0(&baseline.context, candidate).unwrap();
            let decision = derived_decision_id_v0(preimage, b"retire-meter");
            let PocoApplicationOperationBodyV0::RetireMeterPolicy {
                decision_id_hex, ..
            } = &mut candidate.body
            else {
                unreachable!();
            };
            *decision_id_hex = hex::encode(decision);
        };
        let mut invalid_successor = operation.clone();
        invalid_successor.semantic_changes[0].next_value_hex = None;
        bind_retirement_decision(&mut invalid_successor);
        assert_failure(
            baseline.clone(),
            invalid_successor,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut wrong_logical_key = operation.clone();
        wrong_logical_key.semantic_changes[0].logical_key_hex = "ab".repeat(32);
        bind_retirement_decision(&mut wrong_logical_key);
        assert_failure(
            baseline.clone(),
            wrong_logical_key,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut exhausted = baseline.clone();
        exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX).unwrap();
        exhausted
            .overlay
            .authority
            .set_accumulator(exhausted.overlay.accumulator);
        let mut later_bad_proof = operation.clone();
        later_bad_proof.nullifier_insertions.clear();
        assert_failure(
            exhausted,
            later_bad_proof,
            Invariant(InvariantReason::ProtocolCounterExhausted),
        );

        let mut bad_shape = operation.clone();
        bad_shape.nullifier_insertions.clear();
        assert_failure(
            baseline.clone(),
            bad_shape,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut duplicate_proof = operation.clone();
        duplicate_proof
            .nullifier_insertions
            .push(duplicate_proof.nullifier_insertions[0].clone());
        assert_failure(
            baseline.clone(),
            duplicate_proof,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_family = operation.clone();
        bad_family.nullifier_insertions[0].family =
            PocoNullifierFamilyV0::ConsumerKeyDecision.code();
        assert_failure(
            baseline.clone(),
            bad_family,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_subject = operation.clone();
        bad_subject.nullifier_insertions[0].identifier_hex = "a5".repeat(32);
        assert_failure(
            baseline.clone(),
            bad_subject,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        assert_failure(
            baseline.clone(),
            bad_root.clone(),
            DeterministicallyInvalid(Invalid::NullifierNonMembershipRootMismatch),
        );

        let decision_preimage = decision_preimage_digest_v0(&baseline.context, &operation).unwrap();
        let prepare = || {
            validate_operation_capacity_before_clone_v0(
                &baseline.context,
                &baseline.overlay,
                &operation,
                decision_preimage,
            )
            .unwrap()
        };
        let assert_carrier_drift =
            |mut candidate: PocoApplicationOverlayV0,
             candidate_operation: &PocoApplicationOperationV0,
             prepared: PreparedCapacityOperationV0| {
                let before = candidate.clone();
                let error = apply_operation_v0(
                    &baseline.context,
                    &mut candidate,
                    candidate_operation,
                    decision_preimage,
                    prepared,
                )
                .unwrap_err();
                assert_eq!(
                    error
                        .downcast_ref::<PocoApplicationApplyFailureV0>()
                        .copied(),
                    Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
                );
                assert_eq!(candidate.entries, before.entries);
                assert_eq!(
                    candidate.source_authority_value,
                    before.source_authority_value,
                );
                assert_eq!(candidate.authority, before.authority);
                assert_eq!(candidate.accumulator, before.accumulator);
                assert_eq!(candidate.operation_ids, before.operation_ids);
                assert_eq!(
                    candidate
                        .mutations
                        .values()
                        .map(OverlayMutationV0::canonical_bytes)
                        .collect::<Vec<_>>(),
                    before
                        .mutations
                        .values()
                        .map(OverlayMutationV0::canonical_bytes)
                        .collect::<Vec<_>>(),
                );
            };

        let mut cross_family = operation.clone();
        cross_family.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        assert_carrier_drift(baseline.overlay.clone(), &cross_family, prepare());

        let mut body_drift = operation.clone();
        let PocoApplicationOperationBodyV0::RetireMeterPolicy {
            decision_id_hex, ..
        } = &mut body_drift.body
        else {
            unreachable!();
        };
        *decision_id_hex = "cd".repeat(32);
        poison_raw_nullifier_roots_v0(&mut body_drift.nullifier_insertions);
        assert_carrier_drift(baseline.overlay.clone(), &body_drift, prepare());

        let mut field_owner_drift = operation.clone();
        field_owner_drift.nullifier_non_membership_checks =
            vec![field_owner_drift.nullifier_insertions[0].clone()];
        poison_raw_nullifier_roots_v0(&mut field_owner_drift.nullifier_insertions);
        assert_carrier_drift(baseline.overlay.clone(), &field_owner_drift, prepare());

        let mut semantic_owner_drift = operation.clone();
        semantic_owner_drift.semantic_changes[0].next_value_hex = None;
        poison_raw_nullifier_roots_v0(&mut semantic_owner_drift.nullifier_insertions);
        assert_carrier_drift(baseline.overlay.clone(), &semantic_owner_drift, prepare());

        let mut row_drift = baseline.overlay.clone();
        row_drift.authority.meter_policies[target_index].task_id_hex = hex::encode(b"drift-task");
        let mut late_bad_root = operation.clone();
        poison_raw_nullifier_roots_v0(&mut late_bad_root.nullifier_insertions);
        assert_carrier_drift(row_drift, &late_bad_root, prepare());

        let mut source_drift = baseline.overlay.clone();
        source_drift.entries.remove(&semantic_key);
        assert_carrier_drift(source_drift, &late_bad_root, prepare());

        let mut mutation_drift = baseline.overlay.clone();
        let source_value = mutation_drift.entries.get(&semantic_key).unwrap().clone();
        mutation_drift.mutations.insert(
            semantic_key.clone(),
            OverlayMutationV0 {
                kind: semantic_key.0,
                logical_key: semantic_key.1.clone(),
                expected_value: Some(source_value),
                next_value: None,
            },
        );
        assert_carrier_drift(mutation_drift, &late_bad_root, prepare());
    }

    #[test]
    fn prune_retired_meter_preparation_freezes_decrement_and_delete_source() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (baseline, raw, operation) =
            fixture_authoring::prune_retired_meter_full_capacity_fixture_v0().unwrap();
        assert_eq!(
            PocoApplicationOperationV0::decode_exact(&raw).unwrap(),
            operation,
        );
        assert_eq!(serde_json::to_vec(&operation).unwrap(), raw);
        assert_eq!(
            baseline.overlay.authority.meter_policies.len(),
            MAX_METER_POLICIES,
        );
        assert_eq!(baseline.operation_count(), 0);
        let PocoApplicationOperationBodyV0::PruneRetiredMeter {
            meter_id_hex,
            meter_version,
        } = &operation.body
        else {
            unreachable!();
        };
        let target_index = baseline
            .overlay
            .authority
            .meter_policies
            .binary_search_by(|policy| {
                (policy.meter_id_hex.as_str(), policy.meter_version)
                    .cmp(&(meter_id_hex.as_str(), *meter_version))
            })
            .unwrap();
        let source_rows = baseline.overlay.authority.meter_policies.clone();
        let source_target = source_rows[target_index].clone();
        assert_eq!(source_target.retired_at_height, Some(2));
        assert_eq!(operation.semantic_changes.len(), 1);
        assert!(operation.semantic_changes[0].next_value_hex.is_none());
        assert!(operation.nullifier_non_membership_checks.is_empty());
        assert!(operation.nullifier_insertions.is_empty());
        let semantic_key = (
            PocoSnapshotEntryKindV0::MeterDefinition,
            exact_hash32_hex(&operation.semantic_changes[0].logical_key_hex)
                .unwrap()
                .to_vec(),
        );
        let source_value = baseline.overlay.entries.get(&semantic_key).unwrap().clone();
        let accumulator_before = baseline.overlay.accumulator;

        let mut canonical = baseline.clone();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        let expected_rows = source_rows
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != target_index)
            .map(|(_, row)| row.clone())
            .collect::<Vec<_>>();
        assert_eq!(canonical.overlay.authority.meter_policies, expected_rows);
        assert!(canonical
            .overlay
            .authority
            .meter_policies
            .windows(2)
            .all(|pair| {
                (&pair[0].meter_id_hex, pair[0].meter_version)
                    < (&pair[1].meter_id_hex, pair[1].meter_version)
            }));
        assert_eq!(canonical.overlay.accumulator, accumulator_before);
        assert!(!canonical.overlay.entries.contains_key(&semantic_key));
        let mutation = canonical.overlay.mutations.get(&semantic_key).unwrap();
        assert_eq!(mutation.expected_value.as_ref(), Some(&source_value));
        assert!(mutation.next_value.is_none());
        assert_eq!(canonical.overlay.mutations.len(), 1);
        assert_eq!(canonical.clone().seal().unwrap().operation_count(), 1);
        let before_duplicate = canonical.clone();
        assert_eq!(
            canonical.apply_decoded_exact(&raw, &operation),
            Err(DeterministicallyInvalid(Invalid::DuplicateOperation)),
        );
        assert_block_overlay_unchanged(&canonical, &before_duplicate);

        let assert_failure =
            |mut candidate: PocoApplicationBlockOverlayV0,
             candidate_operation: PocoApplicationOperationV0,
             expected: PocoApplicationApplyFailureV0| {
                let candidate_raw = serde_json::to_vec(&candidate_operation).unwrap();
                let before = candidate.clone();
                assert_eq!(
                    candidate.apply_decoded_exact(&candidate_raw, &candidate_operation),
                    Err(expected),
                );
                assert_block_overlay_unchanged(&candidate, &before);
            };
        let unauthorized_field = || RawNullifierInsertionV0 {
            family: PocoNullifierFamilyV0::MeterIdentity.code(),
            identifier_hex: "07".repeat(32),
            proof_hex: String::new(),
        };

        let mut malformed = operation.clone();
        let PocoApplicationOperationBodyV0::PruneRetiredMeter {
            meter_id_hex: malformed_meter_id_hex,
            ..
        } = &mut malformed.body
        else {
            unreachable!();
        };
        *malformed_meter_id_hex = "0".to_string();
        malformed.nullifier_insertions = vec![unauthorized_field()];
        assert_failure(
            baseline.clone(),
            malformed,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut missing = baseline.clone();
        missing
            .overlay
            .authority
            .meter_policies
            .remove(target_index);
        let mut missing_operation = operation.clone();
        missing_operation.nullifier_insertions = vec![unauthorized_field()];
        assert_failure(
            missing,
            missing_operation,
            DeterministicallyInvalid(Invalid::MissingRequiredAuthorityFact),
        );

        let mut synthetic_over_capacity = baseline.clone();
        for suffix in [1u8, 2] {
            let mut extra = source_rows.last().unwrap().clone();
            extra.meter_id_hex = format!("{}{:02x}", "fe".repeat(31), suffix);
            synthetic_over_capacity
                .overlay
                .authority
                .meter_policies
                .push(extra);
        }
        synthetic_over_capacity
            .overlay
            .authority
            .meter_policies
            .sort_by(|left, right| {
                (&left.meter_id_hex, left.meter_version)
                    .cmp(&(&right.meter_id_hex, right.meter_version))
            });
        assert_eq!(
            synthetic_over_capacity
                .overlay
                .authority
                .meter_policies
                .len(),
            MAX_METER_POLICIES + 2,
        );
        let mut later_field_fault = operation.clone();
        later_field_fault.nullifier_insertions = vec![unauthorized_field()];
        assert_failure(
            synthetic_over_capacity,
            later_field_fault,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut unsupported = operation.clone();
        unsupported.nullifier_non_membership_checks = vec![unauthorized_field()];
        let mut active = baseline.clone();
        active.overlay.authority.meter_policies[target_index].retired_at_height = None;
        assert_failure(
            active,
            unsupported,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut insertion = operation.clone();
        insertion.nullifier_insertions = vec![unauthorized_field()];
        assert_failure(
            baseline.clone(),
            insertion,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut active = baseline.clone();
        active.overlay.authority.meter_policies[target_index].retired_at_height = None;
        assert_failure(
            active,
            operation.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut exact_boundary = baseline.clone();
        exact_boundary.overlay.authority.meter_policies[target_index].retired_at_height = Some(4);
        assert_failure(
            exact_boundary,
            operation.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut arithmetic_overflow = baseline.clone();
        arithmetic_overflow.overlay.authority.meter_policies[target_index].retired_at_height =
            Some(u64::MAX);
        assert_failure(
            arithmetic_overflow,
            operation.clone(),
            Invariant(InvariantReason::PlannerArithmetic),
        );

        let (active_reference, active_reference_raw, active_reference_operation) =
            fixture_authoring::prune_retired_meter_active_reference_fixture_v0().unwrap();
        assert_eq!(
            PocoApplicationOperationV0::decode_exact(&active_reference_raw).unwrap(),
            active_reference_operation,
        );
        let mut active_reference_owner_drift = active_reference.clone();
        active_reference_owner_drift
            .overlay
            .authority
            .active_certificates[0]
            .meter_id_hex = hex::encode(b"drift-meter");
        assert_failure(
            active_reference_owner_drift,
            active_reference_operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );
        assert_failure(
            active_reference,
            active_reference_operation,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut retained_usage = baseline.clone();
        retained_usage
            .overlay
            .authority
            .meter_usage
            .push(MeterRollingUsageV0 {
                meter_id_hex: meter_id_hex.clone(),
                meter_version: *meter_version,
                window_epoch: baseline.context.active_epoch.get(),
                consumed_units: CanonicalU128V0::new(1),
            });
        assert_failure(
            retained_usage,
            operation.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut missing_predecessor = baseline.clone();
        missing_predecessor.overlay.entries.remove(&semantic_key);
        assert_failure(
            missing_predecessor,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut authority_semantic_drift = baseline.clone();
        authority_semantic_drift.overlay.authority.meter_policies[target_index].unit_scale =
            CanonicalU128V0::new(2);
        assert_failure(
            authority_semantic_drift,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut missing_delete = operation.clone();
        missing_delete.semantic_changes.clear();
        assert_failure(
            baseline.clone(),
            missing_delete,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut extra_delete = operation.clone();
        extra_delete
            .semantic_changes
            .push(extra_delete.semantic_changes[0].clone());
        assert_failure(
            baseline.clone(),
            extra_delete,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut foreign_delete = operation.clone();
        foreign_delete.semantic_changes[0].logical_key_hex = "ab".repeat(32);
        assert_failure(
            baseline.clone(),
            foreign_delete,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut wrong_kind = operation.clone();
        wrong_kind.semantic_changes[0].kind =
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization as u8;
        assert_failure(
            baseline.clone(),
            wrong_kind,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut replacement = operation.clone();
        replacement.semantic_changes[0].next_value_hex = Some(hex::encode(&source_value));
        assert_failure(
            baseline.clone(),
            replacement,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let decision_preimage = decision_preimage_digest_v0(&baseline.context, &operation).unwrap();
        let prepare = || {
            validate_operation_capacity_before_clone_v0(
                &baseline.context,
                &baseline.overlay,
                &operation,
                decision_preimage,
            )
            .unwrap()
        };
        let assert_carrier_drift =
            |mut candidate: PocoApplicationOverlayV0,
             candidate_operation: &PocoApplicationOperationV0,
             prepared: PreparedCapacityOperationV0| {
                let before = candidate.clone();
                let error = apply_operation_v0(
                    &baseline.context,
                    &mut candidate,
                    candidate_operation,
                    decision_preimage,
                    prepared,
                )
                .unwrap_err();
                assert_eq!(
                    error
                        .downcast_ref::<PocoApplicationApplyFailureV0>()
                        .copied(),
                    Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
                );
                assert_eq!(candidate.entries, before.entries);
                assert_eq!(
                    candidate.source_authority_value,
                    before.source_authority_value,
                );
                assert_eq!(candidate.authority, before.authority);
                assert_eq!(candidate.accumulator, before.accumulator);
                assert_eq!(candidate.operation_ids, before.operation_ids);
                assert_eq!(
                    candidate
                        .mutations
                        .values()
                        .map(OverlayMutationV0::canonical_bytes)
                        .collect::<Vec<_>>(),
                    before
                        .mutations
                        .values()
                        .map(OverlayMutationV0::canonical_bytes)
                        .collect::<Vec<_>>(),
                );
            };

        let mut cross_family = operation.clone();
        cross_family.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        assert_carrier_drift(baseline.overlay.clone(), &cross_family, prepare());

        let mut body_drift = operation.clone();
        let PocoApplicationOperationBodyV0::PruneRetiredMeter { meter_version, .. } =
            &mut body_drift.body
        else {
            unreachable!();
        };
        *meter_version += 1;
        assert_carrier_drift(baseline.overlay.clone(), &body_drift, prepare());

        let mut field_owner_drift = operation.clone();
        field_owner_drift.nullifier_insertions = vec![unauthorized_field()];
        assert_carrier_drift(baseline.overlay.clone(), &field_owner_drift, prepare());

        let mut non_membership_owner_drift = operation.clone();
        non_membership_owner_drift.nullifier_non_membership_checks = vec![unauthorized_field()];
        assert_carrier_drift(
            baseline.overlay.clone(),
            &non_membership_owner_drift,
            prepare(),
        );

        let mut semantic_owner_drift = operation.clone();
        semantic_owner_drift.semantic_changes.clear();
        assert_carrier_drift(baseline.overlay.clone(), &semantic_owner_drift, prepare());

        let mut slot_drift = baseline.overlay.clone();
        slot_drift.authority.meter_policies.remove(target_index);
        assert_carrier_drift(slot_drift, &operation, prepare());

        let mut row_drift = baseline.overlay.clone();
        row_drift.authority.meter_policies[target_index].task_id_hex = hex::encode(b"drift-task");
        assert_carrier_drift(row_drift, &operation, prepare());

        let mut source_drift = baseline.overlay.clone();
        source_drift.entries.remove(&semantic_key);
        assert_carrier_drift(source_drift, &operation, prepare());

        let mut mutation_drift = baseline.overlay.clone();
        mutation_drift.mutations.insert(
            semantic_key.clone(),
            OverlayMutationV0 {
                kind: semantic_key.0,
                logical_key: semantic_key.1.clone(),
                expected_value: Some(source_value),
                next_value: None,
            },
        );
        assert_carrier_drift(mutation_drift, &operation, prepare());
    }

    #[test]
    fn revoke_consumer_key_preparation_freezes_zero_delta_capacity_and_late_proof() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (baseline, raw, operation) =
            fixture_authoring::revoke_consumer_key_full_capacity_fixture_v0().unwrap();
        assert_eq!(
            baseline.overlay.authority.consumer_keys.len(),
            MAX_CONSUMER_KEY_AUTHORITIES,
        );
        assert_eq!(baseline.operation_count(), 0);
        assert_eq!(
            PocoApplicationOperationV0::decode_exact(&raw).unwrap(),
            operation,
        );
        let PocoApplicationOperationBodyV0::RevokeConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
            public_key_hex,
            active_from_height,
            revoked_at_height,
            decision_id_hex,
        } = &operation.body
        else {
            unreachable!();
        };
        let target_index = baseline
            .overlay
            .authority
            .consumer_keys
            .binary_search_by(|item| {
                (
                    item.consumer_id_hex.as_str(),
                    item.consumer_key_id_hex.as_str(),
                )
                    .cmp(&(consumer_id_hex.as_str(), consumer_key_id_hex.as_str()))
            })
            .unwrap();
        let source_rows = baseline.overlay.authority.consumer_keys.clone();
        let source_target = source_rows[target_index].clone();
        assert!(
            !source_target.nonce_watermarks.is_empty(),
            "authenticated full-capacity predecessor must carry a real nonce watermark"
        );
        let semantic_key = (
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            exact_hash32_hex(&operation.semantic_changes[0].logical_key_hex)
                .unwrap()
                .to_vec(),
        );
        let source_semantic = owned_semantic_parts(
            semantic_key.0,
            &semantic_key.1,
            baseline.overlay.entries.get(&semantic_key).unwrap(),
        )
        .unwrap();
        let accumulator_before = baseline.overlay.accumulator.count();

        let mut canonical = baseline.clone();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        assert_eq!(
            canonical.overlay.authority.consumer_keys.len(),
            MAX_CONSUMER_KEY_AUTHORITIES,
        );
        assert!(canonical
            .overlay
            .authority
            .consumer_keys
            .windows(2)
            .all(|pair| {
                (&pair[0].consumer_id_hex, &pair[0].consumer_key_id_hex)
                    < (&pair[1].consumer_id_hex, &pair[1].consumer_key_id_hex)
            }));
        for (index, row) in canonical.overlay.authority.consumer_keys.iter().enumerate() {
            if index == target_index {
                let mut expected = source_target.clone();
                expected.revoked_at_height = Some(*revoked_at_height);
                expected.revocation_decision_id_hex = Some(decision_id_hex.clone());
                assert_eq!(row, &expected);
                assert_eq!(row.nonce_watermarks, source_target.nonce_watermarks);
            } else {
                assert_eq!(row, &source_rows[index]);
            }
        }
        assert_eq!(
            canonical.overlay.accumulator.count(),
            accumulator_before + 1,
        );
        let target_semantic = owned_semantic_parts(
            semantic_key.0,
            &semantic_key.1,
            canonical.overlay.entries.get(&semantic_key).unwrap(),
        )
        .unwrap();
        assert_eq!(
            target_semantic.revision,
            source_semantic.revision.checked_add(1).unwrap(),
        );
        assert_eq!(target_semantic.identity, source_semantic.identity);
        assert!(matches!(
            target_semantic.fact,
            SemanticFactV0::ConsumerKeyAuthorization {
                public_key,
                active_from,
                revoked_at: Some(height),
            } if hex::encode(public_key) == *public_key_hex
                && active_from == *active_from_height
                && height == *revoked_at_height
        ));
        assert_eq!(canonical.seal().unwrap().operation_count(), 1);

        let assert_failure =
            |mut candidate: PocoApplicationBlockOverlayV0,
             candidate_operation: PocoApplicationOperationV0,
             expected: PocoApplicationApplyFailureV0| {
                let candidate_raw = serde_json::to_vec(&candidate_operation).unwrap();
                let before = candidate.clone();
                assert_eq!(
                    candidate.apply_decoded_exact(&candidate_raw, &candidate_operation),
                    Err(expected),
                );
                assert_block_overlay_unchanged(&candidate, &before);
            };

        let mut malformed_consumer = operation.clone();
        let PocoApplicationOperationBodyV0::RevokeConsumerKey {
            consumer_id_hex, ..
        } = &mut malformed_consumer.body
        else {
            unreachable!();
        };
        *consumer_id_hex = "0".to_string();
        assert_failure(
            baseline.clone(),
            malformed_consumer,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut missing = baseline.clone();
        missing.overlay.authority.consumer_keys[target_index].consumer_id_hex = "fe".repeat(32);
        missing
            .overlay
            .authority
            .consumer_keys
            .sort_by(|left, right| {
                (&left.consumer_id_hex, &left.consumer_key_id_hex)
                    .cmp(&(&right.consumer_id_hex, &right.consumer_key_id_hex))
            });
        let mut later_bad_height = operation.clone();
        let PocoApplicationOperationBodyV0::RevokeConsumerKey {
            revoked_at_height, ..
        } = &mut later_bad_height.body
        else {
            unreachable!();
        };
        *revoked_at_height = baseline.context.target_height.get() + 1;
        later_bad_height.nullifier_insertions.clear();
        assert_failure(
            missing,
            later_bad_height,
            DeterministicallyInvalid(Invalid::MissingRequiredAuthorityFact),
        );

        let mut synthetic_over_capacity = baseline.clone();
        let mut fifth = source_rows.last().unwrap().clone();
        fifth.consumer_id_hex = "ff".repeat(31) + "01";
        fifth.consumer_key_id_hex = "ff".repeat(31) + "02";
        synthetic_over_capacity
            .overlay
            .authority
            .consumer_keys
            .push(fifth);
        synthetic_over_capacity
            .overlay
            .authority
            .consumer_keys
            .sort_by(|left, right| {
                (&left.consumer_id_hex, &left.consumer_key_id_hex)
                    .cmp(&(&right.consumer_id_hex, &right.consumer_key_id_hex))
            });
        assert_eq!(
            synthetic_over_capacity
                .overlay
                .authority
                .consumer_keys
                .len(),
            MAX_CONSUMER_KEY_AUTHORITIES + 1,
        );
        let mut synthetic_later_fault = operation.clone();
        synthetic_later_fault.nullifier_non_membership_checks =
            vec![synthetic_later_fault.nullifier_insertions[0].clone()];
        assert_failure(
            synthetic_over_capacity,
            synthetic_later_fault,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut unsupported = operation.clone();
        unsupported.nullifier_non_membership_checks =
            vec![unsupported.nullifier_insertions[0].clone()];
        let PocoApplicationOperationBodyV0::RevokeConsumerKey {
            revoked_at_height, ..
        } = &mut unsupported.body
        else {
            unreachable!();
        };
        *revoked_at_height = baseline.context.target_height.get() + 1;
        assert_failure(
            baseline.clone(),
            unsupported,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut zero_public_key = operation.clone();
        let PocoApplicationOperationBodyV0::RevokeConsumerKey { public_key_hex, .. } =
            &mut zero_public_key.body
        else {
            unreachable!();
        };
        *public_key_hex = "00".repeat(32);
        assert_failure(
            baseline.clone(),
            zero_public_key,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut wrong_decision = operation.clone();
        let PocoApplicationOperationBodyV0::RevokeConsumerKey {
            decision_id_hex, ..
        } = &mut wrong_decision.body
        else {
            unreachable!();
        };
        *decision_id_hex = "ee".repeat(32);
        assert_failure(
            baseline.clone(),
            wrong_decision,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut malformed_authority = baseline.clone();
        malformed_authority.overlay.authority.consumer_keys[target_index].public_key_hex =
            "00".to_string();
        assert_failure(
            malformed_authority,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut missing_predecessor = baseline.clone();
        missing_predecessor.overlay.entries.remove(&semantic_key);
        assert_failure(
            missing_predecessor,
            operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut exhausted = baseline.clone();
        exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX).unwrap();
        exhausted
            .overlay
            .authority
            .set_accumulator(exhausted.overlay.accumulator);
        let mut later_bad_proof = operation.clone();
        later_bad_proof.nullifier_insertions.clear();
        assert_failure(
            exhausted,
            later_bad_proof,
            Invariant(InvariantReason::ProtocolCounterExhausted),
        );

        let mut bad_shape = operation.clone();
        bad_shape.nullifier_insertions.clear();
        assert_failure(
            baseline.clone(),
            bad_shape,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_subject = operation.clone();
        let subject = [0xa5; 32];
        let family = PocoNullifierFamilyV0::MeterDecision;
        let key = derive_poco_nullifier_key_v0(family, subject);
        let siblings = std::array::from_fn(|level| {
            crate::poco_nullifier::poco_nullifier_default_hash_v0(level).unwrap()
        });
        bad_subject.nullifier_insertions[0] = RawNullifierInsertionV0 {
            family: family.code(),
            identifier_hex: hex::encode(subject),
            proof_hex: hex::encode(PocoNullifierProofV0::new(key, siblings).canonical_bytes()),
        };
        assert_failure(
            baseline.clone(),
            bad_subject,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut bad_root = operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_root.nullifier_insertions);
        assert_failure(
            baseline.clone(),
            bad_root.clone(),
            DeterministicallyInvalid(Invalid::NullifierNonMembershipRootMismatch),
        );

        let bad_root_raw = serde_json::to_vec(&bad_root).unwrap();
        let mut operation_full = baseline.clone();
        operation_full.raw_operations = vec![Vec::new(); MAX_APPLICATION_OPERATIONS_PER_BLOCK];
        let before = operation_full.clone();
        assert_eq!(
            operation_full.apply_decoded_exact(&bad_root_raw, &bad_root),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&operation_full, &before);

        let mut byte_full = baseline.clone();
        byte_full.aggregate_operation_bytes = MAX_POCO_SNAPSHOT_BUNDLE_BYTES;
        let before = byte_full.clone();
        assert_eq!(
            byte_full.apply_decoded_exact(&bad_root_raw, &bad_root),
            Err(DeterministicallyInvalid(Invalid::PerBlockCapacity)),
        );
        assert_block_overlay_unchanged(&byte_full, &before);

        let decision_preimage = decision_preimage_digest_v0(&baseline.context, &operation).unwrap();
        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut cross_family = operation.clone();
        cross_family.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        let mut candidate = baseline.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &cross_family,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(before.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut semantic_owner_drift = operation.clone();
        semantic_owner_drift.semantic_changes[0].next_value_hex = None;
        let mut candidate = baseline.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &semantic_owner_drift,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(before.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut body_drift = operation.clone();
        let PocoApplicationOperationBodyV0::RevokeConsumerKey { public_key_hex, .. } =
            &mut body_drift.body
        else {
            unreachable!();
        };
        *public_key_hex = "ab".repeat(32);
        let mut candidate = baseline.overlay.clone();
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &body_drift,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(before.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut candidate = baseline.overlay.clone();
        candidate.authority.consumer_keys[target_index].nonce_watermarks[0].max_accepted_nonce =
            candidate.authority.consumer_keys[target_index].nonce_watermarks[0]
                .max_accepted_nonce
                .checked_add(1)
                .unwrap();
        let before = candidate.clone();
        let mut late_proof_drift = operation.clone();
        poison_raw_nullifier_roots_v0(&mut late_proof_drift.nullifier_insertions);
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &late_proof_drift,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(before.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut candidate = baseline.overlay.clone();
        candidate.authority.consumer_keys[target_index].authorization_decision_id_hex =
            "cd".repeat(32);
        let before = candidate.clone();
        let mut proof_drift = operation.clone();
        poison_raw_nullifier_roots_v0(&mut proof_drift.nullifier_insertions);
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &proof_drift,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(before.mutations.is_empty());

        let prepared = validate_operation_capacity_before_clone_v0(
            &baseline.context,
            &baseline.overlay,
            &operation,
            decision_preimage,
        )
        .unwrap();
        let mut candidate = baseline.overlay.clone();
        candidate.entries.remove(&semantic_key);
        let before = candidate.clone();
        let error = apply_operation_v0(
            &baseline.context,
            &mut candidate,
            &proof_drift,
            decision_preimage,
            prepared,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PocoApplicationApplyFailureV0>()
                .copied(),
            Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
        );
        assert_eq!(candidate.entries, before.entries);
        assert_eq!(candidate.authority, before.authority);
        assert_eq!(candidate.accumulator, before.accumulator);
        assert!(candidate.mutations.is_empty());
        assert!(before.mutations.is_empty());
    }

    #[test]
    fn prune_consumer_key_preparation_freezes_decrements_identity_and_late_proof() {
        use PocoApplicationApplyFailureV0::{DeterministicallyInvalid, Invariant};
        use PocoApplicationDeterministicInvalidV0 as Invalid;
        use PocoApplicationInvariantV0 as InvariantReason;

        let (baseline, raw, operation) =
            fixture_authoring::prune_revoked_consumer_key_full_capacity_fixture_v0().unwrap();
        assert_eq!(
            PocoApplicationOperationV0::decode_exact(&raw).unwrap(),
            operation,
        );
        assert_eq!(serde_json::to_vec(&operation).unwrap(), raw);
        assert_eq!(
            baseline.overlay.authority.consumer_keys.len(),
            MAX_CONSUMER_KEY_AUTHORITIES,
        );
        assert_eq!(baseline.operation_count(), 0);
        let PocoApplicationOperationBodyV0::PruneRevokedConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
        } = &operation.body
        else {
            unreachable!();
        };
        let target_index = baseline
            .overlay
            .authority
            .consumer_keys
            .binary_search_by(|item| {
                (
                    item.consumer_id_hex.as_str(),
                    item.consumer_key_id_hex.as_str(),
                )
                    .cmp(&(consumer_id_hex.as_str(), consumer_key_id_hex.as_str()))
            })
            .unwrap();
        let source_rows = baseline.overlay.authority.consumer_keys.clone();
        let source_target = source_rows[target_index].clone();
        assert_eq!(source_target.revoked_at_height, Some(285));
        assert!(!source_target.nonce_watermarks.is_empty());
        let source_nonce_count = total_nonce_watermarks_v0(&baseline.overlay.authority).unwrap();
        assert_eq!(source_nonce_count, source_target.nonce_watermarks.len());
        let expected_summary = consumer_nonce_summary_digest_v0(&source_target).unwrap();
        assert_eq!(operation.nullifier_insertions.len(), 1);
        assert_eq!(
            operation.nullifier_insertions[0].family,
            PocoNullifierFamilyV0::ConsumerNonceSummary.code(),
        );
        assert_eq!(
            exact_hash32_hex(&operation.nullifier_insertions[0].identifier_hex).unwrap(),
            expected_summary,
        );
        assert_eq!(
            operation.semantic_changes.len(),
            1 + source_target.nonce_watermarks.len(),
        );
        assert!(operation
            .semantic_changes
            .iter()
            .all(|change| change.next_value_hex.is_none()));
        let delete_keys = operation
            .semantic_changes
            .iter()
            .map(|change| {
                (
                    PocoSnapshotEntryKindV0::from_u8(change.kind).unwrap(),
                    exact_hash32_hex(&change.logical_key_hex).unwrap().to_vec(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(delete_keys.len(), operation.semantic_changes.len());
        assert!(delete_keys
            .iter()
            .all(|key| baseline.overlay.entries.contains_key(key)));
        let accumulator_before = baseline.overlay.accumulator.count();

        let mut canonical = baseline.clone();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        let expected_rows = source_rows
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != target_index)
            .map(|(_, row)| row.clone())
            .collect::<Vec<_>>();
        assert_eq!(canonical.overlay.authority.consumer_keys, expected_rows);
        assert!(canonical
            .overlay
            .authority
            .consumer_keys
            .windows(2)
            .all(|pair| {
                (&pair[0].consumer_id_hex, &pair[0].consumer_key_id_hex)
                    < (&pair[1].consumer_id_hex, &pair[1].consumer_key_id_hex)
            }));
        assert_eq!(
            total_nonce_watermarks_v0(&canonical.overlay.authority).unwrap(),
            source_nonce_count - source_target.nonce_watermarks.len(),
        );
        assert_eq!(
            canonical.overlay.accumulator.count(),
            accumulator_before + 1,
        );
        for key in &delete_keys {
            assert!(!canonical.overlay.entries.contains_key(key));
            let mutation = canonical.overlay.mutations.get(key).unwrap();
            assert!(mutation.expected_value.is_some());
            assert!(mutation.next_value.is_none());
        }
        assert_eq!(canonical.overlay.mutations.len(), delete_keys.len());
        assert_eq!(canonical.clone().seal().unwrap().operation_count(), 1);
        let before_duplicate = canonical.clone();
        assert_eq!(
            canonical.apply_decoded_exact(&raw, &operation),
            Err(DeterministicallyInvalid(Invalid::DuplicateOperation)),
        );
        assert_block_overlay_unchanged(&canonical, &before_duplicate);

        let assert_failure =
            |mut candidate: PocoApplicationBlockOverlayV0,
             candidate_operation: PocoApplicationOperationV0,
             expected: PocoApplicationApplyFailureV0| {
                let candidate_raw = serde_json::to_vec(&candidate_operation).unwrap();
                let before = candidate.clone();
                assert_eq!(
                    candidate.apply_decoded_exact(&candidate_raw, &candidate_operation),
                    Err(expected),
                );
                assert_block_overlay_unchanged(&candidate, &before);
            };

        let mut malformed = operation.clone();
        let PocoApplicationOperationBodyV0::PruneRevokedConsumerKey {
            consumer_id_hex, ..
        } = &mut malformed.body
        else {
            unreachable!();
        };
        *consumer_id_hex = "0".to_string();
        poison_raw_nullifier_roots_v0(&mut malformed.nullifier_insertions);
        assert_failure(
            baseline.clone(),
            malformed,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut missing = baseline.clone();
        missing.overlay.authority.consumer_keys.remove(target_index);
        let mut missing_operation = operation.clone();
        poison_raw_nullifier_roots_v0(&mut missing_operation.nullifier_insertions);
        assert_failure(
            missing,
            missing_operation,
            DeterministicallyInvalid(Invalid::MissingRequiredAuthorityFact),
        );

        let mut consumer_over_cap = baseline.clone();
        for suffix in [1u8, 2] {
            let mut extra = source_rows.last().unwrap().clone();
            extra.consumer_id_hex = format!("{}{:02x}", "fe".repeat(31), suffix);
            extra.consumer_key_id_hex = format!("{}{:02x}", "fd".repeat(31), suffix);
            consumer_over_cap
                .overlay
                .authority
                .consumer_keys
                .push(extra);
        }
        consumer_over_cap
            .overlay
            .authority
            .consumer_keys
            .sort_by(|left, right| {
                (&left.consumer_id_hex, &left.consumer_key_id_hex)
                    .cmp(&(&right.consumer_id_hex, &right.consumer_key_id_hex))
            });
        let mut later_fault = operation.clone();
        later_fault.nullifier_non_membership_checks =
            vec![later_fault.nullifier_insertions[0].clone()];
        assert_failure(
            consumer_over_cap,
            later_fault,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut nonce_over_cap = baseline.clone();
        let watermark = source_target.nonce_watermarks[0].clone();
        for (index, row) in nonce_over_cap
            .overlay
            .authority
            .consumer_keys
            .iter_mut()
            .enumerate()
        {
            if index != target_index {
                row.nonce_watermarks = vec![watermark.clone(); 3];
            }
        }
        assert_eq!(
            total_nonce_watermarks_v0(&nonce_over_cap.overlay.authority).unwrap()
                - source_target.nonce_watermarks.len(),
            MAX_TOTAL_NONCE_WATERMARKS + 1,
        );
        let mut later_fault = operation.clone();
        poison_raw_nullifier_roots_v0(&mut later_fault.nullifier_insertions);
        assert_failure(
            nonce_over_cap,
            later_fault,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut unsupported = operation.clone();
        unsupported.nullifier_non_membership_checks =
            vec![unsupported.nullifier_insertions[0].clone()];
        let mut unrevoked = baseline.clone();
        unrevoked.overlay.authority.consumer_keys[target_index].revoked_at_height = None;
        unrevoked.overlay.authority.consumer_keys[target_index].revocation_decision_id_hex = None;
        assert_failure(
            unrevoked,
            unsupported,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut unrevoked = baseline.clone();
        unrevoked.overlay.authority.consumer_keys[target_index].revoked_at_height = None;
        unrevoked.overlay.authority.consumer_keys[target_index].revocation_decision_id_hex = None;
        let mut bad_root = operation.clone();
        poison_raw_nullifier_roots_v0(&mut bad_root.nullifier_insertions);
        assert_failure(
            unrevoked,
            bad_root.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let retention =
            protocol_retention_boundary_v0(0, &baseline.context.active_parameters).unwrap();
        let mut exact_boundary = baseline.clone();
        exact_boundary.overlay.authority.consumer_keys[target_index].revoked_at_height = Some(
            baseline
                .context
                .target_height
                .get()
                .checked_sub(retention)
                .unwrap(),
        );
        assert_failure(
            exact_boundary,
            bad_root.clone(),
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let mut arithmetic = baseline.clone();
        arithmetic.overlay.authority.consumer_keys[target_index].revoked_at_height = Some(u64::MAX);
        assert_failure(
            arithmetic,
            bad_root.clone(),
            Invariant(InvariantReason::PlannerArithmetic),
        );

        let (active_reference, active_raw, active_operation) =
            fixture_authoring::prune_revoked_consumer_key_active_reference_fixture_v0().unwrap();
        assert_eq!(
            PocoApplicationOperationV0::decode_exact(&active_raw).unwrap(),
            active_operation,
        );
        let mut active_bad_root = active_operation.clone();
        poison_raw_nullifier_roots_v0(&mut active_bad_root.nullifier_insertions);
        assert_failure(
            active_reference.clone(),
            active_bad_root,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );
        let mut active_reference_owner_drift = active_reference.clone();
        active_reference_owner_drift
            .overlay
            .authority
            .active_certificates[0]
            .consumer_id_hex = "ff".repeat(32);
        assert_failure(
            active_reference_owner_drift,
            active_operation.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );
        assert_failure(
            active_reference,
            active_operation,
            DeterministicallyInvalid(Invalid::ProtocolWindowOrCap),
        );

        let key_change = operation
            .semantic_changes
            .iter()
            .find(|change| change.kind == PocoSnapshotEntryKindV0::ConsumerKeyAuthorization as u8)
            .unwrap();
        let key_map_key = (
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            exact_hash32_hex(&key_change.logical_key_hex)
                .unwrap()
                .to_vec(),
        );
        let nonce_change = operation
            .semantic_changes
            .iter()
            .find(|change| change.kind == PocoSnapshotEntryKindV0::ConsumerNonce as u8)
            .unwrap();
        let nonce_map_key = (
            PocoSnapshotEntryKindV0::ConsumerNonce,
            exact_hash32_hex(&nonce_change.logical_key_hex)
                .unwrap()
                .to_vec(),
        );

        let mut missing_key_companion = baseline.clone();
        missing_key_companion.overlay.entries.remove(&key_map_key);
        assert_failure(
            missing_key_companion,
            bad_root.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut malformed_nonce_companion = baseline.clone();
        malformed_nonce_companion
            .overlay
            .entries
            .insert(nonce_map_key.clone(), vec![0xff]);
        assert_failure(
            malformed_nonce_companion,
            bad_root.clone(),
            Invariant(InvariantReason::AuthenticatedOverlay),
        );

        let mut omitted_nonce = operation.clone();
        omitted_nonce
            .semantic_changes
            .retain(|change| change.kind != PocoSnapshotEntryKindV0::ConsumerNonce as u8);
        poison_raw_nullifier_roots_v0(&mut omitted_nonce.nullifier_insertions);
        assert_failure(
            baseline.clone(),
            omitted_nonce,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut replacement = operation.clone();
        let replacement_change = replacement
            .semantic_changes
            .iter_mut()
            .find(|change| change.kind == PocoSnapshotEntryKindV0::ConsumerNonce as u8)
            .unwrap();
        replacement_change.next_value_hex = Some(hex::encode(
            baseline.overlay.entries.get(&nonce_map_key).unwrap(),
        ));
        poison_raw_nullifier_roots_v0(&mut replacement.nullifier_insertions);
        assert_failure(
            baseline.clone(),
            replacement,
            DeterministicallyInvalid(Invalid::SemanticTransition),
        );

        let mut exhausted = baseline.clone();
        exhausted.overlay.accumulator =
            PocoNullifierAccumulatorV0::from_authenticated_parts([2; 32], u64::MAX).unwrap();
        exhausted
            .overlay
            .authority
            .set_accumulator(exhausted.overlay.accumulator);
        assert_failure(
            exhausted,
            bad_root.clone(),
            Invariant(InvariantReason::ProtocolCounterExhausted),
        );

        let mut no_proof = operation.clone();
        no_proof.nullifier_insertions.clear();
        assert_failure(
            baseline.clone(),
            no_proof,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut wrong_family = operation.clone();
        wrong_family.nullifier_insertions[0].family =
            PocoNullifierFamilyV0::ConsumerKeyDecision.code();
        assert_failure(
            baseline.clone(),
            wrong_family,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        let mut wrong_identifier = operation.clone();
        wrong_identifier.nullifier_insertions[0].identifier_hex = "ab".repeat(32);
        assert_failure(
            baseline.clone(),
            wrong_identifier,
            DeterministicallyInvalid(Invalid::NullifierProof),
        );

        assert_failure(
            baseline.clone(),
            bad_root.clone(),
            DeterministicallyInvalid(Invalid::NullifierNonMembershipRootMismatch),
        );

        let decision_preimage = decision_preimage_digest_v0(&baseline.context, &operation).unwrap();
        let prepare = || {
            validate_operation_capacity_before_clone_v0(
                &baseline.context,
                &baseline.overlay,
                &operation,
                decision_preimage,
            )
            .unwrap()
        };
        let assert_carrier_drift =
            |mut candidate: PocoApplicationOverlayV0,
             candidate_operation: &PocoApplicationOperationV0,
             prepared: PreparedCapacityOperationV0| {
                let before = candidate.clone();
                let error = apply_operation_v0(
                    &baseline.context,
                    &mut candidate,
                    candidate_operation,
                    decision_preimage,
                    prepared,
                )
                .unwrap_err();
                assert_eq!(
                    error
                        .downcast_ref::<PocoApplicationApplyFailureV0>()
                        .copied(),
                    Some(Invariant(InvariantReason::DerivedMutationPostcondition)),
                );
                assert_eq!(candidate.entries, before.entries);
                assert_eq!(candidate.authority, before.authority);
                assert_eq!(candidate.accumulator, before.accumulator);
                assert_eq!(candidate.operation_ids, before.operation_ids);
                assert!(candidate.mutations.is_empty());
                assert!(before.mutations.is_empty());
            };

        let mut cross_family = bad_root.clone();
        cross_family.body = PocoApplicationOperationBodyV0::PruneExpiredCertificate {
            certificate_id_hex: "11".repeat(32),
        };
        assert_carrier_drift(baseline.overlay.clone(), &cross_family, prepare());

        let mut body_drift = bad_root.clone();
        let PocoApplicationOperationBodyV0::PruneRevokedConsumerKey {
            consumer_key_id_hex,
            ..
        } = &mut body_drift.body
        else {
            unreachable!();
        };
        *consumer_key_id_hex = "cd".repeat(32);
        assert_carrier_drift(baseline.overlay.clone(), &body_drift, prepare());

        let mut semantic_owner_drift = bad_root.clone();
        semantic_owner_drift.semantic_changes.pop();
        assert_carrier_drift(baseline.overlay.clone(), &semantic_owner_drift, prepare());

        let mut row_drift = baseline.overlay.clone();
        row_drift.authority.consumer_keys[target_index].nonce_watermarks[0].max_accepted_nonce += 1;
        assert_carrier_drift(row_drift, &bad_root, prepare());

        let mut source_drift = baseline.overlay.clone();
        source_drift.entries.remove(&nonce_map_key);
        assert_carrier_drift(source_drift, &bad_root, prepare());
    }

    #[test]
    fn consumer_nonce_summary_identity_allows_two_empty_key_prunes() {
        let (mut block, raw_operations) =
            fixture_authoring::prune_two_empty_consumer_keys_fixture_v0().unwrap();
        assert_eq!(raw_operations.len(), 2);
        assert_eq!(block.overlay.authority.consumer_keys.len(), 2);
        assert!(block
            .overlay
            .authority
            .consumer_keys
            .iter()
            .all(|authority| authority.nonce_watermarks.is_empty()));
        let accumulator_before = block.overlay.accumulator.count();
        let mut identifiers = BTreeSet::new();
        for raw in &raw_operations {
            let operation = PocoApplicationOperationV0::decode_exact(raw).unwrap();
            assert_eq!(operation.nullifier_insertions.len(), 1);
            assert_eq!(
                operation.nullifier_insertions[0].family,
                PocoNullifierFamilyV0::ConsumerNonceSummary.code(),
            );
            assert!(identifiers.insert(
                exact_hash32_hex(&operation.nullifier_insertions[0].identifier_hex).unwrap(),
            ));
            block.apply_decoded_exact(raw, &operation).unwrap();
        }
        assert_eq!(identifiers.len(), 2);
        assert!(block.overlay.authority.consumer_keys.is_empty());
        assert_eq!(block.overlay.accumulator.count(), accumulator_before + 2);
        assert_eq!(block.overlay.mutations.len(), 2);
        assert!(block
            .overlay
            .mutations
            .values()
            .all(
                |mutation| mutation.kind == PocoSnapshotEntryKindV0::ConsumerKeyAuthorization
                    && mutation.expected_value.is_some()
                    && mutation.next_value.is_none()
            ));
        let sealed = block.seal().unwrap();
        assert_eq!(sealed.operation_count(), 2);
    }

    #[test]
    fn consumer_key_revocation_splits_authenticated_predecessor_from_signed_successor() {
        let (mut canonical, operation) = consumer_key_revocation_fixture();
        let raw = serde_json::to_vec(&operation).unwrap();
        canonical.apply_decoded_exact(&raw, &operation).unwrap();
        assert_eq!(canonical.operation_count(), 1);
        assert_eq!(
            canonical.overlay.authority.consumer_keys[0].revoked_at_height,
            Some(canonical.context.target_height.get()),
        );

        let (mut corrupted, operation) = consumer_key_revocation_fixture();
        let raw_change = &operation.semantic_changes[0];
        let logical_key = exact_hash32_hex(&raw_change.logical_key_hex).unwrap();
        let map_key = (
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            logical_key.to_vec(),
        );
        let next_value = hex::decode(raw_change.next_value_hex.as_deref().unwrap()).unwrap();
        let next_parts = owned_semantic_parts(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            &logical_key,
            &next_value,
        )
        .unwrap();
        assert!(matches!(
            next_parts.fact,
            SemanticFactV0::ConsumerKeyAuthorization {
                revoked_at: Some(_),
                ..
            }
        ));
        let corrupted_predecessor = encode_test_semantic_envelope_v0(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            next_parts.revision - 1,
            &next_parts.identity,
            &next_parts.payload,
        );
        corrupted
            .overlay
            .entries
            .insert(map_key.clone(), corrupted_predecessor);
        let corrupted_before = corrupted.clone();
        let raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            corrupted.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&corrupted, &corrupted_before);

        let (mut missing, operation) = consumer_key_revocation_fixture();
        missing.overlay.entries.remove(&map_key);
        let missing_before = missing.clone();
        let raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            missing.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&missing, &missing_before);

        let (mut authority_corrupted, operation) = consumer_key_revocation_fixture();
        authority_corrupted.overlay.authority.consumer_keys[0].public_key_hex = "aa".repeat(32);
        let authority_before = authority_corrupted.clone();
        let raw = serde_json::to_vec(&operation).unwrap();
        assert_eq!(
            authority_corrupted.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_block_overlay_unchanged(&authority_corrupted, &authority_before);

        let (mut foreign_key, mut operation) = consumer_key_revocation_fixture();
        operation.semantic_changes[0].logical_key_hex = "ab".repeat(32);
        bind_consumer_key_revocation_decision_v0(&foreign_key.context, &mut operation);
        let raw = serde_json::to_vec(&operation).unwrap();
        let foreign_key_before = foreign_key.clone();
        assert_eq!(
            foreign_key.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );
        assert_block_overlay_unchanged(&foreign_key, &foreign_key_before);

        let (mut signed, mut operation) = consumer_key_revocation_fixture();
        let active_parts = owned_semantic_parts(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            &logical_key,
            signed.overlay.entries.get(&map_key).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            active_parts.fact,
            SemanticFactV0::ConsumerKeyAuthorization {
                revoked_at: None,
                ..
            }
        ));
        let signed_active_successor = encode_test_semantic_envelope_v0(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            active_parts.revision + 1,
            &active_parts.identity,
            &active_parts.payload,
        );
        operation.semantic_changes[0].next_value_hex = Some(hex::encode(signed_active_successor));
        bind_consumer_key_revocation_decision_v0(&signed.context, &mut operation);
        let raw = serde_json::to_vec(&operation).unwrap();
        let signed_before = signed.clone();
        assert_eq!(
            signed.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );
        assert_block_overlay_unchanged(&signed, &signed_before);
    }

    #[test]
    fn consumer_key_prune_negative_fact_is_typed_before_clone() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let operation = PocoApplicationOperationV0 {
            schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
            target_height: 2,
            expected_state_revision: 1,
            body: PocoApplicationOperationBodyV0::PruneRevokedConsumerKey {
                consumer_id_hex: "01".to_string(),
                consumer_key_id_hex: "02".to_string(),
            },
            semantic_changes: Vec::new(),
            nullifier_non_membership_checks: Vec::new(),
            nullifier_insertions: Vec::new(),
        };
        let raw = serde_json::to_vec(&operation).unwrap();

        assert_eq!(
            block.apply_decoded_exact(&raw, &operation),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn decoded_operation_height_and_revision_rejections_are_typed_and_non_mutating() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let original_authority = block.overlay.authority.clone();

        let mut wrong_height = PocoApplicationOperationV0::decode_exact(
            &block.test_define_meter_operation_v0().unwrap(),
        )
        .unwrap();
        wrong_height.target_height = 3;
        let wrong_height_raw = serde_json::to_vec(&wrong_height).unwrap();
        assert_eq!(
            block.apply_decoded_exact(&wrong_height_raw, &wrong_height),
            Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::TargetHeightMismatch,
            ))
        );

        for revision in [0, 2] {
            let mut wrong_revision = PocoApplicationOperationV0::decode_exact(
                &block.test_define_meter_operation_v0().unwrap(),
            )
            .unwrap();
            wrong_revision.expected_state_revision = revision;
            let wrong_revision_raw = serde_json::to_vec(&wrong_revision).unwrap();
            assert_eq!(
                block.apply_decoded_exact(&wrong_revision_raw, &wrong_revision),
                Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                    PocoApplicationDeterministicInvalidV0::AuthorityRevisionMismatch,
                ))
            );
        }

        assert_eq!(block.operation_count(), 0);
        assert_eq!(block.overlay.authority, original_authority);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn semantic_delete_absence_boundary_is_typed_and_non_mutating() {
        let projection = genesis_projection();
        let block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let original_authority = block.overlay.authority.clone();
        let mut operation = PocoApplicationOperationV0::decode_exact(
            &block.test_define_meter_operation_v0().unwrap(),
        )
        .unwrap();
        operation.semantic_changes[0].next_value_hex = None;
        let error = prepare_semantic_changes(&block.overlay, &operation.semantic_changes, false)
            .expect_err("delete of an absent semantic entry must be rejected");
        assert_eq!(
            error.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert_eq!(block.overlay.authority, original_authority);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn malformed_authenticated_semantic_entry_is_invariant_and_non_mutating() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let operation = PocoApplicationOperationV0::decode_exact(
            &block.test_define_meter_operation_v0().unwrap(),
        )
        .unwrap();
        let change = &operation.semantic_changes[0];
        let kind = PocoSnapshotEntryKindV0::from_u8(change.kind).unwrap();
        let logical_key = exact_hex(&change.logical_key_hex, 1, 128, "test logical key").unwrap();
        block
            .overlay
            .entries
            .insert((kind, logical_key), vec![0xff]);
        let before_entries = block.overlay.entries.clone();

        let error = prepare_semantic_changes(&block.overlay, &operation.semantic_changes, false)
            .expect_err("malformed authenticated semantic state must fail stop");
        assert_eq!(
            error.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_eq!(block.overlay.entries, before_entries);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
    }

    #[test]
    fn required_authority_fact_absence_and_corruption_have_distinct_typed_provenance() {
        let identity = b"missing-operation-authority";
        let kind = PocoSnapshotEntryKindV0::ConsumerKeyAuthorization;
        let authority = PocoApplicationAuthorityStateV0::empty();
        let mut overlay = overlay_with_authority(authority.clone());

        let missing = source_parts_for_identity(&overlay, kind, identity)
            .err()
            .expect("authenticated negative fact must reject the operation");
        assert_eq!(
            missing.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );

        let logical_key = semantic_identity_digest_v0(kind, identity);
        overlay
            .entries
            .insert((kind, logical_key.to_vec()), vec![0xff]);
        let before = overlay.entries.clone();
        let corrupt = source_parts_for_identity(&overlay, kind, identity)
            .err()
            .expect("malformed authenticated authority must fail stop");
        assert_eq!(
            corrupt.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::AuthenticatedOverlay,
            )),
        );
        assert_eq!(overlay.authority, authority);
        assert_eq!(overlay.entries, before);
        assert!(overlay.mutations.is_empty());
    }

    #[test]
    fn nullifier_shape_and_root_rejections_have_distinct_typed_reasons() {
        let authority = PocoApplicationAuthorityStateV0::empty();
        let overlay = overlay_with_authority(authority.clone());
        let family = PocoNullifierFamilyV0::MeterDecision;
        let identifier = [7; 32];
        let key = derive_poco_nullifier_key_v0(family, identifier);
        let raw = |proof: PocoNullifierProofV0| RawNullifierInsertionV0 {
            family: family.code(),
            identifier_hex: hex::encode(identifier),
            proof_hex: hex::encode(proof.canonical_bytes()),
        };

        let wrong_key = raw(PocoNullifierProofV0::new([9; 32], [[0; 32]; 256]));
        let malformed =
            verify_nullifier_absences(&overlay, &[wrong_key], &[(family, identifier)]).unwrap_err();
        assert_eq!(
            malformed.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::NullifierProof,
            )),
        );

        let wrong_root = raw(PocoNullifierProofV0::new(key, [[3; 32]; 256]));
        let invalid_root =
            verify_nullifier_absences(&overlay, &[wrong_root], &[(family, identifier)])
                .unwrap_err();
        assert_eq!(
            invalid_root.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::NullifierNonMembershipRootMismatch,
            )),
        );
        assert_eq!(overlay.authority, authority);
        assert!(overlay.mutations.is_empty());
    }

    #[test]
    fn cutoff_freeze_and_decision_context_binding_fail_closed() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let geometry = EpochGeometryV0::new(Epoch::new(0), &parameters).unwrap();
        let cutoff = geometry.checkpoint_height().get() - parameters.snapshot_lead_blocks();
        assert!(context_at(cutoff).is_ok());
        assert!(context_at(cutoff + 1).is_err());

        let operation = minimal_operation();
        let left = decision_preimage_digest_v0(&context_at(2).unwrap(), &operation).unwrap();
        let mut changed = operation.clone();
        changed.target_height = 3;
        let right = decision_preimage_digest_v0(&context_at(3).unwrap(), &changed).unwrap();
        assert_ne!(left, right);
        let mut changed_signer = context_at(2).unwrap();
        changed_signer.authority_signer_commitment = [10; 32];
        assert_ne!(
            left,
            decision_preimage_digest_v0(&changed_signer, &operation).unwrap()
        );
        assert!(require_derived_decision_id(left, b"prune", &"00".repeat(32)).is_err());
    }

    #[test]
    fn safe_prune_boundary_is_protocol_derived_and_strict() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let policy = meter_policy();
        let protocol_epochs = parameters
            .maturity_epochs()
            .checked_add(parameters.max_certificate_age_epochs())
            .unwrap()
            .max(parameters.evidence_window_epochs());
        let protocol_blocks = protocol_epochs
            .checked_mul(parameters.epoch_length_blocks())
            .unwrap();
        let expected_window = protocol_blocks
            .max(policy.rolling_epoch_span * parameters.epoch_length_blocks())
            .max(policy.retention_blocks);
        let boundary = derive_safe_prune_boundary_v0(10, &parameters, &policy).unwrap();
        assert_eq!(boundary, 10 + expected_window);
        assert!(!prune_target_is_strictly_after_boundary_v0(
            boundary - 1,
            boundary
        ));
        assert!(!prune_target_is_strictly_after_boundary_v0(
            boundary, boundary
        ));
        assert!(prune_target_is_strictly_after_boundary_v0(
            boundary + 1,
            boundary
        ));
        let accepted_height_overflow =
            derive_safe_prune_boundary_v0(u64::MAX, &parameters, &policy).unwrap_err();
        assert_eq!(
            accepted_height_overflow.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::ProtocolCounterExhausted,
            )),
        );
        let mut rolling_overflow = policy;
        rolling_overflow.rolling_epoch_span = u64::MAX;
        let rolling_window_overflow =
            derive_safe_prune_boundary_v0(1, &parameters, &rolling_overflow).unwrap_err();
        assert_eq!(
            rolling_window_overflow.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::ProtocolCounterExhausted,
            )),
        );
    }

    #[test]
    fn tuple_acceptance_binds_certificate_and_exact_authenticated_height() {
        let certificate_id = [3; 32];
        let exact = SemanticFactV0::UniqueConsumptionTuple {
            certificate_id,
            accepted_height: 20,
        };
        assert!(validate_tuple_acceptance_authority_v0(&exact, certificate_id, 20).is_ok());
        assert!(validate_tuple_acceptance_authority_v0(&exact, [4; 32], 20).is_err());
        assert!(validate_tuple_acceptance_authority_v0(&exact, certificate_id, 19).is_err());
        assert!(validate_tuple_acceptance_authority_v0(&exact, certificate_id, 21).is_err());
    }

    #[test]
    fn retained_certificate_relationship_must_cover_billing_and_acceptance() {
        let relationship = SemanticFactV0::RelationshipClassification {
            class: RelationshipClassV0::Independent,
            expires_at: 20,
        };
        assert!(relationship_authorizes_retained_certificate_v0(
            &relationship,
            RelationshipClassV0::Independent as u8,
            18,
            19,
        ));
        assert!(!relationship_authorizes_retained_certificate_v0(
            &relationship,
            RelationshipClassV0::Independent as u8,
            18,
            20,
        ));
        assert!(!relationship_authorizes_retained_certificate_v0(
            &relationship,
            RelationshipClassV0::Independent as u8,
            20,
            19,
        ));
        assert!(!relationship_authorizes_retained_certificate_v0(
            &relationship,
            RelationshipClassV0::Related as u8,
            18,
            19,
        ));
    }

    #[test]
    fn scoped_usage_and_reserved_units_are_exact_bounded_and_checked() {
        assert_eq!(checked_usage_after_v0(40, 60, 100, "scope").unwrap(), 100);
        let over_cap = checked_usage_after_v0(40, 61, 100, "scope").unwrap_err();
        assert_eq!(
            over_cap.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
            )),
        );
        let overflow = checked_usage_after_v0(u128::MAX, 1, u128::MAX, "scope").unwrap_err();
        assert_eq!(
            overflow.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::ProtocolCounterExhausted,
            )),
        );
        // A second meter contributes to the same scope instead of resetting it.
        let after_meter_a = checked_usage_after_v0(0, 40, 100, "scope").unwrap();
        assert_eq!(
            checked_usage_after_v0(after_meter_a, 60, 100, "scope").unwrap(),
            100
        );
        assert!(checked_usage_after_v0(after_meter_a, 61, 100, "scope").is_err());
        assert!(validate_reserved_units_exact_v0(10, 10).is_ok());
        assert!(validate_reserved_units_exact_v0(9, 10).is_err());
        assert!(validate_reserved_units_exact_v0(11, 10).is_err());
        assert!(validate_reserved_units_exact_v0(0, 0).is_err());
    }

    #[test]
    fn usage_bucket_total_cap_is_exact_checked_and_non_mutating() {
        assert_eq!(
            validate_usage_bucket_admission_v0(MAX_TOTAL_USAGE_BUCKETS - 1, 1).unwrap(),
            MAX_TOTAL_USAGE_BUCKETS
        );
        assert_eq!(
            validate_usage_bucket_admission_v0(MAX_TOTAL_USAGE_BUCKETS, 0).unwrap(),
            MAX_TOTAL_USAGE_BUCKETS
        );
        let authority = PocoApplicationAuthorityStateV0::empty();
        let before = authority.clone();
        let over_cap = validate_usage_bucket_admission_v0(MAX_TOTAL_USAGE_BUCKETS, 1).unwrap_err();
        assert_eq!(
            over_cap.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
            )),
        );
        let overflow = validate_usage_bucket_admission_v0(usize::MAX, 1).unwrap_err();
        assert_eq!(
            overflow.downcast_ref::<PocoApplicationApplyFailureV0>(),
            Some(&PocoApplicationApplyFailureV0::Invariant(
                PocoApplicationInvariantV0::ProtocolCounterExhausted,
            )),
        );
        assert_eq!(authority, before);
    }

    #[test]
    fn authority_capacity_worst_case_fits_payload_and_overflow_is_non_mutating() {
        let authority = max_capacity_authority_state();
        assert_eq!(total_nonce_watermarks_v0(&authority).unwrap(), 8);
        assert_eq!(usage_bucket_count_v0(&authority).unwrap(), 32);
        assert_eq!(authority_record_count_v0(&authority).unwrap(), 66);
        let encoded = authority.encode_exact().unwrap();
        assert!(encoded.len() <= MAX_POCO_SEMANTIC_PAYLOAD_BYTES);

        let before = authority.clone();
        let mut over_nonce = authority.clone();
        over_nonce
            .consumer_keys
            .last_mut()
            .unwrap()
            .nonce_watermarks
            .push(ConsumerNonceWatermarkV0 {
                provider_id_hex: max_opaque_hex(65_000),
                max_accepted_nonce: u64::MAX,
                logical_key_hex: tagged_hash_hex(65_000),
            });
        assert!(over_nonce.validate().is_err());

        let mut over_family = authority.clone();
        let mut extra_consumer = over_family.consumer_keys.last().unwrap().clone();
        extra_consumer.consumer_id_hex = max_opaque_hex(65_001);
        extra_consumer.consumer_key_id_hex = max_opaque_hex(65_002);
        extra_consumer.nonce_watermarks.clear();
        over_family.consumer_keys.push(extra_consumer);
        assert!(over_family.validate().is_err());
        assert_eq!(authority, before);
    }

    #[test]
    fn operation_capacity_preflight_accepts_exact_and_rejects_over_without_mutation() {
        let (context, _, _, operation) = sequence_vector_fixture("release_refund_replay");
        let mut exact_authority = max_capacity_authority_state();
        exact_authority.funded_unused_reservations.pop();
        exact_authority.validate().unwrap();
        assert_eq!(authority_record_count_v0(&exact_authority).unwrap(), 65);
        let exact_overlay = overlay_with_authority(exact_authority.clone());
        assert!(validate_capacity_test_v0(&context, &exact_overlay, &operation).is_ok());
        assert_eq!(exact_overlay.authority, exact_authority);

        let over_authority = max_capacity_authority_state();
        let over_overlay = overlay_with_authority(over_authority.clone());
        assert!(validate_capacity_test_v0(&context, &over_overlay, &operation).is_err());
        assert_eq!(over_overlay.authority, over_authority);
    }

    #[test]
    fn capacity_preflight_preserves_challenge_and_governance_first_errors() {
        let authority = PocoApplicationAuthorityStateV0::empty();
        let overlay = overlay_with_authority(authority.clone());
        let mut operation = minimal_operation();
        operation.body = PocoApplicationOperationBodyV0::ResolveChallenge {
            certificate_id_hex: "11".repeat(32),
            challenge_id_hex: "22".repeat(32),
            resolution: ChallengeResolutionV0::Rejected,
            resolution_decision_id_hex: "33".repeat(32),
        };
        let error = validate_capacity_test_v0(&context_at(2).unwrap(), &overlay, &operation)
            .expect_err("missing challenge must fail before clone");
        assert_eq!(format!("{error:#}"), "challenge is not pending");
        assert_eq!(overlay.authority, authority);

        operation.body = PocoApplicationOperationBodyV0::ApproveGovernance {
            target_epoch: 1,
            parameters_hash_hex: "44".repeat(32),
            activation_height: 3,
            decision_id_hex: "55".repeat(32),
        };
        let error = validate_capacity_test_v0(&context_at(2).unwrap(), &overlay, &operation)
            .expect_err("missing governance proposal must fail before clone");
        assert_eq!(
            format!("{error:#}"),
            "governance approval lacks authenticated proposal"
        );
        assert_eq!(overlay.authority, authority);
    }

    #[test]
    fn capacity_preflight_rejects_reused_validator_key_before_noop_clone() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/protocol/poco-bft-v0/vectors/poco-snapshot-transition-v0.json"
        ))
        .unwrap();
        let registration = vector["semantic_layout_corpus"]["positive_fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["kind"].as_u64() == Some(9))
            .unwrap();
        let logical_key_hex = registration["logical_key_hex"]
            .as_str()
            .unwrap()
            .to_string();
        let next_value_hex = registration["value_cev0_hex"].as_str().unwrap().to_string();
        let logical_key = hex::decode(&logical_key_hex).unwrap();
        let next_value = hex::decode(&next_value_hex).unwrap();
        let consensus_key = match owned_semantic_parts(
            PocoSnapshotEntryKindV0::ValidatorRegistration,
            &logical_key,
            &next_value,
        )
        .unwrap()
        .fact
        {
            SemanticFactV0::ValidatorRegistration { consensus_key, .. } => consensus_key,
            _ => unreachable!("kind-9 vector must decode as validator registration"),
        };

        let mut authority = PocoApplicationAuthorityStateV0::empty();
        let mut history = max_validator_history(7_000);
        history.consensus_key_hex = hex::encode(consensus_key);
        authority.validator_registration_history.push(history);
        let overlay = overlay_with_authority(authority.clone());
        let mut operation = minimal_operation();
        operation.body = PocoApplicationOperationBodyV0::RotateValidator {
            validator_id_hex: hex::encode(b"validator-a"),
            target_epoch: 0,
            previous_history_head_hex: "11".repeat(32),
            previous_registration_nonce: 1,
            registration_decision_id_hex: "22".repeat(32),
        };
        operation.semantic_changes = vec![RawSemanticChangeV0 {
            kind: PocoSnapshotEntryKindV0::ValidatorRegistration as u8,
            logical_key_hex,
            next_value_hex: Some(next_value_hex),
        }];
        let error = validate_capacity_test_v0(&context_at(2).unwrap(), &overlay, &operation)
            .expect_err("reused validator key must fail before clone");
        assert_eq!(
            format!("{error:#}"),
            "validator consensus key is already active in registration history"
        );
        assert_eq!(overlay.authority, authority);
    }

    #[test]
    fn active_certificate_blocks_validator_rotate_and_revoke_without_mutation() {
        let authority = max_capacity_authority_state();
        let provider = authority.active_certificates[0].provider_id_hex.clone();
        let before = authority.clone();
        assert!(
            ensure_validator_has_no_active_certificate_references_v0(&authority, &provider)
                .is_err()
        );
        assert!(ensure_validator_has_no_active_certificate_references_v0(
            &authority,
            &max_opaque_hex(65_020),
        )
        .is_ok());
        assert_eq!(authority, before);
    }

    #[test]
    fn seal_rejects_authority_target_substitution_via_production_validator() {
        let projection = genesis_projection();
        let mut block =
            PocoApplicationBlockOverlayV0::from_projection(context_at(2).unwrap(), &projection)
                .unwrap();
        let raw = block.test_define_meter_operation_v0().unwrap();
        block.apply_raw(&raw).unwrap();
        block.overlay.authority.meter_policies[0].unit_scale = CanonicalU128V0::new(2);
        assert!(block.seal().is_err());
    }

    #[test]
    fn settlement_release_and_funding_subjects_close_resurrection() {
        let certificate_id = [3; 32];
        let decision_id = [4; 32];
        assert_eq!(
            fund_certificate_absence_subjects_v0(certificate_id),
            [(PocoNullifierFamilyV0::Certificate, certificate_id)]
        );
        assert_eq!(
            release_nullifier_subjects_v0(certificate_id, decision_id),
            [
                (PocoNullifierFamilyV0::Certificate, certificate_id),
                (PocoNullifierFamilyV0::SettlementDecision, decision_id),
            ]
        );
        let subjects = release_nullifier_subjects_v0(certificate_id, decision_id);
        assert!(subjects[0].0.code() < subjects[1].0.code());
    }

    #[test]
    fn lifecycle_and_business_height_companions_are_exact_and_monotonic() {
        let acceptance = "11".repeat(32);
        let resolution = "22".repeat(32);
        assert!(validate_certificate_lifecycle_authority_v0(
            CertificateAuthorityLifecycleV0::Accepted,
            7,
            &acceptance,
            7,
            &acceptance,
        )
        .is_ok());
        assert!(validate_certificate_lifecycle_authority_v0(
            CertificateAuthorityLifecycleV0::Accepted,
            8,
            &acceptance,
            7,
            &acceptance,
        )
        .is_err());
        assert!(validate_certificate_lifecycle_authority_v0(
            CertificateAuthorityLifecycleV0::ChallengeSustained,
            8,
            &resolution,
            7,
            &acceptance,
        )
        .is_ok());
        assert!(validate_certificate_lifecycle_authority_v0(
            CertificateAuthorityLifecycleV0::ChallengeRejected,
            7,
            &resolution,
            7,
            &acceptance,
        )
        .is_err());
        assert!(validate_recorded_business_height_v0(1, 1, "test").is_ok());
        assert!(validate_recorded_business_height_v0(0, 1, "test").is_err());
        assert!(validate_recorded_business_height_v0(2, 1, "test").is_err());
    }

    #[test]
    fn validator_history_is_bounded_and_exactly_companioned() {
        let mut authority = PocoApplicationAuthorityStateV0::empty();
        authority.revision = 2;
        authority.last_target_height = 1;
        let validator_id = vec![1];
        let previous_head = [2; 32];
        let consensus_key = [3; 32];
        let proof_digest = [4; 32];
        let decision_id = [5; 32];
        let history_head = registration_history_head_v0(
            previous_head,
            &validator_id,
            consensus_key,
            1,
            proof_digest,
            decision_id,
            1,
        );
        authority
            .validator_registration_history
            .push(ValidatorRegistrationHistoryV0 {
                validator_id_hex: hex::encode(validator_id),
                history_head_hex: hex::encode(history_head),
                max_registration_nonce: 1,
                consensus_key_hex: hex::encode(consensus_key),
                current_proof_digest_hex: hex::encode(proof_digest),
                previous_history_head_hex: hex::encode(previous_head),
                registration_decision_id_hex: hex::encode(decision_id),
                registration_height: 1,
                retired_key_count: u64::MAX,
                revoked_at_height: None,
                revocation_decision_id_hex: None,
            });
        authority.validate().unwrap();
        let encoded = authority.encode_exact().unwrap();
        let json = std::str::from_utf8(&encoded).unwrap();
        assert!(json.contains("\"retired_key_count\""));
        assert!(!json.contains("retired_consensus_key_hexes"));
        let mut substituted = authority.clone();
        substituted.validator_registration_history[0].current_proof_digest_hex = "00".to_string();
        assert!(substituted.validate().is_err());
        let mut future = authority;
        future.validator_registration_history[0].registration_height = 2;
        assert!(future.validate().is_err());
    }

    #[test]
    fn finalized_governance_retains_exact_proposal_provenance() {
        let mut authority = PocoApplicationAuthorityStateV0::empty();
        authority.revision = 2;
        authority.last_target_height = 2;
        authority
            .finalized_governance_approvals
            .push(FinalizedGovernanceApprovalV0 {
                target_epoch: 1,
                phase: 0,
                proposal_decision_id_hex: "11".repeat(32),
                proposed_height: 1,
                decision_id_hex: "22".repeat(32),
                approval_height: 2,
                parameters_hash_hex: "33".repeat(32),
                activation_height: 3,
            });
        authority.validate().unwrap();
        let encoded = authority.encode_exact().unwrap();
        let json = std::str::from_utf8(&encoded).unwrap();
        assert!(
            json.find("\"proposal_decision_id_hex\"").unwrap()
                < json.find("\"proposed_height\"").unwrap()
        );
        assert!(
            json.find("\"proposed_height\"").unwrap() < json.find("\"decision_id_hex\"").unwrap()
        );
        let mut non_monotonic = authority;
        non_monotonic.finalized_governance_approvals[0].proposed_height = 2;
        assert!(non_monotonic.validate().is_err());
    }

    #[test]
    fn target_projection_bounds_reject_before_value_clone() {
        let mut oversized = BTreeMap::new();
        oversized.insert(
            (PocoSnapshotEntryKindV0::ApplicationAuthorityState, vec![1]),
            vec![0; MAX_POCO_SNAPSHOT_BUNDLE_BYTES],
        );
        assert!(validate_overlay_projection_bounds_before_clone_v0(&oversized).is_err());

        let mut too_many = BTreeMap::new();
        for index in 0..=MAX_POCO_SNAPSHOT_ENTRIES {
            too_many.insert(
                (
                    PocoSnapshotEntryKindV0::ApplicationAuthorityState,
                    (index as u64).to_be_bytes().to_vec(),
                ),
                Vec::new(),
            );
        }
        assert!(validate_overlay_projection_bounds_before_clone_v0(&too_many).is_err());
    }

    #[test]
    fn expired_usage_compacts_without_refunding_current_epoch() {
        let mut authority = PocoApplicationAuthorityStateV0::empty();
        authority.revision = 2;
        authority.last_target_height = 1;
        authority.meter_policies.push(meter_policy());
        authority.meter_usage = vec![
            MeterRollingUsageV0 {
                meter_id_hex: "01".to_string(),
                meter_version: 1,
                window_epoch: 0,
                consumed_units: CanonicalU128V0::new(50),
            },
            MeterRollingUsageV0 {
                meter_id_hex: "01".to_string(),
                meter_version: 1,
                window_epoch: 1,
                consumed_units: CanonicalU128V0::new(60),
            },
        ];
        authority.consumer_provider_usage = vec![
            ConsumerProviderRollingUsageV0 {
                consumer_id_hex: "01".to_string(),
                provider_id_hex: "02".to_string(),
                window_epoch: 0,
                consumed_units: CanonicalU128V0::new(50),
            },
            ConsumerProviderRollingUsageV0 {
                consumer_id_hex: "01".to_string(),
                provider_id_hex: "02".to_string(),
                window_epoch: 1,
                consumed_units: CanonicalU128V0::new(60),
            },
        ];
        let mut context = context_at(2).unwrap();
        context.active_epoch = Epoch::new(1);
        compact_expired_usage_v0(&mut authority, &context).unwrap();
        assert_eq!(authority.meter_usage.len(), 1);
        assert_eq!(authority.meter_usage[0].window_epoch, 1);
        assert_eq!(authority.meter_usage[0].consumed_units.get().unwrap(), 60);
        assert_eq!(authority.consumer_provider_usage.len(), 1);
        assert_eq!(
            authority.consumer_provider_usage[0]
                .consumed_units
                .get()
                .unwrap(),
            60
        );
    }
}
