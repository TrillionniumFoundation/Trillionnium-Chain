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
        validate_operation_capacity_before_clone_v0(&self.context, &self.overlay, operation)
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
        let operation_id = domain_hash(APPLICATION_OPERATION_DOMAIN, raw);
        if self.overlay.operation_ids.contains(&operation_id) {
            return Err(DeterministicallyInvalid(Invalid::DuplicateOperation));
        }

        // Bounds and exact decoded-value/raw-byte binding above precede this
        // potentially large clone.
        let mut candidate = self.overlay.clone();
        candidate.operation_ids.insert(operation_id);
        apply_operation_v0(&self.context, &mut candidate, operation).map_err(|error| {
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

fn validate_validator_consensus_key_before_clone_v0(
    authority: &PocoApplicationAuthorityStateV0,
    operation: &PocoApplicationOperationV0,
) -> Result<()> {
    let [change] = operation.semantic_changes.as_slice() else {
        return Ok(());
    };
    if change.kind != PocoSnapshotEntryKindV0::ValidatorRegistration as u8 {
        return Ok(());
    }
    let Some(next_value_hex) = change.next_value_hex.as_deref() else {
        return Ok(());
    };
    let logical_key = exact_hex(
        &change.logical_key_hex,
        1,
        128,
        "validator semantic logical key",
    )?;
    let next_value = exact_hex(next_value_hex, 1, 65_536, "validator next semantic value")?;
    let parts = owned_semantic_parts(
        PocoSnapshotEntryKindV0::ValidatorRegistration,
        &logical_key,
        &next_value,
    )?;
    if let SemanticFactV0::ValidatorRegistration { consensus_key, .. } = parts.fact {
        let consensus_key_hex = hex::encode(consensus_key);
        ensure!(
            authority
                .validator_registration_history
                .iter()
                .all(|history| {
                    history.consensus_key_hex.as_str() != consensus_key_hex.as_str()
                }),
            "validator consensus key is already active in registration history"
        );
    }
    Ok(())
}

fn validate_operation_capacity_before_clone_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
) -> Result<()> {
    let authority = &overlay.authority;
    let mut delta = OperationRecordDeltaV0::default();
    match &operation.body {
        PocoApplicationOperationBodyV0::AuthorizeConsumerKey { .. } => {
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
            delta.consumer_keys_removed = 1;
            delta.nonce_watermarks_removed = authority.consumer_keys[index].nonce_watermarks.len();
        }
        PocoApplicationOperationBodyV0::DefineMeterPolicy { .. } => {
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
                })?;
            delta.meter_policies_removed = 1;
        }
        PocoApplicationOperationBodyV0::FundSettlement { .. } => {
            delta.reservations_added = 1;
        }
        PocoApplicationOperationBodyV0::AcceptCertificate {
            certificate_id_hex, ..
        } => {
            authority
                .funded_unused_reservations
                .binary_search_by(|reservation| {
                    reservation
                        .certificate_id_hex
                        .as_str()
                        .cmp(certificate_id_hex.as_str())
                })
                .map_err(|_| anyhow::anyhow!("certificate acceptance lacks funded reservation"))?;
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
            delta.reservations_removed = 1;
        }
        PocoApplicationOperationBodyV0::OpenChallenge {
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
            authority
                .active_certificates
                .binary_search_by(|certificate| {
                    certificate
                        .certificate_id_hex
                        .as_str()
                        .cmp(certificate_id_hex.as_str())
                })
                .map_err(|_| {
                    deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
                    )
                })?;
            if authority.pending_challenges.iter().any(|challenge| {
                challenge.challenge_id_hex == *challenge_id_hex
                    || challenge.certificate_id_hex == *certificate_id_hex
            }) {
                return Err(deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
                ));
            }
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
            delta.pending_challenges_removed = 1;
        }
        PocoApplicationOperationBodyV0::ProposeGovernance { .. } => {
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
            authority
                .pending_governance_proposals
                .binary_search_by_key(target_epoch, |proposal| proposal.target_epoch)
                .map_err(|_| {
                    deterministic_application_error_v0(
                        PocoApplicationDeterministicInvalidV0::GovernanceApprovalMissing,
                    )
                })?;
            if authority
                .finalized_governance_approvals
                .binary_search_by_key(target_epoch, |approval| approval.target_epoch)
                .is_ok()
            {
                return Err(deterministic_application_error_v0(
                    PocoApplicationDeterministicInvalidV0::GovernanceRule,
                ));
            }
            delta.pending_governance_removed = 1;
            delta.finalized_governance_added = 1;
        }
        PocoApplicationOperationBodyV0::RegisterValidator { .. } => {
            validate_validator_consensus_key_before_clone_v0(authority, operation)?;
            delta.validator_histories_added = 1;
        }
        PocoApplicationOperationBodyV0::RegisterFutureCandidate {
            validator_id_hex,
            target_epoch,
            ..
        } => {
            exact_opaque_hex(validator_id_hex)?;
            ensure!(
                authority
                    .future_candidate_registrations
                    .binary_search_by(|item| {
                        (item.target_epoch, item.validator_id_hex.as_str())
                            .cmp(&(*target_epoch, validator_id_hex.as_str()))
                    })
                    .is_err(),
                "future candidate is already registered for the target epoch"
            );
            delta.future_candidates_added = 1;
        }
        PocoApplicationOperationBodyV0::PruneRevokedValidatorHistory { .. } => {
            delta.validator_histories_removed = 1;
        }
        PocoApplicationOperationBodyV0::PruneExpiredCertificate { .. } => {
            delta.active_certificates_removed = 1;
        }
        PocoApplicationOperationBodyV0::RotateValidator { .. } => {
            validate_validator_consensus_key_before_clone_v0(authority, operation)?;
        }
        PocoApplicationOperationBodyV0::RevokeConsumerKey { .. }
        | PocoApplicationOperationBodyV0::RetireMeterPolicy { .. }
        | PocoApplicationOperationBodyV0::RevokeValidator { .. } => {}
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
    Ok(())
}

fn accept_capacity_additions_before_clone_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
) -> Result<(usize, usize)> {
    let mut certificate_changes = operation
        .semantic_changes
        .iter()
        .filter(|change| change.kind == PocoSnapshotEntryKindV0::ConsumptionCertificate as u8);
    let certificate_change = certificate_changes
        .next()
        .context("certificate acceptance lacks certificate semantic change")?;
    ensure!(
        certificate_changes.next().is_none(),
        "certificate acceptance has duplicate certificate semantic changes"
    );
    let logical_key = exact_hash32_hex(&certificate_change.logical_key_hex)?;
    let next_value = exact_hex(
        certificate_change
            .next_value_hex
            .as_deref()
            .context("certificate acceptance deletes certificate semantic entry")?,
        1,
        MAX_POCO_SEMANTIC_PAYLOAD_BYTES,
        "certificate semantic value",
    )?;
    let parts = decode_poco_snapshot_value_parts_v0_exact(
        PocoSnapshotEntryKindV0::ConsumptionCertificate,
        &logical_key,
        &next_value,
    )?;
    let certificate = decode_consumption_certificate_v0_exact(parts.payload)
        .map_err(|error| anyhow::anyhow!("decode capacity certificate: {error:?}"))?;
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
        .map_err(|_| anyhow::anyhow!("capacity certificate lacks consumer-key authority"))?;
    let key_authority = &overlay.authority.consumer_keys[key_index];
    let new_nonce_watermark = usize::from(
        key_authority
            .nonce_watermarks
            .binary_search_by(|watermark| watermark.provider_id_hex.cmp(&provider_id_hex))
            .is_err(),
    );
    ensure!(
        key_authority
            .nonce_watermarks
            .len()
            .checked_add(new_nonce_watermark)
            .is_some_and(|count| count <= MAX_NONCE_WATERMARKS_PER_KEY),
        "consumer key nonce watermark count exceeds per-key bound"
    );

    let meter_id_hex = hex::encode(body.meter_id());
    let policy_index = overlay
        .authority
        .meter_policies
        .binary_search_by(|policy| {
            (policy.meter_id_hex.as_str(), policy.meter_version)
                .cmp(&(meter_id_hex.as_str(), body.meter_version()))
        })
        .map_err(|_| anyhow::anyhow!("capacity certificate lacks meter policy"))?;
    let policy = &overlay.authority.meter_policies[policy_index];
    let meter_window = context
        .active_epoch
        .get()
        .checked_div(policy.rolling_epoch_span)
        .context("capacity meter rolling span is zero")?;
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

fn apply_operation_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
) -> Result<()> {
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
    let decision_preimage = decision_preimage_digest_v0(context, operation).map_err(|_| {
        invariant_application_error_v0(PocoApplicationInvariantV0::OperationReencode)
    })?;
    match &operation.body {
        PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
            public_key_hex,
            active_from_height,
            decision_id_hex,
        } => apply_authorize_consumer_key_v0(
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
        }),
        PocoApplicationOperationBodyV0::RevokeConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
            public_key_hex,
            active_from_height,
            revoked_at_height,
            decision_id_hex,
        } => apply_revoke_consumer_key_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            consumer_id_hex,
            consumer_key_id_hex,
            public_key_hex,
            *active_from_height,
            *revoked_at_height,
            decision_id_hex,
        )
        .map_err(|error| {
            preserve_application_failure_or_deterministic_v0(
                error,
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
            )
        }),
        PocoApplicationOperationBodyV0::PruneRevokedConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
        } => apply_prune_revoked_consumer_key_v0(
            context,
            overlay,
            operation,
            consumer_id_hex,
            consumer_key_id_hex,
        ),
        PocoApplicationOperationBodyV0::DefineMeterPolicy {
            policy,
            decision_id_hex,
        } => apply_define_meter_v0(
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
        }),
        PocoApplicationOperationBodyV0::RetireMeterPolicy {
            meter_id_hex,
            meter_version,
            retired_at_height,
            decision_id_hex,
        } => apply_retire_meter_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            meter_id_hex,
            *meter_version,
            *retired_at_height,
            decision_id_hex,
        ),
        PocoApplicationOperationBodyV0::PruneRetiredMeter {
            meter_id_hex,
            meter_version,
        } => {
            apply_prune_retired_meter_v0(context, overlay, operation, meter_id_hex, *meter_version)
        }
        PocoApplicationOperationBodyV0::FundSettlement {
            certificate_id_hex,
            settlement_commitment_hex,
            reserved_units,
            funding_decision_id_hex,
        } => apply_fund_settlement_v0(
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
        }),
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
        PocoApplicationOperationBodyV0::ReleaseSettlement {
            certificate_id_hex,
            release_decision_id_hex,
        } => apply_release_settlement_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            certificate_id_hex,
            release_decision_id_hex,
        ),
        PocoApplicationOperationBodyV0::OpenChallenge {
            certificate_id_hex,
            challenge_id_hex,
            opening_decision_id_hex,
        } => apply_open_challenge_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            certificate_id_hex,
            challenge_id_hex,
            opening_decision_id_hex,
        ),
        PocoApplicationOperationBodyV0::ResolveChallenge {
            certificate_id_hex,
            challenge_id_hex,
            resolution,
            resolution_decision_id_hex,
        } => apply_resolve_challenge_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            certificate_id_hex,
            challenge_id_hex,
            *resolution,
            resolution_decision_id_hex,
        ),
        PocoApplicationOperationBodyV0::ProposeGovernance {
            target_epoch,
            phase,
            parameters_hash_hex,
            activation_height,
            proposal_decision_id_hex,
        } => apply_propose_governance_v0(
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
        }),
        PocoApplicationOperationBodyV0::ApproveGovernance {
            target_epoch,
            parameters_hash_hex,
            activation_height,
            decision_id_hex,
        } => apply_approve_governance_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            *target_epoch,
            parameters_hash_hex,
            *activation_height,
            decision_id_hex,
        ),
        PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex,
            target_epoch,
            registration_decision_id_hex,
        } => apply_register_validator_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            validator_id_hex,
            *target_epoch,
            registration_decision_id_hex,
            false,
            None,
            None,
        ),
        PocoApplicationOperationBodyV0::RotateValidator {
            validator_id_hex,
            target_epoch,
            previous_history_head_hex,
            previous_registration_nonce,
            registration_decision_id_hex,
        } => apply_register_validator_v0(
            context,
            overlay,
            operation,
            decision_preimage,
            validator_id_hex,
            *target_epoch,
            registration_decision_id_hex,
            true,
            Some(previous_history_head_hex),
            Some(*previous_registration_nonce),
        ),
        PocoApplicationOperationBodyV0::RegisterFutureCandidate {
            validator_id_hex,
            target_epoch,
            previous_registration_nonce,
            predecessor_history_head_hex,
            proof_cev0_hex,
            registration_decision_id_hex,
        } => apply_register_future_candidate_v0(
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
        ),
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
fn apply_authorize_consumer_key_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    consumer_id_hex: &str,
    consumer_key_id_hex: &str,
    public_key_hex: &str,
    active_from_height: u64,
    decision_id_hex: &str,
) -> Result<()> {
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
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[
            (PocoNullifierFamilyV0::ConsumerKeyDecision, decision),
            (
                PocoNullifierFamilyV0::ConsumerKeyIdentity,
                semantic_identity_digest_v0(
                    PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
                    &identity,
                ),
            ),
        ],
    )?;
    overlay
        .authority
        .consumer_keys
        .push(ConsumerKeyAuthorityV0 {
            consumer_id_hex: consumer_id_hex.to_string(),
            consumer_key_id_hex: consumer_key_id_hex.to_string(),
            public_key_hex: public_key_hex.to_string(),
            active_from_height,
            authorization_decision_id_hex: decision_id_hex.to_string(),
            revoked_at_height: None,
            revocation_decision_id_hex: None,
            nonce_watermarks: Vec::new(),
        });
    overlay.authority.consumer_keys.sort_by(|left, right| {
        (&left.consumer_id_hex, &left.consumer_key_id_hex)
            .cmp(&(&right.consumer_id_hex, &right.consumer_key_id_hex))
    });
    apply_prepared_changes(overlay, changes, false)
}

#[allow(clippy::too_many_arguments)]
fn apply_revoke_consumer_key_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    consumer_id_hex: &str,
    consumer_key_id_hex: &str,
    public_key_hex: &str,
    active_from_height: u64,
    revoked_at_height: u64,
    decision_id_hex: &str,
) -> Result<()> {
    ensure!(
        revoked_at_height == context.target_height.get(),
        "consumer-key revocation height is not the authenticated target height"
    );
    let consumer_id = exact_opaque_hex(consumer_id_hex)?;
    let consumer_key_id = exact_opaque_hex(consumer_key_id_hex)?;
    let public_key = exact_hash32_hex(public_key_hex)?;
    ensure!(public_key != [0; 32], "zero consumer public key");
    let identity = joined_identity(&[&consumer_id, &consumer_key_id]);
    let decision = require_derived_decision_id(preimage, b"revoke-consumer-key", decision_id_hex)?;
    let authority_index = overlay
        .authority
        .consumer_keys
        .binary_search_by(|item| {
            (
                item.consumer_id_hex.as_str(),
                item.consumer_key_id_hex.as_str(),
            )
                .cmp(&(consumer_id_hex, consumer_key_id_hex))
        })
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    let key_authority = &overlay.authority.consumer_keys[authority_index];
    ensure!(
        key_authority.public_key_hex == public_key_hex
            && key_authority.active_from_height == active_from_height
            && key_authority.revoked_at_height.is_none(),
        "consumer-key revocation authority is substituted or terminal"
    );
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(
        &changes,
        &[PocoSnapshotEntryKindV0::ConsumerKeyAuthorization],
    )?;
    let change = &changes[0];
    ensure!(
        change.expected_value.is_some()
            && change.expected_identity.as_deref() == Some(identity.as_slice())
            && change.next_identity.as_deref() == Some(identity.as_slice()),
        "consumer-key revocation is not an exact update"
    );
    match (change.expected_fact.as_ref(), change.next_fact.as_ref()) {
        (
            Some(SemanticFactV0::ConsumerKeyAuthorization {
                public_key: old_key,
                active_from: old_active,
                revoked_at: None,
            }),
            Some(SemanticFactV0::ConsumerKeyAuthorization {
                public_key: new_key,
                active_from: new_active,
                revoked_at: Some(revoked_at),
            }),
        ) => ensure!(
            *old_key == public_key
                && *new_key == public_key
                && *old_active == active_from_height
                && *new_active == active_from_height
                && *revoked_at == context.target_height.get(),
            "consumer-key revocation semantic value mismatch"
        ),
        _ => bail!("consumer-key revocation is terminal or has wrong semantic state"),
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[(PocoNullifierFamilyV0::ConsumerKeyDecision, decision)],
    )?;
    overlay.authority.consumer_keys[authority_index].revoked_at_height =
        Some(context.target_height.get());
    overlay.authority.consumer_keys[authority_index].revocation_decision_id_hex =
        Some(decision_id_hex.to_string());
    apply_prepared_changes(overlay, changes, false)
}

fn apply_prune_revoked_consumer_key_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    consumer_id_hex: &str,
    consumer_key_id_hex: &str,
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
    let consumer_id = exact_opaque_hex(consumer_id_hex).map_err(|_| signed_semantic())?;
    let consumer_key_id = exact_opaque_hex(consumer_key_id_hex).map_err(|_| signed_semantic())?;
    let authority_index = overlay
        .authority
        .consumer_keys
        .binary_search_by(|item| {
            (
                item.consumer_id_hex.as_str(),
                item.consumer_key_id_hex.as_str(),
            )
                .cmp(&(consumer_id_hex, consumer_key_id_hex))
        })
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    let key_authority = overlay.authority.consumer_keys[authority_index].clone();
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
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, true)?;
    if !changes.iter().all(|change| change.next_value.is_none()) {
        return Err(signed_semantic());
    }
    let mut expected_keys = BTreeSet::new();
    let key_identity = joined_identity(&[&consumer_id, &consumer_key_id]);
    expected_keys.insert((
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
        semantic_identity_digest_v0(
            PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
            &key_identity,
        )
        .to_vec(),
    ));
    for watermark in &key_authority.nonce_watermarks {
        expected_keys.insert((
            PocoSnapshotEntryKindV0::ConsumerNonce,
            exact_hash32_hex(&watermark.logical_key_hex)
                .map_err(|_| authenticated_overlay())?
                .to_vec(),
        ));
    }
    let actual_keys = changes
        .iter()
        .map(|change| (change.kind, change.logical_key.clone()))
        .collect::<BTreeSet<_>>();
    if actual_keys != expected_keys || actual_keys.len() != changes.len() {
        return Err(signed_semantic());
    }
    let nonce_summary = consumer_nonce_summary_digest_v0(&key_authority.nonce_watermarks)
        .map_err(|_| authenticated_overlay())?;
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[(PocoNullifierFamilyV0::ConsumerNonceSummary, nonce_summary)],
    )?;
    overlay.authority.consumer_keys.remove(authority_index);
    apply_prepared_changes(overlay, changes, true)
}

fn apply_define_meter_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    policy: &MeterAuthorityPolicyV0,
    decision_id_hex: &str,
) -> Result<()> {
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
    ensure!(
        change.next_identity.as_deref()
            == Some(meter_identity(&meter_id, policy.meter_version).as_slice()),
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
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[
            (PocoNullifierFamilyV0::MeterDecision, decision),
            (
                PocoNullifierFamilyV0::MeterIdentity,
                semantic_identity_digest_v0(
                    PocoSnapshotEntryKindV0::MeterDefinition,
                    &meter_identity(&meter_id, policy.meter_version),
                ),
            ),
        ],
    )?;
    overlay.authority.meter_policies.push(policy.clone());
    overlay.authority.meter_policies.sort_by(|left, right| {
        (&left.meter_id_hex, left.meter_version).cmp(&(&right.meter_id_hex, right.meter_version))
    });
    apply_prepared_changes(overlay, changes, false)
}

#[allow(clippy::too_many_arguments)]
fn apply_retire_meter_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    meter_id_hex: &str,
    meter_version: u32,
    retired_at_height: u64,
    decision_id_hex: &str,
) -> Result<()> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    let meter_id = exact_opaque_hex(meter_id_hex).map_err(|_| signed_semantic())?;
    if retired_at_height != context.target_height.get() {
        return Err(signed_semantic());
    }
    let decision = require_derived_decision_id(preimage, b"retire-meter", decision_id_hex)?;
    let index = overlay
        .authority
        .meter_policies
        .binary_search_by(|item| {
            (item.meter_id_hex.as_str(), item.meter_version).cmp(&(meter_id_hex, meter_version))
        })
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    let authority_policy = &overlay.authority.meter_policies[index];
    if authority_policy.retired_at_height.is_some() {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::MeterDefinition])?;
    let change = &changes[0];
    if change.next_identity.as_deref() != Some(meter_identity(&meter_id, meter_version).as_slice())
    {
        return Err(signed_semantic());
    }
    let (old_scale, old_active) = match change.expected_fact.as_ref() {
        Some(SemanticFactV0::MeterDefinition {
            unit_scale,
            active_from,
            retired_at: None,
        }) => (*unit_scale, *active_from),
        _ => return Err(authenticated_overlay()),
    };
    let (new_scale, new_active, retired) = match change.next_fact.as_ref() {
        Some(SemanticFactV0::MeterDefinition {
            unit_scale,
            active_from,
            retired_at: Some(retired),
        }) => (*unit_scale, *active_from, *retired),
        _ => return Err(signed_semantic()),
    };
    let authority_scale = authority_policy
        .unit_scale
        .get()
        .map_err(|_| authenticated_overlay())?;
    if old_scale != authority_scale || old_active != authority_policy.active_from_height {
        return Err(authenticated_overlay());
    }
    if new_scale != old_scale || new_active != old_active || retired != retired_at_height {
        return Err(signed_semantic());
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[(PocoNullifierFamilyV0::MeterDecision, decision)],
    )?;
    overlay.authority.meter_policies[index].retired_at_height = Some(retired_at_height);
    apply_prepared_changes(overlay, changes, false)
}

fn apply_prune_retired_meter_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    meter_id_hex: &str,
    meter_version: u32,
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
    if !operation.nullifier_insertions.is_empty() {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::NullifierProof,
        ));
    }
    let meter_id = exact_opaque_hex(meter_id_hex).map_err(|_| signed_semantic())?;
    let policy_index = overlay
        .authority
        .meter_policies
        .binary_search_by(|policy| {
            (policy.meter_id_hex.as_str(), policy.meter_version).cmp(&(meter_id_hex, meter_version))
        })
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    let policy = overlay.authority.meter_policies[policy_index].clone();
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
        body.meter_id() == meter_id.as_slice() && body.meter_version() == meter_version
    })
    .map_err(|_| authenticated_overlay())?;
    if active_reference {
        return Err(protocol_reject());
    }
    if !overlay
        .authority
        .meter_usage
        .iter()
        .all(|usage| usage.meter_id_hex != meter_id_hex || usage.meter_version != meter_version)
    {
        return Err(protocol_reject());
    }
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, true)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::MeterDefinition])?;
    let change = &changes[0];
    if change.next_value.is_some()
        || change.expected_identity.as_deref()
            != Some(meter_identity(&meter_id, meter_version).as_slice())
    {
        return Err(signed_semantic());
    }
    overlay.authority.meter_policies.remove(policy_index);
    apply_prepared_changes(overlay, changes, true)
}

#[allow(clippy::too_many_arguments)]
fn apply_fund_settlement_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    certificate_id_hex: &str,
    settlement_commitment_hex: &str,
    reserved_units: &CanonicalU128V0,
    funding_decision_id_hex: &str,
) -> Result<()> {
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
    verify_nullifier_absences(
        overlay,
        &operation.nullifier_non_membership_checks,
        &fund_certificate_absence_subjects_v0(certificate_id),
    )?;
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[(PocoNullifierFamilyV0::SettlementDecision, funding_decision)],
    )?;
    overlay
        .authority
        .funded_unused_reservations
        .push(FundedUnusedReservationV0 {
            certificate_id_hex: certificate_id_hex.to_string(),
            settlement_commitment_hex: settlement_commitment_hex.to_string(),
            funding_decision_id_hex: funding_decision_id_hex.to_string(),
            finalized_height: context.target_height.get(),
            reserved_units: CanonicalU128V0::new(reserved_units_value),
        });
    overlay
        .authority
        .funded_unused_reservations
        .sort_by(|left, right| left.certificate_id_hex.cmp(&right.certificate_id_hex));
    apply_prepared_changes(overlay, changes, false)
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
    let certificate_id = exact_hash32_hex(certificate_id_hex)?;
    let funding_decision = exact_hash32_hex(funding_decision_id_hex)?;
    let acceptance_decision =
        require_derived_decision_id(preimage, b"accept-certificate", acceptance_decision_id_hex)?;
    let meter_decision =
        require_derived_decision_id(preimage, b"meter-certificate", meter_decision_id_hex)?;
    let evidence_decision =
        require_derived_decision_id(preimage, b"evidence-certificate", evidence_decision_id_hex)?;
    ensure!(
        acceptance_decision != meter_decision
            && acceptance_decision != evidence_decision
            && meter_decision != evidence_decision,
        "certificate decision IDs are not domain-separated"
    );
    ensure!(
        overlay
            .authority
            .active_certificates
            .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
            .is_err(),
        "certificate authority record already exists"
    );

    let reservation_index = overlay
        .authority
        .funded_unused_reservations
        .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
        .map_err(|_| anyhow::anyhow!("certificate has no funded-unused reservation"))?;
    let reservation = overlay.authority.funded_unused_reservations[reservation_index].clone();
    ensure!(
        exact_hash32_hex(&reservation.funding_decision_id_hex)? == funding_decision,
        "certificate funding decision does not match authenticated reservation"
    );

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
    ensure!(
        certificate_change.expected_value.is_none()
            && certificate_change.next_identity.as_deref() == Some(certificate_id.as_slice()),
        "certificate semantic entry is not a new matching certificate"
    );
    let certificate_payload = certificate_change
        .next_payload
        .as_deref()
        .context("certificate operation lacks raw certificate payload")?;
    let certificate = decode_consumption_certificate_v0_exact(certificate_payload)
        .map_err(|error| anyhow::anyhow!("decode accepted certificate: {error:?}"))?;
    ensure!(
        certificate.certificate_id().as_bytes() == &certificate_id,
        "accepted certificate ID mismatch"
    );
    let body = certificate.body();
    validate_reserved_units_exact_v0(reservation.reserved_units.get()?, body.consumed_units())?;

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
    )?;
    let public_key = match key_parts.fact {
        SemanticFactV0::ConsumerKeyAuthorization {
            public_key,
            active_from,
            revoked_at,
        } => {
            ensure!(
                body.billing_start_height().get() >= active_from
                    && context.target_height.get() >= active_from
                    && revoked_at.is_none_or(|height| {
                        body.billing_end_height().get() < height
                            && context.target_height.get() < height
                    }),
                "consumer key is inactive at the authenticated acceptance height"
            );
            public_key
        }
        _ => bail!("consumer-key lookup returned wrong semantic fact"),
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
        .map_err(|_| anyhow::anyhow!("consumer key lacks authenticated authority companion"))?;
    let key_authority = &overlay.authority.consumer_keys[key_authority_index];
    ensure!(
        exact_hash32_hex(&key_authority.public_key_hex)? == public_key
            && key_authority.active_from_height <= context.target_height.get()
            && key_authority.revoked_at_height.is_none_or(|height| {
                body.billing_end_height().get() < height && context.target_height.get() < height
            }),
        "consumer-key semantic/authority companion mismatch"
    );
    certificate
        .verify(
            context.genesis_hash,
            context.chain_id,
            &context.active_parameters,
            context.target_height,
            ConsensusPublicKey::new(public_key),
            &StrictEd25519Verifier,
        )
        .map_err(|error| anyhow::anyhow!("invalid consumption certificate: {error:?}"))?;

    let nonce_change = change_for_kind(&changes, PocoSnapshotEntryKindV0::ConsumerNonce)?;
    let nonce_identity = joined_identity(&[consumer, consumer_key, provider]);
    ensure!(
        nonce_change.next_identity.as_deref() == Some(nonce_identity.as_slice()),
        "consumer nonce identity mismatch"
    );
    let next_nonce = match nonce_change.next_fact.as_ref() {
        Some(SemanticFactV0::ConsumerNonce { max_accepted_nonce }) => *max_accepted_nonce,
        _ => bail!("certificate operation lacks next consumer nonce"),
    };
    ensure!(
        next_nonce == body.consumer_nonce(),
        "accepted nonce differs from certificate nonce"
    );
    if let Some(expected) = nonce_change.expected_fact.as_ref() {
        match expected {
            SemanticFactV0::ConsumerNonce { max_accepted_nonce } => ensure!(
                next_nonce > *max_accepted_nonce,
                "accepted nonce does not advance authenticated watermark"
            ),
            _ => bail!("nonce CAS expected value has wrong semantic kind"),
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
        (None, Err(_)) => ensure!(
            overlay.authority.consumer_keys[key_authority_index]
                .nonce_watermarks
                .len()
                < MAX_NONCE_WATERMARKS_PER_KEY,
            "consumer key has exhausted distinct provider watermark bound"
        ),
        (Some(SemanticFactV0::ConsumerNonce { max_accepted_nonce }), Ok(index)) => {
            let watermark =
                &overlay.authority.consumer_keys[key_authority_index].nonce_watermarks[index];
            ensure!(
                watermark.max_accepted_nonce == *max_accepted_nonce
                    && exact_hash32_hex(&watermark.logical_key_hex)?.as_slice()
                        == nonce_change.logical_key.as_slice(),
                "consumer nonce semantic/authority watermark mismatch"
            );
        }
        _ => bail!("consumer nonce semantic/authority companion mismatch"),
    }

    let tuple_identity = consumption_tuple_identity(body);
    let tuple_change = change_for_kind(&changes, PocoSnapshotEntryKindV0::UniqueConsumptionTuple)?;
    ensure!(
        tuple_change.expected_value.is_none()
            && tuple_change.next_identity.as_deref() == Some(tuple_identity.as_slice()),
        "consumption tuple is not a new exact certificate tuple"
    );
    validate_tuple_acceptance_authority_v0(
        tuple_change
            .next_fact
            .as_ref()
            .context("certificate operation lacks exact tuple semantic fact")?,
        certificate_id,
        context.target_height.get(),
    )?;
    let tuple_key: [u8; 32] = tuple_change
        .logical_key
        .as_slice()
        .try_into()
        .context("consumption tuple logical key is not Hash32")?;

    let meter_id_hex = hex::encode(body.meter_id());
    let meter_index = overlay
        .authority
        .meter_policies
        .binary_search_by(|item| {
            (&item.meter_id_hex, item.meter_version).cmp(&(&meter_id_hex, body.meter_version()))
        })
        .map_err(|_| anyhow::anyhow!("certificate meter policy is not authenticated"))?;
    let meter_policy = overlay.authority.meter_policies[meter_index].clone();
    ensure!(
        meter_policy.active_from_height <= body.billing_start_height().get()
            && meter_policy.active_from_height <= context.target_height.get()
            && meter_policy.retired_at_height.is_none_or(|height| {
                body.billing_end_height().get() < height && context.target_height.get() < height
            }),
        "certificate meter is retired or not yet active"
    );
    ensure!(
        exact_opaque_hex(&meter_policy.task_id_hex)? == body.task_id(),
        "certificate task is outside meter policy"
    );
    if let Some(expected_output) = &meter_policy.output_commitment_hex {
        ensure!(
            exact_hash32_hex(expected_output)? == *body.output_commitment(),
            "certificate output is outside meter policy"
        );
    }
    let meter_semantic_identity = meter_identity(body.meter_id(), body.meter_version());
    let meter_parts = source_parts_for_identity(
        overlay,
        PocoSnapshotEntryKindV0::MeterDefinition,
        &meter_semantic_identity,
    )?;
    match meter_parts.fact {
        SemanticFactV0::MeterDefinition {
            unit_scale,
            active_from,
            retired_at,
        } => ensure!(
            unit_scale == meter_policy.unit_scale.get()?
                && active_from == meter_policy.active_from_height
                && retired_at == meter_policy.retired_at_height,
            "meter policy and authenticated meter semantic fact diverge"
        ),
        _ => bail!("meter lookup returned wrong semantic fact"),
    }
    ensure!(
        body.consumed_units() <= meter_policy.per_certificate_cap.get()?,
        "certificate exceeds per-certificate meter cap"
    );
    ensure!(
        body.consumed_units() <= context.active_parameters.per_certificate_unit_cap(),
        "certificate exceeds active parameter per-certificate cap"
    );
    body.consumed_units()
        .checked_mul(meter_policy.unit_scale.get()?)
        .context("meter scaled-unit arithmetic overflow")?;

    let settlement_change = change_for_kind(&changes, PocoSnapshotEntryKindV0::Settlement)?;
    ensure!(
        settlement_change.expected_identity.as_deref() == Some(certificate_id.as_slice())
            && settlement_change.next_identity.as_deref() == Some(certificate_id.as_slice()),
        "certificate settlement identity mismatch"
    );
    match (
        settlement_change.expected_fact.as_ref(),
        settlement_change.next_fact.as_ref(),
    ) {
        (
            Some(SemanticFactV0::Settlement {
                commitment: old_commitment,
                state: SettlementStateV0::FinalizedFundedUnused,
                finalized_height: old_height,
            }),
            Some(SemanticFactV0::Settlement {
                commitment: new_commitment,
                state: SettlementStateV0::Consumed,
                finalized_height: new_height,
            }),
        ) => ensure!(
            old_commitment == new_commitment
                && *old_commitment == *body.settlement_commitment()
                && hex::encode(old_commitment) == reservation.settlement_commitment_hex
                && *old_height == reservation.finalized_height
                && new_height == old_height
                && *old_height <= context.target_height.get(),
            "certificate settlement authority mismatch"
        ),
        _ => bail!("certificate settlement is not funded-unused to consumed"),
    }

    let measurement_change =
        change_for_kind(&changes, PocoSnapshotEntryKindV0::MeasurementEvidence)?;
    ensure!(
        measurement_change.expected_value.is_none()
            && measurement_change.next_identity.as_deref() == Some(certificate_id.as_slice()),
        "measurement semantic identity mismatch"
    );
    validate_measurement_policy(
        meter_policy.evidence_policy,
        body.measurement_evidence_root().copied(),
        measurement_change.next_fact.as_ref(),
    )?;

    let relationship_identity = joined_identity(&[provider, consumer, body.task_id()]);
    let relationship_parts = source_parts_for_identity(
        overlay,
        PocoSnapshotEntryKindV0::RelationshipClassification,
        &relationship_identity,
    )?;
    let (relationship_class, relationship_expires_at) = match relationship_parts.fact {
        SemanticFactV0::RelationshipClassification { class, expires_at } => {
            ensure!(
                class != RelationshipClassV0::Unresolved
                    && context.target_height.get() < expires_at,
                "certificate relationship is unresolved or expired"
            );
            (class, expires_at)
        }
        _ => bail!("relationship lookup returned wrong semantic fact"),
    };
    ensure!(
        body.billing_end_height().get() < relationship_expires_at,
        "certificate billing interval outlives relationship authority"
    );

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
            _ => bail!("certificate provider lacks an active validator registration"),
        };
    let history_index = overlay
        .authority
        .validator_registration_history
        .binary_search_by(|item| item.validator_id_hex.as_str().cmp(&provider_id_hex))
        .map_err(|_| {
            anyhow::anyhow!("certificate provider lacks registration history authority")
        })?;
    let registration_history = &overlay.authority.validator_registration_history[history_index];
    ensure!(
        exact_hash32_hex(&registration_history.consensus_key_hex)? == registered_key
            && registration_history.max_registration_nonce == registration_nonce
            && exact_hash32_hex(&registration_history.current_proof_digest_hex)?
                == registration_proof_digest,
        "provider registration fact/history companion mismatch"
    );
    let provider_registration_provenance = (
        registration_history.current_proof_digest_hex.clone(),
        registration_history.registration_decision_id_hex.clone(),
        registration_history.registration_height,
        registration_history.history_head_hex.clone(),
    );

    let lifecycle_change =
        change_for_kind(&changes, PocoSnapshotEntryKindV0::RevocationOrChallenge)?;
    ensure!(
        lifecycle_change.expected_value.is_none()
            && lifecycle_change.next_identity.as_deref() == Some(certificate_id.as_slice()),
        "certificate lifecycle semantic identity mismatch"
    );
    match lifecycle_change.next_fact.as_ref() {
        Some(SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::Accepted,
            effective_height,
        }) => ensure!(
            *effective_height == context.target_height.get(),
            "accepted lifecycle is not bound to target height"
        ),
        _ => bail!("certificate operation lacks accepted lifecycle"),
    }

    let usage_window = context
        .active_epoch
        .get()
        .checked_div(meter_policy.rolling_epoch_span)
        .context("meter rolling epoch span is zero")?;
    let usage_key = (&meter_id_hex, body.meter_version(), usage_window);
    let usage_index = overlay.authority.meter_usage.binary_search_by(|item| {
        (&item.meter_id_hex, item.meter_version, item.window_epoch).cmp(&usage_key)
    });
    let previous_usage = match usage_index {
        Ok(index) => overlay.authority.meter_usage[index].consumed_units.get()?,
        Err(_) => 0,
    };
    let next_usage = checked_usage_after_v0(
        previous_usage,
        body.consumed_units(),
        meter_policy.rolling_cap.get()?,
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
            .get()?,
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
            .get()?,
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
            .get()?,
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

#[allow(clippy::too_many_arguments)]
fn apply_release_settlement_v0(
    _context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    certificate_id_hex: &str,
    release_decision_id_hex: &str,
) -> Result<()> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    let certificate_id = exact_hash32_hex(certificate_id_hex).map_err(|_| signed_semantic())?;
    let release_decision =
        require_derived_decision_id(preimage, b"release-settlement", release_decision_id_hex)?;
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
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, true)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::Settlement])?;
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
        }) if hex::encode(commitment) == reservation.settlement_commitment_hex
            && *finalized_height == reservation.finalized_height => {}
        _ => return Err(authenticated_overlay()),
    }
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &release_nullifier_subjects_v0(certificate_id, release_decision),
    )?;
    overlay
        .authority
        .funded_unused_reservations
        .remove(reservation_index);
    // Funding and release decision nullifiers remain in kind 16 permanently;
    // deleting the rich leaf in this same transition cannot reopen replay.
    apply_prepared_changes(overlay, changes, true)
}

#[allow(clippy::too_many_arguments)]
fn apply_open_challenge_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    certificate_id_hex: &str,
    challenge_id_hex: &str,
    opening_decision_id_hex: &str,
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
    require_derived_decision_id(preimage, b"challenge-id", challenge_id_hex)?;
    let decision =
        require_derived_decision_id(preimage, b"open-challenge", opening_decision_id_hex)?;
    let certificate_index = overlay
        .authority
        .active_certificates
        .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )
        })?;
    if overlay.authority.active_certificates[certificate_index].lifecycle
        != CertificateAuthorityLifecycleV0::Accepted
        || context.target_height.get()
            > overlay.authority.active_certificates[certificate_index].prunable_after_height
    {
        return Err(protocol_reject());
    }
    if !overlay.authority.pending_challenges.iter().all(|item| {
        item.challenge_id_hex != challenge_id_hex && item.certificate_id_hex != certificate_id_hex
    }) {
        return Err(protocol_reject());
    }
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
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
            ..
        })
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
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[(PocoNullifierFamilyV0::ChallengeDecision, decision)],
    )?;
    overlay
        .authority
        .pending_challenges
        .push(PendingChallengeAuthorityV0 {
            challenge_id_hex: challenge_id_hex.to_string(),
            certificate_id_hex: certificate_id_hex.to_string(),
            opening_decision_id_hex: opening_decision_id_hex.to_string(),
            opened_height: context.target_height.get(),
        });
    overlay
        .authority
        .pending_challenges
        .sort_by(|left, right| left.challenge_id_hex.cmp(&right.challenge_id_hex));
    apply_prepared_changes(overlay, changes, false)
}

#[allow(clippy::too_many_arguments)]
fn apply_resolve_challenge_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    certificate_id_hex: &str,
    challenge_id_hex: &str,
    resolution: ChallengeResolutionV0,
    resolution_decision_id_hex: &str,
) -> Result<()> {
    let signed_semantic = || {
        deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::SemanticTransition,
        )
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    let certificate_id = exact_hash32_hex(certificate_id_hex).map_err(|_| signed_semantic())?;
    exact_hash32_hex(challenge_id_hex).map_err(|_| signed_semantic())?;
    let decision =
        require_derived_decision_id(preimage, b"resolve-challenge", resolution_decision_id_hex)?;
    let pending_index = overlay
        .authority
        .pending_challenges
        .binary_search_by(|item| item.challenge_id_hex.as_str().cmp(challenge_id_hex))
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::ChallengeNotPending,
            )
        })?;
    if overlay.authority.pending_challenges[pending_index].certificate_id_hex != certificate_id_hex
    {
        return Err(signed_semantic());
    }
    let certificate_index = overlay
        .authority
        .active_certificates
        .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
        .map_err(|_| authenticated_overlay())?;
    if overlay.authority.active_certificates[certificate_index].lifecycle
        != CertificateAuthorityLifecycleV0::Accepted
    {
        return Err(authenticated_overlay());
    }
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::RevocationOrChallenge])?;
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
    let pending = &overlay.authority.pending_challenges[pending_index];
    let pending_height = match change.expected_fact.as_ref() {
        Some(SemanticFactV0::RevocationOrChallenge {
            state: LifecycleStateV0::ChallengePending,
            effective_height,
        }) => *effective_height,
        _ => return Err(authenticated_overlay()),
    };
    if pending_height != pending.opened_height {
        return Err(authenticated_overlay());
    }
    if context.target_height.get() <= pending.opened_height {
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
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[(PocoNullifierFamilyV0::ChallengeDecision, decision)],
    )?;
    overlay.authority.pending_challenges.remove(pending_index);
    overlay.authority.active_certificates[certificate_index].lifecycle = match resolution {
        ChallengeResolutionV0::Rejected => CertificateAuthorityLifecycleV0::ChallengeRejected,
        ChallengeResolutionV0::Sustained => CertificateAuthorityLifecycleV0::ChallengeSustained,
    };
    overlay.authority.active_certificates[certificate_index].lifecycle_effective_height =
        context.target_height.get();
    overlay.authority.active_certificates[certificate_index].lifecycle_decision_id_hex =
        resolution_decision_id_hex.to_string();
    apply_prepared_changes(overlay, changes, false)
}

#[allow(clippy::too_many_arguments)]
fn apply_propose_governance_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    target_epoch: u64,
    phase: u8,
    parameters_hash_hex: &str,
    activation_height: u64,
    proposal_decision_id_hex: &str,
) -> Result<()> {
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
    ensure!(
        overlay
            .authority
            .pending_governance_proposals
            .binary_search_by_key(&target_epoch, |proposal| proposal.target_epoch)
            .is_err()
            && overlay
                .authority
                .finalized_governance_approvals
                .binary_search_by_key(&target_epoch, |approval| approval.target_epoch)
                .is_err(),
        "governance target already has proposal or approval authority"
    );
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
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[(PocoNullifierFamilyV0::GovernanceDecision, decision)],
    )?;
    overlay
        .authority
        .pending_governance_proposals
        .push(PendingGovernanceProposalV0 {
            target_epoch,
            proposal_decision_id_hex: proposal_decision_id_hex.to_string(),
            proposed_height: context.target_height.get(),
            phase: phase as u8,
            parameters_hash_hex: parameters_hash_hex.to_string(),
            activation_height,
        });
    overlay
        .authority
        .pending_governance_proposals
        .sort_by_key(|proposal| proposal.target_epoch);
    apply_prepared_changes(overlay, changes, false)
}

#[allow(clippy::too_many_arguments)]
fn apply_approve_governance_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    target_epoch: u64,
    parameters_hash_hex: &str,
    activation_height: u64,
    decision_id_hex: &str,
) -> Result<()> {
    let governance_reject = || {
        deterministic_application_error_v0(PocoApplicationDeterministicInvalidV0::GovernanceRule)
    };
    let authenticated_overlay =
        || invariant_application_error_v0(PocoApplicationInvariantV0::AuthenticatedOverlay);
    let parameters_hash = exact_hash32_hex(parameters_hash_hex).map_err(|_| governance_reject())?;
    let expected_epoch = context.active_epoch.get().checked_add(1).ok_or_else(|| {
        invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
    })?;
    if target_epoch != expected_epoch {
        return Err(governance_reject());
    }
    let proposal_index = overlay
        .authority
        .pending_governance_proposals
        .binary_search_by_key(&target_epoch, |proposal| proposal.target_epoch)
        .map_err(|_| {
            deterministic_application_error_v0(
                PocoApplicationDeterministicInvalidV0::GovernanceApprovalMissing,
            )
        })?;
    let proposal = overlay.authority.pending_governance_proposals[proposal_index].clone();
    if proposal.parameters_hash_hex != parameters_hash_hex
        || proposal.activation_height != activation_height
    {
        return Err(governance_reject());
    }
    if proposal.proposed_height >= context.target_height.get() {
        return Err(deterministic_application_error_v0(
            PocoApplicationDeterministicInvalidV0::ProtocolWindowOrCap,
        ));
    }
    let mut parameters_identity = vec![2];
    parameters_identity.extend_from_slice(&target_epoch.to_be_bytes());
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
        .is_ok()
    {
        return Err(governance_reject());
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
        || old_phase as u8 != proposal.phase
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
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[(PocoNullifierFamilyV0::GovernanceDecision, decision)],
    )?;
    overlay
        .authority
        .finalized_governance_approvals
        .push(FinalizedGovernanceApprovalV0 {
            target_epoch,
            phase: proposal.phase,
            proposal_decision_id_hex: proposal.proposal_decision_id_hex,
            proposed_height: proposal.proposed_height,
            decision_id_hex: decision_id_hex.to_string(),
            approval_height: context.target_height.get(),
            parameters_hash_hex: parameters_hash_hex.to_string(),
            activation_height,
        });
    overlay
        .authority
        .finalized_governance_approvals
        .sort_by_key(|item| item.target_epoch);
    overlay
        .authority
        .pending_governance_proposals
        .remove(proposal_index);
    apply_prepared_changes(overlay, changes, false)
}

#[allow(clippy::too_many_arguments)]
fn apply_register_validator_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    validator_id_hex: &str,
    target_epoch: u64,
    registration_decision_id_hex: &str,
    rotate: bool,
    previous_history_head_hex: Option<&String>,
    previous_registration_nonce: Option<u64>,
) -> Result<()> {
    let validator_id_bytes = exact_opaque_hex(validator_id_hex)?;
    if rotate {
        ensure_validator_has_no_active_certificate_references_v0(
            &overlay.authority,
            validator_id_hex,
        )?;
    }
    ensure!(
        target_epoch == context.active_epoch.get(),
        "validator registration epoch differs from authenticated active epoch"
    );
    let decision_label: &[u8] = if rotate {
        b"rotate-validator"
    } else {
        b"register-validator"
    };
    let decision =
        require_derived_decision_id(preimage, decision_label, registration_decision_id_hex)?;
    if rotate {
        ensure!(
            operation.nullifier_non_membership_checks.is_empty(),
            "validator rotation has unauthorized identity absence proof"
        );
    } else {
        verify_nullifier_absences(
            overlay,
            &operation.nullifier_non_membership_checks,
            &[(
                PocoNullifierFamilyV0::ValidatorIdentity,
                semantic_identity_digest_v0(
                    PocoSnapshotEntryKindV0::ValidatorRegistration,
                    &validator_id_bytes,
                ),
            )],
        )?;
    }
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::ValidatorRegistration])?;
    let change = &changes[0];
    ensure!(
        change.next_identity.as_deref() == Some(validator_id_bytes.as_slice()),
        "validator registration semantic identity mismatch"
    );
    let next_fact = match change.next_fact.as_ref() {
        Some(SemanticFactV0::ValidatorRegistration {
            consensus_key,
            registration_nonce,
            proof_digest,
            state: RegistrationStateV0::Active,
        }) => (*consensus_key, *registration_nonce, *proof_digest),
        _ => bail!("validator operation lacks active registration fact"),
    };
    let next_consensus_key_hex = hex::encode(next_fact.0);
    if !overlay
        .authority
        .validator_registration_history
        .iter()
        .all(|history| history.consensus_key_hex != next_consensus_key_hex)
    {
        return Err(anyhow::Error::new(
            PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                PocoApplicationDeterministicInvalidV0::ValidatorConsensusKeyAlreadyActive,
            ),
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

    let history_search = overlay
        .authority
        .validator_registration_history
        .binary_search_by(|item| item.validator_id_hex.as_str().cmp(validator_id_hex));
    let (previous_head, retired_key_count) = if rotate {
        let index = history_search
            .map_err(|_| anyhow::anyhow!("validator rotation lacks authenticated history"))?;
        let history = &overlay.authority.validator_registration_history[index];
        ensure!(
            history.revoked_at_height.is_none(),
            "revoked validator registration cannot rotate"
        );
        let expected_head =
            previous_history_head_hex.context("validator rotation lacks previous history head")?;
        let expected_nonce = previous_registration_nonce
            .context("validator rotation lacks previous registration nonce")?;
        ensure!(
            history.history_head_hex == expected_head.as_str()
                && history.max_registration_nonce == expected_nonce,
            "validator rotation predecessor history mismatch"
        );
        ensure!(
            next_fact.1 > history.max_registration_nonce,
            "validator registration nonce is not strictly monotonic"
        );
        ensure!(
            hex::encode(next_fact.0) != history.consensus_key_hex,
            "validator key rotation did not change key"
        );
        match change.expected_fact.as_ref() {
            Some(SemanticFactV0::ValidatorRegistration {
                consensus_key,
                registration_nonce,
                proof_digest,
                state: RegistrationStateV0::Active,
            }) => ensure!(
                hex::encode(consensus_key) == history.consensus_key_hex
                    && *registration_nonce == history.max_registration_nonce
                    && hex::encode(proof_digest) == history.current_proof_digest_hex,
                "validator semantic predecessor differs from history"
            ),
            _ => bail!("validator rotation lacks active semantic predecessor"),
        }
        let next_retired_count = history.retired_key_count.checked_add(1).ok_or_else(|| {
            invariant_application_error_v0(PocoApplicationInvariantV0::ProtocolCounterExhausted)
        })?;
        (
            exact_hash32_hex(&history.history_head_hex)?,
            next_retired_count,
        )
    } else {
        ensure!(history_search.is_err(), "validator is already registered");
        ensure!(
            change.expected_value.is_none(),
            "first registration has semantic predecessor"
        );
        ensure!(
            previous_history_head_hex.is_none() && previous_registration_nonce.is_none(),
            "first registration supplied predecessor history"
        );
        ([0; 32], 0)
    };
    let next_history_head = registration_history_head_v0(
        previous_head,
        &validator_id_bytes,
        next_fact.0,
        next_fact.1,
        next_fact.2,
        decision,
        context.target_height.get(),
    );
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[
            (PocoNullifierFamilyV0::RegistrationDecision, decision),
            (PocoNullifierFamilyV0::ValidatorConsensusKey, next_fact.0),
        ],
    )?;
    let next_history = ValidatorRegistrationHistoryV0 {
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
    };
    match history_search {
        Ok(index) => overlay.authority.validator_registration_history[index] = next_history,
        Err(index) => overlay
            .authority
            .validator_registration_history
            .insert(index, next_history),
    }
    apply_prepared_changes(overlay, changes, false)
}

#[allow(clippy::too_many_arguments)]
fn apply_register_future_candidate_v0(
    context: &AuthenticatedPocoApplicationContextV0,
    overlay: &mut PocoApplicationOverlayV0,
    operation: &PocoApplicationOperationV0,
    preimage: [u8; 32],
    validator_id_hex: &str,
    target_epoch: u64,
    previous_registration_nonce: Option<u64>,
    predecessor_history_head_hex: &str,
    proof_cev0_hex: &str,
    registration_decision_id_hex: &str,
) -> Result<()> {
    ensure!(
        operation.semantic_changes.is_empty()
            && operation.nullifier_non_membership_checks.is_empty(),
        "future candidate registration may not mutate frozen kinds or supply side proofs"
    );
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

    let active = active_projection_context_v0(&overlay.entries)?;
    ensure!(
        active.validator_set.epoch() == context.active_epoch,
        "future candidate active projection epoch drift"
    );
    let predecessor_head = exact_hash32_hex(predecessor_history_head_hex)?;
    match active.validator_set.validator(validator_id) {
        Some(old) if old.consensus_key() != proof_fields.public_key => {
            let previous_nonce = previous_registration_nonce
                .context("changed-key future candidate lacks predecessor nonce")?;
            let history = overlay
                .authority
                .validator_registration_history
                .binary_search_by(|item| item.validator_id_hex.as_str().cmp(validator_id_hex))
                .ok()
                .map(|index| &overlay.authority.validator_registration_history[index])
                .context("changed-key future candidate lacks active registration history")?;
            ensure!(
                history.revoked_at_height.is_none()
                    && exact_hash32_hex(&history.consensus_key_hex)?
                        == *old.consensus_key().as_bytes()
                    && history.max_registration_nonce == previous_nonce
                    && exact_hash32_hex(&history.history_head_hex)? == predecessor_head
                    && proof_fields.registration_nonce > previous_nonce,
                "future candidate predecessor nonce/history is not the authenticated active key"
            );
        }
        Some(_) => {
            bail!("unchanged-key old validator must use canonical proof-free candidate carry")
        }
        None => ensure!(
            previous_registration_nonce.is_none() && predecessor_head == [0; 32],
            "new future candidate supplied a predecessor from outside the old set"
        ),
    }

    ensure!(
        overlay
            .authority
            .future_candidate_registrations
            .binary_search_by(|item| {
                (item.target_epoch, item.validator_id_hex.as_str())
                    .cmp(&(target_epoch, validator_id_hex))
            })
            .is_err(),
        "future candidate is already registered for the target epoch"
    );
    let consensus_key_hex = hex::encode(proof_fields.public_key.as_bytes());
    ensure!(
        overlay
            .authority
            .future_candidate_registrations
            .iter()
            .all(|item| item.consensus_key_hex != consensus_key_hex),
        "future candidate consensus key is already registered"
    );
    for old in active.validator_set.validators() {
        ensure!(
            old.id() == validator_id || old.consensus_key() != proof_fields.public_key,
            "future candidate consensus key belongs to another old validator"
        );
    }

    let decision = require_derived_decision_id(
        preimage,
        b"register-future-candidate",
        registration_decision_id_hex,
    )?;
    insert_nullifiers(
        overlay,
        &operation.nullifier_insertions,
        &[
            (PocoNullifierFamilyV0::RegistrationDecision, decision),
            (
                PocoNullifierFamilyV0::ValidatorConsensusKey,
                *proof_fields.public_key.as_bytes(),
            ),
        ],
    )?;
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
    let insertion = overlay
        .authority
        .future_candidate_registrations
        .binary_search_by(|item| {
            (item.target_epoch, item.validator_id_hex.as_str())
                .cmp(&(target_epoch, validator_id_hex))
        })
        .expect_err("future candidate absence checked above");
    overlay
        .authority
        .future_candidate_registrations
        .insert(insertion, record);
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
    let validator_id = exact_opaque_hex(validator_id_hex)?;
    ensure_validator_has_no_active_certificate_references_v0(&overlay.authority, validator_id_hex)?;
    let decision =
        require_derived_decision_id(preimage, b"revoke-validator", revocation_decision_id_hex)?;
    let history_index = overlay
        .authority
        .validator_registration_history
        .binary_search_by(|history| history.validator_id_hex.as_str().cmp(validator_id_hex))
        .map_err(|_| anyhow::anyhow!("validator revocation lacks registration history"))?;
    ensure!(
        overlay.authority.validator_registration_history[history_index]
            .revoked_at_height
            .is_none(),
        "validator registration is already revoked"
    );
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, false)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::ValidatorRegistration])?;
    let change = &changes[0];
    ensure!(
        change.expected_identity.as_deref() == Some(validator_id.as_slice())
            && change.next_identity.as_deref() == Some(validator_id.as_slice()),
        "validator revocation identity mismatch"
    );
    match (change.expected_fact.as_ref(), change.next_fact.as_ref()) {
        (
            Some(SemanticFactV0::ValidatorRegistration {
                consensus_key: old_key,
                registration_nonce: old_nonce,
                proof_digest: old_proof,
                state: RegistrationStateV0::Active,
            }),
            Some(SemanticFactV0::ValidatorRegistration {
                consensus_key: new_key,
                registration_nonce: new_nonce,
                proof_digest: new_proof,
                state: RegistrationStateV0::Revoked,
            }),
        ) => {
            let history = &overlay.authority.validator_registration_history[history_index];
            ensure!(
                old_key == new_key
                    && old_nonce == new_nonce
                    && old_proof == new_proof
                    && hex::encode(old_key) == history.consensus_key_hex
                    && *old_nonce == history.max_registration_nonce
                    && hex::encode(old_proof) == history.current_proof_digest_hex,
                "validator revocation changes immutable registration authority"
            );
        }
        _ => bail!("validator revocation is not exact active-to-revoked"),
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
    ensure!(
        operation.nullifier_insertions.is_empty(),
        "validator-history prune has unauthorized nullifier insertions"
    );
    let validator_id = exact_opaque_hex(validator_id_hex)?;
    let history_index = overlay
        .authority
        .validator_registration_history
        .binary_search_by(|history| history.validator_id_hex.as_str().cmp(validator_id_hex))
        .map_err(|_| anyhow::anyhow!("validator-history prune lacks authority"))?;
    let history = overlay.authority.validator_registration_history[history_index].clone();
    let revoked_at = history
        .revoked_at_height
        .context("active validator history cannot be pruned")?;
    let boundary = protocol_retention_boundary_v0(revoked_at, &context.active_parameters)?;
    ensure!(
        context.target_height.get() > boundary,
        "validator-history retention boundary has not been strictly crossed"
    );
    ensure!(
        !active_certificate_reference_exists_v0(overlay, |body| {
            body.provider_id().as_bytes() == validator_id.as_slice()
        })?,
        "active certificate still references revoked validator"
    );
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, true)?;
    ensure_change_kinds(&changes, &[PocoSnapshotEntryKindV0::ValidatorRegistration])?;
    let change = &changes[0];
    ensure!(
        change.next_value.is_none()
            && change.expected_identity.as_deref() == Some(validator_id.as_slice()),
        "validator-history prune does not delete exact kind-9 fact"
    );
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
    let certificate_id = exact_hash32_hex(certificate_id_hex)?;
    let certificate_index = overlay
        .authority
        .active_certificates
        .binary_search_by(|item| item.certificate_id_hex.as_str().cmp(certificate_id_hex))
        .map_err(|_| anyhow::anyhow!("pruned certificate is not active"))?;
    let certificate = overlay.authority.active_certificates[certificate_index].clone();
    ensure!(
        prune_target_is_strictly_after_boundary_v0(
            context.target_height.get(),
            certificate.prunable_after_height,
        ),
        "certificate retention/evidence/weight boundary has not been strictly crossed"
    );
    ensure!(
        overlay
            .authority
            .pending_challenges
            .iter()
            .all(|item| item.certificate_id_hex != certificate_id_hex),
        "pending challenge prevents certificate pruning"
    );
    ensure!(
        overlay
            .authority
            .funded_unused_reservations
            .iter()
            .all(|item| item.certificate_id_hex != certificate_id_hex),
        "funded-unused settlement prevents certificate pruning"
    );
    let changes = prepare_semantic_changes(overlay, &operation.semantic_changes, true)?;
    ensure!(
        changes.iter().all(|change| change.next_value.is_none()),
        "prune operation may only delete rich semantic entries"
    );
    let actual_keys = changes
        .iter()
        .map(|change| SemanticKeyRefV0 {
            kind: change.kind as u8,
            logical_key_hex: hex::encode(&change.logical_key),
        })
        .collect::<Vec<_>>();
    ensure!(
        actual_keys == certificate.semantic_keys,
        "prune operation does not delete the exact retained certificate set"
    );
    let settlement_change = change_for_kind(&changes, PocoSnapshotEntryKindV0::Settlement)?;
    ensure!(
        matches!(
            settlement_change.expected_fact.as_ref(),
            Some(SemanticFactV0::Settlement {
                state: SettlementStateV0::Consumed,
                ..
            })
        ),
        "prune requires a terminal consumed settlement"
    );
    let lifecycle_change =
        change_for_kind(&changes, PocoSnapshotEntryKindV0::RevocationOrChallenge)?;
    let expected_terminal_lifecycle = match certificate.lifecycle {
        CertificateAuthorityLifecycleV0::ChallengeRejected => LifecycleStateV0::ChallengeRejected,
        CertificateAuthorityLifecycleV0::ChallengeSustained => LifecycleStateV0::ChallengeSustained,
        CertificateAuthorityLifecycleV0::Accepted => LifecycleStateV0::Accepted,
    };
    ensure!(
        matches!(
            lifecycle_change.expected_fact.as_ref(),
            Some(SemanticFactV0::RevocationOrChallenge { state, .. })
                if *state == expected_terminal_lifecycle
        ),
        "prune authority/semantic lifecycle terminal state mismatch"
    );
    let tuple_key = exact_hash32_hex(&certificate.tuple_key_hex)?;
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
        if predicate(decoded.body()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn consumer_nonce_summary_digest_v0(watermarks: &[ConsumerNonceWatermarkV0]) -> Result<[u8; 32]> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(watermarks.len())
            .context("nonce summary count exceeds u32")?
            .to_be_bytes(),
    );
    for watermark in watermarks {
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
    parameters
        .validate_safety_invariants()
        .map_err(|error| anyhow::anyhow!("invalid active prune parameters: {error:?}"))?;
    validate_meter_policy(meter_policy)?;
    let weight_epochs = parameters
        .maturity_epochs()
        .checked_add(parameters.max_certificate_age_epochs())
        .context("certificate maturity+age prune window overflow")?;
    let protocol_epochs = weight_epochs.max(parameters.evidence_window_epochs());
    let protocol_blocks = protocol_epochs
        .checked_mul(parameters.epoch_length_blocks())
        .context("certificate protocol prune window overflow")?;
    let rolling_blocks = meter_policy
        .rolling_epoch_span
        .checked_mul(parameters.epoch_length_blocks())
        .context("certificate rolling prune window overflow")?;
    let retention_blocks = protocol_blocks
        .max(rolling_blocks)
        .max(meter_policy.retention_blocks);
    ensure!(retention_blocks > 0, "certificate prune window is zero");
    accepted_height
        .checked_add(retention_blocks)
        .context("certificate safe prune boundary overflow")
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
                PocoApplicationDeterministicInvalidV0::SemanticTransition,
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
        let mut operation = PocoApplicationOperationV0 {
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

        let PocoApplicationOperationBodyV0::OpenChallenge {
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
                PocoApplicationDeterministicInvalidV0::MissingRequiredAuthorityFact,
            )),
        );
        assert_eq!(block.operation_count(), 0);
        assert!(block.overlay.operation_ids.is_empty());
        assert!(block.overlay.mutations.is_empty());
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
        assert!(derive_safe_prune_boundary_v0(u64::MAX, &parameters, &policy).is_err());
        let mut rolling_overflow = policy;
        rolling_overflow.rolling_epoch_span = u64::MAX;
        assert!(derive_safe_prune_boundary_v0(1, &parameters, &rolling_overflow).is_err());
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
        let mut exact_authority = max_capacity_authority_state();
        exact_authority.funded_unused_reservations.pop();
        exact_authority.validate().unwrap();
        assert_eq!(authority_record_count_v0(&exact_authority).unwrap(), 65);
        let mut operation = minimal_operation();
        operation.body = PocoApplicationOperationBodyV0::FundSettlement {
            certificate_id_hex: tagged_hash_hex(65_010),
            settlement_commitment_hex: tagged_hash_hex(65_011),
            reserved_units: CanonicalU128V0::new(u128::MAX),
            funding_decision_id_hex: tagged_hash_hex(65_012),
        };
        let exact_overlay = overlay_with_authority(exact_authority.clone());
        assert!(validate_operation_capacity_before_clone_v0(
            &context_at(2).unwrap(),
            &exact_overlay,
            &operation,
        )
        .is_ok());
        assert_eq!(exact_overlay.authority, exact_authority);

        let over_authority = max_capacity_authority_state();
        let over_overlay = overlay_with_authority(over_authority.clone());
        assert!(validate_operation_capacity_before_clone_v0(
            &context_at(2).unwrap(),
            &over_overlay,
            &operation,
        )
        .is_err());
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
        let error = validate_operation_capacity_before_clone_v0(
            &context_at(2).unwrap(),
            &overlay,
            &operation,
        )
        .expect_err("missing challenge must fail before clone");
        assert_eq!(format!("{error:#}"), "challenge is not pending");
        assert_eq!(overlay.authority, authority);

        operation.body = PocoApplicationOperationBodyV0::ApproveGovernance {
            target_epoch: 1,
            parameters_hash_hex: "44".repeat(32),
            activation_height: 3,
            decision_id_hex: "55".repeat(32),
        };
        let error = validate_operation_capacity_before_clone_v0(
            &context_at(2).unwrap(),
            &overlay,
            &operation,
        )
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
        let error = validate_operation_capacity_before_clone_v0(
            &context_at(2).unwrap(),
            &overlay,
            &operation,
        )
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
