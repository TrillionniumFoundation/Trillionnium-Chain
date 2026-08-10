//! Test-only Rust authority for application-operation fixture authoring.
//!
//! This module deliberately sits below `poco_application`, so it can build
//! exact production operation objects and semantic envelopes without making
//! any authority constructor public.  Node receives only decision-zero
//! templates plus proof *descriptors*.  The corresponding fully-derived raw
//! operations are first applied through the real block overlay and JMT here;
//! placeholders and caller-authored semantic bytes never become fixture
//! authority.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tendermint_proto::v0_38::abci::ExecTxResult;
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_consensus_parameters_v0_exact, BlockHeader, BlockId,
    BlockKind, CertifiedHeaderV0, ChainId, ConsensusParametersV0, ConsumptionCertificateBodyV0,
    ConsumptionCertificateV0, Epoch, EpochFallbackReasonV0, EvidenceRoot, FinalityProofV0,
    GenesisHash, HandoffCertificateV0, HandoffDescriptorV0, HandoffDescriptorV0Fields, Height,
    PayloadDigest, ProposalWitnessV0, ProtocolVersion, QcReferenceV0, QuorumCertificate,
    ReceiptsRoot, Signature64, SignatureShareV0, StateRoot, Validator, ValidatorId,
    ValidatorKeyProofOfPossessionV0, ValidatorKeyProofOfPossessionV0Fields, ValidatorSet, View,
    Vote, VotingPower, SCHEMA_VERSION_V0,
};

use super::*;
use crate::{
    auth_tree::{poco_snapshot_key_components, AuthProof, AuthWrite, InMemoryAuthTree},
    poco_checkpoint::{
        active_consensus_configuration, authorize_poco_checkpoint_candidate_selection_v0,
        maybe_authenticated_poco_projection_at_v0, PocoAuthorityConfigV0,
        PocoCheckpointExecutionInputV0, POCO_AUTHORITY_CONFIG_SCHEMA_V0,
    },
    poco_checkpoint_header::{
        bind_prepared_poco_checkpoint_header_for_fixture_v0, prepare_poco_checkpoint_header_v0,
    },
    poco_joint_handoff::authorize_poco_checkpoint_joint_handoff_for_fixture_v0,
    poco_nullifier::{
        derive_poco_nullifier_key_v0, test_non_membership_proof_for_keys_v0, PocoNullifierFamilyV0,
    },
    poco_semantics::{BondStateV0, RelationshipClassV0, RolloutPhaseV0},
    poco_snapshot::{
        poco_snapshot_manifest_key, Ics23PointProofV0, PocoSnapshotManifestV0,
        PocoSnapshotMemberProofV0, PocoSnapshotNamespaceProofV0,
    },
    poco_transition::{
        auth_writes_from_sealed_poco_application_v0, genesis_poco_snapshot_writes_v0,
        scheduled_cutoff_manifest_refresh_write_v0,
        take_and_validate_production_poco_projection_v0, PocoWritePermitV0,
        ProductionPocoProjectionV0,
    },
    validator_lifecycle::ConsensusValidatorV1,
};

const AUTHORING_INPUT_SCHEMA: &str = "trnm.poco-bft.application-operation-authoring-inputs.v0";
const STEP_TEMPLATE_SCHEMA: &str = "trnm.poco-bft.application-operation-step-template.v0";
const NEGATIVE_TEMPLATE_SCHEMA: &str = "trnm.poco-bft.application-operation-negative-template.v0";
const FULL_SOURCE_SCHEMA: &str = "trnm.poco-bft.application-full-genesis-export.v0";
const OUTPUT_ENV: &str = "TRNM_POCO_APPLICATION_OPERATION_AUTHORING_INPUTS";
const FULL_SOURCE_ENV: &str = "TRNM_POCO_APPLICATION_FULL_GENESIS";
const DEFAULT_OUTPUT: &str = "/tmp/trnm-poco-application-operation-authoring-inputs-v0.json";
const CERTIFICATE_PRUNE_SOURCE_ENV: &str = "TRNM_POCO_APPLICATION_CERTIFICATE_PRUNE_SOURCE";
const CONSUMER_KEY_PRUNE_SOURCE_ENV: &str = "TRNM_POCO_APPLICATION_CONSUMER_KEY_PRUNE_SOURCE";
const METER_PRUNE_SOURCE_ENV: &str = "TRNM_POCO_APPLICATION_METER_PRUNE_SOURCE";
const VALIDATOR_PRUNE_SOURCE_ENV: &str = "TRNM_POCO_APPLICATION_VALIDATOR_PRUNE_SOURCE";
const ISOLATED_SOURCE_SCHEMA: &str = "trnm.poco-bft.application-isolated-prune-source-export.v0";
const DEFAULT_CERTIFICATE_PRUNE_SOURCE: &str =
    "/tmp/trnm-poco-application-certificate-prune-source-v0.json";
const DEFAULT_CONSUMER_KEY_PRUNE_SOURCE: &str =
    "/tmp/trnm-poco-application-consumer-key-prune-source-v0.json";
const DEFAULT_METER_PRUNE_SOURCE: &str = "/tmp/trnm-poco-application-meter-prune-source-v0.json";
const DEFAULT_VALIDATOR_PRUNE_SOURCE: &str =
    "/tmp/trnm-poco-application-validator-prune-source-v0.json";
const AUTHENTICATED_CANDIDATE_FIXTURE_SCHEMA: &str =
    "trnm.poco-bft.authenticated-candidate-selection-fixture.v0";
const AUTHENTICATED_CANDIDATE_OUTPUT_ENV: &str = "TRNM_POCO_AUTHENTICATED_CANDIDATE_FIXTURE";
const DEFAULT_AUTHENTICATED_CANDIDATE_OUTPUT: &str =
    "/tmp/trnm-poco-authenticated-candidate-selection-fixture-v0.json";
const AUTHENTICATED_NEXT_EPOCH_COMMITMENT_FIXTURE_SCHEMA: &str =
    "trnm.poco-bft.authenticated-next-epoch-commitment-fixture.v0";
const AUTHENTICATED_NEXT_EPOCH_COMMITMENT_OUTPUT_ENV: &str =
    "TRNM_POCO_AUTHENTICATED_NEXT_EPOCH_COMMITMENT_FIXTURE";
const DEFAULT_AUTHENTICATED_NEXT_EPOCH_COMMITMENT_OUTPUT: &str =
    "/tmp/trnm-poco-authenticated-next-epoch-commitment-fixture-v0.json";
const AUTHENTICATED_CHECKPOINT_HANDOFF_FIXTURE_SCHEMA: &str =
    "trnm.poco-bft.authenticated-checkpoint-handoff-fixture.v0";
const AUTHENTICATED_CHECKPOINT_HANDOFF_OUTPUT_ENV: &str =
    "TRNM_POCO_AUTHENTICATED_CHECKPOINT_HANDOFF_FIXTURE";
const DEFAULT_AUTHENTICATED_CHECKPOINT_HANDOFF_OUTPUT: &str =
    "/tmp/trnm-poco-authenticated-checkpoint-handoff-fixture-v0.json";
const AUTHENTICATED_CANDIDATE_EPOCH_LENGTH: u64 = 10;
const AUTHENTICATED_CANDIDATE_SNAPSHOT_LEAD: u64 = 3;
const AUTHENTICATED_CANDIDATE_ACTIVE_EPOCH: u64 = 2;
const AUTHENTICATED_CANDIDATE_TARGET_EPOCH: u64 = 3;
const AUTHENTICATED_CANDIDATE_BOUNDARY_HEIGHT: u64 = 21;
const AUTHENTICATED_CANDIDATE_FUTURE_REGISTRATION_HEIGHT: u64 = 22;
const AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT: u64 = 25;
const AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT: u64 = 28;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PhysicalWriteExportV0 {
    physical_key_hex: String,
    value_hex: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedRecordExportV0 {
    physical_key_hex: String,
    value_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveParametersExportV0 {
    physical_key_hex: String,
    value_hex: String,
    cev0_hex: String,
    hash_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveGenesisExportV0 {
    chain_id_utf8: String,
    genesis_hash_hex: String,
    validator_lifecycle: NamedRecordExportV0,
    poco_authority_config: NamedRecordExportV0,
    active_parameters: ActiveParametersExportV0,
    other_apphash_writes: Vec<NamedRecordExportV0>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProductionContextExportV0 {
    chain_id_utf8: String,
    genesis_hash_hex: String,
    source_version: u64,
    source_root_hex: String,
    target_height: u64,
    active_epoch: u64,
    active_parameters_cev0_hex: String,
    active_parameters_hash_hex: String,
    authority_signer_commitment_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoryExportV0 {
    version: u64,
    jmt_root_hex: String,
    writes: Vec<PhysicalWriteExportV0>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntryExportV0 {
    kind: u8,
    logical_key_hex: String,
    value_hex: String,
    canonical_entry_cev0_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionExportV0 {
    manifest_hex: String,
    entries_root_hex: String,
    entries: Vec<EntryExportV0>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InitialExportV0 {
    version: u64,
    jmt_root_hex: String,
    active_genesis: ActiveGenesisExportV0,
    production_context: ProductionContextExportV0,
    history: Vec<HistoryExportV0>,
    projection: ProjectionExportV0,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OccupiedNullifierExportV0 {
    family: u8,
    identifier_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoringNullifierStateExportV0 {
    root_hex: String,
    count: u64,
    occupied: Vec<OccupiedNullifierExportV0>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FullSourceExportV0 {
    schema: String,
    schema_version: u16,
    initial: InitialExportV0,
    authoring_nullifier_state: AuthoringNullifierStateExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct CertificateLineageSubjectsV0 {
    certificate_id_hex: String,
}

#[derive(Clone, Debug, Serialize)]
struct ConsumerKeyLineageSubjectsV0 {
    consumer_id_hex: String,
    consumer_key_id_hex: String,
}

#[derive(Clone, Debug, Serialize)]
struct MeterLineageSubjectsV0 {
    meter_id_hex: String,
    meter_version: u32,
}

#[derive(Clone, Debug, Serialize)]
struct ValidatorLineageSubjectsV0 {
    validator_id_hex: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
enum LineageSubjectsV0 {
    Certificate(CertificateLineageSubjectsV0),
    ConsumerKey(ConsumerKeyLineageSubjectsV0),
    Meter(MeterLineageSubjectsV0),
    Validator(ValidatorLineageSubjectsV0),
}

#[derive(Clone, Debug, Serialize)]
struct LineageBaseIntentExportV0 {
    operation_kind: &'static str,
    normalized_business_intent_digest_hex: String,
    subjects: LineageSubjectsV0,
}

#[derive(Clone, Debug, Serialize)]
struct IsolatedSourceExportV0 {
    schema: &'static str,
    schema_version: u16,
    lineage_base_intent: LineageBaseIntentExportV0,
    initial: InitialExportV0,
    authoring_nullifier_state: AuthoringNullifierStateExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct SourceReferenceExportV0 {
    path: String,
    sha256_hex: String,
    schema: String,
}

#[derive(Clone, Debug, Serialize)]
struct SourceReferencesExportV0 {
    full_application_store: SourceReferenceExportV0,
    certificate_prune_replay: SourceReferenceExportV0,
    consumer_key_prune_replay: SourceReferenceExportV0,
    meter_prune_replay: SourceReferenceExportV0,
    validator_prune_replay: SourceReferenceExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct ProofIdentifierDescriptorV0 {
    source: &'static str,
    value: String,
}

#[derive(Clone, Debug, Serialize)]
struct ProofPlanItemV0 {
    list: &'static str,
    family: u8,
    identifier: ProofIdentifierDescriptorV0,
}

#[derive(Clone, Debug, Serialize)]
struct OperationTemplateExportV0 {
    id: String,
    operation_kind: &'static str,
    operation: PocoApplicationOperationV0,
    proof_plan: Vec<ProofPlanItemV0>,
}

#[derive(Clone, Debug, Serialize)]
struct StepTemplateExportV0 {
    schema: &'static str,
    schema_version: u16,
    sequence_id: &'static str,
    id: String,
    operations: Vec<OperationTemplateExportV0>,
}

#[derive(Clone, Debug, Serialize)]
struct ExpectedRejectExportV0 {
    stage: &'static str,
    error_code: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct NegativeTemplateExportV0 {
    schema: &'static str,
    schema_version: u16,
    sequence_id: &'static str,
    id: &'static str,
    raw_operation_json_hexes: Vec<String>,
    expected_reject: ExpectedRejectExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct VerticalSequenceExportV0 {
    id: &'static str,
    execution_scope: &'static str,
    source_export_sha256_hex: String,
    steps: Vec<StepTemplateExportV0>,
    negative: Option<NegativeTemplateExportV0>,
}

#[derive(Clone, Debug, Serialize)]
struct AuthoringInputsExportV0 {
    schema: &'static str,
    schema_version: u16,
    source_exports: SourceReferencesExportV0,
    sequences: Vec<VerticalSequenceExportV0>,
}

/// Separate H3b2b2 evidence.  These records intentionally do not extend the
/// frozen application-operation authoring schema above.
#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCandidateFixtureExportV0 {
    schema: &'static str,
    schema_version: u16,
    fixture_scope: &'static str,
    compact_profile: AuthenticatedCandidateCompactProfileExportV0,
    boundary_contract: AuthenticatedCandidateBoundaryExportV0,
    positive: AuthenticatedCandidateScenarioExportV0,
    authenticated_fallback: AuthenticatedCandidateScenarioExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCandidateCompactProfileExportV0 {
    chain_id_utf8: String,
    genesis_hash_hex: String,
    epoch_length_blocks: u64,
    snapshot_lead_blocks: u64,
    maturity_epochs: u64,
    units_per_power: String,
    bond_atomic_units_per_power: String,
    evidence_window_epochs: u64,
    active_parameters_cev0_hex: String,
    active_parameters_hash_hex: String,
    active_epoch: u64,
    target_epoch: u64,
    boundary_height: u64,
    cutoff_height: u64,
    checkpoint_height: u64,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCandidateBoundaryExportV0 {
    authority: &'static str,
    from_epoch: u64,
    to_epoch: u64,
    height: u64,
    usage_rollover: &'static str,
    cleared_meter_usage: u32,
    cleared_consumer_provider_usage: u32,
    cleared_task_provider_usage: u32,
    cleared_provider_usage: u32,
    preserved_certificate_ids_hex: Vec<String>,
    installed_bonds: Vec<AuthenticatedCandidateBondExportV0>,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCandidateBondExportV0 {
    validator_id_hex: String,
    amount: String,
    locked_until: u64,
    state: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCandidateBlockStepExportV0 {
    height: u64,
    purpose: &'static str,
    raw_operation_json_hexes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCandidateSourceExportV0 {
    head_version: u64,
    head_root_hex: String,
    cutoff_version: u64,
    cutoff_root_hex: String,
    history: Vec<HistoryExportV0>,
    cutoff_projection: ProjectionExportV0,
    head_projection: ProjectionExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCandidateCheckpointExportV0 {
    block_height: u64,
    block_hash_hex: String,
    timestamp_ms: u64,
    parent_height: u64,
    parent_state_root_hex: String,
    next_state_root_hex: String,
    cutoff_entries_root_hex: String,
    cutoff_entry_count: u32,
    payload_root_hex: String,
    receipts_root_hex: String,
    checkpoint_execution_canonical_hex: String,
    execution_id_hex: String,
    authorization_id_hex: String,
    transcript_canonical_hex: String,
    transcript_digest_hex: String,
    result_canonical_hex: String,
    result_digest_hex: String,
    candidate_parameters_hash_hex: String,
    fallback_used: bool,
    fallback_reason_code: u16,
    computed_candidate_count: u32,
    computed_candidate_ids_hex: Vec<String>,
    effective_validator_set_cev0_hex: String,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCandidateScenarioExportV0 {
    id: &'static str,
    expected_fallback_used: bool,
    expected_fallback_reason_code: u16,
    block_steps: Vec<AuthenticatedCandidateBlockStepExportV0>,
    source: AuthenticatedCandidateSourceExportV0,
    checkpoint: AuthenticatedCandidateCheckpointExportV0,
}

/// Separate H3b2b3a shared evidence. It references the independently consumed
/// H3b2b2 corpus by exact file digest and adds only raw H1/H2/commitment
/// authority. No normalized transcript, status, event, or inert token becomes
/// an input to this fixture.
#[derive(Clone, Debug, Serialize)]
struct AuthenticatedNextEpochCommitmentFixtureExportV0 {
    schema: &'static str,
    schema_version: u16,
    fixture_scope: &'static str,
    candidate_vector_path: &'static str,
    candidate_vector_sha256_hex: String,
    positive: AuthenticatedNextEpochCommitmentScenarioExportV0,
    authenticated_fallback: AuthenticatedNextEpochCommitmentScenarioExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedNextEpochCommitmentScenarioExportV0 {
    id: &'static str,
    candidate_source_id: &'static str,
    candidate_binding: AuthenticatedNextEpochCandidateBindingExportV0,
    h1: AuthenticatedNextEpochH1ExportV0,
    h2: AuthenticatedNextEpochH2ExportV0,
    commitment: AuthenticatedNextEpochCommitmentExportV0,
    authorization_id_hex: String,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedNextEpochCandidateBindingExportV0 {
    authorization_id_hex: String,
    checkpoint_execution_id_hex: String,
    candidate_parameters_hash_hex: String,
    cutoff_version: u64,
    cutoff_state_root_hex: String,
    cutoff_entries_root_hex: String,
    cutoff_entry_count: u32,
    fallback_used: bool,
    fallback_reason_code: u16,
    old_validator_set_cev0_hex: String,
    old_parameters_cev0_hex: String,
    new_validator_set_cev0_hex: String,
    new_parameters_cev0_hex: String,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedNextEpochH1ExportV0 {
    cutoff_parent_header_cev0_hex: String,
    cutoff_parent_block_id_hex: String,
    cutoff_parent_timestamp_ms: u64,
    finality_proof_cev0_hex: String,
    proof_id_hex: String,
    finalized_cutoff_block_id_hex: String,
    finalized_cutoff_height: u64,
    finalized_cutoff_state_root_hex: String,
    child_block_id_hex: String,
    grandchild_block_id_hex: String,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedNextEpochH2ExportV0 {
    manifest_cev0_hex: String,
    manifest_proof: AuthenticatedNextEpochIcs23PointExportV0,
    members: Vec<AuthenticatedNextEpochMemberExportV0>,
    absences: Vec<AuthenticatedNextEpochAbsenceExportV0>,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedNextEpochMemberExportV0 {
    kind: u8,
    logical_key_hex: String,
    value_hex: String,
    canonical_entry_cev0_hex: String,
    proof: AuthenticatedNextEpochIcs23PointExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedNextEpochAbsenceExportV0 {
    kind: u8,
    logical_key_hex: String,
    proof: AuthenticatedNextEpochIcs23PointExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedNextEpochIcs23PointExportV0 {
    version: u64,
    root_hash_hex: String,
    key_hex: String,
    value_hex: Option<String>,
    commitment_proof_hex: String,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedNextEpochCommitmentExportV0 {
    cev0_hex: String,
    id_hex: String,
}

/// Dedicated H3b2b3b authoring output. This fixture is intentionally separate
/// from the epoch-zero B2-E/B2-F kernel corpora: all checkpoint, seal, and
/// handoff objects below are rebuilt on the same cutoff-25 H3 history.
#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCheckpointHandoffFixtureExportV0 {
    schema: &'static str,
    schema_version: u16,
    fixture_scope: &'static str,
    candidate_vector_path: &'static str,
    candidate_vector_sha256_hex: String,
    commitment_vector_path: &'static str,
    commitment_vector_sha256_hex: String,
    compact_profile: AuthenticatedCheckpointHandoffProfileExportV0,
    positive: AuthenticatedCheckpointHandoffScenarioExportV0,
    authenticated_fallback: AuthenticatedCheckpointHandoffScenarioExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCheckpointHandoffProfileExportV0 {
    epoch_length_blocks: u64,
    snapshot_lead_blocks: u64,
    old_epoch: u64,
    new_epoch: u64,
    cutoff_height: u64,
    checkpoint_parent_height: u64,
    checkpoint_height: u64,
    seal_1_height: u64,
    seal_2_height: u64,
    activation_height: u64,
    native_execution_profile: &'static str,
    comet_hash_mapping: Option<String>,
    aggregate_digest: Option<String>,
    epoch_anchor_qc_output: bool,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCheckpointHandoffScenarioExportV0 {
    id: &'static str,
    fallback_used: bool,
    fallback_reason_code: u16,
    cutoff: AuthenticatedCheckpointHandoffCutoffExportV0,
    preheader: AuthenticatedCheckpointHandoffPreheaderExportV0,
    checkpoint: AuthenticatedCheckpointHeaderExportV0,
    checkpoint_finality: AuthenticatedCheckpointFinalityExportV0,
    handoff: AuthenticatedCheckpointHandoffEvidenceExportV0,
    bound_authority: AuthenticatedCheckpointHandoffAuthorityExportV0,
}

/// Test-only raw-consumer material kept alongside the serialized b3b export.
///
/// The export path discards this structure and therefore remains byte-for-byte
/// unchanged. Tests retain it so cross-profile evidence can be spliced without
/// decoding JSON or reconstructing any caller-authored authority object.
struct AuthenticatedCheckpointHandoffScenarioFixtureV0 {
    export: AuthenticatedCheckpointHandoffScenarioExportV0,
    authorized_checkpoint: crate::poco_checkpoint_header::AuthorizedPocoCheckpointHeaderV0,
    checkpoint_parent_header_cev0: Vec<u8>,
    checkpoint_finality_cev0: Vec<u8>,
    raw_anchor_kernel_cev0: Vec<u8>,
    descriptor: HandoffDescriptorV0,
    old_validator_set: ValidatorSet,
    new_validator_set: ValidatorSet,
    terminal_header_cev0: Vec<u8>,
    terminal_qc_cev0: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCheckpointHandoffCutoffExportV0 {
    height: u64,
    state_root_hex: String,
    entries_root_hex: String,
    entry_count: u32,
    scheduled_cutoff_authorization_id_hex: String,
    cutoff_candidate_authorization_id_hex: String,
    raw_cutoff_parent_header_cev0_hex: String,
    raw_h1_finality_proof_cev0_hex: String,
    h1_proof_id_hex: String,
    raw_h2: AuthenticatedNextEpochH2ExportV0,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCheckpointHandoffPreheaderExportV0 {
    authorization_id_hex: String,
    checkpoint_parent_header_cev0_hex: String,
    checkpoint_parent_block_id_hex: String,
    old_validator_set_cev0_hex: String,
    old_parameters_cev0_hex: String,
    new_validator_set_cev0_hex: String,
    new_parameters_cev0_hex: String,
    commitment_cev0_hex: String,
    commitment_id_hex: String,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCheckpointHeaderExportV0 {
    native_execution_authorization_id_hex: String,
    application_payload_cev0_hex: String,
    execution_receipts_cev0_hex: String,
    transaction_count: u32,
    receipt_count: u32,
    preparation_id_hex: String,
    header_cev0_hex: String,
    native_block_id_hex: String,
    header_authorization_id_hex: String,
    height: u64,
    view: u64,
    timestamp_ms: u64,
    payload_root_hex: String,
    state_root_hex: String,
    receipts_root_hex: String,
    evidence_root_hex: String,
    next_epoch_commitment_hash_hex: String,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCheckpointFinalityExportV0 {
    raw_finality_proof_cev0_hex: String,
    proof_id_hex: String,
    checkpoint_block_id_hex: String,
    seal_1_header_cev0_hex: String,
    seal_1_block_id_hex: String,
    seal_2_header_cev0_hex: String,
    seal_2_block_id_hex: String,
    terminal_qc_cev0_hex: String,
    terminal_qc_id_hex: String,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCheckpointHandoffEvidenceExportV0 {
    descriptor_cev0_hex: String,
    descriptor_id_hex: String,
    certificate_cev0_hex: String,
    certificate_id_hex: String,
    raw_anchor_certificate_kernel_cev0_hex: String,
    old_signature_count: u32,
    new_signature_count: u32,
}

#[derive(Clone, Debug, Serialize)]
struct AuthenticatedCheckpointHandoffAuthorityExportV0 {
    checkpoint_preparation_id_hex: String,
    checkpoint_header_authorization_id_hex: String,
    checkpoint_execution_authorization_id_hex: String,
    commitment_authorization_id_hex: String,
    scheduled_cutoff_authorization_id_hex: String,
    checkpoint_finality_proof_id_hex: String,
    handoff_certificate_id_hex: String,
    joint_authorization_id_hex: String,
}

#[derive(Clone, Debug)]
struct AuthenticatedCandidateBoundaryFactsV0 {
    cleared_meter_usage: u32,
    cleared_consumer_provider_usage: u32,
    cleared_task_provider_usage: u32,
    cleared_provider_usage: u32,
    preserved_certificate_ids_hex: Vec<String>,
}

#[derive(Clone, Debug)]
enum ProofSubjectV0 {
    Literal([u8; 32]),
    Decision(&'static str),
}

#[derive(Clone, Debug)]
struct ProofRequestV0 {
    list: &'static str,
    family: PocoNullifierFamilyV0,
    subject: ProofSubjectV0,
}

#[derive(Clone, Debug, Default)]
struct FixtureNullifierSetV0 {
    occupied: Vec<(PocoNullifierFamilyV0, [u8; 32])>,
}

impl FixtureNullifierSetV0 {
    fn keys(&self) -> Vec<[u8; 32]> {
        self.occupied
            .iter()
            .map(|(family, identifier)| derive_poco_nullifier_key_v0(*family, *identifier))
            .collect()
    }

    fn contains(&self, family: PocoNullifierFamilyV0, identifier: [u8; 32]) -> bool {
        self.occupied.contains(&(family, identifier))
    }

    fn sort(&mut self) {
        self.occupied.sort();
    }
}

#[derive(Clone, Debug)]
struct BuiltOperationV0 {
    raw: Vec<u8>,
    template: OperationTemplateExportV0,
}

#[derive(Clone)]
struct FixtureChainV0 {
    tree: InMemoryAuthTree,
    projection: ProductionPocoProjectionV0,
    source_version: u64,
    source_root: [u8; 32],
    chain_id: ChainId,
    genesis_hash: GenesisHash,
    active_epoch: Epoch,
    active_parameters: ConsensusParametersV0,
    authority_signer_commitment: [u8; 32],
    nullifiers: FixtureNullifierSetV0,
    // The frozen H3b2b1 authoring path carries the full production InitChain
    // export.  The independent H3b2b2 fixture starts from a purpose-built
    // authenticated namespace and therefore deliberately has no Core-genesis
    // side object to misrepresent as transition authority.
    active_genesis: Option<ActiveGenesisExportV0>,
    history: Vec<HistoryExportV0>,
}

impl FixtureChainV0 {
    fn context(&self) -> Result<AuthenticatedPocoApplicationContextV0> {
        AuthenticatedPocoApplicationContextV0::new(
            self.source_version,
            self.source_root,
            Height::new(
                self.source_version
                    .checked_add(1)
                    .context("fixture target height overflow")?,
            ),
            self.chain_id,
            self.genesis_hash,
            self.active_epoch,
            self.active_parameters,
            self.authority_signer_commitment,
        )
    }

    fn start_overlay(&self) -> Result<PocoApplicationBlockOverlayV0> {
        PocoApplicationBlockOverlayV0::from_projection(self.context()?, &self.projection)
    }

    fn commit_block(
        &mut self,
        block: PocoApplicationBlockOverlayV0,
        next_nullifiers: FixtureNullifierSetV0,
    ) -> Result<()> {
        let target = self
            .source_version
            .checked_add(1)
            .context("fixture target version overflow")?;
        let sealed = block.seal()?;
        ensure!(
            sealed.source_version() == self.source_version
                && sealed.source_root() == self.source_root
                && sealed.target_height().get() == target,
            "fixture sealed plan context drift"
        );
        let writes = auth_writes_from_sealed_poco_application_v0(&sealed)?;
        self.commit_fixture_writes(writes)?;
        self.nullifiers = next_nullifiers;
        Ok(())
    }

    /// Commits one exact authenticated version and records the complete
    /// physical write set. This is also used for the explicitly labelled
    /// fixture-only epoch bootstrap and scheduled manifest refresh; neither
    /// path is represented as an application business operation.
    fn commit_fixture_writes(&mut self, writes: Vec<AuthWrite>) -> Result<()> {
        let target = self
            .source_version
            .checked_add(1)
            .context("fixture target version overflow")?;
        let exported_writes = writes
            .iter()
            .map(|write| PhysicalWriteExportV0 {
                physical_key_hex: hex::encode(write.key()),
                value_hex: write.value().map(hex::encode),
            })
            .collect::<Vec<_>>();
        self.tree.put_value_set(target, writes)?;
        self.source_root = self
            .tree
            .root_hash(target)
            .context("fixture target JMT root missing")?
            .into();
        self.source_version = target;
        self.projection = projection_at(&self.tree, target)?;
        self.history.push(HistoryExportV0 {
            version: target,
            jmt_root_hex: hex::encode(self.source_root),
            writes: exported_writes,
        });
        Ok(())
    }

    fn advance_empty_versions(&mut self, target_version: u64) -> Result<()> {
        while self.source_version < target_version {
            let version = self
                .source_version
                .checked_add(1)
                .context("fixture empty-version overflow")?;
            self.tree
                .put_value_set(version, std::iter::empty())
                .context("advance fixture empty authenticated version")?;
            self.source_root = self
                .tree
                .root_hash(version)
                .context("fixture empty target root missing")?
                .into();
            self.source_version = version;
            self.history.push(HistoryExportV0 {
                version,
                jmt_root_hex: hex::encode(self.source_root),
                writes: Vec::new(),
            });
        }
        Ok(())
    }
}

#[derive(Clone)]
struct CertificateFixtureV0 {
    consumer_id: Vec<u8>,
    consumer_key_id: Vec<u8>,
    provider_id: Vec<u8>,
    task_id: Vec<u8>,
    meter_id: Vec<u8>,
    consumer_signing_key: SigningKey,
    provider_signing_key: SigningKey,
    output_commitment: [u8; 32],
    settlement_commitment: [u8; 32],
    certificate: ConsumptionCertificateV0,
}

fn exact_hash32(value: &str, label: &str) -> Result<[u8; 32]> {
    hex::decode(value)
        .with_context(|| format!("decode {label}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} is not Hash32"))
}

fn decode_write(write: &PhysicalWriteExportV0) -> Result<AuthWrite> {
    let key = hex::decode(&write.physical_key_hex).context("decode fixture physical key")?;
    let value = write
        .value_hex
        .as_deref()
        .map(hex::decode)
        .transpose()
        .context("decode fixture physical value")?;
    let poco = poco_snapshot_key_components(&key)?.is_some();
    match (poco, value) {
        (true, Some(value)) => {
            AuthWrite::put_poco_snapshot(PocoWritePermitV0::test_only(), key, value)
        }
        (true, None) => AuthWrite::delete_poco_snapshot(PocoWritePermitV0::test_only(), key),
        (false, Some(value)) => AuthWrite::put(key, value),
        (false, None) => AuthWrite::delete(key),
    }
}

fn projection_at(tree: &InMemoryAuthTree, version: u64) -> Result<ProductionPocoProjectionV0> {
    let mut live = tree
        .verified_live_values(version)
        .context("read fixture authenticated state")?;
    take_and_validate_production_poco_projection_v0(version, &mut live)?
        .context("fixture has no active PoCO projection")
}

fn load_full_source(path: &Path) -> Result<(FullSourceExportV0, Vec<u8>, FixtureChainV0)> {
    let raw = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let source: FullSourceExportV0 =
        serde_json::from_slice(&raw).context("decode full application source export")?;
    ensure!(
        source.schema == FULL_SOURCE_SCHEMA && source.schema_version == 0,
        "full application source schema mismatch"
    );
    let mut tree = InMemoryAuthTree::default();
    for history in &source.initial.history {
        ensure!(
            history.version == tree.expected_next_version(),
            "full source JMT history is not contiguous"
        );
        let writes = history
            .writes
            .iter()
            .map(decode_write)
            .collect::<Result<Vec<_>>>()?;
        tree.put_value_set(history.version, writes)?;
        ensure!(
            hex::encode(<[u8; 32]>::from(
                tree.root_hash(history.version)
                    .context("full source history root missing")?,
            ),) == history.jmt_root_hex,
            "full source history root mismatch"
        );
    }
    let source_version = source.initial.version;
    let source_root = exact_hash32(&source.initial.jmt_root_hex, "full source root")?;
    ensure!(
        tree.root_hash(source_version).map(<[u8; 32]>::from) == Some(source_root),
        "full source head/root mismatch"
    );
    let projection = projection_at(&tree, source_version)?;
    ensure!(
        hex::encode(projection.manifest().encode()) == source.initial.projection.manifest_hex,
        "full source projection manifest mismatch"
    );
    let context = &source.initial.production_context;
    ensure!(
        context.source_version == source_version
            && exact_hash32(&context.source_root_hex, "production context root")? == source_root,
        "production context does not bind full source head"
    );
    let active_parameters = decode_consensus_parameters_v0_exact(
        &hex::decode(&context.active_parameters_cev0_hex)
            .context("decode production active parameters")?,
    )
    .map_err(|error| anyhow::anyhow!("decode production active parameters: {error:?}"))?;
    ensure!(
        hex::encode(active_parameters.hash().as_bytes()) == context.active_parameters_hash_hex,
        "production parameter hash mismatch"
    );
    ensure!(
        source.authoring_nullifier_state.occupied.is_empty()
            && source.authoring_nullifier_state.count == 0,
        "full source fixture is not an empty nullifier genesis"
    );
    let chain = FixtureChainV0 {
        tree,
        projection,
        source_version,
        source_root,
        chain_id: ChainId::new(&context.chain_id_utf8)
            .map_err(|error| anyhow::anyhow!("invalid fixture chain ID: {error:?}"))?,
        genesis_hash: GenesisHash::new(exact_hash32(
            &context.genesis_hash_hex,
            "production genesis hash",
        )?),
        active_epoch: Epoch::new(context.active_epoch),
        active_parameters,
        authority_signer_commitment: exact_hash32(
            &context.authority_signer_commitment_hex,
            "production signer commitment",
        )?,
        nullifiers: FixtureNullifierSetV0::default(),
        active_genesis: Some(source.initial.active_genesis.clone()),
        history: source.initial.history.clone(),
    };
    // This invokes the exact constructor and production projection validator;
    // JSON context is evidence to compare, not an unchecked operation permit.
    chain.context()?;
    Ok((source, raw, chain))
}

fn projection_export(chain: &FixtureChainV0) -> ProjectionExportV0 {
    projection_value_export(&chain.projection)
}

fn projection_value_export(projection: &ProductionPocoProjectionV0) -> ProjectionExportV0 {
    ProjectionExportV0 {
        manifest_hex: hex::encode(projection.manifest().encode()),
        entries_root_hex: hex::encode(projection.manifest().entries_root()),
        entries: projection
            .entries()
            .iter()
            .map(|entry| EntryExportV0 {
                kind: entry.kind as u8,
                logical_key_hex: hex::encode(&entry.logical_key),
                value_hex: hex::encode(&entry.value),
                canonical_entry_cev0_hex: hex::encode(entry.canonical_bytes()),
            })
            .collect(),
    }
}

fn nullifier_export(chain: &FixtureChainV0) -> AuthoringNullifierStateExportV0 {
    let keys = chain.nullifiers.keys();
    let mut probe = [0xff; 32];
    while keys.contains(&probe) {
        let mut carry = true;
        for byte in probe.iter_mut().rev() {
            let (next, overflow) = byte.overflowing_sub(u8::from(carry));
            *byte = next;
            carry = overflow;
            if !carry {
                break;
            }
        }
        assert!(!carry, "fixture nullifier probe space exhausted");
    }
    AuthoringNullifierStateExportV0 {
        root_hex: hex::encode(
            test_non_membership_proof_for_keys_v0(&keys, probe)
                .expect("fixture nullifier state is canonical")
                .non_membership_root(),
        ),
        count: u64::try_from(chain.nullifiers.occupied.len())
            .expect("fixture nullifier hard bound fits u64"),
        occupied: chain
            .nullifiers
            .occupied
            .iter()
            .map(|(family, identifier)| OccupiedNullifierExportV0 {
                family: family.code(),
                identifier_hex: hex::encode(identifier),
            })
            .collect(),
    }
}

fn initial_export(chain: &FixtureChainV0) -> InitialExportV0 {
    let active_parameters = chain.active_parameters.canonical_bytes();
    InitialExportV0 {
        version: chain.source_version,
        jmt_root_hex: hex::encode(chain.source_root),
        active_genesis: chain
            .active_genesis
            .clone()
            .expect("full-source fixture carries active InitChain evidence"),
        production_context: ProductionContextExportV0 {
            chain_id_utf8: String::from_utf8(chain.chain_id.as_bytes().to_vec())
                .expect("validated chain ID is UTF-8"),
            genesis_hash_hex: hex::encode(chain.genesis_hash.as_bytes()),
            source_version: chain.source_version,
            source_root_hex: hex::encode(chain.source_root),
            target_height: chain
                .source_version
                .checked_add(1)
                .expect("fixture target height fits u64"),
            active_epoch: chain.active_epoch.get(),
            active_parameters_cev0_hex: hex::encode(active_parameters),
            active_parameters_hash_hex: hex::encode(chain.active_parameters.hash().as_bytes()),
            authority_signer_commitment_hex: hex::encode(chain.authority_signer_commitment),
        },
        history: chain.history.clone(),
        projection: projection_export(chain),
    }
}

fn write_isolated_source(
    path: &Path,
    chain: &FixtureChainV0,
    lineage_base_intent: LineageBaseIntentExportV0,
) -> Result<(SourceReferenceExportV0, Vec<u8>)> {
    let source = IsolatedSourceExportV0 {
        schema: ISOLATED_SOURCE_SCHEMA,
        schema_version: 0,
        lineage_base_intent,
        initial: initial_export(chain),
        authoring_nullifier_state: nullifier_export(chain),
    };
    let raw = serde_json::to_vec_pretty(&source).context("encode isolated prune source")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create isolated source parent {}", parent.display()))?;
    }
    fs::write(path, &raw).with_context(|| format!("write {}", path.display()))?;
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    Ok((
        SourceReferenceExportV0 {
            path: canonical.display().to_string(),
            sha256_hex: hex::encode(Sha256::digest(&raw)),
            schema: ISOLATED_SOURCE_SCHEMA.to_string(),
        },
        raw,
    ))
}

fn joined_identity(parts: &[&[u8]]) -> Vec<u8> {
    let mut identity = Vec::new();
    for part in parts {
        encode_bytes(&mut identity, part);
    }
    identity
}

fn optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

fn optional_hash32(output: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value);
        }
        None => output.push(0),
    }
}

fn semantic_change(
    block: &PocoApplicationBlockOverlayV0,
    kind: PocoSnapshotEntryKindV0,
    identity: &[u8],
    payload: &[u8],
) -> Result<RawSemanticChangeV0> {
    let logical_key = semantic_identity_digest_v0(kind, identity).to_vec();
    let current = block
        .overlay
        .entries
        .get(&(kind, logical_key.clone()))
        .cloned();
    let revision = match current.as_deref() {
        Some(value) => decode_poco_snapshot_value_parts_v0_exact(kind, &logical_key, value)?
            .verified
            .revision()
            .checked_add(1)
            .context("fixture semantic revision exhausted")?,
        None => 1,
    };
    let next = encode_test_semantic_envelope_v0(kind, revision, identity, payload);
    Ok(RawSemanticChangeV0 {
        kind: kind as u8,
        logical_key_hex: hex::encode(logical_key),
        next_value_hex: Some(hex::encode(next)),
    })
}

fn semantic_delete(
    block: &PocoApplicationBlockOverlayV0,
    kind: PocoSnapshotEntryKindV0,
    identity: &[u8],
) -> Result<RawSemanticChangeV0> {
    let logical_key = semantic_identity_digest_v0(kind, identity).to_vec();
    ensure!(
        block
            .overlay
            .entries
            .contains_key(&(kind, logical_key.clone())),
        "fixture semantic delete lacks authenticated source entry"
    );
    Ok(RawSemanticChangeV0 {
        kind: kind as u8,
        logical_key_hex: hex::encode(logical_key),
        next_value_hex: None,
    })
}

fn semantic_delete_key(
    block: &PocoApplicationBlockOverlayV0,
    kind: PocoSnapshotEntryKindV0,
    logical_key: Vec<u8>,
) -> Result<RawSemanticChangeV0> {
    ensure!(
        block
            .overlay
            .entries
            .contains_key(&(kind, logical_key.clone())),
        "fixture semantic delete lacks authenticated logical key"
    );
    Ok(RawSemanticChangeV0 {
        kind: kind as u8,
        logical_key_hex: hex::encode(logical_key),
        next_value_hex: None,
    })
}

fn decision_map(
    context: &AuthenticatedPocoApplicationContextV0,
    operation: &mut PocoApplicationOperationV0,
) -> Result<BTreeMap<&'static str, [u8; 32]>> {
    let preimage = decision_preimage_digest_v0(context, operation)?;
    let mut decisions = BTreeMap::new();
    let mut bind = |label: &'static str, target: &mut String| {
        let decision = derived_decision_id_v0(preimage, label.as_bytes());
        *target = hex::encode(decision);
        decisions.insert(label, decision);
    };
    match &mut operation.body {
        PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            decision_id_hex, ..
        } => bind("authorize-consumer-key", decision_id_hex),
        PocoApplicationOperationBodyV0::RevokeConsumerKey {
            decision_id_hex, ..
        } => bind("revoke-consumer-key", decision_id_hex),
        PocoApplicationOperationBodyV0::DefineMeterPolicy {
            decision_id_hex, ..
        } => bind("define-meter", decision_id_hex),
        PocoApplicationOperationBodyV0::RetireMeterPolicy {
            decision_id_hex, ..
        } => bind("retire-meter", decision_id_hex),
        PocoApplicationOperationBodyV0::FundSettlement {
            funding_decision_id_hex,
            ..
        } => bind("fund-settlement", funding_decision_id_hex),
        PocoApplicationOperationBodyV0::AcceptCertificate {
            acceptance_decision_id_hex,
            meter_decision_id_hex,
            evidence_decision_id_hex,
            ..
        } => {
            bind("accept-certificate", acceptance_decision_id_hex);
            bind("meter-certificate", meter_decision_id_hex);
            bind("evidence-certificate", evidence_decision_id_hex);
        }
        PocoApplicationOperationBodyV0::ReleaseSettlement {
            release_decision_id_hex,
            ..
        } => bind("release-settlement", release_decision_id_hex),
        PocoApplicationOperationBodyV0::OpenChallenge {
            challenge_id_hex,
            opening_decision_id_hex,
            ..
        } => {
            bind("challenge-id", challenge_id_hex);
            bind("open-challenge", opening_decision_id_hex);
        }
        PocoApplicationOperationBodyV0::ResolveChallenge {
            resolution_decision_id_hex,
            ..
        } => bind("resolve-challenge", resolution_decision_id_hex),
        PocoApplicationOperationBodyV0::ProposeGovernance {
            proposal_decision_id_hex,
            ..
        } => bind("propose-governance", proposal_decision_id_hex),
        PocoApplicationOperationBodyV0::ApproveGovernance {
            decision_id_hex, ..
        } => bind("approve-governance", decision_id_hex),
        PocoApplicationOperationBodyV0::RegisterValidator {
            registration_decision_id_hex,
            ..
        } => bind("register-validator", registration_decision_id_hex),
        PocoApplicationOperationBodyV0::RotateValidator {
            registration_decision_id_hex,
            ..
        } => bind("rotate-validator", registration_decision_id_hex),
        PocoApplicationOperationBodyV0::RegisterFutureCandidate {
            registration_decision_id_hex,
            ..
        } => bind("register-future-candidate", registration_decision_id_hex),
        PocoApplicationOperationBodyV0::RevokeValidator {
            revocation_decision_id_hex,
            ..
        } => bind("revoke-validator", revocation_decision_id_hex),
        PocoApplicationOperationBodyV0::PruneRevokedConsumerKey { .. }
        | PocoApplicationOperationBodyV0::PruneRetiredMeter { .. }
        | PocoApplicationOperationBodyV0::PruneRevokedValidatorHistory { .. }
        | PocoApplicationOperationBodyV0::PruneExpiredCertificate { .. } => {}
    }
    Ok(decisions)
}

fn zero_decisions(body: &mut PocoApplicationOperationBodyV0) {
    let zero = "0".repeat(64);
    match body {
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
        } => *decision_id_hex = zero,
        PocoApplicationOperationBodyV0::FundSettlement {
            funding_decision_id_hex,
            ..
        } => *funding_decision_id_hex = zero,
        PocoApplicationOperationBodyV0::AcceptCertificate {
            acceptance_decision_id_hex,
            meter_decision_id_hex,
            evidence_decision_id_hex,
            ..
        } => {
            *acceptance_decision_id_hex = zero.clone();
            *meter_decision_id_hex = zero.clone();
            *evidence_decision_id_hex = zero;
        }
        PocoApplicationOperationBodyV0::ReleaseSettlement {
            release_decision_id_hex,
            ..
        } => *release_decision_id_hex = zero,
        PocoApplicationOperationBodyV0::OpenChallenge {
            challenge_id_hex,
            opening_decision_id_hex,
            ..
        } => {
            *challenge_id_hex = zero.clone();
            *opening_decision_id_hex = zero;
        }
        PocoApplicationOperationBodyV0::ResolveChallenge {
            resolution_decision_id_hex,
            ..
        } => *resolution_decision_id_hex = zero,
        PocoApplicationOperationBodyV0::ProposeGovernance {
            proposal_decision_id_hex,
            ..
        } => *proposal_decision_id_hex = zero,
        PocoApplicationOperationBodyV0::ApproveGovernance {
            decision_id_hex, ..
        } => *decision_id_hex = zero,
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
}

fn normalized_business_intent_digest(operation: &PocoApplicationOperationV0) -> Result<[u8; 32]> {
    let raw = serde_json::to_vec(operation).context("encode exact fixture operation")?;
    Ok(crate::poco_application_evidence::application_business_intent_digest_v0(&raw))
}

type FinishedOperationV0 = (
    BuiltOperationV0,
    FixtureNullifierSetV0,
    BTreeMap<&'static str, [u8; 32]>,
);

fn finish_operation(
    block: &PocoApplicationBlockOverlayV0,
    operation_id: &str,
    operation_kind: &'static str,
    body: PocoApplicationOperationBodyV0,
    semantic_changes: Vec<RawSemanticChangeV0>,
    proof_requests: Vec<ProofRequestV0>,
    source_nullifiers: &FixtureNullifierSetV0,
) -> Result<FinishedOperationV0> {
    finish_operation_with_proof_basis(
        block,
        operation_id,
        operation_kind,
        body,
        semantic_changes,
        proof_requests,
        source_nullifiers,
        source_nullifiers,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_operation_with_proof_basis(
    block: &PocoApplicationBlockOverlayV0,
    operation_id: &str,
    operation_kind: &'static str,
    body: PocoApplicationOperationBodyV0,
    mut semantic_changes: Vec<RawSemanticChangeV0>,
    proof_requests: Vec<ProofRequestV0>,
    authority_nullifiers: &FixtureNullifierSetV0,
    proof_basis: &FixtureNullifierSetV0,
) -> Result<FinishedOperationV0> {
    semantic_changes.sort_by(|left, right| {
        (left.kind, left.logical_key_hex.as_str())
            .cmp(&(right.kind, right.logical_key_hex.as_str()))
    });
    let mut operation = PocoApplicationOperationV0 {
        schema: POCO_APPLICATION_OPERATION_SCHEMA_V0.to_string(),
        target_height: block.context.target_height.get(),
        expected_state_revision: block.overlay.authority.revision,
        body,
        semantic_changes,
        nullifier_non_membership_checks: Vec::new(),
        nullifier_insertions: Vec::new(),
    };
    let decisions = decision_map(&block.context, &mut operation)?;

    let mut resolved = proof_requests
        .into_iter()
        .map(|request| {
            let identifier = match request.subject {
                ProofSubjectV0::Literal(identifier) => identifier,
                ProofSubjectV0::Decision(label) => *decisions
                    .get(label)
                    .unwrap_or_else(|| panic!("missing derived fixture decision {label}")),
            };
            (request, identifier)
        })
        .collect::<Vec<_>>();
    resolved.sort_by_key(|(request, identifier)| (request.list, request.family, *identifier));
    let mut next_nullifiers = proof_basis.clone();
    let source_keys = proof_basis.keys();
    let mut raw_absences = Vec::new();
    let mut raw_insertions = Vec::new();
    let mut plan = Vec::new();
    for (request, identifier) in resolved
        .iter()
        .filter(|(request, _)| request.list == "non_membership")
    {
        ensure!(
            !proof_basis.contains(request.family, *identifier),
            "fixture non-membership subject is already occupied"
        );
        let key = derive_poco_nullifier_key_v0(request.family, *identifier);
        let proof = test_non_membership_proof_for_keys_v0(&source_keys, key)?;
        raw_absences.push(RawNullifierInsertionV0 {
            family: request.family.code(),
            identifier_hex: hex::encode(identifier),
            proof_hex: hex::encode(proof.canonical_bytes()),
        });
        plan.push(proof_plan_item(request, *identifier));
    }
    for (request, identifier) in resolved
        .iter()
        .filter(|(request, _)| request.list == "insertion")
    {
        ensure!(
            !next_nullifiers.contains(request.family, *identifier),
            "fixture insertion subject is already occupied"
        );
        let key = derive_poco_nullifier_key_v0(request.family, *identifier);
        let proof = test_non_membership_proof_for_keys_v0(&next_nullifiers.keys(), key)?;
        raw_insertions.push(RawNullifierInsertionV0 {
            family: request.family.code(),
            identifier_hex: hex::encode(identifier),
            proof_hex: hex::encode(proof.canonical_bytes()),
        });
        next_nullifiers.occupied.push((request.family, *identifier));
        plan.push(proof_plan_item(request, *identifier));
    }
    next_nullifiers.sort();
    if std::ptr::eq(authority_nullifiers, proof_basis) {
        ensure!(
            next_nullifiers.occupied.len()
                == authority_nullifiers
                    .occupied
                    .len()
                    .checked_add(
                        resolved
                            .iter()
                            .filter(|(request, _)| request.list == "insertion")
                            .count(),
                    )
                    .context("fixture nullifier count overflow")?,
            "fixture positive nullifier transition count drift"
        );
    }
    operation.nullifier_non_membership_checks = raw_absences;
    operation.nullifier_insertions = raw_insertions;
    let raw = serde_json::to_vec(&operation).context("encode fixture production operation")?;
    ensure!(
        PocoApplicationOperationV0::decode_exact(&raw)? == operation,
        "fixture operation is not exact production JSON"
    );
    let mut template_operation = operation;
    zero_decisions(&mut template_operation.body);
    template_operation.nullifier_non_membership_checks.clear();
    template_operation.nullifier_insertions.clear();
    Ok((
        BuiltOperationV0 {
            raw,
            template: OperationTemplateExportV0 {
                id: operation_id.to_string(),
                operation_kind,
                operation: template_operation,
                proof_plan: plan,
            },
        },
        next_nullifiers,
        decisions,
    ))
}

fn append_stale_permanent_identity_insertion(
    raw: &[u8],
    valid_prefix_state: &FixtureNullifierSetV0,
    family: PocoNullifierFamilyV0,
    identifier: [u8; 32],
) -> Result<Vec<u8>> {
    ensure!(
        valid_prefix_state.contains(family, identifier),
        "fixture stale identity subject is not occupied after prune"
    );
    let mut stale = valid_prefix_state.clone();
    stale
        .occupied
        .retain(|(occupied_family, occupied_identifier)| {
            !(*occupied_family == family && *occupied_identifier == identifier)
        });
    stale.sort();
    let key = derive_poco_nullifier_key_v0(family, identifier);
    let proof = test_non_membership_proof_for_keys_v0(&stale.keys(), key)?;
    let mut operation = PocoApplicationOperationV0::decode_exact(raw)?;
    ensure!(
        operation
            .nullifier_insertions
            .last()
            .is_none_or(|last| last.family < family.code()),
        "fixture permanent identity proof is not the canonical final insertion"
    );
    operation
        .nullifier_insertions
        .push(RawNullifierInsertionV0 {
            family: family.code(),
            identifier_hex: hex::encode(identifier),
            proof_hex: hex::encode(proof.canonical_bytes()),
        });
    let raw = serde_json::to_vec(&operation).context("encode stale identity replay operation")?;
    ensure!(
        PocoApplicationOperationV0::decode_exact(&raw)? == operation,
        "stale identity replay operation is not exact production JSON"
    );
    Ok(raw)
}

fn proof_plan_item(request: &ProofRequestV0, identifier: [u8; 32]) -> ProofPlanItemV0 {
    let (source, value) = match request.subject {
        ProofSubjectV0::Literal(_) => ("literal", hex::encode(identifier)),
        ProofSubjectV0::Decision(label) => ("decision", label.to_string()),
    };
    ProofPlanItemV0 {
        list: request.list,
        family: request.family.code(),
        identifier: ProofIdentifierDescriptorV0 { source, value },
    }
}

fn signature64(signing_key: &SigningKey, message: &[u8]) -> Signature64 {
    Signature64::from_array(signing_key.sign(message).to_bytes())
}

fn tagged_fixture_id(prefix: &[u8], suffix: u8) -> Vec<u8> {
    let mut value = Vec::with_capacity(prefix.len().saturating_add(1));
    value.extend_from_slice(prefix);
    value.push(suffix);
    value
}

fn provider_fixture_signing_key_for_id(validator_id: &[u8]) -> SigningKey {
    let mut preimage = b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:".to_vec();
    preimage.extend_from_slice(validator_id);
    let seed: [u8; 32] = Sha256::digest(preimage).into();
    SigningKey::from_bytes(&seed)
}

fn certificate_fixture(chain: &FixtureChainV0) -> Result<CertificateFixtureV0> {
    certificate_fixture_for_provider(chain, b'a', 0, b"validator-a")
}

fn certificate_fixture_for_provider(
    chain: &FixtureChainV0,
    suffix: u8,
    ordinal: u8,
    provider_id: &[u8],
) -> Result<CertificateFixtureV0> {
    let consumer_id = tagged_fixture_id(b"consumer-", suffix);
    let consumer_key_id = tagged_fixture_id(b"consumer-key-", suffix);
    let provider_id = provider_id.to_vec();
    let task_id = tagged_fixture_id(b"task-", suffix);
    let meter_id = tagged_fixture_id(b"meter-", suffix);
    let consumer_seed = 33u8
        .checked_add(ordinal)
        .context("candidate consumer fixture seed overflow")?;
    let consumer_signing_key = SigningKey::from_bytes(&[consumer_seed; 32]);
    let provider_signing_key = provider_fixture_signing_key_for_id(&provider_id);
    let output_byte = 0x44u8
        .checked_add(ordinal)
        .context("candidate output fixture byte overflow")?;
    let settlement_byte = 0x55u8
        .checked_add(ordinal)
        .context("candidate settlement fixture byte overflow")?;
    let output_commitment = [output_byte; 32];
    let settlement_commitment = [settlement_byte; 32];
    let body = ConsumptionCertificateBodyV0::new(
        chain.genesis_hash,
        chain.chain_id,
        ValidatorId::from_bytes(&provider_id)
            .map_err(|error| anyhow::anyhow!("provider ID: {error:?}"))?,
        ValidatorId::from_bytes(&consumer_id)
            .map_err(|error| anyhow::anyhow!("consumer ID: {error:?}"))?,
        ValidatorId::from_bytes(&consumer_key_id)
            .map_err(|error| anyhow::anyhow!("consumer key ID: {error:?}"))?,
        task_id.clone(),
        output_commitment,
        meter_id.clone(),
        1,
        10,
        Height::new(1),
        Height::new(1),
        1,
        settlement_commitment,
        None,
    )
    .map_err(|error| anyhow::anyhow!("certificate fixture body: {error:?}"))?;
    let certificate = ConsumptionCertificateV0::new(
        body.clone(),
        signature64(&consumer_signing_key, body.digest().as_bytes()),
    )
    .map_err(|error| anyhow::anyhow!("certificate fixture: {error:?}"))?;
    Ok(CertificateFixtureV0 {
        consumer_id,
        consumer_key_id,
        provider_id,
        task_id,
        meter_id,
        consumer_signing_key,
        provider_signing_key,
        output_commitment,
        settlement_commitment,
        certificate,
    })
}

fn validator_pop(
    chain: &FixtureChainV0,
    signing_key: &SigningKey,
    validator_id: &[u8],
    nonce: u64,
) -> Result<ValidatorKeyProofOfPossessionV0> {
    validator_pop_at_epoch(chain, signing_key, validator_id, nonce, chain.active_epoch)
}

fn validator_pop_at_epoch(
    chain: &FixtureChainV0,
    signing_key: &SigningKey,
    validator_id: &[u8],
    nonce: u64,
    target_epoch: Epoch,
) -> Result<ValidatorKeyProofOfPossessionV0> {
    let validator_id = ValidatorId::from_bytes(validator_id)
        .map_err(|error| anyhow::anyhow!("validator fixture ID: {error:?}"))?;
    let public_key =
        trnm_consensus_types::ConsensusPublicKey::new(signing_key.verifying_key().to_bytes());
    let unsigned = ValidatorKeyProofOfPossessionV0::new(ValidatorKeyProofOfPossessionV0Fields {
        schema_version: SCHEMA_VERSION_V0,
        genesis_hash: chain.genesis_hash,
        chain_id: chain.chain_id,
        target_epoch,
        validator_id,
        public_key,
        registration_nonce: nonce,
        signature: Signature64::from_array([0; 64]),
    })
    .map_err(|error| anyhow::anyhow!("unsigned validator PoP fixture: {error:?}"))?;
    ValidatorKeyProofOfPossessionV0::new(ValidatorKeyProofOfPossessionV0Fields {
        signature: signature64(signing_key, unsigned.signing_root().as_bytes()),
        ..unsigned.fields()
    })
    .map_err(|error| anyhow::anyhow!("validator PoP fixture: {error:?}"))
}

fn authorize_consumer_key(
    block: &PocoApplicationBlockOverlayV0,
    fixture: &CertificateFixtureV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let identity = joined_identity(&[&fixture.consumer_id, &fixture.consumer_key_id]);
    let mut payload = identity.clone();
    payload.extend_from_slice(&fixture.consumer_signing_key.verifying_key().to_bytes());
    payload.extend_from_slice(&block.context.target_height.get().to_be_bytes());
    optional_u64(&mut payload, None);
    let change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
        &identity,
        &payload,
    )?;
    let identity_digest = exact_hash32(&change.logical_key_hex, "consumer-key logical key")?;
    let (built, next, _) = finish_operation(
        block,
        "authorize-consumer-key",
        "authorize_consumer_key",
        PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            consumer_id_hex: hex::encode(&fixture.consumer_id),
            consumer_key_id_hex: hex::encode(&fixture.consumer_key_id),
            public_key_hex: hex::encode(fixture.consumer_signing_key.verifying_key().to_bytes()),
            active_from_height: block.context.target_height.get(),
            decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::ConsumerKeyDecision,
                subject: ProofSubjectV0::Decision("authorize-consumer-key"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::ConsumerKeyIdentity,
                subject: ProofSubjectV0::Literal(identity_digest),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next))
}

fn revoke_consumer_key(
    block: &PocoApplicationBlockOverlayV0,
    fixture: &CertificateFixtureV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let identity = joined_identity(&[&fixture.consumer_id, &fixture.consumer_key_id]);
    let mut payload = identity.clone();
    payload.extend_from_slice(&fixture.consumer_signing_key.verifying_key().to_bytes());
    payload.extend_from_slice(&1u64.to_be_bytes());
    optional_u64(&mut payload, Some(block.context.target_height.get()));
    let change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
        &identity,
        &payload,
    )?;
    let (built, next, _) = finish_operation(
        block,
        "revoke-consumer-key",
        "revoke_consumer_key",
        PocoApplicationOperationBodyV0::RevokeConsumerKey {
            consumer_id_hex: hex::encode(&fixture.consumer_id),
            consumer_key_id_hex: hex::encode(&fixture.consumer_key_id),
            public_key_hex: hex::encode(fixture.consumer_signing_key.verifying_key().to_bytes()),
            active_from_height: 1,
            revoked_at_height: block.context.target_height.get(),
            decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::ConsumerKeyDecision,
            subject: ProofSubjectV0::Decision("revoke-consumer-key"),
        }],
        nullifiers,
    )?;
    Ok((built, next))
}

fn consumer_key_full_capacity_with_watermark_chain_v0(
) -> Result<(FixtureChainV0, [CertificateFixtureV0; 4])> {
    let mut chain = authenticated_candidate_genesis_v0()?;
    let fixtures = [
        certificate_fixture_for_provider(&chain, b'a', 0, b"validator-a")?,
        certificate_fixture_for_provider(&chain, b'b', 1, b"validator-b")?,
        certificate_fixture_for_provider(&chain, b'c', 2, b"validator-c")?,
        certificate_fixture_for_provider(&chain, b'd', 3, b"validator-d")?,
    ];
    let mut authorization_block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    let mut first_funding_decision = None;
    for (index, fixture) in fixtures.iter().enumerate() {
        let (authorization, next) =
            authorize_consumer_key(&authorization_block, fixture, &nullifiers)?;
        authorization_block.apply_raw(&authorization.raw)?;
        nullifiers = next;
        if index == 0 {
            let (meter, next) = define_meter(&authorization_block, fixture, &nullifiers)?;
            authorization_block.apply_raw(&meter.raw)?;
            nullifiers = next;
            let (provider, next) =
                register_provider(&authorization_block, &chain, fixture, &nullifiers)?;
            authorization_block.apply_raw(&provider.raw)?;
            nullifiers = next;
            let (funding, next, funding_decision) =
                fund_settlement(&authorization_block, fixture, &nullifiers)?;
            authorization_block.apply_raw(&funding.raw)?;
            nullifiers = next;
            first_funding_decision = Some(funding_decision);
        }
    }
    ensure!(
        authorization_block.overlay.authority.consumer_keys.len() == MAX_CONSUMER_KEY_AUTHORITIES,
        "revoke capacity fixture did not fill the consumer-key family"
    );
    chain.commit_block(authorization_block, nullifiers)?;

    let mut acceptance_block = chain.start_overlay()?;
    let (acceptance, nullifiers) = accept_certificate(
        &acceptance_block,
        &fixtures[0],
        first_funding_decision.context("revoke capacity fixture lacks funding decision")?,
        &chain.nullifiers,
    )?;
    acceptance_block.apply_raw(&acceptance.raw)?;
    chain.commit_block(acceptance_block, nullifiers)?;

    let source = chain.start_overlay()?;
    ensure!(
        source.overlay.authority.consumer_keys.len() == MAX_CONSUMER_KEY_AUTHORITIES,
        "authenticated consumer-key fixture lost the full family"
    );
    ensure!(
        !source.overlay.authority.consumer_keys[0]
            .nonce_watermarks
            .is_empty(),
        "authenticated consumer-key fixture lacks a real nonce watermark"
    );
    Ok((chain, fixtures))
}

pub(super) fn revoke_consumer_key_full_capacity_fixture_v0() -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    let (chain, fixtures) = consumer_key_full_capacity_with_watermark_chain_v0()?;

    let block = chain.start_overlay()?;
    ensure!(
        block.overlay.authority.consumer_keys.len() == MAX_CONSUMER_KEY_AUTHORITIES,
        "authenticated revoke source lost the full consumer-key family"
    );
    ensure!(
        !block.overlay.authority.consumer_keys[0]
            .nonce_watermarks
            .is_empty(),
        "authenticated revoke source lacks a real nonce watermark"
    );
    let (built, _) = revoke_consumer_key(&block, &fixtures[0], &chain.nullifiers)?;
    let operation = PocoApplicationOperationV0::decode_exact(&built.raw)?;
    Ok((block, built.raw, operation))
}

fn meter_full_capacity_chain_v0() -> Result<(FixtureChainV0, [CertificateFixtureV0; 4])> {
    let mut chain = authenticated_candidate_genesis_v0()?;
    let fixtures = [
        certificate_fixture_for_provider(&chain, b'a', 0, b"validator-a")?,
        certificate_fixture_for_provider(&chain, b'b', 1, b"validator-b")?,
        certificate_fixture_for_provider(&chain, b'c', 2, b"validator-c")?,
        certificate_fixture_for_provider(&chain, b'd', 3, b"validator-d")?,
    ];
    let mut definition_block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    for fixture in &fixtures {
        let (definition, next) = define_meter(&definition_block, fixture, &nullifiers)?;
        definition_block.apply_raw(&definition.raw)?;
        nullifiers = next;
    }
    ensure!(
        definition_block.overlay.authority.meter_policies.len() == MAX_METER_POLICIES,
        "meter capacity fixture did not fill the meter-policy family"
    );
    chain.commit_block(definition_block, nullifiers)?;

    Ok((chain, fixtures))
}

pub(super) fn retire_meter_full_capacity_fixture_v0() -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    let (chain, fixtures) = meter_full_capacity_chain_v0()?;

    let block = chain.start_overlay()?;
    ensure!(
        block.overlay.authority.meter_policies.len() == MAX_METER_POLICIES,
        "authenticated retire source lost the full meter-policy family"
    );
    let (retirement, _) = retire_meter(&block, &fixtures[0], &chain.nullifiers)?;
    let operation = PocoApplicationOperationV0::decode_exact(&retirement.raw)?;
    Ok((block, retirement.raw, operation))
}

pub(super) fn prune_retired_meter_full_capacity_fixture_v0() -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    let (mut chain, fixtures) = meter_full_capacity_chain_v0()?;
    let fixture = &fixtures[0];

    let mut retirement_block = chain.start_overlay()?;
    let (retirement, nullifiers) = retire_meter(&retirement_block, fixture, &chain.nullifiers)?;
    retirement_block.apply_raw(&retirement.raw)?;
    chain.commit_block(retirement_block, nullifiers)?;

    chain.advance_empty_versions(283)?;
    chain.active_epoch = Epoch::new(28);
    let block = chain.start_overlay()?;
    ensure!(
        block.context.target_height.get() == 284,
        "meter prune capacity fixture target height drifted"
    );
    ensure!(
        block.overlay.authority.meter_policies.len() == MAX_METER_POLICIES,
        "meter prune capacity fixture lost the full family"
    );
    let target = block
        .overlay
        .authority
        .meter_policies
        .iter()
        .find(|policy| {
            policy.meter_id_hex == hex::encode(&fixture.meter_id) && policy.meter_version == 1
        })
        .context("meter prune capacity fixture lost the target")?;
    ensure!(
        target.retired_at_height == Some(2),
        "meter prune capacity fixture lacks the retired target"
    );
    let protocol_boundary = protocol_retention_boundary_v0(
        target
            .retired_at_height
            .context("meter prune target is active")?,
        &block.context.active_parameters,
    )?;
    let meter_boundary = target
        .retired_at_height
        .context("meter prune target is active")?
        .checked_add(target.retention_blocks)
        .context("meter prune retention boundary overflow")?;
    ensure!(
        block.context.target_height.get() > protocol_boundary.max(meter_boundary),
        "meter prune capacity fixture did not pass retention"
    );
    let (prune, _) = prune_meter(&block, fixture, &chain.nullifiers)?;
    let operation = PocoApplicationOperationV0::decode_exact(&prune.raw)?;
    Ok((block, prune.raw, operation))
}

pub(super) fn prune_retired_meter_active_reference_fixture_v0() -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    let (mut chain, fixtures) = consumer_key_full_capacity_with_watermark_chain_v0()?;
    let fixture = &fixtures[0];

    let mut retirement_block = chain.start_overlay()?;
    let (retirement, nullifiers) = retire_meter(&retirement_block, fixture, &chain.nullifiers)?;
    retirement_block.apply_raw(&retirement.raw)?;
    chain.commit_block(retirement_block, nullifiers)?;

    chain.advance_empty_versions(284)?;
    chain.active_epoch = Epoch::new(28);
    let block = chain.start_overlay()?;
    ensure!(
        block.context.target_height.get() == 285,
        "meter active-reference fixture target height drifted"
    );
    ensure!(
        block
            .overlay
            .authority
            .active_certificates
            .iter()
            .any(|certificate| {
                certificate.meter_id_hex == hex::encode(&fixture.meter_id)
                    && certificate.meter_version == 1
            }),
        "meter active-reference fixture lost its certificate"
    );
    let target = block
        .overlay
        .authority
        .meter_policies
        .iter()
        .find(|policy| {
            policy.meter_id_hex == hex::encode(&fixture.meter_id) && policy.meter_version == 1
        })
        .context("meter active-reference fixture lost the target")?;
    let retired_at = target
        .retired_at_height
        .context("meter active-reference fixture target is active")?;
    let protocol_boundary =
        protocol_retention_boundary_v0(retired_at, &block.context.active_parameters)?;
    let meter_boundary = retired_at
        .checked_add(target.retention_blocks)
        .context("meter active-reference boundary overflow")?;
    ensure!(
        block.context.target_height.get() > protocol_boundary.max(meter_boundary),
        "meter active-reference fixture did not pass retention"
    );
    let (prune, _) = prune_meter(&block, fixture, &chain.nullifiers)?;
    let operation = PocoApplicationOperationV0::decode_exact(&prune.raw)?;
    Ok((block, prune.raw, operation))
}

pub(super) fn prune_revoked_consumer_key_full_capacity_fixture_v0() -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    let (mut chain, fixtures) = consumer_key_full_capacity_with_watermark_chain_v0()?;
    let fixture = &fixtures[0];

    let mut opening_block = chain.start_overlay()?;
    let (opening, nullifiers, challenge_id) =
        open_challenge(&opening_block, fixture, &chain.nullifiers)?;
    opening_block.apply_raw(&opening.raw)?;
    chain.commit_block(opening_block, nullifiers)?;

    let mut resolution_block = chain.start_overlay()?;
    let (resolution, nullifiers) = resolve_challenge(
        &resolution_block,
        fixture,
        challenge_id,
        ChallengeResolutionV0::Rejected,
        &chain.nullifiers,
    )?;
    resolution_block.apply_raw(&resolution.raw)?;
    chain.commit_block(resolution_block, nullifiers)?;

    chain.advance_empty_versions(283)?;
    chain.active_epoch = Epoch::new(28);
    let certificate_id = *fixture.certificate.certificate_id().as_bytes();
    let mut certificate_prune_block = chain.start_overlay()?;
    let (certificate_prune, nullifiers) =
        prune_certificate(&certificate_prune_block, certificate_id, &chain.nullifiers)?;
    certificate_prune_block.apply_raw(&certificate_prune.raw)?;
    chain.commit_block(certificate_prune_block, nullifiers)?;

    let mut revocation_block = chain.start_overlay()?;
    let (revocation, nullifiers) =
        revoke_consumer_key(&revocation_block, fixture, &chain.nullifiers)?;
    revocation_block.apply_raw(&revocation.raw)?;
    chain.commit_block(revocation_block, nullifiers)?;

    chain.advance_empty_versions(571)?;
    chain.active_epoch = Epoch::new(57);
    let block = chain.start_overlay()?;
    ensure!(
        block.context.target_height.get() == 572,
        "consumer-key prune fixture target height drifted"
    );
    ensure!(
        block.overlay.authority.consumer_keys.len() == MAX_CONSUMER_KEY_AUTHORITIES,
        "consumer-key prune fixture lost the full family"
    );
    let target = &block.overlay.authority.consumer_keys[0];
    ensure!(
        target.revoked_at_height == Some(285) && !target.nonce_watermarks.is_empty(),
        "consumer-key prune fixture lacks the revoked full-row target"
    );
    ensure!(
        !block
            .overlay
            .authority
            .active_certificates
            .iter()
            .any(|certificate| { certificate.certificate_id_hex == hex::encode(certificate_id) }),
        "consumer-key prune fixture retained the active certificate reference"
    );
    let (built, _) = prune_consumer_key(&block, fixture, &chain.nullifiers)?;
    let operation = PocoApplicationOperationV0::decode_exact(&built.raw)?;
    Ok((block, built.raw, operation))
}

pub(super) fn prune_revoked_consumer_key_active_reference_fixture_v0() -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    let (mut chain, fixtures) = consumer_key_full_capacity_with_watermark_chain_v0()?;
    let fixture = &fixtures[0];
    let mut revocation_block = chain.start_overlay()?;
    let (revocation, nullifiers) =
        revoke_consumer_key(&revocation_block, fixture, &chain.nullifiers)?;
    revocation_block.apply_raw(&revocation.raw)?;
    chain.commit_block(revocation_block, nullifiers)?;

    chain.advance_empty_versions(283)?;
    chain.active_epoch = Epoch::new(28);
    let block = chain.start_overlay()?;
    ensure!(
        block.context.target_height.get() == 284,
        "active-reference prune fixture target height drifted"
    );
    ensure!(
        block
            .overlay
            .authority
            .active_certificates
            .iter()
            .any(|certificate| {
                certificate.certificate_id_hex
                    == hex::encode(fixture.certificate.certificate_id().as_bytes())
            }),
        "active-reference prune fixture lost its certificate"
    );
    let target = &block.overlay.authority.consumer_keys[0];
    let boundary = protocol_retention_boundary_v0(
        target
            .revoked_at_height
            .context("active-reference prune fixture lacks revocation")?,
        &block.context.active_parameters,
    )?;
    ensure!(
        block.context.target_height.get() > boundary,
        "active-reference prune fixture did not pass retention"
    );
    let (built, _) = prune_consumer_key(&block, fixture, &chain.nullifiers)?;
    let operation = PocoApplicationOperationV0::decode_exact(&built.raw)?;
    Ok((block, built.raw, operation))
}

pub(super) fn prune_two_empty_consumer_keys_fixture_v0(
) -> Result<(PocoApplicationBlockOverlayV0, Vec<Vec<u8>>)> {
    let mut chain = authenticated_candidate_genesis_v0()?;
    let fixtures = [
        certificate_fixture_for_provider(&chain, b'a', 0, b"validator-a")?,
        certificate_fixture_for_provider(&chain, b'b', 1, b"validator-b")?,
    ];
    let mut authorization_block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    for fixture in &fixtures {
        let (authorization, next) =
            authorize_consumer_key(&authorization_block, fixture, &nullifiers)?;
        authorization_block.apply_raw(&authorization.raw)?;
        nullifiers = next;
    }
    chain.commit_block(authorization_block, nullifiers)?;

    let mut revocation_block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    for fixture in &fixtures {
        let (revocation, next) = revoke_consumer_key(&revocation_block, fixture, &nullifiers)?;
        revocation_block.apply_raw(&revocation.raw)?;
        nullifiers = next;
    }
    chain.commit_block(revocation_block, nullifiers)?;

    chain.advance_empty_versions(283)?;
    chain.active_epoch = Epoch::new(28);
    let baseline = chain.start_overlay()?;
    ensure!(
        baseline
            .overlay
            .authority
            .consumer_keys
            .iter()
            .all(|authority| authority.nonce_watermarks.is_empty()),
        "empty consumer-key prune fixture unexpectedly has nonce watermarks"
    );
    let mut authoring_block = baseline.clone();
    let mut nullifiers = chain.nullifiers.clone();
    let mut raw_operations = Vec::with_capacity(fixtures.len());
    for fixture in &fixtures {
        let (prune, next) = prune_consumer_key(&authoring_block, fixture, &nullifiers)?;
        authoring_block.apply_raw(&prune.raw)?;
        raw_operations.push(prune.raw);
        nullifiers = next;
    }
    ensure!(
        authoring_block.overlay.authority.consumer_keys.is_empty(),
        "two-key prune authoring did not remove both empty rows"
    );
    Ok((baseline, raw_operations))
}

fn define_meter(
    block: &PocoApplicationBlockOverlayV0,
    fixture: &CertificateFixtureV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let mut identity = Vec::new();
    encode_bytes(&mut identity, &fixture.meter_id);
    identity.extend_from_slice(&1u32.to_be_bytes());
    let mut payload = identity.clone();
    payload.extend_from_slice(&1u128.to_be_bytes());
    payload.extend_from_slice(&block.context.target_height.get().to_be_bytes());
    optional_u64(&mut payload, None);
    let change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::MeterDefinition,
        &identity,
        &payload,
    )?;
    let identity_digest = exact_hash32(&change.logical_key_hex, "meter logical key")?;
    let policy = MeterAuthorityPolicyV0 {
        meter_id_hex: hex::encode(&fixture.meter_id),
        meter_version: 1,
        task_id_hex: hex::encode(&fixture.task_id),
        output_commitment_hex: Some(hex::encode(fixture.output_commitment)),
        unit_scale: CanonicalU128V0::new(1),
        evidence_policy: MeterEvidencePolicyV0::Optional,
        per_certificate_cap: CanonicalU128V0::new(10),
        rolling_cap: CanonicalU128V0::new(100),
        rolling_epoch_span: 1,
        retention_blocks: 1,
        active_from_height: block.context.target_height.get(),
        retired_at_height: None,
    };
    let (built, next, _) = finish_operation(
        block,
        "define-meter-policy",
        "define_meter_policy",
        PocoApplicationOperationBodyV0::DefineMeterPolicy {
            policy,
            decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::MeterDecision,
                subject: ProofSubjectV0::Decision("define-meter"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::MeterIdentity,
                subject: ProofSubjectV0::Literal(identity_digest),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next))
}

fn retire_meter(
    block: &PocoApplicationBlockOverlayV0,
    fixture: &CertificateFixtureV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let mut identity = Vec::new();
    encode_bytes(&mut identity, &fixture.meter_id);
    identity.extend_from_slice(&1u32.to_be_bytes());
    let mut payload = identity.clone();
    payload.extend_from_slice(&1u128.to_be_bytes());
    payload.extend_from_slice(&1u64.to_be_bytes());
    optional_u64(&mut payload, Some(block.context.target_height.get()));
    let change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::MeterDefinition,
        &identity,
        &payload,
    )?;
    let (built, next, _) = finish_operation(
        block,
        "retire-meter-policy",
        "retire_meter_policy",
        PocoApplicationOperationBodyV0::RetireMeterPolicy {
            meter_id_hex: hex::encode(&fixture.meter_id),
            meter_version: 1,
            retired_at_height: block.context.target_height.get(),
            decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::MeterDecision,
            subject: ProofSubjectV0::Decision("retire-meter"),
        }],
        nullifiers,
    )?;
    Ok((built, next))
}

fn register_provider(
    block: &PocoApplicationBlockOverlayV0,
    chain: &FixtureChainV0,
    fixture: &CertificateFixtureV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let pop = validator_pop(
        chain,
        &fixture.provider_signing_key,
        &fixture.provider_id,
        1,
    )?;
    let pop_bytes = pop
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode validator fixture PoP: {error:?}"))?;
    let mut payload = Vec::new();
    encode_bytes(&mut payload, &fixture.provider_id);
    payload.extend_from_slice(&fixture.provider_signing_key.verifying_key().to_bytes());
    payload.extend_from_slice(&1u64.to_be_bytes());
    payload.push(RegistrationStateV0::Active as u8);
    encode_bytes(&mut payload, &pop_bytes);
    let change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::ValidatorRegistration,
        &fixture.provider_id,
        &payload,
    )?;
    let identity_digest = exact_hash32(&change.logical_key_hex, "validator logical key")?;
    let consensus_key = fixture.provider_signing_key.verifying_key().to_bytes();
    let (built, next, _) = finish_operation(
        block,
        "register-provider-validator",
        "register_validator",
        PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex: hex::encode(&fixture.provider_id),
            target_epoch: chain.active_epoch.get(),
            registration_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "non_membership",
                family: PocoNullifierFamilyV0::ValidatorIdentity,
                subject: ProofSubjectV0::Literal(identity_digest),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::RegistrationDecision,
                subject: ProofSubjectV0::Decision("register-validator"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::ValidatorConsensusKey,
                subject: ProofSubjectV0::Literal(consensus_key),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next))
}

fn fund_settlement(
    block: &PocoApplicationBlockOverlayV0,
    fixture: &CertificateFixtureV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0, [u8; 32])> {
    let certificate_id = *fixture.certificate.certificate_id().as_bytes();
    let mut payload = Vec::new();
    payload.extend_from_slice(&certificate_id);
    payload.extend_from_slice(&fixture.settlement_commitment);
    payload.push(SettlementStateV0::FinalizedFundedUnused as u8);
    payload.extend_from_slice(&block.context.target_height.get().to_be_bytes());
    let change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::Settlement,
        &certificate_id,
        &payload,
    )?;
    let (built, next, decisions) = finish_operation(
        block,
        "fund-settlement",
        "fund_settlement",
        PocoApplicationOperationBodyV0::FundSettlement {
            certificate_id_hex: hex::encode(certificate_id),
            settlement_commitment_hex: hex::encode(fixture.settlement_commitment),
            reserved_units: CanonicalU128V0::new(10),
            funding_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "non_membership",
                family: PocoNullifierFamilyV0::Certificate,
                subject: ProofSubjectV0::Literal(certificate_id),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::SettlementDecision,
                subject: ProofSubjectV0::Decision("fund-settlement"),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next, decisions["fund-settlement"]))
}

fn fund_settlement_with_proof_basis(
    block: &PocoApplicationBlockOverlayV0,
    certificate_id: [u8; 32],
    settlement_commitment: [u8; 32],
    reserved_units: u128,
    authority_nullifiers: &FixtureNullifierSetV0,
    proof_basis: &FixtureNullifierSetV0,
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&certificate_id);
    payload.extend_from_slice(&settlement_commitment);
    payload.push(SettlementStateV0::FinalizedFundedUnused as u8);
    payload.extend_from_slice(&block.context.target_height.get().to_be_bytes());
    let change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::Settlement,
        &certificate_id,
        &payload,
    )?;
    let (built, _, _) = finish_operation_with_proof_basis(
        block,
        "state-dependent-same-subject-replay",
        "fund_settlement",
        PocoApplicationOperationBodyV0::FundSettlement {
            certificate_id_hex: hex::encode(certificate_id),
            settlement_commitment_hex: hex::encode(settlement_commitment),
            reserved_units: CanonicalU128V0::new(reserved_units),
            funding_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "non_membership",
                family: PocoNullifierFamilyV0::Certificate,
                subject: ProofSubjectV0::Literal(certificate_id),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::SettlementDecision,
                subject: ProofSubjectV0::Decision("fund-settlement"),
            },
        ],
        authority_nullifiers,
        proof_basis,
    )?;
    Ok(built.raw)
}

fn accept_certificate(
    block: &PocoApplicationBlockOverlayV0,
    fixture: &CertificateFixtureV0,
    funding_decision: [u8; 32],
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let certificate = &fixture.certificate;
    let body = certificate.body();
    let certificate_id = *certificate.certificate_id().as_bytes();
    let certificate_payload = certificate
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode certificate fixture: {error:?}"))?;
    let certificate_change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::ConsumptionCertificate,
        &certificate_id,
        &certificate_payload,
    )?;
    let nonce_identity = joined_identity(&[
        &fixture.consumer_id,
        &fixture.consumer_key_id,
        &fixture.provider_id,
    ]);
    let mut nonce_payload = nonce_identity.clone();
    nonce_payload.extend_from_slice(&body.consumer_nonce().to_be_bytes());
    let nonce_change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::ConsumerNonce,
        &nonce_identity,
        &nonce_payload,
    )?;
    let tuple_identity = consumption_tuple_identity(body);
    let mut tuple_payload = tuple_identity.clone();
    tuple_payload.extend_from_slice(&certificate_id);
    tuple_payload.extend_from_slice(&block.context.target_height.get().to_be_bytes());
    let tuple_change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::UniqueConsumptionTuple,
        &tuple_identity,
        &tuple_payload,
    )?;
    let tuple_key = exact_hash32(&tuple_change.logical_key_hex, "tuple logical key")?;
    let mut settlement_payload = Vec::new();
    settlement_payload.extend_from_slice(&certificate_id);
    settlement_payload.extend_from_slice(&fixture.settlement_commitment);
    settlement_payload.push(SettlementStateV0::Consumed as u8);
    settlement_payload.extend_from_slice(&1u64.to_be_bytes());
    let settlement_change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::Settlement,
        &certificate_id,
        &settlement_payload,
    )?;
    let mut measurement_payload = Vec::new();
    measurement_payload.extend_from_slice(&certificate_id);
    optional_hash32(&mut measurement_payload, None);
    measurement_payload.push(MeasurementStateV0::NotRequired as u8);
    let measurement_change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::MeasurementEvidence,
        &certificate_id,
        &measurement_payload,
    )?;
    let mut lifecycle_payload = Vec::new();
    lifecycle_payload.extend_from_slice(&certificate_id);
    lifecycle_payload.push(LifecycleStateV0::Accepted as u8);
    lifecycle_payload.extend_from_slice(&block.context.target_height.get().to_be_bytes());
    let lifecycle_change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::RevocationOrChallenge,
        &certificate_id,
        &lifecycle_payload,
    )?;
    let (built, next, _) = finish_operation(
        block,
        "accept-certificate",
        "accept_certificate",
        PocoApplicationOperationBodyV0::AcceptCertificate {
            certificate_id_hex: hex::encode(certificate_id),
            funding_decision_id_hex: hex::encode(funding_decision),
            acceptance_decision_id_hex: "0".repeat(64),
            meter_decision_id_hex: "0".repeat(64),
            evidence_decision_id_hex: "0".repeat(64),
        },
        vec![
            certificate_change,
            nonce_change,
            tuple_change,
            settlement_change,
            measurement_change,
            lifecycle_change,
        ],
        vec![
            ProofRequestV0 {
                list: "non_membership",
                family: PocoNullifierFamilyV0::Certificate,
                subject: ProofSubjectV0::Literal(certificate_id),
            },
            ProofRequestV0 {
                list: "non_membership",
                family: PocoNullifierFamilyV0::Tuple,
                subject: ProofSubjectV0::Literal(tuple_key),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::SettlementDecision,
                subject: ProofSubjectV0::Decision("accept-certificate"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::MeterDecision,
                subject: ProofSubjectV0::Decision("meter-certificate"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::EvidenceDecision,
                subject: ProofSubjectV0::Decision("evidence-certificate"),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next))
}

fn open_challenge(
    block: &PocoApplicationBlockOverlayV0,
    fixture: &CertificateFixtureV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0, [u8; 32])> {
    let certificate_id = *fixture.certificate.certificate_id().as_bytes();
    let mut payload = Vec::new();
    payload.extend_from_slice(&certificate_id);
    payload.push(LifecycleStateV0::ChallengePending as u8);
    payload.extend_from_slice(&block.context.target_height.get().to_be_bytes());
    let change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::RevocationOrChallenge,
        &certificate_id,
        &payload,
    )?;
    let (built, next, decisions) = finish_operation(
        block,
        "open-challenge",
        "open_challenge",
        PocoApplicationOperationBodyV0::OpenChallenge {
            certificate_id_hex: hex::encode(certificate_id),
            challenge_id_hex: "0".repeat(64),
            opening_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::ChallengeDecision,
            subject: ProofSubjectV0::Decision("open-challenge"),
        }],
        nullifiers,
    )?;
    Ok((built, next, decisions["challenge-id"]))
}

fn resolve_challenge(
    block: &PocoApplicationBlockOverlayV0,
    fixture: &CertificateFixtureV0,
    challenge_id: [u8; 32],
    resolution: ChallengeResolutionV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let certificate_id = *fixture.certificate.certificate_id().as_bytes();
    let lifecycle = match resolution {
        ChallengeResolutionV0::Rejected => LifecycleStateV0::ChallengeRejected,
        ChallengeResolutionV0::Sustained => LifecycleStateV0::ChallengeSustained,
    };
    let mut payload = Vec::new();
    payload.extend_from_slice(&certificate_id);
    payload.push(lifecycle as u8);
    payload.extend_from_slice(&block.context.target_height.get().to_be_bytes());
    let change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::RevocationOrChallenge,
        &certificate_id,
        &payload,
    )?;
    let (built, next, _) = finish_operation(
        block,
        "resolve-challenge",
        "resolve_challenge",
        PocoApplicationOperationBodyV0::ResolveChallenge {
            certificate_id_hex: hex::encode(certificate_id),
            challenge_id_hex: hex::encode(challenge_id),
            resolution,
            resolution_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::ChallengeDecision,
            subject: ProofSubjectV0::Decision("resolve-challenge"),
        }],
        nullifiers,
    )?;
    Ok((built, next))
}

fn governance_proposal(
    block: &PocoApplicationBlockOverlayV0,
    chain: &FixtureChainV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let target_epoch = chain
        .active_epoch
        .get()
        .checked_add(1)
        .context("fixture governance target epoch overflow")?;
    let activation_height = EpochGeometryV0::new(chain.active_epoch, &chain.active_parameters)
        .map_err(|error| anyhow::anyhow!("fixture governance source geometry: {error:?}"))?
        .epoch_end()
        .get()
        .checked_add(1)
        .context("fixture governance activation height overflow")?;
    let parameters_bytes = chain.active_parameters.canonical_bytes();
    let parameters_hash = *chain.active_parameters.hash().as_bytes();
    let mut parameters_identity = vec![2];
    parameters_identity.extend_from_slice(&target_epoch.to_be_bytes());
    let parameters_change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::ConsensusParameters,
        &parameters_identity,
        &parameters_bytes,
    )?;
    let governance_identity = target_epoch.to_be_bytes();
    let mut governance_payload = Vec::new();
    governance_payload.push(RolloutPhaseV0::Shadow as u8);
    governance_payload.extend_from_slice(&parameters_hash);
    governance_payload.extend_from_slice(&activation_height.to_be_bytes());
    governance_payload.push(GovernanceApprovalV0::Pending as u8);
    let governance_change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::RolloutOrGovernance,
        &governance_identity,
        &governance_payload,
    )?;
    let (built, next, _) = finish_operation(
        block,
        "propose-governance",
        "propose_governance",
        PocoApplicationOperationBodyV0::ProposeGovernance {
            target_epoch,
            phase: RolloutPhaseV0::Shadow as u8,
            parameters_hash_hex: hex::encode(parameters_hash),
            activation_height,
            proposal_decision_id_hex: "0".repeat(64),
        },
        vec![parameters_change, governance_change],
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::GovernanceDecision,
            subject: ProofSubjectV0::Decision("propose-governance"),
        }],
        nullifiers,
    )?;
    Ok((built, next))
}

fn governance_approval(
    block: &PocoApplicationBlockOverlayV0,
    chain: &FixtureChainV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let target_epoch = chain
        .active_epoch
        .get()
        .checked_add(1)
        .context("fixture governance target epoch overflow")?;
    let activation_height = EpochGeometryV0::new(chain.active_epoch, &chain.active_parameters)
        .map_err(|error| anyhow::anyhow!("fixture governance source geometry: {error:?}"))?
        .epoch_end()
        .get()
        .checked_add(1)
        .context("fixture governance activation height overflow")?;
    let parameters_hash = *chain.active_parameters.hash().as_bytes();
    let governance_identity = target_epoch.to_be_bytes();
    let mut governance_payload = Vec::new();
    governance_payload.push(RolloutPhaseV0::Shadow as u8);
    governance_payload.extend_from_slice(&parameters_hash);
    governance_payload.extend_from_slice(&activation_height.to_be_bytes());
    governance_payload.push(GovernanceApprovalV0::Approved as u8);
    let change = semantic_change(
        block,
        PocoSnapshotEntryKindV0::RolloutOrGovernance,
        &governance_identity,
        &governance_payload,
    )?;
    let (built, next, _) = finish_operation(
        block,
        "approve-governance",
        "approve_governance",
        PocoApplicationOperationBodyV0::ApproveGovernance {
            target_epoch,
            parameters_hash_hex: hex::encode(parameters_hash),
            activation_height,
            decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::GovernanceDecision,
            subject: ProofSubjectV0::Decision("approve-governance"),
        }],
        nullifiers,
    )?;
    Ok((built, next))
}

fn validator_registration_change(
    block: &PocoApplicationBlockOverlayV0,
    chain: &FixtureChainV0,
    validator_id: &[u8],
    signing_key: &SigningKey,
    nonce: u64,
    state: RegistrationStateV0,
) -> Result<RawSemanticChangeV0> {
    let pop = validator_pop(chain, signing_key, validator_id, nonce)?;
    let pop_bytes = pop
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode validator fixture PoP: {error:?}"))?;
    let mut payload = Vec::new();
    encode_bytes(&mut payload, validator_id);
    payload.extend_from_slice(&signing_key.verifying_key().to_bytes());
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload.push(state as u8);
    encode_bytes(&mut payload, &pop_bytes);
    semantic_change(
        block,
        PocoSnapshotEntryKindV0::ValidatorRegistration,
        validator_id,
        &payload,
    )
}

fn register_rotation_fixture(
    block: &PocoApplicationBlockOverlayV0,
    chain: &FixtureChainV0,
    validator_id: &[u8],
    signing_key: &SigningKey,
    nonce: u64,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let change = validator_registration_change(
        block,
        chain,
        validator_id,
        signing_key,
        nonce,
        RegistrationStateV0::Active,
    )?;
    let identity_digest = exact_hash32(&change.logical_key_hex, "rotation validator logical key")?;
    let consensus_key = signing_key.verifying_key().to_bytes();
    let (built, next, _) = finish_operation(
        block,
        "register-rotation-validator",
        "register_validator",
        PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex: hex::encode(validator_id),
            target_epoch: chain.active_epoch.get(),
            registration_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "non_membership",
                family: PocoNullifierFamilyV0::ValidatorIdentity,
                subject: ProofSubjectV0::Literal(identity_digest),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::RegistrationDecision,
                subject: ProofSubjectV0::Decision("register-validator"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::ValidatorConsensusKey,
                subject: ProofSubjectV0::Literal(consensus_key),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next))
}

#[allow(clippy::too_many_arguments)]
fn register_future_candidate_fixture(
    block: &PocoApplicationBlockOverlayV0,
    chain: &FixtureChainV0,
    validator_id: &[u8],
    signing_key: &SigningKey,
    registration_nonce: u64,
    previous_registration_nonce: Option<u64>,
    predecessor_history_head: [u8; 32],
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let target_epoch = chain
        .active_epoch
        .checked_next()
        .map_err(|error| anyhow::anyhow!("future candidate fixture target epoch: {error:?}"))?;
    let proof = validator_pop_at_epoch(
        chain,
        signing_key,
        validator_id,
        registration_nonce,
        target_epoch,
    )?;
    let proof_bytes = proof
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode future candidate fixture PoP: {error:?}"))?;
    let consensus_key = signing_key.verifying_key().to_bytes();
    let (built, next, _) = finish_operation(
        block,
        "register-future-candidate",
        "register_future_candidate",
        PocoApplicationOperationBodyV0::RegisterFutureCandidate {
            validator_id_hex: hex::encode(validator_id),
            target_epoch: target_epoch.get(),
            previous_registration_nonce,
            predecessor_history_head_hex: hex::encode(predecessor_history_head),
            proof_cev0_hex: hex::encode(proof_bytes),
            registration_decision_id_hex: "0".repeat(64),
        },
        Vec::new(),
        vec![
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::RegistrationDecision,
                subject: ProofSubjectV0::Decision("register-future-candidate"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::ValidatorConsensusKey,
                subject: ProofSubjectV0::Literal(consensus_key),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next))
}

pub(super) fn register_validator_capacity_fixture_v0(
    admitted: usize,
) -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    ensure!(
        admitted <= MAX_VALIDATOR_REGISTRATION_HISTORIES,
        "validator registration capacity fixture exceeds family cap"
    );
    let chain = authenticated_candidate_genesis_v0()?;
    let mut block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    for index in 0..=admitted {
        let validator_id = format!("validator-capacity-{index}").into_bytes();
        let signing_key = provider_fixture_signing_key_for_id(&validator_id);
        let (built, next) = register_rotation_fixture(
            &block,
            &chain,
            &validator_id,
            &signing_key,
            u64::try_from(index)?
                .checked_add(1)
                .context("validator capacity fixture registration nonce overflow")?,
            &nullifiers,
        )?;
        if index == admitted {
            let operation = PocoApplicationOperationV0::decode_exact(&built.raw)?;
            return Ok((block, built.raw, operation));
        }
        block.apply_raw(&built.raw)?;
        nullifiers = next;
    }
    unreachable!("inclusive validator capacity fixture loop must return")
}

pub(super) fn future_candidate_capacity_fixture_v0(
    admitted: usize,
) -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    ensure!(
        admitted <= MAX_FUTURE_CANDIDATE_REGISTRATIONS,
        "future candidate capacity fixture exceeds family cap"
    );
    let chain = authenticated_candidate_genesis_v0()?;
    let mut block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    for index in 0..=admitted {
        let validator_id = format!("future-capacity-validator-{index}").into_bytes();
        let signing_key = provider_fixture_signing_key_for_id(&validator_id);
        let (built, next) = register_future_candidate_fixture(
            &block,
            &chain,
            &validator_id,
            &signing_key,
            u64::try_from(index)?
                .checked_add(1)
                .context("future candidate capacity fixture registration nonce overflow")?,
            None,
            [0; 32],
            &nullifiers,
        )?;
        if index == admitted {
            let operation = PocoApplicationOperationV0::decode_exact(&built.raw)?;
            return Ok((block, built.raw, operation));
        }
        block.apply_raw(&built.raw)?;
        nullifiers = next;
    }
    unreachable!("inclusive future candidate fixture loop must return")
}

fn rotate_fixture_validator(
    block: &PocoApplicationBlockOverlayV0,
    chain: &FixtureChainV0,
    validator_id: &[u8],
    signing_key: &SigningKey,
    nonce: u64,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let validator_id_hex = hex::encode(validator_id);
    let history = block
        .overlay
        .authority
        .validator_registration_history
        .iter()
        .find(|history| history.validator_id_hex == validator_id_hex)
        .context("fixture validator rotation lacks source history")?;
    let previous_history_head_hex = history.history_head_hex.clone();
    let previous_registration_nonce = history.max_registration_nonce;
    let change = validator_registration_change(
        block,
        chain,
        validator_id,
        signing_key,
        nonce,
        RegistrationStateV0::Active,
    )?;
    let consensus_key = signing_key.verifying_key().to_bytes();
    let (built, next, _) = finish_operation(
        block,
        "rotate-validator",
        "rotate_validator",
        PocoApplicationOperationBodyV0::RotateValidator {
            validator_id_hex,
            target_epoch: chain.active_epoch.get(),
            previous_history_head_hex,
            previous_registration_nonce,
            registration_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::RegistrationDecision,
                subject: ProofSubjectV0::Decision("rotate-validator"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::ValidatorConsensusKey,
                subject: ProofSubjectV0::Literal(consensus_key),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next))
}

pub(super) fn rotate_validator_full_history_fixture_v0() -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    let mut chain = authenticated_candidate_genesis_v0()?;
    let mut registration_block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    for index in 0..MAX_VALIDATOR_REGISTRATION_HISTORIES {
        let validator_id = format!("rotate-capacity-validator-{index}").into_bytes();
        let signing_key = provider_fixture_signing_key_for_id(&validator_id);
        let (built, next) = register_rotation_fixture(
            &registration_block,
            &chain,
            &validator_id,
            &signing_key,
            u64::try_from(index)?
                .checked_add(1)
                .context("rotate capacity fixture registration nonce overflow")?,
            &nullifiers,
        )?;
        registration_block.apply_raw(&built.raw)?;
        nullifiers = next;
    }
    chain.commit_block(registration_block, nullifiers)?;

    let block = chain.start_overlay()?;
    let validator_id = b"rotate-capacity-validator-0".to_vec();
    let signing_key = provider_fixture_signing_key_for_id(b"rotate-capacity-validator-0-next");
    let (built, _) = rotate_fixture_validator(
        &block,
        &chain,
        &validator_id,
        &signing_key,
        2,
        &chain.nullifiers,
    )?;
    let operation = PocoApplicationOperationV0::decode_exact(&built.raw)?;
    Ok((block, built.raw, operation))
}

fn revoke_fixture_validator(
    block: &PocoApplicationBlockOverlayV0,
    chain: &FixtureChainV0,
    validator_id: &[u8],
    signing_key: &SigningKey,
    nonce: u64,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let change = validator_registration_change(
        block,
        chain,
        validator_id,
        signing_key,
        nonce,
        RegistrationStateV0::Revoked,
    )?;
    let identity_digest =
        semantic_identity_digest_v0(PocoSnapshotEntryKindV0::ValidatorRegistration, validator_id);
    let (built, next, _) = finish_operation(
        block,
        "revoke-validator",
        "revoke_validator",
        PocoApplicationOperationBodyV0::RevokeValidator {
            validator_id_hex: hex::encode(validator_id),
            revocation_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::RegistrationDecision,
                subject: ProofSubjectV0::Decision("revoke-validator"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::ValidatorIdentity,
                subject: ProofSubjectV0::Literal(identity_digest),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next))
}

fn release_settlement(
    block: &PocoApplicationBlockOverlayV0,
    certificate_id: [u8; 32],
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let change = semantic_delete(block, PocoSnapshotEntryKindV0::Settlement, &certificate_id)?;
    let (built, next, _) = finish_operation(
        block,
        "release-settlement",
        "release_settlement",
        PocoApplicationOperationBodyV0::ReleaseSettlement {
            certificate_id_hex: hex::encode(certificate_id),
            release_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::Certificate,
                subject: ProofSubjectV0::Literal(certificate_id),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::SettlementDecision,
                subject: ProofSubjectV0::Decision("release-settlement"),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next))
}

pub(super) fn release_settlement_full_capacity_fixture_v0() -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    let mut chain = authenticated_candidate_genesis_v0()?;
    let mut funding_block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    let mut release_certificate_id = None;
    for index in 0..MAX_FUNDED_UNUSED_RESERVATIONS {
        let mut certificate_id = [0x81; 32];
        certificate_id[31] = u8::try_from(index)?;
        let mut settlement_commitment = [0x91; 32];
        settlement_commitment[31] = u8::try_from(index)?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&certificate_id);
        payload.extend_from_slice(&settlement_commitment);
        payload.push(SettlementStateV0::FinalizedFundedUnused as u8);
        payload.extend_from_slice(&funding_block.context.target_height.get().to_be_bytes());
        let change = semantic_change(
            &funding_block,
            PocoSnapshotEntryKindV0::Settlement,
            &certificate_id,
            &payload,
        )?;
        let (built, next, _) = finish_operation(
            &funding_block,
            "fund-settlement-capacity",
            "fund_settlement",
            PocoApplicationOperationBodyV0::FundSettlement {
                certificate_id_hex: hex::encode(certificate_id),
                settlement_commitment_hex: hex::encode(settlement_commitment),
                reserved_units: CanonicalU128V0::new(u128::try_from(index)? + 1),
                funding_decision_id_hex: "0".repeat(64),
            },
            vec![change],
            vec![
                ProofRequestV0 {
                    list: "non_membership",
                    family: PocoNullifierFamilyV0::Certificate,
                    subject: ProofSubjectV0::Literal(certificate_id),
                },
                ProofRequestV0 {
                    list: "insertion",
                    family: PocoNullifierFamilyV0::SettlementDecision,
                    subject: ProofSubjectV0::Decision("fund-settlement"),
                },
            ],
            &nullifiers,
        )?;
        funding_block.apply_raw(&built.raw)?;
        nullifiers = next;
        release_certificate_id.get_or_insert(certificate_id);
    }
    chain.commit_block(funding_block, nullifiers)?;

    let block = chain.start_overlay()?;
    let (built, _) = release_settlement(
        &block,
        release_certificate_id.context("release capacity fixture lacks certificate")?,
        &chain.nullifiers,
    )?;
    let operation = PocoApplicationOperationV0::decode_exact(&built.raw)?;
    Ok((block, built.raw, operation))
}

pub(super) fn resolve_challenge_full_capacity_fixture_v0() -> Result<(
    PocoApplicationBlockOverlayV0,
    Vec<u8>,
    PocoApplicationOperationV0,
)> {
    let mut chain = authenticated_candidate_genesis_v0()?;
    let fixtures = [
        certificate_fixture_for_provider(&chain, b'a', 0, b"validator-a")?,
        certificate_fixture_for_provider(&chain, b'b', 1, b"validator-b")?,
    ];

    let mut setup_block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    let mut funding_decisions = Vec::with_capacity(fixtures.len());
    for fixture in &fixtures {
        let (authorize, next) = authorize_consumer_key(&setup_block, fixture, &nullifiers)?;
        setup_block.apply_raw(&authorize.raw)?;
        nullifiers = next;
        let (meter, next) = define_meter(&setup_block, fixture, &nullifiers)?;
        setup_block.apply_raw(&meter.raw)?;
        nullifiers = next;
        let (provider, next) = register_provider(&setup_block, &chain, fixture, &nullifiers)?;
        setup_block.apply_raw(&provider.raw)?;
        nullifiers = next;
        let (funding, next, funding_decision) =
            fund_settlement(&setup_block, fixture, &nullifiers)?;
        setup_block.apply_raw(&funding.raw)?;
        nullifiers = next;
        funding_decisions.push(funding_decision);
    }
    chain.commit_block(setup_block, nullifiers)?;

    let mut acceptance_block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    for (fixture, funding_decision) in fixtures.iter().zip(funding_decisions) {
        let (acceptance, next) =
            accept_certificate(&acceptance_block, fixture, funding_decision, &nullifiers)?;
        acceptance_block.apply_raw(&acceptance.raw)?;
        nullifiers = next;
    }
    chain.commit_block(acceptance_block, nullifiers)?;

    let mut opening_block = chain.start_overlay()?;
    let mut nullifiers = chain.nullifiers.clone();
    let mut challenge_ids = Vec::with_capacity(fixtures.len());
    for fixture in &fixtures {
        let (opening, next, challenge_id) = open_challenge(&opening_block, fixture, &nullifiers)?;
        opening_block.apply_raw(&opening.raw)?;
        nullifiers = next;
        challenge_ids.push(challenge_id);
    }
    chain.commit_block(opening_block, nullifiers)?;

    let block = chain.start_overlay()?;
    ensure!(
        block.overlay.authority.pending_challenges.len() == MAX_PENDING_CHALLENGES,
        "resolve capacity fixture did not fill the pending-challenge family"
    );
    let (built, _) = resolve_challenge(
        &block,
        &fixtures[0],
        challenge_ids[0],
        ChallengeResolutionV0::Rejected,
        &chain.nullifiers,
    )?;
    let operation = PocoApplicationOperationV0::decode_exact(&built.raw)?;
    Ok((block, built.raw, operation))
}

fn rebound_negative_operation(
    block: &PocoApplicationBlockOverlayV0,
    base: &BuiltOperationV0,
    operation_kind: &'static str,
    proof_requests: Vec<ProofRequestV0>,
    authority_nullifiers: &FixtureNullifierSetV0,
    proof_basis: &FixtureNullifierSetV0,
) -> Result<Vec<u8>> {
    let base_operation = PocoApplicationOperationV0::decode_exact(&base.raw)?;
    let (rebound, _, _) = finish_operation_with_proof_basis(
        block,
        "state-dependent-same-subject-replay",
        operation_kind,
        base_operation.body,
        base_operation.semantic_changes,
        proof_requests,
        authority_nullifiers,
        proof_basis,
    )?;
    Ok(rebound.raw)
}

fn negative_template(
    sequence_id: &'static str,
    raw: Vec<u8>,
    stage: &'static str,
    error_code: &'static str,
) -> NegativeTemplateExportV0 {
    NegativeTemplateExportV0 {
        schema: NEGATIVE_TEMPLATE_SCHEMA,
        schema_version: 0,
        sequence_id,
        id: "required-state-dependent-same-subject-replay",
        raw_operation_json_hexes: vec![hex::encode(raw)],
        expected_reject: ExpectedRejectExportV0 { stage, error_code },
    }
}

fn step(
    sequence_id: &'static str,
    block: usize,
    operations: Vec<OperationTemplateExportV0>,
) -> StepTemplateExportV0 {
    StepTemplateExportV0 {
        schema: STEP_TEMPLATE_SCHEMA,
        schema_version: 0,
        sequence_id,
        id: format!("block-{block}"),
        operations,
    }
}

fn prune_certificate(
    block: &PocoApplicationBlockOverlayV0,
    certificate_id: [u8; 32],
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let certificate_id_hex = hex::encode(certificate_id);
    let certificate = block
        .overlay
        .authority
        .active_certificates
        .iter()
        .find(|certificate| certificate.certificate_id_hex == certificate_id_hex)
        .context("fixture certificate prune lacks authority")?;
    let tuple_key = exact_hash32(&certificate.tuple_key_hex, "fixture certificate tuple key")?;
    let changes = certificate
        .semantic_keys
        .iter()
        .map(|key| {
            semantic_delete_key(
                block,
                PocoSnapshotEntryKindV0::from_u8(key.kind)?,
                exact_hash32(&key.logical_key_hex, "fixture retained semantic key")?.to_vec(),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let (built, next, _) = finish_operation(
        block,
        "prune-expired-certificate",
        "prune_expired_certificate",
        PocoApplicationOperationBodyV0::PruneExpiredCertificate { certificate_id_hex },
        changes,
        vec![
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::Certificate,
                subject: ProofSubjectV0::Literal(certificate_id),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::Tuple,
                subject: ProofSubjectV0::Literal(tuple_key),
            },
        ],
        nullifiers,
    )?;
    Ok((built, next))
}

fn prune_consumer_key(
    block: &PocoApplicationBlockOverlayV0,
    fixture: &CertificateFixtureV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let consumer_id_hex = hex::encode(&fixture.consumer_id);
    let consumer_key_id_hex = hex::encode(&fixture.consumer_key_id);
    let authority = block
        .overlay
        .authority
        .consumer_keys
        .iter()
        .find(|authority| {
            authority.consumer_id_hex == consumer_id_hex
                && authority.consumer_key_id_hex == consumer_key_id_hex
        })
        .context("fixture consumer-key prune lacks authority")?;
    let mut changes = vec![semantic_delete(
        block,
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
        &joined_identity(&[&fixture.consumer_id, &fixture.consumer_key_id]),
    )?];
    for watermark in &authority.nonce_watermarks {
        changes.push(semantic_delete_key(
            block,
            PocoSnapshotEntryKindV0::ConsumerNonce,
            exact_hash32(&watermark.logical_key_hex, "fixture nonce watermark key")?.to_vec(),
        )?);
    }
    let summary = consumer_nonce_summary_digest_v0(authority)?;
    let (built, next, _) = finish_operation(
        block,
        "prune-revoked-consumer-key",
        "prune_revoked_consumer_key",
        PocoApplicationOperationBodyV0::PruneRevokedConsumerKey {
            consumer_id_hex,
            consumer_key_id_hex,
        },
        changes,
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::ConsumerNonceSummary,
            subject: ProofSubjectV0::Literal(summary),
        }],
        nullifiers,
    )?;
    Ok((built, next))
}

fn prune_meter(
    block: &PocoApplicationBlockOverlayV0,
    fixture: &CertificateFixtureV0,
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let mut identity = Vec::new();
    encode_bytes(&mut identity, &fixture.meter_id);
    identity.extend_from_slice(&1u32.to_be_bytes());
    let change = semantic_delete(block, PocoSnapshotEntryKindV0::MeterDefinition, &identity)?;
    let (built, next, _) = finish_operation(
        block,
        "prune-retired-meter",
        "prune_retired_meter",
        PocoApplicationOperationBodyV0::PruneRetiredMeter {
            meter_id_hex: hex::encode(&fixture.meter_id),
            meter_version: 1,
        },
        vec![change],
        Vec::new(),
        nullifiers,
    )?;
    Ok((built, next))
}

fn prune_validator_history(
    block: &PocoApplicationBlockOverlayV0,
    validator_id: &[u8],
    nullifiers: &FixtureNullifierSetV0,
) -> Result<(BuiltOperationV0, FixtureNullifierSetV0)> {
    let change = semantic_delete(
        block,
        PocoSnapshotEntryKindV0::ValidatorRegistration,
        validator_id,
    )?;
    let (built, next, _) = finish_operation(
        block,
        "prune-revoked-validator-history",
        "prune_revoked_validator_history",
        PocoApplicationOperationBodyV0::PruneRevokedValidatorHistory {
            validator_id_hex: hex::encode(validator_id),
        },
        vec![change],
        Vec::new(),
        nullifiers,
    )?;
    Ok((built, next))
}

fn build_certificate_challenge_sequence(
    mut chain: FixtureChainV0,
    source_digest: String,
    sequence_id: &'static str,
    resolution: ChallengeResolutionV0,
) -> Result<VerticalSequenceExportV0> {
    let fixture = certificate_fixture(&chain)?;
    let mut block = chain.start_overlay()?;
    let (authorize, after_authorize) = authorize_consumer_key(&block, &fixture, &chain.nullifiers)?;
    block.apply_raw(&authorize.raw)?;
    let (meter, after_meter) = define_meter(&block, &fixture, &after_authorize)?;
    block.apply_raw(&meter.raw)?;
    let (registration, after_registration) =
        register_provider(&block, &chain, &fixture, &after_meter)?;
    block.apply_raw(&registration.raw)?;
    let (funding, after_funding, funding_decision) =
        fund_settlement(&block, &fixture, &after_registration)?;
    block.apply_raw(&funding.raw)?;
    let first_step = step(
        sequence_id,
        1,
        vec![
            authorize.template,
            meter.template,
            registration.template,
            funding.template,
        ],
    );
    chain.commit_block(block, after_funding)?;

    let mut block = chain.start_overlay()?;
    let (acceptance, after_acceptance) =
        accept_certificate(&block, &fixture, funding_decision, &chain.nullifiers)?;
    block.apply_raw(&acceptance.raw)?;
    let second_step = step(sequence_id, 2, vec![acceptance.template]);
    chain.commit_block(block, after_acceptance)?;

    let mut block = chain.start_overlay()?;
    let (opening, after_opening, challenge_id) =
        open_challenge(&block, &fixture, &chain.nullifiers)?;
    block.apply_raw(&opening.raw)?;
    let third_step = step(sequence_id, 3, vec![opening.template]);
    chain.commit_block(block, after_opening)?;

    let mut block = chain.start_overlay()?;
    let (resolution_operation, after_resolution) = resolve_challenge(
        &block,
        &fixture,
        challenge_id,
        resolution,
        &chain.nullifiers,
    )?;
    block.apply_raw(&resolution_operation.raw)?;
    let fourth_step = step(sequence_id, 4, vec![resolution_operation.template.clone()]);
    chain.commit_block(block, after_resolution)?;

    let negative_block = chain.start_overlay()?;
    let negative_raw = rebound_negative_operation(
        &negative_block,
        &resolution_operation,
        "resolve_challenge",
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::ChallengeDecision,
            subject: ProofSubjectV0::Decision("resolve-challenge"),
        }],
        &chain.nullifiers,
        &chain.nullifiers,
    )?;
    validate_application_authority_projection_v0(&chain.projection)?;
    Ok(VerticalSequenceExportV0 {
        id: sequence_id,
        execution_scope: "full_application_store",
        source_export_sha256_hex: source_digest,
        steps: vec![first_step, second_step, third_step, fourth_step],
        negative: Some(negative_template(
            sequence_id,
            negative_raw,
            "authority",
            "challenge_not_pending",
        )),
    })
}

fn build_governance_sequence(
    mut chain: FixtureChainV0,
    source_digest: String,
) -> Result<VerticalSequenceExportV0> {
    const SEQUENCE: &str = "governance_propose_approve";
    let mut block = chain.start_overlay()?;
    let (proposal, after_proposal) = governance_proposal(&block, &chain, &chain.nullifiers)?;
    block.apply_raw(&proposal.raw)?;
    let first_step = step(SEQUENCE, 1, vec![proposal.template]);
    chain.commit_block(block, after_proposal)?;

    let mut block = chain.start_overlay()?;
    let (approval, after_approval) = governance_approval(&block, &chain, &chain.nullifiers)?;
    block.apply_raw(&approval.raw)?;
    let second_step = step(SEQUENCE, 2, vec![approval.template.clone()]);
    chain.commit_block(block, after_approval)?;

    let negative_block = chain.start_overlay()?;
    let negative_raw = rebound_negative_operation(
        &negative_block,
        &approval,
        "approve_governance",
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::GovernanceDecision,
            subject: ProofSubjectV0::Decision("approve-governance"),
        }],
        &chain.nullifiers,
        &chain.nullifiers,
    )?;
    Ok(VerticalSequenceExportV0 {
        id: SEQUENCE,
        execution_scope: "full_application_store",
        source_export_sha256_hex: source_digest,
        steps: vec![first_step, second_step],
        negative: Some(negative_template(
            SEQUENCE,
            negative_raw,
            "authority",
            "governance_approval_lacks_authenticated_proposal",
        )),
    })
}

fn build_validator_rotation_sequence(
    mut chain: FixtureChainV0,
    source_digest: String,
) -> Result<VerticalSequenceExportV0> {
    const SEQUENCE: &str = "validator_register_rotate";
    let validator_id = b"validator-rotation-a".to_vec();
    let first_key = SigningKey::from_bytes(&[41; 32]);
    let second_key = SigningKey::from_bytes(&[42; 32]);

    let mut block = chain.start_overlay()?;
    let (registration, after_registration) = register_rotation_fixture(
        &block,
        &chain,
        &validator_id,
        &first_key,
        1,
        &chain.nullifiers,
    )?;
    block.apply_raw(&registration.raw)?;
    let first_step = step(SEQUENCE, 1, vec![registration.template]);
    chain.commit_block(block, after_registration)?;

    let before_rotation_nullifiers = chain.nullifiers.clone();
    let mut block = chain.start_overlay()?;
    let (rotation, after_rotation) = rotate_fixture_validator(
        &block,
        &chain,
        &validator_id,
        &second_key,
        2,
        &chain.nullifiers,
    )?;
    block.apply_raw(&rotation.raw)?;
    let second_step = step(SEQUENCE, 2, vec![rotation.template.clone()]);
    chain.commit_block(block, after_rotation)?;

    let negative_block = chain.start_overlay()?;
    let negative_raw = rebound_negative_operation(
        &negative_block,
        &rotation,
        "rotate_validator",
        vec![
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::RegistrationDecision,
                subject: ProofSubjectV0::Decision("rotate-validator"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::ValidatorConsensusKey,
                subject: ProofSubjectV0::Literal(second_key.verifying_key().to_bytes()),
            },
        ],
        &chain.nullifiers,
        &before_rotation_nullifiers,
    )?;
    Ok(VerticalSequenceExportV0 {
        id: SEQUENCE,
        execution_scope: "full_application_store",
        source_export_sha256_hex: source_digest,
        steps: vec![first_step, second_step],
        negative: Some(negative_template(
            SEQUENCE,
            negative_raw,
            "authority",
            "validator_consensus_key_already_active",
        )),
    })
}

fn build_release_replay_sequence(
    mut chain: FixtureChainV0,
    source_digest: String,
) -> Result<VerticalSequenceExportV0> {
    const SEQUENCE: &str = "release_refund_replay";
    let certificate_id = [0xa1; 32];
    let settlement_commitment = [0xa2; 32];
    let mut block = chain.start_overlay()?;
    let mut payload = Vec::new();
    payload.extend_from_slice(&certificate_id);
    payload.extend_from_slice(&settlement_commitment);
    payload.push(SettlementStateV0::FinalizedFundedUnused as u8);
    payload.extend_from_slice(&block.context.target_height.get().to_be_bytes());
    let change = semantic_change(
        &block,
        PocoSnapshotEntryKindV0::Settlement,
        &certificate_id,
        &payload,
    )?;
    let (funding, after_funding, _) = finish_operation(
        &block,
        "fund-settlement",
        "fund_settlement",
        PocoApplicationOperationBodyV0::FundSettlement {
            certificate_id_hex: hex::encode(certificate_id),
            settlement_commitment_hex: hex::encode(settlement_commitment),
            reserved_units: CanonicalU128V0::new(7),
            funding_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "non_membership",
                family: PocoNullifierFamilyV0::Certificate,
                subject: ProofSubjectV0::Literal(certificate_id),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::SettlementDecision,
                subject: ProofSubjectV0::Decision("fund-settlement"),
            },
        ],
        &chain.nullifiers,
    )?;
    block.apply_raw(&funding.raw)?;
    let first_step = step(SEQUENCE, 1, vec![funding.template]);
    chain.commit_block(block, after_funding)?;

    let stale_proof_basis = chain.nullifiers.clone();
    let mut block = chain.start_overlay()?;
    let (release, after_release) = release_settlement(&block, certificate_id, &chain.nullifiers)?;
    block.apply_raw(&release.raw)?;
    let second_step = step(SEQUENCE, 2, vec![release.template]);
    chain.commit_block(block, after_release)?;

    let negative_block = chain.start_overlay()?;
    let negative_raw = fund_settlement_with_proof_basis(
        &negative_block,
        certificate_id,
        settlement_commitment,
        7,
        &chain.nullifiers,
        &stale_proof_basis,
    )?;
    Ok(VerticalSequenceExportV0 {
        id: SEQUENCE,
        execution_scope: "full_application_store",
        source_export_sha256_hex: source_digest,
        steps: vec![first_step, second_step],
        negative: Some(negative_template(
            SEQUENCE,
            negative_raw,
            "proof",
            "nullifier_non_membership_root_mismatch",
        )),
    })
}

fn isolated_sequence(
    id: &'static str,
    source_digest: String,
    operation: OperationTemplateExportV0,
    negative_raw: Vec<u8>,
) -> VerticalSequenceExportV0 {
    VerticalSequenceExportV0 {
        id,
        execution_scope: "isolated_prune_transition_kernel",
        source_export_sha256_hex: source_digest,
        steps: vec![step(id, 1, vec![operation])],
        negative: Some(negative_template(
            id,
            negative_raw,
            "proof",
            "nullifier_non_membership_root_mismatch",
        )),
    }
}

fn build_certificate_prune_source_and_sequence(
    mut chain: FixtureChainV0,
    path: &Path,
) -> Result<(SourceReferenceExportV0, VerticalSequenceExportV0)> {
    const SEQUENCE: &str = "certificate_prune_replay";
    let fixture = certificate_fixture(&chain)?;
    let mut block = chain.start_overlay()?;
    let (authorize, after_authorize) = authorize_consumer_key(&block, &fixture, &chain.nullifiers)?;
    block.apply_raw(&authorize.raw)?;
    let (meter, after_meter) = define_meter(&block, &fixture, &after_authorize)?;
    block.apply_raw(&meter.raw)?;
    let (registration, after_registration) =
        register_provider(&block, &chain, &fixture, &after_meter)?;
    block.apply_raw(&registration.raw)?;
    let (funding, after_funding, funding_decision) =
        fund_settlement(&block, &fixture, &after_registration)?;
    block.apply_raw(&funding.raw)?;
    chain.commit_block(block, after_funding)?;

    let mut block = chain.start_overlay()?;
    let (acceptance, after_acceptance) =
        accept_certificate(&block, &fixture, funding_decision, &chain.nullifiers)?;
    block.apply_raw(&acceptance.raw)?;
    chain.commit_block(block, after_acceptance)?;
    let mut block = chain.start_overlay()?;
    let (opening, after_opening, challenge_id) =
        open_challenge(&block, &fixture, &chain.nullifiers)?;
    block.apply_raw(&opening.raw)?;
    chain.commit_block(block, after_opening)?;
    let mut block = chain.start_overlay()?;
    let (resolution, after_resolution) = resolve_challenge(
        &block,
        &fixture,
        challenge_id,
        ChallengeResolutionV0::Rejected,
        &chain.nullifiers,
    )?;
    block.apply_raw(&resolution.raw)?;
    chain.commit_block(block, after_resolution)?;

    // Leave both the prune at 284 and its same-subject replay at the exact
    // lead-3 cutoff 285 inside epoch 28's admitted business-operation window.
    chain.advance_empty_versions(283)?;
    chain.active_epoch = Epoch::new(28);
    let funding_operation = PocoApplicationOperationV0::decode_exact(&funding.raw)?;
    let certificate_id = *fixture.certificate.certificate_id().as_bytes();
    let lineage = LineageBaseIntentExportV0 {
        operation_kind: "fund_settlement",
        normalized_business_intent_digest_hex: hex::encode(normalized_business_intent_digest(
            &funding_operation,
        )?),
        subjects: LineageSubjectsV0::Certificate(CertificateLineageSubjectsV0 {
            certificate_id_hex: hex::encode(certificate_id),
        }),
    };
    let (reference, _) = write_isolated_source(path, &chain, lineage)?;
    let source_digest = reference.sha256_hex.clone();
    let stale_proof_basis = chain.nullifiers.clone();
    let mut block = chain.start_overlay()?;
    let (prune, after_prune) = prune_certificate(&block, certificate_id, &chain.nullifiers)?;
    block.apply_raw(&prune.raw)?;
    chain.commit_block(block, after_prune)?;
    let negative_block = chain.start_overlay()?;
    let negative_raw = fund_settlement_with_proof_basis(
        &negative_block,
        certificate_id,
        fixture.settlement_commitment,
        10,
        &chain.nullifiers,
        &stale_proof_basis,
    )?;
    Ok((
        reference,
        isolated_sequence(SEQUENCE, source_digest, prune.template, negative_raw),
    ))
}

fn build_consumer_key_prune_source_and_sequence(
    mut chain: FixtureChainV0,
    path: &Path,
) -> Result<(SourceReferenceExportV0, VerticalSequenceExportV0)> {
    const SEQUENCE: &str = "consumer_key_prune_replay";
    let fixture = certificate_fixture(&chain)?;
    let mut block = chain.start_overlay()?;
    let (authorization, after_authorization) =
        authorize_consumer_key(&block, &fixture, &chain.nullifiers)?;
    block.apply_raw(&authorization.raw)?;
    chain.commit_block(block, after_authorization)?;
    let mut block = chain.start_overlay()?;
    let (revocation, after_revocation) = revoke_consumer_key(&block, &fixture, &chain.nullifiers)?;
    block.apply_raw(&revocation.raw)?;
    chain.commit_block(block, after_revocation)?;

    chain.advance_empty_versions(283)?;
    chain.active_epoch = Epoch::new(28);
    let base = PocoApplicationOperationV0::decode_exact(&authorization.raw)?;
    let lineage = LineageBaseIntentExportV0 {
        operation_kind: "authorize_consumer_key",
        normalized_business_intent_digest_hex: hex::encode(normalized_business_intent_digest(
            &base,
        )?),
        subjects: LineageSubjectsV0::ConsumerKey(ConsumerKeyLineageSubjectsV0 {
            consumer_id_hex: hex::encode(&fixture.consumer_id),
            consumer_key_id_hex: hex::encode(&fixture.consumer_key_id),
        }),
    };
    let (reference, _) = write_isolated_source(path, &chain, lineage)?;
    let source_digest = reference.sha256_hex.clone();
    let mut block = chain.start_overlay()?;
    let (prune, after_prune) = prune_consumer_key(&block, &fixture, &chain.nullifiers)?;
    block.apply_raw(&prune.raw)?;
    chain.commit_block(block, after_prune)?;

    let negative_block = chain.start_overlay()?;
    let identity = joined_identity(&[&fixture.consumer_id, &fixture.consumer_key_id]);
    let identity_digest =
        semantic_identity_digest_v0(PocoSnapshotEntryKindV0::ConsumerKeyAuthorization, &identity);
    let mut payload = identity.clone();
    payload.extend_from_slice(&fixture.consumer_signing_key.verifying_key().to_bytes());
    payload.extend_from_slice(&negative_block.context.target_height.get().to_be_bytes());
    optional_u64(&mut payload, None);
    let change = semantic_change(
        &negative_block,
        PocoSnapshotEntryKindV0::ConsumerKeyAuthorization,
        &identity,
        &payload,
    )?;
    let (negative_prefix, after_decision, _) = finish_operation(
        &negative_block,
        "state-dependent-same-subject-replay",
        "authorize_consumer_key",
        PocoApplicationOperationBodyV0::AuthorizeConsumerKey {
            consumer_id_hex: hex::encode(&fixture.consumer_id),
            consumer_key_id_hex: hex::encode(&fixture.consumer_key_id),
            public_key_hex: hex::encode(fixture.consumer_signing_key.verifying_key().to_bytes()),
            active_from_height: negative_block.context.target_height.get(),
            decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::ConsumerKeyDecision,
            subject: ProofSubjectV0::Decision("authorize-consumer-key"),
        }],
        &chain.nullifiers,
    )?;
    let negative_raw = append_stale_permanent_identity_insertion(
        &negative_prefix.raw,
        &after_decision,
        PocoNullifierFamilyV0::ConsumerKeyIdentity,
        identity_digest,
    )?;
    Ok((
        reference,
        isolated_sequence(SEQUENCE, source_digest, prune.template, negative_raw),
    ))
}

fn build_meter_prune_source_and_sequence(
    mut chain: FixtureChainV0,
    path: &Path,
) -> Result<(SourceReferenceExportV0, VerticalSequenceExportV0)> {
    const SEQUENCE: &str = "meter_prune_replay";
    let fixture = certificate_fixture(&chain)?;
    let mut block = chain.start_overlay()?;
    let (definition, after_definition) = define_meter(&block, &fixture, &chain.nullifiers)?;
    block.apply_raw(&definition.raw)?;
    chain.commit_block(block, after_definition)?;
    let mut block = chain.start_overlay()?;
    let (retirement, after_retirement) = retire_meter(&block, &fixture, &chain.nullifiers)?;
    block.apply_raw(&retirement.raw)?;
    chain.commit_block(block, after_retirement)?;

    chain.advance_empty_versions(283)?;
    chain.active_epoch = Epoch::new(28);
    let base = PocoApplicationOperationV0::decode_exact(&definition.raw)?;
    let lineage = LineageBaseIntentExportV0 {
        operation_kind: "define_meter_policy",
        normalized_business_intent_digest_hex: hex::encode(normalized_business_intent_digest(
            &base,
        )?),
        subjects: LineageSubjectsV0::Meter(MeterLineageSubjectsV0 {
            meter_id_hex: hex::encode(&fixture.meter_id),
            meter_version: 1,
        }),
    };
    let (reference, _) = write_isolated_source(path, &chain, lineage)?;
    let source_digest = reference.sha256_hex.clone();
    let mut block = chain.start_overlay()?;
    let (prune, after_prune) = prune_meter(&block, &fixture, &chain.nullifiers)?;
    block.apply_raw(&prune.raw)?;
    chain.commit_block(block, after_prune)?;

    let negative_block = chain.start_overlay()?;
    let mut identity = Vec::new();
    encode_bytes(&mut identity, &fixture.meter_id);
    identity.extend_from_slice(&1u32.to_be_bytes());
    let identity_digest =
        semantic_identity_digest_v0(PocoSnapshotEntryKindV0::MeterDefinition, &identity);
    let mut payload = identity.clone();
    payload.extend_from_slice(&1u128.to_be_bytes());
    payload.extend_from_slice(&negative_block.context.target_height.get().to_be_bytes());
    optional_u64(&mut payload, None);
    let change = semantic_change(
        &negative_block,
        PocoSnapshotEntryKindV0::MeterDefinition,
        &identity,
        &payload,
    )?;
    let policy = MeterAuthorityPolicyV0 {
        meter_id_hex: hex::encode(&fixture.meter_id),
        meter_version: 1,
        task_id_hex: hex::encode(&fixture.task_id),
        output_commitment_hex: Some(hex::encode(fixture.output_commitment)),
        unit_scale: CanonicalU128V0::new(1),
        evidence_policy: MeterEvidencePolicyV0::Optional,
        per_certificate_cap: CanonicalU128V0::new(10),
        rolling_cap: CanonicalU128V0::new(100),
        rolling_epoch_span: 1,
        retention_blocks: 1,
        active_from_height: negative_block.context.target_height.get(),
        retired_at_height: None,
    };
    let (negative_prefix, after_decision, _) = finish_operation(
        &negative_block,
        "state-dependent-same-subject-replay",
        "define_meter_policy",
        PocoApplicationOperationBodyV0::DefineMeterPolicy {
            policy,
            decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![ProofRequestV0 {
            list: "insertion",
            family: PocoNullifierFamilyV0::MeterDecision,
            subject: ProofSubjectV0::Decision("define-meter"),
        }],
        &chain.nullifiers,
    )?;
    let negative_raw = append_stale_permanent_identity_insertion(
        &negative_prefix.raw,
        &after_decision,
        PocoNullifierFamilyV0::MeterIdentity,
        identity_digest,
    )?;
    Ok((
        reference,
        isolated_sequence(SEQUENCE, source_digest, prune.template, negative_raw),
    ))
}

fn build_validator_prune_source_and_sequence(
    mut chain: FixtureChainV0,
    path: &Path,
) -> Result<(SourceReferenceExportV0, VerticalSequenceExportV0)> {
    const SEQUENCE: &str = "validator_prune_replay";
    let validator_id = b"validator-prune-a".to_vec();
    let signing_key = SigningKey::from_bytes(&[43; 32]);
    let mut block = chain.start_overlay()?;
    let (registration, after_registration) = register_rotation_fixture(
        &block,
        &chain,
        &validator_id,
        &signing_key,
        1,
        &chain.nullifiers,
    )?;
    block.apply_raw(&registration.raw)?;
    chain.commit_block(block, after_registration)?;
    let mut block = chain.start_overlay()?;
    let (revocation, after_revocation) = revoke_fixture_validator(
        &block,
        &chain,
        &validator_id,
        &signing_key,
        1,
        &chain.nullifiers,
    )?;
    block.apply_raw(&revocation.raw)?;
    chain.commit_block(block, after_revocation)?;

    chain.advance_empty_versions(283)?;
    chain.active_epoch = Epoch::new(28);
    let base = PocoApplicationOperationV0::decode_exact(&registration.raw)?;
    let lineage = LineageBaseIntentExportV0 {
        operation_kind: "register_validator",
        normalized_business_intent_digest_hex: hex::encode(normalized_business_intent_digest(
            &base,
        )?),
        subjects: LineageSubjectsV0::Validator(ValidatorLineageSubjectsV0 {
            validator_id_hex: hex::encode(&validator_id),
        }),
    };
    let (reference, _) = write_isolated_source(path, &chain, lineage)?;
    let source_digest = reference.sha256_hex.clone();
    let before_prune = chain.nullifiers.clone();
    let mut block = chain.start_overlay()?;
    let (prune, after_prune) = prune_validator_history(&block, &validator_id, &chain.nullifiers)?;
    block.apply_raw(&prune.raw)?;
    chain.commit_block(block, after_prune)?;

    let negative_block = chain.start_overlay()?;
    let identity_digest = semantic_identity_digest_v0(
        PocoSnapshotEntryKindV0::ValidatorRegistration,
        &validator_id,
    );
    let consensus_key = signing_key.verifying_key().to_bytes();
    let mut proof_basis = before_prune;
    proof_basis.occupied.retain(|(family, identifier)| {
        !((*family == PocoNullifierFamilyV0::ValidatorIdentity && *identifier == identity_digest)
            || (*family == PocoNullifierFamilyV0::ValidatorConsensusKey
                && *identifier == consensus_key))
    });
    let change = validator_registration_change(
        &negative_block,
        &chain,
        &validator_id,
        &signing_key,
        1,
        RegistrationStateV0::Active,
    )?;
    let (negative, _, _) = finish_operation_with_proof_basis(
        &negative_block,
        "state-dependent-same-subject-replay",
        "register_validator",
        PocoApplicationOperationBodyV0::RegisterValidator {
            validator_id_hex: hex::encode(&validator_id),
            target_epoch: chain.active_epoch.get(),
            registration_decision_id_hex: "0".repeat(64),
        },
        vec![change],
        vec![
            ProofRequestV0 {
                list: "non_membership",
                family: PocoNullifierFamilyV0::ValidatorIdentity,
                subject: ProofSubjectV0::Literal(identity_digest),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::RegistrationDecision,
                subject: ProofSubjectV0::Decision("register-validator"),
            },
            ProofRequestV0 {
                list: "insertion",
                family: PocoNullifierFamilyV0::ValidatorConsensusKey,
                subject: ProofSubjectV0::Literal(consensus_key),
            },
        ],
        &chain.nullifiers,
        &proof_basis,
    )?;
    Ok((
        reference,
        isolated_sequence(SEQUENCE, source_digest, prune.template, negative.raw),
    ))
}

fn authenticated_candidate_compact_parameters_with_snapshot_lead_v0(
    snapshot_lead_blocks: u64,
) -> Result<ConsensusParametersV0> {
    let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
    fields.epoch_length_blocks = AUTHENTICATED_CANDIDATE_EPOCH_LENGTH;
    fields.snapshot_lead_blocks = snapshot_lead_blocks;
    // Keep the production maturity rule. Small divisors make the four
    // ten-unit certificates and ten-unit bonds observable without weakening
    // any admission or epoch rule.
    fields.units_per_power = 1;
    fields.bond_atomic_units_per_power = 1;
    ConsensusParametersV0::new(fields)
        .map_err(|error| anyhow::anyhow!("compact candidate parameters: {error:?}"))
}

fn authenticated_candidate_validator_set_v0(
    chain_id: ChainId,
    genesis_hash: GenesisHash,
    parameters: &ConsensusParametersV0,
    epoch: Epoch,
) -> Result<ValidatorSet> {
    let mut validators = [b'a', b'b', b'c', b'd']
        .into_iter()
        .map(|suffix| {
            let validator_id = tagged_fixture_id(b"validator-", suffix);
            let signing_key = provider_fixture_signing_key_for_id(&validator_id);
            Validator::new(
                ValidatorId::from_bytes(&validator_id)
                    .map_err(|error| anyhow::anyhow!("candidate validator ID: {error:?}"))?,
                trnm_consensus_types::ConsensusPublicKey::new(
                    signing_key.verifying_key().to_bytes(),
                ),
                VotingPower::new(10)
                    .map_err(|error| anyhow::anyhow!("candidate validator power: {error:?}"))?,
            )
            .map_err(|error| anyhow::anyhow!("candidate validator: {error:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    validators.sort_by_key(Validator::id);
    let set = ValidatorSet::new(
        genesis_hash,
        chain_id,
        ProtocolVersion::V0,
        epoch,
        parameters.hash(),
        validators,
    )
    .map_err(|error| anyhow::anyhow!("candidate validator set: {error:?}"))?;
    set.validate_against_parameters(parameters)
        .map_err(|error| anyhow::anyhow!("candidate validator-set parameters: {error:?}"))?;
    Ok(set)
}

fn authenticated_candidate_semantic_entry_v0(
    kind: PocoSnapshotEntryKindV0,
    revision: u64,
    identity: &[u8],
    payload: &[u8],
) -> Result<PocoSnapshotEntryV0> {
    PocoSnapshotEntryV0::new(
        kind,
        semantic_identity_digest_v0(kind, identity).to_vec(),
        encode_test_semantic_envelope_v0(kind, revision, identity, payload),
    )
}

fn authenticated_candidate_configuration_entries_v0(
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> Result<Vec<PocoSnapshotEntryV0>> {
    ensure!(
        validator_set.consensus_parameters_hash() == parameters.hash(),
        "candidate configuration parameter hash mismatch"
    );
    let mut identity = vec![1];
    identity.extend_from_slice(&validator_set.epoch().get().to_be_bytes());
    Ok(vec![
        authenticated_candidate_semantic_entry_v0(
            PocoSnapshotEntryKindV0::ValidatorConfiguration,
            1,
            &identity,
            &validator_set
                .try_cev0_bytes()
                .map_err(|error| anyhow::anyhow!("encode candidate validator set: {error:?}"))?,
        )?,
        authenticated_candidate_semantic_entry_v0(
            PocoSnapshotEntryKindV0::ConsensusParameters,
            1,
            &identity,
            &parameters.canonical_bytes(),
        )?,
    ])
}

fn authenticated_candidate_relationship_entry_v0(
    fixture: &CertificateFixtureV0,
) -> Result<PocoSnapshotEntryV0> {
    let identity = joined_identity(&[&fixture.provider_id, &fixture.consumer_id, &fixture.task_id]);
    let mut payload = identity.clone();
    payload.push(RelationshipClassV0::Independent as u8);
    payload.extend_from_slice(&64u64.to_be_bytes());
    authenticated_candidate_semantic_entry_v0(
        PocoSnapshotEntryKindV0::RelationshipClassification,
        1,
        &identity,
        &payload,
    )
}

fn authenticated_candidate_bond_entry_v0(
    validator_id: &[u8],
    amount: u128,
    locked_until: u64,
) -> Result<PocoSnapshotEntryV0> {
    let mut payload = Vec::new();
    encode_bytes(&mut payload, validator_id);
    payload.extend_from_slice(&amount.to_be_bytes());
    payload.extend_from_slice(&locked_until.to_be_bytes());
    payload.push(BondStateV0::ActiveSlashable as u8);
    authenticated_candidate_semantic_entry_v0(
        PocoSnapshotEntryKindV0::ActiveBond,
        1,
        validator_id,
        &payload,
    )
}

fn authenticated_candidate_authority_v0(
    projection: &ProductionPocoProjectionV0,
) -> Result<PocoApplicationAuthorityStateV0> {
    let entry = projection
        .entries()
        .iter()
        .find(|entry| entry.kind == PocoSnapshotEntryKindV0::ApplicationAuthorityState)
        .context("candidate projection lacks kind-16 authority")?;
    let parts =
        decode_poco_snapshot_value_parts_v0_exact(entry.kind, &entry.logical_key, &entry.value)?;
    let authority = PocoApplicationAuthorityStateV0::decode_exact(parts.payload)?;
    ensure!(
        authority.revision() == parts.verified.revision(),
        "candidate authority envelope revision drift"
    );
    Ok(authority)
}

fn authenticated_candidate_projection_commit_v0(
    chain: &mut FixtureChainV0,
    mut target_entries: Vec<PocoSnapshotEntryV0>,
) -> Result<()> {
    let target_height = chain
        .source_version
        .checked_add(1)
        .context("candidate fixture projection height overflow")?;
    target_entries.sort_by(|left, right| {
        (left.kind, left.logical_key.as_slice()).cmp(&(right.kind, right.logical_key.as_slice()))
    });
    let source = chain
        .projection
        .entries()
        .iter()
        .map(|entry| ((entry.kind, entry.logical_key.clone()), entry))
        .collect::<BTreeMap<_, _>>();
    let target = target_entries
        .iter()
        .map(|entry| ((entry.kind, entry.logical_key.clone()), entry))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        target.len() == target_entries.len(),
        "candidate target projection contains duplicate keys"
    );
    let mut writes = Vec::new();
    for (key, entry) in &source {
        if !target.contains_key(key) {
            writes.push(AuthWrite::delete_poco_snapshot(
                PocoWritePermitV0::test_only(),
                entry.jmt_key()?,
            )?);
        }
    }
    for (key, entry) in &target {
        if source
            .get(key)
            .is_none_or(|source| source.value != entry.value)
        {
            writes.push(AuthWrite::put_poco_snapshot(
                PocoWritePermitV0::test_only(),
                entry.jmt_key()?,
                entry.value.clone(),
            )?);
        }
    }
    let manifest =
        PocoSnapshotManifestV0::from_entries(Height::new(target_height), &target_entries)?;
    writes.push(AuthWrite::put_poco_snapshot(
        PocoWritePermitV0::test_only(),
        poco_snapshot_manifest_key()?,
        manifest.encode(),
    )?);
    writes.sort_by(|left, right| left.key().cmp(right.key()));
    chain.commit_fixture_writes(writes)?;
    ensure!(
        chain.projection.entries() == target_entries.as_slice(),
        "candidate committed projection differs from requested target"
    );
    Ok(())
}

fn authenticated_candidate_genesis_with_snapshot_lead_v0(
    snapshot_lead_blocks: u64,
) -> Result<FixtureChainV0> {
    let chain_id = ChainId::from_static("trnm-poco-authenticated-candidate-v0");
    let genesis_hash = GenesisHash::new([0x61; 32]);
    let parameters =
        authenticated_candidate_compact_parameters_with_snapshot_lead_v0(snapshot_lead_blocks)?;
    let validator_set = authenticated_candidate_validator_set_v0(
        chain_id,
        genesis_hash,
        &parameters,
        Epoch::new(0),
    )?;
    let provisional = FixtureChainV0 {
        tree: InMemoryAuthTree::default(),
        projection: {
            // Replaced below after the version-zero authenticated commit.
            let authority = genesis_poco_application_authority_entry_v0()?;
            let manifest = PocoSnapshotManifestV0::from_entries(
                Height::new(0),
                std::slice::from_ref(&authority),
            )?;
            let mut live = BTreeMap::new();
            live.insert(poco_snapshot_manifest_key()?, manifest.encode());
            live.insert(authority.jmt_key()?, authority.value);
            take_and_validate_production_poco_projection_v0(0, &mut live)?
                .context("build provisional candidate projection")?
        },
        source_version: 0,
        source_root: [0; 32],
        chain_id,
        genesis_hash,
        active_epoch: Epoch::new(0),
        active_parameters: parameters,
        authority_signer_commitment: [0x62; 32],
        nullifiers: FixtureNullifierSetV0::default(),
        active_genesis: None,
        history: Vec::new(),
    };
    let mut fixtures = [
        (b'a', 0, b"validator-a".as_slice()),
        (b'b', 1, b"validator-b".as_slice()),
        (b'c', 2, b"validator-c".as_slice()),
        (b'e', 3, b"validator-e".as_slice()),
    ]
    .into_iter()
    .map(|(suffix, ordinal, provider)| {
        certificate_fixture_for_provider(&provisional, suffix, ordinal, provider)
    })
    .collect::<Result<Vec<_>>>()?;
    fixtures.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));

    let mut entries =
        authenticated_candidate_configuration_entries_v0(&validator_set, &parameters)?;
    entries.push(genesis_poco_application_authority_entry_v0()?);
    for fixture in &fixtures {
        entries.push(authenticated_candidate_relationship_entry_v0(fixture)?);
    }
    entries.sort_by(|left, right| {
        (left.kind, left.logical_key.as_slice()).cmp(&(right.kind, right.logical_key.as_slice()))
    });
    let writes = genesis_poco_snapshot_writes_v0(&entries)?;
    let exported_writes = writes
        .iter()
        .map(|write| PhysicalWriteExportV0 {
            physical_key_hex: hex::encode(write.key()),
            value_hex: write.value().map(hex::encode),
        })
        .collect::<Vec<_>>();
    let mut tree = InMemoryAuthTree::default();
    tree.put_value_set(0, writes)?;
    let source_root: [u8; 32] = tree
        .root_hash(0)
        .context("candidate genesis root missing")?
        .into();
    let projection = projection_at(&tree, 0)?;
    validate_application_authority_projection_v0(&projection)?;
    Ok(FixtureChainV0 {
        tree,
        projection,
        source_version: 0,
        source_root,
        chain_id,
        genesis_hash,
        active_epoch: Epoch::new(0),
        active_parameters: parameters,
        authority_signer_commitment: [0x62; 32],
        nullifiers: FixtureNullifierSetV0::default(),
        active_genesis: None,
        history: vec![HistoryExportV0 {
            version: 0,
            jmt_root_hex: hex::encode(source_root),
            writes: exported_writes,
        }],
    })
}

fn authenticated_candidate_genesis_v0() -> Result<FixtureChainV0> {
    authenticated_candidate_genesis_with_snapshot_lead_v0(AUTHENTICATED_CANDIDATE_SNAPSHOT_LEAD)
}

/// Supplies the exact empty-authority, epoch-zero namespace accepted by the
/// production InitChain validator. ABCI evidence later installs the explicitly
/// labelled fixture-only epoch-two source at its real manifest height; this
/// helper never weakens the production genesis contract.
pub(crate) fn authenticated_candidate_abci_genesis_entries_v0() -> Result<Vec<PocoSnapshotEntryV0>>
{
    Ok(authenticated_candidate_genesis_v0()?
        .projection
        .entries()
        .to_vec())
}

fn authenticated_candidate_fixtures_v0(
    chain: &FixtureChainV0,
) -> Result<Vec<CertificateFixtureV0>> {
    [
        (b'a', 0, b"validator-a".as_slice()),
        (b'b', 1, b"validator-b".as_slice()),
        (b'c', 2, b"validator-c".as_slice()),
        (b'e', 3, b"validator-e".as_slice()),
    ]
    .into_iter()
    .map(|(suffix, ordinal, provider)| {
        certificate_fixture_for_provider(chain, suffix, ordinal, provider)
    })
    .collect()
}

fn authenticated_candidate_step_v0(
    height: u64,
    purpose: &'static str,
    operations: &[Vec<u8>],
) -> AuthenticatedCandidateBlockStepExportV0 {
    AuthenticatedCandidateBlockStepExportV0 {
        height,
        purpose,
        raw_operation_json_hexes: operations.iter().map(hex::encode).collect(),
    }
}

fn authenticated_candidate_boundary_v0(
    chain: &mut FixtureChainV0,
) -> Result<AuthenticatedCandidateBoundaryFactsV0> {
    ensure!(
        chain.source_version == AUTHENTICATED_CANDIDATE_BOUNDARY_HEIGHT - 1,
        "candidate boundary source height drift"
    );
    let mut authority = authenticated_candidate_authority_v0(&chain.projection)?;
    ensure!(
        authority.active_certificates.len() == 4
            && authority.active_certificates.iter().all(|certificate| {
                certificate.provider_registration_height == 1
                    && certificate.accepted_height == 2
                    && certificate.finalized_epoch == 0
            }),
        "candidate certificates do not reconstruct epoch-zero production acceptance"
    );
    let facts = AuthenticatedCandidateBoundaryFactsV0 {
        cleared_meter_usage: u32::try_from(authority.meter_usage.len())
            .context("meter usage count exceeds u32")?,
        cleared_consumer_provider_usage: u32::try_from(authority.consumer_provider_usage.len())
            .context("consumer-provider usage count exceeds u32")?,
        cleared_task_provider_usage: u32::try_from(authority.task_provider_usage.len())
            .context("task-provider usage count exceeds u32")?,
        cleared_provider_usage: u32::try_from(authority.provider_usage.len())
            .context("provider usage count exceeds u32")?,
        preserved_certificate_ids_hex: authority
            .active_certificates
            .iter()
            .map(|certificate| certificate.certificate_id_hex.clone())
            .collect(),
    };
    ensure!(
        facts.cleared_meter_usage == 4
            && facts.cleared_consumer_provider_usage == 4
            && facts.cleared_task_provider_usage == 4
            && facts.cleared_provider_usage == 4,
        "candidate epoch-zero usage fixture does not cover all rollover families"
    );
    // This is a fixture/bootstrap state transition, explicitly not an
    // application operation or a claim that Core epoch activation exists.
    authority.meter_usage.clear();
    authority.consumer_provider_usage.clear();
    authority.task_provider_usage.clear();
    authority.provider_usage.clear();
    authority.revision = authority
        .revision
        .checked_add(1)
        .context("candidate boundary authority revision overflow")?;
    authority.last_target_height = AUTHENTICATED_CANDIDATE_BOUNDARY_HEIGHT;

    let parameters = chain.active_parameters;
    let validator_set = authenticated_candidate_validator_set_v0(
        chain.chain_id,
        chain.genesis_hash,
        &parameters,
        Epoch::new(AUTHENTICATED_CANDIDATE_ACTIVE_EPOCH),
    )?;
    let mut target = Vec::new();
    for entry in chain.projection.entries() {
        let role_one_configuration = if matches!(
            entry.kind,
            PocoSnapshotEntryKindV0::ValidatorConfiguration
                | PocoSnapshotEntryKindV0::ConsensusParameters
        ) {
            let parts = decode_poco_snapshot_value_parts_v0_exact(
                entry.kind,
                &entry.logical_key,
                &entry.value,
            )?;
            parts.identity.first().copied() == Some(1)
        } else {
            false
        };
        if !role_one_configuration
            && entry.kind != PocoSnapshotEntryKindV0::ApplicationAuthorityState
        {
            target.push(entry.clone());
        }
    }
    target.extend(authenticated_candidate_configuration_entries_v0(
        &validator_set,
        &parameters,
    )?);
    target.push(PocoSnapshotEntryV0::new(
        PocoSnapshotEntryKindV0::ApplicationAuthorityState,
        poco_application_authority_logical_key_v0().to_vec(),
        encode_application_authority_envelope_v0(&authority)?,
    )?);
    for validator_id in [
        b"validator-a".as_slice(),
        b"validator-b".as_slice(),
        b"validator-c".as_slice(),
        b"validator-e".as_slice(),
    ] {
        target.push(authenticated_candidate_bond_entry_v0(
            validator_id,
            10,
            AUTHENTICATED_CANDIDATE_TARGET_EPOCH
                .checked_add(parameters.evidence_window_epochs())
                .and_then(|coverage_end| coverage_end.checked_add(1))
                .context("candidate bond lock epoch overflow")?,
        )?);
    }
    authenticated_candidate_projection_commit_v0(chain, target)?;
    chain.active_epoch = Epoch::new(AUTHENTICATED_CANDIDATE_ACTIVE_EPOCH);
    chain.active_parameters = parameters;
    validate_application_authority_projection_v0(&chain.projection)?;
    let after = authenticated_candidate_authority_v0(&chain.projection)?;
    ensure!(
        after
            .active_certificates
            .iter()
            .map(|certificate| certificate.certificate_id_hex.clone())
            .collect::<Vec<_>>()
            == facts.preserved_certificate_ids_hex
            && after.meter_usage.is_empty()
            && after.consumer_provider_usage.is_empty()
            && after.task_provider_usage.is_empty()
            && after.provider_usage.is_empty(),
        "candidate boundary changed certificate authority or retained stale usage"
    );
    Ok(facts)
}

#[allow(clippy::type_complexity)]
fn authenticated_candidate_common_history_from_chain_v0(
    mut chain: FixtureChainV0,
) -> Result<(
    FixtureChainV0,
    Vec<CertificateFixtureV0>,
    Vec<AuthenticatedCandidateBlockStepExportV0>,
    AuthenticatedCandidateBoundaryFactsV0,
)> {
    let fixtures = authenticated_candidate_fixtures_v0(&chain)?;
    let mut steps = Vec::new();

    let mut block = chain.start_overlay()?;
    let mut next_nullifiers = chain.nullifiers.clone();
    let mut first_raw = Vec::new();
    let mut funding_decisions = Vec::new();
    for fixture in &fixtures {
        let (authorize, next) = authorize_consumer_key(&block, fixture, &next_nullifiers)?;
        block.apply_raw(&authorize.raw)?;
        first_raw.push(authorize.raw);
        next_nullifiers = next;

        let (meter, next) = define_meter(&block, fixture, &next_nullifiers)?;
        block.apply_raw(&meter.raw)?;
        first_raw.push(meter.raw);
        next_nullifiers = next;

        let (registration, next) = register_provider(&block, &chain, fixture, &next_nullifiers)?;
        block.apply_raw(&registration.raw)?;
        first_raw.push(registration.raw);
        next_nullifiers = next;

        let (funding, next, decision) = fund_settlement(&block, fixture, &next_nullifiers)?;
        block.apply_raw(&funding.raw)?;
        first_raw.push(funding.raw);
        next_nullifiers = next;
        funding_decisions.push(decision);
    }
    ensure!(
        first_raw.len() == 16,
        "candidate admission block operation drift"
    );
    chain.commit_block(block, next_nullifiers)?;
    steps.push(authenticated_candidate_step_v0(
        1,
        "four_provider_admission_and_funding",
        &first_raw,
    ));

    let mut block = chain.start_overlay()?;
    let mut next_nullifiers = chain.nullifiers.clone();
    let mut second_raw = Vec::new();
    for (fixture, funding_decision) in fixtures.iter().zip(funding_decisions) {
        let (acceptance, next) =
            accept_certificate(&block, fixture, funding_decision, &next_nullifiers)?;
        block.apply_raw(&acceptance.raw)?;
        second_raw.push(acceptance.raw);
        next_nullifiers = next;
    }
    ensure!(
        second_raw.len() == 4,
        "candidate acceptance block operation drift"
    );
    chain.commit_block(block, next_nullifiers)?;
    steps.push(authenticated_candidate_step_v0(
        2,
        "four_epoch_zero_certificate_acceptances",
        &second_raw,
    ));
    validate_application_authority_projection_v0(&chain.projection)?;

    chain.advance_empty_versions(AUTHENTICATED_CANDIDATE_BOUNDARY_HEIGHT - 1)?;
    let boundary = authenticated_candidate_boundary_v0(&mut chain)?;
    steps.push(authenticated_candidate_step_v0(
        AUTHENTICATED_CANDIDATE_BOUNDARY_HEIGHT,
        "fixture_only_epoch_two_bootstrap_and_usage_rollover",
        &[],
    ));

    let authority = authenticated_candidate_authority_v0(&chain.projection)?;
    let validator_a = hex::encode(b"validator-a");
    let history_a = authority
        .validator_registration_history
        .binary_search_by(|history| history.validator_id_hex.cmp(&validator_a))
        .ok()
        .map(|index| &authority.validator_registration_history[index])
        .context("candidate changed-key predecessor history missing")?;
    let predecessor_head = exact_hash32(
        &history_a.history_head_hex,
        "candidate predecessor history head",
    )?;
    let previous_nonce = history_a.max_registration_nonce;
    let future_a = provider_fixture_signing_key_for_id(b"future-validator-a");
    let future_e = provider_fixture_signing_key_for_id(b"future-validator-e");
    let mut block = chain.start_overlay()?;
    let (changed_a, after_a) = register_future_candidate_fixture(
        &block,
        &chain,
        b"validator-a",
        &future_a,
        previous_nonce
            .checked_add(1)
            .context("candidate A future nonce overflow")?,
        Some(previous_nonce),
        predecessor_head,
        &chain.nullifiers,
    )?;
    block.apply_raw(&changed_a.raw)?;
    let (new_e, after_e) = register_future_candidate_fixture(
        &block,
        &chain,
        b"validator-e",
        &future_e,
        2,
        None,
        [0; 32],
        &after_a,
    )?;
    block.apply_raw(&new_e.raw)?;
    let future_raw = vec![changed_a.raw, new_e.raw];
    chain.commit_block(block, after_e)?;
    ensure!(
        chain.source_version == AUTHENTICATED_CANDIDATE_FUTURE_REGISTRATION_HEIGHT,
        "candidate future-registration height drift"
    );
    steps.push(authenticated_candidate_step_v0(
        AUTHENTICATED_CANDIDATE_FUTURE_REGISTRATION_HEIGHT,
        "strict_successor_epoch_changed_and_new_candidate_pop",
        &future_raw,
    ));
    validate_application_authority_projection_v0(&chain.projection)?;
    Ok((chain, fixtures, steps, boundary))
}

#[allow(clippy::type_complexity)]
fn authenticated_candidate_common_history_v0() -> Result<(
    FixtureChainV0,
    Vec<CertificateFixtureV0>,
    Vec<AuthenticatedCandidateBlockStepExportV0>,
    AuthenticatedCandidateBoundaryFactsV0,
)> {
    authenticated_candidate_common_history_from_chain_v0(authenticated_candidate_genesis_v0()?)
}

fn authenticated_candidate_scenario_v0(
    mut chain: FixtureChainV0,
    fixtures: &[CertificateFixtureV0],
    mut steps: Vec<AuthenticatedCandidateBlockStepExportV0>,
    fallback: bool,
) -> Result<AuthenticatedCandidateScenarioExportV0> {
    if fallback {
        let mut block = chain.start_overlay()?;
        let (opening, next, _) = open_challenge(&block, &fixtures[0], &chain.nullifiers)?;
        block.apply_raw(&opening.raw)?;
        let raw = vec![opening.raw];
        chain.commit_block(block, next)?;
        steps.push(authenticated_candidate_step_v0(
            AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT - 2,
            "authenticated_pending_challenge_removes_one_contribution",
            &raw,
        ));
    }
    chain.advance_empty_versions(AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT - 1)?;
    if !fallback {
        steps.push(authenticated_candidate_step_v0(
            AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT - 1,
            "positive_projection_no_change",
            &[],
        ));
    }
    ensure!(
        chain.source_version == AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT - 1,
        "candidate pre-cutoff height drift"
    );
    let refresh = scheduled_cutoff_manifest_refresh_write_v0(
        Height::new(AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT),
        &chain.projection,
    )?;
    chain.commit_fixture_writes(vec![refresh])?;
    steps.push(authenticated_candidate_step_v0(
        AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT,
        "scheduled_cutoff_manifest_refresh",
        &[],
    ));
    let cutoff_root = chain.source_root;
    let cutoff_projection = chain.projection.clone();
    ensure!(
        cutoff_projection.manifest().cutoff_height().get() == AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT,
        "candidate manifest is not refreshed at cutoff"
    );
    let parent_height = AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT - 1;
    chain.advance_empty_versions(parent_height)?;
    let head_projection = projection_at(&chain.tree, chain.source_version)?;
    ensure!(
        head_projection.entries() == cutoff_projection.entries()
            && head_projection.manifest().entries_root()
                == cutoff_projection.manifest().entries_root(),
        "candidate projection changed after cutoff"
    );

    let auth_tree = Mutex::new(chain.tree.clone());
    let cutoff = maybe_authenticated_poco_projection_at_v0(
        None,
        &auth_tree,
        AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT,
    )?
    .context("candidate authenticated cutoff missing")?;
    let (old_set, parameters) = active_consensus_configuration(cutoff.projection())?;
    let active_validators = old_set
        .validators()
        .iter()
        .map(|validator| ConsensusValidatorV1 {
            public_key_hex: hex::encode(validator.consensus_key().as_bytes()),
            voting_power: validator.voting_power().get(),
        })
        .collect::<Vec<_>>();
    let parent_root: [u8; 32] = chain
        .tree
        .root_hash(parent_height)
        .context("candidate checkpoint parent root missing")?
        .into();
    ensure!(
        chain.source_version == parent_height && chain.source_root == parent_root,
        "candidate exported source head is not the committed checkpoint parent"
    );
    let next_plan = chain.tree.plan_put_value_set(
        AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT,
        std::iter::empty::<AuthWrite>(),
    )?;
    let next_root: [u8; 32] = next_plan.root_hash.into();
    let block_hash = if fallback { [0x92; 32] } else { [0x91; 32] };
    let timestamp_ms = if fallback { 22_002 } else { 22_001 };
    let txs: Vec<Bytes> = Vec::new();
    let results: Vec<ExecTxResult> = Vec::new();
    let authority = PocoAuthorityConfigV0 {
        schema: POCO_AUTHORITY_CONFIG_SCHEMA_V0.to_string(),
        genesis_hash_hex: hex::encode(chain.genesis_hash.as_bytes()),
        protocol_profile_hash_hex: hex::encode(parameters.hash().as_bytes()),
    };
    let chain_id = String::from_utf8(chain.chain_id.as_bytes().to_vec())
        .context("candidate fixture chain ID is not UTF-8")?;
    let capability = authorize_poco_checkpoint_candidate_selection_v0(
        &authority,
        PocoCheckpointExecutionInputV0 {
            chain_id: &chain_id,
            parent_height,
            parent_state_root: parent_root,
            block_height: AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT,
            block_hash: &block_hash,
            timestamp_ms,
            txs: &txs,
            tx_results: &results,
            next_state_root: next_root,
        },
        &cutoff,
        &active_validators,
    )?;
    let expected_reason = if fallback {
        EpochFallbackReasonV0::TooFewEligibleValidators
    } else {
        EpochFallbackReasonV0::None
    };
    ensure!(
        capability.fallback_used() == fallback && capability.fallback_reason() == expected_reason,
        "candidate scenario outcome differs from expected fallback contract"
    );
    let computed_ids = capability.computed_candidate_ids();
    if fallback {
        ensure!(
            computed_ids.is_empty(),
            "candidate fallback leaked untrusted diagnostics"
        );
    } else {
        let expected = [b'a', b'b', b'c', b'e']
            .into_iter()
            .map(|suffix| ValidatorId::from_bytes(&tagged_fixture_id(b"validator-", suffix)))
            .collect::<core::result::Result<Vec<_>, _>>()
            .map_err(|error| anyhow::anyhow!("expected candidate ID: {error:?}"))?;
        ensure!(computed_ids == expected, "positive candidate ID set drift");
    }
    let checkpoint = capability.checkpoint_execution();
    let effective_set = capability
        .effective_validator_set()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode effective candidate set: {error:?}"))?;
    let checkpoint_export = AuthenticatedCandidateCheckpointExportV0 {
        block_height: AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT,
        block_hash_hex: hex::encode(block_hash),
        timestamp_ms,
        parent_height,
        parent_state_root_hex: hex::encode(parent_root),
        next_state_root_hex: hex::encode(next_root),
        cutoff_entries_root_hex: hex::encode(checkpoint.cutoff_entries_root()),
        cutoff_entry_count: checkpoint.cutoff_entry_count(),
        payload_root_hex: hex::encode(checkpoint.payload_root()),
        receipts_root_hex: hex::encode(checkpoint.receipts_root()),
        checkpoint_execution_canonical_hex: hex::encode(checkpoint.canonical_bytes()),
        execution_id_hex: hex::encode(checkpoint.execution_id()),
        authorization_id_hex: hex::encode(capability.authorization_id()),
        transcript_canonical_hex: hex::encode(capability.transcript_canonical_bytes()),
        transcript_digest_hex: hex::encode(capability.transcript_digest()),
        result_canonical_hex: hex::encode(capability.result_canonical_bytes()),
        result_digest_hex: hex::encode(capability.result_digest()),
        candidate_parameters_hash_hex: hex::encode(
            capability.candidate_parameters_hash().as_bytes(),
        ),
        fallback_used: capability.fallback_used(),
        fallback_reason_code: u16::from(capability.fallback_reason()),
        computed_candidate_count: u32::try_from(computed_ids.len())
            .context("computed candidate count exceeds u32")?,
        computed_candidate_ids_hex: computed_ids
            .iter()
            .map(|validator_id| hex::encode(validator_id.as_bytes()))
            .collect(),
        effective_validator_set_cev0_hex: hex::encode(effective_set),
    };
    Ok(AuthenticatedCandidateScenarioExportV0 {
        id: if fallback {
            "authenticated_pending_challenge_fallback"
        } else {
            "authenticated_distinct_set_success"
        },
        expected_fallback_used: fallback,
        expected_fallback_reason_code: u16::from(expected_reason),
        block_steps: steps,
        source: AuthenticatedCandidateSourceExportV0 {
            head_version: chain.source_version,
            head_root_hex: hex::encode(chain.source_root),
            cutoff_version: AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT,
            cutoff_root_hex: hex::encode(cutoff_root),
            history: chain.history,
            cutoff_projection: projection_value_export(&cutoff_projection),
            head_projection: projection_value_export(&head_projection),
        },
        checkpoint: checkpoint_export,
    })
}

fn build_authenticated_candidate_fixture_export_v0() -> Result<AuthenticatedCandidateFixtureExportV0>
{
    let (chain, fixtures, steps, boundary) = authenticated_candidate_common_history_v0()?;
    let parameters = chain.active_parameters;
    let geometry = EpochGeometryV0::new(chain.active_epoch, &parameters)
        .map_err(|error| anyhow::anyhow!("candidate compact geometry: {error:?}"))?;
    ensure!(
        geometry.epoch_start().get() == AUTHENTICATED_CANDIDATE_BOUNDARY_HEIGHT
            && geometry.checkpoint_height().get() == AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT
            && geometry
                .checkpoint_height()
                .get()
                .checked_sub(parameters.snapshot_lead_blocks())
                == Some(AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT),
        "candidate compact profile schedule drift"
    );
    let positive =
        authenticated_candidate_scenario_v0(chain.clone(), &fixtures, steps.clone(), false)?;
    let authenticated_fallback =
        authenticated_candidate_scenario_v0(chain.clone(), &fixtures, steps, true)?;
    let locked_until = AUTHENTICATED_CANDIDATE_TARGET_EPOCH
        .checked_add(parameters.evidence_window_epochs())
        .and_then(|coverage_end| coverage_end.checked_add(1))
        .context("candidate exported bond lock overflow")?;
    Ok(AuthenticatedCandidateFixtureExportV0 {
        schema: AUTHENTICATED_CANDIDATE_FIXTURE_SCHEMA,
        schema_version: 0,
        fixture_scope:
            "application_authenticated_candidate_reconstruction_not_core_epoch_transition",
        compact_profile: AuthenticatedCandidateCompactProfileExportV0 {
            chain_id_utf8: String::from_utf8(chain.chain_id.as_bytes().to_vec())
                .context("candidate compact chain ID is not UTF-8")?,
            genesis_hash_hex: hex::encode(chain.genesis_hash.as_bytes()),
            epoch_length_blocks: parameters.epoch_length_blocks(),
            snapshot_lead_blocks: parameters.snapshot_lead_blocks(),
            maturity_epochs: parameters.maturity_epochs(),
            units_per_power: parameters.units_per_power().to_string(),
            bond_atomic_units_per_power: parameters.bond_atomic_units_per_power().to_string(),
            evidence_window_epochs: parameters.evidence_window_epochs(),
            active_parameters_cev0_hex: hex::encode(parameters.canonical_bytes()),
            active_parameters_hash_hex: hex::encode(parameters.hash().as_bytes()),
            active_epoch: chain.active_epoch.get(),
            target_epoch: AUTHENTICATED_CANDIDATE_TARGET_EPOCH,
            boundary_height: AUTHENTICATED_CANDIDATE_BOUNDARY_HEIGHT,
            cutoff_height: AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT,
            checkpoint_height: AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT,
        },
        boundary_contract: AuthenticatedCandidateBoundaryExportV0 {
            authority: "fixture_only_bootstrap_not_application_or_core_transition",
            from_epoch: 0,
            to_epoch: AUTHENTICATED_CANDIDATE_ACTIVE_EPOCH,
            height: AUTHENTICATED_CANDIDATE_BOUNDARY_HEIGHT,
            usage_rollover: "clear_epoch_zero_usage_buckets_preserve_certificate_authority",
            cleared_meter_usage: boundary.cleared_meter_usage,
            cleared_consumer_provider_usage: boundary.cleared_consumer_provider_usage,
            cleared_task_provider_usage: boundary.cleared_task_provider_usage,
            cleared_provider_usage: boundary.cleared_provider_usage,
            preserved_certificate_ids_hex: boundary.preserved_certificate_ids_hex,
            installed_bonds: [b'a', b'b', b'c', b'e']
                .into_iter()
                .map(|suffix| AuthenticatedCandidateBondExportV0 {
                    validator_id_hex: hex::encode(tagged_fixture_id(b"validator-", suffix)),
                    amount: "10".to_string(),
                    locked_until,
                    state: "active_slashable",
                })
                .collect(),
        },
        positive,
        authenticated_fallback,
    })
}

fn authenticated_candidate_point_proof_v0(proof: AuthProof) -> Ics23PointProofV0 {
    let encoded_commitment_proof = proof.encoded_commitment_proof();
    Ics23PointProofV0 {
        version: proof.version,
        root_hash: proof.root_hash.0,
        key: proof.key,
        value: proof.value,
        encoded_commitment_proof,
    }
}

fn authenticated_candidate_namespace_proof_v0(
    tree: &InMemoryAuthTree,
    cutoff_projection: &ProductionPocoProjectionV0,
    cutoff_height: u64,
) -> Result<PocoSnapshotNamespaceProofV0> {
    let manifest = cutoff_projection.manifest();
    let manifest_key = poco_snapshot_manifest_key()?;
    let manifest_proof = authenticated_candidate_point_proof_v0(
        tree.prove(cutoff_height, manifest_key)
            .context("candidate H2 manifest proof")?,
    );
    let members = cutoff_projection
        .entries()
        .iter()
        .cloned()
        .map(|entry| {
            let proof = authenticated_candidate_point_proof_v0(
                tree.prove(cutoff_height, entry.jmt_key()?)
                    .context("candidate H2 member proof")?,
            );
            Ok(PocoSnapshotMemberProofV0 { entry, proof })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PocoSnapshotNamespaceProofV0 {
        manifest,
        manifest_proof,
        members,
        absences: Vec::new(),
    })
}

fn authenticated_candidate_quorum_certificate_v0(
    validator_set: &ValidatorSet,
    view: View,
    height: Height,
    block_id: BlockId,
) -> Result<QuorumCertificate> {
    let signing_root = Vote::signing_root_for_set(validator_set, view, height, block_id)
        .map_err(|error| anyhow::anyhow!("candidate H1 vote root: {error:?}"))?;
    let votes = validator_set
        .validators()
        .iter()
        .map(|validator| {
            let signing_key = provider_fixture_signing_key_for_id(validator.id().as_bytes());
            Vote::new(
                validator_set.chain_id(),
                validator_set.protocol_version(),
                validator_set.epoch(),
                view,
                height,
                block_id,
                validator_set.id(),
                validator.id(),
                signature64(&signing_key, signing_root.as_bytes()),
                validator_set,
            )
            .map_err(|error| anyhow::anyhow!("candidate H1 vote: {error:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    QuorumCertificate::new(
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        view,
        height,
        block_id,
        validator_set.id(),
        votes,
        validator_set,
    )
    .map_err(|error| anyhow::anyhow!("candidate H1 QC: {error:?}"))
}

#[allow(clippy::too_many_arguments)]
fn authenticated_candidate_certified_header_v0(
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    header: BlockHeader,
    justify_qc: QuorumCertificate,
    certifying_qc: QuorumCertificate,
    parent_timestamp_ms: u64,
    invalid_proposer_signature: bool,
) -> Result<CertifiedHeaderV0> {
    let justify = QcReferenceV0::ordinary(justify_qc);
    let signing_root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None)
        .map_err(|error| anyhow::anyhow!("candidate H1 proposal root: {error:?}"))?;
    let proposer_key = provider_fixture_signing_key_for_id(header.proposer_id().as_bytes());
    let proposer_signature = if invalid_proposer_signature {
        Signature64::from_array([0x55; 64])
    } else {
        signature64(&proposer_key, signing_root.as_bytes())
    };
    CertifiedHeaderV0::new(
        header,
        justify,
        None,
        None,
        proposer_signature,
        certifying_qc,
        validator_set,
        None,
        parameters,
        parent_timestamp_ms,
    )
    .map_err(|error| anyhow::anyhow!("candidate H1 certified header: {error:?}"))
}

fn authenticated_candidate_cutoff_parent_header_v0(
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    timestamp_ms: u64,
    payload_byte: u8,
) -> Result<BlockHeader> {
    let view = View::new(4);
    let proposer_index =
        usize::try_from((view.get() - 1) % validator_set.validators().len() as u64)
            .context("candidate cutoff-parent proposer index")?;
    BlockHeader::new(
        validator_set.genesis_hash(),
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        view,
        Height::new(AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT - 1),
        BlockKind::Regular,
        BlockId::new([0x6f; 32]),
        validator_set.validators()[proposer_index].id(),
        validator_set.id(),
        parameters.hash(),
        PayloadDigest::new([payload_byte; 32]),
        StateRoot::new([0x70; 32]),
        ReceiptsRoot::new([0x71; 32]),
        EvidenceRoot::new([0x72; 32]),
        timestamp_ms,
        None,
    )
    .map_err(|error| anyhow::anyhow!("candidate cutoff-parent header: {error:?}"))
}

fn authenticated_candidate_cutoff_parent_variant_v0(
    raw_parent_cev0: &[u8],
    payload_digest: PayloadDigest,
    timestamp_ms: u64,
) -> Result<Vec<u8>> {
    let parent = decode_block_header_v0_exact(raw_parent_cev0)
        .map_err(|error| anyhow::anyhow!("decode candidate cutoff-parent variant: {error:?}"))?;
    BlockHeader::new(
        parent.genesis_hash(),
        parent.chain_id(),
        parent.protocol_version(),
        parent.epoch(),
        parent.view(),
        parent.height(),
        parent.block_kind(),
        parent.parent_id(),
        parent.proposer_id(),
        parent.validator_set_id(),
        parent.consensus_parameters_hash(),
        payload_digest,
        parent.state_root(),
        parent.receipts_root(),
        parent.evidence_root(),
        timestamp_ms,
        parent.next_epoch_commitment_hash(),
    )
    .map_err(|error| anyhow::anyhow!("candidate cutoff-parent variant: {error:?}"))?
    .try_cev0_bytes()
    .map_err(|error| anyhow::anyhow!("encode candidate cutoff-parent variant: {error:?}"))
}

fn authenticated_candidate_finalized_cutoff_proof_v0(
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    cutoff_root: [u8; 32],
    invalid_proposer_signature: bool,
) -> Result<(FinalityProofV0, Vec<u8>)> {
    let cutoff_height = AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT;
    let parent_timestamp_ms = 19_000u64;
    let parent_header = authenticated_candidate_cutoff_parent_header_v0(
        validator_set,
        parameters,
        parent_timestamp_ms,
        0x73,
    )?;
    let parent_id = parent_header.id();
    let parent_qc = authenticated_candidate_quorum_certificate_v0(
        validator_set,
        parent_header.view(),
        parent_header.height(),
        parent_id,
    )?;

    let mut parent = parent_id;
    let mut justify = parent_qc;
    let mut parent_timestamp = parent_timestamp_ms;
    let mut certified = Vec::with_capacity(3);
    for (ordinal, (view, height)) in [
        (View::new(5), Height::new(cutoff_height)),
        (View::new(6), Height::new(cutoff_height + 1)),
        (View::new(7), Height::new(cutoff_height + 2)),
    ]
    .into_iter()
    .enumerate()
    {
        let proposer_index =
            usize::try_from((view.get() - 1) % validator_set.validators().len() as u64)
                .context("candidate H1 proposer index")?;
        let timestamp = parent_timestamp
            .checked_add(1_000)
            .context("candidate H1 timestamp overflow")?;
        let header = BlockHeader::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            view,
            height,
            BlockKind::Regular,
            parent,
            validator_set.validators()[proposer_index].id(),
            validator_set.id(),
            parameters.hash(),
            PayloadDigest::new([0x71 + ordinal as u8; 32]),
            StateRoot::new(if ordinal == 0 {
                cutoff_root
            } else {
                [0x74 + ordinal as u8; 32]
            }),
            ReceiptsRoot::new([0x77 + ordinal as u8; 32]),
            EvidenceRoot::new([0x7a + ordinal as u8; 32]),
            timestamp,
            None,
        )
        .map_err(|error| anyhow::anyhow!("candidate H1 header: {error:?}"))?;
        let block_id = header.id();
        let certifying_qc =
            authenticated_candidate_quorum_certificate_v0(validator_set, view, height, block_id)?;
        let value = authenticated_candidate_certified_header_v0(
            validator_set,
            parameters,
            header,
            justify,
            certifying_qc.clone(),
            parent_timestamp,
            invalid_proposer_signature && ordinal == 0,
        )?;
        certified.push(value);
        parent = block_id;
        justify = certifying_qc;
        parent_timestamp = timestamp;
    }
    let proof = FinalityProofV0::new(
        certified.remove(0),
        certified.remove(0),
        certified.remove(0),
        validator_set,
        None,
        parameters,
        parent_timestamp_ms,
    )
    .map_err(|error| anyhow::anyhow!("candidate H1 finality proof: {error:?}"))?;
    let parent_bytes = parent_header
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode candidate cutoff-parent header: {error:?}"))?;
    Ok((proof, parent_bytes))
}

struct AuthenticatedCandidateCommitmentSourceV0 {
    candidate: AuthenticatedPocoCandidateSelectionV0,
    cutoff_candidate: AuthenticatedPocoCutoffCandidateSelectionV0,
    tree: InMemoryAuthTree,
    cutoff_projection: ProductionPocoProjectionV0,
    cutoff_root: [u8; 32],
    cutoff_height: u64,
    old_set: ValidatorSet,
    parameters: ConsensusParametersV0,
}

fn authenticated_candidate_commitment_source_with_snapshot_lead_v0(
    snapshot_lead_blocks: u64,
    fallback: bool,
) -> Result<AuthenticatedCandidateCommitmentSourceV0> {
    let genesis = authenticated_candidate_genesis_with_snapshot_lead_v0(snapshot_lead_blocks)?;
    let (mut chain, fixtures, _, _) =
        authenticated_candidate_common_history_from_chain_v0(genesis)?;
    let geometry = EpochGeometryV0::new(chain.active_epoch, &chain.active_parameters)
        .map_err(|error| anyhow::anyhow!("candidate commitment geometry: {error:?}"))?;
    let checkpoint_height = geometry.checkpoint_height().get();
    let cutoff_height = checkpoint_height
        .checked_sub(snapshot_lead_blocks)
        .context("candidate commitment cutoff underflow")?;
    ensure!(
        checkpoint_height == AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT,
        "candidate commitment checkpoint height drift"
    );
    if fallback {
        let mut block = chain.start_overlay()?;
        let (opening, next, _) = open_challenge(&block, &fixtures[0], &chain.nullifiers)?;
        block.apply_raw(&opening.raw)?;
        chain.commit_block(block, next)?;
    }
    chain.advance_empty_versions(
        cutoff_height
            .checked_sub(1)
            .context("candidate commitment pre-cutoff underflow")?,
    )?;
    let refresh =
        scheduled_cutoff_manifest_refresh_write_v0(Height::new(cutoff_height), &chain.projection)?;
    chain.commit_fixture_writes(vec![refresh])?;
    let cutoff_root = chain.source_root;
    let cutoff_projection = chain.projection.clone();
    chain.advance_empty_versions(checkpoint_height - 1)?;

    let auth_tree = Mutex::new(chain.tree.clone());
    let cutoff = maybe_authenticated_poco_projection_at_v0(None, &auth_tree, cutoff_height)?
        .context("candidate commitment cutoff missing")?;
    let (old_set, parameters) = active_consensus_configuration(cutoff.projection())?;
    ensure!(
        parameters.snapshot_lead_blocks() == snapshot_lead_blocks,
        "candidate commitment snapshot lead drift"
    );
    let active_validators = old_set
        .validators()
        .iter()
        .map(|validator| ConsensusValidatorV1 {
            public_key_hex: hex::encode(validator.consensus_key().as_bytes()),
            voting_power: validator.voting_power().get(),
        })
        .collect::<Vec<_>>();
    let parent_height = checkpoint_height - 1;
    let parent_root: [u8; 32] = chain
        .tree
        .root_hash(parent_height)
        .context("candidate commitment parent root missing")?
        .into();
    let next_root: [u8; 32] = chain
        .tree
        .plan_put_value_set(checkpoint_height, std::iter::empty::<AuthWrite>())?
        .root_hash
        .into();
    let txs = Vec::<Bytes>::new();
    let results = Vec::<ExecTxResult>::new();
    let authority = PocoAuthorityConfigV0 {
        schema: POCO_AUTHORITY_CONFIG_SCHEMA_V0.to_string(),
        genesis_hash_hex: hex::encode(chain.genesis_hash.as_bytes()),
        protocol_profile_hash_hex: hex::encode(parameters.hash().as_bytes()),
    };
    let chain_id = String::from_utf8(chain.chain_id.as_bytes().to_vec())
        .context("candidate commitment chain ID is not UTF-8")?;
    let cutoff_authority = crate::poco_checkpoint::authorize_poco_scheduled_cutoff_v0(
        &authority,
        &chain_id,
        &cutoff,
        &active_validators,
    )?;
    let cutoff_candidate =
        authorize_authenticated_poco_cutoff_candidate_selection_v0(cutoff_authority, &cutoff)?;
    let candidate = authorize_poco_checkpoint_candidate_selection_v0(
        &authority,
        PocoCheckpointExecutionInputV0 {
            chain_id: &chain_id,
            parent_height,
            parent_state_root: parent_root,
            block_height: checkpoint_height,
            block_hash: if fallback { &[0x92; 32] } else { &[0x91; 32] },
            timestamp_ms: if fallback { 22_002 } else { 22_001 },
            txs: &txs,
            tx_results: &results,
            next_state_root: next_root,
        },
        &cutoff,
        &active_validators,
    )?;
    Ok(AuthenticatedCandidateCommitmentSourceV0 {
        candidate,
        cutoff_candidate,
        tree: chain.tree,
        cutoff_projection,
        cutoff_root,
        cutoff_height,
        old_set,
        parameters,
    })
}

fn authenticated_candidate_commitment_inputs_v0(
    fallback: bool,
) -> Result<(
    AuthenticatedPocoCandidateSelectionV0,
    AuthenticatedPocoCutoffCandidateSelectionV0,
    FinalityProofV0,
    FinalityProofV0,
    Vec<u8>,
    PocoSnapshotNamespaceProofV0,
)> {
    let source = authenticated_candidate_commitment_source_with_snapshot_lead_v0(
        AUTHENTICATED_CANDIDATE_SNAPSHOT_LEAD,
        fallback,
    )?;
    ensure!(
        source.cutoff_height == AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT,
        "unified candidate commitment cutoff drift"
    );
    let namespace = authenticated_candidate_namespace_proof_v0(
        &source.tree,
        &source.cutoff_projection,
        source.cutoff_height,
    )?;
    let (proof, parent_header_cev0) = authenticated_candidate_finalized_cutoff_proof_v0(
        &source.old_set,
        &source.parameters,
        source.cutoff_root,
        false,
    )?;
    let (invalid_proof, invalid_parent_header_cev0) =
        authenticated_candidate_finalized_cutoff_proof_v0(
            &source.old_set,
            &source.parameters,
            source.cutoff_root,
            true,
        )?;
    ensure!(
        invalid_parent_header_cev0 == parent_header_cev0,
        "invalid signature fixture changed cutoff parent header"
    );
    Ok((
        source.candidate,
        source.cutoff_candidate,
        proof,
        invalid_proof,
        parent_header_cev0,
        namespace,
    ))
}

fn authenticated_next_epoch_point_export_v0(
    point: &Ics23PointProofV0,
) -> AuthenticatedNextEpochIcs23PointExportV0 {
    AuthenticatedNextEpochIcs23PointExportV0 {
        version: point.version,
        root_hash_hex: hex::encode(point.root_hash),
        key_hex: hex::encode(&point.key),
        value_hex: point.value.as_ref().map(hex::encode),
        commitment_proof_hex: hex::encode(&point.encoded_commitment_proof),
    }
}

fn authenticated_next_epoch_h2_export_v0(
    namespace: &PocoSnapshotNamespaceProofV0,
) -> AuthenticatedNextEpochH2ExportV0 {
    AuthenticatedNextEpochH2ExportV0 {
        manifest_cev0_hex: hex::encode(namespace.manifest.encode()),
        manifest_proof: authenticated_next_epoch_point_export_v0(&namespace.manifest_proof),
        members: namespace
            .members
            .iter()
            .map(|member| AuthenticatedNextEpochMemberExportV0 {
                kind: member.entry.kind as u8,
                logical_key_hex: hex::encode(&member.entry.logical_key),
                value_hex: hex::encode(&member.entry.value),
                canonical_entry_cev0_hex: hex::encode(member.entry.canonical_bytes()),
                proof: authenticated_next_epoch_point_export_v0(&member.proof),
            })
            .collect(),
        absences: namespace
            .absences
            .iter()
            .map(|absence| AuthenticatedNextEpochAbsenceExportV0 {
                kind: absence.kind as u8,
                logical_key_hex: hex::encode(&absence.logical_key),
                proof: authenticated_next_epoch_point_export_v0(&absence.proof),
            })
            .collect(),
    }
}

fn authenticated_next_epoch_commitment_scenario_export_v0(
    fallback: bool,
) -> Result<AuthenticatedNextEpochCommitmentScenarioExportV0> {
    let (candidate, _cutoff_candidate, proof, _invalid_proof, parent_header_cev0, namespace) =
        authenticated_candidate_commitment_inputs_v0(fallback)?;
    let proof_bytes = proof
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode authenticated cutoff proof: {error:?}"))?;
    let authorized = crate::poco_epoch_commitment::authorize_poco_next_epoch_commitment_v0(
        candidate,
        &proof_bytes,
        &parent_header_cev0,
        &namespace,
    )?;
    let candidate = authorized.candidate();
    let checkpoint = candidate.checkpoint_execution();
    let parent_header = authorized.cutoff_parent_header();
    let finalized_cutoff = authorized.finalized_cutoff();
    let old_set_bytes = authorized
        .old_validator_set()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode commitment old set: {error:?}"))?;
    let new_set_bytes = authorized
        .new_validator_set()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode commitment new set: {error:?}"))?;
    let commitment_bytes = authorized
        .commitment()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode authenticated commitment: {error:?}"))?;
    ensure!(
        [
            proof.finalized_block().header(),
            proof.child().header(),
            proof.grandchild().header(),
        ]
        .into_iter()
        .all(|header| header.block_kind() == BlockKind::Regular
            && header.next_epoch_commitment_hash().is_none()),
        "H1 fixture must stop at regular grandchild before checkpoint proposal"
    );
    ensure!(
        finalized_cutoff.cutoff_block_id() == proof.finalized_block().header().id()
            && finalized_cutoff.cutoff_state_root()
                == proof.finalized_block().header().state_root(),
        "authorized cutoff differs from raw H1 proof"
    );
    Ok(AuthenticatedNextEpochCommitmentScenarioExportV0 {
        id: if fallback {
            "authenticated_fallback_commitment"
        } else {
            "authenticated_positive_commitment"
        },
        candidate_source_id: if fallback {
            "authenticated_pending_challenge_fallback"
        } else {
            "authenticated_distinct_set_success"
        },
        candidate_binding: AuthenticatedNextEpochCandidateBindingExportV0 {
            authorization_id_hex: hex::encode(candidate.authorization_id()),
            checkpoint_execution_id_hex: hex::encode(checkpoint.execution_id()),
            candidate_parameters_hash_hex: hex::encode(
                candidate.candidate_parameters_hash().as_bytes(),
            ),
            cutoff_version: finalized_cutoff.cutoff_height().get(),
            cutoff_state_root_hex: hex::encode(finalized_cutoff.cutoff_state_root().as_bytes()),
            cutoff_entries_root_hex: hex::encode(finalized_cutoff.entries_root()),
            cutoff_entry_count: finalized_cutoff.entry_count(),
            fallback_used: candidate.fallback_used(),
            fallback_reason_code: u16::from(candidate.fallback_reason()),
            old_validator_set_cev0_hex: hex::encode(old_set_bytes),
            old_parameters_cev0_hex: hex::encode(authorized.old_parameters().canonical_bytes()),
            new_validator_set_cev0_hex: hex::encode(new_set_bytes),
            new_parameters_cev0_hex: hex::encode(authorized.new_parameters().canonical_bytes()),
        },
        h1: AuthenticatedNextEpochH1ExportV0 {
            cutoff_parent_header_cev0_hex: hex::encode(parent_header_cev0),
            cutoff_parent_block_id_hex: hex::encode(parent_header.id().as_bytes()),
            cutoff_parent_timestamp_ms: parent_header.timestamp_ms(),
            finality_proof_cev0_hex: hex::encode(proof_bytes),
            proof_id_hex: hex::encode(proof.id().as_bytes()),
            finalized_cutoff_block_id_hex: hex::encode(
                proof.finalized_block().header().id().as_bytes(),
            ),
            finalized_cutoff_height: proof.finalized_block().header().height().get(),
            finalized_cutoff_state_root_hex: hex::encode(
                proof.finalized_block().header().state_root().as_bytes(),
            ),
            child_block_id_hex: hex::encode(proof.child().header().id().as_bytes()),
            grandchild_block_id_hex: hex::encode(proof.grandchild().header().id().as_bytes()),
        },
        h2: authenticated_next_epoch_h2_export_v0(&namespace),
        commitment: AuthenticatedNextEpochCommitmentExportV0 {
            cev0_hex: hex::encode(commitment_bytes),
            id_hex: hex::encode(authorized.commitment().id().as_bytes()),
        },
        authorization_id_hex: hex::encode(authorized.authorization_id()),
    })
}

fn authenticated_candidate_vector_path_v0() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../docs/protocol/poco-bft-v0/vectors/\
         poco-authenticated-candidate-selection-v0.json",
    )
}

fn build_authenticated_next_epoch_commitment_fixture_export_v0(
) -> Result<AuthenticatedNextEpochCommitmentFixtureExportV0> {
    let candidate_vector_path = authenticated_candidate_vector_path_v0();
    let candidate_vector = fs::read(&candidate_vector_path).with_context(|| {
        format!(
            "read authenticated candidate source {}",
            candidate_vector_path.display()
        )
    })?;
    Ok(AuthenticatedNextEpochCommitmentFixtureExportV0 {
        schema: AUTHENTICATED_NEXT_EPOCH_COMMITMENT_FIXTURE_SCHEMA,
        schema_version: 0,
        fixture_scope:
            "raw_strict_h1_h2_candidate_to_private_same_version_commitment_not_checkpoint_header_authority",
        candidate_vector_path:
            "docs/protocol/poco-bft-v0/vectors/poco-authenticated-candidate-selection-v0.json",
        candidate_vector_sha256_hex: hex::encode(Sha256::digest(candidate_vector)),
        positive: authenticated_next_epoch_commitment_scenario_export_v0(false)?,
        authenticated_fallback: authenticated_next_epoch_commitment_scenario_export_v0(true)?,
    })
}

fn authenticated_checkpoint_header_from_fields_v0(
    fields: crate::poco_checkpoint_header::PocoCheckpointHeaderFieldsV0,
) -> Result<BlockHeader> {
    BlockHeader::new(
        fields.genesis_hash(),
        fields.chain_id(),
        fields.protocol_version(),
        fields.epoch(),
        fields.view(),
        fields.height(),
        fields.block_kind(),
        fields.parent_id(),
        fields.proposer_id(),
        fields.validator_set_id(),
        fields.consensus_parameters_hash(),
        fields.payload_root(),
        fields.state_root(),
        fields.receipts_root(),
        fields.evidence_root(),
        fields.timestamp_ms(),
        Some(fields.next_epoch_commitment_hash()),
    )
    .map_err(|error| anyhow::anyhow!("construct exact authored checkpoint header: {error:?}"))
}

fn authenticated_checkpoint_scheduled_proposer_v0(
    validator_set: &ValidatorSet,
    view: View,
) -> Result<ValidatorId> {
    let validator_count = u64::try_from(validator_set.validators().len())
        .context("checkpoint-handoff validator count exceeds u64")?;
    let index = view
        .get()
        .saturating_sub(1)
        .checked_rem(validator_count)
        .context("checkpoint-handoff validator set is empty")?;
    let index = usize::try_from(index).context("checkpoint-handoff leader index exceeds usize")?;
    Ok(validator_set.validators()[index].id())
}

#[allow(clippy::too_many_arguments)]
fn authenticated_checkpoint_seal_header_v0(
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    block_kind: BlockKind,
    view: View,
    height: Height,
    parent_id: BlockId,
    state_root: StateRoot,
    commitment_hash: trnm_consensus_types::NextEpochCommitmentHash,
    timestamp_ms: u64,
    empty_payload_root: PayloadDigest,
    empty_receipts_root: ReceiptsRoot,
    empty_evidence_root: EvidenceRoot,
) -> Result<BlockHeader> {
    BlockHeader::new(
        validator_set.genesis_hash(),
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        view,
        height,
        block_kind,
        parent_id,
        authenticated_checkpoint_scheduled_proposer_v0(validator_set, view)?,
        validator_set.id(),
        parameters.hash(),
        empty_payload_root,
        state_root,
        empty_receipts_root,
        empty_evidence_root,
        timestamp_ms,
        Some(commitment_hash),
    )
    .map_err(|error| anyhow::anyhow!("construct authored checkpoint seal header: {error:?}"))
}

fn authenticated_checkpoint_handoff_shares_v0(
    descriptor: &HandoffDescriptorV0,
    validator_set: &ValidatorSet,
    old_role: bool,
) -> Result<Vec<SignatureShareV0>> {
    let signing_root = if old_role {
        descriptor.old_set_signing_root()
    } else {
        descriptor.new_set_signing_root()
    };
    validator_set
        .validators()
        .iter()
        .map(|validator| {
            let signing_key = provider_fixture_signing_key_for_id(validator.id().as_bytes());
            SignatureShareV0::new(
                validator.id(),
                signature64(&signing_key, signing_root.as_bytes()),
            )
            .map_err(|error| anyhow::anyhow!("construct strict handoff signature share: {error:?}"))
        })
        .collect()
}

fn authenticated_checkpoint_handoff_raw_certificate_v0(
    descriptor: &HandoffDescriptorV0,
    old_signatures: &[SignatureShareV0],
    new_signatures: &[SignatureShareV0],
) -> Result<Vec<u8>> {
    fn append_shares(raw: &mut Vec<u8>, shares: &[SignatureShareV0]) -> Result<()> {
        let count = u32::try_from(shares.len()).context("handoff share count exceeds u32")?;
        raw.extend_from_slice(&count.to_be_bytes());
        for share in shares {
            let validator_id = share.validator_id();
            let validator_id_len = u32::try_from(validator_id.as_bytes().len())
                .context("handoff validator ID length exceeds u32")?;
            raw.extend_from_slice(&validator_id_len.to_be_bytes());
            raw.extend_from_slice(validator_id.as_bytes());
            raw.extend_from_slice(share.signature().as_bytes());
        }
        Ok(())
    }

    let mut raw = Vec::new();
    raw.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    raw.extend_from_slice(
        &descriptor
            .try_cev0_bytes()
            .map_err(|error| anyhow::anyhow!("encode raw handoff descriptor: {error:?}"))?,
    );
    append_shares(&mut raw, old_signatures)?;
    append_shares(&mut raw, new_signatures)?;
    Ok(raw)
}

fn authenticated_checkpoint_handoff_scenario_fixture_v0(
    fallback: bool,
) -> Result<AuthenticatedCheckpointHandoffScenarioFixtureV0> {
    let (
        _post_execution_candidate,
        cutoff_candidate,
        cutoff_proof,
        _invalid_cutoff_proof,
        cutoff_parent_header_cev0,
        namespace,
    ) = authenticated_candidate_commitment_inputs_v0(fallback)?;
    let cutoff_proof_cev0 = cutoff_proof
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b cutoff proof: {error:?}"))?;
    let cutoff_candidate_authorization_id = cutoff_candidate.authorization_id();
    let preheader =
        crate::poco_epoch_commitment::authorize_poco_preheader_next_epoch_commitment_v0(
            cutoff_candidate,
            &cutoff_proof_cev0,
            &cutoff_parent_header_cev0,
            &namespace,
        )?;

    let old_validator_set = preheader.old_validator_set().clone();
    let old_parameters = *preheader.old_parameters();
    let new_validator_set = preheader.new_validator_set().clone();
    let new_parameters = *preheader.new_parameters();
    let commitment = preheader.commitment();
    let finalized_cutoff = preheader.finalized_cutoff();
    let geometry = EpochGeometryV0::new(old_validator_set.epoch(), &old_parameters)
        .map_err(|error| anyhow::anyhow!("H3b2b3b compact geometry: {error:?}"))?;
    ensure!(
        geometry.checkpoint_height() == Height::new(AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT)
            && geometry.seal_1_height()
                == Height::new(AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT + 1)
            && geometry.seal_2_height()
                == Height::new(AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT + 2),
        "H3b2b3b compact checkpoint/seal geometry drift"
    );
    let scheduled_cutoff_authorization_id = preheader.scheduled_cutoff().authorization_id();
    let preheader_authorization_id = preheader.authorization_id();
    let checkpoint_parent = preheader.checkpoint_parent().clone();
    let checkpoint_parent_header = checkpoint_parent.header().clone();
    ensure!(
        checkpoint_parent_header.height() == Height::new(27)
            && checkpoint_parent_header.block_kind() == BlockKind::Regular
            && checkpoint_parent_header
                .next_epoch_commitment_hash()
                .is_none(),
        "H3b2b3b checkpoint parent is not the retained commitment-free height-27 H1 grandchild"
    );

    // The first shared b3b profile is deliberately an empty, state-preserving
    // checkpoint. It proves the native ordered-root/header binding without
    // claiming that this vector covers runtime fee/event receipt mapping.
    let raw_execution = crate::native_execution::NativeBlockExecutionV0::empty();
    let authorized_execution = crate::native_execution::authorize_native_checkpoint_execution_v0(
        raw_execution,
        checkpoint_parent_header.height(),
        checkpoint_parent_header.state_root(),
        geometry.checkpoint_height(),
        checkpoint_parent_header.state_root(),
    )?;
    let native_execution_authorization_id = authorized_execution.authorization_id();
    let checkpoint_view = checkpoint_parent_header
        .view()
        .checked_next()
        .map_err(|error| anyhow::anyhow!("checkpoint view overflow: {error:?}"))?;
    let checkpoint_timestamp_ms = checkpoint_parent_header
        .timestamp_ms()
        .checked_add(1_000)
        .context("checkpoint timestamp overflow")?;
    let checkpoint_proposer =
        authenticated_checkpoint_scheduled_proposer_v0(&old_validator_set, checkpoint_view)?;
    let prepared = prepare_poco_checkpoint_header_v0(
        preheader,
        checkpoint_view,
        checkpoint_proposer,
        checkpoint_timestamp_ms,
        authorized_execution,
        Vec::new(),
    )?;
    let checkpoint_fields = prepared.fields();
    let checkpoint_body = prepared.body().clone();
    let checkpoint_receipts = prepared.execution_receipts().clone();
    let checkpoint_preparation_id = prepared.preparation_id();
    let checkpoint_header = authenticated_checkpoint_header_from_fields_v0(checkpoint_fields)?;
    let authorized_checkpoint = bind_prepared_poco_checkpoint_header_for_fixture_v0(
        prepared,
        &checkpoint_header,
        &checkpoint_body,
        &checkpoint_receipts,
    )?;
    let checkpoint_header_authorization_id = authorized_checkpoint.authorization_id();

    let checkpoint_qc = authenticated_candidate_quorum_certificate_v0(
        &old_validator_set,
        checkpoint_header.view(),
        checkpoint_header.height(),
        checkpoint_header.id(),
    )?;
    let checkpoint_certified = authenticated_candidate_certified_header_v0(
        &old_validator_set,
        &old_parameters,
        checkpoint_header.clone(),
        checkpoint_parent.certifying_qc().clone(),
        checkpoint_qc.clone(),
        checkpoint_parent_header.timestamp_ms(),
        false,
    )?;

    let seal_1_view = checkpoint_view
        .checked_next()
        .map_err(|error| anyhow::anyhow!("seal-1 view overflow: {error:?}"))?;
    let seal_1_timestamp_ms = checkpoint_timestamp_ms
        .checked_add(1_000)
        .context("seal-1 timestamp overflow")?;
    let seal_1_header = authenticated_checkpoint_seal_header_v0(
        &old_validator_set,
        &old_parameters,
        BlockKind::EpochSeal1,
        seal_1_view,
        geometry.seal_1_height(),
        checkpoint_header.id(),
        checkpoint_header.state_root(),
        commitment.id(),
        seal_1_timestamp_ms,
        checkpoint_header.payload_digest(),
        checkpoint_header.receipts_root(),
        checkpoint_header.evidence_root(),
    )?;
    let seal_1_qc = authenticated_candidate_quorum_certificate_v0(
        &old_validator_set,
        seal_1_header.view(),
        seal_1_header.height(),
        seal_1_header.id(),
    )?;
    let seal_1_certified = authenticated_candidate_certified_header_v0(
        &old_validator_set,
        &old_parameters,
        seal_1_header.clone(),
        checkpoint_qc,
        seal_1_qc.clone(),
        checkpoint_timestamp_ms,
        false,
    )?;

    let seal_2_view = seal_1_view
        .checked_next()
        .map_err(|error| anyhow::anyhow!("seal-2 view overflow: {error:?}"))?;
    let seal_2_timestamp_ms = seal_1_timestamp_ms
        .checked_add(1_000)
        .context("seal-2 timestamp overflow")?;
    let seal_2_header = authenticated_checkpoint_seal_header_v0(
        &old_validator_set,
        &old_parameters,
        BlockKind::EpochSeal2,
        seal_2_view,
        geometry.seal_2_height(),
        seal_1_header.id(),
        checkpoint_header.state_root(),
        commitment.id(),
        seal_2_timestamp_ms,
        checkpoint_header.payload_digest(),
        checkpoint_header.receipts_root(),
        checkpoint_header.evidence_root(),
    )?;
    let terminal_qc = authenticated_candidate_quorum_certificate_v0(
        &old_validator_set,
        seal_2_header.view(),
        seal_2_header.height(),
        seal_2_header.id(),
    )?;
    let seal_2_certified = authenticated_candidate_certified_header_v0(
        &old_validator_set,
        &old_parameters,
        seal_2_header.clone(),
        seal_1_qc,
        terminal_qc.clone(),
        seal_1_timestamp_ms,
        false,
    )?;
    let checkpoint_finality = FinalityProofV0::new(
        checkpoint_certified,
        seal_1_certified,
        seal_2_certified,
        &old_validator_set,
        None,
        &old_parameters,
        checkpoint_parent_header.timestamp_ms(),
    )
    .map_err(|error| anyhow::anyhow!("construct H3b2b3b checkpoint finality: {error:?}"))?;
    let checkpoint_finality_cev0 = checkpoint_finality
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b checkpoint finality: {error:?}"))?;

    let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
        genesis_hash: old_validator_set.genesis_hash(),
        chain_id: old_validator_set.chain_id(),
        old_epoch: old_validator_set.epoch(),
        new_epoch: new_validator_set.epoch(),
        old_protocol_version: old_validator_set.protocol_version(),
        new_protocol_version: new_validator_set.protocol_version(),
        old_validator_set_hash: old_validator_set.id(),
        new_validator_set_hash: new_validator_set.id(),
        old_consensus_parameters_hash: old_parameters.hash(),
        new_consensus_parameters_hash: new_parameters.hash(),
        checkpoint_height: checkpoint_header.height(),
        checkpoint_block_id: checkpoint_header.id(),
        checkpoint_state_root: checkpoint_header.state_root(),
        next_epoch_commitment_digest: commitment.id(),
        terminal_old_height: seal_2_header.height(),
        terminal_old_block_id: seal_2_header.id(),
        terminal_old_qc_digest: terminal_qc.id(),
        terminal_old_view: seal_2_header.view(),
        activation_height: geometry
            .seal_2_height()
            .checked_next()
            .map_err(|error| anyhow::anyhow!("H3b2b3b activation height overflow: {error:?}"))?,
        initial_new_view: View::new(1),
    })
    .map_err(|error| anyhow::anyhow!("construct H3b2b3b handoff descriptor: {error:?}"))?;
    let descriptor_cev0 = descriptor
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b handoff descriptor: {error:?}"))?;
    let descriptor_id = descriptor.id();
    let old_signatures =
        authenticated_checkpoint_handoff_shares_v0(&descriptor, &old_validator_set, true)?;
    let new_signatures =
        authenticated_checkpoint_handoff_shares_v0(&descriptor, &new_validator_set, false)?;
    let old_signature_count =
        u32::try_from(old_signatures.len()).context("old signature count exceeds u32")?;
    let new_signature_count =
        u32::try_from(new_signatures.len()).context("new signature count exceeds u32")?;
    let certificate = HandoffCertificateV0::new(
        descriptor.clone(),
        old_signatures,
        new_signatures,
        &old_validator_set,
        &new_validator_set,
    )
    .map_err(|error| anyhow::anyhow!("construct H3b2b3b handoff certificate: {error:?}"))?;
    let certificate_cev0 = certificate
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b handoff certificate: {error:?}"))?;
    let certificate_id = certificate.id();
    let terminal_header_cev0 = seal_2_header
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b terminal header: {error:?}"))?;
    let terminal_qc_cev0 = terminal_qc
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b terminal QC: {error:?}"))?;
    let mut raw_anchor_kernel = terminal_header_cev0.clone();
    raw_anchor_kernel.extend_from_slice(&terminal_qc_cev0);
    raw_anchor_kernel.extend_from_slice(&certificate_cev0);
    let checkpoint_parent_header_cev0 = checkpoint_parent_header
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b checkpoint parent: {error:?}"))?;

    // Keep the exporter itself on the raw-consumer boundary: each exact CEV0
    // object must reject independent trailing bytes before the positive join
    // below is allowed to mint the private capability.
    let mut trailing_parent = checkpoint_parent_header_cev0.clone();
    trailing_parent.push(0);
    ensure!(
        authorize_poco_checkpoint_joint_handoff_for_fixture_v0(
            authorized_checkpoint.clone(),
            &trailing_parent,
            &checkpoint_finality_cev0,
            &raw_anchor_kernel,
        )
        .is_err(),
        "H3b2b3b raw consumer accepted trailing checkpoint-parent bytes"
    );
    let mut trailing_finality = checkpoint_finality_cev0.clone();
    trailing_finality.push(0);
    ensure!(
        authorize_poco_checkpoint_joint_handoff_for_fixture_v0(
            authorized_checkpoint.clone(),
            &checkpoint_parent_header_cev0,
            &trailing_finality,
            &raw_anchor_kernel,
        )
        .is_err(),
        "H3b2b3b raw consumer accepted trailing checkpoint-finality bytes"
    );
    let mut trailing_anchor = raw_anchor_kernel.clone();
    trailing_anchor.push(0);
    ensure!(
        authorize_poco_checkpoint_joint_handoff_for_fixture_v0(
            authorized_checkpoint.clone(),
            &checkpoint_parent_header_cev0,
            &checkpoint_finality_cev0,
            &trailing_anchor,
        )
        .is_err(),
        "H3b2b3b raw consumer accepted trailing anchor-kernel bytes"
    );
    let authorized_handoff = authorize_poco_checkpoint_joint_handoff_for_fixture_v0(
        authorized_checkpoint.clone(),
        &checkpoint_parent_header_cev0,
        &checkpoint_finality_cev0,
        &raw_anchor_kernel,
    )?;
    let joint_authorization_id = authorized_handoff.authorization_id();
    let bound = authorized_handoff.bound_facts();
    ensure!(
        bound.checkpoint_execution_authorization_id() == native_execution_authorization_id
            && bound.scheduled_cutoff_authorization_id() == scheduled_cutoff_authorization_id,
        "H3b2b3b final authority lost its native execution or scheduled-cutoff provenance"
    );

    let old_validator_set_cev0 = old_validator_set
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b old validator set: {error:?}"))?;
    let new_validator_set_cev0 = new_validator_set
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b new validator set: {error:?}"))?;
    let commitment_cev0 = commitment
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b commitment: {error:?}"))?;
    let payload_cev0 = checkpoint_body
        .application_payload()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b checkpoint payload: {error:?}"))?;
    let receipts_cev0 = checkpoint_receipts
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b checkpoint receipts: {error:?}"))?;
    let checkpoint_header_cev0 = checkpoint_header
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b checkpoint header: {error:?}"))?;
    let seal_1_header_cev0 = seal_1_header
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode H3b2b3b seal-1 header: {error:?}"))?;
    let scheduled_cutoff = authorized_checkpoint
        .prepared()
        .commitment_authority()
        .scheduled_cutoff();

    let export = AuthenticatedCheckpointHandoffScenarioExportV0 {
        id: if fallback {
            "authenticated_fallback_checkpoint_handoff"
        } else {
            "authenticated_positive_checkpoint_handoff"
        },
        fallback_used: fallback,
        fallback_reason_code: u16::from(if fallback {
            EpochFallbackReasonV0::TooFewEligibleValidators
        } else {
            EpochFallbackReasonV0::None
        }),
        cutoff: AuthenticatedCheckpointHandoffCutoffExportV0 {
            height: finalized_cutoff.cutoff_height().get(),
            state_root_hex: hex::encode(finalized_cutoff.cutoff_state_root().as_bytes()),
            entries_root_hex: hex::encode(finalized_cutoff.entries_root()),
            entry_count: finalized_cutoff.entry_count(),
            scheduled_cutoff_authorization_id_hex: hex::encode(scheduled_cutoff.authorization_id()),
            cutoff_candidate_authorization_id_hex: hex::encode(cutoff_candidate_authorization_id),
            raw_cutoff_parent_header_cev0_hex: hex::encode(cutoff_parent_header_cev0),
            raw_h1_finality_proof_cev0_hex: hex::encode(cutoff_proof_cev0),
            h1_proof_id_hex: hex::encode(cutoff_proof.id().as_bytes()),
            raw_h2: authenticated_next_epoch_h2_export_v0(&namespace),
        },
        preheader: AuthenticatedCheckpointHandoffPreheaderExportV0 {
            authorization_id_hex: hex::encode(preheader_authorization_id),
            checkpoint_parent_header_cev0_hex: hex::encode(&checkpoint_parent_header_cev0),
            checkpoint_parent_block_id_hex: hex::encode(checkpoint_parent_header.id().as_bytes()),
            old_validator_set_cev0_hex: hex::encode(old_validator_set_cev0),
            old_parameters_cev0_hex: hex::encode(old_parameters.canonical_bytes()),
            new_validator_set_cev0_hex: hex::encode(new_validator_set_cev0),
            new_parameters_cev0_hex: hex::encode(new_parameters.canonical_bytes()),
            commitment_cev0_hex: hex::encode(commitment_cev0),
            commitment_id_hex: hex::encode(commitment.id().as_bytes()),
        },
        checkpoint: AuthenticatedCheckpointHeaderExportV0 {
            native_execution_authorization_id_hex: hex::encode(native_execution_authorization_id),
            application_payload_cev0_hex: hex::encode(payload_cev0),
            execution_receipts_cev0_hex: hex::encode(receipts_cev0),
            transaction_count: checkpoint_body.application_payload().transaction_count(),
            receipt_count: u32::try_from(checkpoint_receipts.receipts().len())
                .context("checkpoint receipt count exceeds u32")?,
            preparation_id_hex: hex::encode(checkpoint_preparation_id),
            header_cev0_hex: hex::encode(checkpoint_header_cev0),
            native_block_id_hex: hex::encode(checkpoint_header.id().as_bytes()),
            header_authorization_id_hex: hex::encode(checkpoint_header_authorization_id),
            height: checkpoint_header.height().get(),
            view: checkpoint_header.view().get(),
            timestamp_ms: checkpoint_header.timestamp_ms(),
            payload_root_hex: hex::encode(checkpoint_header.payload_digest().as_bytes()),
            state_root_hex: hex::encode(checkpoint_header.state_root().as_bytes()),
            receipts_root_hex: hex::encode(checkpoint_header.receipts_root().as_bytes()),
            evidence_root_hex: hex::encode(checkpoint_header.evidence_root().as_bytes()),
            next_epoch_commitment_hash_hex: hex::encode(commitment.id().as_bytes()),
        },
        checkpoint_finality: AuthenticatedCheckpointFinalityExportV0 {
            raw_finality_proof_cev0_hex: hex::encode(&checkpoint_finality_cev0),
            proof_id_hex: hex::encode(checkpoint_finality.id().as_bytes()),
            checkpoint_block_id_hex: hex::encode(checkpoint_header.id().as_bytes()),
            seal_1_header_cev0_hex: hex::encode(seal_1_header_cev0),
            seal_1_block_id_hex: hex::encode(seal_1_header.id().as_bytes()),
            seal_2_header_cev0_hex: hex::encode(&terminal_header_cev0),
            seal_2_block_id_hex: hex::encode(seal_2_header.id().as_bytes()),
            terminal_qc_cev0_hex: hex::encode(&terminal_qc_cev0),
            terminal_qc_id_hex: hex::encode(terminal_qc.id().as_bytes()),
        },
        handoff: AuthenticatedCheckpointHandoffEvidenceExportV0 {
            descriptor_cev0_hex: hex::encode(descriptor_cev0),
            descriptor_id_hex: hex::encode(descriptor_id.as_bytes()),
            certificate_cev0_hex: hex::encode(certificate_cev0),
            certificate_id_hex: hex::encode(certificate_id.as_bytes()),
            raw_anchor_certificate_kernel_cev0_hex: hex::encode(&raw_anchor_kernel),
            old_signature_count,
            new_signature_count,
        },
        bound_authority: AuthenticatedCheckpointHandoffAuthorityExportV0 {
            checkpoint_preparation_id_hex: hex::encode(bound.checkpoint_preparation_id()),
            checkpoint_header_authorization_id_hex: hex::encode(
                bound.checkpoint_header_authorization_id(),
            ),
            checkpoint_execution_authorization_id_hex: hex::encode(
                bound.checkpoint_execution_authorization_id(),
            ),
            commitment_authorization_id_hex: hex::encode(bound.commitment_authorization_id()),
            scheduled_cutoff_authorization_id_hex: hex::encode(
                bound.scheduled_cutoff_authorization_id(),
            ),
            checkpoint_finality_proof_id_hex: hex::encode(
                bound.checkpoint_finality_proof_id().as_bytes(),
            ),
            handoff_certificate_id_hex: hex::encode(bound.handoff_certificate_digest().as_bytes()),
            joint_authorization_id_hex: hex::encode(joint_authorization_id),
        },
    };
    Ok(AuthenticatedCheckpointHandoffScenarioFixtureV0 {
        export,
        authorized_checkpoint,
        checkpoint_parent_header_cev0,
        checkpoint_finality_cev0,
        raw_anchor_kernel_cev0: raw_anchor_kernel,
        descriptor,
        old_validator_set,
        new_validator_set,
        terminal_header_cev0,
        terminal_qc_cev0,
    })
}

fn authenticated_checkpoint_handoff_scenario_export_v0(
    fallback: bool,
) -> Result<AuthenticatedCheckpointHandoffScenarioExportV0> {
    Ok(authenticated_checkpoint_handoff_scenario_fixture_v0(fallback)?.export)
}

fn authenticated_next_epoch_commitment_vector_path_v0() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../docs/protocol/poco-bft-v0/vectors/\
         poco-authenticated-next-epoch-commitment-v0.json",
    )
}

fn build_authenticated_checkpoint_handoff_fixture_export_v0(
) -> Result<AuthenticatedCheckpointHandoffFixtureExportV0> {
    let candidate_vector_path = authenticated_candidate_vector_path_v0();
    let candidate_vector = fs::read(&candidate_vector_path).with_context(|| {
        format!(
            "read authenticated candidate source {}",
            candidate_vector_path.display()
        )
    })?;
    let commitment_vector_path = authenticated_next_epoch_commitment_vector_path_v0();
    let commitment_vector = fs::read(&commitment_vector_path).with_context(|| {
        format!(
            "read authenticated commitment source {}",
            commitment_vector_path.display()
        )
    })?;
    Ok(AuthenticatedCheckpointHandoffFixtureExportV0 {
        schema: AUTHENTICATED_CHECKPOINT_HANDOFF_FIXTURE_SCHEMA,
        schema_version: 0,
        fixture_scope:
            "empty_state_preserving_native_checkpoint_raw_two_seal_and_same_version_joint_handoff_not_production_host_or_activation_authority",
        candidate_vector_path:
            "docs/protocol/poco-bft-v0/vectors/poco-authenticated-candidate-selection-v0.json",
        candidate_vector_sha256_hex: hex::encode(Sha256::digest(candidate_vector)),
        commitment_vector_path:
            "docs/protocol/poco-bft-v0/vectors/poco-authenticated-next-epoch-commitment-v0.json",
        commitment_vector_sha256_hex: hex::encode(Sha256::digest(commitment_vector)),
        compact_profile: AuthenticatedCheckpointHandoffProfileExportV0 {
            epoch_length_blocks: AUTHENTICATED_CANDIDATE_EPOCH_LENGTH,
            snapshot_lead_blocks: AUTHENTICATED_CANDIDATE_SNAPSHOT_LEAD,
            old_epoch: AUTHENTICATED_CANDIDATE_ACTIVE_EPOCH,
            new_epoch: AUTHENTICATED_CANDIDATE_TARGET_EPOCH,
            cutoff_height: AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT,
            checkpoint_parent_height: AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT - 1,
            checkpoint_height: AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT,
            seal_1_height: AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT + 1,
            seal_2_height: AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT + 2,
            activation_height: AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT + 3,
            native_execution_profile: "empty_state_preserving_no_runtime_receipt_mapping_claim",
            comet_hash_mapping: None,
            aggregate_digest: None,
            epoch_anchor_qc_output: false,
        },
        positive: authenticated_checkpoint_handoff_scenario_export_v0(false)?,
        authenticated_fallback: authenticated_checkpoint_handoff_scenario_export_v0(true)?,
    })
}

#[test]
fn authenticated_checkpoint_handoff_reconstructs_both_same_chain_profiles() {
    let fixture = build_authenticated_checkpoint_handoff_fixture_export_v0()
        .expect("build authenticated checkpoint handoff fixture");
    assert!(!fixture.positive.fallback_used);
    assert_eq!(fixture.positive.fallback_reason_code, 0);
    assert!(fixture.authenticated_fallback.fallback_used);
    assert_eq!(
        fixture.authenticated_fallback.fallback_reason_code,
        u16::from(EpochFallbackReasonV0::TooFewEligibleValidators)
    );
    for scenario in [&fixture.positive, &fixture.authenticated_fallback] {
        assert_eq!(scenario.cutoff.height, 25);
        assert_eq!(scenario.checkpoint.height, 28);
        assert_eq!(scenario.checkpoint.transaction_count, 0);
        assert_eq!(scenario.checkpoint.receipt_count, 0);
        assert_ne!(
            scenario.bound_authority.checkpoint_preparation_id_hex,
            "00".repeat(32)
        );
        assert_ne!(
            scenario.bound_authority.joint_authorization_id_hex,
            "00".repeat(32)
        );
        assert_eq!(
            scenario.checkpoint.native_execution_authorization_id_hex,
            scenario
                .bound_authority
                .checkpoint_execution_authorization_id_hex
        );
        assert_eq!(
            scenario.handoff.certificate_id_hex,
            scenario.bound_authority.handoff_certificate_id_hex
        );
    }
}

#[test]
fn authenticated_checkpoint_handoff_rejects_fully_valid_cross_profile_raw_chain_splices() {
    let positive = authenticated_checkpoint_handoff_scenario_fixture_v0(false)
        .expect("build positive authenticated checkpoint handoff material");
    let fallback = authenticated_checkpoint_handoff_scenario_fixture_v0(true)
        .expect("build fallback authenticated checkpoint handoff material");

    // Both foreign raw bundles were freshly accepted with their own exact
    // checkpoint by their builders. Keep each finality proof and anchor
    // certificate byte-for-byte intact here; only the b3b same-call join is
    // crossed. The local exact parent is retained so rejection cannot be
    // attributed to a malformed or trailing-byte parent transport.
    assert!(
        authorize_poco_checkpoint_joint_handoff_for_fixture_v0(
            positive.authorized_checkpoint,
            &positive.checkpoint_parent_header_cev0,
            &fallback.checkpoint_finality_cev0,
            &fallback.raw_anchor_kernel_cev0,
        )
        .is_err(),
        "positive checkpoint accepted the fully valid fallback finality/anchor bundle"
    );
    assert!(
        authorize_poco_checkpoint_joint_handoff_for_fixture_v0(
            fallback.authorized_checkpoint,
            &fallback.checkpoint_parent_header_cev0,
            &positive.checkpoint_finality_cev0,
            &positive.raw_anchor_kernel_cev0,
        )
        .is_err(),
        "fallback checkpoint accepted the fully valid positive finality/anchor bundle"
    );
}

#[test]
fn authenticated_checkpoint_handoff_rejects_canonical_old_role_below_quorum_anchor() {
    let fixture = authenticated_checkpoint_handoff_scenario_fixture_v0(false)
        .expect("build positive authenticated checkpoint handoff material");
    let all_old_signatures = authenticated_checkpoint_handoff_shares_v0(
        &fixture.descriptor,
        &fixture.old_validator_set,
        true,
    )
    .expect("build strict old-role handoff shares");
    let new_signatures = authenticated_checkpoint_handoff_shares_v0(
        &fixture.descriptor,
        &fixture.new_validator_set,
        false,
    )
    .expect("build strict new-role handoff shares");

    // First reduce the all-signer fixture to a canonical minimum-quorum old
    // role certificate. Then delete exactly its final share and rebuild the
    // certificate bytes/count and complete raw anchor. No stale certificate
    // bytes, ID, descriptor, terminal header, QC, or signature is retained.
    let mut old_quorum_signatures = Vec::new();
    let mut signed_power = 0u128;
    for share in all_old_signatures {
        signed_power += fixture
            .old_validator_set
            .power_of(share.validator_id())
            .expect("fixture old-role signer belongs to validator set");
        old_quorum_signatures.push(share);
        if signed_power >= fixture.old_validator_set.quorum_power() {
            break;
        }
    }
    assert!(signed_power >= fixture.old_validator_set.quorum_power());
    assert!(old_quorum_signatures.len() > 1);

    let minimum_quorum_certificate = HandoffCertificateV0::new(
        fixture.descriptor.clone(),
        old_quorum_signatures.clone(),
        new_signatures.clone(),
        &fixture.old_validator_set,
        &fixture.new_validator_set,
    )
    .expect("construct canonical minimum-quorum handoff certificate");
    let minimum_quorum_raw = authenticated_checkpoint_handoff_raw_certificate_v0(
        &fixture.descriptor,
        &old_quorum_signatures,
        &new_signatures,
    )
    .expect("encode canonical minimum-quorum handoff certificate");
    assert_eq!(
        minimum_quorum_raw,
        minimum_quorum_certificate
            .try_cev0_bytes()
            .expect("encode typed minimum-quorum handoff certificate"),
        "test raw certificate encoder diverged from canonical CEV0"
    );

    old_quorum_signatures.pop();
    let below_quorum_power = old_quorum_signatures.iter().fold(0u128, |power, share| {
        power
            + fixture
                .old_validator_set
                .power_of(share.validator_id())
                .expect("remaining old-role signer belongs to validator set")
    });
    assert!(below_quorum_power < fixture.old_validator_set.quorum_power());
    let below_quorum_certificate_raw = authenticated_checkpoint_handoff_raw_certificate_v0(
        &fixture.descriptor,
        &old_quorum_signatures,
        &new_signatures,
    )
    .expect("encode canonical below-quorum handoff certificate");
    let mut below_quorum_anchor = fixture.terminal_header_cev0.clone();
    below_quorum_anchor.extend_from_slice(&fixture.terminal_qc_cev0);
    below_quorum_anchor.extend_from_slice(&below_quorum_certificate_raw);

    let error = match authorize_poco_checkpoint_joint_handoff_for_fixture_v0(
        fixture.authorized_checkpoint,
        &fixture.checkpoint_parent_header_cev0,
        &fixture.checkpoint_finality_cev0,
        &below_quorum_anchor,
    ) {
        Ok(_) => panic!("strict b3b join accepted a canonical old-role below-quorum anchor"),
        Err(error) => error,
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("decode exact terminal/handoff kernel")
            && message.contains("InsufficientQuorum"),
        "below-quorum anchor failed outside strict handoff admission: {message}"
    );
}

#[test]
fn authenticated_checkpoint_handoff_final_vector_matches_rust_reconstruction() {
    let vector_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../docs/protocol/poco-bft-v0/vectors/\
         poco-authenticated-checkpoint-handoff-v0.json",
    );
    let raw = fs::read(&vector_path).unwrap_or_else(|error| {
        panic!(
            "read authenticated checkpoint handoff vector {}: {error}",
            vector_path.display()
        )
    });
    let expected: serde_json::Value = serde_json::from_slice(&raw).unwrap_or_else(|error| {
        panic!(
            "decode authenticated checkpoint handoff vector {}: {error}",
            vector_path.display()
        )
    });
    let reconstructed = serde_json::to_value(
        build_authenticated_checkpoint_handoff_fixture_export_v0()
            .expect("reconstruct authenticated checkpoint handoff fixture"),
    )
    .expect("encode reconstructed authenticated checkpoint handoff fixture");
    assert_eq!(
        reconstructed, expected,
        "committed authenticated checkpoint handoff vector drifted from fresh Rust raw-consumer reconstruction"
    );
}

#[test]
fn authenticated_next_epoch_commitment_raw_h1_h2_and_candidate_derive_private_same_version_commitment(
) {
    for fallback in [false, true] {
        let (candidate, cutoff_candidate, proof, invalid_proof, parent_header_cev0, namespace) =
            authenticated_candidate_commitment_inputs_v0(fallback)
                .expect("build candidate commitment inputs");
        let parent_header = decode_block_header_v0_exact(&parent_header_cev0)
            .expect("exact candidate cutoff-parent header");
        let proof_bytes = proof
            .try_cev0_bytes()
            .expect("encode exact candidate cutoff proof");
        let invalid_proof_bytes = invalid_proof
            .try_cev0_bytes()
            .expect("encode invalid candidate cutoff proof");

        crate::poco_epoch_commitment::authorize_poco_next_epoch_commitment_v0(
            candidate.clone(),
            &invalid_proof_bytes,
            &parent_header_cev0,
            &namespace,
        )
        .expect_err("non-strict proposer signature must fail closed");

        let mut trailing_proof = proof_bytes.clone();
        trailing_proof.push(0);
        crate::poco_epoch_commitment::authorize_poco_next_epoch_commitment_v0(
            candidate.clone(),
            &trailing_proof,
            &parent_header_cev0,
            &namespace,
        )
        .expect_err("non-exact finalized-cutoff proof CEV0 must fail closed");

        let mut root_drift = namespace.clone();
        root_drift.manifest_proof.root_hash[0] ^= 1;
        crate::poco_epoch_commitment::authorize_poco_next_epoch_commitment_v0(
            candidate.clone(),
            &proof_bytes,
            &parent_header_cev0,
            &root_drift,
        )
        .expect_err("H2 root substitution must fail closed");

        let mut trailing_parent = parent_header_cev0.clone();
        trailing_parent.push(0);
        crate::poco_epoch_commitment::authorize_poco_next_epoch_commitment_v0(
            candidate.clone(),
            &proof_bytes,
            &trailing_parent,
            &namespace,
        )
        .expect_err("non-exact cutoff-parent CEV0 must fail closed");

        let id_substitution = authenticated_candidate_cutoff_parent_variant_v0(
            &parent_header_cev0,
            PayloadDigest::new([0x99; 32]),
            parent_header.timestamp_ms(),
        )
        .expect("candidate cutoff-parent ID substitution");
        crate::poco_epoch_commitment::authorize_poco_next_epoch_commitment_v0(
            candidate.clone(),
            &proof_bytes,
            &id_substitution,
            &namespace,
        )
        .expect_err("cutoff-parent ID substitution must fail closed");

        let timestamp_substitution = authenticated_candidate_cutoff_parent_variant_v0(
            &parent_header_cev0,
            parent_header.payload_digest(),
            parent_header.timestamp_ms() - 1,
        )
        .expect("candidate cutoff-parent timestamp substitution");
        crate::poco_epoch_commitment::authorize_poco_next_epoch_commitment_v0(
            candidate.clone(),
            &proof_bytes,
            &timestamp_substitution,
            &namespace,
        )
        .expect_err("cutoff-parent timestamp substitution must fail closed");

        let authorized = crate::poco_epoch_commitment::authorize_poco_next_epoch_commitment_v0(
            candidate,
            &proof_bytes,
            &parent_header_cev0,
            &namespace,
        )
        .expect("fresh strict H1/H2 candidate commitment authority");
        let preheader_authorized =
            crate::poco_epoch_commitment::authorize_poco_preheader_next_epoch_commitment_v0(
                cutoff_candidate,
                &proof_bytes,
                &parent_header_cev0,
                &namespace,
            )
            .expect("fresh strict H1/H2 cutoff-only pre-header commitment authority");
        assert_eq!(authorized.finalized_cutoff().proof_id(), proof.id());
        assert_eq!(
            authorized.finalized_cutoff().cutoff_block_id(),
            proof.finalized_block().header().id()
        );
        assert_eq!(authorized.cutoff_parent_header(), &parent_header);
        assert_eq!(authorized.checkpoint_parent(), proof.grandchild());
        assert_eq!(preheader_authorized.checkpoint_parent(), proof.grandchild());
        let fields = authorized.commitment().fields();
        assert_eq!(
            fields.snapshot_cutoff_height.get(),
            AUTHENTICATED_CANDIDATE_CUTOFF_HEIGHT
        );
        assert_eq!(
            fields.snapshot_state_root,
            authorized.finalized_cutoff().cutoff_state_root()
        );
        assert_eq!(
            fields.new_validator_set_hash,
            authorized.new_validator_set().id()
        );
        assert_eq!(
            fields.new_consensus_parameters_hash,
            authorized.new_parameters().hash()
        );
        assert_eq!(fields.fallback_used, fallback);
        assert_eq!(
            fields.fallback_reason,
            if fallback {
                EpochFallbackReasonV0::TooFewEligibleValidators
            } else {
                EpochFallbackReasonV0::None
            }
        );
        assert_eq!(
            authorized.old_validator_set(),
            authorized.candidate().old_validator_set()
        );
        assert_eq!(
            authorized.old_parameters(),
            authorized.candidate().old_parameters()
        );
        for header in [
            proof.finalized_block().header(),
            proof.child().header(),
            proof.grandchild().header(),
        ] {
            assert_eq!(header.block_kind(), BlockKind::Regular);
            assert_eq!(header.next_epoch_commitment_hash(), None);
        }
        assert_eq!(
            proof.grandchild().header().height().get() + 1,
            AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT,
            "H1 must stop immediately before the not-yet-proposed checkpoint"
        );
        assert_ne!(authorized.authorization_id(), [0; 32]);
        assert_eq!(
            preheader_authorized.commitment(),
            authorized.commitment(),
            "pre-header and post-execution paths must derive one commitment"
        );
        assert_eq!(
            preheader_authorized.finalized_cutoff(),
            authorized.finalized_cutoff()
        );
        assert_eq!(
            preheader_authorized.old_validator_set(),
            authorized.old_validator_set()
        );
        assert_eq!(
            preheader_authorized.new_validator_set(),
            authorized.new_validator_set()
        );
        assert_ne!(preheader_authorized.authorization_id(), [0; 32]);
        assert_ne!(
            preheader_authorized.authorization_id(),
            authorized.authorization_id(),
            "pre-header and post-execution capabilities use distinct domains"
        );
    }

    let (positive_candidate, _, _, _, _, _) = authenticated_candidate_commitment_inputs_v0(false)
        .expect("build positive candidate splice input");
    let (_, _, fallback_proof, _, fallback_parent, fallback_namespace) =
        authenticated_candidate_commitment_inputs_v0(true)
            .expect("build fallback H1/H2 splice input");
    let fallback_proof_bytes = fallback_proof
        .try_cev0_bytes()
        .expect("encode fallback cutoff proof");
    let splice_error = crate::poco_epoch_commitment::authorize_poco_next_epoch_commitment_v0(
        positive_candidate,
        &fallback_proof_bytes,
        &fallback_parent,
        &fallback_namespace,
    )
    .expect_err("valid H1/H2 from another cutoff must not rebind a candidate")
    .to_string();
    assert!(
        splice_error.contains("state_root=false")
            && splice_error.contains("entries_root=false")
            && splice_error.contains("entry_count=true"),
        "valid source splice did not reach full cutoff/manifest tuple join: {splice_error}"
    );
}

#[test]
fn authenticated_next_epoch_commitment_snapshot_lead_two_is_rejected_before_candidate_or_h1_h2() {
    let error = match authenticated_candidate_commitment_source_with_snapshot_lead_v0(2, false) {
        Ok(_) => panic!("lead two unexpectedly built an authenticated candidate source"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("snapshot lead must cover the finality-certified chain"),
        "lead two did not fail at the global parameter invariant: {error}"
    );
}

#[test]
fn authenticated_candidate_fixture_closes_positive_and_fallback() {
    let fixture = build_authenticated_candidate_fixture_export_v0()
        .expect("build authenticated candidate fixture");
    assert!(!fixture.positive.checkpoint.fallback_used);
    assert_eq!(fixture.positive.checkpoint.fallback_reason_code, 0);
    assert_eq!(fixture.positive.checkpoint.computed_candidate_count, 4);
    assert!(fixture.authenticated_fallback.checkpoint.fallback_used);
    assert_eq!(
        fixture
            .authenticated_fallback
            .checkpoint
            .fallback_reason_code,
        u16::from(EpochFallbackReasonV0::TooFewEligibleValidators)
    );
    assert_eq!(
        fixture.positive.source.head_version,
        AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT - 1
    );
    assert_eq!(
        fixture.authenticated_fallback.source.head_version,
        AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT - 1
    );
    assert_eq!(
        fixture
            .positive
            .source
            .history
            .last()
            .map(|item| item.version),
        Some(AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT - 1)
    );
    assert_eq!(
        fixture
            .authenticated_fallback
            .source
            .history
            .last()
            .map(|item| item.version),
        Some(AUTHENTICATED_CANDIDATE_CHECKPOINT_HEIGHT - 1)
    );
}

#[test]
fn authenticated_candidate_final_vector_matches_rust_reconstruction() {
    let vector_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../docs/protocol/poco-bft-v0/vectors/\
         poco-authenticated-candidate-selection-v0.json",
    );
    let raw = fs::read(&vector_path).unwrap_or_else(|error| {
        panic!(
            "read authenticated candidate vector {}: {error}",
            vector_path.display()
        )
    });
    let expected: serde_json::Value = serde_json::from_slice(&raw).unwrap_or_else(|error| {
        panic!(
            "decode authenticated candidate vector {}: {error}",
            vector_path.display()
        )
    });
    let reconstructed = serde_json::to_value(
        build_authenticated_candidate_fixture_export_v0()
            .expect("reconstruct authenticated candidate fixture"),
    )
    .expect("encode reconstructed authenticated candidate fixture");
    assert_eq!(
        reconstructed, expected,
        "committed authenticated candidate vector drifted from fresh Rust JMT reconstruction"
    );
}

/// Manual exporter for the separate H3b2b2 corpus. It builds both scenarios
/// from real operations and a continuous in-memory JMT history, executes the
/// one-call checkpoint/candidate authority, and never reads or rewrites the
/// frozen H3b2b1 full-store corpus.
#[test]
#[ignore = "manual authenticated candidate selection fixture exporter"]
fn export_poco_authenticated_candidate_selection_fixture_v0() {
    let output_path = std::env::var_os(AUTHENTICATED_CANDIDATE_OUTPUT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_AUTHENTICATED_CANDIDATE_OUTPUT));
    let output = build_authenticated_candidate_fixture_export_v0()
        .expect("build authenticated candidate fixture");
    let encoded =
        serde_json::to_vec_pretty(&output).expect("encode authenticated candidate fixture");
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).expect("create authenticated candidate fixture directory");
    }
    fs::write(&output_path, encoded).expect("write authenticated candidate fixture");
    eprintln!(
        "wrote authenticated candidate selection fixture to {}",
        output_path.display()
    );
}

#[test]
fn authenticated_next_epoch_commitment_final_vector_matches_rust_reconstruction() {
    let vector_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../docs/protocol/poco-bft-v0/vectors/\
         poco-authenticated-next-epoch-commitment-v0.json",
    );
    let raw = fs::read(&vector_path).unwrap_or_else(|error| {
        panic!(
            "read authenticated next-epoch commitment vector {}: {error}",
            vector_path.display()
        )
    });
    let expected: serde_json::Value = serde_json::from_slice(&raw).unwrap_or_else(|error| {
        panic!(
            "decode authenticated next-epoch commitment vector {}: {error}",
            vector_path.display()
        )
    });
    let reconstructed = serde_json::to_value(
        build_authenticated_next_epoch_commitment_fixture_export_v0()
            .expect("reconstruct authenticated next-epoch commitment fixture"),
    )
    .expect("encode reconstructed authenticated next-epoch commitment fixture");
    assert_eq!(
        reconstructed, expected,
        "committed authenticated next-epoch commitment vector drifted from fresh raw H1/H2 reconstruction"
    );
}

/// Manual exporter for the H3b2b3a shared corpus. The output retains raw
/// parent-header/finality CEV0 and every raw ICS23 member proof. The private
/// authorization is freshly rebuilt; no H1/H2/B2-G inert token is serialized
/// or accepted as authority.
#[test]
#[ignore = "manual authenticated next-epoch commitment fixture exporter"]
fn export_poco_authenticated_next_epoch_commitment_fixture_v0() {
    let output_path = std::env::var_os(AUTHENTICATED_NEXT_EPOCH_COMMITMENT_OUTPUT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_AUTHENTICATED_NEXT_EPOCH_COMMITMENT_OUTPUT));
    let output = build_authenticated_next_epoch_commitment_fixture_export_v0()
        .expect("build authenticated next-epoch commitment fixture");
    let encoded = serde_json::to_vec_pretty(&output)
        .expect("encode authenticated next-epoch commitment fixture");
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .expect("create authenticated next-epoch commitment fixture directory");
    }
    fs::write(&output_path, encoded).expect("write authenticated next-epoch commitment fixture");
    eprintln!(
        "wrote authenticated next-epoch commitment fixture to {}",
        output_path.display()
    );
}

/// Manual exporter for the dedicated H3b2b3b checkpoint-28 evidence chain.
/// Both scenarios rebuild cutoff-only H3b2b3a authority, bind one exact native
/// checkpoint, freshly verify checkpoint/seal finality and both handoff roles,
/// and return only the crate-private joint-handoff capability.
#[test]
#[ignore = "manual authenticated checkpoint handoff fixture exporter"]
fn export_poco_authenticated_checkpoint_handoff_fixture_v0() {
    let output_path = std::env::var_os(AUTHENTICATED_CHECKPOINT_HANDOFF_OUTPUT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_AUTHENTICATED_CHECKPOINT_HANDOFF_OUTPUT));
    let output = build_authenticated_checkpoint_handoff_fixture_export_v0()
        .expect("build authenticated checkpoint handoff fixture");
    let encoded = serde_json::to_vec_pretty(&output)
        .expect("encode authenticated checkpoint handoff fixture");
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .expect("create authenticated checkpoint handoff fixture directory");
    }
    fs::write(&output_path, encoded).expect("write authenticated checkpoint handoff fixture");
    eprintln!(
        "wrote authenticated checkpoint handoff fixture to {}",
        output_path.display()
    );
}

/// Manual, test-only authoring export.  This first vertical slice freezes the
/// complete production setup and certificate-admission blocks.  Subsequent
/// challenge/governance/rotation/prune templates extend the same registry;
/// the final Node gate never treats this intermediate output as a completed
/// operation-sequence vector.
#[test]
#[ignore = "manual Rust application-operation authoring input exporter"]
fn export_poco_application_operation_authoring_inputs_v0() {
    let full_source_path = std::env::var_os(FULL_SOURCE_ENV)
        .map(PathBuf::from)
        .expect("set TRNM_POCO_APPLICATION_FULL_GENESIS to the Rust full-genesis export");
    let output_path = std::env::var_os(OUTPUT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT));
    let (_source, raw_source, chain) =
        load_full_source(&full_source_path).expect("load authenticated full application source");
    let source_digest = hex::encode(Sha256::digest(&raw_source));
    let mut sequences = vec![
        build_certificate_challenge_sequence(
            chain.clone(),
            source_digest.clone(),
            "certificate_challenge_rejected",
            ChallengeResolutionV0::Rejected,
        )
        .expect("build rejected challenge sequence"),
        build_certificate_challenge_sequence(
            chain.clone(),
            source_digest.clone(),
            "certificate_challenge_sustained",
            ChallengeResolutionV0::Sustained,
        )
        .expect("build sustained challenge sequence"),
        build_governance_sequence(chain.clone(), source_digest.clone())
            .expect("build governance sequence"),
        build_validator_rotation_sequence(chain.clone(), source_digest.clone())
            .expect("build validator rotation sequence"),
        build_release_replay_sequence(chain, source_digest.clone())
            .expect("build release/replay sequence"),
    ];
    let (_source, _, isolated_chain) =
        load_full_source(&full_source_path).expect("reload isolated fixture genesis");
    let certificate_prune_path = std::env::var_os(CERTIFICATE_PRUNE_SOURCE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CERTIFICATE_PRUNE_SOURCE));
    let consumer_key_prune_path = std::env::var_os(CONSUMER_KEY_PRUNE_SOURCE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONSUMER_KEY_PRUNE_SOURCE));
    let meter_prune_path = std::env::var_os(METER_PRUNE_SOURCE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_METER_PRUNE_SOURCE));
    let validator_prune_path = std::env::var_os(VALIDATOR_PRUNE_SOURCE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VALIDATOR_PRUNE_SOURCE));
    let (certificate_prune_reference, certificate_prune_sequence) =
        build_certificate_prune_source_and_sequence(
            isolated_chain.clone(),
            &certificate_prune_path,
        )
        .expect("build certificate prune source/sequence");
    let (consumer_key_prune_reference, consumer_key_prune_sequence) =
        build_consumer_key_prune_source_and_sequence(
            isolated_chain.clone(),
            &consumer_key_prune_path,
        )
        .expect("build consumer-key prune source/sequence");
    let (meter_prune_reference, meter_prune_sequence) =
        build_meter_prune_source_and_sequence(isolated_chain.clone(), &meter_prune_path)
            .expect("build meter prune source/sequence");
    let (validator_prune_reference, validator_prune_sequence) =
        build_validator_prune_source_and_sequence(isolated_chain, &validator_prune_path)
            .expect("build validator prune source/sequence");
    sequences.extend([
        certificate_prune_sequence,
        consumer_key_prune_sequence,
        meter_prune_sequence,
        validator_prune_sequence,
    ]);
    let source_path = full_source_path
        .canonicalize()
        .unwrap_or(full_source_path)
        .display()
        .to_string();
    let output = AuthoringInputsExportV0 {
        schema: AUTHORING_INPUT_SCHEMA,
        schema_version: 0,
        source_exports: SourceReferencesExportV0 {
            full_application_store: SourceReferenceExportV0 {
                path: source_path,
                sha256_hex: source_digest,
                schema: FULL_SOURCE_SCHEMA.to_string(),
            },
            certificate_prune_replay: certificate_prune_reference,
            consumer_key_prune_replay: consumer_key_prune_reference,
            meter_prune_replay: meter_prune_reference,
            validator_prune_replay: validator_prune_reference,
        },
        sequences,
    };
    let encoded = serde_json::to_vec_pretty(&output).expect("encode authoring inputs");
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).expect("create authoring output directory");
    }
    fs::write(&output_path, encoded).expect("write authoring input export");
    eprintln!(
        "wrote PoCO application operation authoring inputs to {}",
        output_path.display()
    );
}
