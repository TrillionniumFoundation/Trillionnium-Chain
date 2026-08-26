use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, ensure, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    response_apply_snapshot_chunk, response_offer_snapshot, response_process_proposal, Event,
    EventAttribute, ExecTxResult, RequestApplySnapshotChunk, RequestCheckTx, RequestFinalizeBlock,
    RequestInfo, RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot,
    RequestPrepareProposal, RequestProcessProposal, RequestQuery, ResponseApplySnapshotChunk,
    ResponseCheckTx, ResponseCommit, ResponseFinalizeBlock, ResponseInfo, ResponseInitChain,
    ResponseListSnapshots, ResponseLoadSnapshotChunk, ResponseOfferSnapshot,
    ResponsePrepareProposal, ResponseProcessProposal, ResponseQuery, Snapshot, ValidatorUpdate,
};
use tendermint_proto::v0_38::crypto::{ProofOp, ProofOps};
use trnm_finality_types::{hash_domain, SignedCommandEnvelopeV1};
#[cfg(test)]
use trnm_node::live::node::{CommandInterpreter, RoutingCommandInterpreter};
use trnm_node::live::{
    merkle::root_only,
    node::{AuthorizedSignerV1, ObjectView},
    store::{ObjectMutation, StoredObject},
};
use trnm_protocol::{
    account_key, fee_policy_key, task_key, CanonicalTxV1, FeePolicyV1,
    CANONICAL_TX_PAYLOAD_TYPE_V1, FEE_POLICY_OBJECT_TYPE_V1,
};
#[cfg(test)]
use trnm_runtime::TryStateViewV0 as RuntimeTryStateViewV0;
use trnm_runtime::{
    ExecutionContext, ResourceEstimate, RuntimeEvent, StateObject, StateView as RuntimeStateView,
};

mod auth_tree;
#[allow(dead_code)]
mod execution_outcome;
/// Candidate-local, offline-only Comet -> PoCO migration replay and ceremony
/// verifier.  This module is deliberately not wired into node startup or
/// production activation; it closes the concrete MIG-ROOT rehearsal boundary
/// required by the canonical development plan.
pub mod migration_rehearsal;
mod native_consensus_application_host;
mod native_execution;
#[allow(dead_code)]
mod native_payload_validation;
#[allow(dead_code)]
mod native_speculative_overlay;
#[allow(dead_code)]
mod native_valid_artifact;
#[allow(dead_code)]
mod native_validation_artifact;
mod native_validation_valid_delivery;
#[cfg(feature = "scale-gate")]
mod persistent_scale;
#[allow(dead_code)]
mod poco_application;
#[cfg(test)]
mod poco_application_evidence;
mod poco_checkpoint;
#[allow(dead_code)]
mod poco_checkpoint_header;
#[allow(dead_code)]
mod poco_epoch_commitment;
#[allow(dead_code)]
mod poco_joint_handoff;
#[allow(dead_code)]
mod poco_nullifier;
#[allow(dead_code)]
mod poco_preparation_journal;
mod poco_semantics;
pub mod poco_snapshot;
#[cfg(feature = "recovery-test-support")]
mod recovery_test_support;
// B2-H3a/H3b1 is crate-private: exact PoCO state is now sealed across the
// production persistence and restore paths, while the authoritative runtime
// mutation source and business authorization remain a later step.
#[allow(dead_code)]
pub(crate) mod poco_transition;
#[cfg(feature = "scale-gate")]
mod scale;
mod store;
mod validator_lifecycle;

pub use native_consensus_application_host::{
    ConfirmedNativeApplicationAppliedFactsV0, ConfirmedNativeApplicationFinalizationAppliedV0,
    ConfirmedNativeApplicationNodeCheckpointFactsV0,
    ConfirmedNativeApplicationStateSyncAnchorSuccessorsV0,
    ConfirmedNativeApplicationStateSyncAnchorV0,
    ConfirmedNativeApplicationValidCompletionRecoveryV0, NativeConsensusApplicationAppliedKindV0,
    NativeConsensusApplicationAuthoritiesInstallRejectionV0,
    NativeConsensusApplicationHostConfigV0, NativeConsensusApplicationHostErrorV0,
    NativeConsensusApplicationHostV0, NativeConsensusApplicationValidCompletionSourceV0,
    NativeStateSyncAnchorSuccessorValidationFactsV0,
    PreparedNativeApplicationH1ProjectionExpectationV0,
};
pub use native_validation_valid_delivery::{
    CoreAcceptedNativeValidationValidInvariantV0, CoreAcceptedNativeValidationValidV0,
    InvalidCoreAcceptedNativeValidationValidV0, NativeAuthenticatedGenesisH1AckedValidV0,
    NativeAuthenticatedGenesisH1CompletedAppConfirmationV0,
    NativeAuthenticatedGenesisH1CoreAcceptedValidV0, NativeAuthenticatedGenesisH1DeliveredValidV0,
    NativeAuthenticatedGenesisH1SafetyPersistedValidV0, NativeValidationValidAppFactsV0,
    NativeValidationValidCallbackBindFailureV0, NativeValidationValidCallbackFailureV0,
    NativeValidationValidCallbackRejectionV0, NativeValidationValidCallbackV0,
    RejectedNativeValidationValidCallbackV0,
};
pub use poco_checkpoint::{PocoAuthorityConfigV0, POCO_AUTHORITY_CONFIG_SCHEMA_V0};
#[cfg(test)]
pub(crate) use store::native_validation_recovery::NativeValidationConfirmedInvalidTransitionV0;
pub use store::native_validation_recovery::{
    NativeValidationRecoveredAckedFactsV0, NativeValidationRecoveredInvalidCallbackFactsV0,
    NativeValidationRecoveredInvalidReasonV0, NativeValidationRecoveredInvalidStateV0,
    NativeValidationRecoveryOpenFailureV0, NativeValidationRecoveryReconcileFailureV0,
    NativeValidationRecoveryStoreConfigV0, NativeValidationRecoveryStoreV0,
    NativeValidationRecoveryTransitionFailureV0, NativeValidationRecoveryUnsupportedV0,
};
pub use store::{
    ConfirmedNativeAuthenticatedGenesisApplicationCommissioningV0,
    ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCompletedV0,
    ConfirmedNativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
    ConfirmedNativeAuthenticatedGenesisH1StableApplicationV0,
    NativeAuthenticatedGenesisApplicationCommissioningConfigV0,
    NativeAuthenticatedGenesisApplicationCommissioningDispositionV0,
    NativeAuthenticatedGenesisApplicationCommissioningErrorV0,
    NativeAuthenticatedGenesisApplicationCommissioningHostV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverCompletedHostV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverConfigV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverCoreAcceptedV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverErrorV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverHostV0,
    NativeAuthenticatedGenesisH1ObligationTakeoverSourceV0,
    NativeAuthenticatedGenesisH1OfflineApplicationRegistrarV0,
    NativeAuthenticatedGenesisH1OfflineCompletedV0,
    NativeAuthenticatedGenesisH1OfflineValidationActivationRejectionV0,
    NativeAuthenticatedGenesisH1OfflineValidationErrorV0,
    NativeAuthenticatedGenesisH1OfflineValidationFactsV0,
    NativeAuthenticatedGenesisH1OfflineValidationHostV0,
    NativeAuthenticatedGenesisH1StableApplicationHostV0,
    NativeAuthenticatedGenesisH1StableApplicationSourceV0,
    NativeAuthenticatedGenesisH1StableRecoveryConfigV0,
    NativeAuthenticatedGenesisH1StableRecoveryErrorV0,
    PreparedNativeAuthenticatedGenesisH1InactiveExpectationV0,
};

#[cfg(feature = "recovery-test-support")]
pub use recovery_test_support::{
    advance_native_validation_recovery_test_fixture_to_delivered_v0,
    empty_native_application_trusted_base_root_for_recovery_test_v0,
    empty_state_sync_anchor_successor_commitments_for_recovery_test_v0,
    initialize_empty_native_application_test_fixture_v0,
    initialize_legacy_genesis_application_test_fixture_v0,
    initialize_native_validation_recovery_test_fixture_v0, LegacyGenesisApplicationTestFixtureV0,
    NativeEmptyAnchorSuccessorCommitmentsV0, NativeEmptyApplicationTestFixtureV0,
    NativeValidationRecoveryTestConfigBundleV0, NativeValidationRecoveryTestFixtureConfigV0,
    NativeValidationRecoveryTestFixtureErrorV0, NativeValidationRecoveryTestFixtureStateV0,
    NativeValidationRecoveryTestFixtureV0,
};

#[cfg(feature = "scale-gate")]
pub use persistent_scale::{
    run_persistent_scale_gate, PersistentScaleConfig, PersistentScaleReport,
};
#[cfg(feature = "scale-gate")]
pub use scale::{run_auth_tree_scale_gate, AuthTreeScaleConfig, AuthTreeScaleReport};

use auth_tree::{
    stored_object_key, validator_state_key, AuthWrite, AuthenticatedObjectRecord, InMemoryAuthTree,
    PlannedAuthUpdate,
};
use native_execution::{
    authorize_native_checkpoint_execution_v0, AuthorizedNativeCheckpointExecutionV0,
    NativeBlockExecutionV0, NativeTransactionReceiptFactsV0,
};
use poco_application::{
    AuthenticatedPocoApplicationContextV0, AuthenticatedPocoCandidateSelectionV0,
    PocoApplicationBlockOverlayV0, POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
};
use poco_checkpoint::{
    active_consensus_configuration, authorize_poco_checkpoint_candidate_selection_v0,
    maybe_authenticated_poco_projection_at_v0, validate_application_validator_projection,
    AuthenticatedPocoProjectionAtV0, PocoCheckpointExecutionInputV0,
};
use poco_transition::{
    auth_writes_from_sealed_poco_application_v0, genesis_poco_snapshot_writes_v0,
    scheduled_cutoff_manifest_refresh_write_v0, take_and_validate_production_poco_projection_v0,
};
use store::{ApplicationStore, PinnedSnapshot};
#[cfg(test)]
use store::{AuthenticatedRuntimeReadFailureV0, AuthenticatedRuntimeReadSnapshotV0};
use validator_lifecycle::{
    validators_from_abci, validators_to_abci, ConsensusValidatorV1, ValidatorGovernanceV1,
    ValidatorLifecycleStateV1, ValidatorSetTransitionV1, ValidatorTransitionAuthorization,
    VALIDATOR_LIFECYCLE_SCHEMA_V1, VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
};

pub const CONFIG_SCHEMA_V1: &str = "trnm_cometbft_app_config_v1";
pub const GENESIS_SCHEMA_V2: &str = "trnm_cometbft_genesis_v2";
pub const SIMULATION_RESPONSE_SCHEMA_V1: &str = "trnm_canonical_simulation_response_v1";
const APP_VERSION: u64 = 4;
const SNAPSHOT_FORMAT_V3: u32 = 3;
const SNAPSHOT_FORMAT_V4: u32 = 4;
const SNAPSHOT_SQLITE_STORE_SCHEMA_V3: u32 = 3;
const SNAPSHOT_SQLITE_STORE_SCHEMA_V4: u32 = 4;
const SNAPSHOT_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_SNAPSHOT_CHUNKS: u32 = 4096;
const RETAINED_SNAPSHOTS: usize = 16;
const DISK_SNAPSHOT_INTERVAL: u64 = 5;
const RETAINED_DISK_SNAPSHOTS: usize = 3;
pub(crate) const AUTH_PROOF_RETENTION_VERSIONS: u64 = 8_192;
const AUTH_PRUNE_INTERVAL: u64 = 256;
const AUTH_PRUNE_BATCH_ROWS: usize = 256;
const AUTH_PRUNE_BATCH_LOGICAL_BYTES: u64 = 4 * 1024 * 1024;
const AUTH_PRUNE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(2);
const AUTH_PRUNE_INTER_BATCH_DELAY: std::time::Duration = std::time::Duration::from_millis(1);
const MAX_SIMULATION_TX_BYTES: usize = 1024 * 1024;
const MAX_SNAPSHOT_METADATA_BYTES: usize = 1024 * 1024;
const DISK_SNAPSHOT_MANIFEST_SCHEMA_V1: &str = "trnm_disk_snapshot_manifest_v1";
const MAX_DISK_SNAPSHOT_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

fn authenticated_query_floor(height: u64) -> u64 {
    if height <= AUTH_PROOF_RETENTION_VERSIONS || !height.is_multiple_of(AUTH_PRUNE_INTERVAL) {
        0
    } else {
        height
            .saturating_sub(AUTH_PROOF_RETENTION_VERSIONS)
            .saturating_add(1)
    }
}

pub(crate) fn validate_poco_parameter_retention_v0(
    parameters: &trnm_consensus_types::ConsensusParametersV0,
) -> Result<()> {
    ensure!(
        parameters.snapshot_lead_blocks() <= AUTH_PROOF_RETENTION_VERSIONS,
        "PoCO snapshot lead exceeds authenticated JMT history retention"
    );
    ensure!(
        u64::from(parameters.max_block_bytes())
            <= u64::try_from(store::MAX_NATIVE_VALIDATION_BODY_RECORD_BYTES)
                .expect("native validation body cap fits u64"),
        "consensus max_block_bytes exceeds the application validation journal body limit"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationErrorV1 {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationResponseV1 {
    pub schema: String,
    pub height: u64,
    pub app_hash_hex: String,
    pub gas_used: u64,
    pub fee_estimate: String,
    pub would_succeed: bool,
    pub error: Option<SimulationErrorV1>,
    pub events: Vec<RuntimeEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestCrashStage {
    ProcessProposal,
    FinalizeBlock,
    CommitAfterPersist,
}

#[derive(Debug, Clone)]
pub struct TestCrashPlan {
    pub stage: TestCrashStage,
    pub height: u64,
    pub marker_path: PathBuf,
}

impl TestCrashPlan {
    fn trigger_if_matching(&self, stage: TestCrashStage, height: u64) {
        if self.stage != stage || self.height != height {
            return;
        }
        let mut marker = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.marker_path)
        {
            Ok(marker) => marker,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return,
            Err(error) => panic!(
                "create test crash marker {}: {error}",
                self.marker_path.display()
            ),
        };
        writeln!(marker, "stage={stage:?} height={height}").expect("write test crash marker");
        marker.sync_all().expect("sync test crash marker");
        eprintln!(
            "[trnm-cometbft-app] unsafe_test_crash stage={stage:?} height={height} marker={}",
            self.marker_path.display()
        );
        std::process::exit(86);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusAppConfig {
    pub schema: String,
    pub chain_id: String,
    pub authorized_signers: Vec<AuthorizedSignerV1>,
    #[serde(default)]
    pub poco_authority: Option<PocoAuthorityConfigV0>,
    #[serde(default)]
    pub state_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAppStateV2 {
    pub schema: String,
    pub chain_id: String,
    pub app_version: u64,
    pub authorized_signers: Vec<AuthorizedSignerV1>,
    #[serde(default)]
    pub poco_authority: Option<PocoAuthorityConfigV0>,
    /// Optional exact namespace-8 genesis projection. An empty list preserves
    /// legacy/inert PoCO state; H3b2b1 production operations require this list
    /// to contain the frozen active configuration and kind-16 application
    /// authority head. No runtime path upgrades a legacy projection in place.
    #[serde(default)]
    pub poco_genesis_entries: Vec<PocoGenesisEntryV0>,
    pub validator_governance: ValidatorGovernanceV1,
    pub initial_validators: Vec<ConsensusValidatorV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PocoGenesisEntryV0 {
    pub kind: u8,
    pub logical_key_hex: String,
    pub value_hex: String,
}

struct ValidatedGenesisV2 {
    lifecycle: ValidatorLifecycleStateV1,
    poco_entries: Vec<poco_snapshot::PocoSnapshotEntryV0>,
}

fn validate_authorized_signers_v1(authorized_signers: &[AuthorizedSignerV1]) -> Result<()> {
    ensure!(
        !authorized_signers.is_empty(),
        "authorized_signers must not be empty"
    );
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for signer in authorized_signers {
        ensure!(ids.insert(signer.signer_id.clone()), "duplicate signer_id");
        ensure!(
            keys.insert(signer.public_key_hex.clone()),
            "duplicate signer public key"
        );
        ensure!(
            matches!(signer.signer_role.as_str(), "hepta" | "nakama" | "operator"),
            "unsupported signer role"
        );
        let key = trnm_finality_types::crypto::verifying_key_from_hex(&signer.public_key_hex)
            .context("authorized signer public key must be canonical Ed25519")?;
        ensure!(
            !key.is_weak(),
            "authorized signer public key must not be small-order"
        );
    }
    Ok(())
}

impl ConsensusAppConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == CONFIG_SCHEMA_V1,
            "unsupported app config schema"
        );
        ensure!(
            !self.chain_id.is_empty()
                && self.chain_id == self.chain_id.trim()
                && self.chain_id.len() <= 128,
            "chain_id is not canonical"
        );
        validate_authorized_signers_v1(&self.authorized_signers)?;
        if let Some(authority) = &self.poco_authority {
            authority.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct AppState {
    height: u64,
    app_hash: [u8; 32],
    objects: BTreeMap<String, StoredObject>,
    command_ids: BTreeSet<String>,
    signer_nonces: BTreeSet<(String, u64)>,
    validator_lifecycle: Option<ValidatorLifecycleStateV1>,
    pending: Option<PendingBlock>,
}

#[derive(Debug, Clone)]
struct PendingBlock {
    height: u64,
    app_hash: [u8; 32],
    tx_results: Vec<ExecTxResult>,
    #[allow(dead_code)]
    native_execution: AuthorizedNativeCheckpointExecutionV0,
    validator_updates: Vec<ValidatorUpdate>,
    delta: BlockDelta,
    auth_update: PlannedAuthUpdate,
    poco_checkpoint_execution: Option<AuthenticatedPocoCandidateSelectionV0>,
}

struct CheckpointBlockExecutionInput<'a> {
    txs: &'a [Bytes],
    tx_results: &'a [ExecTxResult],
    native_execution: &'a AuthorizedNativeCheckpointExecutionV0,
    timestamp_ms: u64,
    block_hash: &'a [u8],
    next_state_root: [u8; 32],
}

struct AppliedTransactionV0 {
    tx_result: ExecTxResult,
    native_receipt: NativeTransactionReceiptFactsV0,
}

const MAX_AUTHENTICATED_POCO_PROJECTION_CACHE_ENTRIES: usize = 4;
type AuthenticatedPocoProjectionCache = BTreeMap<(u64, [u8; 32]), AuthenticatedPocoProjectionAtV0>;

#[derive(Debug, Clone, Copy)]
enum PocoScheduleCacheV0 {
    Inactive,
    Active {
        cutoff_height: u64,
        checkpoint_height: u64,
    },
}

#[derive(Debug, Clone, Default)]
struct BlockDelta {
    objects: BTreeMap<String, StoredObject>,
    command_ids: BTreeSet<String>,
    signer_nonces: BTreeSet<(String, u64)>,
    validator_lifecycle: Option<ValidatorLifecycleStateV1>,
    poco_application: Option<PocoApplicationBlockOverlayV0>,
}

struct OverlayObjects<'a> {
    base: &'a BTreeMap<String, StoredObject>,
    changes: &'a BTreeMap<String, StoredObject>,
    store: Option<&'a ApplicationStore>,
}

impl ObjectView for OverlayObjects<'_> {
    fn get(&self, object_key_hex: &str) -> Option<&StoredObject> {
        self.changes
            .get(object_key_hex)
            .or_else(|| self.base.get(object_key_hex))
    }
}

impl RuntimeStateView for OverlayObjects<'_> {
    fn get(&self, object_key_hex: &str) -> Option<StateObject> {
        self.changes
            .get(object_key_hex)
            .or_else(|| self.base.get(object_key_hex))
            .cloned()
            .or_else(|| {
                self.store.and_then(|store| {
                    store.load_object(object_key_hex).unwrap_or_else(|error| {
                        panic!(
                            "fail-stop: read authenticated runtime object {object_key_hex}: {error:#}"
                        )
                    })
                })
            })
            .map(|object| StateObject {
                object_type: object.object_type.clone(),
                version: object.version,
                value_bytes: object.value_bytes.clone(),
            })
    }
}

/// Test-only model of the unwired authenticated native planning view.
///
/// Unlike the legacy ABCI overlay, its persistent fallback is one already
/// validated, pinned read transaction rather than an independently reopened
/// store read for every object.
#[cfg(test)]
struct AuthenticatedRuntimeOverlayObjects<'a> {
    base: &'a BTreeMap<String, StoredObject>,
    changes: &'a BTreeMap<String, StoredObject>,
    snapshot: &'a AuthenticatedRuntimeReadSnapshotV0,
}

#[cfg(test)]
impl RuntimeTryStateViewV0 for AuthenticatedRuntimeOverlayObjects<'_> {
    type Error = AuthenticatedRuntimeReadFailureV0;

    fn try_get(
        &self,
        object_key_hex: &str,
    ) -> std::result::Result<Option<StateObject>, Self::Error> {
        let object = if let Some(object) = self
            .changes
            .get(object_key_hex)
            .or_else(|| self.base.get(object_key_hex))
        {
            Some(object.clone())
        } else {
            self.snapshot.load(object_key_hex)?
        };
        Ok(object.map(|object| StateObject {
            object_type: object.object_type,
            version: object.version,
            value_bytes: object.value_bytes,
        }))
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            height: 0,
            app_hash: empty_app_hash(),
            objects: BTreeMap::new(),
            command_ids: BTreeSet::new(),
            signer_nonces: BTreeSet::new(),
            validator_lifecycle: None,
            pending: None,
        }
    }
}

struct AppCore {
    config: ConsensusAppConfig,
    #[cfg(test)]
    interpreter: RoutingCommandInterpreter,
    store: Option<ApplicationStore>,
    state: Mutex<AppState>,
    auth_tree: Mutex<InMemoryAuthTree>,
    poco_projection_cache: Mutex<AuthenticatedPocoProjectionCache>,
    poco_schedule_cache: Mutex<Option<PocoScheduleCacheV0>>,
    snapshots: Mutex<BTreeMap<u64, SnapshotRecord>>,
    snapshot_building: Mutex<SnapshotBuildQueue>,
    snapshot_restore: Mutex<Option<SnapshotRestore>>,
    auth_prune_worker: Mutex<AuthPruneWorkerState>,
    auth_prune_fatal: Mutex<Option<String>>,
    test_crash_plan: Option<TestCrashPlan>,
}

#[derive(Default)]
struct SnapshotBuildQueue {
    active: Option<u64>,
    catch_up_requested: bool,
}

#[derive(Default)]
struct AuthPruneWorkerState {
    active: bool,
    wake_requested: bool,
}

struct PendingDiskSnapshot {
    state: AppState,
    disk_path: PathBuf,
    pinned: PinnedSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAppStateV4 {
    schema: String,
    height: u64,
    app_hash_hex: String,
    objects: Vec<PersistedObjectV1>,
    command_ids: BTreeSet<String>,
    signer_nonces: BTreeSet<(String, u64)>,
    validator_lifecycle: ValidatorLifecycleStateV1,
    auth_tree_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedObjectV1 {
    object_key_hex: String,
    object_type: String,
    version: u64,
    value_hash_hex: String,
    value_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotMetadataV3 {
    schema: String,
    chain_id: String,
    height: u64,
    app_hash_hex: String,
    app_version: u64,
    store_schema: u32,
    state_codec: String,
    auth_tree_codec: String,
    oldest_auth_version: u64,
    total_bytes: u64,
    chunk_size: u32,
    payload_hash_hex: String,
    chunk_hashes_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotMetadataV4 {
    schema: String,
    chain_id: String,
    height: u64,
    app_hash_hex: String,
    app_version: u64,
    store_schema: u32,
    state_codec: String,
    auth_tree_codec: String,
    history_mode: String,
    oldest_auth_version: u64,
    authorized_signers_hash_hex: String,
    total_bytes: u64,
    chunk_size: u32,
    payload_hash_hex: String,
    chunk_hashes_hex: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskSnapshotManifestV1 {
    schema: String,
    height: u64,
    format: u32,
    chunks: u32,
    manifest_hash_hex: String,
    metadata_hex: String,
    payload_len: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRestoreJournalV1 {
    schema: String,
    manifest_hash_hex: String,
    total_bytes: u64,
    chunk_size: u32,
    received: Vec<bool>,
}

#[derive(Debug)]
enum SnapshotRestore {
    MemoryV3 {
        metadata: SnapshotMetadataV3,
        chunks: Vec<Option<Bytes>>,
    },
    FileV4 {
        metadata: SnapshotMetadataV4,
        manifest_hash_hex: String,
        stage_path: PathBuf,
        journal_path: PathBuf,
        received: Vec<bool>,
    },
    Installed {
        chunks: u32,
    },
}

#[derive(Debug, Clone)]
struct SnapshotRecord {
    snapshot: Snapshot,
    payload: SnapshotPayload,
}

#[derive(Debug, Clone)]
enum SnapshotPayload {
    Memory(Vec<u8>),
    File { path: PathBuf, len: usize },
}

impl SnapshotRestore {
    fn reuses_files_from(&self, previous: &Self) -> bool {
        matches!(
            (self, previous),
            (
                Self::FileV4 {
                    stage_path: left_stage,
                    journal_path: left_journal,
                    ..
                },
                Self::FileV4 {
                    stage_path: right_stage,
                    journal_path: right_journal,
                    ..
                }
            ) if left_stage == right_stage && left_journal == right_journal
        )
    }

    fn cleanup_files(&self) {
        if let Self::FileV4 {
            stage_path,
            journal_path,
            ..
        } = self
        {
            for path in [stage_path, journal_path] {
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => eprintln!(
                        "[trnm-cometbft-app] failed to remove rejected snapshot stage {}: {error}",
                        path.display()
                    ),
                }
            }
        }
    }
}

impl SnapshotPayload {
    fn read_chunk(&self, chunk: u32) -> Result<Bytes> {
        let start = chunk as usize * SNAPSHOT_CHUNK_SIZE;
        let len = match self {
            Self::Memory(bytes) => bytes.len(),
            Self::File { len, .. } => *len,
        };
        let end = start.saturating_add(SNAPSHOT_CHUNK_SIZE).min(len);
        ensure!(start < end, "snapshot chunk is outside payload");
        match self {
            Self::Memory(bytes) => Ok(Bytes::copy_from_slice(&bytes[start..end])),
            Self::File { path, .. } => {
                let mut file = fs::File::open(path)
                    .with_context(|| format!("open snapshot payload {}", path.display()))?;
                file.seek(SeekFrom::Start(start as u64))?;
                let mut bytes = vec![0u8; end - start];
                file.read_exact(&mut bytes)?;
                Ok(Bytes::from(bytes))
            }
        }
    }

    fn remove_file(&self) -> Result<()> {
        if let Self::File { path, .. } = self {
            for candidate in [path.clone(), snapshot_manifest_path(path)] {
                match fs::remove_file(&candidate) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct CometBftApplication {
    core: Arc<AppCore>,
}

fn validate_signed_command_envelope_against_policy_v1<'a>(
    envelope: &SignedCommandEnvelopeV1,
    expected_chain_id: &str,
    timestamp_ms: u64,
    authorized_signers: &'a [AuthorizedSignerV1],
) -> Result<&'a AuthorizedSignerV1> {
    envelope.validate_at_strict(expected_chain_id, timestamp_ms)?;
    let signer = authorized_signers
        .iter()
        .find(|signer| signer.signer_id == envelope.signer_id)
        .ok_or_else(|| anyhow!("command signer is not authorized"))?;
    ensure!(
        signer.signer_role == envelope.signer_role,
        "signer role mismatch"
    );
    ensure!(
        signer.public_key_hex == envelope.public_key_hex,
        "signer public key mismatch"
    );
    Ok(signer)
}

impl CometBftApplication {
    /// Borrows the only production native-validation host tuple: the store,
    /// chain binding, and signer-policy preimage already validated together at
    /// application startup. This is not wired to ABCI or a Core callback yet.
    #[allow(dead_code)]
    fn native_validation_host_v0(
        &self,
    ) -> Option<native_payload_validation::NativeValidationHostV0<'_>> {
        native_payload_validation::NativeValidationHostV0::from_app_core(&self.core)
    }

    pub fn new(config: ConsensusAppConfig) -> Result<Self> {
        Self::new_inner(config, None)
    }

    pub fn new_with_test_crash_plan(
        config: ConsensusAppConfig,
        crash_plan: TestCrashPlan,
    ) -> Result<Self> {
        ensure!(crash_plan.height > 0, "test crash height must be positive");
        ensure!(
            crash_plan.marker_path.parent().is_some(),
            "test crash marker must have a parent directory"
        );
        Self::new_inner(config, Some(crash_plan))
    }

    fn new_inner(
        config: ConsensusAppConfig,
        test_crash_plan: Option<TestCrashPlan>,
    ) -> Result<Self> {
        config.validate()?;
        #[cfg(test)]
        let interpreter =
            RoutingCommandInterpreter::from_authorized_signers(&config.authorized_signers)?;
        let store = config
            .state_path
            .as_ref()
            .map(|path| {
                ApplicationStore::open(
                    path,
                    &config.chain_id,
                    &hex::encode(signer_policy_commitment(&config.authorized_signers)),
                )
            })
            .transpose()?;
        let (state, auth_tree) = match &store {
            Some(store) => (store.load_or_migrate()?, InMemoryAuthTree::default()),
            None => (AppState::default(), InMemoryAuthTree::default()),
        };
        if let Some(lifecycle) = state.validator_lifecycle.as_ref() {
            validate_lifecycle_authorization(&config, lifecycle)?;
        }
        validate_poco_authority_binding(&config, &state, store.as_ref())?;
        let mut snapshots = match (&store, state.height) {
            (Some(store), height) if height > 0 => {
                load_disk_snapshot_records(&config, &state, store).unwrap_or_else(|error| {
                    eprintln!(
                    "[trnm-cometbft-app] optional disk snapshot catalog recovery failed: {error:#}"
                );
                    BTreeMap::new()
                })
            }
            _ => BTreeMap::new(),
        };
        if state.height > 0 && store.is_none() {
            match build_snapshot(
                &config.chain_id,
                &state,
                &auth_tree,
                snapshot_path(&config, state.height),
            ) {
                Ok(snapshot) => {
                    snapshots.insert(state.height, snapshot);
                }
                Err(error) => {
                    eprintln!(
                        "[trnm-cometbft-app] committed SQLite state is authoritative; optional startup snapshot failed: {error:#}"
                    );
                }
            }
        }
        let application = Self {
            core: Arc::new(AppCore {
                config,
                #[cfg(test)]
                interpreter,
                store,
                state: Mutex::new(state),
                auth_tree: Mutex::new(auth_tree),
                poco_projection_cache: Mutex::new(BTreeMap::new()),
                poco_schedule_cache: Mutex::new(None),
                snapshots: Mutex::new(snapshots),
                snapshot_building: Mutex::new(SnapshotBuildQueue::default()),
                snapshot_restore: Mutex::new(None),
                auth_prune_worker: Mutex::new(AuthPruneWorkerState::default()),
                auth_prune_fatal: Mutex::new(None),
                test_crash_plan,
            }),
        };
        if let Some(store) = &application.core.store {
            if store.has_pending_auth_prune()? {
                application.wake_authenticated_prune_worker()?;
            }
        }
        Ok(application)
    }

    fn trigger_test_crash(&self, stage: TestCrashStage, height: u64) {
        if let Some(plan) = &self.core.test_crash_plan {
            plan.trigger_if_matching(stage, height);
        }
    }

    pub fn height_and_app_hash(&self) -> Result<(u64, [u8; 32])> {
        let state = self
            .core
            .state
            .lock()
            .map_err(|_| anyhow!("consensus application state lock poisoned"))?;
        Ok((state.height, state.app_hash))
    }

    fn simulate_canonical_tx(&self, state: &AppState, tx_bytes: &[u8]) -> SimulationResponseV1 {
        let response = |estimate: ResourceEstimate,
                        would_succeed: bool,
                        error: Option<SimulationErrorV1>,
                        events: Vec<RuntimeEvent>| SimulationResponseV1 {
            schema: SIMULATION_RESPONSE_SCHEMA_V1.to_string(),
            height: state.height,
            app_hash_hex: hex::encode(state.app_hash),
            gas_used: estimate.gas_used,
            fee_estimate: estimate.fee_estimate.to_string(),
            would_succeed,
            error,
            events,
        };
        let failure = |estimate: ResourceEstimate, code: &str, message: String| {
            response(
                estimate,
                false,
                Some(SimulationErrorV1 {
                    code: code.to_string(),
                    message,
                }),
                Vec::new(),
            )
        };
        let zero_estimate = ResourceEstimate {
            gas_used: 0,
            fee_estimate: 0,
        };
        if tx_bytes.len() > MAX_SIMULATION_TX_BYTES {
            return failure(
                zero_estimate,
                "simulation_input_too_large",
                format!("canonical transaction JSON exceeds {MAX_SIMULATION_TX_BYTES} bytes"),
            );
        }
        let tx: CanonicalTxV1 = match serde_json::from_slice(tx_bytes) {
            Ok(tx) => tx,
            Err(_) => {
                return failure(
                    zero_estimate,
                    "invalid_transaction_json",
                    "canonical transaction JSON could not be decoded".to_string(),
                )
            }
        };
        let authorized_signer = self
            .core
            .config
            .authorized_signers
            .iter()
            .find(|signer| signer.signer_id == tx.sender);
        // The fallback role is used only to compute a useful resource estimate for
        // an unauthorized sender. Authorization is checked before execution below.
        let estimate_role = authorized_signer
            .map(|signer| signer.signer_role.as_str())
            .unwrap_or("operator");
        let no_changes = BTreeMap::new();
        let objects = OverlayObjects {
            base: &state.objects,
            changes: &no_changes,
            store: self.core.store.as_ref(),
        };
        let estimate_context = ExecutionContext {
            height: state.height.saturating_add(1),
            signer_id: &tx.sender,
            signer_role: estimate_role,
            payload_len: tx_bytes.len(),
        };
        let estimate = match trnm_runtime::estimate_resources(&tx, estimate_context, &objects) {
            Ok(estimate) => estimate,
            Err(error) => {
                return failure(zero_estimate, error.code(), error.to_string());
            }
        };
        let Some(signer) = authorized_signer else {
            return failure(
                estimate,
                "unauthorized_sender",
                "canonical transaction sender is not authorized".to_string(),
            );
        };
        let execution_context = ExecutionContext {
            height: state.height.saturating_add(1),
            signer_id: &tx.sender,
            signer_role: &signer.signer_role,
            payload_len: tx_bytes.len(),
        };
        match trnm_runtime::execute(&tx, execution_context, &objects) {
            Ok(receipt) => {
                debug_assert_eq!(receipt.gas_used, estimate.gas_used);
                debug_assert_eq!(receipt.fee_charged, estimate.fee_estimate);
                response(estimate, true, None, receipt.events)
            }
            Err(error) => failure(estimate, error.code(), error.to_string()),
        }
    }

    fn validate_envelope(
        &self,
        envelope: &SignedCommandEnvelopeV1,
        timestamp_ms: u64,
    ) -> Result<()> {
        validate_signed_command_envelope_against_policy_v1(
            envelope,
            &self.core.config.chain_id,
            timestamp_ms,
            &self.core.config.authorized_signers,
        )?;
        Ok(())
    }

    fn start_block_delta(&self, state: &AppState) -> Result<BlockDelta> {
        let mut lifecycle = state
            .validator_lifecycle
            .clone()
            .context("validator lifecycle is not initialized")?;
        lifecycle.prepare_height(state.height.saturating_add(1))?;
        Ok(BlockDelta {
            validator_lifecycle: (Some(&lifecycle) != state.validator_lifecycle.as_ref())
                .then_some(lifecycle),
            ..Default::default()
        })
    }

    fn plan_block(
        &self,
        state: &AppState,
        txs: &[Bytes],
        timestamp_ms: u64,
    ) -> Result<(BlockDelta, Vec<ExecTxResult>, NativeBlockExecutionV0)> {
        let mut delta = self.start_block_delta(state)?;
        let mut tx_results = Vec::with_capacity(txs.len());
        let mut native_receipts = Vec::with_capacity(txs.len());
        for tx in txs {
            let applied = self.apply_tx(state, &mut delta, tx, timestamp_ms)?;
            tx_results.push(applied.tx_result);
            native_receipts.push(applied.native_receipt);
        }
        let native_execution = NativeBlockExecutionV0::try_new(txs, native_receipts)?;
        Ok((delta, tx_results, native_execution))
    }

    fn production_poco_projection_at(
        &self,
        version: u64,
    ) -> Result<AuthenticatedPocoProjectionAtV0> {
        self.maybe_production_poco_projection_at(version)?
            .context("PoCO authority requires an active production namespace")
    }

    fn maybe_production_poco_projection_at(
        &self,
        version: u64,
    ) -> Result<Option<AuthenticatedPocoProjectionAtV0>> {
        let state_root: [u8; 32] = if let Some(store) = &self.core.store {
            store.authenticated_root_at(version)?.into()
        } else {
            self.core
                .auth_tree
                .lock()
                .map_err(|_| anyhow!("authenticated state tree lock poisoned"))?
                .root_hash(version)
                .with_context(|| format!("missing authenticated root at version {version}"))?
                .into()
        };
        let cache_key = (version, state_root);
        if let Some(cached) = self
            .core
            .poco_projection_cache
            .lock()
            .map_err(|_| anyhow!("PoCO projection cache lock poisoned"))?
            .get(&cache_key)
            .cloned()
        {
            return Ok(Some(cached));
        }

        let Some(authenticated) = maybe_authenticated_poco_projection_at_v0(
            self.core.store.as_ref(),
            &self.core.auth_tree,
            version,
        )?
        else {
            return Ok(None);
        };
        ensure!(
            authenticated.state_root() == state_root,
            "authenticated PoCO root changed during projection load"
        );
        let mut cache = self
            .core
            .poco_projection_cache
            .lock()
            .map_err(|_| anyhow!("PoCO projection cache lock poisoned"))?;
        cache.insert(cache_key, authenticated.clone());
        while cache.len() > MAX_AUTHENTICATED_POCO_PROJECTION_CACHE_ENTRIES {
            let oldest = *cache.keys().next().expect("nonempty bounded cache");
            cache.remove(&oldest);
        }
        Ok(Some(authenticated))
    }

    fn validated_live_poco_configuration(
        &self,
        state: &AppState,
        delta: &BlockDelta,
    ) -> Result<
        Option<(
            AuthenticatedPocoProjectionAtV0,
            trnm_consensus_types::ValidatorSet,
            trnm_consensus_types::ConsensusParametersV0,
        )>,
    > {
        let Some(projection) = self.maybe_production_poco_projection_at(state.height)? else {
            return Ok(None);
        };
        ensure!(
            projection.version() == state.height && projection.state_root() == state.app_hash,
            "authenticated PoCO projection differs from committed application head"
        );
        let authority = self
            .core
            .config
            .poco_authority
            .as_ref()
            .context("active PoCO projection lacks configured authority")?;
        authority.validate()?;
        let (validator_set, parameters) = active_consensus_configuration(projection.projection())?;
        validate_poco_parameter_retention_v0(&parameters)?;
        let configured_chain =
            trnm_consensus_types::ChainId::from_bytes(self.core.config.chain_id.as_bytes())
                .map_err(|error| anyhow!("invalid configured PoCO chain ID: {error:?}"))?;
        let configured_genesis = trnm_consensus_types::GenesisHash::new(
            trnm_finality_types::decode_hash32("PoCO genesis hash", &authority.genesis_hash_hex)?,
        );
        let configured_profile = trnm_finality_types::decode_hash32(
            "PoCO protocol profile hash",
            &authority.protocol_profile_hash_hex,
        )?;
        ensure!(
            validator_set.chain_id() == configured_chain
                && validator_set.genesis_hash() == configured_genesis
                && validator_set.consensus_parameters_hash() == parameters.hash()
                && *parameters.hash().as_bytes() == configured_profile,
            "live PoCO configuration differs from configured chain/genesis/profile"
        );
        validator_set
            .validate_against_parameters(&parameters)
            .map_err(|error| anyhow!("invalid live PoCO configuration: {error:?}"))?;
        validate_application_validator_projection(
            &validator_set,
            &effective_validator_lifecycle(state, delta)?.active_validators,
        )?;
        Ok(Some((projection, validator_set, parameters)))
    }

    fn start_poco_application_overlay(
        &self,
        state: &AppState,
        delta: &BlockDelta,
    ) -> Result<PocoApplicationBlockOverlayV0> {
        let (projection, validator_set, parameters) = self
            .validated_live_poco_configuration(state, delta)?
            .context("PoCO application operation requires genesis-activated authority")?;
        let context = AuthenticatedPocoApplicationContextV0::new(
            state.height,
            state.app_hash,
            trnm_consensus_types::Height::new(
                state
                    .height
                    .checked_add(1)
                    .context("PoCO application target height overflow")?,
            ),
            validator_set.chain_id(),
            validator_set.genesis_hash(),
            validator_set.epoch(),
            parameters,
            poco_application_governance_signer_commitment_v0(effective_validator_lifecycle(
                state, delta,
            )?),
        )?;
        PocoApplicationBlockOverlayV0::from_projection(context, projection.projection())
    }

    fn poco_schedule_for_state(
        &self,
        state: &AppState,
        delta: &BlockDelta,
    ) -> Result<PocoScheduleCacheV0> {
        if let Some(cached) = *self
            .core
            .poco_schedule_cache
            .lock()
            .map_err(|_| anyhow!("PoCO schedule cache lock poisoned"))?
        {
            return Ok(cached);
        }
        let schedule = if let Some((_, validator_set, parameters)) =
            self.validated_live_poco_configuration(state, delta)?
        {
            let geometry =
                trnm_consensus_types::EpochGeometryV0::new(validator_set.epoch(), &parameters)
                    .map_err(|error| anyhow!("invalid live PoCO epoch geometry: {error:?}"))?;
            let checkpoint_height = geometry.checkpoint_height().get();
            let cutoff_height = checkpoint_height
                .checked_sub(parameters.snapshot_lead_blocks())
                .context("PoCO snapshot cutoff height underflow")?;
            PocoScheduleCacheV0::Active {
                cutoff_height,
                checkpoint_height,
            }
        } else {
            PocoScheduleCacheV0::Inactive
        };
        *self
            .core
            .poco_schedule_cache
            .lock()
            .map_err(|_| anyhow!("PoCO schedule cache lock poisoned"))? = Some(schedule);
        Ok(schedule)
    }

    fn clear_poco_runtime_caches(&self) -> Result<()> {
        self.core
            .poco_projection_cache
            .lock()
            .map_err(|_| anyhow!("PoCO projection cache lock poisoned"))?
            .clear();
        *self
            .core
            .poco_schedule_cache
            .lock()
            .map_err(|_| anyhow!("PoCO schedule cache lock poisoned"))? = None;
        Ok(())
    }

    fn authorize_checkpoint_execution_if_due(
        &self,
        state: &AppState,
        delta: &BlockDelta,
        block: CheckpointBlockExecutionInput<'_>,
    ) -> Result<Option<AuthenticatedPocoCandidateSelectionV0>> {
        let native_execution = block.native_execution.execution();
        ensure!(
            native_execution.application_payload().transactions().len() == block.txs.len()
                && native_execution
                    .application_payload()
                    .transactions()
                    .iter()
                    .zip(block.txs)
                    .all(|(native, transport)| native.as_slice() == transport.as_ref()),
            "native application payload differs from exact ABCI transaction bytes"
        );
        ensure!(
            native_execution.execution_receipts().receipts().len() == block.tx_results.len(),
            "native execution receipts differ from ABCI transaction count"
        );
        let next_height = state
            .height
            .checked_add(1)
            .context("PoCO checkpoint height overflow")?;
        ensure!(
            block.native_execution.parent_height().get() == state.height
                && block.native_execution.parent_state_root().as_bytes() == &state.app_hash
                && block.native_execution.target_height().get() == next_height
                && block.native_execution.post_state_root().as_bytes() == &block.next_state_root,
            "authorized native execution differs from committed checkpoint state transition"
        );
        let Some(authority) = self.core.config.poco_authority.as_ref() else {
            return Ok(None);
        };
        let Some(current_projection) = self.maybe_production_poco_projection_at(state.height)?
        else {
            // Configured authority with an explicitly empty namespace is the
            // supported legacy/inert state. It has no PoCO schedule and must
            // continue processing ordinary blocks without inventing a
            // checkpoint obligation.
            return Ok(None);
        };
        let (old_set, active_parameters) =
            active_consensus_configuration(current_projection.projection())?;
        let geometry =
            trnm_consensus_types::EpochGeometryV0::new(old_set.epoch(), &active_parameters)
                .map_err(|error| anyhow!("invalid active PoCO epoch geometry: {error:?}"))?;
        if geometry.checkpoint_height().get() != next_height {
            return Ok(None);
        }
        ensure!(
            state.height > 0,
            "PoCO checkpoint authority requires an initialized parent state"
        );
        let cutoff_height = next_height
            .checked_sub(active_parameters.snapshot_lead_blocks())
            .context("PoCO snapshot cutoff height underflow")?;
        let cutoff_projection = self.production_poco_projection_at(cutoff_height)?;
        ensure!(
            cutoff_projection.projection() == current_projection.projection(),
            "PoCO projection changed after the scheduled snapshot cutoff"
        );
        let lifecycle = effective_validator_lifecycle(state, delta)?;
        let capability = authorize_poco_checkpoint_candidate_selection_v0(
            authority,
            PocoCheckpointExecutionInputV0 {
                chain_id: &self.core.config.chain_id,
                parent_height: state.height,
                parent_state_root: state.app_hash,
                block_height: next_height,
                block_hash: block.block_hash,
                timestamp_ms: block.timestamp_ms,
                txs: block.txs,
                tx_results: block.tx_results,
                next_state_root: block.next_state_root,
            },
            &cutoff_projection,
            &lifecycle.active_validators,
        )?;
        Ok(Some(capability))
    }

    fn execute_block(
        &self,
        state: &AppState,
        txs: &[Bytes],
        timestamp_ms: u64,
        block_hash: &[u8],
    ) -> Result<PendingBlock> {
        let (mut delta, tx_results, native_execution) =
            self.plan_block(state, txs, timestamp_ms)?;
        let next_height = state
            .height
            .checked_add(1)
            .context("application height overflow")?;
        let mut writes = authenticated_writes_for_delta(next_height, &delta)?;
        if let Some(overlay) = delta.poco_application.take() {
            ensure!(
                overlay.source_version() == state.height
                    && overlay.source_root() == state.app_hash
                    && overlay.target_height().get() == next_height,
                "PoCO block overlay is not bound to the committed source/target"
            );
            let sealed = overlay.seal()?;
            ensure!(
                sealed.source_version() == state.height
                    && sealed.source_root() == state.app_hash
                    && sealed.target_height().get() == next_height,
                "sealed PoCO plan is not bound to the committed source/target"
            );
            writes.extend(auth_writes_from_sealed_poco_application_v0(&sealed)?);
        } else if let PocoScheduleCacheV0::Active {
            cutoff_height,
            checkpoint_height,
        } = self.poco_schedule_for_state(state, &delta)?
        {
            ensure!(
                cutoff_height < checkpoint_height,
                "invalid cached PoCO cutoff/checkpoint schedule"
            );
            if next_height == cutoff_height {
                let (projection, _, _) = self
                    .validated_live_poco_configuration(state, &delta)?
                    .context("scheduled PoCO cutoff lacks active projection")?;
                writes.push(scheduled_cutoff_manifest_refresh_write_v0(
                    trnm_consensus_types::Height::new(next_height),
                    projection.projection(),
                )?);
            }
        }
        let auth_update = if let Some(store) = &self.core.store {
            store.plan_auth_update(next_height, writes)?
        } else {
            self.core
                .auth_tree
                .lock()
                .map_err(|_| anyhow!("authenticated state tree lock poisoned"))?
                .plan_put_value_set(next_height, writes)?
        };
        let app_hash = auth_update.root_hash.into();
        let native_execution = authorize_native_checkpoint_execution_v0(
            native_execution,
            trnm_consensus_types::Height::new(state.height),
            trnm_consensus_types::StateRoot::new(state.app_hash),
            trnm_consensus_types::Height::new(next_height),
            trnm_consensus_types::StateRoot::new(app_hash),
        )?;
        let poco_checkpoint_execution = self.authorize_checkpoint_execution_if_due(
            state,
            &delta,
            CheckpointBlockExecutionInput {
                txs,
                tx_results: &tx_results,
                native_execution: &native_execution,
                timestamp_ms,
                block_hash,
                next_state_root: app_hash,
            },
        )?;
        let validator_updates = effective_validator_lifecycle(state, &delta)?
            .updates_due_at_finalize_height(next_height)?;
        Ok(PendingBlock {
            height: next_height,
            app_hash,
            tx_results,
            native_execution,
            validator_updates,
            delta,
            auth_update,
            poco_checkpoint_execution,
        })
    }

    fn apply_tx(
        &self,
        state: &AppState,
        delta: &mut BlockDelta,
        tx: &[u8],
        timestamp_ms: u64,
    ) -> Result<AppliedTransactionV0> {
        let envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(tx).context("decode signed command envelope")?;
        self.validate_envelope(&envelope, timestamp_ms)?;
        let payload = envelope.payload_bytes()?;
        if envelope.payload_type == POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0 {
            let lifecycle = effective_validator_lifecycle(state, delta)?;
            ensure!(
                envelope.signer_role == "operator"
                    && envelope.signer_id == lifecycle.governance.signer_id,
                "PoCO application operation requires the AppHash-authenticated governance signer"
            );
            if delta.poco_application.is_none() {
                delta.poco_application = Some(self.start_poco_application_overlay(state, delta)?);
            }
            delta
                .poco_application
                .as_mut()
                .expect("PoCO overlay initialized above")
                .apply_raw(&payload)?;
            return Ok(AppliedTransactionV0 {
                tx_result: ExecTxResult::default(),
                native_receipt: NativeTransactionReceiptFactsV0::internal_operation(),
            });
        }
        if envelope.payload_type == VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1 {
            let transition: ValidatorSetTransitionV1 =
                serde_json::from_slice(&payload).context("decode validator set transition")?;
            let mut lifecycle = effective_validator_lifecycle(state, delta)?.clone();
            lifecycle.schedule(
                transition,
                ValidatorTransitionAuthorization {
                    command_id: &envelope.command_id,
                    signer_id: &envelope.signer_id,
                    signer_role: &envelope.signer_role,
                    nonce: envelope.nonce,
                    chain_id: &self.core.config.chain_id,
                    accepted_height: state.height.saturating_add(1),
                },
            )?;
            delta.validator_lifecycle = Some(lifecycle);
            return Ok(AppliedTransactionV0 {
                tx_result: ExecTxResult::default(),
                native_receipt: NativeTransactionReceiptFactsV0::internal_operation(),
            });
        }
        let (mutations, tx_result, native_receipt) = if envelope.payload_type
            == CANONICAL_TX_PAYLOAD_TYPE_V1
        {
            let tx: CanonicalTxV1 =
                serde_json::from_slice(&payload).context("decode canonical transaction")?;
            ensure!(
                envelope.signer_id == tx.sender,
                "canonical transaction sender must equal envelope signer"
            );
            ensure!(
                envelope.nonce == tx.nonce,
                "canonical transaction nonce must equal envelope nonce"
            );
            let objects = OverlayObjects {
                base: &state.objects,
                changes: &delta.objects,
                store: self.core.store.as_ref(),
            };
            let receipt = trnm_runtime::execute(
                &tx,
                ExecutionContext {
                    height: state.height.saturating_add(1),
                    signer_id: &envelope.signer_id,
                    signer_role: &envelope.signer_role,
                    payload_len: payload.len(),
                },
                &objects,
            )?;
            let native_receipt =
                NativeTransactionReceiptFactsV0::try_from_runtime_receipt(&receipt)?;
            let trnm_runtime::RuntimeReceipt {
                gas_used,
                events,
                mutations,
                ..
            } = receipt;
            let tx_result = ExecTxResult {
                gas_wanted: i64::try_from(tx.max_gas).unwrap_or(i64::MAX),
                gas_used: i64::try_from(gas_used).unwrap_or(i64::MAX),
                events: events
                    .into_iter()
                    .map(|event| Event {
                        r#type: event.kind,
                        attributes: event
                            .attributes
                            .into_iter()
                            .map(|(key, value)| EventAttribute {
                                key,
                                value,
                                index: true,
                            })
                            .collect(),
                    })
                    .collect(),
                ..Default::default()
            };
            (
                mutations
                    .into_iter()
                    .map(|mutation| ObjectMutation {
                        object_key_hex: mutation.object_key_hex,
                        object_type: mutation.object_type,
                        expected_version: mutation.expected_version,
                        next_version: mutation.next_version,
                        value_bytes: mutation.value_bytes,
                    })
                    .collect::<Vec<_>>(),
                tx_result,
                native_receipt,
            )
        } else {
            #[cfg(test)]
            {
                if envelope.payload_type == "opaque_fixture_v1" {
                    let persisted_command = self
                        .core
                        .store
                        .as_ref()
                        .map(|store| store.contains_command_id(&envelope.command_id))
                        .transpose()?
                        .unwrap_or(false);
                    ensure!(
                        !persisted_command
                            && !state.command_ids.contains(&envelope.command_id)
                            && delta.command_ids.insert(envelope.command_id.clone()),
                        "command_id replay rejected"
                    );
                    let signer_nonce = (envelope.signer_id.clone(), envelope.nonce);
                    let persisted_nonce = self
                        .core
                        .store
                        .as_ref()
                        .map(|store| store.contains_signer_nonce(&signer_nonce.0, signer_nonce.1))
                        .transpose()?
                        .unwrap_or(false);
                    ensure!(
                        !persisted_nonce
                            && !state.signer_nonces.contains(&signer_nonce)
                            && delta.signer_nonces.insert(signer_nonce),
                        "signer nonce replay rejected"
                    );
                    let objects = OverlayObjects {
                        base: &state.objects,
                        changes: &delta.objects,
                        store: self.core.store.as_ref(),
                    };
                    (
                        self.core
                            .interpreter
                            .prepare_execution(&envelope, &objects)?
                            .mutations,
                        ExecTxResult::default(),
                        NativeTransactionReceiptFactsV0::internal_operation(),
                    )
                } else {
                    return Err(anyhow!("unsupported payload_type"));
                }
            }
            #[cfg(not(test))]
            {
                return Err(anyhow!("unsupported payload_type"));
            }
        };
        for mutation in mutations {
            ensure!(
                mutation.object_key_hex != poco_authority_object_key(),
                "PoCO authority object is genesis-only and immutable"
            );
            let persisted_version = self
                .core
                .store
                .as_ref()
                .map(|store| store.load_object(&mutation.object_key_hex))
                .transpose()?
                .flatten()
                .map(|object| object.version);
            let current_version = delta
                .objects
                .get(&mutation.object_key_hex)
                .or_else(|| state.objects.get(&mutation.object_key_hex))
                .map(|object| object.version)
                .or(persisted_version);
            ensure!(
                current_version == mutation.expected_version,
                "object version precondition mismatch"
            );
            let stored = mutation.into_stored();
            delta.objects.insert(stored.object_key_hex.clone(), stored);
        }
        Ok(AppliedTransactionV0 {
            tx_result,
            native_receipt,
        })
    }

    fn validate_genesis(&self, request: &RequestInitChain) -> Result<ValidatedGenesisV2> {
        ensure!(
            request.chain_id == self.core.config.chain_id,
            "genesis chain_id mismatch"
        );
        ensure!(
            !request.app_state_bytes.is_empty(),
            "genesis app_state must not be empty"
        );
        let genesis: GenesisAppStateV2 =
            serde_json::from_slice(&request.app_state_bytes).context("decode genesis app_state")?;
        ensure!(
            genesis.schema == GENESIS_SCHEMA_V2,
            "unsupported genesis schema"
        );
        ensure!(
            genesis.chain_id == self.core.config.chain_id,
            "genesis app_state chain_id mismatch"
        );
        ensure!(
            genesis.app_version == APP_VERSION,
            "unsupported genesis app version"
        );
        ensure!(
            request
                .consensus_params
                .as_ref()
                .and_then(|params| params.version.as_ref())
                .is_some_and(|version| version.app == APP_VERSION),
            "genesis consensus params app version mismatch"
        );
        ensure!(
            canonical_signers(&genesis.authorized_signers)
                == canonical_signers(&self.core.config.authorized_signers),
            "genesis authorized signers do not match application config"
        );
        ensure!(
            genesis.poco_authority == self.core.config.poco_authority,
            "genesis PoCO authority does not match application config"
        );
        genesis.validator_governance.validate()?;
        let request_validators = validators_from_abci(&request.validators)?;
        ensure!(
            request_validators == genesis.initial_validators,
            "genesis app_state validators do not match CometBFT validators"
        );
        let lifecycle = ValidatorLifecycleStateV1::from_genesis(
            self.core.config.chain_id.clone(),
            APP_VERSION,
            hex::encode(signer_policy_commitment(
                &self.core.config.authorized_signers,
            )),
            genesis.validator_governance,
            request_validators,
        )?;
        validate_lifecycle_authorization(&self.core.config, &lifecycle)?;
        let poco_entries = validate_poco_genesis_entries_v0(
            &genesis.poco_genesis_entries,
            genesis.poco_authority.as_ref(),
            &self.core.config.chain_id,
            &lifecycle.active_validators,
        )?;
        Ok(ValidatedGenesisV2 {
            lifecycle,
            poco_entries,
        })
    }

    fn retain_snapshot(&self, state: &AppState) -> Result<()> {
        let disk_path = snapshot_path(&self.core.config, state.height);
        if disk_path.is_some() && !state.height.is_multiple_of(DISK_SNAPSHOT_INTERVAL) {
            return Ok(());
        }
        let retained = if self.core.config.state_path.is_some() {
            RETAINED_DISK_SNAPSHOTS
        } else {
            RETAINED_SNAPSHOTS
        };
        if let Some(disk_path) = disk_path {
            if self
                .core
                .snapshots
                .lock()
                .map_err(|_| anyhow!("snapshot store lock poisoned"))?
                .contains_key(&state.height)
            {
                return Ok(());
            }
            let store = self
                .core
                .store
                .clone()
                .context("disk snapshot requires persistent application store")?;
            let mut building = self
                .core
                .snapshot_building
                .lock()
                .map_err(|_| anyhow!("snapshot worker lock poisoned"))?;
            if building.active == Some(state.height) {
                return Ok(());
            }
            if building.active.is_some() {
                building.catch_up_requested = true;
                return Ok(());
            }
            let pinned = store.pin_snapshot(state)?;
            building.active = Some(state.height);
            drop(building);
            let core = Arc::clone(&self.core);
            let chain_id = self.core.config.chain_id.clone();
            let state = state.clone();
            let spawn = std::thread::Builder::new()
                .name(format!("trnm-snapshot-{}", state.height))
                .spawn(move || {
                    run_disk_snapshot_worker(
                        core,
                        store,
                        chain_id,
                        PendingDiskSnapshot {
                            state,
                            disk_path,
                            pinned,
                        },
                        retained,
                    );
                });
            if let Err(error) = spawn {
                let mut building = self
                    .core
                    .snapshot_building
                    .lock()
                    .map_err(|_| anyhow!("snapshot worker lock poisoned"))?;
                building.active = None;
                building.catch_up_requested = false;
                return Err(error).context("spawn asynchronous snapshot worker");
            }
            return Ok(());
        }
        let auth_tree = self
            .core
            .auth_tree
            .lock()
            .map_err(|_| anyhow!("authenticated state tree lock poisoned"))?
            .clone();
        let record = build_snapshot(&self.core.config.chain_id, state, &auth_tree, None)?;
        install_snapshot_record(&self.core.snapshots, state.height, record, retained)
    }

    fn maybe_prune_authenticated_history(&self, state: &AppState) -> Result<()> {
        if self.core.store.is_some() {
            if state.height > AUTH_PROOF_RETENTION_VERSIONS
                && state.height.is_multiple_of(AUTH_PRUNE_INTERVAL)
            {
                self.wake_authenticated_prune_worker()?;
            }
            return Ok(());
        }
        if state.height <= AUTH_PROOF_RETENTION_VERSIONS
            || !state.height.is_multiple_of(AUTH_PRUNE_INTERVAL)
        {
            return Ok(());
        }
        let retain_from = state
            .height
            .saturating_sub(AUTH_PROOF_RETENTION_VERSIONS)
            .saturating_add(1);
        let mut pruned = self
            .core
            .auth_tree
            .lock()
            .map_err(|_| anyhow!("authenticated state tree lock poisoned"))?
            .clone();
        pruned.prune_versions_before(retain_from)?;
        ensure!(
            pruned.root_hash(state.height).map(Into::<[u8; 32]>::into) == Some(state.app_hash),
            "authenticated pruning changed the committed AppHash"
        );
        *self
            .core
            .auth_tree
            .lock()
            .map_err(|_| anyhow!("authenticated state tree lock poisoned"))? = pruned;
        Ok(())
    }

    fn wake_authenticated_prune_worker(&self) -> Result<()> {
        if self.core.store.is_none() {
            return Ok(());
        }
        let mut worker = self
            .core
            .auth_prune_worker
            .lock()
            .map_err(|_| anyhow!("authenticated prune worker lock poisoned"))?;
        if worker.active {
            worker.wake_requested = true;
            return Ok(());
        }
        worker.active = true;
        worker.wake_requested = false;
        let core = Arc::clone(&self.core);
        let spawn = std::thread::Builder::new()
            .name("trnm-auth-prune".to_string())
            .spawn(move || run_authenticated_prune_worker(core));
        if let Err(error) = spawn {
            worker.active = false;
            return Err(error).context("spawn authenticated prune worker");
        }
        Ok(())
    }

    fn ensure_authenticated_maintenance_healthy(&self) {
        let failure = self
            .core
            .auth_prune_fatal
            .lock()
            .unwrap_or_else(|_| panic!("authenticated maintenance fatal latch poisoned"))
            .clone();
        if let Some(failure) = failure {
            panic!("authenticated maintenance failed closed: {failure}");
        }
    }
}

fn run_disk_snapshot_worker(
    core: Arc<AppCore>,
    store: ApplicationStore,
    chain_id: String,
    mut pending: PendingDiskSnapshot,
    retained: usize,
) {
    loop {
        let height = pending.state.height;
        let result = build_store_snapshot(&store, &chain_id, pending)
            .and_then(|record| install_snapshot_record(&core.snapshots, height, record, retained));
        if let Err(error) = result {
            eprintln!(
                "[trnm-cometbft-app] asynchronous snapshot {} failed: {error:#}",
                height
            );
        }
        let next = (|| -> Result<Option<PendingDiskSnapshot>> {
            let state = core
                .state
                .lock()
                .map_err(|_| anyhow!("application state lock poisoned"))?;
            let mut building = core
                .snapshot_building
                .lock()
                .map_err(|_| anyhow!("snapshot worker queue lock poisoned"))?;
            if !building.catch_up_requested || state.height <= height {
                building.active = None;
                building.catch_up_requested = false;
                return Ok(None);
            }
            building.catch_up_requested = false;
            let disk_path = snapshot_path(&core.config, state.height)
                .context("persistent snapshot catch-up requires a disk path")?;
            let pinned = store.pin_snapshot(&state)?;
            building.active = Some(state.height);
            Ok(Some(PendingDiskSnapshot {
                state: state.clone(),
                disk_path,
                pinned,
            }))
        })();
        let next = match next {
            Ok(next) => next,
            Err(error) => {
                eprintln!(
                    "[trnm-cometbft-app] snapshot worker could not pin catch-up head: {error:#}"
                );
                if let Ok(mut building) = core.snapshot_building.lock() {
                    building.active = None;
                    building.catch_up_requested = false;
                }
                None
            }
        };
        let Some(next) = next else {
            break;
        };
        pending = next;
    }
}

fn run_authenticated_prune_worker(core: Arc<AppCore>) {
    let store = core
        .store
        .clone()
        .expect("authenticated prune worker requires persistent storage");
    loop {
        let batch =
            store.try_prune_auth_batch(AUTH_PRUNE_BATCH_ROWS, AUTH_PRUNE_BATCH_LOGICAL_BYTES);
        match batch {
            Ok(None) => {
                std::thread::sleep(AUTH_PRUNE_RETRY_DELAY);
            }
            Ok(Some(outcome)) if outcome.complete => {
                let mut worker = match core.auth_prune_worker.lock() {
                    Ok(worker) => worker,
                    Err(_) => {
                        record_authenticated_prune_failure(
                            &core,
                            "authenticated prune worker lock poisoned".to_string(),
                        );
                        return;
                    }
                };
                if worker.wake_requested {
                    worker.wake_requested = false;
                    drop(worker);
                    std::thread::yield_now();
                    continue;
                }
                worker.active = false;
                return;
            }
            Ok(Some(outcome)) => {
                if outcome.elapsed > std::time::Duration::from_millis(50) {
                    let removed = outcome
                        .stats
                        .nodes_removed
                        .saturating_add(outcome.stats.value_versions_removed)
                        .saturating_add(outcome.stats.preimages_removed)
                        .saturating_add(outcome.stats.stale_indices_removed)
                        .saturating_add(outcome.stats.roots_removed);
                    eprintln!(
                        "[trnm-cometbft-app] authenticated prune batch exceeded the \
                         50ms engineering guardrail: floor={} target={} rows={} \
                         removed={} bytes={} elapsed_ms={}",
                        outcome.query_floor,
                        outcome.target,
                        outcome.rows_examined,
                        removed,
                        outcome.logical_bytes_examined,
                        outcome.elapsed.as_millis()
                    );
                }
                std::thread::sleep(AUTH_PRUNE_INTER_BATCH_DELAY);
            }
            Err(error) if is_transient_sqlite_contention(&error) => {
                std::thread::sleep(AUTH_PRUNE_RETRY_DELAY);
            }
            Err(error) => {
                record_authenticated_prune_failure(&core, format!("{error:#}"));
                if let Ok(mut worker) = core.auth_prune_worker.lock() {
                    worker.active = false;
                }
                return;
            }
        }
    }
}

fn is_transient_sqlite_contention(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<rusqlite::Error>()
            .is_some_and(|error| {
                matches!(
                    error,
                    rusqlite::Error::SqliteFailure(code, _)
                        if matches!(
                            code.code,
                            rusqlite::ErrorCode::DatabaseBusy
                                | rusqlite::ErrorCode::DatabaseLocked
                        )
                )
            })
    })
}

fn record_authenticated_prune_failure(core: &AppCore, failure: String) {
    eprintln!(
        "[trnm-cometbft-app] authenticated maintenance failed closed; \
         consensus will stop before the next state transition: {failure}"
    );
    if let Ok(mut fatal) = core.auth_prune_fatal.lock() {
        *fatal = Some(failure);
    }
}

fn install_snapshot_record(
    snapshots: &Mutex<BTreeMap<u64, SnapshotRecord>>,
    height: u64,
    record: SnapshotRecord,
    retained: usize,
) -> Result<()> {
    let mut snapshots = snapshots
        .lock()
        .map_err(|_| anyhow!("snapshot store lock poisoned"))?;
    snapshots.insert(height, record);
    while snapshots.len() > retained {
        let oldest = *snapshots
            .keys()
            .next()
            .expect("snapshot store is non-empty");
        if let Some(record) = snapshots.remove(&oldest) {
            record.payload.remove_file()?;
        }
    }
    Ok(())
}

impl Application for CometBftApplication {
    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        let (height, app_hash) = self
            .height_and_app_hash()
            .unwrap_or_else(|error| panic!("read committed state for ABCI Info: {error:#}"));
        ResponseInfo {
            data: "trnm-consensus-app".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            app_version: APP_VERSION,
            last_block_height: height as i64,
            last_block_app_hash: Bytes::copy_from_slice(&app_hash),
        }
    }

    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        let validated = self
            .validate_genesis(&request)
            .unwrap_or_else(|error| panic!("refuse incompatible CometBFT genesis: {error:#}"));
        let lifecycle = validated.lifecycle;
        let genesis_poco_entries = validated.poco_entries;
        let validators = validators_to_abci(&lifecycle.active_validators)
            .expect("validated genesis validators convert to ABCI");
        let mut state = self
            .core
            .state
            .lock()
            .unwrap_or_else(|_| panic!("state lock poisoned during InitChain"));
        assert_eq!(
            state.height, 0,
            "InitChain cannot replace committed application state"
        );
        match state.validator_lifecycle.as_ref() {
            Some(existing) => {
                assert_eq!(
                    existing, &lifecycle,
                    "repeated InitChain validator lifecycle mismatch"
                );
                let fee_policy = default_fee_policy_object();
                let committed_fee_policy = state
                    .objects
                    .get(&fee_policy.object_key_hex)
                    .cloned()
                    .or_else(|| {
                        self.core.store.as_ref().and_then(|store| {
                            store
                                .load_object(&fee_policy.object_key_hex)
                                .unwrap_or_else(|error| {
                                    panic!("load repeated genesis fee policy: {error:#}")
                                })
                        })
                    });
                assert_eq!(
                    committed_fee_policy.as_ref(),
                    Some(&fee_policy),
                    "repeated InitChain fee policy mismatch"
                );
                let expected_authority = self
                    .core
                    .config
                    .poco_authority
                    .as_ref()
                    .map(poco_authority_object);
                let authority_key = poco_authority_object_key();
                let committed_authority =
                    state.objects.get(&authority_key).cloned().or_else(|| {
                        self.core.store.as_ref().and_then(|store| {
                            store.load_object(&authority_key).unwrap_or_else(|error| {
                                panic!("load repeated genesis PoCO authority: {error:#}")
                            })
                        })
                    });
                assert_eq!(
                    committed_authority, expected_authority,
                    "repeated InitChain PoCO authority mismatch"
                );
                let committed_poco = if let Some(store) = &self.core.store {
                    store
                        .production_poco_projection(0)
                        .unwrap_or_else(|error| panic!("load repeated PoCO genesis: {error:#}"))
                        .1
                } else {
                    let tree = self
                        .core
                        .auth_tree
                        .lock()
                        .unwrap_or_else(|_| panic!("authenticated state tree lock poisoned"));
                    let mut live = tree
                        .verified_live_values(0)
                        .unwrap_or_else(|error| panic!("load repeated PoCO genesis: {error:#}"));
                    take_and_validate_production_poco_projection_v0(0, &mut live)
                        .unwrap_or_else(|error| panic!("validate repeated PoCO genesis: {error:#}"))
                };
                assert_eq!(
                    committed_poco
                        .as_ref()
                        .map(|projection| projection.entries()),
                    (!genesis_poco_entries.is_empty()).then_some(genesis_poco_entries.as_slice()),
                    "repeated InitChain PoCO genesis projection mismatch"
                );
                let auth_key = stored_object_key(&fee_policy.object_key_hex)
                    .expect("genesis fee policy has an authenticated key");
                let proof = if let Some(store) = &self.core.store {
                    store
                        .prove(0, auth_key)
                        .unwrap_or_else(|error| panic!("prove repeated genesis state: {error:#}"))
                } else {
                    self.core
                        .auth_tree
                        .lock()
                        .unwrap_or_else(|_| panic!("authenticated state tree lock poisoned"))
                        .prove(0, auth_key)
                        .expect("prove repeated genesis state")
                };
                assert_eq!(
                    <[u8; 32]>::from(proof.root_hash),
                    state.app_hash,
                    "repeated InitChain authenticated root mismatch"
                );
            }
            None => {
                let mut initialized = state.clone();
                initialized.validator_lifecycle = Some(lifecycle);
                let fee_policy = default_fee_policy_object();
                match initialized.objects.get(&fee_policy.object_key_hex) {
                    Some(existing) => {
                        assert_eq!(existing, &fee_policy, "genesis fee policy object mismatch")
                    }
                    None => {
                        initialized
                            .objects
                            .insert(fee_policy.object_key_hex.clone(), fee_policy);
                    }
                }
                if let Some(authority) = self.core.config.poco_authority.as_ref() {
                    let authority = poco_authority_object(authority);
                    match initialized.objects.get(&authority.object_key_hex) {
                        Some(existing) => assert_eq!(
                            existing, &authority,
                            "genesis PoCO authority object mismatch"
                        ),
                        None => {
                            initialized
                                .objects
                                .insert(authority.object_key_hex.clone(), authority);
                        }
                    }
                }
                let mut writes = authenticated_writes_for_state(0, &initialized)
                    .expect("validated genesis state converts to authenticated writes");
                writes.extend(
                    genesis_poco_snapshot_writes_v0(&genesis_poco_entries)
                        .expect("validated PoCO genesis projection converts to sealed writes"),
                );
                let auth_update = if let Some(store) = &self.core.store {
                    store
                        .plan_auth_update(0, writes)
                        .expect("validated genesis state produces persisted AppHash v4")
                } else {
                    self.core
                        .auth_tree
                        .lock()
                        .unwrap_or_else(|_| panic!("authenticated state tree lock poisoned"))
                        .plan_put_value_set(0, writes)
                        .expect("validated genesis state produces AppHash v4")
                };
                initialized.app_hash = auth_update.root_hash.into();
                if let Some(store) = &self.core.store {
                    store
                        .replace_empty_state(&state, &initialized, &auth_update)
                        .unwrap_or_else(|error| {
                            panic!("persist initialized validator lifecycle: {error:#}")
                        });
                    initialized.objects.clear();
                    initialized.command_ids.clear();
                    initialized.signer_nonces.clear();
                } else {
                    self.core
                        .auth_tree
                        .lock()
                        .unwrap_or_else(|_| panic!("authenticated state tree lock poisoned"))
                        .apply(auth_update)
                        .expect("apply genesis authenticated state");
                }
                *state = initialized;
            }
        }
        let app_hash = state.app_hash;
        ResponseInitChain {
            consensus_params: request.consensus_params,
            validators,
            app_hash: Bytes::copy_from_slice(&app_hash),
        }
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        let state = match self.core.state.lock() {
            Ok(state) => state,
            Err(_) => return check_tx_error("state lock poisoned"),
        };
        match self.plan_block(&state, &[request.tx], now_unix_ms()) {
            Ok((_, tx_results, _)) => {
                let Some(result) = tx_results.into_iter().next() else {
                    return check_tx_error("transaction planning returned no result");
                };
                ResponseCheckTx {
                    code: result.code,
                    data: result.data,
                    log: result.log,
                    info: result.info,
                    gas_wanted: result.gas_wanted,
                    gas_used: result.gas_used,
                    events: result.events,
                    codespace: result.codespace,
                }
            }
            Err(error) => check_tx_error(&format!("{error:#}")),
        }
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        let state = match self.core.state.lock() {
            Ok(state) => state,
            Err(_) => return query_error("state lock poisoned"),
        };
        let query_height = if request.height == 0 {
            state.height
        } else if request.height > 0 {
            request.height as u64
        } else {
            return query_error("query height must not be negative");
        };
        if query_height > state.height {
            return query_error("query height is ahead of committed state");
        }
        if request.path == "/simulate" {
            if request.prove {
                return query_error("simulation query does not support proofs");
            }
            if query_height != state.height {
                return query_error("simulation is available only at the latest committed height");
            }
            let simulation = self.simulate_canonical_tx(&state, &request.data);
            let value = match serde_json::to_vec(&simulation) {
                Ok(value) => value,
                Err(error) => {
                    return query_error(&format!("encode simulation response: {error}"));
                }
            };
            return ResponseQuery {
                code: 0,
                key: Bytes::from_static(b"/simulate"),
                value: Bytes::from(value),
                height: query_height as i64,
                log: SIMULATION_RESPONSE_SCHEMA_V1.to_string(),
                ..Default::default()
            };
        }
        let key = match query_object_key(&request.path) {
            Ok(key) => key,
            Err(error) => return query_error(&format!("{error:#}")),
        };
        if request.prove {
            let auth_key = match stored_object_key(&key) {
                Ok(key) => key,
                Err(error) => return query_error(&format!("{error:#}")),
            };
            let proof = match if let Some(store) = &self.core.store {
                store.prove(query_height, auth_key.clone())
            } else {
                self.core
                    .auth_tree
                    .lock()
                    .map_err(|_| anyhow!("authenticated state tree lock poisoned"))
                    .and_then(|tree| tree.prove(query_height, auth_key.clone()))
            } {
                Ok(proof) => proof,
                Err(error) => return query_error(&format!("{error:#}")),
            };
            let proof_is_valid = match proof.value.as_deref() {
                Some(value) => auth_tree::verify_ics23_membership(&proof, value),
                None => auth_tree::verify_ics23_non_membership(&proof),
            };
            if !proof_is_valid {
                return query_error("generated authenticated-state proof failed self-verification");
            }
            let log = proof
                .value
                .as_deref()
                .and_then(|value| AuthenticatedObjectRecord::decode(value).ok())
                .map(|record| record.object_type)
                .unwrap_or_else(|| "object not found".to_string());
            return ResponseQuery {
                code: 0,
                key: Bytes::from(auth_key.clone()),
                value: proof.value.clone().map(Bytes::from).unwrap_or_default(),
                proof_ops: Some(ProofOps {
                    ops: vec![ProofOp {
                        r#type: "ics23:jmt:v1".to_string(),
                        key: auth_key,
                        data: proof.encoded_commitment_proof(),
                    }],
                }),
                height: proof.version as i64,
                log,
                ..Default::default()
            };
        }
        if query_height != state.height {
            return query_error("historical query height is unavailable");
        }
        let object = match state.objects.get(&key).cloned() {
            Some(object) => Some(object),
            None => match self.core.store.as_ref() {
                Some(store) => match store.load_object(&key) {
                    Ok(object) => object,
                    Err(error) => return query_error(&format!("{error:#}")),
                },
                None => None,
            },
        };
        let Some(object) = object else {
            return ResponseQuery {
                code: 1,
                log: "object not found".to_string(),
                height: query_height as i64,
                ..Default::default()
            };
        };
        ResponseQuery {
            code: 0,
            key: Bytes::copy_from_slice(key.as_bytes()),
            value: Bytes::copy_from_slice(&object.value_bytes),
            height: query_height as i64,
            log: object.object_type,
            ..Default::default()
        }
    }

    fn prepare_proposal(&self, request: RequestPrepareProposal) -> ResponsePrepareProposal {
        if request.max_tx_bytes <= 0 {
            return ResponsePrepareProposal::default();
        }
        let state = match self.core.state.lock() {
            Ok(state) if request.height == state.height as i64 + 1 => state,
            _ => return ResponsePrepareProposal::default(),
        };
        let Ok(timestamp_ms) = consensus_timestamp_ms(request.time.as_ref()) else {
            return ResponsePrepareProposal::default();
        };
        let mut delta = match self.start_block_delta(&state) {
            Ok(delta) => delta,
            Err(_) => return ResponsePrepareProposal::default(),
        };
        let mut total_bytes = 0usize;
        let max_bytes = usize::try_from(request.max_tx_bytes).unwrap_or(0);
        let mut txs = Vec::new();
        for tx in request.txs {
            let next_total = total_bytes.saturating_add(tx.len());
            if next_total > max_bytes {
                continue;
            }
            let mut candidate = delta.clone();
            if self
                .apply_tx(&state, &mut candidate, &tx, timestamp_ms)
                .is_err()
            {
                continue;
            }
            if candidate
                .poco_application
                .clone()
                .map(PocoApplicationBlockOverlayV0::seal)
                .transpose()
                .is_err()
            {
                continue;
            }
            delta = candidate;
            total_bytes = next_total;
            txs.push(tx);
        }
        ResponsePrepareProposal { txs }
    }

    fn process_proposal(&self, request: RequestProcessProposal) -> ResponseProcessProposal {
        self.ensure_authenticated_maintenance_healthy();
        self.trigger_test_crash(
            TestCrashStage::ProcessProposal,
            u64::try_from(request.height).unwrap_or(0),
        );
        let accepted = self
            .core
            .state
            .lock()
            .map_err(|_| anyhow!("state lock poisoned"))
            .and_then(|state| {
                ensure!(
                    request.height == state.height as i64 + 1,
                    "proposal height mismatch"
                );
                self.execute_block(
                    &state,
                    &request.txs,
                    consensus_timestamp_ms(request.time.as_ref())?,
                    &request.hash,
                )?;
                Ok(())
            })
            .is_ok();
        ResponseProcessProposal {
            status: if accepted {
                response_process_proposal::ProposalStatus::Accept as i32
            } else {
                response_process_proposal::ProposalStatus::Reject as i32
            },
        }
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        self.ensure_authenticated_maintenance_healthy();
        self.trigger_test_crash(
            TestCrashStage::FinalizeBlock,
            u64::try_from(request.height).unwrap_or(0),
        );
        let mut state = self.core.state.lock().unwrap_or_else(|_| {
            panic!("consensus application state lock poisoned during FinalizeBlock")
        });
        assert_eq!(
            request.height,
            state.height as i64 + 1,
            "refuse non-contiguous FinalizeBlock height"
        );
        let timestamp_ms = consensus_timestamp_ms(request.time.as_ref()).unwrap_or_else(|error| {
            panic!("refuse FinalizeBlock with invalid consensus timestamp: {error:#}")
        });
        let pending = self
            .execute_block(&state, &request.txs, timestamp_ms, &request.hash)
            .unwrap_or_else(|error| {
                panic!(
                    "ProcessProposal accepted a block that FinalizeBlock cannot execute: {error:#}"
                )
            });
        let app_hash = Bytes::copy_from_slice(&pending.app_hash);
        let validator_updates = pending.validator_updates.clone();
        let checkpoint_events = pending
            .poco_checkpoint_execution
            .as_ref()
            .map(|capability| Event {
                r#type: "trnm.poco.checkpoint-execution.v0".to_string(),
                attributes: {
                    let checkpoint = capability.checkpoint_execution();
                    vec![
                        ("execution_id", hex::encode(checkpoint.execution_id())),
                        ("epoch", checkpoint.epoch().get().to_string()),
                        (
                            "checkpoint_height",
                            checkpoint.checkpoint_height().get().to_string(),
                        ),
                        (
                            "cutoff_height",
                            checkpoint.cutoff_height().get().to_string(),
                        ),
                        (
                            "cutoff_state_root",
                            hex::encode(checkpoint.cutoff_state_root().as_bytes()),
                        ),
                        ("payload_root", hex::encode(checkpoint.payload_root())),
                        ("receipts_root", hex::encode(checkpoint.receipts_root())),
                        (
                            "next_state_root",
                            hex::encode(checkpoint.next_state_root().as_bytes()),
                        ),
                        (
                            "manifest_entries_root",
                            hex::encode(checkpoint.cutoff_entries_root()),
                        ),
                        (
                            "manifest_entry_count",
                            checkpoint.cutoff_entry_count().to_string(),
                        ),
                        (
                            "candidate_authorization_id",
                            hex::encode(capability.authorization_id()),
                        ),
                        (
                            "candidate_transcript_digest",
                            hex::encode(capability.transcript_digest()),
                        ),
                        (
                            "candidate_result_digest",
                            hex::encode(capability.result_digest()),
                        ),
                        (
                            "candidate_parameters_hash",
                            hex::encode(capability.candidate_parameters_hash().as_bytes()),
                        ),
                        ("fallback_used", capability.fallback_used().to_string()),
                        (
                            "fallback_reason",
                            u16::from(capability.fallback_reason()).to_string(),
                        ),
                    ]
                    .into_iter()
                    .map(|(key, value)| EventAttribute {
                        key: key.to_string(),
                        value,
                        index: true,
                    })
                    .collect()
                },
            })
            .into_iter()
            .collect();
        state.pending = Some(pending);
        ResponseFinalizeBlock {
            tx_results: state
                .pending
                .as_ref()
                .expect("pending block installed")
                .tx_results
                .clone(),
            validator_updates,
            app_hash,
            events: checkpoint_events,
            ..Default::default()
        }
    }

    fn commit(&self) -> ResponseCommit {
        self.ensure_authenticated_maintenance_healthy();
        let mut state =
            self.core.state.lock().unwrap_or_else(|_| {
                panic!("consensus application state lock poisoned during commit")
            });
        let pending = state
            .pending
            .take()
            .expect("refuse ABCI Commit without a finalized pending block");
        if let Some(store) = &self.core.store {
            store
                .persist_transition(&state, &pending, authenticated_query_floor(pending.height))
                .unwrap_or_else(|error| {
                    panic!("persist committed consensus application state: {error:#}")
                });
        }
        self.trigger_test_crash(TestCrashStage::CommitAfterPersist, pending.height);
        let PendingBlock {
            height,
            app_hash,
            delta,
            auth_update,
            ..
        } = pending;
        if self.core.store.is_none() {
            self.core
                .auth_tree
                .lock()
                .unwrap_or_else(|_| panic!("authenticated state tree lock poisoned during commit"))
                .apply(auth_update)
                .unwrap_or_else(|error| {
                    panic!("apply committed authenticated state tree update: {error:#}")
                });
        }
        state.height = height;
        state.app_hash = app_hash;
        if self.core.store.is_none() {
            for (key, object) in delta.objects {
                state.objects.insert(key, object);
            }
            state.command_ids.extend(delta.command_ids);
            state.signer_nonces.extend(delta.signer_nonces);
        }
        if let Some(lifecycle) = delta.validator_lifecycle {
            state.validator_lifecycle = Some(lifecycle);
        }
        if let Err(error) = self.maybe_prune_authenticated_history(&state) {
            panic!("prune committed authenticated history: {error:#}");
        }
        if let Err(error) = self.retain_snapshot(&state) {
            eprintln!(
                "[trnm-cometbft-app] committed state but failed to retain optional snapshot: {error:#}"
            );
        }
        ResponseCommit::default()
    }

    fn list_snapshots(&self) -> ResponseListSnapshots {
        let snapshots = match self.core.snapshots.lock() {
            Ok(snapshots) => snapshots,
            Err(_) => return ResponseListSnapshots::default(),
        };
        ResponseListSnapshots {
            snapshots: snapshots
                .values()
                .rev()
                .map(|record| record.snapshot.clone())
                .collect(),
        }
    }

    fn offer_snapshot(&self, request: RequestOfferSnapshot) -> ResponseOfferSnapshot {
        let result = (|| -> Result<()> {
            let mut guard = self
                .core
                .snapshot_restore
                .lock()
                .map_err(|_| anyhow!("snapshot restore lock poisoned"))?;
            let restore = self.validate_snapshot_offer(request)?;
            let reuses_files = guard
                .as_ref()
                .is_some_and(|previous| restore.reuses_files_from(previous));
            let previous = guard.replace(restore);
            if let Some(previous) = previous {
                if !reuses_files {
                    previous.cleanup_files();
                }
            }
            let keep = match guard.as_ref() {
                Some(SnapshotRestore::FileV4 {
                    stage_path,
                    journal_path,
                    ..
                }) => Some((stage_path.as_path(), journal_path.as_path())),
                _ => None,
            };
            if let Err(error) = cleanup_snapshot_restore_directory(&self.core.config, keep) {
                if let Some(rejected) = guard.take() {
                    rejected.cleanup_files();
                }
                return Err(error).context("clean snapshot restore staging directory");
            }
            Ok(())
        })()
        .map(|_| response_offer_snapshot::Result::Accept)
        .unwrap_or(response_offer_snapshot::Result::Reject);
        ResponseOfferSnapshot {
            result: result as i32,
        }
    }

    fn load_snapshot_chunk(&self, request: RequestLoadSnapshotChunk) -> ResponseLoadSnapshotChunk {
        let snapshots = match self.core.snapshots.lock() {
            Ok(snapshots) => snapshots,
            Err(_) => return ResponseLoadSnapshotChunk::default(),
        };
        let Some(record) = snapshots.get(&request.height) else {
            return ResponseLoadSnapshotChunk::default();
        };
        if request.format != record.snapshot.format || request.chunk >= record.snapshot.chunks {
            return ResponseLoadSnapshotChunk::default();
        }
        ResponseLoadSnapshotChunk {
            chunk: record.payload.read_chunk(request.chunk).unwrap_or_default(),
        }
    }

    fn apply_snapshot_chunk(
        &self,
        request: RequestApplySnapshotChunk,
    ) -> ResponseApplySnapshotChunk {
        let retry_index = request.index;
        let retry_sender = request.sender.clone();
        match self.apply_snapshot_chunk_inner(request) {
            Ok(()) => snapshot_apply_response(response_apply_snapshot_chunk::Result::Accept),
            Err(error) if error.to_string().contains("retry snapshot chunk") => {
                ResponseApplySnapshotChunk {
                    result: response_apply_snapshot_chunk::Result::Retry as i32,
                    refetch_chunks: vec![retry_index],
                    reject_senders: (!retry_sender.is_empty())
                        .then_some(retry_sender)
                        .into_iter()
                        .collect(),
                }
            }
            Err(_) => {
                if let Ok(mut restore) = self.core.snapshot_restore.lock() {
                    if let Some(rejected) = restore.take() {
                        rejected.cleanup_files();
                    }
                }
                snapshot_apply_response(response_apply_snapshot_chunk::Result::RejectSnapshot)
            }
        }
    }
}

impl CometBftApplication {
    fn validate_snapshot_offer(&self, request: RequestOfferSnapshot) -> Result<SnapshotRestore> {
        let snapshot = request
            .snapshot
            .ok_or_else(|| anyhow!("snapshot offer is missing snapshot metadata"))?;
        match snapshot.format {
            SNAPSHOT_FORMAT_V3 => self.validate_snapshot_offer_v3(snapshot, &request.app_hash),
            SNAPSHOT_FORMAT_V4 => self.validate_snapshot_offer_v4(snapshot, &request.app_hash),
            _ => Err(anyhow!("unsupported snapshot format")),
        }
    }

    fn validate_snapshot_offer_v3(
        &self,
        snapshot: Snapshot,
        trusted_app_hash: &[u8],
    ) -> Result<SnapshotRestore> {
        ensure!(
            snapshot.format == SNAPSHOT_FORMAT_V3,
            "snapshot format changed during validation"
        );
        ensure!(
            self.core.store.is_none(),
            "persistent applications accept only streaming snapshot format 4"
        );
        ensure!(snapshot.hash.len() == 32, "invalid snapshot hash length");
        ensure!(
            !snapshot.metadata.is_empty() && snapshot.metadata.len() <= MAX_SNAPSHOT_METADATA_BYTES,
            "snapshot metadata size is outside bounds"
        );
        let metadata: SnapshotMetadataV3 =
            serde_json::from_slice(&snapshot.metadata).context("decode snapshot metadata")?;
        ensure!(
            metadata.schema == "trnm_cometbft_snapshot_metadata_v3",
            "unsupported snapshot metadata schema"
        );
        ensure!(
            metadata.app_version == APP_VERSION,
            "snapshot app version mismatch"
        );
        ensure!(
            metadata.store_schema == SNAPSHOT_SQLITE_STORE_SCHEMA_V3,
            "snapshot store schema mismatch"
        );
        ensure!(
            metadata.chain_id == self.core.config.chain_id,
            "snapshot chain mismatch"
        );
        ensure!(
            metadata.height == snapshot.height,
            "snapshot height mismatch"
        );
        ensure!(
            metadata.oldest_auth_version <= metadata.height,
            "snapshot authenticated history boundary is invalid"
        );
        ensure!(metadata.height > 0, "genesis snapshot is not restorable");
        ensure!(
            metadata.chunk_size == SNAPSHOT_CHUNK_SIZE as u32,
            "snapshot chunk size mismatch"
        );
        ensure!(
            metadata.state_codec == "json-v4"
                && metadata.auth_tree_codec == "jmt-sha256-v0.12.0+borsh-v1",
            "snapshot codec mismatch"
        );
        validate_snapshot_shape(
            &snapshot,
            metadata.total_bytes,
            metadata.chunk_size,
            &metadata.chunk_hashes_hex,
        )?;
        trnm_finality_types::decode_hash32("snapshot payload hash", &metadata.payload_hash_hex)?;
        ensure!(
            snapshot_manifest_hash(&snapshot.metadata).as_slice() == snapshot.hash.as_ref(),
            "snapshot manifest hash mismatch"
        );
        let app_hash =
            trnm_finality_types::decode_hash32("snapshot app_hash", &metadata.app_hash_hex)?;
        ensure!(trusted_app_hash == app_hash, "snapshot app hash mismatch");
        let state = self
            .core
            .state
            .lock()
            .map_err(|_| anyhow!("consensus application state lock poisoned"))?;
        if (state.height, state.app_hash) == (metadata.height, app_hash) {
            return Ok(SnapshotRestore::Installed {
                chunks: snapshot.chunks,
            });
        }
        ensure!(
            state.height == 0 && state.pending.is_none(),
            "snapshot restore requires empty application state"
        );
        drop(state);
        Ok(SnapshotRestore::MemoryV3 {
            chunks: vec![None; snapshot.chunks as usize],
            metadata,
        })
    }

    fn validate_snapshot_offer_v4(
        &self,
        snapshot: Snapshot,
        trusted_app_hash: &[u8],
    ) -> Result<SnapshotRestore> {
        ensure!(
            self.core.store.is_some(),
            "SQLite snapshot format requires a persistent application store"
        );
        ensure!(snapshot.hash.len() == 32, "invalid snapshot hash length");
        ensure!(
            !snapshot.metadata.is_empty() && snapshot.metadata.len() <= MAX_SNAPSHOT_METADATA_BYTES,
            "snapshot metadata size is outside bounds"
        );
        let metadata: SnapshotMetadataV4 =
            serde_json::from_slice(&snapshot.metadata).context("decode snapshot metadata")?;
        ensure!(
            metadata.schema == "trnm_cometbft_snapshot_metadata_v4",
            "unsupported snapshot metadata schema"
        );
        ensure!(
            metadata.chain_id == self.core.config.chain_id
                && metadata.height == snapshot.height
                && metadata.height > 0,
            "snapshot chain or height mismatch"
        );
        ensure!(
            metadata.app_version == APP_VERSION
                && matches!(
                    metadata.store_schema,
                    SNAPSHOT_SQLITE_STORE_SCHEMA_V3 | SNAPSHOT_SQLITE_STORE_SCHEMA_V4
                ),
            "snapshot app or store version mismatch"
        );
        ensure!(
            metadata.state_codec == "sqlite-backup-v1"
                && metadata.auth_tree_codec == "jmt-sha256-v0.12.0+borsh-v1"
                && metadata.history_mode == "latest-only"
                && metadata.oldest_auth_version == metadata.height,
            "snapshot codec or authenticated history mode mismatch"
        );
        ensure!(
            metadata.authorized_signers_hash_hex
                == hex::encode(signer_policy_commitment(
                    &self.core.config.authorized_signers
                )),
            "snapshot authorized signer policy mismatch"
        );
        validate_snapshot_shape(
            &snapshot,
            metadata.total_bytes,
            metadata.chunk_size,
            &metadata.chunk_hashes_hex,
        )?;
        trnm_finality_types::decode_hash32("snapshot payload hash", &metadata.payload_hash_hex)?;
        ensure!(
            snapshot_manifest_hash_v4(&snapshot.metadata).as_slice() == snapshot.hash.as_ref(),
            "snapshot manifest hash mismatch"
        );
        let app_hash =
            trnm_finality_types::decode_hash32("snapshot app_hash", &metadata.app_hash_hex)?;
        ensure!(trusted_app_hash == app_hash, "snapshot app hash mismatch");

        let state = self
            .core
            .state
            .lock()
            .map_err(|_| anyhow!("consensus application state lock poisoned"))?;
        if (state.height, state.app_hash) == (metadata.height, app_hash) {
            return Ok(SnapshotRestore::Installed {
                chunks: snapshot.chunks,
            });
        }
        ensure!(
            state.height == 0 && state.pending.is_none(),
            "snapshot restore requires empty application state"
        );
        drop(state);

        let manifest_hash_hex = hex::encode(&snapshot.hash);
        let (stage_path, journal_path) =
            snapshot_restore_paths(&self.core.config, &manifest_hash_hex)?;
        if let Some(parent) = stage_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut received = vec![false; snapshot.chunks as usize];
        if journal_path.exists() && stage_path.exists() {
            let journal: SnapshotRestoreJournalV1 =
                serde_json::from_slice(&fs::read(&journal_path)?)
                    .context("decode snapshot restore journal")?;
            ensure!(
                journal.schema == "trnm_snapshot_restore_journal_v1"
                    && journal.manifest_hash_hex == manifest_hash_hex
                    && journal.total_bytes == metadata.total_bytes
                    && journal.chunk_size == metadata.chunk_size
                    && journal.received.len() == received.len(),
                "snapshot restore journal does not match offered manifest"
            );
            ensure!(
                fs::metadata(&stage_path)?.len() == metadata.total_bytes,
                "snapshot restore staging file length mismatch"
            );
            received = journal.received;
            for (index, present) in received.iter_mut().enumerate() {
                if !*present {
                    continue;
                }
                let chunk =
                    read_snapshot_file_chunk(&stage_path, index, metadata.total_bytes as usize)?;
                let expected = trnm_finality_types::decode_hash32(
                    "snapshot chunk hash",
                    &metadata.chunk_hashes_hex[index],
                )?;
                if snapshot_chunk_hash_v4(index as u32, &chunk) != expected {
                    *present = false;
                }
            }
        } else {
            let file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(&stage_path)?;
            file.set_len(metadata.total_bytes)?;
            file.sync_all()?;
        }
        persist_snapshot_restore_journal(&journal_path, &manifest_hash_hex, &metadata, &received)?;
        Ok(SnapshotRestore::FileV4 {
            metadata,
            manifest_hash_hex,
            stage_path,
            journal_path,
            received,
        })
    }

    fn apply_snapshot_chunk_inner(&self, request: RequestApplySnapshotChunk) -> Result<()> {
        let mut restore_guard = self
            .core
            .snapshot_restore
            .lock()
            .map_err(|_| anyhow!("snapshot restore lock poisoned"))?;
        let restore = restore_guard
            .as_mut()
            .ok_or_else(|| anyhow!("snapshot chunk received without accepted offer"))?;
        let index = request.index as usize;
        match restore {
            SnapshotRestore::Installed { chunks } => {
                ensure!(request.index < *chunks, "snapshot chunk index out of range");
                return Ok(());
            }
            SnapshotRestore::MemoryV3 { metadata, chunks } => {
                ensure!(index < chunks.len(), "snapshot chunk index out of range");
                let expected_len = if index + 1 == chunks.len() {
                    metadata.total_bytes as usize - index * SNAPSHOT_CHUNK_SIZE
                } else {
                    SNAPSHOT_CHUNK_SIZE
                };
                ensure!(
                    request.chunk.len() == expected_len,
                    "retry snapshot chunk: invalid length"
                );
                let expected_chunk_hash = trnm_finality_types::decode_hash32(
                    "snapshot chunk hash",
                    &metadata.chunk_hashes_hex[index],
                )?;
                ensure!(
                    snapshot_chunk_hash(index as u32, &request.chunk) == expected_chunk_hash,
                    "retry snapshot chunk: content hash mismatch"
                );
                if let Some(existing) = &chunks[index] {
                    ensure!(
                        existing == &request.chunk,
                        "conflicting duplicate snapshot chunk"
                    );
                } else {
                    chunks[index] = Some(request.chunk);
                }
                if chunks.iter().any(Option::is_none) {
                    return Ok(());
                }

                let mut bytes = Vec::with_capacity(metadata.total_bytes as usize);
                for chunk in chunks.iter() {
                    bytes.extend_from_slice(chunk.as_ref().expect("all chunks checked"));
                }
                ensure!(
                    snapshot_payload_hash(&bytes)
                        == trnm_finality_types::decode_hash32(
                            "snapshot payload hash",
                            &metadata.payload_hash_hex,
                        )?,
                    "snapshot payload hash mismatch"
                );
                let (mut next, next_auth_tree) = decode_state(&bytes)?;
                let lifecycle = next
                    .validator_lifecycle
                    .as_ref()
                    .context("restored snapshot is missing validator lifecycle")?;
                validate_lifecycle_authorization(&self.core.config, lifecycle)?;
                validate_poco_authority_binding(&self.core.config, &next, None)?;
                ensure!(
                    next.height == metadata.height
                        && hex::encode(next.app_hash) == metadata.app_hash_hex,
                    "restored snapshot head mismatch"
                );
                let mut state = self
                    .core
                    .state
                    .lock()
                    .map_err(|_| anyhow!("consensus application state lock poisoned"))?;
                ensure!(
                    state.height == 0 && state.pending.is_none(),
                    "application state changed during snapshot restore"
                );
                if let Some(store) = &self.core.store {
                    store.replace_empty_state_from_tree(&state, &next, &next_auth_tree)?;
                    next.objects.clear();
                    next.command_ids.clear();
                    next.signer_nonces.clear();
                } else {
                    *self
                        .core
                        .auth_tree
                        .lock()
                        .map_err(|_| anyhow!("authenticated state tree lock poisoned"))? =
                        next_auth_tree;
                }
                *state = next;
                self.clear_poco_runtime_caches()?;
                if let Err(error) = self.retain_snapshot(&state) {
                    eprintln!(
                        "[trnm-cometbft-app] restored state but failed to retain optional snapshot: {error:#}"
                    );
                }
            }
            SnapshotRestore::FileV4 {
                metadata,
                manifest_hash_hex,
                stage_path,
                journal_path,
                received,
            } => {
                ensure!(index < received.len(), "snapshot chunk index out of range");
                let expected_len =
                    snapshot_chunk_len(index, received.len(), metadata.total_bytes as usize);
                ensure!(
                    request.chunk.len() == expected_len,
                    "retry snapshot chunk: invalid length"
                );
                let expected_chunk_hash = trnm_finality_types::decode_hash32(
                    "snapshot chunk hash",
                    &metadata.chunk_hashes_hex[index],
                )?;
                ensure!(
                    snapshot_chunk_hash_v4(index as u32, &request.chunk) == expected_chunk_hash,
                    "retry snapshot chunk: content hash mismatch"
                );
                if received[index] {
                    let existing =
                        read_snapshot_file_chunk(stage_path, index, metadata.total_bytes as usize)?;
                    ensure!(
                        existing.as_slice() == request.chunk.as_ref(),
                        "conflicting duplicate snapshot chunk"
                    );
                } else {
                    write_snapshot_file_chunk(stage_path, index, &request.chunk)?;
                    received[index] = true;
                    persist_snapshot_restore_journal(
                        journal_path,
                        manifest_hash_hex,
                        metadata,
                        received,
                    )?;
                }
                if received.iter().any(|present| !present) {
                    return Ok(());
                }
                ensure!(
                    snapshot_payload_hash_file_v4(stage_path)?
                        == trnm_finality_types::decode_hash32(
                            "snapshot payload hash",
                            &metadata.payload_hash_hex,
                        )?,
                    "snapshot payload hash mismatch"
                );

                let mut state = self
                    .core
                    .state
                    .lock()
                    .map_err(|_| anyhow!("consensus application state lock poisoned"))?;
                ensure!(
                    state.height == 0 && state.pending.is_none(),
                    "application state changed during snapshot restore"
                );
                let store = self
                    .core
                    .store
                    .as_ref()
                    .context("SQLite snapshot restore lost persistent store")?;
                let expected_app_hash = trnm_finality_types::decode_hash32(
                    "snapshot app_hash",
                    &metadata.app_hash_hex,
                )?;
                let validated = store.validate_snapshot_database(
                    stage_path,
                    metadata.height,
                    expected_app_hash,
                )?;
                let lifecycle = validated
                    .validator_lifecycle
                    .as_ref()
                    .context("restored snapshot is missing validator lifecycle")?;
                validate_lifecycle_authorization(&self.core.config, lifecycle)?;
                let restored_authority =
                    store.load_snapshot_object(stage_path, &poco_authority_object_key())?;
                ensure!(
                    restored_authority
                        == self
                            .core
                            .config
                            .poco_authority
                            .as_ref()
                            .map(poco_authority_object),
                    "restored PoCO authority does not match application config"
                );
                let next = store.install_snapshot_database(
                    &state,
                    stage_path,
                    metadata.height,
                    expected_app_hash,
                )?;
                *state = next;
                self.clear_poco_runtime_caches()?;
                if let Err(error) = self.retain_snapshot(&state) {
                    eprintln!(
                        "[trnm-cometbft-app] restored state but failed to retain optional snapshot: {error:#}"
                    );
                }
                for path in [stage_path.as_path(), journal_path.as_path()] {
                    match fs::remove_file(path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => eprintln!(
                            "[trnm-cometbft-app] restored state but failed to remove {}: {error}",
                            path.display()
                        ),
                    }
                }
            }
        }
        restore_guard.take();
        Ok(())
    }
}

fn snapshot_apply_response(
    result: response_apply_snapshot_chunk::Result,
) -> ResponseApplySnapshotChunk {
    ResponseApplySnapshotChunk {
        result: result as i32,
        refetch_chunks: Vec::new(),
        reject_senders: Vec::new(),
    }
}

fn check_tx_error(message: &str) -> ResponseCheckTx {
    ResponseCheckTx {
        code: 1,
        log: message.to_string(),
        codespace: "trnm".to_string(),
        ..Default::default()
    }
}

fn query_object_key(path: &str) -> Result<String> {
    if let Some(account) = path.strip_prefix("/account/") {
        ensure!(!account.is_empty(), "account query identifier is empty");
        Ok(account_key(account))
    } else if let Some(task_id) = path.strip_prefix("/task/") {
        ensure!(!task_id.is_empty(), "task query identifier is empty");
        Ok(task_key(task_id))
    } else if let Some(object_key) = path.strip_prefix("/object/") {
        ensure!(!object_key.is_empty(), "object query key is empty");
        Ok(object_key.to_string())
    } else {
        Err(anyhow!("unsupported query path"))
    }
}

fn query_error(message: &str) -> ResponseQuery {
    ResponseQuery {
        code: 1,
        log: message.to_string(),
        ..Default::default()
    }
}

fn canonical_signers(signers: &[AuthorizedSignerV1]) -> BTreeSet<(String, String, String)> {
    signers
        .iter()
        .map(|signer| {
            (
                signer.signer_id.clone(),
                signer.signer_role.clone(),
                signer.public_key_hex.clone(),
            )
        })
        .collect()
}

fn validate_poco_genesis_entries_v0(
    raw_entries: &[PocoGenesisEntryV0],
    authority: Option<&PocoAuthorityConfigV0>,
    chain_id: &str,
    application_validators: &[ConsensusValidatorV1],
) -> Result<Vec<poco_snapshot::PocoSnapshotEntryV0>> {
    if raw_entries.is_empty() {
        // An empty list is the explicit legacy/inert state. It remains
        // restorable but cannot be consumed by the H3b2b1 planner.
        return Ok(Vec::new());
    }
    let authority = authority.context("PoCO genesis entries require authenticated authority")?;
    ensure!(
        raw_entries.len() <= poco_snapshot::MAX_POCO_SNAPSHOT_ENTRIES,
        "PoCO genesis entry count exceeds bound"
    );
    let mut encoded_total = 0usize;
    for entry in raw_entries {
        encoded_total = encoded_total
            .checked_add(entry.logical_key_hex.len())
            .and_then(|size| size.checked_add(entry.value_hex.len()))
            .context("PoCO genesis hex size overflow")?;
        ensure!(
            encoded_total <= poco_snapshot::MAX_POCO_SNAPSHOT_BUNDLE_BYTES.saturating_mul(2),
            "PoCO genesis hex exceeds decoded 8 MiB bound"
        );
    }

    let mut entries = raw_entries
        .iter()
        .map(|raw| {
            let kind = poco_snapshot::PocoSnapshotEntryKindV0::from_u8(raw.kind)?;
            let logical_key =
                hex::decode(&raw.logical_key_hex).context("decode PoCO genesis logical key hex")?;
            let value = hex::decode(&raw.value_hex).context("decode PoCO genesis value hex")?;
            poco_transition::decode_poco_snapshot_value_v0_exact(kind, &logical_key, &value)?;
            poco_snapshot::PocoSnapshotEntryV0::new(kind, logical_key, value)
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by(|left, right| {
        (left.kind, left.logical_key.as_slice()).cmp(&(right.kind, right.logical_key.as_slice()))
    });
    poco_snapshot::validate_entries(&entries)?;

    let authority_key = poco_application::poco_application_authority_logical_key_v0();
    let authority_entries = entries
        .iter()
        .filter(|entry| {
            entry.kind == poco_snapshot::PocoSnapshotEntryKindV0::ApplicationAuthorityState
        })
        .collect::<Vec<_>>();
    ensure!(
        authority_entries.len() == 1
            && authority_entries[0].logical_key.as_slice() == authority_key,
        "PoCO genesis requires exactly one canonical application authority entry"
    );
    let parts = poco_transition::decode_poco_snapshot_value_parts_v0_exact(
        authority_entries[0].kind,
        &authority_entries[0].logical_key,
        &authority_entries[0].value,
    )?;
    ensure!(
        parts.verified.revision() == 1
            && parts.identity == poco_application::poco_application_authority_identity_v0()
            && poco_application::PocoApplicationAuthorityStateV0::decode_exact(parts.payload)?
                == poco_application::PocoApplicationAuthorityStateV0::empty(),
        "PoCO genesis application authority is not the exact empty revision-1 state"
    );

    let manifest = poco_snapshot::PocoSnapshotManifestV0::from_entries(
        trnm_consensus_types::Height::new(0),
        &entries,
    )?;
    let mut live = BTreeMap::new();
    for entry in &entries {
        ensure!(
            live.insert(entry.jmt_key()?, entry.value.clone()).is_none(),
            "duplicate PoCO genesis physical entry"
        );
    }
    live.insert(
        poco_snapshot::poco_snapshot_manifest_key()?,
        manifest.encode(),
    );
    let projection = take_and_validate_production_poco_projection_v0(0, &mut live)?
        .context("PoCO genesis projection is inactive")?;
    ensure!(live.is_empty(), "PoCO genesis validation left hidden state");
    let (validator_set, parameters) = active_consensus_configuration(&projection)?;
    validate_poco_parameter_retention_v0(&parameters)?;
    let expected_chain_id = trnm_consensus_types::ChainId::from_bytes(chain_id.as_bytes())
        .map_err(|error| anyhow!("invalid PoCO genesis chain ID: {error:?}"))?;
    let expected_genesis = trnm_consensus_types::GenesisHash::new(
        trnm_finality_types::decode_hash32("PoCO genesis hash", &authority.genesis_hash_hex)?,
    );
    let expected_profile = trnm_finality_types::decode_hash32(
        "PoCO protocol profile hash",
        &authority.protocol_profile_hash_hex,
    )?;
    ensure!(
        validator_set.chain_id() == expected_chain_id
            && validator_set.genesis_hash() == expected_genesis,
        "PoCO genesis validator set authority mismatch"
    );
    ensure!(
        validator_set.consensus_parameters_hash() == parameters.hash()
            && *parameters.hash().as_bytes() == expected_profile,
        "PoCO genesis active parameter/profile mismatch"
    );
    validator_set
        .validate_against_parameters(&parameters)
        .map_err(|error| anyhow!("invalid PoCO genesis active configuration: {error:?}"))?;
    validate_application_validator_projection(&validator_set, application_validators)?;
    Ok(entries)
}

fn default_fee_policy_object() -> StoredObject {
    ObjectMutation {
        object_key_hex: fee_policy_key(),
        object_type: FEE_POLICY_OBJECT_TYPE_V1.to_string(),
        expected_version: None,
        next_version: 1,
        value_bytes: serde_json::to_vec(&FeePolicyV1::default())
            .expect("default fee policy serialization is infallible"),
    }
    .into_stored()
}

fn poco_authority_object_key() -> String {
    hex::encode(hash_domain(
        "trnm.state.object.key.v1",
        &[b"trnm.poco.authority.v0"],
    ))
}

fn poco_authority_object(authority: &PocoAuthorityConfigV0) -> StoredObject {
    ObjectMutation {
        object_key_hex: poco_authority_object_key(),
        object_type: "trnm.poco.authority.v0".to_string(),
        expected_version: None,
        next_version: 0,
        value_bytes: serde_json::to_vec(authority)
            .expect("validated PoCO authority serialization is infallible"),
    }
    .into_stored()
}

fn validate_poco_authority_binding(
    config: &ConsensusAppConfig,
    state: &AppState,
    store: Option<&ApplicationStore>,
) -> Result<()> {
    let key = poco_authority_object_key();
    if state.validator_lifecycle.is_none() {
        ensure!(
            !state.objects.contains_key(&key),
            "uninitialized state contains a PoCO authority object"
        );
        return Ok(());
    }
    let committed = state.objects.get(&key).cloned().or_else(|| {
        store.and_then(|store| {
            store.load_object(&key).unwrap_or_else(|error| {
                panic!("fail-stop: load authenticated PoCO authority object: {error:#}")
            })
        })
    });
    let expected = config.poco_authority.as_ref().map(poco_authority_object);
    ensure!(
        committed == expected,
        "authenticated PoCO authority does not match application config"
    );
    Ok(())
}

fn effective_validator_lifecycle<'a>(
    state: &'a AppState,
    delta: &'a BlockDelta,
) -> Result<&'a ValidatorLifecycleStateV1> {
    delta
        .validator_lifecycle
        .as_ref()
        .or(state.validator_lifecycle.as_ref())
        .context("validator lifecycle is not initialized")
}

fn poco_application_governance_signer_commitment_v0(
    lifecycle: &ValidatorLifecycleStateV1,
) -> [u8; 32] {
    hash_domain(
        "trnm.poco-bft.application-governance-signer.v0",
        &[
            lifecycle.governance.signer_id.as_bytes(),
            lifecycle.authorized_signers_hash_hex.as_bytes(),
        ],
    )
}

fn validate_lifecycle_authorization(
    config: &ConsensusAppConfig,
    lifecycle: &ValidatorLifecycleStateV1,
) -> Result<()> {
    lifecycle.validate()?;
    ensure!(
        lifecycle.chain_id == config.chain_id,
        "validator lifecycle chain_id differs from local application config"
    );
    ensure!(
        lifecycle.app_version == APP_VERSION,
        "validator lifecycle app version differs from local application"
    );
    ensure!(
        lifecycle.authorized_signers_hash_hex
            == hex::encode(signer_policy_commitment(&config.authorized_signers)),
        "validator lifecycle authorized signer policy differs from local application config"
    );
    // v1 is deliberately fail-closed single-operator governance. The signer
    // is explicit in committed state; threshold authorization is still required
    // before public testnet readiness.
    let signer = config
        .authorized_signers
        .iter()
        .find(|signer| signer.signer_id == lifecycle.governance.signer_id)
        .context("validator governance signer is not locally authorized")?;
    ensure!(
        signer.signer_role == "operator",
        "validator governance signer must have operator role"
    );
    Ok(())
}

fn signer_policy_commitment(signers: &[AuthorizedSignerV1]) -> [u8; 32] {
    root_only(
        "trnm.cometbft.authorized-signers.v1",
        canonical_signers(signers)
            .iter()
            .map(|(signer_id, signer_role, public_key_hex)| {
                hash_domain(
                    "trnm.cometbft.authorized-signer.v1",
                    &[
                        signer_id.as_bytes(),
                        signer_role.as_bytes(),
                        public_key_hex.as_bytes(),
                    ],
                )
            }),
    )
}

fn authenticated_object_write(object: &StoredObject) -> Result<AuthWrite> {
    let key = stored_object_key(&object.object_key_hex)?;
    let value = AuthenticatedObjectRecord::new(
        object.object_type.clone(),
        object.version,
        object.value_bytes.clone(),
    )?
    .encode()?;
    AuthWrite::put(key, value)
}

fn authenticated_lifecycle_write(
    height: u64,
    lifecycle: &ValidatorLifecycleStateV1,
) -> Result<AuthWrite> {
    lifecycle.validate()?;
    let value = AuthenticatedObjectRecord::new(
        VALIDATOR_LIFECYCLE_SCHEMA_V1,
        height,
        serde_json::to_vec(lifecycle)?,
    )?
    .encode()?;
    AuthWrite::put(validator_state_key()?, value)
}

fn authenticated_writes_for_state(height: u64, state: &AppState) -> Result<Vec<AuthWrite>> {
    let mut writes = state
        .objects
        .values()
        .map(authenticated_object_write)
        .collect::<Result<Vec<_>>>()?;
    if let Some(lifecycle) = &state.validator_lifecycle {
        writes.push(authenticated_lifecycle_write(height, lifecycle)?);
    }
    Ok(writes)
}

fn authenticated_writes_for_delta(height: u64, delta: &BlockDelta) -> Result<Vec<AuthWrite>> {
    let mut writes = delta
        .objects
        .values()
        .map(authenticated_object_write)
        .collect::<Result<Vec<_>>>()?;
    if let Some(lifecycle) = &delta.validator_lifecycle {
        writes.push(authenticated_lifecycle_write(height, lifecycle)?);
    }
    Ok(writes)
}

fn validate_in_memory_authenticated_domain_projection(
    state: &AppState,
    auth_tree: &InMemoryAuthTree,
) -> Result<()> {
    ensure!(
        state.pending.is_none(),
        "cannot validate pending application state"
    );
    ensure!(
        auth_tree.latest_version() == Some(state.height)
            && auth_tree
                .root_hash(state.height)
                .map(Into::<[u8; 32]>::into)
                == Some(state.app_hash),
        "authenticated tree does not match application head"
    );
    let mut authenticated = auth_tree.verified_live_values(state.height)?;
    for object in state.objects.values() {
        let key = stored_object_key(&object.object_key_hex)?;
        let value = authenticated.remove(&key).with_context(|| {
            format!(
                "persisted object {} is absent from authenticated state",
                object.object_key_hex
            )
        })?;
        ensure!(
            value
                == AuthenticatedObjectRecord::new(
                    object.object_type.clone(),
                    object.version,
                    object.value_bytes.clone(),
                )?
                .encode()?,
            "persisted object {} differs from authenticated value",
            object.object_key_hex
        );
    }
    let lifecycle = state
        .validator_lifecycle
        .as_ref()
        .context("persisted state is missing validator lifecycle")?;
    let lifecycle_value = authenticated
        .remove(&validator_state_key()?)
        .context("persisted validator lifecycle is absent from authenticated state")?;
    let lifecycle_record = AuthenticatedObjectRecord::decode(&lifecycle_value)?;
    ensure!(
        lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
            && lifecycle_record.object_version <= state.height
            && lifecycle_record.value == serde_json::to_vec(lifecycle)?,
        "persisted validator lifecycle differs from authenticated value"
    );
    take_and_validate_production_poco_projection_v0(state.height, &mut authenticated)?;
    ensure!(
        authenticated.is_empty(),
        "authenticated state contains {} leaves absent from persisted application state",
        authenticated.len()
    );
    Ok(())
}

fn empty_app_hash() -> [u8; 32] {
    hash_domain("trnm.cometbft.application.empty.v2", &[])
}

#[cfg(test)]
fn test_authorized_empty_native_execution(
    parent_height: u64,
    parent_state_root: [u8; 32],
    target_height: u64,
    post_state_root: [u8; 32],
) -> AuthorizedNativeCheckpointExecutionV0 {
    authorize_native_checkpoint_execution_v0(
        NativeBlockExecutionV0::empty(),
        trnm_consensus_types::Height::new(parent_height),
        trnm_consensus_types::StateRoot::new(parent_state_root),
        trnm_consensus_types::Height::new(target_height),
        trnm_consensus_types::StateRoot::new(post_state_root),
    )
    .expect("test native execution transition is authorized")
}

#[cfg(test)]
fn compute_app_hash(
    _height: u64,
    objects: &BTreeMap<String, StoredObject>,
    command_ids: &BTreeSet<String>,
    signer_nonces: &BTreeSet<(String, u64)>,
    validator_lifecycle: Option<&ValidatorLifecycleStateV1>,
) -> [u8; 32] {
    let object_root = root_only(
        "trnm.state.objects.v1",
        objects.values().map(StoredObject::leaf_hash),
    );
    let command_root = root_only(
        "trnm.state.command-ids.v1",
        command_ids
            .iter()
            .map(|command_id| hash_domain("trnm.state.command-id.v1", &[command_id.as_bytes()])),
    );
    let nonce_root = root_only(
        "trnm.state.signer-nonces.v1",
        signer_nonces.iter().map(|(signer_id, nonce)| {
            hash_domain(
                "trnm.state.signer-nonce.v1",
                &[signer_id.as_bytes(), &nonce.to_be_bytes()],
            )
        }),
    );
    compose_app_hash(
        object_root,
        command_root,
        nonce_root,
        validator_lifecycle_commitment(validator_lifecycle),
    )
}

#[cfg(test)]
fn compose_app_hash(
    object_root: [u8; 32],
    command_root: [u8; 32],
    nonce_root: [u8; 32],
    validator_lifecycle_root: [u8; 32],
) -> [u8; 32] {
    hash_domain(
        "trnm.cometbft.application.v3",
        &[
            &object_root,
            &command_root,
            &nonce_root,
            &validator_lifecycle_root,
        ],
    )
}

#[cfg(test)]
fn validator_lifecycle_commitment(lifecycle: Option<&ValidatorLifecycleStateV1>) -> [u8; 32] {
    lifecycle
        .map(|lifecycle| {
            lifecycle
                .commitment()
                .expect("committed validator lifecycle must be valid")
        })
        .unwrap_or_else(|| hash_domain("trnm.cometbft.validator-lifecycle.empty.v1", &[]))
}

fn consensus_timestamp_ms(
    timestamp: Option<&tendermint_proto::google::protobuf::Timestamp>,
) -> Result<u64> {
    let timestamp = timestamp.context("consensus timestamp is missing")?;
    ensure!(
        timestamp.seconds >= 0,
        "consensus timestamp seconds must not be negative"
    );
    ensure!(
        (0..1_000_000_000).contains(&timestamp.nanos),
        "consensus timestamp nanos is outside protobuf range"
    );
    let seconds =
        u64::try_from(timestamp.seconds).context("convert consensus timestamp seconds")?;
    let nanos = u64::try_from(timestamp.nanos).context("convert consensus timestamp nanos")?;
    seconds
        .checked_mul(1_000)
        .and_then(|millis| millis.checked_add(nanos / 1_000_000))
        .context("consensus timestamp exceeds u64 milliseconds")
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn decode_state(bytes: &[u8]) -> Result<(AppState, InMemoryAuthTree)> {
    let persisted: PersistedAppStateV4 =
        serde_json::from_slice(bytes).context("decode persisted application state")?;
    ensure!(
        persisted.schema == "trnm_cometbft_app_state_v4",
        "unsupported persisted app state schema"
    );
    let app_hash =
        trnm_finality_types::decode_hash32("persisted app_hash", &persisted.app_hash_hex)?;
    persisted.validator_lifecycle.validate()?;
    let mut objects = BTreeMap::new();
    for object in persisted.objects {
        let value_bytes =
            hex::decode(&object.value_hex).context("decode persisted object value")?;
        let stored = StoredObject {
            object_key_hex: object.object_key_hex,
            object_type: object.object_type,
            version: object.version,
            value_hash_hex: object.value_hash_hex,
            value_bytes,
        };
        ensure!(
            stored.value_hash_hex
                == hex::encode(hash_domain(
                    "trnm.state.object.value.v1",
                    &[&stored.value_bytes]
                )),
            "persisted object value hash mismatch"
        );
        ensure!(
            objects
                .insert(stored.object_key_hex.clone(), stored)
                .is_none(),
            "duplicate persisted object key"
        );
    }
    let auth_tree = InMemoryAuthTree::decode_snapshot(
        &hex::decode(&persisted.auth_tree_hex).context("decode authenticated tree snapshot hex")?,
    )?;
    ensure!(
        auth_tree.latest_version() == Some(persisted.height)
            && auth_tree
                .root_hash(persisted.height)
                .map(Into::<[u8; 32]>::into)
                == Some(app_hash),
        "persisted authenticated tree does not match application head"
    );
    let state = AppState {
        height: persisted.height,
        app_hash,
        objects,
        command_ids: persisted.command_ids,
        signer_nonces: persisted.signer_nonces,
        validator_lifecycle: Some(persisted.validator_lifecycle),
        pending: None,
    };
    validate_in_memory_authenticated_domain_projection(&state, &auth_tree)?;
    Ok((state, auth_tree))
}

fn encode_state(state: &AppState, auth_tree: &InMemoryAuthTree) -> Result<Vec<u8>> {
    ensure!(
        state.pending.is_none(),
        "cannot encode pending application state"
    );
    ensure!(
        auth_tree.latest_version() == Some(state.height)
            && auth_tree
                .root_hash(state.height)
                .map(Into::<[u8; 32]>::into)
                == Some(state.app_hash),
        "cannot encode state with a different authenticated tree head"
    );
    validate_in_memory_authenticated_domain_projection(state, auth_tree)?;
    let persisted = PersistedAppStateV4 {
        schema: "trnm_cometbft_app_state_v4".to_string(),
        height: state.height,
        app_hash_hex: hex::encode(state.app_hash),
        objects: state
            .objects
            .values()
            .map(|object| PersistedObjectV1 {
                object_key_hex: object.object_key_hex.clone(),
                object_type: object.object_type.clone(),
                version: object.version,
                value_hash_hex: object.value_hash_hex.clone(),
                value_hex: hex::encode(&object.value_bytes),
            })
            .collect(),
        command_ids: state.command_ids.clone(),
        signer_nonces: state.signer_nonces.clone(),
        validator_lifecycle: state
            .validator_lifecycle
            .clone()
            .context("cannot encode state before validator lifecycle initialization")?,
        auth_tree_hex: hex::encode(auth_tree.encode_snapshot()?),
    };
    Ok(serde_json::to_vec(&persisted)?)
}

fn snapshot_payload_hash(bytes: &[u8]) -> [u8; 32] {
    hash_domain("trnm.cometbft.snapshot.payload.v3", &[bytes])
}

fn snapshot_chunk_hash(index: u32, bytes: &[u8]) -> [u8; 32] {
    hash_domain(
        "trnm.cometbft.snapshot.chunk.v3",
        &[&index.to_be_bytes(), bytes],
    )
}

fn snapshot_manifest_hash(metadata: &[u8]) -> [u8; 32] {
    hash_domain("trnm.cometbft.snapshot.manifest.v3", &[metadata])
}

fn snapshot_chunk_hash_v4(index: u32, bytes: &[u8]) -> [u8; 32] {
    hash_domain(
        "trnm.cometbft.snapshot.chunk.v4",
        &[&index.to_be_bytes(), bytes],
    )
}

fn snapshot_manifest_hash_v4(metadata: &[u8]) -> [u8; 32] {
    hash_domain("trnm.cometbft.snapshot.manifest.v4", &[metadata])
}

fn snapshot_payload_hasher_v4() -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.cometbft.snapshot.payload.v4");
    hasher.update([0]);
    hasher
}

fn snapshot_payload_hash_file_v4(path: &Path) -> Result<[u8; 32]> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("open snapshot payload {}", path.display()))?;
    let mut hasher = snapshot_payload_hasher_v4();
    let mut buffer = vec![0_u8; SNAPSHOT_CHUNK_SIZE];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn snapshot_file_hashes_v4(path: &Path) -> Result<(u64, [u8; 32], Vec<String>)> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("open snapshot payload {}", path.display()))?;
    let mut payload_hasher = snapshot_payload_hasher_v4();
    let mut chunk_hashes = Vec::new();
    let mut total_bytes = 0_u64;
    let mut buffer = vec![0_u8; SNAPSHOT_CHUNK_SIZE];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        payload_hasher.update(&buffer[..count]);
        chunk_hashes.push(hex::encode(snapshot_chunk_hash_v4(
            u32::try_from(chunk_hashes.len()).context("snapshot chunk index exceeds u32")?,
            &buffer[..count],
        )));
        total_bytes = total_bytes.saturating_add(count as u64);
    }
    ensure!(total_bytes > 0, "SQLite snapshot payload is empty");
    Ok((total_bytes, payload_hasher.finalize().into(), chunk_hashes))
}

fn validate_snapshot_shape(
    snapshot: &Snapshot,
    total_bytes: u64,
    chunk_size: u32,
    chunk_hashes_hex: &[String],
) -> Result<()> {
    ensure!(
        snapshot.chunks > 0 && snapshot.chunks <= MAX_SNAPSHOT_CHUNKS,
        "invalid snapshot chunk count"
    );
    ensure!(
        chunk_size == SNAPSHOT_CHUNK_SIZE as u32,
        "snapshot chunk size mismatch"
    );
    ensure!(total_bytes > 0, "snapshot is empty");
    ensure!(
        total_bytes <= (MAX_SNAPSHOT_CHUNKS as u64).saturating_mul(SNAPSHOT_CHUNK_SIZE as u64),
        "snapshot byte length exceeds limit"
    );
    let total_bytes =
        usize::try_from(total_bytes).context("snapshot byte length exceeds platform capacity")?;
    ensure!(
        total_bytes.div_ceil(SNAPSHOT_CHUNK_SIZE) as u32 == snapshot.chunks,
        "snapshot byte length mismatch"
    );
    ensure!(
        chunk_hashes_hex.len() == snapshot.chunks as usize,
        "snapshot chunk hash count mismatch"
    );
    for hash in chunk_hashes_hex {
        trnm_finality_types::decode_hash32("snapshot chunk hash", hash)?;
    }
    Ok(())
}

fn snapshot_chunk_len(index: usize, chunks: usize, total_bytes: usize) -> usize {
    if index + 1 == chunks {
        total_bytes - index * SNAPSHOT_CHUNK_SIZE
    } else {
        SNAPSHOT_CHUNK_SIZE
    }
}

fn read_snapshot_file_chunk(path: &Path, index: usize, total_bytes: usize) -> Result<Vec<u8>> {
    let chunks = total_bytes.div_ceil(SNAPSHOT_CHUNK_SIZE);
    ensure!(index < chunks, "snapshot chunk index out of range");
    let mut file =
        fs::File::open(path).with_context(|| format!("open snapshot stage {}", path.display()))?;
    file.seek(SeekFrom::Start(
        u64::try_from(index.saturating_mul(SNAPSHOT_CHUNK_SIZE))
            .context("snapshot chunk offset exceeds u64")?,
    ))?;
    let mut bytes = vec![0_u8; snapshot_chunk_len(index, chunks, total_bytes)];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_snapshot_file_chunk(path: &Path, index: usize, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open snapshot stage {}", path.display()))?;
    file.seek(SeekFrom::Start(
        u64::try_from(index.saturating_mul(SNAPSHOT_CHUNK_SIZE))
            .context("snapshot chunk offset exceeds u64")?,
    ))?;
    file.write_all(bytes)?;
    file.sync_data()?;
    Ok(())
}

fn persist_snapshot_restore_journal(
    path: &Path,
    manifest_hash_hex: &str,
    metadata: &SnapshotMetadataV4,
    received: &[bool],
) -> Result<()> {
    persist_state_bytes(
        path,
        &serde_json::to_vec(&SnapshotRestoreJournalV1 {
            schema: "trnm_snapshot_restore_journal_v1".to_string(),
            manifest_hash_hex: manifest_hash_hex.to_string(),
            total_bytes: metadata.total_bytes,
            chunk_size: metadata.chunk_size,
            received: received.to_vec(),
        })?,
    )
}

fn snapshot_restore_paths(
    config: &ConsensusAppConfig,
    manifest_hash_hex: &str,
) -> Result<(PathBuf, PathBuf)> {
    ensure!(
        manifest_hash_hex.len() == 64
            && manifest_hash_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "snapshot manifest hash is not canonical lowercase hex"
    );
    let state_path = config
        .state_path
        .as_ref()
        .context("snapshot restore requires persistent state path")?;
    let directory = state_path.with_extension("restore");
    Ok((
        directory.join(format!("{manifest_hash_hex}.sqlite3.part")),
        directory.join(format!("{manifest_hash_hex}.journal.json")),
    ))
}

fn cleanup_snapshot_restore_directory(
    config: &ConsensusAppConfig,
    keep: Option<(&Path, &Path)>,
) -> Result<()> {
    let Some(state_path) = &config.state_path else {
        return Ok(());
    };
    let directory = state_path.with_extension("restore");
    if !directory.exists() {
        return Ok(());
    }
    let mut removed = false;
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let path = entry.path();
        if keep.is_some_and(|(stage, journal)| path == stage || path == journal) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
        removed = true;
    }
    if removed {
        fs::File::open(&directory)?.sync_all()?;
    }
    Ok(())
}

fn snapshot_path(config: &ConsensusAppConfig, height: u64) -> Option<PathBuf> {
    config.state_path.as_ref().map(|state_path| {
        state_path
            .with_extension("snapshots")
            .join(format!("{height:020}.snapshot"))
    })
}

fn snapshot_manifest_path(payload_path: &Path) -> PathBuf {
    let mut path = payload_path.as_os_str().to_os_string();
    path.push(".manifest.json");
    PathBuf::from(path)
}

fn persist_disk_snapshot_manifest(record: &SnapshotRecord) -> Result<()> {
    let SnapshotPayload::File { path, len } = &record.payload else {
        return Ok(());
    };
    let payload_len = u64::try_from(*len).context("snapshot payload length exceeds u64")?;
    let manifest = DiskSnapshotManifestV1 {
        schema: DISK_SNAPSHOT_MANIFEST_SCHEMA_V1.to_string(),
        height: record.snapshot.height,
        format: record.snapshot.format,
        chunks: record.snapshot.chunks,
        manifest_hash_hex: hex::encode(&record.snapshot.hash),
        metadata_hex: hex::encode(&record.snapshot.metadata),
        payload_len,
    };
    persist_state_bytes(
        &snapshot_manifest_path(path),
        &serde_json::to_vec(&manifest)?,
    )
}

fn load_disk_snapshot_records(
    config: &ConsensusAppConfig,
    state: &AppState,
    store: &ApplicationStore,
) -> Result<BTreeMap<u64, SnapshotRecord>> {
    let Some(state_path) = &config.state_path else {
        return Ok(BTreeMap::new());
    };
    let directory = state_path.with_extension("snapshots");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeMap::new());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read snapshot directory {}", directory.display()));
        }
    };
    let mut heights = BTreeSet::new();
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(height) = name
            .strip_suffix(".snapshot.manifest.json")
            .and_then(|height| {
                (height.len() == 20 && height.bytes().all(|byte| byte.is_ascii_digit()))
                    .then(|| height.parse::<u64>().ok())
                    .flatten()
            })
        else {
            continue;
        };
        if height > 0 && height <= state.height {
            heights.insert(height);
        }
    }
    let mut records = BTreeMap::new();
    for height in heights.into_iter().rev() {
        match load_disk_snapshot_record(config, state, store, height) {
            Ok(record) => {
                records.insert(height, record);
                if records.len() == RETAINED_DISK_SNAPSHOTS {
                    break;
                }
            }
            Err(error) => eprintln!(
                "[trnm-cometbft-app] ignored invalid retained snapshot {height}: {error:#}"
            ),
        }
    }
    cleanup_snapshot_directory(&directory, &records)?;
    Ok(records)
}

fn load_disk_snapshot_record(
    config: &ConsensusAppConfig,
    state: &AppState,
    store: &ApplicationStore,
    height: u64,
) -> Result<SnapshotRecord> {
    let payload_path =
        snapshot_path(config, height).context("persistent snapshot path is unavailable")?;
    let manifest_path = snapshot_manifest_path(&payload_path);
    let manifest_size = fs::metadata(&manifest_path)
        .with_context(|| format!("stat snapshot manifest {}", manifest_path.display()))?
        .len();
    ensure!(
        manifest_size > 0 && manifest_size <= MAX_DISK_SNAPSHOT_MANIFEST_BYTES,
        "snapshot manifest size is outside bounds"
    );
    let manifest: DiskSnapshotManifestV1 = serde_json::from_slice(
        &fs::read(&manifest_path)
            .with_context(|| format!("read snapshot manifest {}", manifest_path.display()))?,
    )?;
    ensure!(
        manifest.schema == DISK_SNAPSHOT_MANIFEST_SCHEMA_V1
            && manifest.height == height
            && manifest.format == SNAPSHOT_FORMAT_V4,
        "retained snapshot manifest identity mismatch"
    );
    let metadata_bytes =
        hex::decode(&manifest.metadata_hex).context("decode retained snapshot metadata")?;
    let metadata: SnapshotMetadataV4 =
        serde_json::from_slice(&metadata_bytes).context("decode retained snapshot metadata")?;
    let snapshot = Snapshot {
        height,
        format: manifest.format,
        chunks: manifest.chunks,
        hash: Bytes::from(
            trnm_finality_types::decode_hash32(
                "retained snapshot manifest hash",
                &manifest.manifest_hash_hex,
            )?
            .to_vec(),
        ),
        metadata: Bytes::copy_from_slice(&metadata_bytes),
    };
    ensure!(
        snapshot_manifest_hash_v4(&metadata_bytes).as_slice() == snapshot.hash.as_ref(),
        "retained snapshot manifest hash mismatch"
    );
    validate_snapshot_shape(
        &snapshot,
        metadata.total_bytes,
        metadata.chunk_size,
        &metadata.chunk_hashes_hex,
    )?;
    let signer_policy_hash = state
        .validator_lifecycle
        .as_ref()
        .context("committed state is missing validator lifecycle")?
        .authorized_signers_hash_hex
        .as_str();
    ensure!(
        metadata.schema == "trnm_cometbft_snapshot_metadata_v4"
            && metadata.chain_id == config.chain_id
            && metadata.height == height
            && height <= state.height
            && metadata.app_version == APP_VERSION
            && matches!(
                metadata.store_schema,
                SNAPSHOT_SQLITE_STORE_SCHEMA_V3 | SNAPSHOT_SQLITE_STORE_SCHEMA_V4
            )
            && metadata.state_codec == "sqlite-backup-v1"
            && metadata.auth_tree_codec == "jmt-sha256-v0.12.0+borsh-v1"
            && metadata.history_mode == "latest-only"
            && metadata.oldest_auth_version == height
            && metadata.authorized_signers_hash_hex == signer_policy_hash
            && manifest.payload_len == metadata.total_bytes,
        "retained snapshot metadata does not match the running application"
    );
    let expected_app_hash =
        trnm_finality_types::decode_hash32("retained snapshot app hash", &metadata.app_hash_hex)?;
    let (total_bytes, payload_hash, chunk_hashes_hex) = snapshot_file_hashes_v4(&payload_path)?;
    ensure!(
        total_bytes == metadata.total_bytes
            && hex::encode(payload_hash) == metadata.payload_hash_hex
            && chunk_hashes_hex == metadata.chunk_hashes_hex,
        "retained snapshot payload does not match its manifest"
    );
    let validated =
        store.validate_snapshot_database(&payload_path, metadata.height, expected_app_hash)?;
    let lifecycle = validated
        .validator_lifecycle
        .as_ref()
        .context("retained snapshot is missing validator lifecycle")?;
    validate_lifecycle_authorization(config, lifecycle)?;
    Ok(SnapshotRecord {
        snapshot,
        payload: SnapshotPayload::File {
            path: payload_path,
            len: usize::try_from(total_bytes)
                .context("snapshot payload length exceeds platform capacity")?,
        },
    })
}

fn cleanup_snapshot_directory(
    directory: &Path,
    records: &BTreeMap<u64, SnapshotRecord>,
) -> Result<()> {
    let mut keep = BTreeSet::new();
    for record in records.values() {
        if let SnapshotPayload::File { path, .. } = &record.payload {
            if let Some(name) = path.file_name() {
                keep.insert(name.to_os_string());
            }
            if let Some(name) = snapshot_manifest_path(path).file_name() {
                keep.insert(name.to_os_string());
            }
        }
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let recognized = name.to_str().is_some_and(|name| {
            name.len() > 20
                && name.as_bytes()[..20].iter().all(u8::is_ascii_digit)
                && name[20..].starts_with(".snapshot")
        });
        if recognized && !keep.contains(&name) && entry.file_type()?.is_file() {
            fs::remove_file(entry.path()).with_context(|| {
                format!("remove stale snapshot artifact {}", entry.path().display())
            })?;
        }
    }
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn build_store_snapshot(
    store: &ApplicationStore,
    chain_id: &str,
    pending: PendingDiskSnapshot,
) -> Result<SnapshotRecord> {
    let PendingDiskSnapshot {
        state,
        disk_path,
        pinned,
    } = pending;
    let snapshot_state = store.build_snapshot_database(&state, &disk_path, pinned)?;
    ensure!(
        (snapshot_state.height, snapshot_state.app_hash) == (state.height, state.app_hash),
        "SQLite snapshot captured a different application head"
    );
    let (total_bytes, payload_hash, chunk_hashes_hex) = snapshot_file_hashes_v4(&disk_path)?;
    let chunks =
        u32::try_from(chunk_hashes_hex.len()).context("snapshot chunk count exceeds u32")?;
    ensure!(
        chunks > 0 && chunks <= MAX_SNAPSHOT_CHUNKS,
        "application snapshot exceeds chunk limit"
    );
    let authorized_signers_hash_hex = snapshot_state
        .validator_lifecycle
        .as_ref()
        .context("snapshot is missing validator lifecycle")?
        .authorized_signers_hash_hex
        .clone();
    let metadata = SnapshotMetadataV4 {
        schema: "trnm_cometbft_snapshot_metadata_v4".to_string(),
        chain_id: chain_id.to_string(),
        height: snapshot_state.height,
        app_hash_hex: hex::encode(snapshot_state.app_hash),
        app_version: APP_VERSION,
        store_schema: SNAPSHOT_SQLITE_STORE_SCHEMA_V4,
        state_codec: "sqlite-backup-v1".to_string(),
        auth_tree_codec: "jmt-sha256-v0.12.0+borsh-v1".to_string(),
        history_mode: "latest-only".to_string(),
        oldest_auth_version: snapshot_state.height,
        authorized_signers_hash_hex,
        total_bytes,
        chunk_size: SNAPSHOT_CHUNK_SIZE as u32,
        payload_hash_hex: hex::encode(payload_hash),
        chunk_hashes_hex,
    };
    let metadata = serde_json::to_vec(&metadata)?;
    let manifest_hash = snapshot_manifest_hash_v4(&metadata);
    let record = SnapshotRecord {
        snapshot: Snapshot {
            height: snapshot_state.height,
            format: SNAPSHOT_FORMAT_V4,
            chunks,
            hash: Bytes::copy_from_slice(&manifest_hash),
            metadata: Bytes::from(metadata),
        },
        payload: SnapshotPayload::File {
            path: disk_path,
            len: usize::try_from(total_bytes)
                .context("snapshot byte length exceeds platform capacity")?,
        },
    };
    if let Err(error) = persist_disk_snapshot_manifest(&record) {
        let _ = record.payload.remove_file();
        return Err(error).context("persist disk snapshot manifest");
    }
    Ok(record)
}

fn build_snapshot(
    chain_id: &str,
    state: &AppState,
    auth_tree: &InMemoryAuthTree,
    disk_path: Option<PathBuf>,
) -> Result<SnapshotRecord> {
    ensure!(
        state.pending.is_none(),
        "cannot snapshot pending application state"
    );
    let bytes = encode_state(state, auth_tree)?;
    let chunk_count = bytes.len().div_ceil(SNAPSHOT_CHUNK_SIZE) as u32;
    ensure!(
        chunk_count > 0 && chunk_count <= MAX_SNAPSHOT_CHUNKS,
        "application snapshot exceeds chunk limit"
    );
    let chunk_hashes_hex = bytes
        .chunks(SNAPSHOT_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| {
            Ok(hex::encode(snapshot_chunk_hash(
                u32::try_from(index).context("snapshot chunk index exceeds u32")?,
                chunk,
            )))
        })
        .collect::<Result<Vec<_>>>()?;
    let metadata = SnapshotMetadataV3 {
        schema: "trnm_cometbft_snapshot_metadata_v3".to_string(),
        chain_id: chain_id.to_string(),
        height: state.height,
        app_hash_hex: hex::encode(state.app_hash),
        app_version: APP_VERSION,
        store_schema: SNAPSHOT_SQLITE_STORE_SCHEMA_V3,
        state_codec: "json-v4".to_string(),
        auth_tree_codec: "jmt-sha256-v0.12.0+borsh-v1".to_string(),
        oldest_auth_version: auth_tree
            .roots()
            .first_key_value()
            .map(|(version, _)| *version)
            .context("snapshot authenticated tree has no root")?,
        total_bytes: bytes.len() as u64,
        chunk_size: SNAPSHOT_CHUNK_SIZE as u32,
        payload_hash_hex: hex::encode(snapshot_payload_hash(&bytes)),
        chunk_hashes_hex,
    };
    let metadata = serde_json::to_vec(&metadata)?;
    let manifest_hash = snapshot_manifest_hash(&metadata);
    let payload = if let Some(path) = disk_path {
        persist_state_bytes(&path, &bytes)?;
        SnapshotPayload::File {
            path,
            len: bytes.len(),
        }
    } else {
        SnapshotPayload::Memory(bytes)
    };
    Ok(SnapshotRecord {
        snapshot: Snapshot {
            height: state.height,
            format: SNAPSHOT_FORMAT_V3,
            chunks: chunk_count,
            hash: Bytes::copy_from_slice(&manifest_hash),
            metadata: Bytes::from(metadata),
        },
        payload,
    })
}

fn persist_state_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create app state directory {}", parent.display()))?;
    }
    let temporary = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("json")
    ));
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("open temporary app state {}", temporary.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("protect temporary app state {}", temporary.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path).with_context(|| {
        format!(
            "replace committed app state {} with {}",
            path.display(),
            temporary.display()
        )
    })?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_lifecycle::{
        validator_key_proof_message, ValidatorKeyProofV1, VALIDATOR_GOVERNANCE_SCHEMA_V1,
        VALIDATOR_TRANSITION_SCHEMA_V1,
    };
    use crate::{
        poco_application::genesis_poco_application_authority_entry_v0,
        poco_snapshot::{
            poco_snapshot_manifest_key, PocoSnapshotEntryKindV0, PocoSnapshotEntryV0,
            PocoSnapshotManifestV0,
        },
        poco_transition::{encode_poco_snapshot_value_envelope_v0, PocoWritePermitV0},
    };
    use ed25519_dalek::SigningKey;
    use tendermint_proto::{
        google::protobuf::Timestamp,
        v0_38::abci::{
            RequestApplySnapshotChunk, RequestCheckTx, RequestFinalizeBlock, RequestInitChain,
            RequestLoadSnapshotChunk, RequestOfferSnapshot, RequestPrepareProposal,
            RequestProcessProposal, RequestQuery,
        },
        v0_38::crypto::public_key,
        v0_38::types::{ConsensusParams, VersionParams},
    };
    use trnm_finality_types::crypto::{public_key_hex, sign_hex};

    const POCO_TRANSITION_VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/poco-snapshot-transition-v0.json"
    );

    fn initial_validators() -> Vec<ConsensusValidatorV1> {
        let mut validators = (21u8..=24)
            .map(|seed| ConsensusValidatorV1 {
                public_key_hex: public_key_hex(&SigningKey::from_bytes(&[seed; 32])),
                voting_power: 10,
            })
            .collect::<Vec<_>>();
        validators.sort_by(|left, right| left.public_key_hex.cmp(&right.public_key_hex));
        validators
    }

    #[test]
    fn authenticated_runtime_overlay_uses_one_snapshot_and_preserves_typed_failures() {
        let root = std::env::temp_dir().join(format!(
            "trnm-authenticated-runtime-overlay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("create authenticated overlay test directory");
        let (app, _) = persistent_fixture(root.join("state.json"));
        let (height, app_hash) = app
            .height_and_app_hash()
            .expect("read authenticated overlay parent");
        let store = app.core.store.as_ref().expect("persistent test store");
        let snapshot = store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(height, app_hash)
            .expect("begin authenticated runtime overlay snapshot");

        let object_key = "fallible-overlay-object".to_string();
        let local_value = b"local-value".to_vec();
        let local_object = StoredObject {
            object_key_hex: object_key.clone(),
            object_type: "trnm.test-object.v0".to_string(),
            version: 7,
            value_hash_hex: hex::encode(hash_domain("trnm.state.object.value.v1", &[&local_value])),
            value_bytes: local_value.clone(),
        };
        let changes = BTreeMap::from([(object_key.clone(), local_object)]);
        let base_value = b"base-value".to_vec();
        let base = BTreeMap::from([(
            object_key.clone(),
            StoredObject {
                object_key_hex: object_key.clone(),
                object_type: "trnm.base-object.v0".to_string(),
                version: 2,
                value_hash_hex: hex::encode(hash_domain(
                    "trnm.state.object.value.v1",
                    &[&base_value],
                )),
                value_bytes: base_value,
            },
        )]);

        let overlay = AuthenticatedRuntimeOverlayObjects {
            base: &base,
            changes: &changes,
            snapshot: &snapshot,
        };
        let local = RuntimeTryStateViewV0::try_get(&overlay, &object_key)
            .expect("local overlay hit must not touch snapshot")
            .expect("local object exists");
        assert_eq!(local.object_type, "trnm.test-object.v0");
        assert_eq!(local.version, 7);
        assert_eq!(local.value_bytes, local_value);

        let empty = BTreeMap::new();
        let overlay = AuthenticatedRuntimeOverlayObjects {
            base: &empty,
            changes: &empty,
            snapshot: &snapshot,
        };
        let persisted = RuntimeTryStateViewV0::try_get(&overlay, &fee_policy_key())
            .expect("load persisted fee policy through pinned snapshot")
            .expect("genesis fee policy is authenticated");
        assert_eq!(persisted.object_type, FEE_POLICY_OBJECT_TYPE_V1);
        assert_eq!(
            RuntimeTryStateViewV0::try_get(&overlay, "missing-authenticated-object")
                .expect("verify snapshot non-membership"),
            None
        );
        assert!(matches!(
            RuntimeTryStateViewV0::try_get(&overlay, ""),
            Err(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage: store::AuthenticatedRuntimeReadStageV0::DeriveObjectKey,
                ..
            })
        ));

        snapshot
            .finish()
            .expect("finish authenticated overlay snapshot");
        drop(app);
        fs::remove_dir_all(root).expect("remove authenticated overlay test directory");
    }

    fn active_poco_genesis_fixture_with_state_path(
        state_path: Option<PathBuf>,
    ) -> (CometBftApplication, SigningKey, Vec<PocoSnapshotEntryV0>) {
        let vector: serde_json::Value = serde_json::from_str(POCO_TRANSITION_VECTOR).unwrap();
        let positives = vector["semantic_layout_corpus"]["positive_fixtures"]
            .as_array()
            .unwrap();
        let mut entries = [13_u8, 14_u8]
            .into_iter()
            .map(|kind| {
                let source = positives
                    .iter()
                    .find(|fixture| fixture["kind"].as_u64() == Some(u64::from(kind)))
                    .unwrap();
                PocoSnapshotEntryV0::new(
                    PocoSnapshotEntryKindV0::from_u8(kind).unwrap(),
                    hex::decode(source["logical_key_hex"].as_str().unwrap()).unwrap(),
                    hex::decode(source["value_cev0_hex"].as_str().unwrap()).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        entries.push(genesis_poco_application_authority_entry_v0().unwrap());
        let projection_from_entries = |entries: &[PocoSnapshotEntryV0]| {
            let manifest =
                PocoSnapshotManifestV0::from_entries(trnm_consensus_types::Height::new(0), entries)
                    .unwrap();
            let mut live = BTreeMap::new();
            live.insert(poco_snapshot_manifest_key().unwrap(), manifest.encode());
            for entry in entries {
                live.insert(entry.jmt_key().unwrap(), entry.value.clone());
            }
            let projection = take_and_validate_production_poco_projection_v0(0, &mut live)
                .unwrap()
                .unwrap();
            assert!(live.is_empty());
            projection
        };
        entries.sort_by(|left, right| {
            (left.kind, left.logical_key.as_slice())
                .cmp(&(right.kind, right.logical_key.as_slice()))
        });
        let provisional_projection = projection_from_entries(&entries);
        let (provisional_set, _) = active_consensus_configuration(&provisional_projection).unwrap();
        let relationship_provider = provisional_set
            .validators()
            .iter()
            .find(|validator| validator.id().as_bytes() == b"validator-a")
            .expect("active genesis fixture contains validator-a")
            .id()
            .as_bytes()
            .to_vec();
        let relationship_consumer = b"consumer-a".to_vec();
        let relationship_task = b"task-a".to_vec();
        let frame_identity = |output: &mut Vec<u8>, value: &[u8]| {
            output.extend_from_slice(&(value.len() as u32).to_be_bytes());
            output.extend_from_slice(value);
        };
        let mut relationship_identity = Vec::new();
        for value in [
            relationship_provider.as_slice(),
            relationship_consumer.as_slice(),
            relationship_task.as_slice(),
        ] {
            frame_identity(&mut relationship_identity, value);
        }
        let mut relationship_payload = relationship_identity.clone();
        // Reciprocal is authorizing; Unresolved (the generic kind-8 corpus
        // value) is intentionally rejected by certificate admission.
        relationship_payload.push(3);
        relationship_payload.extend_from_slice(&40u64.to_be_bytes());
        let (relationship_key, relationship_value) = encode_poco_snapshot_value_envelope_v0(
            PocoSnapshotEntryKindV0::RelationshipClassification,
            1,
            &relationship_identity,
            &relationship_payload,
        )
        .unwrap();
        entries.push(
            PocoSnapshotEntryV0::new(
                PocoSnapshotEntryKindV0::RelationshipClassification,
                relationship_key,
                relationship_value,
            )
            .unwrap(),
        );
        entries.sort_by(|left, right| {
            (left.kind, left.logical_key.as_slice())
                .cmp(&(right.kind, right.logical_key.as_slice()))
        });
        let projection = projection_from_entries(&entries);
        let (validator_set, parameters) = active_consensus_configuration(&projection).unwrap();
        assert!(validator_set
            .validators()
            .iter()
            .any(|validator| { validator.id().as_bytes() == relationship_provider.as_slice() }));
        let relationship = projection
            .entries()
            .iter()
            .find(|entry| entry.kind == PocoSnapshotEntryKindV0::RelationshipClassification)
            .unwrap();
        let relationship_parts = poco_transition::decode_poco_snapshot_value_parts_v0_exact(
            relationship.kind,
            &relationship.logical_key,
            &relationship.value,
        )
        .unwrap();
        match relationship_parts.fact {
            poco_semantics::SemanticFactV0::RelationshipClassification { class, expires_at } => {
                assert_ne!(class, poco_semantics::RelationshipClassV0::Unresolved);
                assert!(expires_at > 0);
            }
            _ => panic!("genesis relationship decoded as wrong semantic kind"),
        }
        let mut validators = validator_set
            .validators()
            .iter()
            .map(|validator| ConsensusValidatorV1 {
                public_key_hex: hex::encode(validator.consensus_key().as_bytes()),
                voting_power: validator.voting_power().get(),
            })
            .collect::<Vec<_>>();
        validators.sort_by(|left, right| left.public_key_hex.cmp(&right.public_key_hex));
        let chain_id = String::from_utf8(validator_set.chain_id().as_bytes().to_vec()).unwrap();
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let secondary_signing_key = SigningKey::from_bytes(&[12u8; 32]);
        let authority = PocoAuthorityConfigV0 {
            schema: POCO_AUTHORITY_CONFIG_SCHEMA_V0.to_string(),
            genesis_hash_hex: hex::encode(validator_set.genesis_hash().as_bytes()),
            protocol_profile_hash_hex: hex::encode(parameters.hash().as_bytes()),
        };
        let app = CometBftApplication::new(ConsensusAppConfig {
            schema: CONFIG_SCHEMA_V1.to_string(),
            chain_id: chain_id.clone(),
            authorized_signers: vec![
                AuthorizedSignerV1 {
                    signer_id: "did:operator:1".to_string(),
                    signer_role: "operator".to_string(),
                    public_key_hex: public_key_hex(&signing_key),
                },
                AuthorizedSignerV1 {
                    signer_id: "did:operator:2".to_string(),
                    signer_role: "operator".to_string(),
                    public_key_hex: public_key_hex(&secondary_signing_key),
                },
            ],
            poco_authority: Some(authority.clone()),
            state_path,
        })
        .unwrap();
        let genesis = GenesisAppStateV2 {
            schema: GENESIS_SCHEMA_V2.to_string(),
            chain_id: chain_id.clone(),
            app_version: APP_VERSION,
            authorized_signers: app.core.config.authorized_signers.clone(),
            poco_authority: Some(authority),
            poco_genesis_entries: entries
                .iter()
                .map(|entry| PocoGenesisEntryV0 {
                    kind: entry.kind as u8,
                    logical_key_hex: hex::encode(&entry.logical_key),
                    value_hex: hex::encode(&entry.value),
                })
                .collect(),
            validator_governance: ValidatorGovernanceV1 {
                schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
                signer_id: "did:operator:1".to_string(),
                min_activation_delay_blocks: 2,
                unsafe_allow_single_validator_genesis: false,
            },
            initial_validators: validators.clone(),
        };
        app.init_chain(RequestInitChain {
            chain_id,
            app_state_bytes: Bytes::from(serde_json::to_vec(&genesis).unwrap()),
            consensus_params: Some(ConsensusParams {
                version: Some(VersionParams { app: APP_VERSION }),
                ..Default::default()
            }),
            validators: validators_to_abci(&validators).unwrap(),
            ..Default::default()
        });
        (app, signing_key, entries)
    }

    fn active_poco_genesis_fixture() -> (CometBftApplication, SigningKey, Vec<PocoSnapshotEntryV0>)
    {
        active_poco_genesis_fixture_with_state_path(None)
    }

    fn authenticated_candidate_vector_v0() -> serde_json::Value {
        let vector_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../../docs/protocol/poco-bft-v0/vectors/\
             poco-authenticated-candidate-selection-v0.json",
        );
        let raw = fs::read(&vector_path).unwrap_or_else(|error| {
            panic!(
                "read authenticated-candidate vector {}: {error}",
                vector_path.display()
            )
        });
        serde_json::from_slice(&raw).unwrap_or_else(|error| {
            panic!(
                "decode authenticated-candidate vector {}: {error}",
                vector_path.display()
            )
        })
    }

    fn authenticated_candidate_scenario_entries_v0(
        scenario: &serde_json::Value,
    ) -> Vec<PocoSnapshotEntryV0> {
        let mut entries = scenario["source"]["head_projection"]["entries"]
            .as_array()
            .expect("candidate head projection entries")
            .iter()
            .map(|entry| {
                PocoSnapshotEntryV0::new(
                    PocoSnapshotEntryKindV0::from_u8(
                        u8::try_from(entry["kind"].as_u64().expect("candidate entry kind"))
                            .expect("candidate entry kind is u8"),
                    )
                    .expect("candidate entry kind is known"),
                    hex::decode(
                        entry["logical_key_hex"]
                            .as_str()
                            .expect("candidate logical key"),
                    )
                    .expect("decode candidate logical key"),
                    hex::decode(entry["value_hex"].as_str().expect("candidate entry value"))
                        .expect("decode candidate entry value"),
                )
                .expect("candidate source entry")
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            (left.kind, left.logical_key.as_slice())
                .cmp(&(right.kind, right.logical_key.as_slice()))
        });
        entries
    }

    /// Initializes the normal ABCI application with the exact empty-authority
    /// epoch-zero source accepted by production InitChain. The canonical
    /// scenario authority is installed later at manifest height 24 by an
    /// explicit test-only source bootstrap, matching the corpus's documented
    /// fixture-only epoch boundary without weakening the production API.
    fn authenticated_candidate_abci_fixture_v0(
        compact_profile: &serde_json::Value,
        state_path: Option<PathBuf>,
    ) -> (CometBftApplication, ConsensusAppConfig) {
        let entries =
            poco_application::fixture_authoring::authenticated_candidate_abci_genesis_entries_v0()
                .expect("candidate ABCI epoch-zero genesis entries");

        let manifest =
            PocoSnapshotManifestV0::from_entries(trnm_consensus_types::Height::new(0), &entries)
                .expect("candidate equivalent-bootstrap manifest");
        let mut live = BTreeMap::new();
        live.insert(
            poco_snapshot_manifest_key().expect("candidate manifest key"),
            manifest.encode(),
        );
        for entry in &entries {
            live.insert(
                entry.jmt_key().expect("candidate physical entry key"),
                entry.value.clone(),
            );
        }
        let projection = take_and_validate_production_poco_projection_v0(0, &mut live)
            .expect("candidate equivalent-bootstrap projection")
            .expect("candidate equivalent bootstrap is active");
        assert!(live.is_empty());
        poco_application::validate_application_authority_projection_v0(&projection)
            .expect("candidate epoch-zero genesis authority audit");
        let (validator_set, parameters) =
            active_consensus_configuration(&projection).expect("candidate genesis configuration");
        assert_eq!(
            validator_set.epoch().get(),
            0,
            "candidate ABCI genesis must retain the real epoch-zero source"
        );
        assert_eq!(
            hex::encode(parameters.hash().as_bytes()),
            compact_profile["active_parameters_hash_hex"]
                .as_str()
                .expect("candidate parameters hash")
        );
        let mut validators = validator_set
            .validators()
            .iter()
            .map(|validator| ConsensusValidatorV1 {
                public_key_hex: hex::encode(validator.consensus_key().as_bytes()),
                voting_power: validator.voting_power().get(),
            })
            .collect::<Vec<_>>();
        validators.sort_by(|left, right| left.public_key_hex.cmp(&right.public_key_hex));

        let chain_id = compact_profile["chain_id_utf8"]
            .as_str()
            .expect("candidate chain ID")
            .to_string();
        let operator = SigningKey::from_bytes(&[11; 32]);
        let authority = PocoAuthorityConfigV0 {
            schema: POCO_AUTHORITY_CONFIG_SCHEMA_V0.to_string(),
            genesis_hash_hex: compact_profile["genesis_hash_hex"]
                .as_str()
                .expect("candidate genesis hash")
                .to_string(),
            protocol_profile_hash_hex: compact_profile["active_parameters_hash_hex"]
                .as_str()
                .expect("candidate protocol profile")
                .to_string(),
        };
        let config = ConsensusAppConfig {
            schema: CONFIG_SCHEMA_V1.to_string(),
            chain_id: chain_id.clone(),
            authorized_signers: vec![AuthorizedSignerV1 {
                signer_id: "did:operator:1".to_string(),
                signer_role: "operator".to_string(),
                public_key_hex: public_key_hex(&operator),
            }],
            poco_authority: Some(authority.clone()),
            state_path,
        };
        let app = CometBftApplication::new(config.clone()).expect("candidate ABCI application");
        let genesis = GenesisAppStateV2 {
            schema: GENESIS_SCHEMA_V2.to_string(),
            chain_id: chain_id.clone(),
            app_version: APP_VERSION,
            authorized_signers: config.authorized_signers.clone(),
            poco_authority: Some(authority),
            poco_genesis_entries: entries
                .iter()
                .map(|entry| PocoGenesisEntryV0 {
                    kind: entry.kind as u8,
                    logical_key_hex: hex::encode(&entry.logical_key),
                    value_hex: hex::encode(&entry.value),
                })
                .collect(),
            validator_governance: ValidatorGovernanceV1 {
                schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
                signer_id: "did:operator:1".to_string(),
                min_activation_delay_blocks: 2,
                unsafe_allow_single_validator_genesis: false,
            },
            initial_validators: validators.clone(),
        };
        app.init_chain(RequestInitChain {
            chain_id,
            app_state_bytes: Bytes::from(
                serde_json::to_vec(&genesis).expect("encode candidate ABCI genesis"),
            ),
            consensus_params: Some(ConsensusParams {
                version: Some(VersionParams { app: APP_VERSION }),
                ..Default::default()
            }),
            validators: validators_to_abci(&validators).expect("candidate ABCI validators"),
            ..Default::default()
        });
        (app, config)
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationFullGenesisExportV0 {
        schema: &'static str,
        schema_version: u16,
        initial: PocoApplicationFullGenesisInitialV0,
        authoring_nullifier_state: PocoApplicationAuthoringNullifierStateV0,
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationFullGenesisInitialV0 {
        version: u64,
        jmt_root_hex: String,
        active_genesis: PocoApplicationActiveGenesisExportV0,
        production_context: PocoApplicationProductionContextExportV0,
        history: Vec<PocoApplicationHistoryExportV0>,
        projection: PocoApplicationProjectionExportV0,
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationProductionContextExportV0 {
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

    #[derive(serde::Serialize)]
    struct PocoApplicationActiveGenesisExportV0 {
        chain_id_utf8: String,
        genesis_hash_hex: String,
        validator_lifecycle: PocoApplicationNamedRecordExportV0,
        poco_authority_config: PocoApplicationNamedRecordExportV0,
        active_parameters: PocoApplicationActiveParametersExportV0,
        other_apphash_writes: Vec<PocoApplicationPhysicalWriteExportV0>,
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationNamedRecordExportV0 {
        physical_key_hex: String,
        value_hex: String,
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationActiveParametersExportV0 {
        physical_key_hex: String,
        value_hex: String,
        cev0_hex: String,
        hash_hex: String,
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationHistoryExportV0 {
        version: u64,
        jmt_root_hex: String,
        writes: Vec<PocoApplicationPhysicalWriteExportV0>,
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationPhysicalWriteExportV0 {
        physical_key_hex: String,
        value_hex: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationProjectionExportV0 {
        manifest_hex: String,
        entries_root_hex: String,
        entries: Vec<PocoApplicationEntryExportV0>,
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationEntryExportV0 {
        kind: u8,
        logical_key_hex: String,
        value_hex: String,
        canonical_entry_cev0_hex: String,
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationAuthoringNullifierStateV0 {
        root_hex: String,
        count: u64,
        occupied: Vec<PocoApplicationOccupiedNullifierExportV0>,
    }

    #[derive(serde::Serialize)]
    struct PocoApplicationOccupiedNullifierExportV0 {
        family: u8,
        identifier_hex: String,
    }

    /// Manual v2 vector-authoring exporter.  The source is the real active
    /// InitChain fixture above, and every emitted physical value is read back
    /// from the committed authenticated tree.  A parallel ApplicationStore
    /// InitChain must prove the same root and every emitted leaf before any
    /// JSON is printed.
    #[test]
    #[ignore = "manual active-genesis full-AppHash vector exporter"]
    fn export_active_poco_application_full_genesis_v0() {
        let (memory, _, entries) = active_poco_genesis_fixture();
        let production_context = {
            let state = memory.core.state.lock().unwrap();
            let delta = memory.start_block_delta(&state).unwrap();
            let (authenticated, validator_set, parameters) = memory
                .validated_live_poco_configuration(&state, &delta)
                .unwrap()
                .expect("active genesis production PoCO configuration");
            assert_eq!(authenticated.version(), state.height);
            assert_eq!(authenticated.state_root(), state.app_hash);
            // This invokes the same private constructor used by block
            // execution; the export never accepts a Node-supplied context.
            memory
                .start_poco_application_overlay(&state, &delta)
                .unwrap();
            PocoApplicationProductionContextExportV0 {
                chain_id_utf8: String::from_utf8(validator_set.chain_id().as_bytes().to_vec())
                    .unwrap(),
                genesis_hash_hex: hex::encode(validator_set.genesis_hash().as_bytes()),
                source_version: state.height,
                source_root_hex: hex::encode(state.app_hash),
                target_height: state.height.checked_add(1).unwrap(),
                active_epoch: validator_set.epoch().get(),
                active_parameters_cev0_hex: hex::encode(parameters.canonical_bytes()),
                active_parameters_hash_hex: hex::encode(parameters.hash().as_bytes()),
                authority_signer_commitment_hex: hex::encode(
                    poco_application_governance_signer_commitment_v0(
                        effective_validator_lifecycle(&state, &delta).unwrap(),
                    ),
                ),
            }
        };
        let tree = memory.core.auth_tree.lock().unwrap();
        let version = 0_u64;
        let full_root: [u8; 32] = tree.root_hash(version).unwrap().into();
        let live = tree.verified_live_values(version).unwrap();
        drop(tree);

        let persistent_root = std::env::temp_dir().join(format!(
            "trnm-poco-application-genesis-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state_path = persistent_root.join("app-state.json");
        let (persistent, _, persistent_entries) =
            active_poco_genesis_fixture_with_state_path(Some(state_path));
        assert_eq!(persistent_entries, entries);
        let committed = persistent.core.state.lock().unwrap().clone();
        assert_eq!(committed.height, version);
        assert_eq!(committed.app_hash, full_root);
        let store = persistent.core.store.as_ref().unwrap();
        for (key, value) in &live {
            let proof = store.prove(version, key.clone()).unwrap();
            assert_eq!(<[u8; 32]>::from(proof.root_hash), full_root);
            assert_eq!(proof.value.as_deref(), Some(value.as_slice()));
        }

        let lifecycle_key = validator_state_key().unwrap();
        let authority_key = stored_object_key(&poco_authority_object_key()).unwrap();
        let active_parameters_entry = entries
            .iter()
            .find(|entry| entry.kind == PocoSnapshotEntryKindV0::ConsensusParameters)
            .unwrap();
        let active_parameters_key = active_parameters_entry.jmt_key().unwrap();
        let active_parameters_parts = poco_transition::decode_poco_snapshot_value_parts_v0_exact(
            PocoSnapshotEntryKindV0::ConsensusParameters,
            &active_parameters_entry.logical_key,
            &active_parameters_entry.value,
        )
        .unwrap();
        let active_parameters = trnm_consensus_types::decode_consensus_parameters_v0_exact(
            active_parameters_parts.payload,
        )
        .unwrap();

        let mut projection_live = live.clone();
        let projection =
            take_and_validate_production_poco_projection_v0(version, &mut projection_live)
                .unwrap()
                .unwrap();
        let projection_entries = projection
            .entries()
            .iter()
            .map(|entry| PocoApplicationEntryExportV0 {
                kind: entry.kind as u8,
                logical_key_hex: hex::encode(&entry.logical_key),
                value_hex: hex::encode(&entry.value),
                canonical_entry_cev0_hex: hex::encode(entry.canonical_bytes()),
            })
            .collect::<Vec<_>>();
        let history_writes = live
            .iter()
            .map(|(key, value)| PocoApplicationPhysicalWriteExportV0 {
                physical_key_hex: hex::encode(key),
                value_hex: Some(hex::encode(value)),
            })
            .collect::<Vec<_>>();
        let other_apphash_writes = live
            .iter()
            .filter(|(key, _)| {
                *key != &lifecycle_key && *key != &authority_key && *key != &active_parameters_key
            })
            .map(|(key, value)| PocoApplicationPhysicalWriteExportV0 {
                physical_key_hex: hex::encode(key),
                value_hex: Some(hex::encode(value)),
            })
            .collect::<Vec<_>>();
        let authority = memory.core.config.poco_authority.as_ref().unwrap();
        let application_authority_entry = entries
            .iter()
            .find(|entry| entry.kind == PocoSnapshotEntryKindV0::ApplicationAuthorityState)
            .unwrap();
        let application_authority_parts =
            poco_transition::decode_poco_snapshot_value_parts_v0_exact(
                PocoSnapshotEntryKindV0::ApplicationAuthorityState,
                &application_authority_entry.logical_key,
                &application_authority_entry.value,
            )
            .unwrap();
        let application_authority =
            poco_application::PocoApplicationAuthorityStateV0::decode_exact(
                application_authority_parts.payload,
            )
            .unwrap();
        assert_eq!(application_authority.nullifier_count(), 0);
        assert_eq!(
            application_authority.nullifier_root().unwrap(),
            poco_nullifier::empty_poco_nullifier_root_v0()
        );
        let exported = PocoApplicationFullGenesisExportV0 {
            schema: "trnm.poco-bft.application-full-genesis-export.v0",
            schema_version: 0,
            initial: PocoApplicationFullGenesisInitialV0 {
                version,
                jmt_root_hex: hex::encode(full_root),
                active_genesis: PocoApplicationActiveGenesisExportV0 {
                    chain_id_utf8: memory.core.config.chain_id.clone(),
                    genesis_hash_hex: authority.genesis_hash_hex.clone(),
                    validator_lifecycle: PocoApplicationNamedRecordExportV0 {
                        physical_key_hex: hex::encode(&lifecycle_key),
                        value_hex: hex::encode(live.get(&lifecycle_key).unwrap()),
                    },
                    poco_authority_config: PocoApplicationNamedRecordExportV0 {
                        physical_key_hex: hex::encode(&authority_key),
                        value_hex: hex::encode(live.get(&authority_key).unwrap()),
                    },
                    active_parameters: PocoApplicationActiveParametersExportV0 {
                        physical_key_hex: hex::encode(&active_parameters_key),
                        value_hex: hex::encode(live.get(&active_parameters_key).unwrap()),
                        cev0_hex: hex::encode(active_parameters_parts.payload),
                        hash_hex: hex::encode(active_parameters.hash().as_bytes()),
                    },
                    other_apphash_writes,
                },
                production_context,
                history: vec![PocoApplicationHistoryExportV0 {
                    version,
                    jmt_root_hex: hex::encode(full_root),
                    writes: history_writes,
                }],
                projection: PocoApplicationProjectionExportV0 {
                    manifest_hex: hex::encode(projection.manifest().encode()),
                    entries_root_hex: hex::encode(projection.manifest().entries_root()),
                    entries: projection_entries,
                },
            },
            authoring_nullifier_state: PocoApplicationAuthoringNullifierStateV0 {
                root_hex: hex::encode(application_authority.nullifier_root().unwrap()),
                count: application_authority.nullifier_count(),
                occupied: Vec::new(),
            },
        };
        let encoded = serde_json::to_vec_pretty(&exported).unwrap();
        if let Some(path) = std::env::var_os("TRNM_POCO_APPLICATION_GENESIS_EXPORT") {
            fs::write(&path, &encoded).unwrap();
            eprintln!(
                "wrote active PoCO application full-genesis export to {}",
                PathBuf::from(path).display()
            );
        } else {
            println!("{}", String::from_utf8(encoded).unwrap());
        }

        drop(persistent);
        fs::remove_dir_all(&persistent_root).unwrap();
    }

    #[test]
    fn authenticated_query_floor_advances_only_on_retention_intervals() {
        assert_eq!(authenticated_query_floor(8_192), 0);
        assert_eq!(authenticated_query_floor(8_447), 0);
        assert_eq!(authenticated_query_floor(8_448), 257);
        assert_eq!(authenticated_query_floor(8_704), 513);
    }

    #[test]
    fn poco_snapshot_lead_is_bounded_by_authenticated_history_retention() {
        let mut fields =
            trnm_consensus_types::ConsensusParametersV0::reference_shadow_v0().fields();
        fields.snapshot_lead_blocks = AUTH_PROOF_RETENTION_VERSIONS;
        let exact = trnm_consensus_types::ConsensusParametersV0::new(fields).unwrap();
        validate_poco_parameter_retention_v0(&exact).unwrap();

        fields.snapshot_lead_blocks = AUTH_PROOF_RETENTION_VERSIONS + 1;
        let over = trnm_consensus_types::ConsensusParametersV0::new(fields).unwrap();
        assert!(validate_poco_parameter_retention_v0(&over).is_err());
    }

    #[test]
    fn consensus_block_limit_is_compatible_with_validation_journal_capacity() {
        let maximum = u32::try_from(store::MAX_NATIVE_VALIDATION_BODY_RECORD_BYTES).unwrap();
        let mut fields =
            trnm_consensus_types::ConsensusParametersV0::reference_shadow_v0().fields();
        fields.max_block_bytes = maximum;
        fields.max_consensus_message_bytes = maximum + 1;
        let exact = trnm_consensus_types::ConsensusParametersV0::new(fields).unwrap();
        validate_poco_parameter_retention_v0(&exact).unwrap();

        fields.max_consensus_message_bytes = maximum + 1024;
        let wider_message = trnm_consensus_types::ConsensusParametersV0::new(fields).unwrap();
        validate_poco_parameter_retention_v0(&wider_message).unwrap();

        fields.max_block_bytes = maximum + 1;
        let oversized = trnm_consensus_types::ConsensusParametersV0::new(fields).unwrap();
        assert!(validate_poco_parameter_retention_v0(&oversized).is_err());
    }

    #[test]
    fn poco_application_operation_is_identical_across_abci_and_authenticated_jmt() {
        let (app, signing_key, _) = active_poco_genesis_fixture();
        let before = app.height_and_app_hash().unwrap();
        let operation = {
            let state = app.core.state.lock().unwrap();
            let delta = app.start_block_delta(&state).unwrap();
            app.start_poco_application_overlay(&state, &delta)
                .unwrap()
                .test_define_meter_operation_v0()
                .unwrap()
        };
        let tx = poco_application_tx(
            &signing_key,
            &app.core.config.chain_id,
            "poco-application-integration-1",
            1,
            &operation,
        );
        let expected = {
            let state = app.core.state.lock().unwrap();
            app.execute_block(&state, std::slice::from_ref(&tx), 2_000, &[])
                .unwrap()
                .app_hash
        };

        let prepared = app.prepare_proposal(RequestPrepareProposal {
            txs: vec![tx.clone()],
            max_tx_bytes: 1024 * 1024,
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(prepared.txs, vec![tx.clone()]);
        assert_eq!(
            app.process_proposal(RequestProcessProposal {
                txs: prepared.txs.clone(),
                height: 1,
                time: block_time(),
                ..Default::default()
            })
            .status,
            response_process_proposal::ProposalStatus::Accept as i32
        );
        let finalized = app.finalize_block(RequestFinalizeBlock {
            txs: prepared.txs,
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(finalized.app_hash.as_ref(), expected);
        app.commit();
        assert_eq!(app.height_and_app_hash().unwrap(), (1, expected));
        assert_ne!(before.1, expected);

        let authenticated = app.production_poco_projection_at(1).unwrap();
        assert_eq!(
            authenticated.projection().manifest().cutoff_height().get(),
            1
        );
        assert!(authenticated
            .projection()
            .entries()
            .iter()
            .any(|entry| { entry.kind == PocoSnapshotEntryKindV0::MeterDefinition }));
        let authority = authenticated
            .projection()
            .entries()
            .iter()
            .find(|entry| entry.kind == PocoSnapshotEntryKindV0::ApplicationAuthorityState)
            .unwrap();
        let parts = poco_transition::decode_poco_snapshot_value_parts_v0_exact(
            authority.kind,
            &authority.logical_key,
            &authority.value,
        )
        .unwrap();
        let authority =
            poco_application::PocoApplicationAuthorityStateV0::decode_exact(parts.payload).unwrap();
        assert_eq!(authority.revision(), 2);
        assert_eq!(authority.last_target_height(), 1);
        assert_eq!(authority.nullifier_count(), 2);

        let committed = app.height_and_app_hash().unwrap();
        assert_eq!(
            app.process_proposal(RequestProcessProposal {
                txs: vec![tx],
                height: 2,
                time: block_time(),
                ..Default::default()
            })
            .status,
            response_process_proposal::ProposalStatus::Reject as i32
        );
        assert_eq!(app.height_and_app_hash().unwrap(), committed);
    }

    #[test]
    fn poco_application_rejects_non_governance_operator_before_overlay_mutation() {
        let (app, _, _) = active_poco_genesis_fixture();
        let operation = {
            let state = app.core.state.lock().unwrap();
            let delta = app.start_block_delta(&state).unwrap();
            app.start_poco_application_overlay(&state, &delta)
                .unwrap()
                .test_define_meter_operation_v0()
                .unwrap()
        };
        let secondary = SigningKey::from_bytes(&[12u8; 32]);
        let envelope = SignedCommandEnvelopeV1::sign(
            &app.core.config.chain_id,
            "poco-application-wrong-operator",
            "did:operator:2",
            "operator",
            1,
            1_000,
            10_000,
            POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &operation,
            &secondary,
        )
        .unwrap();
        let before = app.height_and_app_hash().unwrap();
        assert_eq!(
            app.process_proposal(RequestProcessProposal {
                txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
                height: 1,
                time: block_time(),
                ..Default::default()
            })
            .status,
            response_process_proposal::ProposalStatus::Reject as i32
        );
        assert_eq!(app.height_and_app_hash().unwrap(), before);
        assert!(app.core.state.lock().unwrap().pending.is_none());
    }

    #[test]
    fn poco_application_sqlite_failpoints_recover_old_or_new_authority_atomically() {
        let root = std::env::temp_dir().join(format!(
            "trnm-poco-application-atomicity-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (app, signing_key, _) = active_poco_genesis_fixture_with_state_path(Some(state_path));
        let config = app.core.config.clone();
        let source = app.height_and_app_hash().unwrap();
        let operation = {
            let state = app.core.state.lock().unwrap();
            let delta = app.start_block_delta(&state).unwrap();
            app.start_poco_application_overlay(&state, &delta)
                .unwrap()
                .test_define_meter_operation_v0()
                .unwrap()
        };
        let tx = poco_application_tx(
            &signing_key,
            &app.core.config.chain_id,
            "poco-application-atomicity-1",
            1,
            &operation,
        );
        let pending = {
            let state = app.core.state.lock().unwrap();
            app.execute_block(&state, std::slice::from_ref(&tx), 2_000, &[])
                .unwrap()
        };
        app.core
            .store
            .as_ref()
            .unwrap()
            .persist_transition_with_failpoint(
                &app.core.state.lock().unwrap(),
                &pending,
                store::StoreFailpoint::BeforeSqlCommit,
            )
            .unwrap_err();
        drop(app);

        let app = CometBftApplication::new(config.clone()).unwrap();
        assert_eq!(app.height_and_app_hash().unwrap(), source);
        let pending = {
            let state = app.core.state.lock().unwrap();
            app.execute_block(&state, &[tx], 2_000, &[]).unwrap()
        };
        let target = (pending.height, pending.app_hash);
        app.core
            .store
            .as_ref()
            .unwrap()
            .persist_transition_with_failpoint(
                &app.core.state.lock().unwrap(),
                &pending,
                store::StoreFailpoint::AfterSqlCommitBeforeStatus,
            )
            .unwrap_err();
        drop(app);

        let restarted = CometBftApplication::new(config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), target);
        let projection = restarted.production_poco_projection_at(1).unwrap();
        assert!(projection
            .projection()
            .entries()
            .iter()
            .any(|entry| { entry.kind == PocoSnapshotEntryKindV0::MeterDefinition }));
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn orphan_application_authority_is_rejected_by_codec_and_sqlite_precommit() {
        let build_writes = |source_entries: &[PocoSnapshotEntryV0]| {
            let orphan = poco_application::test_orphan_meter_authority_entry_v0().unwrap();
            let mut target_entries = source_entries
                .iter()
                .filter(|entry| entry.kind != PocoSnapshotEntryKindV0::ApplicationAuthorityState)
                .cloned()
                .collect::<Vec<_>>();
            target_entries.push(orphan.clone());
            target_entries.sort_by(|left, right| {
                (left.kind, left.logical_key.as_slice())
                    .cmp(&(right.kind, right.logical_key.as_slice()))
            });
            let manifest = PocoSnapshotManifestV0::from_entries(
                trnm_consensus_types::Height::new(1),
                &target_entries,
            )
            .unwrap();
            vec![
                AuthWrite::put_poco_snapshot(
                    PocoWritePermitV0::test_only(),
                    poco_snapshot_manifest_key().unwrap(),
                    manifest.encode(),
                )
                .unwrap(),
                AuthWrite::put_poco_snapshot(
                    PocoWritePermitV0::test_only(),
                    orphan.jmt_key().unwrap(),
                    orphan.value,
                )
                .unwrap(),
            ]
        };

        let (memory_app, _, entries) = active_poco_genesis_fixture();
        let mut memory_state = memory_app.core.state.lock().unwrap().clone();
        let mut memory_tree = memory_app.core.auth_tree.lock().unwrap().clone();
        let update = memory_tree
            .plan_put_value_set(1, build_writes(&entries))
            .unwrap();
        memory_state.height = 1;
        memory_state.app_hash = memory_tree.apply(update).unwrap().into();
        assert!(encode_state(&memory_state, &memory_tree).is_err());
        drop(memory_app);

        let root = std::env::temp_dir().join(format!(
            "trnm-poco-orphan-authority-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let (persistent, _, entries) =
            active_poco_genesis_fixture_with_state_path(Some(root.join("app-state.json")));
        let config = persistent.core.config.clone();
        let current = persistent.core.state.lock().unwrap().clone();
        let auth_update = persistent
            .core
            .store
            .as_ref()
            .unwrap()
            .plan_auth_update(1, build_writes(&entries))
            .unwrap();
        let pending = PendingBlock {
            height: 1,
            app_hash: auth_update.root_hash.into(),
            tx_results: Vec::new(),
            native_execution: test_authorized_empty_native_execution(
                current.height,
                current.app_hash,
                1,
                auth_update.root_hash.into(),
            ),
            validator_updates: Vec::new(),
            delta: BlockDelta::default(),
            auth_update,
            poco_checkpoint_execution: None,
        };
        let error = persistent
            .core
            .store
            .as_ref()
            .unwrap()
            .persist_transition(&current, &pending, 0)
            .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("application authority references absent semantic entry"),
            "{rendered}"
        );
        drop(persistent);
        let restarted = CometBftApplication::new(config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap().0, 0);
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    fn fixture() -> (CometBftApplication, SignedCommandEnvelopeV1) {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let app = CometBftApplication::new(ConsensusAppConfig {
            schema: CONFIG_SCHEMA_V1.to_string(),
            chain_id: "trnm-comet-spike".to_string(),
            authorized_signers: vec![AuthorizedSignerV1 {
                signer_id: "did:operator:1".to_string(),
                signer_role: "operator".to_string(),
                public_key_hex: public_key_hex(&signing_key),
            }],
            poco_authority: None,
            state_path: None,
        })
        .unwrap();
        app.init_chain(genesis_request(&app));
        let envelope = SignedCommandEnvelopeV1::sign(
            "trnm-comet-spike",
            "command-1",
            "did:operator:1",
            "operator",
            1,
            1_000,
            10_000,
            "opaque_fixture_v1",
            b"deterministic-payload",
            &signing_key,
        )
        .unwrap();
        (app, envelope)
    }

    #[test]
    fn signer_policy_rejects_undecodable_and_small_order_ed25519_keys() {
        const UNDECODABLE_PUBLIC_KEY: [u8; 32] = [
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const IDENTITY_PUBLIC_KEY: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let valid_key = SigningKey::from_bytes(&[11u8; 32]);
        let mut config = ConsensusAppConfig {
            schema: CONFIG_SCHEMA_V1.to_string(),
            chain_id: "trnm-comet-spike".to_string(),
            authorized_signers: vec![AuthorizedSignerV1 {
                signer_id: "did:operator:1".to_string(),
                signer_role: "operator".to_string(),
                public_key_hex: public_key_hex(&valid_key),
            }],
            poco_authority: None,
            state_path: None,
        };
        config.validate().unwrap();

        config.authorized_signers[0].public_key_hex = hex::encode(UNDECODABLE_PUBLIC_KEY);
        assert!(config.validate().is_err());
        config.authorized_signers[0].public_key_hex = hex::encode(IDENTITY_PUBLIC_KEY);
        assert!(config.validate().is_err());
    }

    #[test]
    fn app_command_policy_helper_rejects_identity_key_forge() {
        const IDENTITY_POINT: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let mut envelope = SignedCommandEnvelopeV1::sign(
            "trnm-comet-spike",
            "strict-command-1",
            "did:operator:1",
            "operator",
            1,
            1_000,
            10_000,
            "opaque_fixture_v1",
            b"deterministic-payload",
            &signing_key,
        )
        .unwrap();
        let honest_policy = vec![AuthorizedSignerV1 {
            signer_id: envelope.signer_id.clone(),
            signer_role: envelope.signer_role.clone(),
            public_key_hex: envelope.public_key_hex.clone(),
        }];
        validate_signed_command_envelope_against_policy_v1(
            &envelope,
            "trnm-comet-spike",
            1_500,
            &honest_policy,
        )
        .unwrap();

        envelope.public_key_hex = hex::encode(IDENTITY_POINT);
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&IDENTITY_POINT);
        envelope.signature_hex = hex::encode(signature);
        let weak_policy = vec![AuthorizedSignerV1 {
            signer_id: envelope.signer_id.clone(),
            signer_role: envelope.signer_role.clone(),
            public_key_hex: envelope.public_key_hex.clone(),
        }];
        assert!(validate_signed_command_envelope_against_policy_v1(
            &envelope,
            "trnm-comet-spike",
            1_500,
            &weak_policy,
        )
        .is_err());
    }

    fn persistent_fixture(state_path: PathBuf) -> (CometBftApplication, SignedCommandEnvelopeV1) {
        let (fixture_app, envelope) = fixture();
        let app = CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(state_path),
            ..fixture_app.core.config.clone()
        })
        .unwrap();
        initialize(&app);
        (app, envelope)
    }

    #[test]
    fn poco_authority_is_genesis_authenticated_and_restart_bound() {
        let root = std::env::temp_dir().join(format!(
            "trnm-poco-authority-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("authority-state.json");
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let authority = PocoAuthorityConfigV0 {
            schema: POCO_AUTHORITY_CONFIG_SCHEMA_V0.to_string(),
            genesis_hash_hex: hex::encode([7u8; 32]),
            protocol_profile_hash_hex: hex::encode([8u8; 32]),
        };
        let config = ConsensusAppConfig {
            schema: CONFIG_SCHEMA_V1.to_string(),
            chain_id: "trnm-comet-spike".to_string(),
            authorized_signers: vec![AuthorizedSignerV1 {
                signer_id: "did:operator:1".to_string(),
                signer_role: "operator".to_string(),
                public_key_hex: public_key_hex(&signing_key),
            }],
            poco_authority: Some(authority.clone()),
            state_path: Some(state_path),
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        app.init_chain(genesis_request(&app));
        // Configured authority with an explicitly empty PoCO namespace is a
        // supported inert/legacy deployment. Checkpoint discovery must not
        // turn that state into a first-block liveness failure.
        finalize_and_commit(&app, 1, Vec::new());
        assert_eq!(app.height_and_app_hash().unwrap().0, 1);
        let committed = app
            .core
            .store
            .as_ref()
            .unwrap()
            .load_object(&poco_authority_object_key())
            .unwrap();
        assert_eq!(committed, Some(poco_authority_object(&authority)));
        drop(app);

        CometBftApplication::new(config.clone()).unwrap();
        let mut wrong = config;
        wrong
            .poco_authority
            .as_mut()
            .unwrap()
            .protocol_profile_hash_hex = hex::encode([9u8; 32]);
        assert!(CometBftApplication::new(wrong).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn genesis_rejects_local_only_poco_authority() {
        let (app, _) = fixture();
        let mut request = genesis_request(&app);
        let mut genesis: GenesisAppStateV2 =
            serde_json::from_slice(&request.app_state_bytes).unwrap();
        genesis.poco_authority = Some(PocoAuthorityConfigV0 {
            schema: POCO_AUTHORITY_CONFIG_SCHEMA_V0.to_string(),
            genesis_hash_hex: hex::encode([7u8; 32]),
            protocol_profile_hash_hex: hex::encode([8u8; 32]),
        });
        request.app_state_bytes = Bytes::from(serde_json::to_vec(&genesis).unwrap());
        assert!(app.validate_genesis(&request).is_err());
    }

    fn production_poco_writes(manifest_height: u64, include_hidden_leaf: bool) -> Vec<AuthWrite> {
        let identity = |consumer: &[u8], key: &[u8], provider: &[u8]| {
            let mut bytes = Vec::new();
            for value in [consumer, key, provider] {
                bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
                bytes.extend_from_slice(value);
            }
            bytes
        };
        let entry = |consumer: &[u8], key: &[u8], provider: &[u8], nonce: u64| {
            let identity = identity(consumer, key, provider);
            let mut payload = identity.clone();
            payload.extend_from_slice(&nonce.to_be_bytes());
            let (logical_key, value) = encode_poco_snapshot_value_envelope_v0(
                PocoSnapshotEntryKindV0::ConsumerNonce,
                1,
                &identity,
                &payload,
            )
            .unwrap();
            PocoSnapshotEntryV0::new(PocoSnapshotEntryKindV0::ConsumerNonce, logical_key, value)
                .unwrap()
        };
        let committed = entry(b"consumer-a", b"key-a", b"provider-a", 1);
        let manifest = PocoSnapshotManifestV0::from_entries(
            trnm_consensus_types::Height::new(manifest_height),
            std::slice::from_ref(&committed),
        )
        .unwrap();
        let mut writes = vec![
            AuthWrite::put_poco_snapshot(
                PocoWritePermitV0::test_only(),
                poco_snapshot_manifest_key().unwrap(),
                manifest.encode(),
            )
            .unwrap(),
            AuthWrite::put_poco_snapshot(
                PocoWritePermitV0::test_only(),
                committed.jmt_key().unwrap(),
                committed.value,
            )
            .unwrap(),
        ];
        if include_hidden_leaf {
            let hidden = entry(b"consumer-b", b"key-b", b"provider-b", 1);
            writes.push(
                AuthWrite::put_poco_snapshot(
                    PocoWritePermitV0::test_only(),
                    hidden.jmt_key().unwrap(),
                    hidden.value,
                )
                .unwrap(),
            );
        }
        writes
    }

    fn block_time() -> Option<Timestamp> {
        Some(Timestamp {
            seconds: 2,
            nanos: 0,
        })
    }

    fn genesis_request(app: &CometBftApplication) -> RequestInitChain {
        let initial_validators = initial_validators();
        let genesis = GenesisAppStateV2 {
            schema: GENESIS_SCHEMA_V2.to_string(),
            chain_id: app.core.config.chain_id.clone(),
            app_version: APP_VERSION,
            authorized_signers: app.core.config.authorized_signers.clone(),
            poco_authority: app.core.config.poco_authority.clone(),
            poco_genesis_entries: Vec::new(),
            validator_governance: ValidatorGovernanceV1 {
                schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
                signer_id: "did:operator:1".to_string(),
                min_activation_delay_blocks: 2,
                unsafe_allow_single_validator_genesis: false,
            },
            initial_validators: initial_validators.clone(),
        };
        RequestInitChain {
            chain_id: app.core.config.chain_id.clone(),
            app_state_bytes: Bytes::from(serde_json::to_vec(&genesis).unwrap()),
            consensus_params: Some(ConsensusParams {
                version: Some(VersionParams { app: APP_VERSION }),
                ..Default::default()
            }),
            validators: validators_to_abci(&initial_validators).unwrap(),
            ..Default::default()
        }
    }

    fn initialize(app: &CometBftApplication) {
        app.init_chain(genesis_request(app));
    }

    fn wait_for_snapshot(app: &CometBftApplication, height: u64) -> Snapshot {
        for _ in 0..1_000 {
            if let Some(snapshot) = app
                .list_snapshots()
                .snapshots
                .into_iter()
                .find(|snapshot| snapshot.height == height)
            {
                return snapshot;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("snapshot {height} was not built before the test deadline");
    }

    fn validator(seed: u8, voting_power: u64) -> ConsensusValidatorV1 {
        ConsensusValidatorV1 {
            public_key_hex: public_key_hex(&SigningKey::from_bytes(&[seed; 32])),
            voting_power,
        }
    }

    fn validator_transition(
        app: &CometBftApplication,
        transition_id: &str,
        activation_height: u64,
        mut target_validators: Vec<ConsensusValidatorV1>,
        proof_seeds: &[u8],
    ) -> ValidatorSetTransitionV1 {
        target_validators.sort_by(|left, right| left.public_key_hex.cmp(&right.public_key_hex));
        let base_validator_set_hash_hex = app
            .core
            .state
            .lock()
            .unwrap()
            .validator_lifecycle
            .as_ref()
            .unwrap()
            .active_set_hash_hex()
            .unwrap();
        let message = validator_key_proof_message(
            &app.core.config.chain_id,
            transition_id,
            &base_validator_set_hash_hex,
            activation_height,
            &target_validators,
        )
        .unwrap();
        ValidatorSetTransitionV1 {
            schema: VALIDATOR_TRANSITION_SCHEMA_V1.to_string(),
            chain_id: app.core.config.chain_id.clone(),
            transition_id: transition_id.to_string(),
            base_validator_set_hash_hex,
            activation_height,
            target_validators,
            new_validator_proofs: proof_seeds
                .iter()
                .map(|seed| {
                    let key = SigningKey::from_bytes(&[*seed; 32]);
                    ValidatorKeyProofV1 {
                        public_key_hex: public_key_hex(&key),
                        signature_hex: sign_hex(&key, &message),
                    }
                })
                .collect(),
        }
    }

    fn transition_envelope(
        transition: &ValidatorSetTransitionV1,
        nonce: u64,
    ) -> SignedCommandEnvelopeV1 {
        SignedCommandEnvelopeV1::sign(
            &transition.chain_id,
            &transition.transition_id,
            "did:operator:1",
            "operator",
            nonce,
            1_000,
            10_000,
            VALIDATOR_TRANSITION_SCHEMA_V1,
            &serde_json::to_vec(transition).unwrap(),
            &SigningKey::from_bytes(&[11u8; 32]),
        )
        .unwrap()
    }

    fn transition_tx(transition: &ValidatorSetTransitionV1, nonce: u64) -> Bytes {
        Bytes::from(serde_json::to_vec(&transition_envelope(transition, nonce)).unwrap())
    }

    fn canonical_tx(
        signing_key: &SigningKey,
        command_id: &str,
        signer_id: &str,
        signer_role: &str,
        envelope_nonce: u64,
        tx: &CanonicalTxV1,
    ) -> Bytes {
        let envelope = SignedCommandEnvelopeV1::sign(
            "trnm-comet-spike",
            command_id,
            signer_id,
            signer_role,
            envelope_nonce,
            1_000,
            10_000,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &serde_json::to_vec(tx).unwrap(),
            signing_key,
        )
        .unwrap();
        Bytes::from(serde_json::to_vec(&envelope).unwrap())
    }

    fn poco_application_tx(
        signing_key: &SigningKey,
        chain_id: &str,
        command_id: &str,
        envelope_nonce: u64,
        operation: &[u8],
    ) -> Bytes {
        let envelope = SignedCommandEnvelopeV1::sign(
            chain_id,
            command_id,
            "did:operator:1",
            "operator",
            envelope_nonce,
            1_000,
            10_000,
            POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            operation,
            signing_key,
        )
        .unwrap();
        Bytes::from(serde_json::to_vec(&envelope).unwrap())
    }

    struct PocoFullStoreStepReplayV0 {
        authenticated_context: AuthenticatedPocoApplicationContextV0,
        context: poco_application_evidence::PocoApplicationProductionContextExportV0,
        source_version: u64,
        source_root: [u8; 32],
        source_projection: poco_transition::ProductionPocoProjectionV0,
        target_version: u64,
        target_root: [u8; 32],
        target_projection: poco_transition::ProductionPocoProjectionV0,
        raw_operations: Vec<Vec<u8>>,
        signed_txs: Vec<Bytes>,
        process_body: poco_checkpoint::CheckpointBodyEvidenceV0,
        finalize_body: poco_checkpoint::CheckpointBodyEvidenceV0,
        next_production_context:
            poco_application_evidence::PocoApplicationProductionContextExportV0,
        failpoints: PocoFullStoreFailpointEvidenceV0,
        restores: PocoFullStoreRestoreEvidenceV0,
    }

    struct PocoFullStoreFailpointEvidenceV0 {
        before_sql_commit_error_sha256: [u8; 32],
        before_restart_version: u64,
        before_restart_root: [u8; 32],
        after_sql_commit_error_sha256: [u8; 32],
        sqlite_committed_version: u64,
        sqlite_committed_root: [u8; 32],
        sqlite_committed_projection: poco_transition::ProductionPocoProjectionV0,
        restart_version: u64,
        restart_root: [u8; 32],
    }

    struct PocoFullStoreRestoreEvidenceV0 {
        v3_version: u64,
        v3_root: [u8; 32],
        v3_projection: poco_transition::ProductionPocoProjectionV0,
        v4_version: u64,
        v4_root: [u8; 32],
        v4_projection: poco_transition::ProductionPocoProjectionV0,
    }

    struct PocoFullStoreNegativeReplayV0 {
        context: poco_application_evidence::PocoApplicationProductionContextExportV0,
        source_version: u64,
        source_root: [u8; 32],
        source_projection: poco_transition::ProductionPocoProjectionV0,
        raw_operations: Vec<Vec<u8>>,
        signed_txs: Vec<Bytes>,
        process_actual: poco_application_evidence::PocoApplicationActualRejectionExportV0,
        independent_actual: poco_application_evidence::PocoApplicationActualRejectionExportV0,
        restart_version: u64,
        restart_root: [u8; 32],
        restart_projection: poco_transition::ProductionPocoProjectionV0,
    }

    /// Three independently initialized applications keep proposal planning,
    /// finalization and persistent commit/restart evidence from sharing a
    /// pending block or a history-specific JMT plan.
    struct PocoFullStoreReplayHarnessV0 {
        process_app: CometBftApplication,
        finalize_app: CometBftApplication,
        persistent_app: Option<CometBftApplication>,
        persistent_config: ConsensusAppConfig,
        persistent_root: PathBuf,
        operator: SigningKey,
        next_envelope_nonce: u64,
    }

    impl PocoFullStoreReplayHarnessV0 {
        fn new() -> Self {
            static NEXT_SEQUENCE_REPLAY_DIR: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let (process_app, _, process_entries) = active_poco_genesis_fixture();
            let (finalize_app, _, finalize_entries) = active_poco_genesis_fixture();
            assert_eq!(process_entries, finalize_entries);
            let replay_directory_id =
                NEXT_SEQUENCE_REPLAY_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let persistent_root = std::env::temp_dir().join(format!(
                "trnm-poco-application-sequence-replay-{}-{}-{}",
                std::process::id(),
                now_unix_ms(),
                replay_directory_id
            ));
            fs::create_dir_all(&persistent_root).unwrap();
            let (persistent_app, _, persistent_entries) =
                active_poco_genesis_fixture_with_state_path(Some(
                    persistent_root.join("app-state.json"),
                ));
            assert_eq!(process_entries, persistent_entries);
            let persistent_config = persistent_app.core.config.clone();
            let expected = process_app.height_and_app_hash().unwrap();
            assert_eq!(finalize_app.height_and_app_hash().unwrap(), expected);
            assert_eq!(persistent_app.height_and_app_hash().unwrap(), expected);
            Self {
                process_app,
                finalize_app,
                persistent_app: Some(persistent_app),
                persistent_config,
                persistent_root,
                operator: SigningKey::from_bytes(&[11; 32]),
                next_envelope_nonce: 1,
            }
        }

        fn signed_txs(
            &self,
            sequence_id: &str,
            step_id: &str,
            raw_operations: &[Vec<u8>],
        ) -> Vec<Bytes> {
            raw_operations
                .iter()
                .enumerate()
                .map(|(index, operation)| {
                    poco_application_tx(
                        &self.operator,
                        &self.process_app.core.config.chain_id,
                        &format!("poco-sequence-{sequence_id}-{step_id}-{index}"),
                        self.next_envelope_nonce
                            .checked_add(u64::try_from(index).unwrap())
                            .unwrap(),
                        operation,
                    )
                })
                .collect()
        }

        fn replay_step(
            &mut self,
            sequence_id: &str,
            step_id: &str,
            raw_operations: Vec<Vec<u8>>,
        ) -> PocoFullStoreStepReplayV0 {
            assert!(!raw_operations.is_empty());
            let signed_txs = self.signed_txs(sequence_id, step_id, &raw_operations);
            let (source_version, source_root) = self.process_app.height_and_app_hash().unwrap();
            assert_eq!(
                self.finalize_app.height_and_app_hash().unwrap(),
                (source_version, source_root)
            );
            assert_eq!(
                self.persistent_app
                    .as_ref()
                    .unwrap()
                    .height_and_app_hash()
                    .unwrap(),
                (source_version, source_root)
            );
            let authenticated_source = self
                .process_app
                .production_poco_projection_at(source_version)
                .unwrap();
            let source_projection_ref: &poco_transition::ProductionPocoProjectionV0 =
                authenticated_source.projection();
            let source_projection = source_projection_ref.clone();
            let target_version = source_version.checked_add(1).unwrap();
            let target_height = i64::try_from(target_version).unwrap();
            let source_signer_commitment = {
                let state = self.process_app.core.state.lock().unwrap();
                let delta = self.process_app.start_block_delta(&state).unwrap();
                poco_application_governance_signer_commitment_v0(
                    effective_validator_lifecycle(&state, &delta).unwrap(),
                )
            };
            let source_epoch = active_consensus_configuration(&source_projection)
                .unwrap()
                .0
                .epoch()
                .get();
            let (authenticated_context, context) =
                poco_application_evidence::production_context_from_projection(
                    &source_projection,
                    source_version,
                    source_root,
                    target_version,
                    source_epoch,
                    source_signer_commitment,
                );

            let process_pending = {
                let state = self.process_app.core.state.lock().unwrap();
                self.process_app
                    .execute_block(&state, &signed_txs, 2_000, &[])
                    .unwrap()
            };
            assert_eq!(process_pending.height, target_version);
            let process_body = poco_checkpoint::checkpoint_body_evidence_v0(
                &signed_txs,
                &process_pending.tx_results,
            )
            .unwrap();
            let process_response = self.process_app.process_proposal(RequestProcessProposal {
                txs: signed_txs.clone(),
                height: target_height,
                time: block_time(),
                ..Default::default()
            });
            assert_eq!(
                process_response.status,
                response_process_proposal::ProposalStatus::Accept as i32
            );

            let finalized = self.finalize_app.finalize_block(RequestFinalizeBlock {
                txs: signed_txs.clone(),
                height: target_height,
                time: block_time(),
                ..Default::default()
            });
            let target_root: [u8; 32] = finalized
                .app_hash
                .as_ref()
                .try_into()
                .expect("FinalizeBlock AppHash32");
            assert_eq!(target_root, process_pending.app_hash);
            assert_eq!(finalized.tx_results, process_pending.tx_results);
            let finalize_body =
                poco_checkpoint::checkpoint_body_evidence_v0(&signed_txs, &finalized.tx_results)
                    .unwrap();
            assert_eq!(process_body, finalize_body);
            self.finalize_app.commit();

            // Advance the independent ProcessProposal instance only after its
            // proposal evidence has been captured.
            let process_finalized = self.process_app.finalize_block(RequestFinalizeBlock {
                txs: signed_txs.clone(),
                height: target_height,
                time: block_time(),
                ..Default::default()
            });
            assert_eq!(process_finalized.app_hash.as_ref(), target_root);
            assert_eq!(process_finalized.tx_results, finalized.tx_results);
            self.process_app.commit();

            let before_sql_commit_error_sha256 = {
                let persistent = self.persistent_app.as_ref().unwrap();
                let persistent_pending = {
                    let state = persistent.core.state.lock().unwrap();
                    persistent
                        .execute_block(&state, &signed_txs, 2_000, &[])
                        .unwrap()
                };
                assert_eq!(persistent_pending.height, target_version);
                assert_eq!(persistent_pending.app_hash, target_root);
                assert_eq!(persistent_pending.tx_results, finalized.tx_results);
                let error = persistent
                    .core
                    .store
                    .as_ref()
                    .unwrap()
                    .persist_transition_with_failpoint(
                        &persistent.core.state.lock().unwrap(),
                        &persistent_pending,
                        store::StoreFailpoint::BeforeSqlCommit,
                    )
                    .expect_err("before-SQL-COMMIT failpoint unexpectedly committed");
                assert_eq!(
                    persistent.height_and_app_hash().unwrap(),
                    (source_version, source_root)
                );
                let error_chain = error
                    .chain()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(": ");
                Sha256::digest(error_chain.as_bytes()).into()
            };
            let persistent = self.persistent_app.take().unwrap();
            drop(persistent);
            let restarted = CometBftApplication::new(self.persistent_config.clone()).unwrap();
            assert_eq!(
                restarted.height_and_app_hash().unwrap(),
                (source_version, source_root)
            );
            let restarted_source = restarted
                .production_poco_projection_at(source_version)
                .unwrap();
            let restarted_source_ref: &poco_transition::ProductionPocoProjectionV0 =
                restarted_source.projection();
            assert_eq!(restarted_source_ref, &source_projection);
            self.persistent_app = Some(restarted);

            let (after_sql_commit_error_sha256, sqlite_committed_root, sqlite_committed_projection) = {
                let persistent = self.persistent_app.as_ref().unwrap();
                let persistent_pending = {
                    let state = persistent.core.state.lock().unwrap();
                    persistent
                        .execute_block(&state, &signed_txs, 2_000, &[])
                        .unwrap()
                };
                assert_eq!(persistent_pending.height, target_version);
                assert_eq!(persistent_pending.app_hash, target_root);
                assert_eq!(persistent_pending.tx_results, finalized.tx_results);
                let error = persistent
                    .core
                    .store
                    .as_ref()
                    .unwrap()
                    .persist_transition_with_failpoint(
                        &persistent.core.state.lock().unwrap(),
                        &persistent_pending,
                        store::StoreFailpoint::AfterSqlCommitBeforeStatus,
                    )
                    .expect_err("after-SQL-COMMIT failpoint unexpectedly returned success");
                assert_eq!(
                    persistent.height_and_app_hash().unwrap(),
                    (source_version, source_root),
                    "in-memory status must remain old until restart"
                );
                let (committed_root, committed_projection) = persistent
                    .core
                    .store
                    .as_ref()
                    .unwrap()
                    .production_poco_projection(target_version)
                    .unwrap();
                let committed_root: [u8; 32] = committed_root.into();
                assert_eq!(committed_root, target_root);
                let committed_projection = committed_projection
                    .expect("committed target must retain an active PoCO projection");
                let error_chain = error
                    .chain()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(": ");
                (
                    Sha256::digest(error_chain.as_bytes()).into(),
                    committed_root,
                    committed_projection,
                )
            };
            let persistent = self.persistent_app.take().unwrap();
            drop(persistent);
            let restarted = CometBftApplication::new(self.persistent_config.clone()).unwrap();
            assert_eq!(
                restarted.height_and_app_hash().unwrap(),
                (target_version, target_root)
            );
            let restarted_target = restarted
                .production_poco_projection_at(target_version)
                .unwrap();
            let restarted_target_ref: &poco_transition::ProductionPocoProjectionV0 =
                restarted_target.projection();
            assert_eq!(restarted_target_ref, &sqlite_committed_projection);
            self.persistent_app = Some(restarted);
            let failpoints = PocoFullStoreFailpointEvidenceV0 {
                before_sql_commit_error_sha256,
                before_restart_version: source_version,
                before_restart_root: source_root,
                after_sql_commit_error_sha256,
                sqlite_committed_version: target_version,
                sqlite_committed_root,
                sqlite_committed_projection,
                restart_version: target_version,
                restart_root: target_root,
            };

            assert_eq!(
                self.process_app.height_and_app_hash().unwrap(),
                (target_version, target_root)
            );
            assert_eq!(
                self.finalize_app.height_and_app_hash().unwrap(),
                (target_version, target_root)
            );
            let authenticated_target = self
                .persistent_app
                .as_ref()
                .unwrap()
                .production_poco_projection_at(target_version)
                .unwrap();
            let target_projection_ref: &poco_transition::ProductionPocoProjectionV0 =
                authenticated_target.projection();
            let target_projection = target_projection_ref.clone();
            let restores = {
                let snapshot = wait_for_snapshot(&self.process_app, target_version);
                assert_eq!(snapshot.format, SNAPSHOT_FORMAT_V3);
                let v3_target =
                    CometBftApplication::new(self.process_app.core.config.clone()).unwrap();
                assert_eq!(
                    v3_target
                        .offer_snapshot(RequestOfferSnapshot {
                            snapshot: Some(snapshot.clone()),
                            app_hash: Bytes::copy_from_slice(&target_root),
                        })
                        .result,
                    response_offer_snapshot::Result::Accept as i32
                );
                for index in 0..snapshot.chunks {
                    let chunk = self
                        .process_app
                        .load_snapshot_chunk(RequestLoadSnapshotChunk {
                            height: snapshot.height,
                            format: snapshot.format,
                            chunk: index,
                        })
                        .chunk;
                    assert_eq!(
                        v3_target
                            .apply_snapshot_chunk(RequestApplySnapshotChunk {
                                index,
                                chunk,
                                sender: "poco-evidence-source-v3".to_string(),
                            })
                            .result,
                        response_apply_snapshot_chunk::Result::Accept as i32
                    );
                }
                assert_eq!(
                    v3_target.height_and_app_hash().unwrap(),
                    (target_version, target_root)
                );
                let v3_projection = v3_target
                    .production_poco_projection_at(target_version)
                    .unwrap();
                let v3_projection_ref: &poco_transition::ProductionPocoProjectionV0 =
                    v3_projection.projection();
                assert_eq!(v3_projection_ref, &target_projection);
                let v3_projection = v3_projection_ref.clone();
                drop(v3_target);

                let v4_record = {
                    let persistent = self.persistent_app.as_ref().unwrap();
                    let state = persistent.core.state.lock().unwrap().clone();
                    let store = persistent.core.store.as_ref().unwrap();
                    let pinned = store.pin_snapshot(&state).unwrap();
                    build_store_snapshot(
                        store,
                        &persistent.core.config.chain_id,
                        PendingDiskSnapshot {
                            state,
                            disk_path: self.persistent_root.join(format!(
                                "poco-evidence-source-{target_version}.snapshot.sqlite3"
                            )),
                            pinned,
                        },
                    )
                    .unwrap()
                };
                assert_eq!(v4_record.snapshot.format, SNAPSHOT_FORMAT_V4);
                assert_eq!(v4_record.snapshot.height, target_version);
                let mut v4_config = self.persistent_config.clone();
                v4_config.state_path = Some(
                    self.persistent_root
                        .join(format!("poco-evidence-v4-target-{target_version}.json")),
                );
                let v4_target = CometBftApplication::new(v4_config).unwrap();
                assert_eq!(
                    v4_target
                        .offer_snapshot(RequestOfferSnapshot {
                            snapshot: Some(v4_record.snapshot.clone()),
                            app_hash: Bytes::copy_from_slice(&target_root),
                        })
                        .result,
                    response_offer_snapshot::Result::Accept as i32
                );
                for index in 0..v4_record.snapshot.chunks {
                    assert_eq!(
                        v4_target
                            .apply_snapshot_chunk(RequestApplySnapshotChunk {
                                index,
                                chunk: v4_record.payload.read_chunk(index).unwrap(),
                                sender: "poco-evidence-source-v4".to_string(),
                            })
                            .result,
                        response_apply_snapshot_chunk::Result::Accept as i32
                    );
                }
                assert_eq!(
                    v4_target.height_and_app_hash().unwrap(),
                    (target_version, target_root)
                );
                let v4_projection = v4_target
                    .production_poco_projection_at(target_version)
                    .unwrap();
                let v4_projection_ref: &poco_transition::ProductionPocoProjectionV0 =
                    v4_projection.projection();
                assert_eq!(v4_projection_ref, &target_projection);
                let v4_projection = v4_projection_ref.clone();
                drop(v4_target);
                v4_record.payload.remove_file().unwrap();

                PocoFullStoreRestoreEvidenceV0 {
                    v3_version: target_version,
                    v3_root: target_root,
                    v3_projection,
                    v4_version: target_version,
                    v4_root: target_root,
                    v4_projection,
                }
            };
            let next_signer_commitment = {
                let state = self.process_app.core.state.lock().unwrap();
                let delta = self.process_app.start_block_delta(&state).unwrap();
                poco_application_governance_signer_commitment_v0(
                    effective_validator_lifecycle(&state, &delta).unwrap(),
                )
            };
            let next_epoch = active_consensus_configuration(&target_projection)
                .unwrap()
                .0
                .epoch()
                .get();
            let (_, next_production_context) =
                poco_application_evidence::production_context_from_projection(
                    &target_projection,
                    target_version,
                    target_root,
                    target_version.checked_add(1).unwrap(),
                    next_epoch,
                    next_signer_commitment,
                );
            let process_target = self
                .process_app
                .production_poco_projection_at(target_version)
                .unwrap();
            let process_target_ref: &poco_transition::ProductionPocoProjectionV0 =
                process_target.projection();
            assert_eq!(process_target_ref, &target_projection);
            let finalize_target = self
                .finalize_app
                .production_poco_projection_at(target_version)
                .unwrap();
            let finalize_target_ref: &poco_transition::ProductionPocoProjectionV0 =
                finalize_target.projection();
            assert_eq!(finalize_target_ref, &target_projection);
            let source_authority = poco_application_evidence::authority_summary(&source_projection);
            let target_authority = poco_application_evidence::authority_summary(&target_projection);
            assert_eq!(target_authority.revision, source_authority.revision + 1);

            self.next_envelope_nonce = self
                .next_envelope_nonce
                .checked_add(u64::try_from(signed_txs.len()).unwrap())
                .unwrap();
            PocoFullStoreStepReplayV0 {
                authenticated_context,
                context,
                source_version,
                source_root,
                source_projection,
                target_version,
                target_root,
                target_projection,
                raw_operations,
                signed_txs,
                process_body,
                finalize_body,
                next_production_context,
                failpoints,
                restores,
            }
        }

        fn replay_negative(
            &mut self,
            sequence_id: &str,
            negative_id: &str,
            raw_operations: Vec<Vec<u8>>,
        ) -> PocoFullStoreNegativeReplayV0 {
            assert!(!raw_operations.is_empty());
            let signed_txs = self.signed_txs(sequence_id, negative_id, &raw_operations);
            let (source_version, source_root) = self.process_app.height_and_app_hash().unwrap();
            assert_eq!(
                self.finalize_app.height_and_app_hash().unwrap(),
                (source_version, source_root)
            );
            assert_eq!(
                self.persistent_app
                    .as_ref()
                    .unwrap()
                    .height_and_app_hash()
                    .unwrap(),
                (source_version, source_root)
            );
            let authenticated_source = self
                .process_app
                .production_poco_projection_at(source_version)
                .unwrap();
            let source_projection_ref: &poco_transition::ProductionPocoProjectionV0 =
                authenticated_source.projection();
            let source_projection = source_projection_ref.clone();
            let source_signer_commitment = {
                let state = self.process_app.core.state.lock().unwrap();
                let delta = self.process_app.start_block_delta(&state).unwrap();
                poco_application_governance_signer_commitment_v0(
                    effective_validator_lifecycle(&state, &delta).unwrap(),
                )
            };
            let source_epoch = active_consensus_configuration(&source_projection)
                .unwrap()
                .0
                .epoch()
                .get();
            let (_, context) = poco_application_evidence::production_context_from_projection(
                &source_projection,
                source_version,
                source_root,
                source_version.checked_add(1).unwrap(),
                source_epoch,
                source_signer_commitment,
            );
            let process_actual = {
                let state = self.process_app.core.state.lock().unwrap();
                let error = self
                    .process_app
                    .execute_block(&state, &signed_txs, 2_000, &[])
                    .expect_err("negative replay unexpectedly executed");
                poco_application_evidence::classify_application_rejection_v0(
                    &error,
                    &source_projection,
                    &raw_operations,
                )
            };
            let response = self.process_app.process_proposal(RequestProcessProposal {
                txs: signed_txs.clone(),
                height: i64::try_from(source_version.checked_add(1).unwrap()).unwrap(),
                time: block_time(),
                ..Default::default()
            });
            assert_eq!(
                response.status,
                response_process_proposal::ProposalStatus::Reject as i32
            );
            assert_eq!(
                self.process_app.height_and_app_hash().unwrap(),
                (source_version, source_root)
            );
            assert!(self
                .process_app
                .core
                .state
                .lock()
                .unwrap()
                .pending
                .is_none());

            let mut independent_actual = None;
            for app in [&self.finalize_app, self.persistent_app.as_ref().unwrap()] {
                let state = app.core.state.lock().unwrap();
                let error = app
                    .execute_block(&state, &signed_txs, 2_000, &[])
                    .expect_err("negative replay differs across application instances");
                let actual = poco_application_evidence::classify_application_rejection_v0(
                    &error,
                    &source_projection,
                    &raw_operations,
                );
                assert_eq!(actual, process_actual);
                if let Some(previous) = &independent_actual {
                    assert_eq!(previous, &actual);
                } else {
                    independent_actual = Some(actual);
                }
                assert_eq!(
                    (state.height, state.app_hash),
                    (source_version, source_root)
                );
                assert!(state.pending.is_none());
            }
            let persistent = self.persistent_app.take().unwrap();
            drop(persistent);
            let restarted = CometBftApplication::new(self.persistent_config.clone()).unwrap();
            assert_eq!(
                restarted.height_and_app_hash().unwrap(),
                (source_version, source_root)
            );
            let restarted_source = restarted
                .production_poco_projection_at(source_version)
                .unwrap();
            let restarted_source_ref: &poco_transition::ProductionPocoProjectionV0 =
                restarted_source.projection();
            assert_eq!(restarted_source_ref, &source_projection);
            let restart_projection = restarted_source_ref.clone();
            self.persistent_app = Some(restarted);
            PocoFullStoreNegativeReplayV0 {
                context,
                source_version,
                source_root,
                source_projection,
                raw_operations,
                signed_txs,
                process_actual,
                independent_actual: independent_actual.expect("independent negative executor"),
                restart_version: source_version,
                restart_root: source_root,
                restart_projection,
            }
        }
    }

    impl Drop for PocoFullStoreReplayHarnessV0 {
        fn drop(&mut self) {
            if let Some(persistent) = self.persistent_app.take() {
                drop(persistent);
            }
            let _ = fs::remove_dir_all(&self.persistent_root);
        }
    }

    fn application_sequence_source_digest_v0(sequence: &serde_json::Value) -> [u8; 32] {
        hex::decode(
            sequence["source_export_sha256_hex"]
                .as_str()
                .expect("sequence source-export digest"),
        )
        .expect("decode sequence source-export digest")
        .try_into()
        .expect("Hash32 sequence source-export digest")
    }

    fn replay_full_application_sequence_events_v0(
        sequence: &serde_json::Value,
    ) -> (
        Vec<poco_application_evidence::PocoApplicationSerializedEventV0>,
        Option<poco_application_evidence::PocoApplicationSerializedEventV0>,
    ) {
        assert_eq!(
            sequence["execution_scope"].as_str(),
            Some("full_application_store")
        );
        let sequence_id = sequence["id"].as_str().expect("sequence id");
        let source_export_sha256 = application_sequence_source_digest_v0(sequence);
        let mut harness = PocoFullStoreReplayHarnessV0::new();
        let (initial_version, initial_root) = harness.process_app.height_and_app_hash().unwrap();
        let (retained_tree, retained_version, retained_root, retained_projection) =
            poco_application_evidence::authenticated_tree_from_sequence_initial_v0(
                &sequence["initial"],
            );
        assert_eq!(
            initial_version,
            sequence["initial"]["version"]
                .as_u64()
                .expect("sequence initial version"),
            "full-store sequence does not start at the real fixture version"
        );
        assert_eq!(
            hex::encode(initial_root),
            sequence["initial"]["jmt_root_hex"]
                .as_str()
                .expect("sequence initial root"),
            "full-store sequence does not start at the real fixture root"
        );
        assert_eq!(
            (retained_version, retained_root),
            (initial_version, initial_root)
        );
        let actual_live = harness
            .process_app
            .core
            .auth_tree
            .lock()
            .unwrap()
            .verified_live_values(initial_version)
            .unwrap();
        assert_eq!(
            retained_tree
                .verified_live_values(retained_version)
                .unwrap(),
            actual_live,
            "retained full source leaves differ from the real InitChain fixture"
        );
        let actual_projection = harness
            .process_app
            .production_poco_projection_at(initial_version)
            .unwrap();
        let actual_projection_ref: &poco_transition::ProductionPocoProjectionV0 =
            actual_projection.projection();
        assert_eq!(actual_projection_ref, &retained_projection);

        let mut events = Vec::new();
        for step in sequence["steps"].as_array().expect("sequence steps") {
            let step_id = step["id"].as_str().expect("step id");
            let raw_operations =
                poco_application_evidence::application_sequence_raw_operations_v0(step);
            let replay = harness.replay_step(sequence_id, step_id, raw_operations);
            let scope_evidence =
                poco_application_evidence::full_application_store_scope_evidence_v0(
                    poco_application_evidence::FullApplicationStoreScopeEvidenceInputV0 {
                        signed_txs: &replay.signed_txs,
                        source_version: replay.source_version,
                        source_root: replay.source_root,
                        source_projection: &replay.source_projection,
                        target_version: replay.target_version,
                        target_root: replay.target_root,
                        process_body: &replay.process_body,
                        finalize_body: &replay.finalize_body,
                        sqlite_commit_projection: &replay.failpoints.sqlite_committed_projection,
                        sqlite_restart_projection: &replay.target_projection,
                        snapshot_v3_projection: &replay.restores.v3_projection,
                        snapshot_v4_projection: &replay.restores.v4_projection,
                    },
                );
            let event = poco_application_evidence::application_sequence_step_event_v0(
                source_export_sha256,
                poco_application_evidence::application_sequence_step_request_sha256_v0(
                    sequence, step,
                ),
                sequence_id,
                step_id,
                "full_application_store",
                replay.authenticated_context,
                replay.context,
                replay.source_root,
                &replay.source_projection,
                replay.target_root,
                &replay.target_projection,
                &replay.raw_operations,
                Some(scope_evidence),
                replay.next_production_context,
            );
            events.push(poco_application_evidence::serialize_application_sequence_event_v0(&event));
        }

        let negative_event = sequence["negatives"]
            .as_array()
            .expect("sequence negatives")
            .first()
            .map(|negative| {
                assert_eq!(
                    sequence["negatives"].as_array().unwrap().len(),
                    1,
                    "full-store automaton must have one negative"
                );
                let negative_id = negative["id"].as_str().expect("negative id");
                let raw_operations =
                    poco_application_evidence::application_sequence_negative_raw_operations_v0(
                        negative,
                    );
                let replay = harness.replay_negative(sequence_id, negative_id, raw_operations);
                assert_eq!(replay.source_version, replay.context.source_version);
                let event = poco_application_evidence::full_application_store_negative_event_v0(
                    source_export_sha256,
                    poco_application_evidence::application_sequence_negative_request_sha256_v0(
                        sequence, negative,
                    ),
                    sequence_id,
                    negative_id,
                    replay.context,
                    replay.source_root,
                    &replay.source_projection,
                    &replay.raw_operations,
                    &replay.signed_txs,
                    replay.process_actual,
                    replay.independent_actual,
                    replay.restart_version,
                    replay.restart_root,
                    &replay.restart_projection,
                );
                poco_application_evidence::serialize_application_sequence_event_v0(&event)
            });
        (events, negative_event)
    }

    fn verify_retained_application_sequence_sources_v0(draft: &serde_json::Value) {
        let source_exports = draft["source_exports"]
            .as_array()
            .expect("operation-sequence source registry");
        for source in source_exports {
            let raw = hex::decode(
                source["raw_json_hex"]
                    .as_str()
                    .expect("retained source raw JSON"),
            )
            .expect("decode retained source raw JSON");
            assert_eq!(
                hex::encode(Sha256::digest(&raw)),
                source["sha256_hex"]
                    .as_str()
                    .expect("retained source digest"),
                "retained source raw digest drift"
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&raw).expect("decode retained source JSON");
            let (tree, version, root, projection) =
                poco_application_evidence::authenticated_tree_from_sequence_initial_v0(
                    &parsed["initial"],
                );
            assert_eq!(tree.latest_version(), Some(version));
            assert_eq!(tree.root_hash(version).unwrap().0, root);
            poco_application::validate_application_authority_projection_v0(&projection)
                .expect("retained source cross-entry authority");
        }
        for sequence in draft["sequences"].as_array().expect("operation sequences") {
            let digest = sequence["source_export_sha256_hex"]
                .as_str()
                .expect("sequence source digest");
            let source = source_exports
                .iter()
                .find(|source| source["sha256_hex"].as_str() == Some(digest))
                .expect("sequence source bytes retained in registry");
            let raw = hex::decode(source["raw_json_hex"].as_str().unwrap()).unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(
                parsed["initial"], sequence["initial"],
                "sequence initial differs from its retained authenticated source"
            );
            poco_application_evidence::validate_application_sequence_business_lineage_v0(
                sequence, &parsed,
            );
        }
    }

    fn replay_application_sequence_events_v0(draft: &serde_json::Value) -> Vec<Vec<u8>> {
        verify_retained_application_sequence_sources_v0(draft);
        let mut missing = Vec::new();
        for sequence in draft["sequences"].as_array().expect("operation sequences") {
            let (step_events, negative_event) = if sequence["execution_scope"].as_str()
                == Some("full_application_store")
            {
                replay_full_application_sequence_events_v0(sequence)
            } else {
                let replay =
                    poco_application_evidence::replay_isolated_application_sequence_v0(sequence);
                (replay.step_events, replay.negative_event)
            };
            let steps = sequence["steps"].as_array().expect("sequence steps");
            assert_eq!(step_events.len(), steps.len());
            for (step, actual) in steps.iter().zip(step_events) {
                if step["rust_event"].is_null() {
                    missing.push(actual.raw);
                } else {
                    assert_eq!(
                        actual.value, step["rust_event"],
                        "already-merged Rust step event no longer replays exactly"
                    );
                }
            }
            if let Some(negative) = sequence["negatives"]
                .as_array()
                .expect("sequence negatives")
                .first()
            {
                let actual = negative_event.expect("negative replay event");
                if negative["rust_event"].is_null() {
                    missing.push(actual.raw);
                } else {
                    assert_eq!(
                        actual.value, negative["rust_event"],
                        "already-merged Rust negative event no longer replays exactly"
                    );
                }
            } else {
                assert!(negative_event.is_none());
            }
        }
        missing
    }

    #[test]
    #[ignore = "manual machine-readable operation-sequence Rust event exporter"]
    fn export_poco_application_operation_sequence_rust_events() {
        let draft = poco_application_evidence::operation_sequence_authoring_value_v0();
        let events = replay_application_sequence_events_v0(&draft);
        assert!(
            !events.is_empty(),
            "operation-sequence draft has no null Rust event"
        );
        let mut encoded = Vec::new();
        for event in events {
            assert!(event.starts_with(b"{\"schema\":"));
            encoded.extend_from_slice(&event);
            encoded.push(b'\n');
        }
        if let Some(output) = std::env::var_os("TRNM_POCO_APPLICATION_SEQUENCE_RUST_EVENTS") {
            let output = PathBuf::from(output);
            let parent = output.parent().expect("Rust event output parent");
            fs::create_dir_all(parent).unwrap();
            let temporary = parent.join(format!(
                ".{}.tmp-{}-{}",
                output
                    .file_name()
                    .expect("Rust event output file name")
                    .to_string_lossy(),
                std::process::id(),
                now_unix_ms()
            ));
            fs::write(&temporary, &encoded).unwrap();
            fs::rename(&temporary, &output).unwrap();
            eprintln!(
                "wrote {} PoCO application Rust event(s) to {}",
                encoded.iter().filter(|byte| **byte == b'\n').count(),
                output.display()
            );
        } else {
            print!("{}", String::from_utf8(encoded).unwrap());
        }
    }

    #[test]
    fn poco_application_operation_sequences_final_vector_matches_rust_replay() {
        let vector_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../../docs/protocol/poco-bft-v0/vectors/\
             poco-application-operation-sequences-v0.json",
        );
        let raw = fs::read(&vector_path).unwrap_or_else(|error| {
            panic!(
                "read final PoCO application operation sequences {}: {error}",
                vector_path.display()
            )
        });
        let vector: serde_json::Value = serde_json::from_slice(&raw).unwrap_or_else(|error| {
            panic!(
                "decode final PoCO application operation sequences {}: {error}",
                vector_path.display()
            )
        });
        assert_eq!(
            vector["schema"].as_str(),
            Some("trnm.poco-bft.application-operation-sequences.vector.v0")
        );
        assert_eq!(vector["schema_version"].as_u64(), Some(0));
        let missing = replay_application_sequence_events_v0(&vector);
        assert!(
            missing.is_empty(),
            "final operation-sequence vector contains a null Rust event"
        );
    }

    #[test]
    #[ignore = "manual shape-independent full ApplicationStore replay scaffold"]
    fn full_store_sequence_replay_scaffold_uses_independent_instances() {
        let mut harness = PocoFullStoreReplayHarnessV0::new();
        let operation = {
            let state = harness.process_app.core.state.lock().unwrap();
            let delta = harness.process_app.start_block_delta(&state).unwrap();
            harness
                .process_app
                .start_poco_application_overlay(&state, &delta)
                .unwrap()
                .test_define_meter_operation_v0()
                .unwrap()
        };
        let replay =
            harness.replay_step("shape-independent", "define-meter", vec![operation.clone()]);
        assert_eq!(replay.source_version, 0);
        assert_eq!(replay.target_version, 1);
        assert_ne!(replay.source_root, replay.target_root);
        assert_ne!(replay.source_projection, replay.target_projection);
        assert_eq!(replay.raw_operations, vec![operation.clone()]);
        assert_eq!(replay.signed_txs.len(), 1);
        assert_eq!(replay.process_body, replay.finalize_body);
        assert_eq!(replay.process_body.encoded_receipts().len(), 1);
        assert_ne!(replay.process_body.payload_root(), [0; 32]);
        assert_ne!(replay.process_body.receipts_root(), [0; 32]);
        assert_ne!(replay.failpoints.before_sql_commit_error_sha256, [0; 32]);
        assert_eq!(
            replay.failpoints.before_restart_version,
            replay.source_version
        );
        assert_eq!(replay.failpoints.before_restart_root, replay.source_root);
        assert_ne!(replay.failpoints.after_sql_commit_error_sha256, [0; 32]);
        assert_eq!(
            replay.failpoints.sqlite_committed_version,
            replay.target_version
        );
        assert_eq!(replay.failpoints.sqlite_committed_root, replay.target_root);
        assert_eq!(
            replay.failpoints.sqlite_committed_projection,
            replay.target_projection
        );
        assert_eq!(replay.failpoints.restart_version, replay.target_version);
        assert_eq!(replay.failpoints.restart_root, replay.target_root);
        assert_eq!(replay.restores.v3_version, replay.target_version);
        assert_eq!(replay.restores.v3_root, replay.target_root);
        assert_eq!(replay.restores.v3_projection, replay.target_projection);
        assert_eq!(replay.restores.v4_version, replay.target_version);
        assert_eq!(replay.restores.v4_root, replay.target_root);
        assert_eq!(replay.restores.v4_projection, replay.target_projection);
        let scope_evidence = poco_application_evidence::full_application_store_scope_evidence_v0(
            poco_application_evidence::FullApplicationStoreScopeEvidenceInputV0 {
                signed_txs: &replay.signed_txs,
                source_version: replay.source_version,
                source_root: replay.source_root,
                source_projection: &replay.source_projection,
                target_version: replay.target_version,
                target_root: replay.target_root,
                process_body: &replay.process_body,
                finalize_body: &replay.finalize_body,
                sqlite_commit_projection: &replay.failpoints.sqlite_committed_projection,
                sqlite_restart_projection: &replay.target_projection,
                snapshot_v3_projection: &replay.restores.v3_projection,
                snapshot_v4_projection: &replay.restores.v4_projection,
            },
        );
        let event = poco_application_evidence::application_sequence_step_event_v0(
            [1; 32],
            [2; 32],
            "shape-independent",
            "define-meter",
            "full_application_store",
            replay.authenticated_context.clone(),
            replay.context.clone(),
            replay.source_root,
            &replay.source_projection,
            replay.target_root,
            &replay.target_projection,
            &replay.raw_operations,
            Some(scope_evidence),
            replay.next_production_context.clone(),
        );
        let event_bytes = serde_json::to_vec(&event).unwrap();
        assert!(event_bytes
            .starts_with(br#"{"schema":"trnm.poco-bft.application-operation-rust-step-event.v0""#));

        assert_eq!(harness.next_envelope_nonce, 2);
    }

    fn authenticated_candidate_block_time_v0(timestamp_ms: u64) -> Option<Timestamp> {
        Some(Timestamp {
            seconds: i64::try_from(timestamp_ms / 1_000).expect("candidate timestamp seconds"),
            nanos: i32::try_from((timestamp_ms % 1_000) * 1_000_000)
                .expect("candidate timestamp nanos"),
        })
    }

    fn advance_authenticated_candidate_app_v0(app: &CometBftApplication, target_height: u64) {
        let (source_height, _) = app
            .height_and_app_hash()
            .expect("candidate source application head");
        for height in source_height + 1..=target_height {
            let hash = [u8::try_from(height).expect("compact candidate height is u8"); 32];
            let finalized = app.finalize_block(RequestFinalizeBlock {
                txs: Vec::new(),
                hash: Bytes::copy_from_slice(&hash),
                height: i64::try_from(height).expect("candidate ABCI height"),
                time: authenticated_candidate_block_time_v0(
                    height.checked_mul(1_000).expect("candidate setup time"),
                ),
                ..Default::default()
            });
            assert!(finalized.tx_results.is_empty());
            assert_eq!(finalized.app_hash.len(), 32);
            app.commit();
            assert_eq!(
                app.height_and_app_hash().unwrap().0,
                height,
                "candidate setup commit height drift"
            );
        }
    }

    fn install_authenticated_candidate_source_v0(
        app: &CometBftApplication,
        target_height: u64,
        target_entries: &[PocoSnapshotEntryV0],
    ) {
        let mut state = app.core.state.lock().expect("candidate bootstrap state");
        assert_eq!(
            state.height.checked_add(1),
            Some(target_height),
            "candidate source bootstrap must be contiguous"
        );
        let source = app
            .production_poco_projection_at(state.height)
            .expect("candidate bootstrap source projection");
        let source_entries = source
            .projection()
            .entries()
            .iter()
            .map(|entry| ((entry.kind, entry.logical_key.clone()), entry))
            .collect::<BTreeMap<_, _>>();
        let target = target_entries
            .iter()
            .map(|entry| ((entry.kind, entry.logical_key.clone()), entry))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(target.len(), target_entries.len());

        let delta = app
            .start_block_delta(&state)
            .expect("candidate bootstrap block delta");
        let mut writes = authenticated_writes_for_delta(target_height, &delta)
            .expect("candidate bootstrap application writes");
        for (key, entry) in &source_entries {
            if !target.contains_key(key) {
                writes.push(
                    AuthWrite::delete_poco_snapshot(
                        PocoWritePermitV0::test_only(),
                        entry.jmt_key().expect("candidate source physical key"),
                    )
                    .expect("candidate source deletion"),
                );
            }
        }
        for (key, entry) in &target {
            if source_entries
                .get(key)
                .is_none_or(|source| source.value != entry.value)
            {
                writes.push(
                    AuthWrite::put_poco_snapshot(
                        PocoWritePermitV0::test_only(),
                        entry.jmt_key().expect("candidate target physical key"),
                        entry.value.clone(),
                    )
                    .expect("candidate target insertion"),
                );
            }
        }
        let manifest = PocoSnapshotManifestV0::from_entries(
            trnm_consensus_types::Height::new(target_height),
            target_entries,
        )
        .expect("candidate source manifest");
        writes.push(
            AuthWrite::put_poco_snapshot(
                PocoWritePermitV0::test_only(),
                poco_snapshot_manifest_key().expect("candidate source manifest key"),
                manifest.encode(),
            )
            .expect("candidate source manifest write"),
        );
        writes.sort_by(|left, right| left.key().cmp(right.key()));
        let auth_update = if let Some(store) = &app.core.store {
            store
                .plan_auth_update(target_height, writes)
                .expect("candidate persistent bootstrap plan")
        } else {
            app.core
                .auth_tree
                .lock()
                .expect("candidate bootstrap JMT")
                .plan_put_value_set(target_height, writes)
                .expect("candidate in-memory bootstrap plan")
        };
        let app_hash = auth_update.root_hash.into();
        let validator_updates = effective_validator_lifecycle(&state, &delta)
            .expect("candidate bootstrap lifecycle")
            .updates_due_at_finalize_height(target_height)
            .expect("candidate bootstrap validator updates");
        state.pending = Some(PendingBlock {
            height: target_height,
            app_hash,
            tx_results: Vec::new(),
            native_execution: test_authorized_empty_native_execution(
                state.height,
                state.app_hash,
                target_height,
                app_hash,
            ),
            validator_updates,
            delta,
            auth_update,
            poco_checkpoint_execution: None,
        });
        drop(state);
        app.commit();
        app.clear_poco_runtime_caches()
            .expect("clear candidate bootstrap caches");
        let installed = app
            .production_poco_projection_at(target_height)
            .expect("candidate installed projection");
        assert_eq!(installed.projection().entries(), target_entries);
        assert_eq!(
            installed.projection().manifest().cutoff_height().get(),
            target_height
        );
        poco_application::validate_application_authority_projection_v0(installed.projection())
            .expect("candidate installed source authority audit");
    }

    fn plan_authenticated_candidate_v0(
        app: &CometBftApplication,
        height: u64,
        block_hash: &[u8],
        timestamp_ms: u64,
    ) -> AuthenticatedPocoCandidateSelectionV0 {
        let state = app.core.state.lock().expect("candidate application state");
        let capability = app
            .execute_block(&state, &[], timestamp_ms, block_hash)
            .expect("candidate checkpoint production plan")
            .poco_checkpoint_execution
            .expect("scheduled checkpoint produces candidate authority");
        assert_eq!(
            capability.checkpoint_execution().checkpoint_height().get(),
            height
        );
        capability
    }

    fn assert_authenticated_candidate_matches_vector_v0(
        capability: &AuthenticatedPocoCandidateSelectionV0,
        scenario: &serde_json::Value,
    ) {
        let checkpoint = &scenario["checkpoint"];
        assert_eq!(
            hex::encode(capability.transcript_digest()),
            checkpoint["transcript_digest_hex"]
                .as_str()
                .expect("candidate transcript digest")
        );
        assert_eq!(
            hex::encode(capability.result_digest()),
            checkpoint["result_digest_hex"]
                .as_str()
                .expect("candidate result digest")
        );
        assert_eq!(
            hex::encode(capability.candidate_parameters_hash().as_bytes()),
            checkpoint["candidate_parameters_hash_hex"]
                .as_str()
                .expect("candidate parameter hash")
        );
        assert_eq!(
            capability.fallback_used(),
            checkpoint["fallback_used"]
                .as_bool()
                .expect("candidate fallback bit")
        );
        assert_eq!(
            u16::from(capability.fallback_reason()),
            u16::try_from(
                checkpoint["fallback_reason_code"]
                    .as_u64()
                    .expect("candidate fallback reason")
            )
            .expect("candidate fallback reason is u16")
        );
        assert_eq!(
            capability
                .computed_candidate_ids()
                .iter()
                .map(|validator_id| hex::encode(validator_id.as_bytes()))
                .collect::<Vec<_>>(),
            checkpoint["computed_candidate_ids_hex"]
                .as_array()
                .expect("candidate ID array")
                .iter()
                .map(|value| value.as_str().expect("candidate ID hex").to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            hex::encode(
                capability
                    .effective_validator_set()
                    .try_cev0_bytes()
                    .expect("encode effective candidate validator set")
            ),
            checkpoint["effective_validator_set_cev0_hex"]
                .as_str()
                .expect("effective candidate validator set")
        );
        assert_ne!(capability.authorization_id(), [0; 32]);
    }

    #[test]
    fn authenticated_candidate_corpus_replays_across_abci_sqlite_cache_and_restore() {
        static NEXT_CANDIDATE_REPLAY_DIR: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let vector = authenticated_candidate_vector_v0();
        assert_eq!(
            vector["schema"].as_str(),
            Some("trnm.poco-bft.authenticated-candidate-selection-fixture.v0")
        );
        let compact_profile = &vector["compact_profile"];
        let checkpoint_height = compact_profile["checkpoint_height"]
            .as_u64()
            .expect("candidate checkpoint height");
        let parent_height = checkpoint_height - 1;
        let cutoff_height = compact_profile["cutoff_height"]
            .as_u64()
            .expect("candidate cutoff height");
        let source_bootstrap_height = cutoff_height - 1;

        for scenario_name in ["positive", "authenticated_fallback"] {
            let scenario = &vector[scenario_name];
            let source_entries = authenticated_candidate_scenario_entries_v0(scenario);
            let checkpoint = &scenario["checkpoint"];
            let timestamp_ms = checkpoint["timestamp_ms"]
                .as_u64()
                .expect("candidate checkpoint timestamp");
            let block_hash = hex::decode(
                checkpoint["block_hash_hex"]
                    .as_str()
                    .expect("candidate checkpoint block hash"),
            )
            .expect("decode candidate checkpoint block hash");

            // ProcessProposal and FinalizeBlock use separate application
            // instances and therefore cannot share a pending block, cached
            // JMT plan, or private candidate capability.
            let (process_app, _) = authenticated_candidate_abci_fixture_v0(compact_profile, None);
            let (finalize_app, _) = authenticated_candidate_abci_fixture_v0(compact_profile, None);
            advance_authenticated_candidate_app_v0(&process_app, source_bootstrap_height - 1);
            install_authenticated_candidate_source_v0(
                &process_app,
                source_bootstrap_height,
                &source_entries,
            );
            advance_authenticated_candidate_app_v0(&finalize_app, source_bootstrap_height - 1);
            install_authenticated_candidate_source_v0(
                &finalize_app,
                source_bootstrap_height,
                &source_entries,
            );
            advance_authenticated_candidate_app_v0(&process_app, parent_height);
            advance_authenticated_candidate_app_v0(&finalize_app, parent_height);
            assert_eq!(
                process_app.height_and_app_hash().unwrap(),
                finalize_app.height_and_app_hash().unwrap()
            );

            let process_capability = plan_authenticated_candidate_v0(
                &process_app,
                checkpoint_height,
                &block_hash,
                timestamp_ms,
            );
            assert_authenticated_candidate_matches_vector_v0(&process_capability, scenario);
            let process_response = process_app.process_proposal(RequestProcessProposal {
                txs: Vec::new(),
                hash: Bytes::copy_from_slice(&block_hash),
                height: i64::try_from(checkpoint_height).unwrap(),
                time: authenticated_candidate_block_time_v0(timestamp_ms),
                ..Default::default()
            });
            assert_eq!(
                process_response.status,
                response_process_proposal::ProposalStatus::Accept as i32
            );
            assert!(process_app.core.state.lock().unwrap().pending.is_none());

            let finalized = finalize_app.finalize_block(RequestFinalizeBlock {
                txs: Vec::new(),
                hash: Bytes::copy_from_slice(&block_hash),
                height: i64::try_from(checkpoint_height).unwrap(),
                time: authenticated_candidate_block_time_v0(timestamp_ms),
                ..Default::default()
            });
            let finalize_capability = finalize_app
                .core
                .state
                .lock()
                .unwrap()
                .pending
                .as_ref()
                .and_then(|pending| pending.poco_checkpoint_execution.clone())
                .expect("FinalizeBlock retains private candidate capability until commit");
            assert_eq!(process_capability, finalize_capability);
            assert_eq!(finalized.events.len(), 1);
            assert_eq!(
                finalized.events[0].r#type,
                "trnm.poco.checkpoint-execution.v0"
            );
            assert!(finalized.events[0].attributes.iter().any(|attribute| {
                attribute.key == "candidate_authorization_id"
                    && attribute.value == hex::encode(finalize_capability.authorization_id())
            }));

            // A V3 restore retains the authenticated cutoff history needed to
            // recompute the exact private checkpoint/candidate authority.
            let snapshot = wait_for_snapshot(&process_app, parent_height);
            assert_eq!(snapshot.format, SNAPSHOT_FORMAT_V3);
            let v3_target = CometBftApplication::new(process_app.core.config.clone())
                .expect("candidate V3 target");
            assert_eq!(
                v3_target
                    .offer_snapshot(RequestOfferSnapshot {
                        snapshot: Some(snapshot.clone()),
                        app_hash: Bytes::copy_from_slice(
                            &process_app.height_and_app_hash().unwrap().1,
                        ),
                    })
                    .result,
                response_offer_snapshot::Result::Accept as i32
            );
            for index in 0..snapshot.chunks {
                let chunk = process_app
                    .load_snapshot_chunk(RequestLoadSnapshotChunk {
                        height: snapshot.height,
                        format: snapshot.format,
                        chunk: index,
                    })
                    .chunk;
                assert_eq!(
                    v3_target
                        .apply_snapshot_chunk(RequestApplySnapshotChunk {
                            index,
                            chunk,
                            sender: "candidate-v3-replay".to_string(),
                        })
                        .result,
                    response_apply_snapshot_chunk::Result::Accept as i32
                );
            }
            let v3_capability = plan_authenticated_candidate_v0(
                &v3_target,
                checkpoint_height,
                &block_hash,
                timestamp_ms,
            );
            assert_eq!(v3_capability, process_capability);

            // Complete the two independent ABCI instances only after their
            // proposal/finalization evidence has been compared.
            let process_finalized = process_app.finalize_block(RequestFinalizeBlock {
                txs: Vec::new(),
                hash: Bytes::copy_from_slice(&block_hash),
                height: i64::try_from(checkpoint_height).unwrap(),
                time: authenticated_candidate_block_time_v0(timestamp_ms),
                ..Default::default()
            });
            assert_eq!(process_finalized.app_hash, finalized.app_hash);
            process_app.commit();
            finalize_app.commit();
            assert_eq!(
                process_app.height_and_app_hash().unwrap(),
                finalize_app.height_and_app_hash().unwrap()
            );

            // SQLite starts from the same semantic corpus but maintains an
            // independent retained JMT. Restart at the committed parent,
            // prove rejection is write-free, then exercise explicit cache
            // miss/hit and the real checkpoint ABCI path.
            let replay_id =
                NEXT_CANDIDATE_REPLAY_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let persistent_root = std::env::temp_dir().join(format!(
                "trnm-poco-authenticated-candidate-replay-{}-{}-{replay_id}",
                std::process::id(),
                now_unix_ms()
            ));
            fs::create_dir_all(&persistent_root).unwrap();
            let state_path = persistent_root.join("app-state.json");
            let (persistent, persistent_config) =
                authenticated_candidate_abci_fixture_v0(compact_profile, Some(state_path));
            advance_authenticated_candidate_app_v0(&persistent, source_bootstrap_height - 1);
            install_authenticated_candidate_source_v0(
                &persistent,
                source_bootstrap_height,
                &source_entries,
            );
            // Stop at the exact periodic cutoff and drain its asynchronous
            // snapshot before advancing. A busy production worker may legally
            // coalesce later interval requests to the newest committed head.
            advance_authenticated_candidate_app_v0(&persistent, cutoff_height);
            let periodic_v4_snapshot = wait_for_snapshot(&persistent, cutoff_height);
            assert_eq!(periodic_v4_snapshot.format, SNAPSHOT_FORMAT_V4);
            advance_authenticated_candidate_app_v0(&persistent, parent_height);
            let parent_head = persistent.height_and_app_hash().unwrap();

            // Restore the real periodic V4 snapshot at the retained cutoff,
            // advance the restored SQLite application through the checkpoint
            // parent, then recompute the checkpoint. A latest-only V4 snapshot
            // made at the parent correctly drops the earlier cutoff and is not
            // checkpoint-grade history.
            let mut v4_config = persistent_config.clone();
            v4_config.state_path =
                Some(persistent_root.join(format!("candidate-v4-target-{scenario_name}.json")));
            let v4_target =
                CometBftApplication::new(v4_config).expect("candidate V4 restore target");
            assert_eq!(
                v4_target
                    .offer_snapshot(RequestOfferSnapshot {
                        snapshot: Some(periodic_v4_snapshot.clone()),
                        app_hash: Bytes::copy_from_slice(
                            &persistent
                                .production_poco_projection_at(cutoff_height)
                                .expect("candidate V4 cutoff source")
                                .state_root(),
                        ),
                    })
                    .result,
                response_offer_snapshot::Result::Accept as i32
            );
            for index in 0..periodic_v4_snapshot.chunks {
                let chunk = persistent
                    .load_snapshot_chunk(RequestLoadSnapshotChunk {
                        height: periodic_v4_snapshot.height,
                        format: periodic_v4_snapshot.format,
                        chunk: index,
                    })
                    .chunk;
                assert_eq!(
                    v4_target
                        .apply_snapshot_chunk(RequestApplySnapshotChunk {
                            index,
                            chunk,
                            sender: "candidate-v4-replay".to_string(),
                        })
                        .result,
                    response_apply_snapshot_chunk::Result::Accept as i32
                );
            }
            assert_eq!(v4_target.height_and_app_hash().unwrap().0, cutoff_height);
            advance_authenticated_candidate_app_v0(&v4_target, parent_height);
            assert_eq!(v4_target.height_and_app_hash().unwrap(), parent_head);
            let v4_capability = plan_authenticated_candidate_v0(
                &v4_target,
                checkpoint_height,
                &block_hash,
                timestamp_ms,
            );
            assert_eq!(v4_capability, process_capability);
            drop(v4_target);
            drop(persistent);
            let restarted =
                CometBftApplication::new(persistent_config.clone()).expect("candidate restart");
            assert_eq!(restarted.height_and_app_hash().unwrap(), parent_head);

            let cutoff_before = restarted
                .production_poco_projection_at(cutoff_height)
                .expect("candidate retained cutoff before rejection");
            let rejected = restarted.process_proposal(RequestProcessProposal {
                txs: Vec::new(),
                hash: Bytes::copy_from_slice(&[0; 32]),
                height: i64::try_from(checkpoint_height).unwrap(),
                time: authenticated_candidate_block_time_v0(timestamp_ms),
                ..Default::default()
            });
            assert_eq!(
                rejected.status,
                response_process_proposal::ProposalStatus::Reject as i32
            );
            assert_eq!(restarted.height_and_app_hash().unwrap(), parent_head);
            assert!(restarted.core.state.lock().unwrap().pending.is_none());
            let cutoff_after = restarted
                .production_poco_projection_at(cutoff_height)
                .expect("candidate retained cutoff after rejection");
            assert_eq!(cutoff_after, cutoff_before);
            drop(restarted);
            let restarted =
                CometBftApplication::new(persistent_config.clone()).expect("candidate rere-start");
            assert_eq!(restarted.height_and_app_hash().unwrap(), parent_head);

            restarted.clear_poco_runtime_caches().unwrap();
            assert!(restarted
                .core
                .poco_projection_cache
                .lock()
                .unwrap()
                .is_empty());
            let cache_miss_capability = plan_authenticated_candidate_v0(
                &restarted,
                checkpoint_height,
                &block_hash,
                timestamp_ms,
            );
            let cache_entries = restarted.core.poco_projection_cache.lock().unwrap().len();
            assert!(
                cache_entries >= 2,
                "candidate plan must load head and cutoff"
            );
            let cache_hit_capability = plan_authenticated_candidate_v0(
                &restarted,
                checkpoint_height,
                &block_hash,
                timestamp_ms,
            );
            assert_eq!(
                restarted.core.poco_projection_cache.lock().unwrap().len(),
                cache_entries
            );
            assert_eq!(cache_hit_capability, cache_miss_capability);
            assert_eq!(cache_hit_capability, process_capability);

            assert_eq!(
                restarted
                    .process_proposal(RequestProcessProposal {
                        txs: Vec::new(),
                        hash: Bytes::copy_from_slice(&block_hash),
                        height: i64::try_from(checkpoint_height).unwrap(),
                        time: authenticated_candidate_block_time_v0(timestamp_ms),
                        ..Default::default()
                    })
                    .status,
                response_process_proposal::ProposalStatus::Accept as i32
            );
            let persistent_finalized = restarted.finalize_block(RequestFinalizeBlock {
                txs: Vec::new(),
                hash: Bytes::copy_from_slice(&block_hash),
                height: i64::try_from(checkpoint_height).unwrap(),
                time: authenticated_candidate_block_time_v0(timestamp_ms),
                ..Default::default()
            });
            let persistent_capability = restarted
                .core
                .state
                .lock()
                .unwrap()
                .pending
                .as_ref()
                .and_then(|pending| pending.poco_checkpoint_execution.clone())
                .expect("persistent FinalizeBlock candidate capability");
            assert_eq!(persistent_capability, process_capability);
            restarted.commit();
            let committed_head = restarted.height_and_app_hash().unwrap();
            assert_eq!(
                committed_head.1.as_slice(),
                persistent_finalized.app_hash.as_ref()
            );
            drop(restarted);

            // Capabilities are never serialized. After the checkpoint commit,
            // reconstruct one fresh from the retained historical cutoff and
            // exact committed block inputs, then compare every private field.
            let restarted = CometBftApplication::new(persistent_config.clone())
                .expect("candidate post-checkpoint restart");
            assert_eq!(restarted.height_and_app_hash().unwrap(), committed_head);
            let cutoff = restarted
                .production_poco_projection_at(cutoff_height)
                .expect("candidate retained cutoff after checkpoint restart");
            let active_validators = restarted
                .core
                .state
                .lock()
                .unwrap()
                .validator_lifecycle
                .as_ref()
                .expect("candidate validator lifecycle")
                .active_validators
                .clone();
            let fresh = authorize_poco_checkpoint_candidate_selection_v0(
                restarted
                    .core
                    .config
                    .poco_authority
                    .as_ref()
                    .expect("candidate configured authority"),
                PocoCheckpointExecutionInputV0 {
                    chain_id: &restarted.core.config.chain_id,
                    parent_height,
                    parent_state_root: parent_head.1,
                    block_height: checkpoint_height,
                    block_hash: &block_hash,
                    timestamp_ms,
                    txs: &[],
                    tx_results: &[],
                    next_state_root: committed_head.1,
                },
                &cutoff,
                &active_validators,
            )
            .expect("fresh post-restart candidate reconstruction");
            assert_eq!(fresh, persistent_capability);
            drop(restarted);
            fs::remove_dir_all(&persistent_root).unwrap();
        }
    }

    #[test]
    fn authenticated_candidate_checkpoint_rejects_physically_pruned_cutoff_without_writes() {
        static NEXT_PRUNED_CANDIDATE_DIR: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let vector = authenticated_candidate_vector_v0();
        let compact_profile = &vector["compact_profile"];
        let scenario = &vector["positive"];
        let checkpoint_height = compact_profile["checkpoint_height"]
            .as_u64()
            .expect("pruned candidate checkpoint height");
        let parent_height = checkpoint_height - 1;
        let cutoff_height = compact_profile["cutoff_height"]
            .as_u64()
            .expect("pruned candidate cutoff height");
        let source_bootstrap_height = cutoff_height - 1;
        let source_entries = authenticated_candidate_scenario_entries_v0(scenario);
        let timestamp_ms = scenario["checkpoint"]["timestamp_ms"]
            .as_u64()
            .expect("pruned candidate checkpoint timestamp");
        let block_hash = hex::decode(
            scenario["checkpoint"]["block_hash_hex"]
                .as_str()
                .expect("pruned candidate checkpoint block hash"),
        )
        .expect("decode pruned candidate checkpoint block hash");

        let replay_id =
            NEXT_PRUNED_CANDIDATE_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let persistent_root = std::env::temp_dir().join(format!(
            "trnm-poco-authenticated-candidate-pruned-cutoff-{}-{}-{replay_id}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&persistent_root).unwrap();
        let state_path = persistent_root.join("app-state.json");
        let database_path = state_path.with_extension("json.sqlite3");
        let (app, config) =
            authenticated_candidate_abci_fixture_v0(compact_profile, Some(state_path));
        advance_authenticated_candidate_app_v0(&app, source_bootstrap_height - 1);
        install_authenticated_candidate_source_v0(&app, source_bootstrap_height, &source_entries);
        // Stop at the exact periodic cutoff and drain its asynchronous V4
        // snapshot before advancing. A busy production worker intentionally
        // coalesces later interval requests to the newest committed head.
        advance_authenticated_candidate_app_v0(&app, cutoff_height);
        let cutoff_snapshot = wait_for_snapshot(&app, cutoff_height);
        assert_eq!(cutoff_snapshot.format, SNAPSHOT_FORMAT_V4);
        advance_authenticated_candidate_app_v0(&app, parent_height);

        let parent_head = app.height_and_app_hash().unwrap();
        let parent_projection = app
            .production_poco_projection_at(parent_height)
            .expect("pruned candidate parent projection before rejection");
        let parent_state = app.core.state.lock().unwrap().clone();
        assert!(parent_state.pending.is_none());
        let retain_from = cutoff_height
            .checked_add(1)
            .expect("pruned candidate retention floor overflow");
        assert!(
            retain_from < parent_height,
            "lead-three cutoff pruning floor must remain below the checkpoint parent"
        );
        let store = app.core.store.as_ref().expect("pruned candidate store");
        let stats = store
            .prune_auth_versions_before(&parent_state, retain_from)
            .expect("physically prune candidate cutoff history");
        assert!(stats.roots_removed > 0);
        assert_eq!(
            store.auth_prune_status().unwrap(),
            store::AuthPruneStatus {
                query_floor: retain_from,
                target: None,
            }
        );
        let cutoff_error = store
            .production_poco_projection(cutoff_height)
            .expect_err("pruned cutoff projection must be unavailable")
            .to_string();
        assert!(
            cutoff_error.contains("was pruned; retained query floor"),
            "unexpected pruned-cutoff error: {cutoff_error}"
        );
        let physical_cutoff_roots = rusqlite::Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM auth_roots WHERE version_be=?1",
                rusqlite::params![cutoff_height.to_be_bytes().as_slice()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap();
        assert_eq!(
            physical_cutoff_roots, 0,
            "logical retention floor advanced without removing the cutoff root"
        );

        let request = RequestProcessProposal {
            txs: Vec::new(),
            hash: Bytes::copy_from_slice(&block_hash),
            height: i64::try_from(checkpoint_height).unwrap(),
            time: authenticated_candidate_block_time_v0(timestamp_ms),
            ..Default::default()
        };
        let rejected = app.process_proposal(request);
        assert_eq!(
            rejected.status,
            response_process_proposal::ProposalStatus::Reject as i32
        );
        {
            let state = app.core.state.lock().unwrap();
            assert_eq!((state.height, state.app_hash), parent_head);
            assert!(state.pending.is_none());
        }
        assert_eq!(
            app.production_poco_projection_at(parent_height)
                .expect("candidate parent survives ProcessProposal rejection"),
            parent_projection
        );
        assert_eq!(store.auth_prune_status().unwrap().query_floor, retain_from);
        drop(parent_state);
        drop(app);

        let restarted = CometBftApplication::new(config.clone()).expect("pruned candidate restart");
        assert_eq!(restarted.height_and_app_hash().unwrap(), parent_head);
        assert!(restarted.core.state.lock().unwrap().pending.is_none());
        assert_eq!(
            restarted
                .production_poco_projection_at(parent_height)
                .expect("candidate parent survives restart"),
            parent_projection
        );
        let restarted_store = restarted
            .core
            .store
            .as_ref()
            .expect("restarted pruned candidate store");
        assert_eq!(
            restarted_store.auth_prune_status().unwrap(),
            store::AuthPruneStatus {
                query_floor: retain_from,
                target: None,
            }
        );

        // This is an independent defensive FinalizeBlock invocation after
        // ProcessProposal has already proved that normal consensus flow must
        // reject the block. The ABCI Application trait has no Result/status
        // channel for FinalizeBlock, so execution divergence is deliberately
        // fail-stop rather than a normal rejection response. Catch that
        // expected panic, then inspect the poisoned state guard directly:
        // execution failed before installing a pending block or advancing the
        // committed head.
        let finalized = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            restarted.finalize_block(RequestFinalizeBlock {
                txs: Vec::new(),
                hash: Bytes::copy_from_slice(&block_hash),
                height: i64::try_from(checkpoint_height).unwrap(),
                time: authenticated_candidate_block_time_v0(timestamp_ms),
                ..Default::default()
            })
        }));
        let panic = match finalized {
            Ok(_) => panic!("FinalizeBlock accepted a pruned cutoff"),
            Err(panic) => panic,
        };
        let panic_message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .expect("pruned-cutoff FinalizeBlock panic must carry a message");
        assert!(
            panic_message.contains("was pruned; retained query floor"),
            "unexpected pruned-cutoff FinalizeBlock panic: {panic_message}"
        );
        {
            let state = restarted
                .core
                .state
                .lock()
                .expect_err("failed FinalizeBlock must poison its guarded state")
                .into_inner();
            assert_eq!((state.height, state.app_hash), parent_head);
            assert!(state.pending.is_none());
        }
        assert_eq!(
            restarted_store.auth_prune_status().unwrap().query_floor,
            retain_from
        );
        drop(restarted);

        let final_restart =
            CometBftApplication::new(config).expect("post-Finalize pruned candidate restart");
        assert_eq!(final_restart.height_and_app_hash().unwrap(), parent_head);
        assert!(final_restart.core.state.lock().unwrap().pending.is_none());
        assert_eq!(
            final_restart
                .production_poco_projection_at(parent_height)
                .expect("candidate parent survives failed FinalizeBlock and restart"),
            parent_projection
        );
        let final_store = final_restart
            .core
            .store
            .as_ref()
            .expect("final pruned candidate store");
        assert_eq!(
            final_store.auth_prune_status().unwrap(),
            store::AuthPruneStatus {
                query_floor: retain_from,
                target: None,
            }
        );
        assert!(final_store
            .production_poco_projection(cutoff_height)
            .is_err());
        drop(final_restart);
        fs::remove_dir_all(&persistent_root).unwrap();
    }

    fn simulate(app: &CometBftApplication, tx: &CanonicalTxV1) -> SimulationResponseV1 {
        let query = app.query(RequestQuery {
            path: "/simulate".to_string(),
            data: Bytes::from(serde_json::to_vec(tx).unwrap()),
            ..Default::default()
        });
        assert_eq!(query.code, 0, "simulation query failed: {}", query.log);
        assert_eq!(query.log, SIMULATION_RESPONSE_SCHEMA_V1);
        serde_json::from_slice(&query.value).unwrap()
    }

    fn finalize_and_commit(
        app: &CometBftApplication,
        height: u64,
        txs: Vec<Bytes>,
    ) -> ResponseFinalizeBlock {
        let response = app.finalize_block(RequestFinalizeBlock {
            txs,
            height: height as i64,
            time: block_time(),
            ..Default::default()
        });
        app.commit();
        response
    }

    fn legacy_v3_state_bytes(state: &AppState) -> Vec<u8> {
        let legacy_app_hash = compute_app_hash(
            state.height,
            &state.objects,
            &state.command_ids,
            &state.signer_nonces,
            state.validator_lifecycle.as_ref(),
        );
        serde_json::to_vec(&serde_json::json!({
            "schema": "trnm_cometbft_app_state_v3",
            "height": state.height,
            "app_hash_hex": hex::encode(legacy_app_hash),
            "objects": state.objects.values().map(|object| serde_json::json!({
                "object_key_hex": object.object_key_hex,
                "object_type": object.object_type,
                "version": object.version,
                "value_hash_hex": object.value_hash_hex,
                "value_hex": hex::encode(&object.value_bytes),
            })).collect::<Vec<_>>(),
            "command_ids": state.command_ids,
            "signer_nonces": state.signer_nonces,
            "validator_lifecycle": state.validator_lifecycle,
        }))
        .unwrap()
    }

    fn update_key_hex(update: &ValidatorUpdate) -> String {
        match update
            .pub_key
            .as_ref()
            .and_then(|key| key.sum.as_ref())
            .unwrap()
        {
            public_key::Sum::Ed25519(bytes) => hex::encode(bytes),
            _ => panic!("validator update did not contain an Ed25519 key"),
        }
    }

    fn assert_transition_rejected(
        app: &CometBftApplication,
        transition: &ValidatorSetTransitionV1,
        nonce: u64,
    ) {
        let response = app.process_proposal(RequestProcessProposal {
            txs: vec![transition_tx(transition, nonce)],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(
            response.status,
            response_process_proposal::ProposalStatus::Reject as i32
        );
    }

    #[test]
    fn independent_apps_produce_identical_app_hashes() {
        let (left, envelope) = fixture();
        let (right, _) = fixture();
        let tx = Bytes::from(serde_json::to_vec(&envelope).unwrap());
        let request = RequestFinalizeBlock {
            txs: vec![tx],
            height: 1,
            time: block_time(),
            ..Default::default()
        };
        let left_result = left.finalize_block(request.clone());
        let right_result = right.finalize_block(request);
        assert_eq!(left_result.tx_results[0].code, 0);
        assert_eq!(left_result.app_hash, right_result.app_hash);
        assert_ne!(left_result.app_hash.as_ref(), empty_app_hash());
    }

    #[test]
    fn canonical_transactions_emit_events_query_state_and_reject_bad_inputs() {
        use trnm_protocol::{CanonicalCommandV1, CANONICAL_TX_SCHEMA_V1, TASK_OBJECT_TYPE_V1};

        let operator_key = SigningKey::from_bytes(&[11u8; 32]);
        let client_key = SigningKey::from_bytes(&[12u8; 32]);
        let app = CometBftApplication::new(ConsensusAppConfig {
            schema: CONFIG_SCHEMA_V1.to_string(),
            chain_id: "trnm-comet-spike".to_string(),
            authorized_signers: vec![
                AuthorizedSignerV1 {
                    signer_id: "did:operator:1".to_string(),
                    signer_role: "operator".to_string(),
                    public_key_hex: public_key_hex(&operator_key),
                },
                AuthorizedSignerV1 {
                    signer_id: "did:client:1".to_string(),
                    signer_role: "hepta".to_string(),
                    public_key_hex: public_key_hex(&client_key),
                },
            ],
            poco_authority: None,
            state_path: None,
        })
        .unwrap();
        initialize(&app);

        let credit = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:operator:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreditAccount {
                account: "did:client:1".to_string(),
                amount: 100_000,
            },
        };
        let credit_result = finalize_and_commit(
            &app,
            1,
            vec![canonical_tx(
                &operator_key,
                "credit-client",
                "did:operator:1",
                "operator",
                1,
                &credit,
            )],
        );
        assert_eq!(
            credit_result.tx_results[0].events[0].r#type,
            "account_credited"
        );

        let create = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:client:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreateTask {
                task_id: "task-1".to_string(),
                reward: 10_000,
                worker_stake: 5_000,
                result_deadline_height: 20,
                challenge_window_blocks: 10,
            },
        };
        let create_bytes = canonical_tx(
            &client_key,
            "create-task",
            "did:client:1",
            "hepta",
            1,
            &create,
        );
        let create_result = finalize_and_commit(&app, 2, vec![create_bytes.clone()]);
        assert!(create_result.tx_results[0]
            .events
            .iter()
            .any(|event| event.r#type == "task_created"));
        assert!(create_result.tx_results[0].gas_used > 0);

        let query = app.query(RequestQuery {
            path: "/task/task-1".to_string(),
            ..Default::default()
        });
        assert_eq!(query.code, 0);
        assert_eq!(query.log, TASK_OBJECT_TYPE_V1);
        let task: trnm_protocol::TaskV1 = serde_json::from_slice(&query.value).unwrap();
        assert_eq!(task.status, trnm_protocol::TaskStatusV1::Open);
        let proof_query = app.query(RequestQuery {
            path: "/task/task-1".to_string(),
            prove: true,
            ..Default::default()
        });
        assert_eq!(proof_query.code, 0);
        assert_eq!(proof_query.log, TASK_OBJECT_TYPE_V1);
        let authenticated = AuthenticatedObjectRecord::decode(&proof_query.value).unwrap();
        assert_eq!(authenticated.object_type, TASK_OBJECT_TYPE_V1);
        assert_eq!(authenticated.value, query.value);
        let proof_ops = proof_query.proof_ops.expect("v4 query returns proof ops");
        assert_eq!(proof_ops.ops.len(), 1);
        assert_eq!(proof_ops.ops[0].r#type, "ics23:jmt:v1");
        assert_eq!(proof_ops.ops[0].key, proof_query.key);
        assert!(!proof_ops.ops[0].data.is_empty());

        let replay = app.process_proposal(RequestProcessProposal {
            txs: vec![create_bytes],
            height: 3,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(
            replay.status,
            response_process_proposal::ProposalStatus::Reject as i32
        );

        let mut over_gas = create;
        over_gas.nonce = 2;
        over_gas.max_gas = 1;
        over_gas.command = CanonicalCommandV1::Transfer {
            to: "did:operator:1".to_string(),
            amount: 1,
        };
        let rejected = app.process_proposal(RequestProcessProposal {
            txs: vec![canonical_tx(
                &client_key,
                "over-gas",
                "did:client:1",
                "hepta",
                2,
                &over_gas,
            )],
            height: 3,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(
            rejected.status,
            response_process_proposal::ProposalStatus::Reject as i32
        );

        let unknown = SignedCommandEnvelopeV1::sign(
            "trnm-comet-spike",
            "unknown-payload",
            "did:client:1",
            "hepta",
            3,
            1_000,
            10_000,
            "trnm.unknown.v1",
            b"{}",
            &client_key,
        )
        .unwrap();
        let rejected = app.process_proposal(RequestProcessProposal {
            txs: vec![Bytes::from(serde_json::to_vec(&unknown).unwrap())],
            height: 3,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(
            rejected.status,
            response_process_proposal::ProposalStatus::Reject as i32
        );
    }

    #[test]
    fn simulation_matches_check_tx_and_committed_receipt_without_mutation() {
        use trnm_protocol::{AccountV1, CanonicalCommandV1, CANONICAL_TX_SCHEMA_V1};

        let operator_key = SigningKey::from_bytes(&[11u8; 32]);
        let client_key = SigningKey::from_bytes(&[12u8; 32]);
        let app = CometBftApplication::new(ConsensusAppConfig {
            schema: CONFIG_SCHEMA_V1.to_string(),
            chain_id: "trnm-comet-spike".to_string(),
            authorized_signers: vec![
                AuthorizedSignerV1 {
                    signer_id: "did:operator:1".to_string(),
                    signer_role: "operator".to_string(),
                    public_key_hex: public_key_hex(&operator_key),
                },
                AuthorizedSignerV1 {
                    signer_id: "did:client:1".to_string(),
                    signer_role: "hepta".to_string(),
                    public_key_hex: public_key_hex(&client_key),
                },
            ],
            poco_authority: None,
            state_path: None,
        })
        .unwrap();
        initialize(&app);
        let credit = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:operator:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreditAccount {
                account: "did:client:1".to_string(),
                amount: 100_000,
            },
        };
        finalize_and_commit(
            &app,
            1,
            vec![canonical_tx(
                &operator_key,
                "simulation-credit-client",
                "did:operator:1",
                "operator",
                1,
                &credit,
            )],
        );

        let transfer = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:client:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::Transfer {
                to: "did:operator:1".to_string(),
                amount: 7,
            },
        };
        let before = {
            let state = app.core.state.lock().unwrap();
            (
                state.height,
                state.app_hash,
                state.objects.clone(),
                state.command_ids.clone(),
                state.signer_nonces.clone(),
            )
        };
        let simulation = simulate(&app, &transfer);
        assert_eq!(simulation.schema, SIMULATION_RESPONSE_SCHEMA_V1);
        assert_eq!(simulation.height, before.0);
        assert_eq!(simulation.app_hash_hex, hex::encode(before.1));
        assert!(simulation.would_succeed);
        assert_eq!(simulation.error, None);
        assert!(simulation.gas_used > 0);
        assert_eq!(
            simulation.fee_estimate.parse::<u128>().unwrap(),
            u128::from(simulation.gas_used)
        );
        assert_eq!(simulation.events.len(), 1);
        assert_eq!(simulation.events[0].kind, "transfer");
        {
            let state = app.core.state.lock().unwrap();
            assert_eq!(state.height, before.0);
            assert_eq!(state.app_hash, before.1);
            assert_eq!(state.objects, before.2);
            assert_eq!(state.command_ids, before.3);
            assert_eq!(state.signer_nonces, before.4);
            assert!(state.pending.is_none());
        }

        let payload = serde_json::to_vec(&transfer).unwrap();
        let now = now_unix_ms();
        let check_envelope = SignedCommandEnvelopeV1::sign(
            "trnm-comet-spike",
            "simulation-check-transfer",
            "did:client:1",
            "hepta",
            1,
            now.saturating_sub(1_000),
            now.saturating_add(60_000),
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &payload,
            &client_key,
        )
        .unwrap();
        let checked = app.check_tx(RequestCheckTx {
            tx: Bytes::from(serde_json::to_vec(&check_envelope).unwrap()),
            ..Default::default()
        });
        assert_eq!(checked.code, 0, "CheckTx failed: {}", checked.log);
        assert_eq!(checked.gas_wanted, transfer.max_gas as i64);
        assert_eq!(checked.gas_used, simulation.gas_used as i64);
        assert_eq!(checked.events.len(), simulation.events.len());
        assert_eq!(checked.events[0].r#type, simulation.events[0].kind);

        let finalized = finalize_and_commit(
            &app,
            2,
            vec![canonical_tx(
                &client_key,
                "simulation-finalize-transfer",
                "did:client:1",
                "hepta",
                1,
                &transfer,
            )],
        );
        assert_eq!(finalized.tx_results[0].code, 0);
        assert_eq!(finalized.tx_results[0].gas_used, simulation.gas_used as i64);
        assert_eq!(
            finalized.tx_results[0].events[0].r#type,
            simulation.events[0].kind
        );
        let account_query = app.query(RequestQuery {
            path: "/account/did:client:1".to_string(),
            ..Default::default()
        });
        let client: AccountV1 = serde_json::from_slice(&account_query.value).unwrap();
        let charged_fee = simulation.fee_estimate.parse::<u128>().unwrap();
        assert_eq!(client.balance, 100_000 - 7 - charged_fee);
        assert_eq!(client.nonce, 1);
    }

    #[test]
    fn simulation_reports_limit_nonce_and_authorization_failures_with_estimates() {
        use trnm_protocol::{CanonicalCommandV1, CANONICAL_TX_SCHEMA_V1};

        let operator_key = SigningKey::from_bytes(&[11u8; 32]);
        let client_key = SigningKey::from_bytes(&[12u8; 32]);
        let app = CometBftApplication::new(ConsensusAppConfig {
            schema: CONFIG_SCHEMA_V1.to_string(),
            chain_id: "trnm-comet-spike".to_string(),
            authorized_signers: vec![
                AuthorizedSignerV1 {
                    signer_id: "did:operator:1".to_string(),
                    signer_role: "operator".to_string(),
                    public_key_hex: public_key_hex(&operator_key),
                },
                AuthorizedSignerV1 {
                    signer_id: "did:client:1".to_string(),
                    signer_role: "hepta".to_string(),
                    public_key_hex: public_key_hex(&client_key),
                },
            ],
            poco_authority: None,
            state_path: None,
        })
        .unwrap();
        initialize(&app);
        let credit = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:operator:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreditAccount {
                account: "did:client:1".to_string(),
                amount: 100_000,
            },
        };
        finalize_and_commit(
            &app,
            1,
            vec![canonical_tx(
                &operator_key,
                "simulation-failure-credit",
                "did:operator:1",
                "operator",
                1,
                &credit,
            )],
        );
        let base = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:client:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::Transfer {
                to: "did:operator:1".to_string(),
                amount: 1,
            },
        };
        let before = app.height_and_app_hash().unwrap();

        let mut low_gas = base.clone();
        low_gas.max_gas = 1;
        let response = simulate(&app, &low_gas);
        assert!(!response.would_succeed);
        assert!(response.gas_used > low_gas.max_gas);
        assert!(response.fee_estimate.parse::<u128>().unwrap() > 0);
        assert_eq!(response.error.as_ref().unwrap().code, "gas_limit_exceeded");

        let mut low_fee = base.clone();
        low_fee.fee_limit = 0;
        let response = simulate(&app, &low_fee);
        assert!(!response.would_succeed);
        assert!(response.gas_used > 0);
        assert!(response.fee_estimate.parse::<u128>().unwrap() > low_fee.fee_limit);
        assert_eq!(response.error.as_ref().unwrap().code, "fee_limit_exceeded");

        let mut wrong_nonce = base.clone();
        wrong_nonce.nonce = 2;
        let response = simulate(&app, &wrong_nonce);
        assert!(!response.would_succeed);
        assert!(response.gas_used > 0);
        assert_eq!(response.error.as_ref().unwrap().code, "nonce_mismatch");

        let mut unauthorized = base;
        unauthorized.sender = "did:unknown:1".to_string();
        let response = simulate(&app, &unauthorized);
        assert!(!response.would_succeed);
        assert!(response.gas_used > 0);
        assert_eq!(response.error.as_ref().unwrap().code, "unauthorized_sender");
        assert_eq!(app.height_and_app_hash().unwrap(), before);
        assert!(app.core.state.lock().unwrap().pending.is_none());
    }

    #[test]
    fn simulation_query_has_versioned_schema_and_latest_state_only() {
        let (app, _) = fixture();
        let malformed = app.query(RequestQuery {
            path: "/simulate".to_string(),
            data: Bytes::from_static(b"{not-json"),
            ..Default::default()
        });
        assert_eq!(malformed.code, 0);
        assert_eq!(malformed.log, SIMULATION_RESPONSE_SCHEMA_V1);
        let response: SimulationResponseV1 = serde_json::from_slice(&malformed.value).unwrap();
        assert_eq!(response.schema, SIMULATION_RESPONSE_SCHEMA_V1);
        assert!(!response.would_succeed);
        assert_eq!(
            response.error.as_ref().unwrap().code,
            "invalid_transaction_json"
        );
        let value: serde_json::Value = serde_json::from_slice(&malformed.value).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            [
                "app_hash_hex",
                "error",
                "events",
                "fee_estimate",
                "gas_used",
                "height",
                "schema",
                "would_succeed",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        );

        assert_ne!(
            app.query(RequestQuery {
                path: "/simulate".to_string(),
                data: Bytes::from_static(b"{}"),
                prove: true,
                ..Default::default()
            })
            .code,
            0
        );
        finalize_and_commit(&app, 1, Vec::new());
        assert_eq!(
            app.query(RequestQuery {
                path: "/simulate".to_string(),
                data: Bytes::from_static(b"{}"),
                height: 0,
                ..Default::default()
            })
            .code,
            0,
            "height zero always means latest and must not be rejected"
        );
        finalize_and_commit(&app, 2, Vec::new());
        assert_ne!(
            app.query(RequestQuery {
                path: "/simulate".to_string(),
                data: Bytes::from_static(b"{}"),
                height: 1,
                ..Default::default()
            })
            .code,
            0
        );
    }

    #[test]
    fn incremental_v4_root_matches_materialized_authenticated_state() {
        fn object(key: &str, version: u64, value: &[u8]) -> StoredObject {
            StoredObject {
                object_key_hex: key.to_string(),
                object_type: "fixture".to_string(),
                version,
                value_hash_hex: hex::encode(hash_domain("trnm.state.object.value.v1", &[value])),
                value_bytes: value.to_vec(),
            }
        }

        let (app, _) = fixture();
        let state = app.core.state.lock().unwrap().clone();
        let base_tree = app.core.auth_tree.lock().unwrap().clone();

        let mut delta = BlockDelta::default();
        delta.objects.insert("b".to_string(), object("b", 1, b"b1"));
        delta.objects.insert("c".to_string(), object("c", 2, b"c2"));

        let incremental = base_tree
            .plan_put_value_set(1, authenticated_writes_for_delta(1, &delta).unwrap())
            .unwrap();
        let mut materialized = state;
        materialized.objects.extend(delta.objects);
        let fresh = InMemoryAuthTree::default()
            .plan_put_value_set(0, authenticated_writes_for_state(0, &materialized).unwrap())
            .unwrap();
        assert_eq!(
            incremental.root_hash, fresh.root_hash,
            "incremental and materialized v4 roots must match"
        );
    }

    #[test]
    fn init_chain_binds_chain_identity_signers_and_app_version() {
        let (app, _) = fixture();
        let response = app.init_chain(genesis_request(&app));
        assert_ne!(response.app_hash.as_ref(), empty_app_hash());
        let fee_policy = default_fee_policy_object();
        assert_eq!(
            app.core
                .state
                .lock()
                .unwrap()
                .objects
                .get(&fee_policy.object_key_hex),
            Some(&fee_policy)
        );

        let mut wrong_chain = genesis_request(&app);
        wrong_chain.chain_id = "wrong-chain".to_string();
        assert!(std::panic::catch_unwind(|| app.init_chain(wrong_chain)).is_err());

        let mut wrong_version = genesis_request(&app);
        let mut genesis: GenesisAppStateV2 =
            serde_json::from_slice(&wrong_version.app_state_bytes).unwrap();
        genesis.app_version = APP_VERSION + 1;
        wrong_version.app_state_bytes = Bytes::from(serde_json::to_vec(&genesis).unwrap());
        assert!(std::panic::catch_unwind(|| app.init_chain(wrong_version)).is_err());

        let mut changed_governance = genesis_request(&app);
        let mut genesis: GenesisAppStateV2 =
            serde_json::from_slice(&changed_governance.app_state_bytes).unwrap();
        genesis.validator_governance.min_activation_delay_blocks = 3;
        changed_governance.app_state_bytes = Bytes::from(serde_json::to_vec(&genesis).unwrap());
        assert!(std::panic::catch_unwind(|| app.init_chain(changed_governance)).is_err());
    }

    #[test]
    fn exact_poco_projection_survives_state_codec_and_sqlite_restart() {
        let (memory_app, _) = fixture();
        let mut memory_state = memory_app.core.state.lock().unwrap().clone();
        let mut memory_tree = memory_app.core.auth_tree.lock().unwrap().clone();
        let update = memory_tree
            .plan_put_value_set(1, production_poco_writes(1, false))
            .unwrap();
        memory_state.height = 1;
        memory_state.app_hash = memory_tree.apply(update).unwrap().into();
        let encoded = encode_state(&memory_state, &memory_tree).unwrap();
        let (decoded_state, decoded_tree) = decode_state(&encoded).unwrap();
        assert_eq!(decoded_state.height, 1);
        assert_eq!(decoded_state.app_hash, memory_state.app_hash);
        assert!(decoded_tree
            .prove(1, poco_snapshot_manifest_key().unwrap())
            .unwrap()
            .value
            .is_some());

        let root = std::env::temp_dir().join(format!(
            "trnm-poco-projection-valid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state_path = root.join("valid").join("app-state.json");
        let (persistent, _) = persistent_fixture(state_path.clone());
        let config = persistent.core.config.clone();
        let current = persistent.core.state.lock().unwrap().clone();
        let store = persistent.core.store.as_ref().unwrap();
        let auth_update = store
            .plan_auth_update(1, production_poco_writes(1, false))
            .unwrap();
        let app_hash = auth_update.root_hash.into();
        let pending = PendingBlock {
            height: 1,
            app_hash,
            tx_results: Vec::new(),
            native_execution: test_authorized_empty_native_execution(
                current.height,
                current.app_hash,
                1,
                app_hash,
            ),
            validator_updates: Vec::new(),
            delta: BlockDelta::default(),
            auth_update,
            poco_checkpoint_execution: None,
        };
        store.persist_transition(&current, &pending, 0).unwrap();
        drop(persistent);

        let restarted = CometBftApplication::new(config).unwrap();
        let restarted_state = restarted.core.state.lock().unwrap();
        assert_eq!(restarted_state.height, 1);
        assert_eq!(restarted_state.app_hash, app_hash);
        assert!(restarted
            .core
            .store
            .as_ref()
            .unwrap()
            .prove(1, poco_snapshot_manifest_key().unwrap())
            .unwrap()
            .value
            .is_some());
        drop(restarted_state);
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hidden_poco_leaf_is_rejected_by_state_codec_and_before_sqlite_commit() {
        let (memory_app, _) = fixture();
        let mut memory_state = memory_app.core.state.lock().unwrap().clone();
        let mut memory_tree = memory_app.core.auth_tree.lock().unwrap().clone();
        let update = memory_tree
            .plan_put_value_set(1, production_poco_writes(1, true))
            .unwrap();
        memory_state.height = 1;
        memory_state.app_hash = memory_tree.apply(update).unwrap().into();
        assert!(encode_state(&memory_state, &memory_tree).is_err());

        let root = std::env::temp_dir().join(format!(
            "trnm-poco-projection-invalid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state_path = root.join("invalid").join("app-state.json");
        let (persistent, _) = persistent_fixture(state_path);
        let config = persistent.core.config.clone();
        let current = persistent.core.state.lock().unwrap().clone();
        let store = persistent.core.store.as_ref().unwrap();
        let auth_update = store
            .plan_auth_update(1, production_poco_writes(1, true))
            .unwrap();
        let pending = PendingBlock {
            height: 1,
            app_hash: auth_update.root_hash.into(),
            tx_results: Vec::new(),
            native_execution: test_authorized_empty_native_execution(
                current.height,
                current.app_hash,
                1,
                auth_update.root_hash.into(),
            ),
            validator_updates: Vec::new(),
            delta: BlockDelta::default(),
            auth_update,
            poco_checkpoint_execution: None,
        };
        let error = store.persist_transition(&current, &pending, 0).unwrap_err();
        assert!(format!("{error:#}").contains("manifest entry count mismatch"));
        drop(persistent);
        let restarted = CometBftApplication::new(config).unwrap();
        assert_eq!(restarted.core.state.lock().unwrap().height, 0);
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn genesis_requires_safe_validator_power_unless_single_node_dev_mode_is_committed() {
        let (fixture_app, _) = fixture();

        let unsafe_single = |allow_unsafe: bool| {
            let app = CometBftApplication::new(fixture_app.core.config.clone()).unwrap();
            let mut request = genesis_request(&app);
            let mut genesis: GenesisAppStateV2 =
                serde_json::from_slice(&request.app_state_bytes).unwrap();
            genesis.initial_validators = vec![validator(21, 10)];
            genesis
                .validator_governance
                .unsafe_allow_single_validator_genesis = allow_unsafe;
            request.validators = validators_to_abci(&genesis.initial_validators).unwrap();
            request.app_state_bytes = Bytes::from(serde_json::to_vec(&genesis).unwrap());
            (app, request)
        };

        let (rejected, request) = unsafe_single(false);
        assert!(std::panic::catch_unwind(|| rejected.init_chain(request)).is_err());

        let (accepted, request) = unsafe_single(true);
        assert!(!accepted.init_chain(request).app_hash.is_empty());

        let dominant = CometBftApplication::new(fixture_app.core.config.clone()).unwrap();
        let mut request = genesis_request(&dominant);
        let mut genesis: GenesisAppStateV2 =
            serde_json::from_slice(&request.app_state_bytes).unwrap();
        genesis.initial_validators = vec![
            validator(21, 40),
            validator(22, 10),
            validator(23, 10),
            validator(24, 10),
        ];
        genesis
            .initial_validators
            .sort_by(|left, right| left.public_key_hex.cmp(&right.public_key_hex));
        request.validators = validators_to_abci(&genesis.initial_validators).unwrap();
        request.app_state_bytes = Bytes::from(serde_json::to_vec(&genesis).unwrap());
        assert!(std::panic::catch_unwind(|| dominant.init_chain(request)).is_err());
    }

    #[test]
    fn validator_lifecycle_add_remove_and_key_rotation_activate_at_h_plus_two() {
        let (app, _) = fixture();

        let mut five = initial_validators();
        five.push(validator(25, 10));
        let add = validator_transition(&app, "validator-add-25", 3, five, &[25]);
        let response = finalize_and_commit(&app, 1, vec![transition_tx(&add, 1)]);
        assert_eq!(response.validator_updates.len(), 1);
        assert_eq!(response.validator_updates[0].power, 10);
        assert_eq!(
            update_key_hex(&response.validator_updates[0]),
            validator(25, 10).public_key_hex
        );
        {
            let state = app.core.state.lock().unwrap();
            let lifecycle = state.validator_lifecycle.as_ref().unwrap();
            assert_eq!(lifecycle.active_validators.len(), 4);
            assert_eq!(
                lifecycle
                    .pending_transition
                    .as_ref()
                    .unwrap()
                    .activation_height,
                3
            );
            let proof = app
                .core
                .auth_tree
                .lock()
                .unwrap()
                .prove(state.height, validator_state_key().unwrap())
                .unwrap();
            let record =
                AuthenticatedObjectRecord::decode(proof.value.as_deref().unwrap()).unwrap();
            let committed: ValidatorLifecycleStateV1 =
                serde_json::from_slice(&record.value).unwrap();
            assert_eq!(&committed, lifecycle);
        }
        assert!(finalize_and_commit(&app, 2, Vec::new())
            .validator_updates
            .is_empty());
        finalize_and_commit(&app, 3, Vec::new());
        {
            let state = app.core.state.lock().unwrap();
            let lifecycle = state.validator_lifecycle.as_ref().unwrap();
            assert_eq!(lifecycle.active_validators.len(), 5);
            assert!(lifecycle.pending_transition.is_none());
            assert_eq!(
                lifecycle.last_applied_transition_id.as_deref(),
                Some("validator-add-25")
            );
        }

        let removed_key = validator(21, 10).public_key_hex;
        let four = app
            .core
            .state
            .lock()
            .unwrap()
            .validator_lifecycle
            .as_ref()
            .unwrap()
            .active_validators
            .iter()
            .filter(|validator| validator.public_key_hex != removed_key)
            .cloned()
            .collect::<Vec<_>>();
        let remove = validator_transition(&app, "validator-remove-21", 6, four, &[]);
        let response = finalize_and_commit(&app, 4, vec![transition_tx(&remove, 2)]);
        assert_eq!(response.validator_updates.len(), 1);
        assert_eq!(response.validator_updates[0].power, 0);
        assert_eq!(update_key_hex(&response.validator_updates[0]), removed_key);
        finalize_and_commit(&app, 5, Vec::new());
        finalize_and_commit(&app, 6, Vec::new());
        assert_eq!(
            app.core
                .state
                .lock()
                .unwrap()
                .validator_lifecycle
                .as_ref()
                .unwrap()
                .active_validators
                .len(),
            4
        );

        let rotated_out = validator(22, 10).public_key_hex;
        let rotated_in = validator(26, 10).public_key_hex;
        let mut rotated = app
            .core
            .state
            .lock()
            .unwrap()
            .validator_lifecycle
            .as_ref()
            .unwrap()
            .active_validators
            .iter()
            .filter(|validator| validator.public_key_hex != rotated_out)
            .cloned()
            .collect::<Vec<_>>();
        rotated.push(validator(26, 10));
        let rotation = validator_transition(&app, "validator-rotate-22-26", 9, rotated, &[26]);
        let response = finalize_and_commit(&app, 7, vec![transition_tx(&rotation, 3)]);
        let updates = response
            .validator_updates
            .iter()
            .map(|update| (update_key_hex(update), update.power))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(updates.get(&rotated_out), Some(&0));
        assert_eq!(updates.get(&rotated_in), Some(&10));
        finalize_and_commit(&app, 8, Vec::new());
        finalize_and_commit(&app, 9, Vec::new());
        let state = app.core.state.lock().unwrap();
        let lifecycle = state.validator_lifecycle.as_ref().unwrap();
        assert!(lifecycle
            .active_validators
            .iter()
            .any(|validator| validator.public_key_hex == rotated_in));
        assert!(!lifecycle
            .active_validators
            .iter()
            .any(|validator| validator.public_key_hex == rotated_out));
        assert_eq!(
            lifecycle.last_applied_transition_id.as_deref(),
            Some("validator-rotate-22-26")
        );
    }

    #[test]
    fn validator_lifecycle_rejects_missing_wrong_and_tampered_key_proofs() {
        for case in ["missing", "wrong", "tampered"] {
            let (app, _) = fixture();
            let mut target = initial_validators();
            target.push(validator(25, 10));
            let mut transition =
                validator_transition(&app, "validator-proof-case", 3, target, &[25]);
            match case {
                "missing" => transition.new_validator_proofs.clear(),
                "wrong" => {
                    let message = validator_key_proof_message(
                        &transition.chain_id,
                        &transition.transition_id,
                        &transition.base_validator_set_hash_hex,
                        transition.activation_height,
                        &transition.target_validators,
                    )
                    .unwrap();
                    transition.new_validator_proofs[0].signature_hex =
                        sign_hex(&SigningKey::from_bytes(&[26u8; 32]), &message);
                }
                "tampered" => {
                    transition.new_validator_proofs[0]
                        .signature_hex
                        .replace_range(0..2, "00");
                }
                _ => unreachable!(),
            }
            assert_transition_rejected(&app, &transition, 1);
        }
    }

    #[test]
    fn validator_lifecycle_rejects_stale_repeated_and_unsafe_transitions() {
        let (stale_app, _) = fixture();
        let mut target = initial_validators();
        target.push(validator(25, 10));
        let mut stale = validator_transition(&stale_app, "validator-stale-base", 3, target, &[25]);
        stale.base_validator_set_hash_hex = "00".repeat(32);
        assert_transition_rejected(&stale_app, &stale, 1);

        let (pending_app, _) = fixture();
        let mut first_target = initial_validators();
        first_target.push(validator(25, 10));
        let first = validator_transition(
            &pending_app,
            "validator-first-pending",
            3,
            first_target,
            &[25],
        );
        let mut second_target = initial_validators();
        second_target.push(validator(26, 10));
        let second = validator_transition(
            &pending_app,
            "validator-second-pending",
            3,
            second_target,
            &[26],
        );
        let response = pending_app.process_proposal(RequestProcessProposal {
            txs: vec![transition_tx(&first, 1), transition_tx(&second, 2)],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(
            response.status,
            response_process_proposal::ProposalStatus::Reject as i32
        );

        let (small_app, _) = fixture();
        let too_small = validator_transition(
            &small_app,
            "validator-too-small",
            3,
            initial_validators().into_iter().take(3).collect(),
            &[],
        );
        assert_transition_rejected(&small_app, &too_small, 1);

        let (power_app, _) = fixture();
        let mut unsafe_power = initial_validators();
        unsafe_power.push(validator(25, 30));
        let unsafe_power =
            validator_transition(&power_app, "validator-unsafe-power", 3, unsafe_power, &[25]);
        assert_transition_rejected(&power_app, &unsafe_power, 1);

        let (alias_app, _) = fixture();
        let mut aliased_target = initial_validators();
        aliased_target[0].public_key_hex = aliased_target[0].public_key_hex.to_uppercase();
        let alias = ValidatorSetTransitionV1 {
            schema: VALIDATOR_TRANSITION_SCHEMA_V1.to_string(),
            chain_id: alias_app.core.config.chain_id.clone(),
            transition_id: "validator-case-alias".to_string(),
            base_validator_set_hash_hex: alias_app
                .core
                .state
                .lock()
                .unwrap()
                .validator_lifecycle
                .as_ref()
                .unwrap()
                .active_set_hash_hex()
                .unwrap(),
            activation_height: 3,
            target_validators: aliased_target,
            new_validator_proofs: Vec::new(),
        };
        assert_transition_rejected(&alias_app, &alias, 1);
    }

    #[test]
    fn pending_validator_transition_survives_sqlite_restart_and_snapshot_restore() {
        let root = std::env::temp_dir().join(format!(
            "trnm-validator-lifecycle-persistence-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (fixture_app, _) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path),
            ..fixture_app.core.config.clone()
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        let mut target = initial_validators();
        target.push(validator(25, 10));
        let transition = validator_transition(&app, "validator-persist-pending", 10, target, &[25]);
        finalize_and_commit(&app, 1, vec![transition_tx(&transition, 1)]);
        for height in 2..=5 {
            finalize_and_commit(&app, height, Vec::new());
        }
        let expected = app.height_and_app_hash().unwrap();
        let expected_pending = app
            .core
            .state
            .lock()
            .unwrap()
            .validator_lifecycle
            .as_ref()
            .unwrap()
            .pending_transition
            .clone();
        wait_for_snapshot(&app, 5);
        drop(app);

        let source = CometBftApplication::new(config).unwrap();
        assert_eq!(source.height_and_app_hash().unwrap(), expected);
        assert_eq!(
            source
                .core
                .state
                .lock()
                .unwrap()
                .validator_lifecycle
                .as_ref()
                .unwrap()
                .pending_transition,
            expected_pending
        );
        let snapshot = source
            .list_snapshots()
            .snapshots
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(snapshot.height, 5);

        let target_app = CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(root.join("restored-state.json")),
            ..source.core.config.clone()
        })
        .unwrap();
        assert_eq!(
            target_app
                .offer_snapshot(RequestOfferSnapshot {
                    snapshot: Some(snapshot.clone()),
                    app_hash: Bytes::copy_from_slice(&expected.1),
                })
                .result,
            response_offer_snapshot::Result::Accept as i32
        );
        for index in 0..snapshot.chunks {
            let chunk = source
                .load_snapshot_chunk(RequestLoadSnapshotChunk {
                    height: snapshot.height,
                    format: snapshot.format,
                    chunk: index,
                })
                .chunk;
            assert_eq!(
                target_app
                    .apply_snapshot_chunk(RequestApplySnapshotChunk {
                        index,
                        chunk,
                        sender: "source-validator".to_string(),
                    })
                    .result,
                response_apply_snapshot_chunk::Result::Accept as i32
            );
        }
        assert_eq!(target_app.height_and_app_hash().unwrap(), expected);
        assert_eq!(
            target_app
                .core
                .state
                .lock()
                .unwrap()
                .validator_lifecycle
                .as_ref()
                .unwrap()
                .pending_transition,
            expected_pending
        );

        for height in 6..=10 {
            let source_response = finalize_and_commit(&source, height, Vec::new());
            let target_response = finalize_and_commit(&target_app, height, Vec::new());
            assert_eq!(
                source_response.validator_updates,
                target_response.validator_updates
            );
            if height == 8 {
                assert_eq!(source_response.validator_updates.len(), 1);
                assert_eq!(source_response.validator_updates[0].power, 10);
            } else {
                assert!(source_response.validator_updates.is_empty());
            }
            assert_eq!(
                source.height_and_app_hash().unwrap(),
                target_app.height_and_app_hash().unwrap()
            );
        }
        {
            let source_state = source.core.state.lock().unwrap();
            let source_lifecycle = source_state.validator_lifecycle.as_ref().unwrap();
            assert!(source_lifecycle.pending_transition.is_none());
            assert_eq!(source_lifecycle.active_validators.len(), 5);
            assert_eq!(
                source_lifecycle.last_applied_transition_id.as_deref(),
                Some("validator-persist-pending")
            );
        }
        wait_for_snapshot(&source, 10);
        wait_for_snapshot(&target_app, 10);
        drop(source);
        drop(target_app);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prepare_proposal_filters_replays_and_invalid_transactions_deterministically() {
        let (app, envelope) = fixture();
        let valid = Bytes::from(serde_json::to_vec(&envelope).unwrap());
        let invalid = Bytes::from_static(b"not-json");
        let request = RequestPrepareProposal {
            txs: vec![invalid, valid.clone(), valid.clone()],
            max_tx_bytes: 1024 * 1024,
            height: 1,
            time: block_time(),
            ..Default::default()
        };
        let left = app.prepare_proposal(request.clone());
        let right = app.prepare_proposal(request);
        assert_eq!(left.txs, vec![valid]);
        assert_eq!(left, right);
        assert_eq!(
            app.process_proposal(RequestProcessProposal {
                txs: left.txs,
                height: 1,
                time: block_time(),
                ..Default::default()
            })
            .status,
            response_process_proposal::ProposalStatus::Accept as i32
        );
    }

    #[test]
    fn prepare_proposal_enforces_max_bytes_without_blocking_later_small_tx() {
        let (app, envelope) = fixture();
        let valid = Bytes::from(serde_json::to_vec(&envelope).unwrap());
        let oversized = Bytes::from(vec![0u8; valid.len() + 1]);
        let response = app.prepare_proposal(RequestPrepareProposal {
            txs: vec![oversized, valid.clone()],
            max_tx_bytes: valid.len() as i64,
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(response.txs, vec![valid]);
    }

    #[test]
    fn process_proposal_rejects_tampered_envelope() {
        let (app, mut envelope) = fixture();
        envelope.payload_hex = hex::encode(b"tampered");
        let response = app.process_proposal(RequestProcessProposal {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(
            response.status,
            response_process_proposal::ProposalStatus::Reject as i32
        );
    }

    #[test]
    fn consensus_paths_reject_missing_and_invalid_timestamps_deterministically() {
        let (app, envelope) = fixture();
        let tx = Bytes::from(serde_json::to_vec(&envelope).unwrap());
        assert!(app
            .prepare_proposal(RequestPrepareProposal {
                txs: vec![tx.clone()],
                max_tx_bytes: 1_000_000,
                height: 1,
                time: None,
                ..Default::default()
            })
            .txs
            .is_empty());
        assert_eq!(
            app.process_proposal(RequestProcessProposal {
                txs: vec![tx.clone()],
                height: 1,
                time: None,
                ..Default::default()
            })
            .status,
            response_process_proposal::ProposalStatus::Reject as i32
        );
        assert_eq!(
            app.process_proposal(RequestProcessProposal {
                txs: vec![tx],
                height: 1,
                time: Some(Timestamp {
                    seconds: 2,
                    nanos: 1_000_000_000,
                }),
                ..Default::default()
            })
            .status,
            response_process_proposal::ProposalStatus::Reject as i32
        );

        let (direct_finalize, envelope) = fixture();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            direct_finalize.finalize_block(RequestFinalizeBlock {
                txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
                height: 1,
                time: None,
                ..Default::default()
            });
        }));
        assert!(panic.is_err());
    }

    #[test]
    fn finalize_does_not_advance_committed_height_before_commit() {
        let (app, envelope) = fixture();
        let response = app.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(response.tx_results[0].code, 0);
        assert_eq!(app.height_and_app_hash().unwrap().0, 0);
        app.commit();
        assert_eq!(app.height_and_app_hash().unwrap().0, 1);
    }

    #[test]
    fn commit_without_finalize_fails_stop() {
        let (app, _) = fixture();
        assert!(std::panic::catch_unwind(|| app.commit()).is_err());
    }

    #[test]
    fn committed_state_survives_application_restart() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-state-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (fixture_app, envelope) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path),
            ..fixture_app.core.config.clone()
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        let response = app.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(response.tx_results[0].code, 0);
        app.commit();
        let expected = app.height_and_app_hash().unwrap();
        drop(app);

        let restarted = CometBftApplication::new(config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), expected);
        {
            let state = restarted.core.state.lock().unwrap();
            assert!(state.objects.is_empty());
            assert!(state.command_ids.is_empty());
            assert!(state.signer_nonces.is_empty());
        }
        assert_eq!(restarted.core.auth_tree.lock().unwrap().node_count(), 0);
        assert_eq!(
            restarted
                .query(RequestQuery {
                    path: format!("/object/{}", fee_policy_key()),
                    prove: true,
                    ..Default::default()
                })
                .code,
            0
        );
        finalize_and_commit(&restarted, 2, Vec::new());
        assert_eq!(restarted.height_and_app_hash().unwrap().0, 2);
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_restores_fresh_application_and_persists_state() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-restored-state-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let (source, envelope) = persistent_fixture(root.join("source-state.json"));
        let response = source.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(response.tx_results[0].code, 0);
        source.commit();
        for height in 2..=5 {
            finalize_and_commit(&source, height, Vec::new());
        }
        let source_state = source.height_and_app_hash().unwrap();
        let snapshot = wait_for_snapshot(&source, 5);
        assert_eq!(snapshot.height, source_state.0);
        assert_eq!(snapshot.format, SNAPSHOT_FORMAT_V4);
        let state_path = root.join("target-state.json");
        let target = CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(state_path.clone()),
            ..source.core.config.clone()
        })
        .unwrap();
        let offer = target.offer_snapshot(RequestOfferSnapshot {
            snapshot: Some(snapshot.clone()),
            app_hash: Bytes::copy_from_slice(&source_state.1),
        });
        assert_eq!(offer.result, response_offer_snapshot::Result::Accept as i32);
        for index in 0..snapshot.chunks {
            let chunk = source
                .load_snapshot_chunk(RequestLoadSnapshotChunk {
                    height: snapshot.height,
                    format: snapshot.format,
                    chunk: index,
                })
                .chunk;
            let applied = target.apply_snapshot_chunk(RequestApplySnapshotChunk {
                index,
                chunk,
                sender: "source-validator".to_string(),
            });
            assert_eq!(
                applied.result,
                response_apply_snapshot_chunk::Result::Accept as i32
            );
        }
        assert_eq!(target.height_and_app_hash().unwrap(), source_state);
        wait_for_snapshot(&target, 5);
        drop(target);

        let restarted = CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(state_path),
            ..source.core.config.clone()
        })
        .unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), source_state);
        drop(restarted);
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_validation_jobs_and_outbox_remain_source_local_across_snapshot_install() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-snapshot-reservation-scrub-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let journal_counts = |path: &Path| {
            let connection = rusqlite::Connection::open(path).unwrap();
            let jobs = connection
                .query_row("SELECT COUNT(*) FROM validation_jobs_v0", [], |row| {
                    row.get::<_, u64>(0)
                })
                .unwrap();
            let outbox = connection
                .query_row(
                    "SELECT COUNT(*) FROM validation_callback_outbox_v0",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap();
            (jobs, outbox)
        };

        let source_state_path = root.join("source-state.json");
        let source_database_path = source_state_path.with_extension("json.sqlite3");
        let (source, _) = persistent_fixture(source_state_path);
        finalize_and_commit(&source, 1, Vec::new());
        let committed = source.core.state.lock().unwrap().clone();
        let expected = (committed.height, committed.app_hash);
        let source_store = source.core.store.as_ref().unwrap();
        let validation_identity = match source_store.reserve_or_reopen_native_validation_job_v0(
            store::NativeValidationReservationFactsV0::new_for_test_v0(
                trnm_consensus_core::PayloadValidationRouteV0::Proposal,
                11,
                &source.core.config.chain_id,
            ),
        ) {
            Ok(store::NativeValidationReservationDecisionV0::Reserved(token)) => {
                (token.route(), token.validation_id())
            }
            Ok(store::NativeValidationReservationDecisionV0::Existing(_)) | Err(_) => {
                panic!("first source reservation must own durable admission")
            }
        };
        // This is a deliberate raw-SQL malformed-child fixture: the active v8
        // binary accepts only fully verified callback delivery states, but snapshot
        // scrubbing must still remove child rows before their parent without
        // changing the authoritative source copy.
        let source_connection = rusqlite::Connection::open(&source_database_path).unwrap();
        source_connection
            .execute(
                "INSERT INTO validation_callback_outbox_v0(
                     route, block_id, view_be, generation_be, result_kind,
                     artifact_checksum, payload_codec, payload_bytes,
                     payload_checksum, idempotency_key, delivery_attempt_be,
                     outbox_checksum
                 ) VALUES (0, ?1, ?2, ?3, 0, ?4, 'future-fixture-v0', X'01',
                           ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    validation_identity.1.block_id().as_bytes().as_slice(),
                    validation_identity.1.view().get().to_be_bytes().as_slice(),
                    validation_identity.1.generation().to_be_bytes().as_slice(),
                    [0x74_u8; 32].as_slice(),
                    [0x75_u8; 32].as_slice(),
                    [0x76_u8; 32].as_slice(),
                    0_u64.to_be_bytes().as_slice(),
                    [0x77_u8; 32].as_slice(),
                ],
            )
            .unwrap();
        source_connection
            .execute(
                "UPDATE validation_journal_accounting_v0
                 SET outbox_count_be=?1, outbox_bytes_be=?2
                 WHERE singleton=1",
                rusqlite::params![
                    1_u64.to_be_bytes().as_slice(),
                    1_u64.to_be_bytes().as_slice(),
                ],
            )
            .unwrap();
        drop(source_connection);
        assert_eq!(
            validation_identity.0,
            trnm_consensus_core::PayloadValidationRouteV0::Proposal
        );
        assert_eq!(journal_counts(&source_database_path), (1, 1));

        let snapshot_path = root.join("reservation-local.snapshot");
        let pinned = source_store.pin_snapshot(&committed).unwrap();
        let built = source_store
            .build_snapshot_database(&committed, &snapshot_path, pinned)
            .unwrap();
        assert_eq!((built.height, built.app_hash), expected);
        // The builder validates the temporary v8 database before its atomic
        // rename, so success also proves both node-local journal tables were
        // empty rather than copied into the snapshot.
        assert!(!snapshot_path.with_extension("snapshot.tmp").exists());
        assert_eq!(journal_counts(&source_database_path), (1, 1));
        assert_eq!(journal_counts(&snapshot_path), (0, 0));

        let target_state_path = root.join("target-state.json");
        let target_database_path = target_state_path.with_extension("json.sqlite3");
        let target_config = ConsensusAppConfig {
            state_path: Some(target_state_path),
            ..source.core.config.clone()
        };
        let target = CometBftApplication::new(target_config.clone()).unwrap();
        initialize(&target);
        let empty = target.core.state.lock().unwrap().clone();
        assert_eq!(empty.height, 0);
        let target_store = target.core.store.as_ref().unwrap();
        assert!(matches!(
            target_store.reserve_or_reopen_native_validation_job_v0(
                store::NativeValidationReservationFactsV0::new_for_test_v0(
                    trnm_consensus_core::PayloadValidationRouteV0::Proposal,
                    12,
                    &target.core.config.chain_id,
                ),
            ),
            Ok(store::NativeValidationReservationDecisionV0::Reserved(_))
        ));
        assert_eq!(journal_counts(&target_database_path), (1, 0));
        let error = target_store
            .install_snapshot_database(&empty, &snapshot_path, expected.0, expected.1)
            .expect_err("snapshot install must not silently discard target-local work");
        assert!(error
            .to_string()
            .contains("refuses to discard local native validation or speculative-overlay work"));
        assert_eq!(journal_counts(&target_database_path), (1, 0));
        let target_connection = rusqlite::Connection::open(&target_database_path).unwrap();
        target_connection
            .execute("DELETE FROM validation_jobs_v0", [])
            .unwrap();
        target_connection
            .execute(
                "UPDATE validation_journal_accounting_v0
                 SET job_count_be=zeroblob(8), request_bytes_be=zeroblob(8)
                 WHERE singleton=1",
                [],
            )
            .unwrap();
        drop(target_connection);
        let installed = target_store
            .install_snapshot_database(&empty, &snapshot_path, expected.0, expected.1)
            .unwrap();
        assert_eq!((installed.height, installed.app_hash), expected);
        assert_eq!(journal_counts(&target_database_path), (0, 0));
        assert_eq!(journal_counts(&source_database_path), (1, 1));
        drop(target);

        let restarted = CometBftApplication::new(target_config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), expected);
        assert_eq!(journal_counts(&target_database_path), (0, 0));
        drop(restarted);
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persistent_application_rejects_legacy_in_memory_snapshot_format() {
        let (source, envelope) = fixture();
        finalize_and_commit(
            &source,
            1,
            vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
        );
        let source_state = source.height_and_app_hash().unwrap();
        let snapshot = source.list_snapshots().snapshots.pop().unwrap();
        assert_eq!(snapshot.format, SNAPSHOT_FORMAT_V3);
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-reject-v3-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        let target = CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(root.join("target-state.json")),
            ..source.core.config.clone()
        })
        .unwrap();
        assert_eq!(
            target
                .offer_snapshot(RequestOfferSnapshot {
                    snapshot: Some(snapshot),
                    app_hash: Bytes::copy_from_slice(&source_state.1),
                })
                .result,
            response_offer_snapshot::Result::Reject as i32
        );
        drop(target);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn format4_streaming_restore_resumes_after_reoffer_and_restart() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-streaming-resume-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let (source, _) = persistent_fixture(root.join("source-state.json"));
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let envelope = SignedCommandEnvelopeV1::sign(
            "trnm-comet-spike",
            "large-streaming-snapshot",
            "did:operator:1",
            "operator",
            1,
            1_000,
            10_000,
            "opaque_fixture_v1",
            &vec![0x5a; 1024 * 1024],
            &signing_key,
        )
        .unwrap();
        finalize_and_commit(
            &source,
            1,
            vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
        );
        for height in 2..=5 {
            finalize_and_commit(&source, height, Vec::new());
        }
        let source_state = source.height_and_app_hash().unwrap();
        let snapshot = wait_for_snapshot(&source, 5);
        assert_eq!(snapshot.format, SNAPSHOT_FORMAT_V4);
        assert!(snapshot.chunks >= 2);

        let target_config = ConsensusAppConfig {
            state_path: Some(root.join("target-state.json")),
            ..source.core.config.clone()
        };
        let restore_directory = target_config
            .state_path
            .as_ref()
            .unwrap()
            .with_extension("restore");
        fs::create_dir_all(&restore_directory).unwrap();
        let orphan_stage = restore_directory.join("orphan.sqlite3.part");
        let orphan_journal = restore_directory.join("orphan.journal.json");
        fs::write(&orphan_stage, b"orphan").unwrap();
        fs::write(&orphan_journal, b"orphan").unwrap();
        let target = CometBftApplication::new(target_config.clone()).unwrap();
        let offer = || RequestOfferSnapshot {
            snapshot: Some(snapshot.clone()),
            app_hash: Bytes::copy_from_slice(&source_state.1),
        };
        assert_eq!(
            target.offer_snapshot(offer()).result,
            response_offer_snapshot::Result::Accept as i32
        );
        assert!(!orphan_stage.exists());
        assert!(!orphan_journal.exists());
        let first = source
            .load_snapshot_chunk(RequestLoadSnapshotChunk {
                height: snapshot.height,
                format: snapshot.format,
                chunk: 0,
            })
            .chunk;
        assert_eq!(
            target
                .apply_snapshot_chunk(RequestApplySnapshotChunk {
                    index: 0,
                    chunk: first,
                    sender: "source-a".to_string(),
                })
                .result,
            response_apply_snapshot_chunk::Result::Accept as i32
        );
        assert_eq!(
            target.offer_snapshot(offer()).result,
            response_offer_snapshot::Result::Accept as i32
        );
        drop(target);

        let resumed = CometBftApplication::new(target_config.clone()).unwrap();
        assert_eq!(
            resumed.offer_snapshot(offer()).result,
            response_offer_snapshot::Result::Accept as i32
        );
        for index in 1..snapshot.chunks {
            let chunk = source
                .load_snapshot_chunk(RequestLoadSnapshotChunk {
                    height: snapshot.height,
                    format: snapshot.format,
                    chunk: index,
                })
                .chunk;
            assert_eq!(
                resumed
                    .apply_snapshot_chunk(RequestApplySnapshotChunk {
                        index,
                        chunk,
                        sender: "source-b".to_string(),
                    })
                    .result,
                response_apply_snapshot_chunk::Result::Accept as i32
            );
        }
        assert_eq!(resumed.height_and_app_hash().unwrap(), source_state);
        wait_for_snapshot(&resumed, 5);
        if restore_directory.exists() {
            assert_eq!(fs::read_dir(&restore_directory).unwrap().count(), 0);
        }
        drop(resumed);
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn format4_rejects_future_unreachable_rows_and_schema_mutation() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-hostile-snapshot-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let (source, _) = persistent_fixture(root.join("source-state.json"));
        for height in 1..=5 {
            finalize_and_commit(&source, height, Vec::new());
        }
        let expected = source.height_and_app_hash().unwrap();
        wait_for_snapshot(&source, 5);
        let payload_path = {
            let snapshots = source.core.snapshots.lock().unwrap();
            match &snapshots.get(&5).unwrap().payload {
                SnapshotPayload::File { path, .. } => path.clone(),
                SnapshotPayload::Memory(_) => panic!("format-4 payload must be disk-backed"),
            }
        };
        let store = source.core.store.as_ref().unwrap();

        let future_path = root.join("future-row.snapshot");
        fs::copy(&payload_path, &future_path).unwrap();
        {
            let connection = rusqlite::Connection::open(&future_path).unwrap();
            connection
                .execute(
                    "INSERT INTO auth_values(key_hash, version_be, value, is_deleted)
                     VALUES (?1, ?2, ?3, 0)",
                    rusqlite::params![
                        [0xabu8; 32].as_slice(),
                        6_u64.to_be_bytes().as_slice(),
                        b"future".as_slice(),
                    ],
                )
                .unwrap();
        }
        assert!(
            store
                .validate_snapshot_database(&future_path, expected.0, expected.1)
                .is_err(),
            "future unreachable JMT rows must be rejected before install"
        );

        let schema_path = root.join("mutated-schema.snapshot");
        fs::copy(&payload_path, &schema_path).unwrap();
        {
            let connection = rusqlite::Connection::open(&schema_path).unwrap();
            connection
                .execute_batch("PRAGMA writable_schema=ON;")
                .unwrap();
            assert_eq!(
                connection
                    .execute(
                        "UPDATE sqlite_schema
                         SET sql=replace(
                             sql,
                             'value TEXT NOT NULL',
                             'value TEXT NOT NULL CHECK(length(value)>0)'
                         )
                         WHERE type='table' AND name='metadata'",
                        [],
                    )
                    .unwrap(),
                1
            );
            connection
                .execute_batch("PRAGMA writable_schema=OFF;")
                .unwrap();
        }
        assert!(
            store
                .validate_snapshot_database(&schema_path, expected.0, expected.1)
                .is_err(),
            "non-canonical SQLite DDL must be rejected before install"
        );

        let oversized_path = root.join("oversized-node.snapshot");
        fs::copy(&payload_path, &oversized_path).unwrap();
        {
            let connection = rusqlite::Connection::open(&oversized_path).unwrap();
            assert_eq!(
                connection
                    .execute(
                        "UPDATE auth_nodes
                         SET node=zeroblob(65537)
                         WHERE rowid=(SELECT rowid FROM auth_nodes LIMIT 1)",
                        [],
                    )
                    .unwrap(),
                1
            );
        }
        let error = store
            .validate_snapshot_database(&oversized_path, expected.0, expected.1)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("resource limit"),
            "oversized untrusted JMT rows must be rejected before decoding"
        );
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn format4_lifecycle_mismatch_is_rejected_before_destructive_install() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-lifecycle-preflight-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let (source, _) = persistent_fixture(root.join("source-state.json"));
        for height in 1..=5 {
            finalize_and_commit(&source, height, Vec::new());
        }
        let source_state = source.height_and_app_hash().unwrap();
        let original = wait_for_snapshot(&source, 5);
        let original_path = {
            let snapshots = source.core.snapshots.lock().unwrap();
            match &snapshots.get(&5).unwrap().payload {
                SnapshotPayload::File { path, .. } => path.clone(),
                SnapshotPayload::Memory(_) => panic!("format-4 payload must be disk-backed"),
            }
        };

        let mut target_config = source.core.config.clone();
        target_config.authorized_signers[0].public_key_hex =
            public_key_hex(&SigningKey::from_bytes(&[12u8; 32]));
        target_config.state_path = Some(root.join("target-state.json"));
        let target_policy_hash =
            hex::encode(signer_policy_commitment(&target_config.authorized_signers));
        let tampered_path = root.join("policy-rebound.snapshot");
        fs::copy(&original_path, &tampered_path).unwrap();
        {
            let connection = rusqlite::Connection::open(&tampered_path).unwrap();
            assert_eq!(
                connection
                    .execute(
                        "UPDATE metadata
                         SET value=?1
                         WHERE key='authorized_signers_hash_hex'",
                        rusqlite::params![&target_policy_hash],
                    )
                    .unwrap(),
                1
            );
        }
        let (total_bytes, payload_hash, chunk_hashes_hex) =
            snapshot_file_hashes_v4(&tampered_path).unwrap();
        let mut metadata: SnapshotMetadataV4 = serde_json::from_slice(&original.metadata).unwrap();
        metadata.authorized_signers_hash_hex = target_policy_hash;
        metadata.total_bytes = total_bytes;
        metadata.payload_hash_hex = hex::encode(payload_hash);
        metadata.chunk_hashes_hex = chunk_hashes_hex;
        let metadata_bytes = serde_json::to_vec(&metadata).unwrap();
        let snapshot = Snapshot {
            height: original.height,
            format: SNAPSHOT_FORMAT_V4,
            chunks: u32::try_from(metadata.chunk_hashes_hex.len()).unwrap(),
            hash: Bytes::copy_from_slice(&snapshot_manifest_hash_v4(&metadata_bytes)),
            metadata: Bytes::from(metadata_bytes),
        };

        let target = CometBftApplication::new(target_config.clone()).unwrap();
        assert_eq!(
            target
                .offer_snapshot(RequestOfferSnapshot {
                    snapshot: Some(snapshot.clone()),
                    app_hash: Bytes::copy_from_slice(&source_state.1),
                })
                .result,
            response_offer_snapshot::Result::Accept as i32
        );
        for index in 0..snapshot.chunks {
            let chunk = read_snapshot_file_chunk(
                &tampered_path,
                index as usize,
                metadata.total_bytes as usize,
            )
            .unwrap();
            let applied = target.apply_snapshot_chunk(RequestApplySnapshotChunk {
                index,
                chunk: Bytes::from(chunk),
                sender: "policy-forger".to_string(),
            });
            if index + 1 == snapshot.chunks {
                assert_eq!(
                    applied.result,
                    response_apply_snapshot_chunk::Result::RejectSnapshot as i32
                );
            } else {
                assert_eq!(
                    applied.result,
                    response_apply_snapshot_chunk::Result::Accept as i32
                );
            }
        }
        assert_eq!(target.height_and_app_hash().unwrap().0, 0);
        drop(target);

        let restarted = CometBftApplication::new(target_config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap().0, 0);
        initialize(&restarted);
        assert_eq!(restarted.height_and_app_hash().unwrap().0, 0);
        drop(restarted);
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_rejects_authenticated_leaves_omitted_from_domain_state() {
        let (source, envelope) = fixture();
        finalize_and_commit(
            &source,
            1,
            vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
        );
        let state = source.core.state.lock().unwrap().clone();
        let auth_tree = source.core.auth_tree.lock().unwrap().clone();
        let encoded = encode_state(&state, &auth_tree).expect("encode valid state");
        let mut persisted: PersistedAppStateV4 =
            serde_json::from_slice(&encoded).expect("decode persisted state");
        assert!(!persisted.objects.is_empty());
        persisted.objects.remove(0);

        let error =
            decode_state(&serde_json::to_vec(&persisted).expect("encode omitted-object snapshot"))
                .expect_err("snapshot with an unclaimed authenticated leaf must fail");
        assert!(
            error
                .to_string()
                .contains("leaves absent from persisted application state"),
            "unexpected snapshot rejection: {error:#}"
        );
    }

    #[test]
    fn snapshot_retries_tampered_chunk_without_mutating_state() {
        let (source, envelope) = fixture();
        source.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        source.commit();
        let source_state = source.height_and_app_hash().unwrap();
        let snapshot = source.list_snapshots().snapshots.pop().unwrap();
        assert_eq!(snapshot.chunks, 1);

        let (target, _) = fixture();
        let offer = target.offer_snapshot(RequestOfferSnapshot {
            snapshot: Some(snapshot.clone()),
            app_hash: Bytes::copy_from_slice(&source_state.1),
        });
        assert_eq!(offer.result, response_offer_snapshot::Result::Accept as i32);
        let mut chunk = source
            .load_snapshot_chunk(RequestLoadSnapshotChunk {
                height: snapshot.height,
                format: snapshot.format,
                chunk: 0,
            })
            .chunk
            .to_vec();
        chunk[0] ^= 1;
        let applied = target.apply_snapshot_chunk(RequestApplySnapshotChunk {
            index: 0,
            chunk: Bytes::from(chunk),
            sender: "malicious-validator".to_string(),
        });
        assert_eq!(
            applied.result,
            response_apply_snapshot_chunk::Result::Retry as i32
        );
        assert_eq!(applied.refetch_chunks, vec![0]);
        assert_eq!(
            applied.reject_senders,
            vec!["malicious-validator".to_string()]
        );
        assert_eq!(target.height_and_app_hash().unwrap().0, 0);
        let correct = source
            .load_snapshot_chunk(RequestLoadSnapshotChunk {
                height: snapshot.height,
                format: snapshot.format,
                chunk: 0,
            })
            .chunk;
        assert_eq!(
            target
                .apply_snapshot_chunk(RequestApplySnapshotChunk {
                    index: 0,
                    chunk: correct,
                    sender: "honest-validator".to_string(),
                })
                .result,
            response_apply_snapshot_chunk::Result::Accept as i32
        );
        assert_eq!(target.height_and_app_hash().unwrap(), source_state);
    }

    #[test]
    fn snapshot_rejects_invalid_lifecycle_without_panicking() {
        let (source, envelope) = fixture();
        finalize_and_commit(
            &source,
            1,
            vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
        );
        let source_state = source.height_and_app_hash().unwrap();
        let mut snapshot = source.list_snapshots().snapshots.pop().unwrap();
        let original = source
            .load_snapshot_chunk(RequestLoadSnapshotChunk {
                height: snapshot.height,
                format: snapshot.format,
                chunk: 0,
            })
            .chunk;
        let mut persisted: serde_json::Value = serde_json::from_slice(&original).unwrap();
        persisted["validator_lifecycle"]["governance"]["min_activation_delay_blocks"] =
            serde_json::json!(1);
        let tampered = serde_json::to_vec(&persisted).unwrap();
        let mut metadata: SnapshotMetadataV3 = serde_json::from_slice(&snapshot.metadata).unwrap();
        metadata.total_bytes = tampered.len() as u64;
        snapshot.chunks = tampered.len().div_ceil(SNAPSHOT_CHUNK_SIZE) as u32;
        metadata.payload_hash_hex = hex::encode(snapshot_payload_hash(&tampered));
        metadata.chunk_hashes_hex = tampered
            .chunks(SNAPSHOT_CHUNK_SIZE)
            .enumerate()
            .map(|(index, chunk)| {
                hex::encode(snapshot_chunk_hash(u32::try_from(index).unwrap(), chunk))
            })
            .collect();
        snapshot.metadata = Bytes::from(serde_json::to_vec(&metadata).unwrap());
        snapshot.hash = Bytes::copy_from_slice(&snapshot_manifest_hash(&snapshot.metadata));

        let target =
            CometBftApplication::new(source.core.config.clone()).expect("fresh target app");
        assert_eq!(
            target
                .offer_snapshot(RequestOfferSnapshot {
                    snapshot: Some(snapshot),
                    app_hash: Bytes::copy_from_slice(&source_state.1),
                })
                .result,
            response_offer_snapshot::Result::Accept as i32
        );
        let applied = std::panic::catch_unwind(|| {
            target.apply_snapshot_chunk(RequestApplySnapshotChunk {
                index: 0,
                chunk: Bytes::from(tampered),
                sender: "malicious-validator".to_string(),
            })
        });
        assert!(applied.is_ok());
        assert_eq!(
            applied.unwrap().result,
            response_apply_snapshot_chunk::Result::RejectSnapshot as i32
        );
        assert_eq!(target.height_and_app_hash().unwrap().0, 0);
    }

    #[test]
    fn snapshot_identity_rejects_wrong_chain_or_authorized_signer_policy() {
        let (source, envelope) = fixture();
        finalize_and_commit(
            &source,
            1,
            vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
        );
        let source_state = source.height_and_app_hash().unwrap();
        let snapshot = source.list_snapshots().snapshots.pop().unwrap();
        let chunk = source
            .load_snapshot_chunk(RequestLoadSnapshotChunk {
                height: snapshot.height,
                format: snapshot.format,
                chunk: 0,
            })
            .chunk;

        let mut wrong_signer_config = source.core.config.clone();
        wrong_signer_config.authorized_signers[0].public_key_hex =
            public_key_hex(&SigningKey::from_bytes(&[12u8; 32]));
        let wrong_signer = CometBftApplication::new(wrong_signer_config).unwrap();
        assert_eq!(
            wrong_signer
                .offer_snapshot(RequestOfferSnapshot {
                    snapshot: Some(snapshot.clone()),
                    app_hash: Bytes::copy_from_slice(&source_state.1),
                })
                .result,
            response_offer_snapshot::Result::Accept as i32
        );
        assert_eq!(
            wrong_signer
                .apply_snapshot_chunk(RequestApplySnapshotChunk {
                    index: 0,
                    chunk: chunk.clone(),
                    sender: "source-validator".to_string(),
                })
                .result,
            response_apply_snapshot_chunk::Result::RejectSnapshot as i32
        );

        let wrong_chain = CometBftApplication::new(ConsensusAppConfig {
            chain_id: "trnm-cloned-chain".to_string(),
            ..source.core.config.clone()
        })
        .unwrap();
        assert_eq!(
            wrong_chain
                .offer_snapshot(RequestOfferSnapshot {
                    snapshot: Some(snapshot),
                    app_hash: Bytes::copy_from_slice(&source_state.1),
                })
                .result,
            response_offer_snapshot::Result::Reject as i32
        );
    }

    #[test]
    fn snapshot_restore_cas_cannot_overwrite_concurrently_committed_state() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-snapshot-cas-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let (source, source_envelope) = persistent_fixture(root.join("source-state.json"));
        source.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&source_envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        source.commit();
        for height in 2..=5 {
            finalize_and_commit(&source, height, Vec::new());
        }
        let source_state = source.height_and_app_hash().unwrap();
        let snapshot = wait_for_snapshot(&source, 5);
        let state_path = root.join("target-state.json");
        let target_config = ConsensusAppConfig {
            state_path: Some(state_path),
            ..source.core.config.clone()
        };
        let target = CometBftApplication::new(target_config.clone()).unwrap();
        initialize(&target);
        assert_eq!(
            target
                .offer_snapshot(RequestOfferSnapshot {
                    snapshot: Some(snapshot.clone()),
                    app_hash: Bytes::copy_from_slice(&source_state.1),
                })
                .result,
            response_offer_snapshot::Result::Accept as i32
        );

        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let local_envelope = SignedCommandEnvelopeV1::sign(
            "trnm-comet-spike",
            "command-local-wins",
            "did:operator:1",
            "operator",
            2,
            1_000,
            10_000,
            "opaque_fixture_v1",
            b"local-state",
            &signing_key,
        )
        .unwrap();
        target.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&local_envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        target.commit();
        let expected = target.height_and_app_hash().unwrap();

        let chunk = source
            .load_snapshot_chunk(RequestLoadSnapshotChunk {
                height: snapshot.height,
                format: snapshot.format,
                chunk: 0,
            })
            .chunk;
        let applied = target.apply_snapshot_chunk(RequestApplySnapshotChunk {
            index: 0,
            chunk,
            sender: "stale-source".to_string(),
        });
        assert_eq!(
            applied.result,
            response_apply_snapshot_chunk::Result::RejectSnapshot as i32
        );
        assert_eq!(target.height_and_app_hash().unwrap(), expected);
        drop(target);

        let restarted = CometBftApplication::new(target_config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), expected);
        drop(restarted);
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn production_snapshots_are_periodic_disk_backed_and_bounded() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-periodic-snapshots-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        let state_path = root.join("app-state.json");
        let (fixture_app, _) = fixture();
        let app = CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(state_path.clone()),
            ..fixture_app.core.config.clone()
        })
        .unwrap();
        initialize(&app);
        for height in 1..=20 {
            finalize_and_commit(&app, height, Vec::new());
        }
        wait_for_snapshot(&app, 20);
        let snapshots = app.list_snapshots().snapshots;
        assert_eq!(snapshots.first().unwrap().height, 20);
        assert!(!snapshots.is_empty() && snapshots.len() <= RETAINED_DISK_SNAPSHOTS);
        let snapshot_heights = snapshots
            .iter()
            .map(|snapshot| snapshot.height)
            .collect::<Vec<_>>();
        let snapshot_dir = state_path.with_extension("snapshots");
        let names = fs::read_dir(&snapshot_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            names
                .iter()
                .filter(|name| name.ends_with(".snapshot"))
                .count(),
            snapshots.len()
        );
        assert_eq!(
            names
                .iter()
                .filter(|name| name.ends_with(".snapshot.manifest.json"))
                .count(),
            snapshots.len()
        );
        drop(app);
        let restarted = CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(state_path.clone()),
            ..fixture_app.core.config.clone()
        })
        .unwrap();
        assert_eq!(
            restarted
                .list_snapshots()
                .snapshots
                .iter()
                .map(|snapshot| snapshot.height)
                .collect::<Vec<_>>(),
            snapshot_heights
        );
        let app = restarted;
        let newest = &snapshots[0];
        let chunk = app.load_snapshot_chunk(RequestLoadSnapshotChunk {
            height: newest.height,
            format: newest.format,
            chunk: 0,
        });
        assert!(!chunk.chunk.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v3_json_requires_explicit_export_new_genesis_and_is_not_mutated() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-migration-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (source, envelope) = fixture();
        let response = source.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(response.tx_results[0].code, 0);
        source.commit();
        let source_state = source.core.state.lock().unwrap().clone();
        let legacy_bytes = legacy_v3_state_bytes(&source_state);
        fs::write(&state_path, &legacy_bytes).unwrap();

        let error = match CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(state_path.clone()),
            ..source.core.config.clone()
        }) {
            Ok(_) => panic!("v3 state must not migrate implicitly"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("explicit export/new-genesis migration tool"),
            "unexpected error: {error:#}"
        );
        assert_eq!(fs::read(&state_path).unwrap(), legacy_bytes);
        assert!(!state_path.with_extension("json.sqlite3").exists());
        assert!(!state_path.with_extension("json.legacy-v3").exists());
        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(status["schema"], "trnm_cometbft_app_state_v3");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sqlite_head_wins_after_crash_between_database_commit_and_status_refresh() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-recovery-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (fixture_app, envelope) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path.clone()),
            ..fixture_app.core.config.clone()
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        app.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        app.commit();
        let expected = app.height_and_app_hash().unwrap();
        drop(app);

        fs::write(
            &state_path,
            br#"{"schema":"trnm_cometbft_app_status_v2","app_version":3,"height":0,"app_hash_hex":"stale"}"#,
        )
        .unwrap();
        let restarted = CometBftApplication::new(config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), expected);
        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(status["height"], 1);
        assert_eq!(status["app_hash_hex"], hex::encode(expected.1));
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema3_sqlite_store_migrates_query_floor_atomically_and_continues() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-schema4-migration-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (fixture_app, _) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path.clone()),
            ..fixture_app.core.config.clone()
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        for height in 1..=3 {
            finalize_and_commit(&app, height, Vec::new());
        }
        let expected = app.height_and_app_hash().unwrap();
        drop(app);

        let database_path = state_path.with_extension("json.sqlite3");
        let database = rusqlite::Connection::open(&database_path).unwrap();
        database
            .execute(
                "UPDATE metadata SET value='3' WHERE key='schema_version'",
                [],
            )
            .unwrap();
        database
            .execute(
                "DELETE FROM metadata
                 WHERE key IN ('auth_query_floor', 'auth_prune_target')",
                [],
            )
            .unwrap();
        database
            .execute_batch(
                "
                DROP INDEX auth_stale_nodes_by_node_key;
                DROP TABLE auth_stale_values;
                DROP TABLE native_finalization_receipts_v0;
                DROP TABLE native_committed_head_v0;
                DROP TABLE native_authenticated_genesis_application_v0;
                DROP TABLE native_speculative_overlay_sources_v0;
                DROP TABLE native_speculative_overlays_v0;
                DROP TABLE validation_callback_outbox_v0;
                DROP TABLE validation_jobs_v0;
                DROP TABLE validation_journal_accounting_v0;
                ",
            )
            .unwrap();
        drop(database);

        let restarted = CometBftApplication::new(config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), expected);
        let store = restarted.core.store.as_ref().unwrap();
        assert_eq!(
            store.auth_prune_status().unwrap(),
            store::AuthPruneStatus {
                query_floor: 0,
                target: None,
            }
        );
        let database = rusqlite::Connection::open(database_path).unwrap();
        assert_eq!(
            database
                .query_row(
                    "SELECT value FROM metadata WHERE key='schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "13"
        );
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM validation_jobs_v0", [], |row| row
                    .get::<_, u64>(0),)
                .unwrap(),
            0
        );
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM validation_callback_outbox_v0",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        drop(database);
        finalize_and_commit(&restarted, 4, Vec::new());
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema3_latest_only_database_is_normalized_during_snapshot_install() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-schema3-snapshot-install-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let source_path = root.join("source-state.json");
        let (source, _) = persistent_fixture(source_path);
        for height in 1..=5 {
            finalize_and_commit(&source, height, Vec::new());
        }
        wait_for_snapshot(&source, 5);
        let expected = source.height_and_app_hash().unwrap();
        let payload_path = {
            let snapshots = source.core.snapshots.lock().unwrap();
            match &snapshots.get(&5).unwrap().payload {
                SnapshotPayload::File { path, .. } => path.clone(),
                SnapshotPayload::Memory(_) => panic!("persistent snapshot must be disk-backed"),
            }
        };
        let database = rusqlite::Connection::open(&payload_path).unwrap();
        database
            .execute(
                "UPDATE metadata SET value='3' WHERE key='schema_version'",
                [],
            )
            .unwrap();
        database
            .execute(
                "DELETE FROM metadata
                 WHERE key IN ('auth_query_floor', 'auth_prune_target')",
                [],
            )
            .unwrap();
        database
            .execute_batch(
                "
                DROP INDEX auth_stale_nodes_by_node_key;
                DROP TABLE auth_stale_values;
                DROP TABLE native_finalization_receipts_v0;
                DROP TABLE native_committed_head_v0;
                DROP TABLE native_authenticated_genesis_application_v0;
                DROP TABLE native_speculative_overlay_sources_v0;
                DROP TABLE native_speculative_overlays_v0;
                DROP TABLE validation_callback_outbox_v0;
                DROP TABLE validation_jobs_v0;
                DROP TABLE validation_journal_accounting_v0;
                ",
            )
            .unwrap();
        drop(database);

        let target_path = root.join("target-state.json");
        let target_config = ConsensusAppConfig {
            state_path: Some(target_path),
            ..source.core.config.clone()
        };
        let target = CometBftApplication::new(target_config.clone()).unwrap();
        initialize(&target);
        let empty = target.core.state.lock().unwrap().clone();
        let installed = target
            .core
            .store
            .as_ref()
            .unwrap()
            .install_snapshot_database(&empty, &payload_path, expected.0, expected.1)
            .unwrap();
        assert_eq!((installed.height, installed.app_hash), expected);
        let store = target.core.store.as_ref().unwrap();
        assert_eq!(
            store.auth_prune_status().unwrap(),
            store::AuthPruneStatus {
                query_floor: expected.0,
                target: None,
            }
        );
        assert!(store
            .prove(expected.0, validator_state_key().unwrap())
            .is_ok());
        drop(target);

        let restarted = CometBftApplication::new(target_config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), expected);
        finalize_and_commit(&restarted, expected.0 + 1, Vec::new());
        drop(restarted);
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema4_authenticated_prune_metadata_corruption_fails_closed() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-schema4-prune-corruption-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let base_state_path = root.join("base").join("app-state.json");
        let (app, _) = persistent_fixture(base_state_path.clone());
        for height in 1..=4 {
            finalize_and_commit(&app, height, Vec::new());
        }
        app.core
            .store
            .as_ref()
            .unwrap()
            .request_auth_prune(3)
            .unwrap();
        let app_config = app.core.config.clone();
        drop(app);
        let base_database_path = base_state_path.with_extension("json.sqlite3");
        let database = rusqlite::Connection::open(&base_database_path).unwrap();
        database
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(database);

        for (name, mutation) in [
            (
                "missing-floor",
                "DELETE FROM metadata WHERE key='auth_query_floor'",
            ),
            (
                "target-below-floor",
                "UPDATE metadata SET value='2' WHERE key='auth_prune_target'",
            ),
            (
                "target-above-floor",
                "UPDATE metadata SET value='4' WHERE key='auth_prune_target'",
            ),
            (
                "invalid-floor",
                "UPDATE metadata SET value='invalid' WHERE key='auth_query_floor'",
            ),
            (
                "missing-pending-target",
                "DELETE FROM metadata WHERE key='auth_prune_target'",
            ),
        ] {
            let state_path = root.join(name).join("app-state.json");
            fs::create_dir_all(state_path.parent().unwrap()).unwrap();
            let database_path = state_path.with_extension("json.sqlite3");
            fs::copy(&base_database_path, &database_path).unwrap();
            let database = rusqlite::Connection::open(database_path).unwrap();
            database.execute_batch(mutation).unwrap();
            drop(database);
            assert!(
                CometBftApplication::new(ConsensusAppConfig {
                    state_path: Some(state_path),
                    ..app_config.clone()
                })
                .is_err(),
                "schema-4 prune metadata mutation {name} reopened"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn committed_sqlite_head_replaces_untrusted_legacy_status_file() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-rollback-guard-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (fixture_app, envelope) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path.clone()),
            ..fixture_app.core.config.clone()
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        app.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        app.commit();
        let expected = app.height_and_app_hash().unwrap();
        drop(app);

        let stale = fixture_app.core.state.lock().unwrap().clone();
        fs::write(&state_path, legacy_v3_state_bytes(&stale)).unwrap();
        let restarted = CometBftApplication::new(config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), expected);
        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(status["schema"], "trnm_cometbft_app_status_v2");
        assert_eq!(status["app_version"], APP_VERSION);
        assert_eq!(status["height"], expected.0);
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sqlite_transaction_failpoints_recover_old_or_new_tip_atomically() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-atomicity-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (fixture_app, _) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path),
            ..fixture_app.core.config.clone()
        };

        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        let mut target = initial_validators();
        target.push(validator(25, 10));
        let transition = validator_transition(&app, "validator-atomic-pending", 3, target, &[25]);
        let tx = transition_tx(&transition, 1);
        let pending = {
            let state = app.core.state.lock().unwrap();
            app.execute_block(&state, std::slice::from_ref(&tx), 2_000, &[1; 32])
                .unwrap()
        };
        app.core
            .store
            .as_ref()
            .unwrap()
            .persist_transition_with_failpoint(
                &app.core.state.lock().unwrap(),
                &pending,
                store::StoreFailpoint::BeforeSqlCommit,
            )
            .unwrap_err();
        drop(app);
        let app = CometBftApplication::new(config.clone()).unwrap();
        assert_eq!(app.height_and_app_hash().unwrap().0, 0);
        assert!(app
            .core
            .state
            .lock()
            .unwrap()
            .validator_lifecycle
            .as_ref()
            .unwrap()
            .pending_transition
            .is_none());

        let pending = {
            let state = app.core.state.lock().unwrap();
            app.execute_block(&state, &[tx], 2_000, &[1; 32]).unwrap()
        };
        let expected = (pending.height, pending.app_hash);
        app.core
            .store
            .as_ref()
            .unwrap()
            .persist_transition_with_failpoint(
                &app.core.state.lock().unwrap(),
                &pending,
                store::StoreFailpoint::AfterSqlCommitBeforeStatus,
            )
            .unwrap_err();
        drop(app);
        let restarted = CometBftApplication::new(config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), expected);
        assert_eq!(
            restarted
                .core
                .state
                .lock()
                .unwrap()
                .validator_lifecycle
                .as_ref()
                .unwrap()
                .pending_transition
                .as_ref()
                .unwrap()
                .transition_id,
            "validator-atomic-pending"
        );
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sqlite_object_corruption_fails_closed_on_restart() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-corruption-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (fixture_app, envelope) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path.clone()),
            ..fixture_app.core.config.clone()
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        app.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        app.commit();
        drop(app);

        let database =
            rusqlite::Connection::open(state_path.with_extension("json.sqlite3")).unwrap();
        database
            .execute(
                "UPDATE objects
                 SET object_type='tampered-but-self-consistent',
                     version='99'",
                [],
            )
            .unwrap();
        drop(database);
        assert!(CometBftApplication::new(config).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sqlite_future_version_poisoning_fails_closed_on_restart() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-future-row-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (app, _) = persistent_fixture(state_path.clone());
        finalize_and_commit(&app, 1, Vec::new());
        drop(app);

        let database =
            rusqlite::Connection::open(state_path.with_extension("json.sqlite3")).unwrap();
        database
            .execute(
                "INSERT INTO auth_values(key_hash, version_be, value, is_deleted)
                 VALUES (?1, ?2, ?3, 0)",
                rusqlite::params![
                    [0xcdu8; 32].as_slice(),
                    2_u64.to_be_bytes().as_slice(),
                    b"future".as_slice(),
                ],
            )
            .unwrap();
        drop(database);
        let (fixture_app, _) = fixture();
        assert!(CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(state_path),
            ..fixture_app.core.config.clone()
        })
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pruned_authenticated_history_survives_sqlite_restart_and_continues() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-prune-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (fixture_app, _) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path),
            ..fixture_app.core.config.clone()
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        for height in 1..=3 {
            finalize_and_commit(&app, height, Vec::new());
        }
        let state = app.core.state.lock().unwrap().clone();
        let stats = app
            .core
            .store
            .as_ref()
            .unwrap()
            .prune_auth_versions_before(&state, 2)
            .unwrap();
        assert_eq!(stats.roots_removed, 2);
        assert!(stats.nodes_removed > 0);

        let path = format!("/object/{}", fee_policy_key());
        assert_ne!(
            app.query(RequestQuery {
                path: path.clone(),
                height: 1,
                prove: true,
                ..Default::default()
            })
            .code,
            0
        );
        for height in [2, 3] {
            assert_eq!(
                app.query(RequestQuery {
                    path: path.clone(),
                    height,
                    prove: true,
                    ..Default::default()
                })
                .code,
                0
            );
        }
        let expected = app.height_and_app_hash().unwrap();
        drop(app);

        let restarted = CometBftApplication::new(config).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), expected);
        assert_ne!(
            restarted
                .query(RequestQuery {
                    path: path.clone(),
                    height: 1,
                    prove: true,
                    ..Default::default()
                })
                .code,
            0
        );
        assert_eq!(
            restarted
                .query(RequestQuery {
                    path,
                    height: 2,
                    prove: true,
                    ..Default::default()
                })
                .code,
            0
        );
        finalize_and_commit(&restarted, 4, Vec::new());
        assert_eq!(restarted.height_and_app_hash().unwrap().0, 4);
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn budgeted_authenticated_pruning_is_logical_first_resumable_and_proof_safe() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-budgeted-prune-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (fixture_app, _) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path),
            ..fixture_app.core.config.clone()
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        for height in 1..=3 {
            finalize_and_commit(&app, height, Vec::new());
        }
        let pinned_head = app.height_and_app_hash().unwrap();
        let store = app.core.store.as_ref().unwrap();
        let status = store.request_auth_prune(2).unwrap();
        assert_eq!(status.query_floor, 2);
        assert_eq!(status.target, Some(2));
        assert!(
            store.prove(1, validator_state_key().unwrap()).is_err(),
            "logical floor must reject old queries before physical deletion"
        );
        assert_eq!(
            <[u8; 32]>::from(
                store
                    .prove(3, validator_state_key().unwrap())
                    .unwrap()
                    .root_hash
            ),
            pinned_head.1
        );
        let pinned = store
            .pin_snapshot(&app.core.state.lock().unwrap().clone())
            .unwrap();
        assert!(
            store
                .try_prune_auth_batch(1, 1024 * 1024)
                .unwrap()
                .is_none(),
            "physical pruning must yield while a live snapshot read is pinned"
        );
        finalize_and_commit(&app, 4, Vec::new());
        let expected = app.height_and_app_hash().unwrap();
        assert_eq!(
            expected.1, pinned_head.1,
            "empty collision commit changed the authenticated root"
        );
        assert!(
            store
                .try_prune_auth_batch(1, 1024 * 1024)
                .unwrap()
                .is_none(),
            "physical pruning must continue yielding after a Commit advances a pinned head"
        );
        drop(pinned);
        let first = store.try_prune_auth_batch(1, 1024 * 1024).unwrap().unwrap();
        assert_eq!(first.rows_examined, 1);
        assert!(!first.complete);
        assert!(store.prove(2, validator_state_key().unwrap()).is_ok());
        drop(app);

        let restarted = CometBftApplication::new(config.clone()).unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), expected);
        let store = restarted.core.store.as_ref().unwrap();
        for _ in 0..1_000 {
            assert!(store.prove(2, validator_state_key().unwrap()).is_ok());
            assert_eq!(
                <[u8; 32]>::from(
                    store
                        .prove(4, validator_state_key().unwrap())
                        .unwrap()
                        .root_hash
                ),
                expected.1
            );
            if store.auth_prune_status().unwrap().target.is_none()
                && !restarted.core.auth_prune_worker.lock().unwrap().active
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(
            store.auth_prune_status().unwrap(),
            store::AuthPruneStatus {
                query_floor: 2,
                target: None,
            }
        );
        assert!(store.prove(1, validator_state_key().unwrap()).is_err());
        finalize_and_commit(&restarted, 5, Vec::new());
        assert_eq!(restarted.height_and_app_hash().unwrap().0, 5);
        wait_for_snapshot(&restarted, 5);
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn budgeted_authenticated_pruning_collects_superseded_value_history() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-value-prune-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (app, _) = persistent_fixture(state_path.clone());
        let store = app.core.store.as_ref().unwrap();
        let mut state = app.core.state.lock().unwrap().clone();
        let object_key = "persistent-value-prune-object";
        for object_version in 1..=6 {
            let mut delta = BlockDelta::default();
            let object = ObjectMutation {
                object_key_hex: object_key.to_string(),
                object_type: "trnm_value_prune_fixture_v1".to_string(),
                expected_version: (object_version > 1).then_some(object_version - 1),
                next_version: object_version,
                value_bytes: object_version.to_be_bytes().to_vec(),
            }
            .into_stored();
            delta.objects.insert(object_key.to_string(), object);
            let next_height = state.height + 1;
            let writes = authenticated_writes_for_delta(next_height, &delta).unwrap();
            let auth_update = store.plan_auth_update(next_height, writes).unwrap();
            let pending = PendingBlock {
                height: next_height,
                app_hash: auth_update.root_hash.into(),
                tx_results: Vec::new(),
                native_execution: test_authorized_empty_native_execution(
                    state.height,
                    state.app_hash,
                    next_height,
                    auth_update.root_hash.into(),
                ),
                validator_updates: Vec::new(),
                delta,
                auth_update,
                poco_checkpoint_execution: None,
            };
            store.persist_transition(&state, &pending, 0).unwrap();
            state.height = pending.height;
            state.app_hash = pending.app_hash;
        }
        let database_path = state_path.with_extension("json.sqlite3");
        let before = rusqlite::Connection::open(&database_path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM auth_values", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap();
        store.request_auth_prune(4).unwrap();
        let mut removed_values = 0_usize;
        for _ in 0..1_000 {
            let outcome = store.try_prune_auth_batch(1, 1024 * 1024).unwrap().unwrap();
            removed_values = removed_values.saturating_add(outcome.stats.value_versions_removed);
            if outcome.complete {
                break;
            }
        }
        assert_eq!(store.auth_prune_status().unwrap().target, None);
        assert!(
            removed_values >= 3,
            "superseded value history was not physically collected"
        );
        let database = rusqlite::Connection::open(database_path).unwrap();
        let after = database
            .query_row("SELECT COUNT(*) FROM auth_values", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap();
        assert!(after < before);
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*)
                     FROM auth_stale_values
                     WHERE stale_since_version_be<=?1",
                    rusqlite::params![4_u64.to_be_bytes().as_slice()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        drop(database);
        let proof_key = stored_object_key(object_key).unwrap();
        assert!(store.prove(3, proof_key.clone()).is_err());
        assert!(store.prove(4, proof_key.clone()).unwrap().value.is_some());
        assert!(store.prove(6, proof_key).unwrap().value.is_some());
        drop(app);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn background_authenticated_prune_worker_drains_the_requested_floor() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-background-prune-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (app, _) = persistent_fixture(state_path);
        for height in 1..=4 {
            finalize_and_commit(&app, height, Vec::new());
        }
        let expected = app.height_and_app_hash().unwrap();
        let store = app.core.store.as_ref().unwrap();
        store.request_auth_prune(3).unwrap();
        app.wake_authenticated_prune_worker().unwrap();
        for _ in 0..1_000 {
            if store.auth_prune_status().unwrap().target.is_none()
                && !app.core.auth_prune_worker.lock().unwrap().active
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(
            store.auth_prune_status().unwrap(),
            store::AuthPruneStatus {
                query_floor: 3,
                target: None,
            }
        );
        assert!(!app.core.auth_prune_worker.lock().unwrap().active);
        assert!(store.prove(2, validator_state_key().unwrap()).is_err());
        assert_eq!(
            <[u8; 32]>::from(
                store
                    .prove(4, validator_state_key().unwrap())
                    .unwrap()
                    .root_hash
            ),
            expected.1
        );
        drop(app);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sqlite_store_preserves_canonical_account_nonce_and_chain_binding() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-u64-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let operator_key = SigningKey::from_bytes(&[11u8; 32]);
        let config = ConsensusAppConfig {
            schema: CONFIG_SCHEMA_V1.to_string(),
            chain_id: "trnm-comet-spike".to_string(),
            authorized_signers: vec![AuthorizedSignerV1 {
                signer_id: "did:operator:1".to_string(),
                signer_role: "operator".to_string(),
                public_key_hex: public_key_hex(&operator_key),
            }],
            poco_authority: None,
            state_path: Some(state_path),
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        let credit = CanonicalTxV1 {
            schema: trnm_protocol::CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:operator:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: trnm_protocol::CanonicalCommandV1::CreditAccount {
                account: "did:operator:1".to_string(),
                amount: 42,
            },
        };
        let response = finalize_and_commit(
            &app,
            1,
            vec![canonical_tx(
                &operator_key,
                "credit-operator",
                "did:operator:1",
                "operator",
                1,
                &credit,
            )],
        );
        assert_eq!(response.tx_results[0].code, 0);
        drop(app);

        let restarted = CometBftApplication::new(config.clone()).unwrap();
        let query = restarted.query(RequestQuery {
            path: "/account/did:operator:1".to_string(),
            ..Default::default()
        });
        assert_eq!(query.code, 0);
        let account: trnm_protocol::AccountV1 = serde_json::from_slice(&query.value).unwrap();
        assert_eq!(account.balance, 42);
        assert_eq!(account.nonce, 1);
        drop(restarted);

        let wrong_chain = ConsensusAppConfig {
            chain_id: "wrong-chain".to_string(),
            ..config
        };
        assert!(CometBftApplication::new(wrong_chain).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sqlite_store_binds_authorized_signer_policy_across_restarts() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-signer-policy-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
        let (fixture_app, envelope) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path),
            ..fixture_app.core.config.clone()
        };
        let app = CometBftApplication::new(config.clone()).unwrap();
        initialize(&app);
        app.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        app.commit();
        drop(app);

        let mut changed_id = config.clone();
        changed_id.authorized_signers[0].signer_id = "did:operator:changed".to_string();
        assert!(CometBftApplication::new(changed_id).is_err());

        let mut changed_role = config.clone();
        changed_role.authorized_signers[0].signer_role = "hepta".to_string();
        assert!(CometBftApplication::new(changed_role).is_err());

        let mut changed_key = config.clone();
        changed_key.authorized_signers[0].public_key_hex =
            public_key_hex(&SigningKey::from_bytes(&[12u8; 32]));
        assert!(CometBftApplication::new(changed_key).is_err());

        assert!(CometBftApplication::new(config).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}
