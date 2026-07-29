use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, ensure, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
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
use trnm_runtime::{
    ExecutionContext, ResourceEstimate, RuntimeEvent, StateObject, StateView as RuntimeStateView,
};

mod auth_tree;
#[cfg(feature = "scale-gate")]
mod scale;
mod store;
mod validator_lifecycle;

#[cfg(feature = "scale-gate")]
pub use scale::{run_auth_tree_scale_gate, AuthTreeScaleConfig, AuthTreeScaleReport};

use auth_tree::{
    stored_object_key, validator_state_key, AuthWrite, AuthenticatedObjectRecord, InMemoryAuthTree,
    PlannedAuthUpdate,
};
use store::ApplicationStore;
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
const SNAPSHOT_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_SNAPSHOT_CHUNKS: u32 = 4096;
const RETAINED_SNAPSHOTS: usize = 16;
const DISK_SNAPSHOT_INTERVAL: u64 = 5;
const RETAINED_DISK_SNAPSHOTS: usize = 3;
const AUTH_PROOF_RETENTION_VERSIONS: u64 = 8_192;
const AUTH_PRUNE_INTERVAL: u64 = 256;
const MAX_SIMULATION_TX_BYTES: usize = 1024 * 1024;

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
    pub state_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAppStateV2 {
    pub schema: String,
    pub chain_id: String,
    pub app_version: u64,
    pub authorized_signers: Vec<AuthorizedSignerV1>,
    pub validator_governance: ValidatorGovernanceV1,
    pub initial_validators: Vec<ConsensusValidatorV1>,
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
        ensure!(
            !self.authorized_signers.is_empty(),
            "authorized_signers must not be empty"
        );
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for signer in &self.authorized_signers {
            ensure!(ids.insert(signer.signer_id.clone()), "duplicate signer_id");
            ensure!(
                keys.insert(signer.public_key_hex.clone()),
                "duplicate signer public key"
            );
            ensure!(
                matches!(signer.signer_role.as_str(), "hepta" | "nakama" | "operator"),
                "unsupported signer role"
            );
            let bytes = hex::decode(&signer.public_key_hex)
                .context("authorized signer public key must be hex")?;
            ensure!(
                bytes.len() == 32,
                "authorized signer public key must be 32 bytes"
            );
            ensure!(
                signer.public_key_hex == hex::encode(&bytes),
                "authorized signer public key must use canonical lowercase hex"
            );
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
    validator_updates: Vec<ValidatorUpdate>,
    delta: BlockDelta,
    auth_update: PlannedAuthUpdate,
}

#[derive(Debug, Clone, Default)]
struct BlockDelta {
    objects: BTreeMap<String, StoredObject>,
    command_ids: BTreeSet<String>,
    signer_nonces: BTreeSet<(String, u64)>,
    validator_lifecycle: Option<ValidatorLifecycleStateV1>,
}

struct OverlayObjects<'a> {
    base: &'a BTreeMap<String, StoredObject>,
    changes: &'a BTreeMap<String, StoredObject>,
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
        ObjectView::get(self, object_key_hex).map(|object| StateObject {
            object_type: object.object_type.clone(),
            version: object.version,
            value_bytes: object.value_bytes.clone(),
        })
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
    snapshots: Mutex<BTreeMap<u64, SnapshotRecord>>,
    snapshot_building: Mutex<Option<u64>>,
    snapshot_restore: Mutex<Option<SnapshotRestore>>,
    test_crash_plan: Option<TestCrashPlan>,
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

#[derive(Debug, Clone)]
struct SnapshotRestore {
    metadata: SnapshotMetadataV3,
    chunks: Vec<Option<Bytes>>,
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
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct CometBftApplication {
    core: Arc<AppCore>,
}

impl CometBftApplication {
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
            Some(store) => store.load_or_migrate()?,
            None => (AppState::default(), InMemoryAuthTree::default()),
        };
        if let Some(lifecycle) = state.validator_lifecycle.as_ref() {
            validate_lifecycle_authorization(&config, lifecycle)?;
        }
        let mut snapshots = BTreeMap::new();
        if state.height > 0 {
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
        Ok(Self {
            core: Arc::new(AppCore {
                config,
                #[cfg(test)]
                interpreter,
                store,
                state: Mutex::new(state),
                auth_tree: Mutex::new(auth_tree),
                snapshots: Mutex::new(snapshots),
                snapshot_building: Mutex::new(None),
                snapshot_restore: Mutex::new(None),
                test_crash_plan,
            }),
        })
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
        envelope.validate_at(&self.core.config.chain_id, timestamp_ms)?;
        let signer = self
            .core
            .config
            .authorized_signers
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
    ) -> Result<(BlockDelta, Vec<ExecTxResult>)> {
        let mut delta = self.start_block_delta(state)?;
        let mut tx_results = Vec::with_capacity(txs.len());
        for tx in txs {
            tx_results.push(self.apply_tx(state, &mut delta, tx, timestamp_ms)?);
        }
        Ok((delta, tx_results))
    }

    fn execute_block(
        &self,
        state: &AppState,
        txs: &[Bytes],
        timestamp_ms: u64,
    ) -> Result<PendingBlock> {
        let (delta, tx_results) = self.plan_block(state, txs, timestamp_ms)?;
        let next_height = state.height.saturating_add(1);
        let writes = authenticated_writes_for_delta(next_height, &delta)?;
        let auth_update = self
            .core
            .auth_tree
            .lock()
            .map_err(|_| anyhow!("authenticated state tree lock poisoned"))?
            .plan_put_value_set(next_height, writes)?;
        let app_hash = auth_update.root_hash.into();
        let validator_updates = effective_validator_lifecycle(state, &delta)?
            .updates_due_at_finalize_height(next_height)?;
        Ok(PendingBlock {
            height: next_height,
            app_hash,
            tx_results,
            validator_updates,
            delta,
            auth_update,
        })
    }

    fn apply_tx(
        &self,
        state: &AppState,
        delta: &mut BlockDelta,
        tx: &[u8],
        timestamp_ms: u64,
    ) -> Result<ExecTxResult> {
        let envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(tx).context("decode signed command envelope")?;
        self.validate_envelope(&envelope, timestamp_ms)?;
        let payload = envelope.payload_bytes()?;
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
            return Ok(ExecTxResult::default());
        }
        let (mutations, tx_result) = if envelope.payload_type == CANONICAL_TX_PAYLOAD_TYPE_V1 {
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
            let tx_result = ExecTxResult {
                gas_wanted: i64::try_from(tx.max_gas).unwrap_or(i64::MAX),
                gas_used: i64::try_from(receipt.gas_used).unwrap_or(i64::MAX),
                events: receipt
                    .events
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
                receipt
                    .mutations
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
            )
        } else {
            #[cfg(test)]
            {
                if envelope.payload_type == "opaque_fixture_v1" {
                    ensure!(
                        !state.command_ids.contains(&envelope.command_id)
                            && delta.command_ids.insert(envelope.command_id.clone()),
                        "command_id replay rejected"
                    );
                    let signer_nonce = (envelope.signer_id.clone(), envelope.nonce);
                    ensure!(
                        !state.signer_nonces.contains(&signer_nonce)
                            && delta.signer_nonces.insert(signer_nonce),
                        "signer nonce replay rejected"
                    );
                    let objects = OverlayObjects {
                        base: &state.objects,
                        changes: &delta.objects,
                    };
                    (
                        self.core
                            .interpreter
                            .prepare_execution(&envelope, &objects)?
                            .mutations,
                        ExecTxResult::default(),
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
            let current_version = delta
                .objects
                .get(&mutation.object_key_hex)
                .or_else(|| state.objects.get(&mutation.object_key_hex))
                .map(|object| object.version);
            ensure!(
                current_version == mutation.expected_version,
                "object version precondition mismatch"
            );
            let stored = mutation.into_stored();
            delta.objects.insert(stored.object_key_hex.clone(), stored);
        }
        Ok(tx_result)
    }

    fn validate_genesis(&self, request: &RequestInitChain) -> Result<ValidatorLifecycleStateV1> {
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
        Ok(lifecycle)
    }

    fn retain_snapshot(&self, state: &AppState) -> Result<()> {
        let disk_path = snapshot_path(&self.core.config, state.height);
        if disk_path.is_some() && !state.height.is_multiple_of(DISK_SNAPSHOT_INTERVAL) {
            return Ok(());
        }
        let auth_tree = self
            .core
            .auth_tree
            .lock()
            .map_err(|_| anyhow!("authenticated state tree lock poisoned"))?
            .clone();
        let retained = if self.core.config.state_path.is_some() {
            RETAINED_DISK_SNAPSHOTS
        } else {
            RETAINED_SNAPSHOTS
        };
        if let Some(disk_path) = disk_path {
            {
                let mut building = self
                    .core
                    .snapshot_building
                    .lock()
                    .map_err(|_| anyhow!("snapshot worker lock poisoned"))?;
                if building.is_some() {
                    return Ok(());
                }
                *building = Some(state.height);
            }
            let core = Arc::clone(&self.core);
            let chain_id = self.core.config.chain_id.clone();
            let state = state.clone();
            let spawn = std::thread::Builder::new()
                .name(format!("trnm-snapshot-{}", state.height))
                .spawn(move || {
                    let result = build_snapshot(&chain_id, &state, &auth_tree, Some(disk_path))
                        .and_then(|record| {
                            install_snapshot_record(&core.snapshots, state.height, record, retained)
                        });
                    if let Err(error) = result {
                        eprintln!(
                            "[trnm-cometbft-app] asynchronous snapshot {} failed: {error:#}",
                            state.height
                        );
                    }
                    if let Ok(mut building) = core.snapshot_building.lock() {
                        *building = None;
                    }
                });
            if let Err(error) = spawn {
                *self
                    .core
                    .snapshot_building
                    .lock()
                    .map_err(|_| anyhow!("snapshot worker lock poisoned"))? = None;
                return Err(error).context("spawn asynchronous snapshot worker");
            }
            return Ok(());
        }
        let record = build_snapshot(&self.core.config.chain_id, state, &auth_tree, None)?;
        install_snapshot_record(&self.core.snapshots, state.height, record, retained)
    }

    fn maybe_prune_authenticated_history(&self, state: &AppState) -> Result<()> {
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
        if let Some(store) = &self.core.store {
            store.replace_auth_tree(state, &pruned)?;
        }
        *self
            .core
            .auth_tree
            .lock()
            .map_err(|_| anyhow!("authenticated state tree lock poisoned"))? = pruned;
        Ok(())
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
        let lifecycle = self
            .validate_genesis(&request)
            .unwrap_or_else(|error| panic!("refuse incompatible CometBFT genesis: {error:#}"));
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
                assert_eq!(
                    state.objects.get(&fee_policy.object_key_hex),
                    Some(&fee_policy),
                    "repeated InitChain fee policy mismatch"
                );
                let auth_tree = self
                    .core
                    .auth_tree
                    .lock()
                    .unwrap_or_else(|_| panic!("authenticated state tree lock poisoned"));
                assert_eq!(
                    auth_tree.root_hash(0).map(Into::<[u8; 32]>::into),
                    Some(state.app_hash),
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
                let writes = authenticated_writes_for_state(0, &initialized)
                    .expect("validated genesis state converts to authenticated writes");
                let mut auth_tree = self
                    .core
                    .auth_tree
                    .lock()
                    .unwrap_or_else(|_| panic!("authenticated state tree lock poisoned"));
                let auth_update = auth_tree
                    .plan_put_value_set(0, writes)
                    .expect("validated genesis state produces AppHash v4");
                initialized.app_hash = auth_update.root_hash.into();
                if let Some(store) = &self.core.store {
                    store
                        .replace_empty_state(&state, &initialized, &auth_update)
                        .unwrap_or_else(|error| {
                            panic!("persist initialized validator lifecycle: {error:#}")
                        });
                }
                auth_tree
                    .apply(auth_update)
                    .expect("apply persisted genesis authenticated state");
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
            Ok((_, tx_results)) => {
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
            let committed = state.clone();
            drop(state);
            let simulation = self.simulate_canonical_tx(&committed, &request.data);
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
            drop(state);
            let auth_key = match stored_object_key(&key) {
                Ok(key) => key,
                Err(error) => return query_error(&format!("{error:#}")),
            };
            let proof = match self
                .core
                .auth_tree
                .lock()
                .map_err(|_| anyhow!("authenticated state tree lock poisoned"))
                .and_then(|tree| tree.prove(query_height, auth_key.clone()))
            {
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
        let Some(object) = state.objects.get(&key) else {
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
            log: object.object_type.clone(),
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
            delta = candidate;
            total_bytes = next_total;
            txs.push(tx);
        }
        ResponsePrepareProposal { txs }
    }

    fn process_proposal(&self, request: RequestProcessProposal) -> ResponseProcessProposal {
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
                self.plan_block(
                    &state,
                    &request.txs,
                    consensus_timestamp_ms(request.time.as_ref())?,
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
            .execute_block(&state, &request.txs, timestamp_ms)
            .unwrap_or_else(|error| {
                panic!(
                    "ProcessProposal accepted a block that FinalizeBlock cannot execute: {error:#}"
                )
            });
        let app_hash = Bytes::copy_from_slice(&pending.app_hash);
        let validator_updates = pending.validator_updates.clone();
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
            ..Default::default()
        }
    }

    fn commit(&self) -> ResponseCommit {
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
                .persist_transition(&state, &pending)
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
        self.core
            .auth_tree
            .lock()
            .unwrap_or_else(|_| panic!("authenticated state tree lock poisoned during commit"))
            .apply(auth_update)
            .unwrap_or_else(|error| {
                panic!("apply committed authenticated state tree update: {error:#}")
            });
        state.height = height;
        state.app_hash = app_hash;
        for (key, object) in delta.objects {
            state.objects.insert(key, object);
        }
        state.command_ids.extend(delta.command_ids);
        state.signer_nonces.extend(delta.signer_nonces);
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
        let result = self
            .validate_snapshot_offer(request)
            .map(|restore| {
                self.core
                    .snapshot_restore
                    .lock()
                    .map_err(|_| anyhow!("snapshot restore lock poisoned"))?
                    .replace(restore);
                Ok::<_, anyhow::Error>(())
            })
            .and_then(|result| result)
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
        match self.apply_snapshot_chunk_inner(request) {
            Ok(()) => snapshot_apply_response(response_apply_snapshot_chunk::Result::Accept),
            Err(error) if error.to_string().contains("retry snapshot chunk") => {
                snapshot_apply_response(response_apply_snapshot_chunk::Result::Retry)
            }
            Err(_) => {
                if let Ok(mut restore) = self.core.snapshot_restore.lock() {
                    restore.take();
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
        ensure!(
            snapshot.format == SNAPSHOT_FORMAT_V3,
            "unsupported snapshot format"
        );
        ensure!(
            snapshot.chunks > 0 && snapshot.chunks <= MAX_SNAPSHOT_CHUNKS,
            "invalid snapshot chunk count"
        );
        ensure!(snapshot.hash.len() == 32, "invalid snapshot hash length");
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
        ensure!(metadata.store_schema == 3, "snapshot store schema mismatch");
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
        ensure!(metadata.total_bytes > 0, "snapshot is empty");
        ensure!(
            metadata.total_bytes
                <= (MAX_SNAPSHOT_CHUNKS as u64).saturating_mul(SNAPSHOT_CHUNK_SIZE as u64),
            "snapshot byte length exceeds limit"
        );
        let total_bytes = usize::try_from(metadata.total_bytes)
            .context("snapshot byte length exceeds platform capacity")?;
        let expected_chunks = total_bytes.div_ceil(SNAPSHOT_CHUNK_SIZE) as u32;
        ensure!(
            expected_chunks == snapshot.chunks,
            "snapshot byte length mismatch"
        );
        ensure!(
            metadata.chunk_hashes_hex.len() == snapshot.chunks as usize,
            "snapshot chunk hash count mismatch"
        );
        for hash in &metadata.chunk_hashes_hex {
            trnm_finality_types::decode_hash32("snapshot chunk hash", hash)?;
        }
        trnm_finality_types::decode_hash32("snapshot payload hash", &metadata.payload_hash_hex)?;
        ensure!(
            snapshot_manifest_hash(&snapshot.metadata).as_slice() == snapshot.hash.as_ref(),
            "snapshot manifest hash mismatch"
        );
        let app_hash =
            trnm_finality_types::decode_hash32("snapshot app_hash", &metadata.app_hash_hex)?;
        ensure!(
            request.app_hash.as_ref() == app_hash,
            "snapshot app hash mismatch"
        );
        let state = self
            .core
            .state
            .lock()
            .map_err(|_| anyhow!("consensus application state lock poisoned"))?;
        ensure!(
            state.height == 0 && state.pending.is_none(),
            "snapshot restore requires empty application state"
        );
        drop(state);
        Ok(SnapshotRestore {
            chunks: vec![None; snapshot.chunks as usize],
            metadata,
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
        ensure!(
            index < restore.chunks.len(),
            "snapshot chunk index out of range"
        );
        let expected_len = if index + 1 == restore.chunks.len() {
            restore.metadata.total_bytes as usize - index * SNAPSHOT_CHUNK_SIZE
        } else {
            SNAPSHOT_CHUNK_SIZE
        };
        ensure!(
            request.chunk.len() == expected_len,
            "retry snapshot chunk: invalid length"
        );
        let expected_chunk_hash = trnm_finality_types::decode_hash32(
            "snapshot chunk hash",
            &restore.metadata.chunk_hashes_hex[index],
        )?;
        ensure!(
            snapshot_chunk_hash(index as u32, &request.chunk) == expected_chunk_hash,
            "retry snapshot chunk: content hash mismatch"
        );
        if let Some(existing) = &restore.chunks[index] {
            ensure!(
                existing == &request.chunk,
                "conflicting duplicate snapshot chunk"
            );
        } else {
            restore.chunks[index] = Some(request.chunk);
        }
        if restore.chunks.iter().any(Option::is_none) {
            return Ok(());
        }
        let mut bytes = Vec::with_capacity(restore.metadata.total_bytes as usize);
        for chunk in &restore.chunks {
            bytes.extend_from_slice(chunk.as_ref().expect("all chunks checked"));
        }
        ensure!(
            snapshot_payload_hash(&bytes)
                == trnm_finality_types::decode_hash32(
                    "snapshot payload hash",
                    &restore.metadata.payload_hash_hex,
                )?,
            "snapshot payload hash mismatch"
        );
        let (next, next_auth_tree) = decode_state(&bytes)?;
        let lifecycle = next
            .validator_lifecycle
            .as_ref()
            .context("restored snapshot is missing validator lifecycle")?;
        validate_lifecycle_authorization(&self.core.config, lifecycle)?;
        ensure!(
            next.height == restore.metadata.height,
            "restored height mismatch"
        );
        ensure!(
            hex::encode(next.app_hash) == restore.metadata.app_hash_hex,
            "restored app hash mismatch"
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
        }
        *self
            .core
            .auth_tree
            .lock()
            .map_err(|_| anyhow!("authenticated state tree lock poisoned"))? = next_auth_tree;
        *state = next;
        if let Err(error) = self.retain_snapshot(&state) {
            eprintln!(
                "[trnm-cometbft-app] restored state but failed to retain optional snapshot: {error:#}"
            );
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

fn empty_app_hash() -> [u8; 32] {
    hash_domain("trnm.cometbft.application.empty.v2", &[])
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
    let mut authenticated = auth_tree.verified_live_values(persisted.height)?;
    for object in objects.values() {
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
    let lifecycle_value = authenticated
        .remove(&validator_state_key()?)
        .context("persisted validator lifecycle is absent from authenticated state")?;
    let lifecycle_record = AuthenticatedObjectRecord::decode(&lifecycle_value)?;
    ensure!(
        lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
            && lifecycle_record.object_version <= persisted.height
            && lifecycle_record.value == serde_json::to_vec(&persisted.validator_lifecycle)?,
        "persisted validator lifecycle differs from authenticated value"
    );
    ensure!(
        authenticated.is_empty(),
        "authenticated state contains {} leaves absent from persisted application state",
        authenticated.len()
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

fn snapshot_path(config: &ConsensusAppConfig, height: u64) -> Option<PathBuf> {
    config.state_path.as_ref().map(|state_path| {
        state_path
            .with_extension("snapshots")
            .join(format!("{height:020}.snapshot"))
    })
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
        store_schema: 3,
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
        .open(&temporary)
        .with_context(|| format!("open temporary app state {}", temporary.display()))?;
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

    use super::*;
    use crate::validator_lifecycle::{
        validator_key_proof_message, ValidatorKeyProofV1, VALIDATOR_GOVERNANCE_SCHEMA_V1,
        VALIDATOR_TRANSITION_SCHEMA_V1,
    };

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
            state_path: None,
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
        let source_lifecycle = source.core.state.lock().unwrap();
        let source_lifecycle = source_lifecycle.validator_lifecycle.as_ref().unwrap();
        assert!(source_lifecycle.pending_transition.is_none());
        assert_eq!(source_lifecycle.active_validators.len(), 5);
        assert_eq!(
            source_lifecycle.last_applied_transition_id.as_deref(),
            Some("validator-persist-pending")
        );
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
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_restores_fresh_application_and_persists_state() {
        let (source, envelope) = fixture();
        let response = source.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        assert_eq!(response.tx_results[0].code, 0);
        source.commit();
        let source_state = source.height_and_app_hash().unwrap();
        let snapshot = source.list_snapshots().snapshots.pop().unwrap();
        assert_eq!(snapshot.height, source_state.0);
        let mut snapshot_payload = Vec::new();
        for index in 0..snapshot.chunks {
            snapshot_payload.extend_from_slice(
                &source
                    .load_snapshot_chunk(RequestLoadSnapshotChunk {
                        height: snapshot.height,
                        format: snapshot.format,
                        chunk: index,
                    })
                    .chunk,
            );
        }
        decode_state(&snapshot_payload).expect("source snapshot must self-decode");

        let root = std::env::temp_dir().join(format!(
            "trnm-comet-restored-state-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
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
        drop(target);

        let restarted = CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(state_path),
            ..source.core.config.clone()
        })
        .unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), source_state);
        drop(restarted);
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
        assert_eq!(target.height_and_app_hash().unwrap().0, 0);
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
        let (source, source_envelope) = fixture();
        source.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&source_envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        source.commit();
        let source_state = source.height_and_app_hash().unwrap();
        let snapshot = source.list_snapshots().snapshots.pop().unwrap();

        let root = std::env::temp_dir().join(format!(
            "trnm-comet-snapshot-cas-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let state_path = root.join("app-state.json");
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
        for _ in 0..500 {
            let heights = app
                .list_snapshots()
                .snapshots
                .iter()
                .map(|snapshot| snapshot.height)
                .collect::<Vec<_>>();
            if heights == vec![20, 15, 10] {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let snapshots = app.list_snapshots().snapshots;
        assert_eq!(
            snapshots
                .iter()
                .map(|snapshot| snapshot.height)
                .collect::<Vec<_>>(),
            vec![20, 15, 10]
        );
        let snapshot_dir = state_path.with_extension("snapshots");
        assert_eq!(fs::read_dir(&snapshot_dir).unwrap().count(), 3);
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
            app.execute_block(&state, std::slice::from_ref(&tx), 2_000)
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
            app.execute_block(&state, &[tx], 2_000).unwrap()
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
        let mut pruned = app.core.auth_tree.lock().unwrap().clone();
        let nodes_before = pruned.node_count();
        let stats = pruned.prune_versions_before(2).unwrap();
        assert_eq!(stats.roots_removed, 2);
        assert!(pruned.node_count() < nodes_before);
        app.core
            .store
            .as_ref()
            .unwrap()
            .replace_auth_tree(&state, &pruned)
            .unwrap();
        *app.core.auth_tree.lock().unwrap() = pruned;

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
