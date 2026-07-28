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
use trnm_runtime::{ExecutionContext, StateObject, StateView as RuntimeStateView};

mod store;
mod validator_lifecycle;

use store::ApplicationStore;
use validator_lifecycle::{
    validators_from_abci, validators_to_abci, ConsensusValidatorV1, ValidatorGovernanceV1,
    ValidatorLifecycleStateV1, ValidatorSetTransitionV1, VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
};

pub const CONFIG_SCHEMA_V1: &str = "trnm_cometbft_app_config_v1";
pub const GENESIS_SCHEMA_V2: &str = "trnm_cometbft_genesis_v2";
const APP_VERSION: u64 = 3;
const SNAPSHOT_FORMAT_V2: u32 = 2;
const SNAPSHOT_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_SNAPSHOT_CHUNKS: u32 = 4096;
const RETAINED_SNAPSHOTS: usize = 16;
const DISK_SNAPSHOT_INTERVAL: u64 = 5;
const RETAINED_DISK_SNAPSHOTS: usize = 3;

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
    snapshots: Mutex<BTreeMap<u64, SnapshotRecord>>,
    snapshot_restore: Mutex<Option<SnapshotRestore>>,
    test_crash_plan: Option<TestCrashPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAppStateV3 {
    schema: String,
    height: u64,
    app_hash_hex: String,
    objects: Vec<PersistedObjectV1>,
    command_ids: BTreeSet<String>,
    signer_nonces: BTreeSet<(String, u64)>,
    validator_lifecycle: ValidatorLifecycleStateV1,
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
struct SnapshotMetadataV2 {
    schema: String,
    chain_id: String,
    height: u64,
    app_hash_hex: String,
    app_version: u64,
    total_bytes: u64,
    chunk_size: u32,
}

#[derive(Debug, Clone)]
struct SnapshotRestore {
    snapshot: Snapshot,
    metadata: SnapshotMetadataV2,
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
        let state = match &store {
            Some(store) => store.load_or_migrate()?,
            None => AppState::default(),
        };
        if let Some(lifecycle) = state.validator_lifecycle.as_ref() {
            validate_lifecycle_authorization(&config, lifecycle)?;
        }
        let mut snapshots = BTreeMap::new();
        if state.height > 0 {
            snapshots.insert(
                state.height,
                build_snapshot(
                    &config.chain_id,
                    &state,
                    snapshot_path(&config, state.height),
                )?,
            );
        }
        Ok(Self {
            core: Arc::new(AppCore {
                config,
                #[cfg(test)]
                interpreter,
                store,
                state: Mutex::new(state),
                snapshots: Mutex::new(snapshots),
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
        let app_hash = compute_app_hash_with_delta(next_height, state, &delta);
        let validator_updates = effective_validator_lifecycle(state, &delta)?
            .updates_due_at_finalize_height(next_height)?;
        Ok(PendingBlock {
            height: next_height,
            app_hash,
            tx_results,
            validator_updates,
            delta,
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
        if envelope.payload_type == VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1 {
            let transition: ValidatorSetTransitionV1 =
                serde_json::from_slice(&envelope.payload_bytes()?)
                    .context("decode validator set transition")?;
            let mut lifecycle = effective_validator_lifecycle(state, delta)?.clone();
            lifecycle.schedule(
                transition,
                &envelope.command_id,
                &envelope.signer_id,
                &envelope.signer_role,
                &self.core.config.chain_id,
                state.height.saturating_add(1),
            )?;
            delta.validator_lifecycle = Some(lifecycle);
            return Ok(ExecTxResult::default());
        }
        let payload = envelope.payload_bytes()?;
        let (mutations, tx_result) = if envelope.payload_type == CANONICAL_TX_PAYLOAD_TYPE_V1 {
            let tx: CanonicalTxV1 =
                serde_json::from_slice(&payload).context("decode canonical transaction")?;
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
        let record = build_snapshot(&self.core.config.chain_id, state, disk_path)?;
        let mut snapshots = self
            .core
            .snapshots
            .lock()
            .map_err(|_| anyhow!("snapshot store lock poisoned"))?;
        snapshots.insert(state.height, record);
        let retained = if self.core.config.state_path.is_some() {
            RETAINED_DISK_SNAPSHOTS
        } else {
            RETAINED_SNAPSHOTS
        };
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
                initialized.app_hash = compute_app_hash(
                    0,
                    &initialized.objects,
                    &initialized.command_ids,
                    &initialized.signer_nonces,
                    initialized.validator_lifecycle.as_ref(),
                );
                if let Some(store) = &self.core.store {
                    store
                        .replace_empty_state(&state, &initialized)
                        .unwrap_or_else(|error| {
                            panic!("persist initialized validator lifecycle: {error:#}")
                        });
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
            Ok(_) => ResponseCheckTx::default(),
            Err(error) => check_tx_error(&format!("{error:#}")),
        }
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        if request.prove {
            return query_error("proof queries are unavailable before AppHash v4");
        }
        let state = match self.core.state.lock() {
            Ok(state) => state,
            Err(_) => return query_error("state lock poisoned"),
        };
        if request.height != 0 && request.height != state.height as i64 {
            return query_error("historical query height is unavailable");
        }
        let key = if let Some(account) = request.path.strip_prefix("/account/") {
            account_key(account)
        } else if let Some(task_id) = request.path.strip_prefix("/task/") {
            task_key(task_id)
        } else if let Some(object_key) = request.path.strip_prefix("/object/") {
            object_key.to_string()
        } else {
            return query_error("unsupported query path");
        };
        let Some(object) = state.objects.get(&key) else {
            return ResponseQuery {
                code: 1,
                log: "object not found".to_string(),
                height: state.height as i64,
                ..Default::default()
            };
        };
        ResponseQuery {
            code: 0,
            key: Bytes::copy_from_slice(key.as_bytes()),
            value: Bytes::copy_from_slice(&object.value_bytes),
            height: state.height as i64,
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
        let timestamp_ms = timestamp_ms(request.time.as_ref());
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
                self.plan_block(&state, &request.txs, timestamp_ms(request.time.as_ref()))?;
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
        let pending = self
            .execute_block(&state, &request.txs, timestamp_ms(request.time.as_ref()))
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
        state.height = pending.height;
        state.app_hash = pending.app_hash;
        for (key, object) in pending.delta.objects {
            state.objects.insert(key, object);
        }
        state.command_ids.extend(pending.delta.command_ids);
        state.signer_nonces.extend(pending.delta.signer_nonces);
        if let Some(lifecycle) = pending.delta.validator_lifecycle {
            state.validator_lifecycle = Some(lifecycle);
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
            snapshot.format == SNAPSHOT_FORMAT_V2,
            "unsupported snapshot format"
        );
        ensure!(
            snapshot.chunks > 0 && snapshot.chunks <= MAX_SNAPSHOT_CHUNKS,
            "invalid snapshot chunk count"
        );
        ensure!(snapshot.hash.len() == 32, "invalid snapshot hash length");
        let metadata: SnapshotMetadataV2 =
            serde_json::from_slice(&snapshot.metadata).context("decode snapshot metadata")?;
        ensure!(
            metadata.schema == "trnm_cometbft_snapshot_metadata_v2",
            "unsupported snapshot metadata schema"
        );
        ensure!(
            metadata.app_version == APP_VERSION,
            "snapshot app version mismatch"
        );
        ensure!(
            metadata.chain_id == self.core.config.chain_id,
            "snapshot chain mismatch"
        );
        ensure!(
            metadata.height == snapshot.height,
            "snapshot height mismatch"
        );
        ensure!(metadata.height > 0, "genesis snapshot is not restorable");
        ensure!(
            metadata.chunk_size == SNAPSHOT_CHUNK_SIZE as u32,
            "snapshot chunk size mismatch"
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
            snapshot,
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
            snapshot_hash(&bytes).as_slice() == restore.snapshot.hash.as_ref(),
            "snapshot content hash mismatch"
        );
        let next = decode_state(&bytes)?;
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
            store.replace_empty_state(&state, &next)?;
        }
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

fn empty_app_hash() -> [u8; 32] {
    hash_domain("trnm.cometbft.application.empty.v2", &[])
}

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

fn compute_app_hash_with_delta(_height: u64, state: &AppState, delta: &BlockDelta) -> [u8; 32] {
    let object_root = root_only(
        "trnm.state.objects.v1",
        merged_object_leaves(&state.objects, &delta.objects),
    );
    let command_root = root_only(
        "trnm.state.command-ids.v1",
        state
            .command_ids
            .union(&delta.command_ids)
            .map(|command_id| hash_domain("trnm.state.command-id.v1", &[command_id.as_bytes()])),
    );
    let nonce_root = root_only(
        "trnm.state.signer-nonces.v1",
        state
            .signer_nonces
            .union(&delta.signer_nonces)
            .map(|(signer_id, nonce)| {
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
        validator_lifecycle_commitment(
            delta
                .validator_lifecycle
                .as_ref()
                .or(state.validator_lifecycle.as_ref()),
        ),
    )
}

fn merged_object_leaves(
    base: &BTreeMap<String, StoredObject>,
    changes: &BTreeMap<String, StoredObject>,
) -> Vec<[u8; 32]> {
    let mut base = base.iter().peekable();
    let mut changes = changes.iter().peekable();
    let mut leaves = Vec::with_capacity(base.len().saturating_add(changes.len()));
    loop {
        match (base.peek(), changes.peek()) {
            (Some((base_key, base_object)), Some((change_key, change_object))) => {
                match base_key.cmp(change_key) {
                    std::cmp::Ordering::Less => {
                        leaves.push(base_object.leaf_hash());
                        base.next();
                    }
                    std::cmp::Ordering::Equal => {
                        leaves.push(change_object.leaf_hash());
                        base.next();
                        changes.next();
                    }
                    std::cmp::Ordering::Greater => {
                        leaves.push(change_object.leaf_hash());
                        changes.next();
                    }
                }
            }
            (Some((_, object)), None) => {
                leaves.push(object.leaf_hash());
                base.next();
            }
            (None, Some((_, object))) => {
                leaves.push(object.leaf_hash());
                changes.next();
            }
            (None, None) => break,
        }
    }
    leaves
}

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

fn validator_lifecycle_commitment(lifecycle: Option<&ValidatorLifecycleStateV1>) -> [u8; 32] {
    lifecycle
        .map(|lifecycle| {
            lifecycle
                .commitment()
                .expect("committed validator lifecycle must be valid")
        })
        .unwrap_or_else(|| hash_domain("trnm.cometbft.validator-lifecycle.empty.v1", &[]))
}

fn timestamp_ms(timestamp: Option<&tendermint_proto::google::protobuf::Timestamp>) -> u64 {
    let Some(timestamp) = timestamp else {
        return now_unix_ms();
    };
    let seconds = timestamp.seconds.max(0) as u64;
    let nanos = timestamp.nanos.max(0) as u64;
    seconds
        .saturating_mul(1_000)
        .saturating_add(nanos / 1_000_000)
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn load_state(path: &Path) -> Result<AppState> {
    if !path.exists() {
        return Ok(AppState::default());
    }
    decode_state(&fs::read(path).with_context(|| format!("read app state {}", path.display()))?)
        .with_context(|| format!("decode app state {}", path.display()))
}

fn decode_state(bytes: &[u8]) -> Result<AppState> {
    let persisted: PersistedAppStateV3 =
        serde_json::from_slice(bytes).context("decode persisted application state")?;
    ensure!(
        persisted.schema == "trnm_cometbft_app_state_v3",
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
    let expected = compute_app_hash(
        persisted.height,
        &objects,
        &persisted.command_ids,
        &persisted.signer_nonces,
        Some(&persisted.validator_lifecycle),
    );
    ensure!(expected == app_hash, "persisted application hash mismatch");
    Ok(AppState {
        height: persisted.height,
        app_hash,
        objects,
        command_ids: persisted.command_ids,
        signer_nonces: persisted.signer_nonces,
        validator_lifecycle: Some(persisted.validator_lifecycle),
        pending: None,
    })
}

fn encode_state(state: &AppState) -> Result<Vec<u8>> {
    ensure!(
        state.pending.is_none(),
        "cannot encode pending application state"
    );
    let persisted = PersistedAppStateV3 {
        schema: "trnm_cometbft_app_state_v3".to_string(),
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
    };
    Ok(serde_json::to_vec(&persisted)?)
}

fn snapshot_hash(bytes: &[u8]) -> [u8; 32] {
    hash_domain("trnm.cometbft.snapshot.v2", &[bytes])
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
    disk_path: Option<PathBuf>,
) -> Result<SnapshotRecord> {
    ensure!(
        state.pending.is_none(),
        "cannot snapshot pending application state"
    );
    let bytes = encode_state(state)?;
    let chunk_count = bytes.len().div_ceil(SNAPSHOT_CHUNK_SIZE) as u32;
    ensure!(
        chunk_count > 0 && chunk_count <= MAX_SNAPSHOT_CHUNKS,
        "application snapshot exceeds chunk limit"
    );
    let metadata = SnapshotMetadataV2 {
        schema: "trnm_cometbft_snapshot_metadata_v2".to_string(),
        chain_id: chain_id.to_string(),
        height: state.height,
        app_hash_hex: hex::encode(state.app_hash),
        app_version: APP_VERSION,
        total_bytes: bytes.len() as u64,
        chunk_size: SNAPSHOT_CHUNK_SIZE as u32,
    };
    let content_hash = snapshot_hash(&bytes);
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
            format: SNAPSHOT_FORMAT_V2,
            chunks: chunk_count,
            hash: Bytes::copy_from_slice(&content_hash),
            metadata: Bytes::from(serde_json::to_vec(&metadata)?),
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
            RequestApplySnapshotChunk, RequestFinalizeBlock, RequestInitChain,
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
        let unimplemented_proof = app.query(RequestQuery {
            path: "/task/task-1".to_string(),
            prove: true,
            ..Default::default()
        });
        assert_ne!(unimplemented_proof.code, 0);
        assert!(unimplemented_proof.proof_ops.is_none());

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
    fn application_hash_commits_replay_protection_state() {
        let objects = BTreeMap::new();
        let empty_commands = BTreeSet::new();
        let empty_nonces = BTreeSet::new();
        let base = compute_app_hash(1, &objects, &empty_commands, &empty_nonces, None);

        let mut commands = BTreeSet::new();
        commands.insert("command-1".to_string());
        assert_ne!(
            base,
            compute_app_hash(1, &objects, &commands, &empty_nonces, None)
        );

        let mut nonces = BTreeSet::new();
        nonces.insert(("did:operator:1".to_string(), 1));
        assert_ne!(
            base,
            compute_app_hash(1, &objects, &empty_commands, &nonces, None)
        );
    }

    #[test]
    fn application_hash_is_stable_when_only_height_advances() {
        let objects = BTreeMap::new();
        let command_ids = BTreeSet::new();
        let signer_nonces = BTreeSet::new();
        assert_eq!(
            compute_app_hash(1, &objects, &command_ids, &signer_nonces, None),
            compute_app_hash(u64::MAX, &objects, &command_ids, &signer_nonces, None)
        );
    }

    #[test]
    fn delta_app_hash_exactly_matches_materialized_v3_state() {
        fn object(key: &str, version: u64, value: &[u8]) -> StoredObject {
            StoredObject {
                object_key_hex: key.to_string(),
                object_type: "fixture".to_string(),
                version,
                value_hash_hex: hex::encode(hash_domain("trnm.state.object.value.v1", &[value])),
                value_bytes: value.to_vec(),
            }
        }

        let mut state = AppState::default();
        state.objects.insert("a".to_string(), object("a", 1, b"a1"));
        state.objects.insert("c".to_string(), object("c", 1, b"c1"));
        state.command_ids.insert("command-old".to_string());
        state
            .signer_nonces
            .insert(("did:operator:1".to_string(), 1));
        state.height = 7;
        state.app_hash = compute_app_hash(
            state.height,
            &state.objects,
            &state.command_ids,
            &state.signer_nonces,
            state.validator_lifecycle.as_ref(),
        );

        let mut delta = BlockDelta::default();
        delta.objects.insert("b".to_string(), object("b", 1, b"b1"));
        delta.objects.insert("c".to_string(), object("c", 2, b"c2"));
        delta.command_ids.insert("command-new".to_string());
        delta
            .signer_nonces
            .insert(("did:operator:1".to_string(), u64::MAX));

        let mut objects = state.objects.clone();
        objects.extend(delta.objects.clone());
        let mut command_ids = state.command_ids.clone();
        command_ids.extend(delta.command_ids.clone());
        let mut signer_nonces = state.signer_nonces.clone();
        signer_nonces.extend(delta.signer_nonces.clone());
        assert_eq!(
            compute_app_hash_with_delta(8, &state, &delta),
            compute_app_hash(
                8,
                &objects,
                &command_ids,
                &signer_nonces,
                state.validator_lifecycle.as_ref(),
            )
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
        let response = finalize_and_commit(&app, 1, vec![transition_tx(&add, 101)]);
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
            let mut without_pending = lifecycle.clone();
            without_pending.pending_transition = None;
            assert_ne!(
                state.app_hash,
                compute_app_hash(
                    state.height,
                    &state.objects,
                    &state.command_ids,
                    &state.signer_nonces,
                    Some(&without_pending),
                )
            );
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
        let response = finalize_and_commit(&app, 4, vec![transition_tx(&remove, 102)]);
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
        let response = finalize_and_commit(&app, 7, vec![transition_tx(&rotation, 103)]);
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
            assert_transition_rejected(&app, &transition, 201);
        }
    }

    #[test]
    fn validator_lifecycle_rejects_stale_repeated_and_unsafe_transitions() {
        let (stale_app, _) = fixture();
        let mut target = initial_validators();
        target.push(validator(25, 10));
        let mut stale = validator_transition(&stale_app, "validator-stale-base", 3, target, &[25]);
        stale.base_validator_set_hash_hex = "00".repeat(32);
        assert_transition_rejected(&stale_app, &stale, 301);

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
            txs: vec![transition_tx(&first, 302), transition_tx(&second, 303)],
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
        assert_transition_rejected(&small_app, &too_small, 304);

        let (power_app, _) = fixture();
        let mut unsafe_power = initial_validators();
        unsafe_power.push(validator(25, 30));
        let unsafe_power =
            validator_transition(&power_app, "validator-unsafe-power", 3, unsafe_power, &[25]);
        assert_transition_rejected(&power_app, &unsafe_power, 305);

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
        assert_transition_rejected(&alias_app, &alias, 306);
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
        finalize_and_commit(&app, 1, vec![transition_tx(&transition, 401)]);
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
    fn snapshot_rejects_tampered_content_without_mutating_state() {
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
            response_apply_snapshot_chunk::Result::RejectSnapshot as i32
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
        let mut metadata: SnapshotMetadataV2 = serde_json::from_slice(&snapshot.metadata).unwrap();
        metadata.total_bytes = tampered.len() as u64;
        snapshot.chunks = tampered.len().div_ceil(SNAPSHOT_CHUNK_SIZE) as u32;
        snapshot.hash = Bytes::copy_from_slice(&snapshot_hash(&tampered));
        snapshot.metadata = Bytes::from(serde_json::to_vec(&metadata).unwrap());

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

        let mut wrong_chain_snapshot = snapshot;
        let mut metadata: SnapshotMetadataV2 =
            serde_json::from_slice(&wrong_chain_snapshot.metadata).unwrap();
        metadata.chain_id = "trnm-cloned-chain".to_string();
        wrong_chain_snapshot.metadata = Bytes::from(serde_json::to_vec(&metadata).unwrap());
        let wrong_chain = CometBftApplication::new(ConsensusAppConfig {
            chain_id: "trnm-cloned-chain".to_string(),
            ..source.core.config.clone()
        })
        .unwrap();
        assert_eq!(
            wrong_chain
                .offer_snapshot(RequestOfferSnapshot {
                    snapshot: Some(wrong_chain_snapshot),
                    app_hash: Bytes::copy_from_slice(&source_state.1),
                })
                .result,
            response_offer_snapshot::Result::Accept as i32
        );
        assert_eq!(
            wrong_chain
                .apply_snapshot_chunk(RequestApplySnapshotChunk {
                    index: 0,
                    chunk,
                    sender: "cloned-chain-validator".to_string(),
                })
                .result,
            response_apply_snapshot_chunk::Result::RejectSnapshot as i32
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
        let validator_lifecycle = fixture_app
            .core
            .state
            .lock()
            .unwrap()
            .validator_lifecycle
            .clone();
        for height in 1..=20 {
            let objects = BTreeMap::new();
            let command_ids = BTreeSet::new();
            let signer_nonces = BTreeSet::new();
            let mut state = AppState {
                height,
                app_hash: [0u8; 32],
                objects,
                command_ids,
                signer_nonces,
                validator_lifecycle: validator_lifecycle.clone(),
                pending: None,
            };
            state.app_hash = compute_app_hash(
                height,
                &state.objects,
                &state.command_ids,
                &state.signer_nonces,
                state.validator_lifecycle.as_ref(),
            );
            app.retain_snapshot(&state).unwrap();
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
    fn v3_json_migrates_once_to_sqlite_with_recoverable_backup() {
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
        fs::write(&state_path, encode_state(&source_state).unwrap()).unwrap();

        let migrated = CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(state_path.clone()),
            ..source.core.config.clone()
        })
        .unwrap();
        assert_eq!(
            migrated.height_and_app_hash().unwrap(),
            (source_state.height, source_state.app_hash)
        );
        assert!(state_path.with_extension("json.sqlite3").exists());
        assert!(state_path.with_extension("json.legacy-v3").exists());
        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(status["schema"], "trnm_cometbft_app_status_v2");
        assert_eq!(status["app_version"], APP_VERSION);
        drop(migrated);
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
    fn legacy_json_and_existing_sqlite_head_mismatch_fails_closed() {
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
        drop(app);

        let stale = fixture_app.core.state.lock().unwrap().clone();
        fs::write(&state_path, encode_state(&stale).unwrap()).unwrap();
        assert!(CometBftApplication::new(config).is_err());
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
        let tx = transition_tx(&transition, 501);
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
            .execute("UPDATE objects SET value_bytes=X'00'", [])
            .unwrap();
        drop(database);
        assert!(CometBftApplication::new(config).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sqlite_store_preserves_full_u64_nonce_domain_and_chain_binding() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-store-u64-{}-{}",
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
        let mut state = AppState {
            height: 1,
            validator_lifecycle: fixture_app
                .core
                .state
                .lock()
                .unwrap()
                .validator_lifecycle
                .clone(),
            ..Default::default()
        };
        state
            .signer_nonces
            .insert(("did:operator:1".to_string(), u64::MAX));
        state.app_hash = compute_app_hash(
            state.height,
            &state.objects,
            &state.command_ids,
            &state.signer_nonces,
            state.validator_lifecycle.as_ref(),
        );
        app.core
            .store
            .as_ref()
            .unwrap()
            .replace_state(&state)
            .unwrap();
        drop(app);

        let restarted = CometBftApplication::new(config.clone()).unwrap();
        assert!(restarted
            .core
            .state
            .lock()
            .unwrap()
            .signer_nonces
            .contains(&("did:operator:1".to_string(), u64::MAX)));
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
