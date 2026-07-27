use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, ensure, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    response_apply_snapshot_chunk, response_offer_snapshot, response_process_proposal,
    ExecTxResult, RequestApplySnapshotChunk, RequestCheckTx, RequestFinalizeBlock, RequestInfo,
    RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot, RequestPrepareProposal,
    RequestProcessProposal, ResponseApplySnapshotChunk, ResponseCheckTx, ResponseCommit,
    ResponseFinalizeBlock, ResponseInfo, ResponseInitChain, ResponseListSnapshots,
    ResponseLoadSnapshotChunk, ResponseOfferSnapshot, ResponsePrepareProposal,
    ResponseProcessProposal, Snapshot,
};
use trnm_finality_types::{hash_domain, SignedCommandEnvelopeV1};
use trnm_node::live::{
    merkle::root_only,
    node::{AuthorizedSignerV1, CommandInterpreter, ObjectView, RoutingCommandInterpreter},
    store::StoredObject,
};

mod store;

use store::ApplicationStore;

pub const CONFIG_SCHEMA_V1: &str = "trnm_cometbft_app_config_v1";
pub const GENESIS_SCHEMA_V1: &str = "trnm_cometbft_genesis_v1";
const SNAPSHOT_FORMAT_V1: u32 = 1;
const SNAPSHOT_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_SNAPSHOT_CHUNKS: u32 = 4096;
const RETAINED_SNAPSHOTS: usize = 16;
const DISK_SNAPSHOT_INTERVAL: u64 = 5;
const RETAINED_DISK_SNAPSHOTS: usize = 3;

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
pub struct GenesisAppStateV1 {
    pub schema: String,
    pub chain_id: String,
    pub app_version: u64,
    pub authorized_signers: Vec<AuthorizedSignerV1>,
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
    pending: Option<PendingBlock>,
}

#[derive(Debug, Clone)]
struct PendingBlock {
    height: u64,
    app_hash: [u8; 32],
    delta: BlockDelta,
}

#[derive(Debug, Clone, Default)]
struct BlockDelta {
    objects: BTreeMap<String, StoredObject>,
    command_ids: BTreeSet<String>,
    signer_nonces: BTreeSet<(String, u64)>,
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

impl Default for AppState {
    fn default() -> Self {
        Self {
            height: 0,
            app_hash: empty_app_hash(),
            objects: BTreeMap::new(),
            command_ids: BTreeSet::new(),
            signer_nonces: BTreeSet::new(),
            pending: None,
        }
    }
}

struct AppCore {
    config: ConsensusAppConfig,
    interpreter: RoutingCommandInterpreter,
    store: Option<ApplicationStore>,
    state: Mutex<AppState>,
    snapshots: Mutex<BTreeMap<u64, SnapshotRecord>>,
    snapshot_restore: Mutex<Option<SnapshotRestore>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAppStateV2 {
    schema: String,
    height: u64,
    app_hash_hex: String,
    objects: Vec<PersistedObjectV1>,
    command_ids: BTreeSet<String>,
    signer_nonces: BTreeSet<(String, u64)>,
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
struct SnapshotMetadataV1 {
    schema: String,
    chain_id: String,
    height: u64,
    app_hash_hex: String,
    total_bytes: u64,
    chunk_size: u32,
}

#[derive(Debug, Clone)]
struct SnapshotRestore {
    snapshot: Snapshot,
    metadata: SnapshotMetadataV1,
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
        config.validate()?;
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
                interpreter,
                store,
                state: Mutex::new(state),
                snapshots: Mutex::new(snapshots),
                snapshot_restore: Mutex::new(None),
            }),
        })
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

    fn plan_block(&self, state: &AppState, txs: &[Bytes], timestamp_ms: u64) -> Result<BlockDelta> {
        let mut delta = BlockDelta::default();
        for tx in txs {
            self.apply_tx(state, &mut delta, tx, timestamp_ms)?;
        }
        Ok(delta)
    }

    fn execute_block(
        &self,
        state: &AppState,
        txs: &[Bytes],
        timestamp_ms: u64,
    ) -> Result<PendingBlock> {
        let delta = self.plan_block(state, txs, timestamp_ms)?;
        let next_height = state.height.saturating_add(1);
        let app_hash = compute_app_hash_with_delta(next_height, state, &delta);
        Ok(PendingBlock {
            height: next_height,
            app_hash,
            delta,
        })
    }

    fn apply_tx(
        &self,
        state: &AppState,
        delta: &mut BlockDelta,
        tx: &[u8],
        timestamp_ms: u64,
    ) -> Result<()> {
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
        let execution = {
            let objects = OverlayObjects {
                base: &state.objects,
                changes: &delta.objects,
            };
            self.core
                .interpreter
                .prepare_execution(&envelope, &objects)?
        };
        execution.validate()?;
        for mutation in execution.mutations {
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
        Ok(())
    }

    fn validate_genesis(&self, request: &RequestInitChain) -> Result<()> {
        ensure!(
            request.chain_id == self.core.config.chain_id,
            "genesis chain_id mismatch"
        );
        ensure!(
            !request.app_state_bytes.is_empty(),
            "genesis app_state must not be empty"
        );
        let genesis: GenesisAppStateV1 =
            serde_json::from_slice(&request.app_state_bytes).context("decode genesis app_state")?;
        ensure!(
            genesis.schema == GENESIS_SCHEMA_V1,
            "unsupported genesis schema"
        );
        ensure!(
            genesis.chain_id == self.core.config.chain_id,
            "genesis app_state chain_id mismatch"
        );
        ensure!(genesis.app_version == 2, "unsupported genesis app version");
        ensure!(
            canonical_signers(&genesis.authorized_signers)
                == canonical_signers(&self.core.config.authorized_signers),
            "genesis authorized signers do not match application config"
        );
        let state = self
            .core
            .state
            .lock()
            .map_err(|_| anyhow!("state lock poisoned"))?;
        ensure!(
            state.height == 0,
            "InitChain cannot replace committed state"
        );
        Ok(())
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
            app_version: 2,
            last_block_height: height as i64,
            last_block_app_hash: Bytes::copy_from_slice(&app_hash),
        }
    }

    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        self.validate_genesis(&request)
            .unwrap_or_else(|error| panic!("refuse incompatible CometBFT genesis: {error:#}"));
        let (_, app_hash) = self
            .height_and_app_hash()
            .expect("read initialized application state");
        ResponseInitChain {
            consensus_params: request.consensus_params,
            validators: request.validators,
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

    fn prepare_proposal(&self, request: RequestPrepareProposal) -> ResponsePrepareProposal {
        if request.max_tx_bytes <= 0 {
            return ResponsePrepareProposal::default();
        }
        let state = match self.core.state.lock() {
            Ok(state) if request.height == state.height as i64 + 1 => state,
            _ => return ResponsePrepareProposal::default(),
        };
        let timestamp_ms = timestamp_ms(request.time.as_ref());
        let mut delta = BlockDelta::default();
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
        state.pending = Some(pending);
        ResponseFinalizeBlock {
            tx_results: request
                .txs
                .iter()
                .map(|_| ExecTxResult::default())
                .collect(),
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
        state.height = pending.height;
        state.app_hash = pending.app_hash;
        for (key, object) in pending.delta.objects {
            state.objects.insert(key, object);
        }
        state.command_ids.extend(pending.delta.command_ids);
        state.signer_nonces.extend(pending.delta.signer_nonces);
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
            snapshot.format == SNAPSHOT_FORMAT_V1,
            "unsupported snapshot format"
        );
        ensure!(
            snapshot.chunks > 0 && snapshot.chunks <= MAX_SNAPSHOT_CHUNKS,
            "invalid snapshot chunk count"
        );
        ensure!(snapshot.hash.len() == 32, "invalid snapshot hash length");
        let metadata: SnapshotMetadataV1 =
            serde_json::from_slice(&snapshot.metadata).context("decode snapshot metadata")?;
        ensure!(
            metadata.schema == "trnm_cometbft_snapshot_metadata_v1",
            "unsupported snapshot metadata schema"
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
    hash_domain("trnm.cometbft.application.empty.v1", &[])
}

fn compute_app_hash(
    height: u64,
    objects: &BTreeMap<String, StoredObject>,
    command_ids: &BTreeSet<String>,
    signer_nonces: &BTreeSet<(String, u64)>,
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
    compose_app_hash(height, object_root, command_root, nonce_root)
}

fn compute_app_hash_with_delta(height: u64, state: &AppState, delta: &BlockDelta) -> [u8; 32] {
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
    compose_app_hash(height, object_root, command_root, nonce_root)
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
    height: u64,
    object_root: [u8; 32],
    command_root: [u8; 32],
    nonce_root: [u8; 32],
) -> [u8; 32] {
    hash_domain(
        "trnm.cometbft.application.v2",
        &[
            &height.to_be_bytes(),
            &object_root,
            &command_root,
            &nonce_root,
        ],
    )
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
    let persisted: PersistedAppStateV2 =
        serde_json::from_slice(bytes).context("decode persisted application state")?;
    ensure!(
        persisted.schema == "trnm_cometbft_app_state_v2",
        "unsupported persisted app state schema"
    );
    let app_hash =
        trnm_finality_types::decode_hash32("persisted app_hash", &persisted.app_hash_hex)?;
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
    );
    ensure!(expected == app_hash, "persisted application hash mismatch");
    Ok(AppState {
        height: persisted.height,
        app_hash,
        objects,
        command_ids: persisted.command_ids,
        signer_nonces: persisted.signer_nonces,
        pending: None,
    })
}

fn encode_state(state: &AppState) -> Result<Vec<u8>> {
    ensure!(
        state.pending.is_none(),
        "cannot encode pending application state"
    );
    let persisted = PersistedAppStateV2 {
        schema: "trnm_cometbft_app_state_v2".to_string(),
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
    };
    Ok(serde_json::to_vec(&persisted)?)
}

fn snapshot_hash(bytes: &[u8]) -> [u8; 32] {
    hash_domain("trnm.cometbft.snapshot.v1", &[bytes])
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
    let metadata = SnapshotMetadataV1 {
        schema: "trnm_cometbft_snapshot_metadata_v1".to_string(),
        chain_id: chain_id.to_string(),
        height: state.height,
        app_hash_hex: hex::encode(state.app_hash),
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
            format: SNAPSHOT_FORMAT_V1,
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
            RequestProcessProposal,
        },
    };
    use trnm_finality_types::crypto::public_key_hex;

    use super::*;

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
        let genesis = GenesisAppStateV1 {
            schema: GENESIS_SCHEMA_V1.to_string(),
            chain_id: app.core.config.chain_id.clone(),
            app_version: 2,
            authorized_signers: app.core.config.authorized_signers.clone(),
        };
        RequestInitChain {
            chain_id: app.core.config.chain_id.clone(),
            app_state_bytes: Bytes::from(serde_json::to_vec(&genesis).unwrap()),
            ..Default::default()
        }
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
    fn application_hash_commits_replay_protection_state() {
        let objects = BTreeMap::new();
        let empty_commands = BTreeSet::new();
        let empty_nonces = BTreeSet::new();
        let base = compute_app_hash(1, &objects, &empty_commands, &empty_nonces);

        let mut commands = BTreeSet::new();
        commands.insert("command-1".to_string());
        assert_ne!(
            base,
            compute_app_hash(1, &objects, &commands, &empty_nonces)
        );

        let mut nonces = BTreeSet::new();
        nonces.insert(("did:operator:1".to_string(), 1));
        assert_ne!(
            base,
            compute_app_hash(1, &objects, &empty_commands, &nonces)
        );
    }

    #[test]
    fn delta_app_hash_exactly_matches_materialized_v2_state() {
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
            compute_app_hash(8, &objects, &command_ids, &signer_nonces)
        );
    }

    #[test]
    fn init_chain_binds_chain_identity_signers_and_app_version() {
        let (app, _) = fixture();
        let response = app.init_chain(genesis_request(&app));
        assert_eq!(response.app_hash.as_ref(), empty_app_hash());

        let mut wrong_chain = genesis_request(&app);
        wrong_chain.chain_id = "wrong-chain".to_string();
        assert!(std::panic::catch_unwind(|| app.init_chain(wrong_chain)).is_err());

        let mut wrong_version = genesis_request(&app);
        let mut genesis: GenesisAppStateV1 =
            serde_json::from_slice(&wrong_version.app_state_bytes).unwrap();
        genesis.app_version = 3;
        wrong_version.app_state_bytes = Bytes::from(serde_json::to_vec(&genesis).unwrap());
        assert!(std::panic::catch_unwind(|| app.init_chain(wrong_version)).is_err());
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
        for height in 1..=20 {
            let objects = BTreeMap::new();
            let command_ids = BTreeSet::new();
            let signer_nonces = BTreeSet::new();
            let state = AppState {
                height,
                app_hash: compute_app_hash(height, &objects, &command_ids, &signer_nonces),
                objects,
                command_ids,
                signer_nonces,
                pending: None,
            };
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
    fn legacy_v2_json_migrates_once_to_sqlite_with_recoverable_backup() {
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
        assert!(state_path.with_extension("json.legacy-v2").exists());
        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(status["schema"], "trnm_cometbft_app_status_v1");
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
            br#"{"schema":"trnm_cometbft_app_status_v1","height":0,"app_hash_hex":"stale"}"#,
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
        app.finalize_block(RequestFinalizeBlock {
            txs: vec![Bytes::from(serde_json::to_vec(&envelope).unwrap())],
            height: 1,
            time: block_time(),
            ..Default::default()
        });
        app.commit();
        drop(app);

        fs::write(&state_path, encode_state(&AppState::default()).unwrap()).unwrap();
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
        let (fixture_app, envelope) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(state_path),
            ..fixture_app.core.config.clone()
        };
        let tx = Bytes::from(serde_json::to_vec(&envelope).unwrap());

        let app = CometBftApplication::new(config.clone()).unwrap();
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
