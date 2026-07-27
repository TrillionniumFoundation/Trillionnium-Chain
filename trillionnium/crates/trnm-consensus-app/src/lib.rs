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
    merkle::root_and_proofs,
    node::{AuthorizedSignerV1, CommandInterpreter, RoutingCommandInterpreter},
    store::StoredObject,
};

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
    objects: BTreeMap<String, StoredObject>,
    command_ids: BTreeSet<String>,
    signer_nonces: BTreeSet<(String, u64)>,
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
        let state = match &config.state_path {
            Some(path) => load_state(path)?,
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

    fn execute_block(
        &self,
        state: &AppState,
        txs: &[Bytes],
        timestamp_ms: u64,
    ) -> Result<PendingBlock> {
        let mut objects = state.objects.clone();
        let mut command_ids = state.command_ids.clone();
        let mut signer_nonces = state.signer_nonces.clone();
        for tx in txs {
            self.apply_tx(
                &mut objects,
                &mut command_ids,
                &mut signer_nonces,
                tx,
                timestamp_ms,
            )?;
        }
        let next_height = state.height.saturating_add(1);
        let app_hash = compute_app_hash(next_height, &objects, &command_ids, &signer_nonces);
        Ok(PendingBlock {
            height: next_height,
            app_hash,
            objects,
            command_ids,
            signer_nonces,
        })
    }

    fn apply_tx(
        &self,
        objects: &mut BTreeMap<String, StoredObject>,
        command_ids: &mut BTreeSet<String>,
        signer_nonces: &mut BTreeSet<(String, u64)>,
        tx: &[u8],
        timestamp_ms: u64,
    ) -> Result<()> {
        let envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(tx).context("decode signed command envelope")?;
        self.validate_envelope(&envelope, timestamp_ms)?;
        ensure!(
            command_ids.insert(envelope.command_id.clone()),
            "command_id replay rejected"
        );
        ensure!(
            signer_nonces.insert((envelope.signer_id.clone(), envelope.nonce)),
            "signer nonce replay rejected"
        );
        let execution = self
            .core
            .interpreter
            .prepare_execution(&envelope, objects)?;
        execution.validate()?;
        for mutation in execution.mutations {
            let current_version = objects
                .get(&mutation.object_key_hex)
                .map(|object| object.version);
            ensure!(
                current_version == mutation.expected_version,
                "object version precondition mismatch"
            );
            let stored = mutation.into_stored();
            objects.insert(stored.object_key_hex.clone(), stored);
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
        if disk_path.is_some() && state.height % DISK_SNAPSHOT_INTERVAL != 0 {
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
        let (height, app_hash) = self.height_and_app_hash().unwrap_or((0, empty_app_hash()));
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
        match self.execute_block(&state, &[request.tx], now_unix_ms()) {
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
        let mut objects = state.objects.clone();
        let mut command_ids = state.command_ids.clone();
        let mut signer_nonces = state.signer_nonces.clone();
        let mut total_bytes = 0usize;
        let max_bytes = usize::try_from(request.max_tx_bytes).unwrap_or(0);
        let mut txs = Vec::new();
        for tx in request.txs {
            let next_total = total_bytes.saturating_add(tx.len());
            if next_total > max_bytes {
                continue;
            }
            let mut candidate_objects = objects.clone();
            let mut candidate_command_ids = command_ids.clone();
            let mut candidate_signer_nonces = signer_nonces.clone();
            if self
                .apply_tx(
                    &mut candidate_objects,
                    &mut candidate_command_ids,
                    &mut candidate_signer_nonces,
                    &tx,
                    timestamp_ms,
                )
                .is_err()
            {
                continue;
            }
            objects = candidate_objects;
            command_ids = candidate_command_ids;
            signer_nonces = candidate_signer_nonces;
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
                self.execute_block(&state, &request.txs, timestamp_ms(request.time.as_ref()))?;
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
        let mut state = match self.core.state.lock() {
            Ok(state) => state,
            Err(_) => return finalize_error(request.txs.len(), "state lock poisoned"),
        };
        if request.height != state.height as i64 + 1 {
            return finalize_error(request.txs.len(), "finalize height mismatch");
        }
        match self.execute_block(&state, &request.txs, timestamp_ms(request.time.as_ref())) {
            Ok(pending) => {
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
            Err(error) => finalize_error(request.txs.len(), &format!("{error:#}")),
        }
    }

    fn commit(&self) -> ResponseCommit {
        if let Ok(mut state) = self.core.state.lock() {
            if let Some(pending) = state.pending.take() {
                let next = AppState {
                    height: pending.height,
                    app_hash: pending.app_hash,
                    objects: pending.objects,
                    command_ids: pending.command_ids,
                    signer_nonces: pending.signer_nonces,
                    pending: None,
                };
                if let Some(path) = &self.core.config.state_path {
                    persist_state(path, &next).unwrap_or_else(|error| {
                        panic!("persist committed consensus application state: {error:#}")
                    });
                }
                self.retain_snapshot(&next).unwrap_or_else(|error| {
                    panic!("retain committed consensus application snapshot: {error:#}")
                });
                *state = next;
            }
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
        if let Some(path) = &self.core.config.state_path {
            persist_state_bytes(path, &bytes)?;
        }
        let mut state = self
            .core
            .state
            .lock()
            .map_err(|_| anyhow!("consensus application state lock poisoned"))?;
        ensure!(
            state.height == 0 && state.pending.is_none(),
            "application state changed during snapshot restore"
        );
        *state = next;
        self.retain_snapshot(&state)?;
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

fn finalize_error(tx_count: usize, message: &str) -> ResponseFinalizeBlock {
    ResponseFinalizeBlock {
        tx_results: (0..tx_count)
            .map(|_| ExecTxResult {
                code: 1,
                log: message.to_string(),
                codespace: "trnm".to_string(),
                ..Default::default()
            })
            .collect(),
        app_hash: Bytes::copy_from_slice(&empty_app_hash()),
        ..Default::default()
    }
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
    let object_leaves = objects
        .values()
        .map(StoredObject::leaf_hash)
        .collect::<Vec<_>>();
    let command_leaves = command_ids
        .iter()
        .map(|command_id| hash_domain("trnm.state.command-id.v1", &[command_id.as_bytes()]))
        .collect::<Vec<_>>();
    let nonce_leaves = signer_nonces
        .iter()
        .map(|(signer_id, nonce)| {
            hash_domain(
                "trnm.state.signer-nonce.v1",
                &[signer_id.as_bytes(), &nonce.to_be_bytes()],
            )
        })
        .collect::<Vec<_>>();
    let (object_root, _) = root_and_proofs("trnm.state.objects.v1", &object_leaves);
    let (command_root, _) = root_and_proofs("trnm.state.command-ids.v1", &command_leaves);
    let (nonce_root, _) = root_and_proofs("trnm.state.signer-nonces.v1", &nonce_leaves);
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

fn persist_state(path: &Path, state: &AppState) -> Result<()> {
    persist_state_bytes(path, &encode_state(state)?)
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
    fn committed_state_survives_application_restart() {
        let root = std::env::temp_dir().join(format!(
            "trnm-comet-state-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let (fixture_app, envelope) = fixture();
        let config = ConsensusAppConfig {
            state_path: Some(root.clone()),
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
        let _ = fs::remove_file(root);
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
            "trnm-comet-restored-state-{}-{}.json",
            std::process::id(),
            now_unix_ms()
        ));
        let target = CometBftApplication::new(ConsensusAppConfig {
            state_path: Some(root.clone()),
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
            state_path: Some(root.clone()),
            ..source.core.config.clone()
        })
        .unwrap();
        assert_eq!(restarted.height_and_app_hash().unwrap(), source_state);
        let _ = fs::remove_file(root);
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
}
