use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, ensure, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    response_process_proposal, ExecTxResult, RequestCheckTx, RequestFinalizeBlock, RequestInfo,
    RequestProcessProposal, ResponseCheckTx, ResponseCommit, ResponseFinalizeBlock, ResponseInfo,
    ResponseProcessProposal,
};
use trnm_finality_types::{hash_domain, SignedCommandEnvelopeV1};
use trnm_node::live::{
    merkle::root_and_proofs,
    node::{AuthorizedSignerV1, CommandInterpreter, RoutingCommandInterpreter},
    store::StoredObject,
};

pub const CONFIG_SCHEMA_V1: &str = "trnm_cometbft_app_config_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusAppConfig {
    pub schema: String,
    pub chain_id: String,
    pub authorized_signers: Vec<AuthorizedSignerV1>,
    #[serde(default)]
    pub state_path: Option<PathBuf>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAppStateV1 {
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
        Ok(Self {
            core: Arc::new(AppCore {
                config,
                interpreter,
                state: Mutex::new(state),
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
                .prepare_execution(&envelope, &objects)?;
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
        }
        let leaves = objects
            .values()
            .map(StoredObject::leaf_hash)
            .collect::<Vec<_>>();
        let (state_root, _) = root_and_proofs("trnm.state.objects.v1", &leaves);
        let next_height = state.height.saturating_add(1);
        let app_hash = hash_domain(
            "trnm.cometbft.application.v1",
            &[&next_height.to_be_bytes(), &state_root],
        );
        Ok(PendingBlock {
            height: next_height,
            app_hash,
            objects,
            command_ids,
            signer_nonces,
        })
    }
}

impl Application for CometBftApplication {
    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        let (height, app_hash) = self.height_and_app_hash().unwrap_or((0, empty_app_hash()));
        ResponseInfo {
            data: "trnm-consensus-app".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            app_version: 1,
            last_block_height: height as i64,
            last_block_app_hash: Bytes::copy_from_slice(&app_hash),
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
                *state = next;
            }
        }
        ResponseCommit::default()
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
    let persisted: PersistedAppStateV1 = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read app state {}", path.display()))?,
    )
    .with_context(|| format!("decode app state {}", path.display()))?;
    ensure!(
        persisted.schema == "trnm_cometbft_app_state_v1",
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
    let leaves = objects
        .values()
        .map(StoredObject::leaf_hash)
        .collect::<Vec<_>>();
    let (state_root, _) = root_and_proofs("trnm.state.objects.v1", &leaves);
    let expected = hash_domain(
        "trnm.cometbft.application.v1",
        &[&persisted.height.to_be_bytes(), &state_root],
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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create app state directory {}", parent.display()))?;
    }
    let persisted = PersistedAppStateV1 {
        schema: "trnm_cometbft_app_state_v1".to_string(),
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
    let bytes = serde_json::to_vec(&persisted)?;
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
    file.write_all(&bytes)?;
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
        v0_38::abci::{RequestFinalizeBlock, RequestProcessProposal},
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
}
