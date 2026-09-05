use std::{
    collections::BTreeMap,
    fs,
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, ensure, Context, Result};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::{
    crypto::{public_key_hex, sign_hex, signing_key_from_hex},
    http::{read_request, write_json, write_response},
    merkle::root_and_proofs,
    node::{AuthorizedSignerV1, CommandInterpreter, RoutingCommandInterpreter},
    protocol::{
        ValidatorVoteRequestV1, ValidatorVoteV1, BLOCK_HEADER_SCHEMA_V1, VALIDATOR_VOTE_SCHEMA_V1,
    },
    store::StoredObject,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorConfig {
    pub chain_id: String,
    pub validator_id: String,
    pub validator_set_id: String,
    pub listen_addr: SocketAddr,
    pub private_key_path: PathBuf,
    pub database_path: PathBuf,
    pub genesis_block_hash_hex: String,
    pub authorized_signers: Vec<AuthorizedSignerV1>,
    pub max_transactions_per_block: usize,
}

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub struct ValidatorService {
    config: ValidatorConfig,
    signing_key: SigningKey,
    interpreter: RoutingCommandInterpreter,
    connection: Mutex<Connection>,
}

impl ValidatorService {
    pub fn open(config: ValidatorConfig) -> Result<Self> {
        ensure!(
            config.listen_addr.ip().is_loopback(),
            "devnet validator listen_addr must be loopback"
        );
        ensure!(
            (1..=1_024).contains(&config.max_transactions_per_block),
            "validator max_transactions_per_block out of range"
        );
        let key = load_signing_key_file(&config.private_key_path)?;
        let interpreter =
            RoutingCommandInterpreter::from_authorized_signers(&config.authorized_signers)?;
        if let Some(parent) = config.database_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create validator database directory {}", parent.display())
            })?;
        }
        let connection = Connection::open(&config.database_path).with_context(|| {
            format!("open validator database {}", config.database_path.display())
        })?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS validator_votes (
                height INTEGER PRIMARY KEY,
                block_hash_hex TEXT NOT NULL,
                previous_block_hash_hex TEXT NOT NULL,
                timestamp_unix_ms INTEGER NOT NULL,
                signature_hex TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS validator_objects (
                object_key_hex TEXT PRIMARY KEY,
                object_type TEXT NOT NULL,
                version INTEGER NOT NULL,
                value_hash_hex TEXT NOT NULL,
                value_bytes BLOB NOT NULL,
                updated_at_height INTEGER NOT NULL
            );
            ",
        )?;
        Ok(Self {
            config,
            signing_key: key,
            interpreter,
            connection: Mutex::new(connection),
        })
    }

    pub fn public_key_hex(&self) -> String {
        public_key_hex(&self.signing_key)
    }

    pub fn vote(&self, request: &ValidatorVoteRequestV1) -> Result<ValidatorVoteV1> {
        ensure!(
            request.schema == "trnm_validator_vote_request_v1",
            "unsupported validator vote request schema"
        );
        request.header.validate()?;
        ensure!(
            request.header.schema == BLOCK_HEADER_SCHEMA_V1,
            "unsupported proposed block header"
        );
        ensure!(
            request.header.chain_id == self.config.chain_id,
            "proposal chain_id mismatch"
        );
        ensure!(
            request.header.validator_set_id == self.config.validator_set_id,
            "proposal validator_set_id mismatch"
        );
        let now = now_unix_ms()?;
        ensure!(
            request.header.timestamp_unix_ms <= now.saturating_add(60_000),
            "proposal timestamp is too far in the future"
        );
        let block_hash_hex = hex::encode(request.header.block_hash()?);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow!("validator database lock poisoned"))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String)> = transaction
            .query_row(
                "SELECT block_hash_hex, signature_hex FROM validator_votes WHERE height = ?1",
                params![request.header.height],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_hash, signature_hex)) = existing {
            ensure!(
                existing_hash == block_hash_hex,
                "validator refuses conflicting block at already-signed height"
            );
            transaction.commit()?;
            return Ok(self.vote_response(request.header.height, block_hash_hex, signature_hex));
        }

        let tip: Option<(u64, String, u64)> = transaction
            .query_row(
                "SELECT height, block_hash_hex, timestamp_unix_ms
                   FROM validator_votes ORDER BY height DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        match tip {
            Some((tip_height, tip_hash, tip_timestamp)) => {
                ensure!(
                    request.header.height == tip_height.saturating_add(1),
                    "proposal height must extend validator's durable tip"
                );
                ensure!(
                    request.header.previous_block_hash_hex == tip_hash,
                    "proposal previous block hash does not extend validator tip"
                );
                ensure!(
                    request.header.timestamp_unix_ms >= tip_timestamp,
                    "proposal timestamp regresses"
                );
            }
            None => {
                ensure!(
                    request.header.height == 1,
                    "first validator vote must be for height 1"
                );
                ensure!(
                    request.header.previous_block_hash_hex == self.config.genesis_block_hash_hex,
                    "height 1 proposal does not extend configured genesis"
                );
            }
        }

        ensure!(
            !request.commands.is_empty(),
            "validator refuses an empty block proposal"
        );
        ensure!(
            request.commands.len() <= self.config.max_transactions_per_block,
            "proposal exceeds validator transaction limit"
        );
        let mut projected_objects = load_objects(&transaction)?;
        let mut transaction_leaves = Vec::with_capacity(request.commands.len());
        for envelope in &request.commands {
            envelope.validate_at(&self.config.chain_id, request.header.timestamp_unix_ms)?;
            let authorized = self
                .config
                .authorized_signers
                .iter()
                .find(|signer| signer.signer_id == envelope.signer_id)
                .ok_or_else(|| anyhow!("proposal command signer is not authorized"))?;
            ensure!(
                authorized.signer_role == envelope.signer_role
                    && authorized.public_key_hex == envelope.public_key_hex,
                "proposal command signer policy mismatch"
            );
            let execution = self
                .interpreter
                .prepare_execution(envelope, &projected_objects)?;
            execution.validate()?;
            for mutation in execution.mutations {
                let current_version = projected_objects
                    .get(&mutation.object_key_hex)
                    .map(|object| object.version);
                ensure!(
                    current_version == mutation.expected_version,
                    "proposal command object version precondition mismatch"
                );
                let stored = mutation.into_stored();
                projected_objects.insert(stored.object_key_hex.clone(), stored);
            }
            transaction_leaves.push(super::crypto::hash_domain(
                "trnm.transaction.leaf.v1",
                &[hex::encode(envelope.tx_hash()?).as_bytes()],
            ));
        }
        let (transaction_root, _) = root_and_proofs("trnm.transactions.v1", &transaction_leaves);
        ensure!(
            request.header.transaction_root_hex == hex::encode(transaction_root),
            "proposal transaction root does not match independently verified commands"
        );
        let object_leaves = projected_objects
            .values()
            .map(StoredObject::leaf_hash)
            .collect::<Vec<_>>();
        let (state_root, _) = root_and_proofs("trnm.state.objects.v1", &object_leaves);
        ensure!(
            request.header.state_root_hex == hex::encode(state_root),
            "proposal state root does not match independent execution"
        );

        let signature_hex = sign_hex(
            &self.signing_key,
            &ValidatorVoteV1::signing_bytes(
                &self.config.chain_id,
                &self.config.validator_set_id,
                request.header.height,
                &block_hash_hex,
            ),
        );
        transaction.execute(
            "INSERT INTO validator_votes
             (height, block_hash_hex, previous_block_hash_hex, timestamp_unix_ms, signature_hex)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                request.header.height,
                block_hash_hex,
                request.header.previous_block_hash_hex,
                request.header.timestamp_unix_ms,
                signature_hex
            ],
        )?;
        transaction.execute("DELETE FROM validator_objects", [])?;
        for object in projected_objects.values() {
            ensure!(
                object.version <= i64::MAX as u64,
                "object version exceeds durable range"
            );
            transaction.execute(
                "INSERT INTO validator_objects
                 (object_key_hex, object_type, version, value_hash_hex, value_bytes,
                  updated_at_height)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    object.object_key_hex,
                    object.object_type,
                    object.version as i64,
                    object.value_hash_hex,
                    object.value_bytes,
                    request.header.height as i64,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(self.vote_response(request.header.height, block_hash_hex, signature_hex))
    }

    fn vote_response(
        &self,
        height: u64,
        block_hash_hex: String,
        signature_hex: String,
    ) -> ValidatorVoteV1 {
        ValidatorVoteV1 {
            schema: VALIDATOR_VOTE_SCHEMA_V1.to_string(),
            validator_id: self.config.validator_id.clone(),
            validator_set_id: self.config.validator_set_id.clone(),
            height,
            block_hash_hex,
            public_key_hex: self.public_key_hex(),
            signature_hex,
        }
    }

    pub fn serve(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr)
            .with_context(|| format!("bind validator {}", self.config.listen_addr))?;
        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    let service = Arc::clone(&self);
                    thread::spawn(move || {
                        if let Err(error) = service.handle_connection(stream) {
                            eprintln!("[validator] request rejected: {error:#}");
                        }
                    });
                }
                Err(error) => eprintln!("[validator] accept failed: {error}"),
            }
        }
        Ok(())
    }

    pub fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        let request_limit = self
            .config
            .max_transactions_per_block
            .saturating_mul(1024 * 1024 + 4096);
        let request = match read_request(&mut stream, request_limit) {
            Ok(request) => request,
            Err(error) => {
                write_json(
                    &mut stream,
                    400,
                    &ErrorBody {
                        error: "malformed_request",
                    },
                )?;
                return Err(error);
            }
        };
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/health") => write_json(
                &mut stream,
                200,
                &serde_json::json!({
                    "status": "ok",
                    "chain_id": self.config.chain_id,
                    "validator_id": self.config.validator_id,
                    "validator_set_id": self.config.validator_set_id,
                    "public_key_hex": self.public_key_hex()
                }),
            ),
            ("GET", "/metrics") => {
                let connection = self
                    .connection
                    .lock()
                    .map_err(|_| anyhow!("validator database lock poisoned"))?;
                let votes: u64 =
                    connection
                        .query_row("SELECT COUNT(*) FROM validator_votes", [], |row| row.get(0))?;
                let objects: u64 =
                    connection.query_row("SELECT COUNT(*) FROM validator_objects", [], |row| {
                        row.get(0)
                    })?;
                let body = format!(
                    concat!(
                        "# TYPE trnm_validator_votes_total counter\n",
                        "trnm_validator_votes_total{{validator_id=\"{}\"}} {}\n",
                        "# TYPE trnm_validator_objects gauge\n",
                        "trnm_validator_objects{{validator_id=\"{}\"}} {}\n"
                    ),
                    self.config.validator_id, votes, self.config.validator_id, objects,
                );
                write_response(
                    &mut stream,
                    200,
                    "text/plain; version=0.0.4; charset=utf-8",
                    body.as_bytes(),
                )
            }
            ("POST", "/v1/vote") => {
                let parsed: ValidatorVoteRequestV1 = match serde_json::from_slice(&request.body) {
                    Ok(value) => value,
                    Err(error) => {
                        write_json(
                            &mut stream,
                            400,
                            &ErrorBody {
                                error: "invalid_json",
                            },
                        )?;
                        return Err(error.into());
                    }
                };
                match self.vote(&parsed) {
                    Ok(vote) => write_json(&mut stream, 200, &vote),
                    Err(error) => {
                        write_json(
                            &mut stream,
                            409,
                            &ErrorBody {
                                error: "vote_rejected",
                            },
                        )?;
                        Err(error)
                    }
                }
            }
            _ => write_json(&mut stream, 404, &ErrorBody { error: "not_found" }),
        }
    }
}

fn load_objects(transaction: &rusqlite::Transaction<'_>) -> Result<BTreeMap<String, StoredObject>> {
    let mut statement = transaction.prepare(
        "SELECT object_key_hex, object_type, version, value_hash_hex, value_bytes
           FROM validator_objects ORDER BY object_key_hex",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(StoredObject {
            object_key_hex: row.get(0)?,
            object_type: row.get(1)?,
            version: row.get(2)?,
            value_hash_hex: row.get(3)?,
            value_bytes: row.get(4)?,
        })
    })?;
    let mut objects = BTreeMap::new();
    for row in rows {
        let object = row?;
        objects.insert(object.object_key_hex.clone(), object);
    }
    Ok(objects)
}

pub fn load_validator_config(path: &Path) -> Result<ValidatorConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read validator config {}", path.display()))?;
    let config: ValidatorConfig = match path.extension().and_then(|value| value.to_str()) {
        Some("json") => serde_json::from_str(&raw)
            .with_context(|| format!("parse validator JSON config {}", path.display()))?,
        Some("toml") => toml::from_str(&raw)
            .with_context(|| format!("parse validator TOML config {}", path.display()))?,
        _ => {
            return Err(anyhow!(
                "validator config must use .json or .toml extension"
            ))
        }
    };
    Ok(config)
}

pub fn load_signing_key_file(path: &Path) -> Result<SigningKey> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect validator private key {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "validator private key must be a regular non-symlink file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "validator private key must not be accessible to group or world"
        );
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read validator private key {}", path.display()))?;
    ensure!(
        raw.ends_with('\n') && !raw[..raw.len() - 1].contains('\n'),
        "validator private key file must contain one newline-terminated key"
    );
    signing_key_from_hex(&raw[..raw.len() - 1])
}

fn now_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is before UNIX epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| anyhow!("system clock does not fit u64 milliseconds"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::{
        crypto::{hash_domain, public_key_hex},
        merkle::root_and_proofs,
        node::AuthorizedSignerV1,
        protocol::{BlockHeaderV1, ValidatorVoteRequestV1, BLOCK_HEADER_SCHEMA_V1},
    };
    use std::os::unix::fs::PermissionsExt;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "trnm-live-validator-{}-{}-{}",
            label,
            std::process::id(),
            now_unix_ms().unwrap()
        ))
    }

    fn service(label: &str) -> (Arc<ValidatorService>, PathBuf) {
        let root = temp_path(label);
        fs::create_dir_all(&root).unwrap();
        let key_path = root.join("validator.key");
        fs::write(&key_path, format!("{}\n", hex::encode([7u8; 32]))).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let command_key = SigningKey::from_bytes(&[8u8; 32]);
        let config = ValidatorConfig {
            chain_id: "trnm-devnet-test".to_string(),
            validator_id: "validator-1".to_string(),
            validator_set_id: "validators-v1".to_string(),
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            private_key_path: key_path,
            database_path: root.join("votes.sqlite"),
            genesis_block_hash_hex: hex::encode(hash_domain("genesis", &[b"test"])),
            authorized_signers: vec![AuthorizedSignerV1 {
                signer_id: "did:key:test-signer".to_string(),
                signer_role: "operator".to_string(),
                public_key_hex: public_key_hex(&command_key),
            }],
            max_transactions_per_block: 64,
        };
        (Arc::new(ValidatorService::open(config).unwrap()), root)
    }

    fn request(
        service: &ValidatorService,
        height: u64,
        previous: String,
    ) -> ValidatorVoteRequestV1 {
        let now = now_unix_ms().unwrap();
        let envelope = super::super::protocol::SignedCommandEnvelopeV1::sign(
            service.config.chain_id.clone(),
            format!("command-{height}"),
            "did:key:test-signer",
            "operator",
            height,
            now - 10,
            now + 60_000,
            "test_payload_v1",
            &height.to_be_bytes(),
            &SigningKey::from_bytes(&[8u8; 32]),
        )
        .unwrap();
        let execution = service
            .interpreter
            .prepare_execution(&envelope, &BTreeMap::new())
            .unwrap();
        let objects = execution
            .mutations
            .into_iter()
            .map(|mutation| mutation.into_stored())
            .collect::<Vec<_>>();
        let transaction_leaf = hash_domain(
            "trnm.transaction.leaf.v1",
            &[hex::encode(envelope.tx_hash().unwrap()).as_bytes()],
        );
        let (transaction_root, _) = root_and_proofs("trnm.transactions.v1", &[transaction_leaf]);
        let object_leaves = objects
            .iter()
            .map(StoredObject::leaf_hash)
            .collect::<Vec<_>>();
        let (state_root, _) = root_and_proofs("trnm.state.objects.v1", &object_leaves);
        ValidatorVoteRequestV1 {
            schema: "trnm_validator_vote_request_v1".to_string(),
            header: BlockHeaderV1 {
                schema: BLOCK_HEADER_SCHEMA_V1.to_string(),
                chain_id: service.config.chain_id.clone(),
                height,
                previous_block_hash_hex: previous,
                transaction_root_hex: hex::encode(transaction_root),
                state_root_hex: hex::encode(state_root),
                validator_set_id: service.config.validator_set_id.clone(),
                timestamp_unix_ms: now,
            },
            commands: vec![envelope],
        }
    }

    #[test]
    fn validator_persists_idempotent_vote_and_rejects_equivocation() {
        let (service, root) = service("equivocation");
        let first = request(&service, 1, service.config.genesis_block_hash_hex.clone());
        let vote = service.vote(&first).unwrap();
        assert_eq!(service.vote(&first).unwrap(), vote);

        let mut conflicting = first;
        conflicting.header.state_root_hex = hex::encode([9u8; 32]);
        assert!(service.vote(&conflicting).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validator_requires_contiguous_chain_extension() {
        let (service, root) = service("contiguous");
        let skipped = request(&service, 2, service.config.genesis_block_hash_hex.clone());
        assert!(service.vote(&skipped).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validator_reexecutes_body_and_rejects_forged_roots() {
        let (service, root) = service("validity");
        let valid = request(&service, 1, service.config.genesis_block_hash_hex.clone());

        let mut forged_state = valid.clone();
        forged_state.header.state_root_hex = hex::encode([9u8; 32]);
        assert!(service.vote(&forged_state).is_err());

        let mut forged_command = valid.clone();
        forged_command.commands[0].payload_hex = hex::encode(b"tampered");
        assert!(service.vote(&forged_command).is_err());

        service.vote(&valid).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
