use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use trnm_research_protocol::{
    ApplyOutcome, AuthorityIdentityV1, AuthoritySetV1, ResearchObjectKind,
    ResearchProtocolSnapshotV1, ResearchProtocolState, SignedResearchCommandV1,
};

use super::{
    crypto::{decode_hash32, hash_domain},
    http::{post_json, read_request, write_json, write_response},
    merkle::root_and_proofs,
    protocol::{
        BlockHeaderV1, FinalityReceiptV1, ObjectRefV1, QuorumCertificateV1,
        SignedCommandEnvelopeV1, ValidatorSetV1, ValidatorVoteRequestV1, ValidatorVoteV1,
        BLOCK_HEADER_SCHEMA_V1, FINALITY_RECEIPT_SCHEMA_V1,
    },
    store::{
        CommandStatus, DurableStore, FinalizedCommand, InsertCommandOutcome, ObjectMutation,
        QueuedCommand, StoredObject,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedSignerV1 {
    pub signer_id: String,
    pub signer_role: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveChainConfig {
    pub schema: String,
    pub scope: String,
    pub development_only: bool,
    pub chain_id: String,
    pub listen_addr: SocketAddr,
    pub database_path: PathBuf,
    pub block_interval_ms: u64,
    pub max_transactions_per_block: usize,
    pub validator_request_timeout_ms: u64,
    pub validator_set: ValidatorSetV1,
    pub authorized_signers: Vec<AuthorizedSignerV1>,
}

impl LiveChainConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "trnm_chain_node_config_v1",
            "unsupported live node config schema"
        );
        ensure!(
            self.scope == "loopback-local-devnet" && self.development_only,
            "live node package is restricted to development-only loopback devnet scope"
        );
        ensure!(
            self.listen_addr.ip().is_loopback(),
            "live node listen_addr must be loopback"
        );
        ensure!(
            self.block_interval_ms > 0,
            "block_interval_ms must be positive"
        );
        ensure!(
            (1..=1000).contains(&self.max_transactions_per_block),
            "max_transactions_per_block must be in 1..=1000"
        );
        ensure!(
            (100..=30_000).contains(&self.validator_request_timeout_ms),
            "validator_request_timeout_ms must be in 100..=30000"
        );
        ensure!(
            !self.chain_id.is_empty()
                && self.chain_id.len() <= 128
                && self.chain_id == self.chain_id.trim(),
            "chain_id is not canonical"
        );
        self.validator_set.validate()?;
        ensure!(
            !self.authorized_signers.is_empty(),
            "authorized_signers must not be empty"
        );
        let mut signer_ids = BTreeSet::new();
        let mut signer_keys = BTreeSet::new();
        for signer in &self.authorized_signers {
            ensure!(
                !signer.signer_id.is_empty() && signer.signer_id == signer.signer_id.trim(),
                "authorized signer_id is not canonical"
            );
            ensure!(
                matches!(signer.signer_role.as_str(), "hepta" | "nakama" | "operator"),
                "authorized signer role is unsupported"
            );
            let _ = decode_hash32("authorized signer public key", &signer.public_key_hex)?;
            ensure!(
                signer_ids.insert(signer.signer_id.clone()),
                "duplicate authorized signer_id"
            );
            ensure!(
                signer_keys.insert(signer.public_key_hex.clone()),
                "duplicate authorized signer public key"
            );
        }
        Ok(())
    }

    pub fn genesis_hash_hex(&self) -> Result<String> {
        self.validate()?;
        let mut validators = self
            .validator_set
            .validators
            .iter()
            .map(|validator| {
                serde_json::json!({
                    "validator_id": validator.validator_id,
                    "public_key_hex": validator.public_key_hex,
                    "voting_power": validator.voting_power
                })
            })
            .collect::<Vec<_>>();
        validators.sort_by(|left, right| {
            left["validator_id"]
                .as_str()
                .cmp(&right["validator_id"].as_str())
        });
        let mut signers = self.authorized_signers.clone();
        signers.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "trnm_chain_genesis_commitment_v1",
            "scope": self.scope,
            "development_only": self.development_only,
            "chain_id": self.chain_id,
            "validator_set_id": self.validator_set.validator_set_id,
            "quorum_power": self.validator_set.quorum_power,
            "validators": validators,
            "authorized_signers": signers
        }))?;
        Ok(hex::encode(hash_domain("trnm.chain.genesis.v1", &[&bytes])))
    }

    fn authorized_signer(&self, signer_id: &str) -> Option<&AuthorizedSignerV1> {
        self.authorized_signers
            .iter()
            .find(|signer| signer.signer_id == signer_id)
    }
}

pub trait ObjectView {
    fn get(&self, object_key_hex: &str) -> Option<&StoredObject>;

    fn contains_key(&self, object_key_hex: &str) -> bool {
        self.get(object_key_hex).is_some()
    }
}

impl ObjectView for BTreeMap<String, StoredObject> {
    fn get(&self, object_key_hex: &str) -> Option<&StoredObject> {
        BTreeMap::get(self, object_key_hex)
    }
}

pub trait CommandInterpreter: Send + Sync {
    fn prepare_execution(
        &self,
        envelope: &SignedCommandEnvelopeV1,
        objects: &dyn ObjectView,
    ) -> Result<CommandExecution>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExecution {
    pub primary_object_key_hex: String,
    pub domain_command_fingerprint_hex: Option<String>,
    pub mutations: Vec<ObjectMutation>,
}

impl CommandExecution {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.mutations.is_empty(),
            "command execution must contain at least one mutation"
        );
        let mut keys = BTreeSet::new();
        for mutation in &self.mutations {
            ensure!(
                keys.insert(mutation.object_key_hex.clone()),
                "command execution contains duplicate object mutation"
            );
            ensure!(
                mutation.next_version > 0
                    && mutation.next_version
                        == mutation.expected_version.unwrap_or(0).saturating_add(1),
                "object mutation version transition is not contiguous"
            );
        }
        ensure!(
            keys.contains(&self.primary_object_key_hex),
            "primary object must be present in command mutations"
        );
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct OpaqueCommitmentInterpreter;

impl CommandInterpreter for OpaqueCommitmentInterpreter {
    fn prepare_execution(
        &self,
        envelope: &SignedCommandEnvelopeV1,
        objects: &dyn ObjectView,
    ) -> Result<CommandExecution> {
        let key = hex::encode(hash_domain(
            "trnm.opaque.command.object-key.v1",
            &[
                envelope.payload_type.as_bytes(),
                envelope.command_id.as_bytes(),
            ],
        ));
        ensure!(
            !objects.contains_key(&key),
            "opaque command object already exists"
        );
        Ok(CommandExecution {
            primary_object_key_hex: key.clone(),
            domain_command_fingerprint_hex: None,
            mutations: vec![ObjectMutation {
                object_key_hex: key,
                object_type: envelope.payload_type.clone(),
                expected_version: None,
                next_version: 1,
                value_bytes: envelope.payload_bytes()?,
            }],
        })
    }
}

pub const RESEARCH_COMMAND_PAYLOAD_TYPE_V1: &str = "trnm_research_command_v1";
const RESEARCH_SNAPSHOT_OBJECT_TYPE_V1: &str = "trnm_research_protocol_snapshot_v1";

pub struct RoutingCommandInterpreter {
    opaque: OpaqueCommitmentInterpreter,
    research_authorities: AuthoritySetV1,
}

impl RoutingCommandInterpreter {
    pub fn from_config(config: &LiveChainConfig) -> Result<Self> {
        Self::from_authorized_signers(&config.authorized_signers)
    }

    pub fn from_authorized_signers(signers: &[AuthorizedSignerV1]) -> Result<Self> {
        let mut nakama = Vec::new();
        let mut hepta = Vec::new();
        for signer in signers {
            let identity = AuthorityIdentityV1::new(
                signer.signer_id.clone(),
                decode_hash32("authorized signer public key", &signer.public_key_hex)?,
            )
            .map_err(|error| anyhow!("invalid research authority: {error}"))?;
            match signer.signer_role.as_str() {
                "nakama" => nakama.push(identity),
                "hepta" => hepta.push(identity),
                "operator" => {}
                _ => unreachable!("LiveChainConfig validates signer roles"),
            }
        }
        Ok(Self {
            opaque: OpaqueCommitmentInterpreter,
            research_authorities: AuthoritySetV1::new(nakama, hepta)
                .map_err(|error| anyhow!("invalid research authority set: {error}"))?,
        })
    }

    fn prepare_research_execution(
        &self,
        envelope: &SignedCommandEnvelopeV1,
        objects: &dyn ObjectView,
    ) -> Result<CommandExecution> {
        let signed = SignedResearchCommandV1::from_canonical_bytes(&envelope.payload_bytes()?)
            .map_err(|error| anyhow!("decode canonical research command: {error}"))?;
        ensure!(
            signed.chain_id == envelope.chain_id,
            "inner research command chain_id does not match outer envelope"
        );
        ensure!(
            signed.signer_did == envelope.signer_id,
            "inner research signer DID does not match outer envelope"
        );
        let expected_role = match signed.signer_role {
            trnm_research_protocol::AuthorityRole::NakamaAuthority => "nakama",
            trnm_research_protocol::AuthorityRole::HeptaAuthority => "hepta",
        };
        ensure!(
            envelope.signer_role == expected_role,
            "inner research signer role does not match outer envelope"
        );
        ensure!(
            hex::encode(signed.public_key) == envelope.public_key_hex,
            "inner research signer key does not match outer envelope"
        );

        let snapshot_key = research_snapshot_key();
        let mut state = if let Some(stored) = objects.get(&snapshot_key) {
            ensure!(
                stored.object_type == RESEARCH_SNAPSHOT_OBJECT_TYPE_V1,
                "research snapshot object type mismatch"
            );
            let snapshot: ResearchProtocolSnapshotV1 = serde_json::from_slice(&stored.value_bytes)
                .context("decode durable research protocol snapshot")?;
            ResearchProtocolState::from_snapshot(snapshot)
                .map_err(|error| anyhow!("restore durable research protocol state: {error}"))?
        } else {
            ResearchProtocolState::with_authorities(self.research_authorities.clone())
                .map_err(|error| anyhow!("initialize research protocol state: {error}"))?
        };
        ensure!(
            state.export_snapshot().authorities == self.research_authorities,
            "durable research authority set differs from genesis signer policy"
        );

        let outcome = state
            .apply(&signed)
            .map_err(|error| anyhow!("apply research protocol command: {error}"))?;
        let (primary_object_ref, changed_object_refs) = match outcome {
            ApplyOutcome::Applied {
                primary_object_ref,
                changed_object_refs,
            }
            | ApplyOutcome::Idempotent {
                primary_object_ref,
                changed_object_refs,
            } => (primary_object_ref, changed_object_refs),
        };

        let mut mutations = Vec::with_capacity(changed_object_refs.len() + 1);
        for object_ref in changed_object_refs {
            let object_key_hex = research_object_key(object_ref.kind, object_ref.key.as_bytes());
            let expected_version = objects.get(&object_key_hex).map(|object| object.version);
            ensure!(
                expected_version.unwrap_or(0).saturating_add(1) == object_ref.object_version,
                "research object version transition is not contiguous"
            );
            mutations.push(ObjectMutation {
                object_key_hex,
                object_type: research_object_type(object_ref.kind).to_string(),
                expected_version,
                next_version: object_ref.object_version,
                value_bytes: state
                    .object_canonical_bytes(object_ref)
                    .map_err(|error| anyhow!("encode research object: {error}"))?,
            });
        }

        let snapshot_version = objects
            .get(&snapshot_key)
            .map(|object| object.version)
            .unwrap_or(0)
            .saturating_add(1);
        mutations.push(ObjectMutation {
            object_key_hex: snapshot_key,
            object_type: RESEARCH_SNAPSHOT_OBJECT_TYPE_V1.to_string(),
            expected_version: objects
                .get(&research_snapshot_key())
                .map(|object| object.version),
            next_version: snapshot_version,
            value_bytes: serde_json::to_vec(&state.export_snapshot())?,
        });

        Ok(CommandExecution {
            primary_object_key_hex: research_object_key(
                primary_object_ref.kind,
                primary_object_ref.key.as_bytes(),
            ),
            domain_command_fingerprint_hex: Some(hex::encode(signed.command_fingerprint())),
            mutations,
        })
    }
}

impl CommandInterpreter for RoutingCommandInterpreter {
    fn prepare_execution(
        &self,
        envelope: &SignedCommandEnvelopeV1,
        objects: &dyn ObjectView,
    ) -> Result<CommandExecution> {
        if envelope.payload_type == RESEARCH_COMMAND_PAYLOAD_TYPE_V1 {
            self.prepare_research_execution(envelope, objects)
        } else {
            self.opaque.prepare_execution(envelope, objects)
        }
    }
}

fn research_snapshot_key() -> String {
    hex::encode(hash_domain(
        "trnm.research.protocol.snapshot.object-key.v1",
        &[b"singleton"],
    ))
}

fn research_object_key(kind: ResearchObjectKind, key: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(33);
    bytes.push(kind as u8);
    bytes.extend_from_slice(key);
    hex::encode(bytes)
}

fn research_object_type(kind: ResearchObjectKind) -> &'static str {
    match kind {
        ResearchObjectKind::MatchEvidence => "trnm_match_evidence_v1",
        ResearchObjectKind::EvaluationCommitment => "trnm_evaluation_commitment_v1",
        ResearchObjectKind::WorkloadReceipt => "trnm_workload_receipt_v1",
        ResearchObjectKind::ResearchClaim => "trnm_research_claim_v1",
        ResearchObjectKind::LicenseDeclaration => "trnm_license_declaration_v1",
        ResearchObjectKind::ClaimChallenge => "trnm_claim_challenge_v1",
        ResearchObjectKind::ClaimResolution => "trnm_claim_resolution_v1",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
// Preserve the development-only JSON response shape without adding wire-level indirection.
#[allow(clippy::large_enum_variant)]
pub enum SubmitOutcome {
    Accepted {
        command_id: String,
        transaction_hash_hex: String,
    },
    Pending {
        command_id: String,
        transaction_hash_hex: String,
    },
    Rejected {
        command_id: String,
        transaction_hash_hex: String,
        reason: Option<String>,
    },
    Finalized {
        receipt: FinalityReceiptV1,
    },
}

pub struct LiveChain {
    config: LiveChainConfig,
    genesis_hash_hex: String,
    store: DurableStore,
    interpreter: Arc<dyn CommandInterpreter>,
}

impl LiveChain {
    pub fn open(config: LiveChainConfig) -> Result<Self> {
        let interpreter = Arc::new(RoutingCommandInterpreter::from_config(&config)?);
        Self::open_with_interpreter(config, interpreter)
    }

    pub fn open_with_interpreter(
        config: LiveChainConfig,
        interpreter: Arc<dyn CommandInterpreter>,
    ) -> Result<Self> {
        config.validate()?;
        let genesis_hash_hex = config.genesis_hash_hex()?;
        let store = DurableStore::open(&config.database_path)?;
        let signer_policy_hash = hex::encode(hash_domain(
            "trnm.authorized.signers.v1",
            &[&serde_json::to_vec(&config.authorized_signers)?],
        ));
        store.bind_chain_metadata(&BTreeMap::from([
            ("chain_id".to_string(), config.chain_id.clone()),
            ("genesis_hash_hex".to_string(), genesis_hash_hex.clone()),
            (
                "validator_set_id".to_string(),
                config.validator_set.validator_set_id.clone(),
            ),
            ("signer_policy_hash".to_string(), signer_policy_hash),
        ]))?;
        Ok(Self {
            config,
            genesis_hash_hex,
            store,
            interpreter,
        })
    }

    pub fn config(&self) -> &LiveChainConfig {
        &self.config
    }

    pub fn genesis_hash_hex(&self) -> &str {
        &self.genesis_hash_hex
    }

    pub fn submit(
        &self,
        envelope: &SignedCommandEnvelopeV1,
        now_unix_ms: u64,
    ) -> Result<SubmitOutcome> {
        envelope.validate_at(&self.config.chain_id, now_unix_ms)?;
        let authorized = self
            .config
            .authorized_signer(&envelope.signer_id)
            .ok_or_else(|| anyhow!("signer_id is not authorized by genesis policy"))?;
        ensure!(
            authorized.signer_role == envelope.signer_role,
            "signer_role does not match genesis policy"
        );
        ensure!(
            authorized.public_key_hex == envelope.public_key_hex,
            "signer public key does not match genesis policy"
        );
        let transaction_hash_hex = hex::encode(envelope.tx_hash()?);
        match self.store.insert_command(envelope)? {
            InsertCommandOutcome::Inserted => Ok(SubmitOutcome::Accepted {
                command_id: envelope.command_id.clone(),
                transaction_hash_hex,
            }),
            InsertCommandOutcome::ExistingPending => Ok(SubmitOutcome::Pending {
                command_id: envelope.command_id.clone(),
                transaction_hash_hex,
            }),
            InsertCommandOutcome::ExistingRejected(reason) => Ok(SubmitOutcome::Rejected {
                command_id: envelope.command_id.clone(),
                transaction_hash_hex,
                reason,
            }),
            InsertCommandOutcome::ExistingFinalized(receipt) => {
                Ok(SubmitOutcome::Finalized { receipt })
            }
            InsertCommandOutcome::AlteredReplay => {
                Err(anyhow!("command_id altered-payload replay rejected"))
            }
            InsertCommandOutcome::NonceConflict => {
                Err(anyhow!("signer nonce is already bound to another command"))
            }
        }
    }

    pub fn finalize_pending(&self) -> Result<Vec<FinalityReceiptV1>> {
        let queued = self
            .store
            .queued_commands(self.config.max_transactions_per_block)?;
        if queued.is_empty() {
            return Ok(Vec::new());
        }
        let tip = self.store.tip(&self.genesis_hash_hex)?;
        let mut projected_objects = self.store.objects()?;
        let mut selected = Vec::<(QueuedCommand, CommandExecution)>::new();
        let mut touched = BTreeSet::new();
        for queued_command in queued {
            let execution = match self
                .interpreter
                .prepare_execution(&queued_command.envelope, &projected_objects)
                .and_then(|execution| {
                    execution.validate()?;
                    Ok(execution)
                }) {
                Ok(execution) => execution,
                Err(error) => {
                    self.store.set_command_status(
                        &queued_command.envelope.command_id,
                        CommandStatus::Rejected,
                        Some(&format!("{error:#}")),
                    )?;
                    continue;
                }
            };
            if execution.mutations.iter().any(|mutation| {
                mutation.object_key_hex != research_snapshot_key()
                    && touched.contains(&mutation.object_key_hex)
            }) {
                self.store.set_command_status(
                    &queued_command.envelope.command_id,
                    CommandStatus::Deferred,
                    Some("conflicts with an earlier command selected for this block"),
                )?;
                continue;
            }
            for mutation in &execution.mutations {
                let current_version = projected_objects
                    .get(&mutation.object_key_hex)
                    .map(|object| object.version);
                ensure!(
                    current_version == mutation.expected_version,
                    "interpreter object version precondition does not match projected state"
                );
                if mutation.object_key_hex != research_snapshot_key() {
                    touched.insert(mutation.object_key_hex.clone());
                }
                let stored = mutation.clone().into_stored();
                projected_objects.insert(stored.object_key_hex.clone(), stored);
            }
            selected.push((queued_command, execution));
        }
        if selected.is_empty() {
            return Ok(Vec::new());
        }

        let transaction_leaves = selected
            .iter()
            .map(|(pending, _)| {
                hash_domain(
                    "trnm.transaction.leaf.v1",
                    &[pending.transaction_hash_hex.as_bytes()],
                )
            })
            .collect::<Vec<_>>();
        let (transaction_root, transaction_proofs) =
            root_and_proofs("trnm.transactions.v1", &transaction_leaves);

        let object_values = projected_objects.values().cloned().collect::<Vec<_>>();
        let object_leaves = object_values
            .iter()
            .map(StoredObject::leaf_hash)
            .collect::<Vec<_>>();
        let (state_root, object_proofs) = root_and_proofs("trnm.state.objects.v1", &object_leaves);
        let object_proof_by_key = object_values
            .iter()
            .zip(object_proofs)
            .map(|(object, proof)| (object.object_key_hex.clone(), proof))
            .collect::<BTreeMap<_, _>>();

        let timestamp_unix_ms = selected
            .iter()
            .map(|(pending, _)| pending.envelope.issued_at_unix_ms)
            .max()
            .unwrap_or(0)
            .max(tip.timestamp_unix_ms.saturating_add(1));
        let header = BlockHeaderV1 {
            schema: BLOCK_HEADER_SCHEMA_V1.to_string(),
            chain_id: self.config.chain_id.clone(),
            height: tip.height.saturating_add(1),
            previous_block_hash_hex: tip.block_hash_hex.clone(),
            transaction_root_hex: hex::encode(transaction_root),
            state_root_hex: hex::encode(state_root),
            validator_set_id: self.config.validator_set.validator_set_id.clone(),
            timestamp_unix_ms,
        };
        let block_hash_hex = hex::encode(header.block_hash()?);
        let quorum_certificate = self.collect_quorum(&header, &selected)?;
        quorum_certificate.verify(&self.config.chain_id, &self.config.validator_set)?;

        let mut finalized = Vec::with_capacity(selected.len());
        for (index, ((pending, execution), transaction_proof)) in
            selected.into_iter().zip(transaction_proofs).enumerate()
        {
            let stored = projected_objects
                .get(&execution.primary_object_key_hex)
                .ok_or_else(|| anyhow!("prepared object missing from projected state"))?;
            let object_ref = ObjectRefV1 {
                object_key_hex: stored.object_key_hex.clone(),
                object_type: stored.object_type.clone(),
                version: stored.version,
                value_hash_hex: stored.value_hash_hex.clone(),
            };
            let object_proof = object_proof_by_key
                .get(&stored.object_key_hex)
                .cloned()
                .ok_or_else(|| anyhow!("prepared object proof missing"))?;
            let mut receipt = FinalityReceiptV1 {
                schema: FINALITY_RECEIPT_SCHEMA_V1.to_string(),
                chain_id: self.config.chain_id.clone(),
                command_id: pending.envelope.command_id.clone(),
                domain_command_fingerprint_hex: execution.domain_command_fingerprint_hex,
                transaction_hash_hex: pending.transaction_hash_hex.clone(),
                transaction_index: index as u64,
                block_height: header.height,
                block_hash_hex: block_hash_hex.clone(),
                block_header: header.clone(),
                state_root_hex: header.state_root_hex.clone(),
                transaction_root_hex: header.transaction_root_hex.clone(),
                object_ref: Some(object_ref),
                transaction_inclusion_proof: transaction_proof,
                object_inclusion_proof: Some(object_proof),
                validator_set_id: header.validator_set_id.clone(),
                quorum_certificate: quorum_certificate.clone(),
                receipt_hash_hex: String::new(),
            };
            receipt.receipt_hash_hex = hex::encode(receipt.compute_receipt_hash()?);
            verify_finality_receipt(&receipt, &self.config.validator_set)?;
            finalized.push(FinalizedCommand {
                command_id: pending.envelope.command_id,
                transaction_hash_hex: pending.transaction_hash_hex,
                transaction_index: index as u64,
                mutations: execution.mutations,
                receipt,
            });
        }
        self.store
            .commit_finalized_block(&tip, &header, &quorum_certificate, &finalized)?;
        Ok(finalized
            .into_iter()
            .map(|finalized| finalized.receipt)
            .collect())
    }

    fn collect_quorum(
        &self,
        header: &BlockHeaderV1,
        selected: &[(QueuedCommand, CommandExecution)],
    ) -> Result<QuorumCertificateV1> {
        let block_hash_hex = hex::encode(header.block_hash()?);
        let request = ValidatorVoteRequestV1 {
            schema: "trnm_validator_vote_request_v1".to_string(),
            header: header.clone(),
            commands: selected
                .iter()
                .map(|(queued, _)| queued.envelope.clone())
                .collect(),
        };
        let timeout = Duration::from_millis(self.config.validator_request_timeout_ms);
        let (sender, receiver) = mpsc::channel();
        for validator in self.config.validator_set.validators.clone() {
            let sender = sender.clone();
            let request = request.clone();
            thread::spawn(move || {
                let response = post_json::<_, ValidatorVoteV1>(
                    &validator.vote_endpoint,
                    &request,
                    timeout,
                    64 * 1024,
                );
                let _ = sender.send((validator, response));
            });
        }
        drop(sender);
        let mut signatures = Vec::new();
        let mut collected_power = 0u64;
        let mut failures = Vec::new();
        let deadline = std::time::Instant::now() + timeout;
        while collected_power < self.config.validator_set.quorum_power {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (validator, response) = match receiver.recv_timeout(remaining) {
                Ok(value) => value,
                Err(_) => break,
            };
            match response {
                Ok(response) if response.status == 200 => {
                    if let Err(error) = response
                        .value
                        .verify(&self.config.chain_id, &self.config.validator_set)
                    {
                        failures.push(format!("{}: invalid vote: {error}", validator.validator_id));
                        continue;
                    }
                    if response.value.block_hash_hex != block_hash_hex {
                        failures.push(format!("{}: wrong block hash", validator.validator_id));
                        continue;
                    }
                    collected_power = collected_power.saturating_add(validator.voting_power);
                    signatures.push(response.value);
                }
                Ok(response) => failures.push(format!(
                    "{}: HTTP {}",
                    validator.validator_id, response.status
                )),
                Err(error) => failures.push(format!("{}: {error}", validator.validator_id)),
            }
        }
        signatures.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        ensure!(
            collected_power >= self.config.validator_set.quorum_power,
            "validator quorum unavailable: collected power {collected_power}, required {}; failures={}",
            self.config.validator_set.quorum_power,
            failures.join("; ")
        );
        Ok(QuorumCertificateV1 {
            validator_set_id: self.config.validator_set.validator_set_id.clone(),
            height: header.height,
            block_hash_hex,
            signatures,
        })
    }

    pub fn receipt(&self, command_id: &str) -> Result<Option<FinalityReceiptV1>> {
        self.store.receipt(command_id)
    }

    pub fn serve(self: Arc<Self>) -> Result<()> {
        let producer = Arc::clone(&self);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(producer.config.block_interval_ms));
            match producer.finalize_pending() {
                Ok(receipts) if !receipts.is_empty() => {
                    println!(
                        "[chain] finalized height={} transactions={}",
                        receipts[0].block_height,
                        receipts.len()
                    );
                }
                Ok(_) => {}
                Err(error) => eprintln!("[chain] finalization deferred: {error:#}"),
            }
        });

        let listener = TcpListener::bind(self.config.listen_addr)
            .with_context(|| format!("bind live chain node {}", self.config.listen_addr))?;
        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    let chain = Arc::clone(&self);
                    thread::spawn(move || {
                        if let Err(error) = chain.handle_connection(stream) {
                            eprintln!("[chain] request rejected: {error:#}");
                        }
                    });
                }
                Err(error) => eprintln!("[chain] accept failed: {error}"),
            }
        }
        Ok(())
    }

    pub fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        let request = match read_request(&mut stream, 2 * 1024 * 1024) {
            Ok(request) => request,
            Err(error) => {
                write_json(
                    &mut stream,
                    400,
                    &serde_json::json!({"error":"malformed_request"}),
                )?;
                return Err(error);
            }
        };
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/health") => {
                let tip = self.store.tip(&self.genesis_hash_hex)?;
                write_json(
                    &mut stream,
                    200,
                    &serde_json::json!({
                        "status": "ok",
                        "scope": self.config.scope,
                        "development_only": self.config.development_only,
                        "chain_id": self.config.chain_id,
                        "height": tip.height,
                        "block_hash_hex": tip.block_hash_hex,
                        "validator_set_id": self.config.validator_set.validator_set_id
                    }),
                )
            }
            ("GET", "/metrics") => {
                let tip = self.store.tip(&self.genesis_hash_hex)?;
                let metrics = self.store.metrics()?;
                let body = format!(
                    concat!(
                        "# TYPE trnm_chain_height gauge\n",
                        "trnm_chain_height {}\n",
                        "# TYPE trnm_chain_commands gauge\n",
                        "trnm_chain_commands{{status=\"accepted\"}} {}\n",
                        "trnm_chain_commands{{status=\"deferred\"}} {}\n",
                        "trnm_chain_commands{{status=\"rejected\"}} {}\n",
                        "trnm_chain_commands{{status=\"finalized\"}} {}\n",
                        "# TYPE trnm_chain_objects gauge\n",
                        "trnm_chain_objects {}\n"
                    ),
                    tip.height,
                    metrics.accepted_commands,
                    metrics.deferred_commands,
                    metrics.rejected_commands,
                    metrics.finalized_commands,
                    metrics.objects,
                );
                write_response(
                    &mut stream,
                    200,
                    "text/plain; version=0.0.4; charset=utf-8",
                    body.as_bytes(),
                )
            }
            ("GET", "/v1/validator-set") => {
                write_json(&mut stream, 200, &self.config.validator_set)
            }
            ("GET", path) if path.starts_with("/v1/finality/") => {
                let command_id = &path["/v1/finality/".len()..];
                ensure!(
                    !command_id.is_empty()
                        && command_id.len() <= 160
                        && !command_id.contains(['/', '?', '#', '\0']),
                    "invalid command_id path"
                );
                match self.receipt(command_id)? {
                    Some(receipt) => write_json(&mut stream, 200, &receipt),
                    None => write_json(
                        &mut stream,
                        404,
                        &serde_json::json!({"error":"receipt_not_found"}),
                    ),
                }
            }
            ("POST", "/v1/transactions") => {
                let envelope: SignedCommandEnvelopeV1 = match serde_json::from_slice(&request.body)
                {
                    Ok(value) => value,
                    Err(error) => {
                        write_json(
                            &mut stream,
                            400,
                            &serde_json::json!({"error":"invalid_json"}),
                        )?;
                        return Err(error.into());
                    }
                };
                match self.submit(&envelope, now_unix_ms()?) {
                    Ok(outcome @ SubmitOutcome::Rejected { .. }) => {
                        write_json(&mut stream, 409, &outcome)
                    }
                    Ok(outcome) => write_json(&mut stream, 202, &outcome),
                    Err(error) => {
                        write_json(
                            &mut stream,
                            409,
                            &serde_json::json!({"error":"transaction_rejected"}),
                        )?;
                        Err(error)
                    }
                }
            }
            ("POST", "/v1/admin/finalize") => match self.finalize_pending() {
                Ok(receipts) => write_json(&mut stream, 200, &receipts),
                Err(error) => {
                    write_json(
                        &mut stream,
                        503,
                        &serde_json::json!({"error":"finalization_unavailable"}),
                    )?;
                    Err(error)
                }
            },
            _ => write_json(&mut stream, 404, &serde_json::json!({"error":"not_found"})),
        }
    }
}

pub use trnm_finality_verifier::verify_finality_receipt;

pub fn load_live_chain_config(path: &Path) -> Result<LiveChainConfig> {
    let raw =
        fs::read(path).with_context(|| format!("read live chain config {}", path.display()))?;
    let config = serde_json::from_slice(&raw)
        .with_context(|| format!("parse live chain config {}", path.display()))?;
    Ok(config)
}

pub fn now_unix_ms() -> Result<u64> {
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
        crypto::public_key_hex,
        validator::{ValidatorConfig, ValidatorService},
    };
    use ed25519_dalek::SigningKey;
    use std::{os::unix::fs::PermissionsExt, sync::Arc};

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "trnm-live-chain-{}-{}-{}",
            label,
            std::process::id(),
            now_unix_ms().unwrap()
        ))
    }

    fn spawn_validator(
        root: &Path,
        index: u8,
        genesis_hash_hex: &str,
        authorized_signers: Vec<AuthorizedSignerV1>,
    ) -> (ValidatorSetEntry, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let key = SigningKey::from_bytes(&[index; 32]);
        let key_path = root.join(format!("validator-{index}.key"));
        fs::write(&key_path, format!("{}\n", hex::encode(key.to_bytes()))).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let service = Arc::new(
            ValidatorService::open(ValidatorConfig {
                chain_id: "trnm-devnet-test".to_string(),
                validator_id: format!("validator-{index}"),
                validator_set_id: "validators-v1".to_string(),
                listen_addr: address,
                private_key_path: key_path,
                database_path: root.join(format!("validator-{index}.sqlite")),
                genesis_block_hash_hex: genesis_hash_hex.to_string(),
                authorized_signers,
                max_transactions_per_block: 128,
            })
            .unwrap(),
        );
        let service_thread = Arc::clone(&service);
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            service_thread.handle_connection(stream).unwrap();
        });
        (
            ValidatorSetEntry {
                validator_id: format!("validator-{index}"),
                public_key_hex: public_key_hex(&key),
                vote_endpoint: format!("http://{address}/v1/vote"),
            },
            handle,
        )
    }

    struct ValidatorSetEntry {
        validator_id: String,
        public_key_hex: String,
        vote_endpoint: String,
    }

    fn config_and_handles(
        root: &Path,
        signer_key: &SigningKey,
    ) -> (LiveChainConfig, Vec<thread::JoinHandle<()>>) {
        let placeholder_set = ValidatorSetV1 {
            validator_set_id: "validators-v1".to_string(),
            validators: (1..=4)
                .map(|index| super::super::protocol::ValidatorDescriptorV1 {
                    validator_id: format!("validator-{index}"),
                    public_key_hex: public_key_hex(&SigningKey::from_bytes(&[index; 32])),
                    vote_endpoint: format!("http://127.0.0.1:{}/v1/vote", 30_000 + index as u16),
                    voting_power: 1,
                })
                .collect(),
            quorum_power: 3,
        };
        let placeholder_config = LiveChainConfig {
            schema: "trnm_chain_node_config_v1".to_string(),
            scope: "loopback-local-devnet".to_string(),
            development_only: true,
            chain_id: "trnm-devnet-test".to_string(),
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            database_path: root.join("chain.sqlite"),
            block_interval_ms: 1_000,
            max_transactions_per_block: 10,
            validator_request_timeout_ms: 2_000,
            validator_set: placeholder_set,
            authorized_signers: vec![
                AuthorizedSignerV1 {
                    signer_id: "did:key:hepta-test".to_string(),
                    signer_role: "hepta".to_string(),
                    public_key_hex: public_key_hex(signer_key),
                },
                AuthorizedSignerV1 {
                    signer_id: "did:trnm:nakama-test".to_string(),
                    signer_role: "nakama".to_string(),
                    public_key_hex: public_key_hex(&SigningKey::from_bytes(&[43u8; 32])),
                },
            ],
        };
        let genesis = placeholder_config.genesis_hash_hex().unwrap();
        let mut entries = Vec::new();
        let mut handles = Vec::new();
        for index in 1..=4 {
            let (entry, handle) = spawn_validator(
                root,
                index,
                &genesis,
                placeholder_config.authorized_signers.clone(),
            );
            entries.push(entry);
            handles.push(handle);
        }
        let mut config = placeholder_config;
        for (descriptor, entry) in config.validator_set.validators.iter_mut().zip(entries) {
            descriptor.validator_id = entry.validator_id;
            descriptor.public_key_hex = entry.public_key_hex;
            descriptor.vote_endpoint = entry.vote_endpoint;
        }
        // Endpoint addresses are operational routing, not consensus identity.
        // Recompute validator services' configured genesis from identity-only config.
        (config, handles)
    }

    #[test]
    fn live_chain_finalizes_network_signed_receipt_and_survives_restart() {
        let root = temp_root("finality");
        fs::create_dir_all(&root).unwrap();
        let signer_key = SigningKey::from_bytes(&[42u8; 32]);
        let (config, handles) = config_and_handles(&root, &signer_key);
        let chain = LiveChain::open(config.clone()).unwrap();
        let envelope = SignedCommandEnvelopeV1::sign(
            "trnm-devnet-test",
            "command-1",
            "did:key:hepta-test",
            "hepta",
            1,
            now_unix_ms().unwrap() - 10,
            now_unix_ms().unwrap() + 60_000,
            "evaluation_commitment_v1",
            b"canonical-payload",
            &signer_key,
        )
        .unwrap();
        assert!(matches!(
            chain.submit(&envelope, now_unix_ms().unwrap()).unwrap(),
            SubmitOutcome::Accepted { .. }
        ));
        let receipts = chain.finalize_pending().unwrap();
        assert_eq!(receipts.len(), 1);
        verify_finality_receipt(&receipts[0], &config.validator_set).unwrap();
        for handle in handles {
            handle.join().unwrap();
        }
        drop(chain);

        let restarted = LiveChain::open(config).unwrap();
        let receipt = restarted.receipt("command-1").unwrap().unwrap();
        assert_eq!(receipt.receipt_hash_hex, receipts[0].receipt_hash_hex);
        assert!(matches!(
            restarted.submit(&envelope, now_unix_ms().unwrap()).unwrap(),
            SubmitOutcome::Finalized { .. }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[derive(Debug, Default)]
    struct PoisonRejectingInterpreter {
        opaque: OpaqueCommitmentInterpreter,
    }

    impl CommandInterpreter for PoisonRejectingInterpreter {
        fn prepare_execution(
            &self,
            envelope: &SignedCommandEnvelopeV1,
            objects: &dyn ObjectView,
        ) -> Result<CommandExecution> {
            ensure!(
                envelope.payload_bytes()? != b"poison",
                "permanently invalid payload"
            );
            self.opaque.prepare_execution(envelope, objects)
        }
    }

    #[test]
    fn rejected_command_does_not_poison_later_finalization() {
        let root = temp_root("pending-poison");
        fs::create_dir_all(&root).unwrap();
        let signer_key = SigningKey::from_bytes(&[42u8; 32]);
        let (config, handles) = config_and_handles(&root, &signer_key);
        let chain = LiveChain::open_with_interpreter(
            config.clone(),
            Arc::new(PoisonRejectingInterpreter::default()),
        )
        .unwrap();
        let now = now_unix_ms().unwrap();
        let poison = SignedCommandEnvelopeV1::sign(
            config.chain_id.clone(),
            "command-poison",
            "did:key:hepta-test",
            "hepta",
            1,
            now - 10,
            now + 60_000,
            "evaluation_commitment_v1",
            b"poison",
            &signer_key,
        )
        .unwrap();
        let valid = SignedCommandEnvelopeV1::sign(
            config.chain_id.clone(),
            "command-valid",
            "did:key:hepta-test",
            "hepta",
            2,
            now - 10,
            now + 60_000,
            "evaluation_commitment_v1",
            b"valid",
            &signer_key,
        )
        .unwrap();

        assert!(matches!(
            chain.submit(&poison, now).unwrap(),
            SubmitOutcome::Accepted { .. }
        ));
        assert!(matches!(
            chain.submit(&valid, now).unwrap(),
            SubmitOutcome::Accepted { .. }
        ));
        let receipts = chain.finalize_pending().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].command_id, "command-valid");
        assert!(matches!(
            chain.store.command_status("command-poison").unwrap(),
            Some((CommandStatus::Rejected, Some(_)))
        ));
        assert!(matches!(
            chain.submit(&poison, now).unwrap(),
            SubmitOutcome::Rejected { .. }
        ));
        for handle in handles {
            handle.join().unwrap();
        }
        drop(chain);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_chain_applies_protocol_native_research_state_and_receipts_exact_object() {
        use trnm_research_protocol::{
            AuthorityRole, CanonicalCbor, ExternalKey, MatchEvidenceCommitmentV1,
            ResearchCommandV1, SignedResearchCommandV1,
        };

        let root = temp_root("research-finality");
        fs::create_dir_all(&root).unwrap();
        let hepta_key = SigningKey::from_bytes(&[42u8; 32]);
        let nakama_key = SigningKey::from_bytes(&[43u8; 32]);
        let (config, handles) = config_and_handles(&root, &hepta_key);
        let chain = LiveChain::open(config.clone()).unwrap();
        let research_command = SignedResearchCommandV1::sign(
            config.chain_id.clone(),
            ExternalKey::from_bytes([0x10; 32]),
            "did:trnm:nakama-test".to_string(),
            AuthorityRole::NakamaAuthority,
            1,
            ResearchCommandV1::MatchEvidenceCommitment(MatchEvidenceCommitmentV1 {
                commitment_id: ExternalKey::from_bytes([0x11; 32]),
                match_id: ExternalKey::from_bytes([0x12; 32]),
                challenge_id: ExternalKey::from_bytes([0x13; 32]),
                event_root: [0x21; 32],
                roster_root: [0x22; 32],
                ruleset_hash: [0x23; 32],
                dataset_hash: [0x24; 32],
                archive_hash: [0x25; 32],
                event_count: 3,
                completed_at_unix_s: 1_753_450_000,
            }),
            &nakama_key,
        )
        .unwrap();
        let envelope = SignedCommandEnvelopeV1::sign(
            config.chain_id.clone(),
            "research-command-1",
            "did:trnm:nakama-test",
            "nakama",
            1,
            now_unix_ms().unwrap() - 10,
            now_unix_ms().unwrap() + 60_000,
            RESEARCH_COMMAND_PAYLOAD_TYPE_V1,
            &research_command.canonical_bytes(),
            &nakama_key,
        )
        .unwrap();
        let second_research_command = SignedResearchCommandV1::sign(
            config.chain_id.clone(),
            ExternalKey::from_bytes([0x30; 32]),
            "did:trnm:nakama-test".to_string(),
            AuthorityRole::NakamaAuthority,
            2,
            ResearchCommandV1::MatchEvidenceCommitment(MatchEvidenceCommitmentV1 {
                commitment_id: ExternalKey::from_bytes([0x31; 32]),
                match_id: ExternalKey::from_bytes([0x32; 32]),
                challenge_id: ExternalKey::from_bytes([0x33; 32]),
                event_root: [0x41; 32],
                roster_root: [0x42; 32],
                ruleset_hash: [0x43; 32],
                dataset_hash: [0x44; 32],
                archive_hash: [0x45; 32],
                event_count: 4,
                completed_at_unix_s: 1_753_450_001,
            }),
            &nakama_key,
        )
        .unwrap();
        let second_envelope = SignedCommandEnvelopeV1::sign(
            config.chain_id.clone(),
            "research-command-2",
            "did:trnm:nakama-test",
            "nakama",
            2,
            now_unix_ms().unwrap() - 10,
            now_unix_ms().unwrap() + 60_000,
            RESEARCH_COMMAND_PAYLOAD_TYPE_V1,
            &second_research_command.canonical_bytes(),
            &nakama_key,
        )
        .unwrap();

        assert!(matches!(
            chain.submit(&envelope, now_unix_ms().unwrap()).unwrap(),
            SubmitOutcome::Accepted { .. }
        ));
        assert!(matches!(
            chain
                .submit(&second_envelope, now_unix_ms().unwrap())
                .unwrap(),
            SubmitOutcome::Accepted { .. }
        ));
        let receipts = chain.finalize_pending().unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].block_height, receipts[1].block_height);
        let receipt = &receipts[0];
        verify_finality_receipt(receipt, &config.validator_set).unwrap();
        let object_ref = receipt.object_ref.as_ref().unwrap();
        assert_eq!(object_ref.object_type, "trnm_match_evidence_v1");
        assert_eq!(object_ref.version, 1);
        assert!(receipt.object_inclusion_proof.is_some());
        for handle in handles {
            handle.join().unwrap();
        }
        drop(chain);

        let restarted = LiveChain::open(config).unwrap();
        assert_eq!(
            restarted
                .receipt("research-command-1")
                .unwrap()
                .unwrap()
                .receipt_hash_hex,
            receipt.receipt_hash_hex
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn receipt_verifier_rejects_tampered_state_root() {
        let mut receipt = FinalityReceiptV1 {
            schema: FINALITY_RECEIPT_SCHEMA_V1.to_string(),
            chain_id: "x".to_string(),
            command_id: "c".to_string(),
            domain_command_fingerprint_hex: None,
            transaction_hash_hex: hex::encode([0u8; 32]),
            transaction_index: 0,
            block_height: 1,
            block_hash_hex: hex::encode([0u8; 32]),
            block_header: BlockHeaderV1 {
                schema: BLOCK_HEADER_SCHEMA_V1.to_string(),
                chain_id: "x".to_string(),
                height: 1,
                previous_block_hash_hex: hex::encode([0u8; 32]),
                transaction_root_hex: hex::encode([0u8; 32]),
                state_root_hex: hex::encode([0u8; 32]),
                validator_set_id: "v".to_string(),
                timestamp_unix_ms: 1,
            },
            state_root_hex: hex::encode([0u8; 32]),
            transaction_root_hex: hex::encode([0u8; 32]),
            object_ref: None,
            transaction_inclusion_proof: super::super::protocol::MerkleProofV1 {
                tree_domain: "x".to_string(),
                leaf_hash_hex: hex::encode([0u8; 32]),
                leaf_index: 0,
                leaf_count: 1,
                steps: Vec::new(),
            },
            object_inclusion_proof: None,
            validator_set_id: "v".to_string(),
            quorum_certificate: QuorumCertificateV1 {
                validator_set_id: "v".to_string(),
                height: 1,
                block_hash_hex: hex::encode([0u8; 32]),
                signatures: Vec::new(),
            },
            receipt_hash_hex: String::new(),
        };
        receipt.state_root_hex = hex::encode([9u8; 32]);
        let empty_set = ValidatorSetV1 {
            validator_set_id: "v".to_string(),
            validators: Vec::new(),
            quorum_power: 0,
        };
        assert!(verify_finality_receipt(&receipt, &empty_set).is_err());
    }
}
