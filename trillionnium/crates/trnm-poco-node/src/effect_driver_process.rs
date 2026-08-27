//! Candidate-only OS process wrapper for the Core effect driver.
//!
//! This module is intentionally compiled only by `g1-process-test-support`.
//! It is a small, black-boxable process boundary around the real
//! `CandidateEffectDriverV1`: one Core, one Core-owned SafetyRules authority,
//! a bounded stdin command queue, a file-backed transition/checkpoint fence,
//! and a fixture signer.  It is useful for proving ordering and fail-stop
//! behaviour across an actual process boundary; it is not a production node,
//! a network listener, or a recovery implementation.

#![cfg(feature = "g1-process-test-support")]
#![forbid(unsafe_code)]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use trnm_application_tx_builder_v0::validate_strict_json_structure_v0;
use trnm_consensus_core::{
    Core, CoreConfig, Effect, OutboundMessage, SafetyHalt, SafetyState, SafetyStatePersistenceV0,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_rules::{InertSafetyTransitionV1, SafetyRulesDurableTransitionStoreV1};
use trnm_consensus_types::{
    CanonicalSignIntentV0, CanonicalSignable, ChainId, ConsensusParametersV0, ConsensusPublicKey,
    Epoch, GenesisHash, GenesisQcV0, ProtocolVersion, SignatureBytes, Validator, ValidatorId,
    ValidatorSet, View, VotingPower,
};

use crate::effect_driver::{
    CandidateEffectDriverAdmissionV1, CandidateEffectDriverErrorV1, CandidateEffectDriverFactsV1,
    CandidateEffectDriverHooksV1, CandidateEffectDriverStatusV1, CandidateEffectDriverV1,
};

/// This process is a candidate fixture only.
pub const EFFECT_DRIVER_PROCESS_CANDIDATE_V1: bool = true;
/// The process never enables production consensus activation.
pub const EFFECT_DRIVER_PROCESS_PRODUCTION_ACTIVATION_V1: bool = false;
/// Bounded command frame size.  Oversized lines are rejected before parsing.
pub const EFFECT_DRIVER_PROCESS_MAX_FRAME_BYTES_V1: usize = 64 * 1024;
/// Queue capacity used by the process wrapper.
pub const EFFECT_DRIVER_PROCESS_QUEUE_CAPACITY_V1: usize = 8;

const CHAIN_ID_V1: &str = "trnm-effect-driver-process-v1";
const ROOT_MARKER_V1: &str = "effect-driver-process.marker";
const TRANSITION_WAL_V1: &str = "safety-transition.wal";
const SAFETY_STATE_V1: &str = "safety-state.record";
const CHECKPOINT_V1: &str = "whole-node.checkpoint";
const OUTBOUND_WAL_V1: &str = "outbound.wal";
const TIMER_WAL_V1: &str = "timer.wal";
const FAIL_CHECKPOINT_ENV_V1: &str = "TRNM_POCO_EFFECT_PROCESS_FAIL_CHECKPOINT";
const LOCAL_KEY_BYTES_V1: [u8; 32] = [41; 32];

#[derive(Debug)]
pub struct EffectDriverProcessErrorV1 {
    code: &'static str,
    detail: String,
}

impl EffectDriverProcessErrorV1 {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for EffectDriverProcessErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for EffectDriverProcessErrorV1 {}

impl From<io::Error> for EffectDriverProcessErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::new("io", format!("{error:?}"))
    }
}

/// Summary returned after a clean `shutdown`/EOF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectDriverProcessSummaryV1 {
    pub generation: u64,
    pub processed_ingress: u64,
    pub processed_effects: u64,
    pub broadcasts: u64,
    pub status: CandidateEffectDriverStatusV1,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum CommandV1 {
    #[serde(rename = "enqueue_timeout")]
    EnqueueTimeout { generation: u64 },
    #[serde(rename = "drive")]
    Drive,
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "shutdown")]
    Shutdown,
}

#[derive(Debug)]
struct FileTransitionStoreV1 {
    path: PathBuf,
    previous_successor: Option<[u8; 32]>,
    transitions: u64,
}

impl FileTransitionStoreV1 {
    fn open(root: &Path) -> Result<Self, EffectDriverProcessErrorV1> {
        Ok(Self {
            path: root.join(TRANSITION_WAL_V1),
            previous_successor: None,
            transitions: 0,
        })
    }
}

impl SafetyRulesDurableTransitionStoreV1 for FileTransitionStoreV1 {
    type Error = String;

    fn persist_transition_v1(
        &mut self,
        transition: &InertSafetyTransitionV1,
    ) -> Result<(), Self::Error> {
        let predecessor = *transition.predecessor_state_digest().as_bytes();
        if let Some(previous) = self.previous_successor {
            if predecessor != previous {
                return Err("transition predecessor does not match WAL successor".to_owned());
            }
        }
        let successor = *transition.successor_state().digest().as_bytes();
        let intent = transition.canonical_intent();
        let line = format!(
            "v=1\tindex={}\tkind={:?}\tpredecessor={}\tsuccessor={}\tcandidate={}\troot={}\tfingerprint={}\trevision={}\n",
            self.transitions,
            transition.kind(),
            hex::encode(predecessor),
            hex::encode(successor),
            hex::encode(transition.candidate_digest().as_bytes()),
            hex::encode(intent.signing_root().as_bytes()),
            hex::encode(intent.fingerprint().as_bytes()),
            intent.authorizing_safety_revision(),
        );
        append_durable(&self.path, line.as_bytes()).map_err(|error| format!("{error:?}"))?;
        self.previous_successor = Some(successor);
        self.transitions = self.transitions.saturating_add(1);
        Ok(())
    }
}

struct FileHooksV1 {
    root: PathBuf,
    persisted: Option<SafetyState>,
    persisted_record: Option<Vec<u8>>,
    broadcasts: u64,
    fail_checkpoint: bool,
}

impl FileHooksV1 {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            persisted: None,
            persisted_record: None,
            broadcasts: 0,
            fail_checkpoint: std::env::var_os(FAIL_CHECKPOINT_ENV_V1).is_some(),
        }
    }

    fn record_for_state(state: &SafetyState) -> Vec<u8> {
        // `Debug` is deliberately labelled as a fixture fingerprint rather
        // than a protocol encoding.  The typed state is retained in memory
        // and compared on readback; the file is only a durable crash marker.
        let debug = format!("{state:?}");
        let digest = Sha256::digest(debug.as_bytes());
        format!(
            "v=1\trevision={}\tepoch={}\tview={}\tfingerprint={}\n",
            state.revision(),
            state.epoch().get(),
            state.current_view().get(),
            hex::encode(digest),
        )
        .into_bytes()
    }

    fn checkpoint_record(core: &Core, intent: &CanonicalSignIntentV0) -> Vec<u8> {
        format!(
            "v=1\trevision={}\tepoch={}\tview={}\troot={}\tfingerprint={}\n",
            core.safety_state().revision(),
            core.safety_state().epoch().get(),
            core.safety_state().current_view().get(),
            hex::encode(intent.signing_root().as_bytes()),
            hex::encode(intent.fingerprint().as_bytes()),
        )
        .into_bytes()
    }

    fn read_checkpoint_revision(&self) -> Result<Option<u64>, String> {
        let path = self.root.join(CHECKPOINT_V1);
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("checkpoint read: {error:?}")),
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| "checkpoint is not UTF-8".to_owned())?;
        let field = text
            .split('\t')
            .find_map(|part| part.strip_prefix("revision="))
            .ok_or_else(|| "checkpoint revision field missing".to_owned())?;
        field
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| "checkpoint revision is not an integer".to_owned())
    }
}

impl CandidateEffectDriverHooksV1 for FileHooksV1 {
    type Error = String;

    fn persist_safety_state_v1(
        &mut self,
        request: &SafetyStatePersistenceV0,
    ) -> Result<(), Self::Error> {
        let record = Self::record_for_state(request.state());
        atomic_replace(&self.root.join(SAFETY_STATE_V1), &record)
            .map_err(|error| format!("safety state persist: {error:?}"))?;
        self.persisted = Some(request.state().clone());
        self.persisted_record = Some(record);
        Ok(())
    }

    fn confirm_safety_state_v1(&mut self, expected: &SafetyState) -> Result<(), Self::Error> {
        if self.persisted.as_ref() != Some(expected) {
            return Err("typed SafetyState readback mismatch".to_owned());
        }
        let expected_record = Self::record_for_state(expected);
        if self.persisted_record.as_deref() != Some(expected_record.as_slice()) {
            return Err("SafetyState record cache mismatch".to_owned());
        }
        let on_disk = fs::read(self.root.join(SAFETY_STATE_V1))
            .map_err(|error| format!("safety state readback: {error:?}"))?;
        if on_disk != expected_record {
            return Err("SafetyState durable readback mismatch".to_owned());
        }
        Ok(())
    }

    fn validate_payload_v1(
        &mut self,
        _effect: Effect,
        _core: &mut Core,
    ) -> Result<Vec<Effect>, Self::Error> {
        // The process command surface intentionally exposes timeout only.
        // Proposal validation remains an explicit unsupported boundary.
        Err("proposal validation is not enabled by this candidate process".to_owned())
    }

    fn compare_and_advance_whole_node_checkpoint_v1(
        &mut self,
        core: &Core,
        intent: &CanonicalSignIntentV0,
    ) -> Result<(), Self::Error> {
        if self.fail_checkpoint {
            return Err("injected whole-node checkpoint CAS failure".to_owned());
        }
        let revision = core.safety_state().revision();
        let previous = self.read_checkpoint_revision()?;
        let expected_previous = revision.checked_sub(1);
        let predecessor_matches = match (expected_previous, previous) {
            (Some(0), None) => true,
            (Some(expected), Some(found)) => expected == found,
            _ => false,
        };
        if !predecessor_matches {
            return Err(format!(
                "checkpoint CAS predecessor mismatch: expected {:?}, found {:?}",
                expected_previous, previous
            ));
        }
        atomic_replace(
            &self.root.join(CHECKPOINT_V1),
            &Self::checkpoint_record(core, intent),
        )
        .map_err(|error| format!("checkpoint CAS: {error:?}"))?;
        Ok(())
    }

    fn sign_v1(&mut self, intent: &CanonicalSignIntentV0) -> Result<SignatureBytes, Self::Error> {
        let revision = self.read_checkpoint_revision()?;
        if revision != Some(intent.authorizing_safety_revision()) {
            return Err("signer observed no matching checkpoint".to_owned());
        }
        let key = SigningKey::from_bytes(&LOCAL_KEY_BYTES_V1);
        Ok(SignatureBytes::from_array(
            key.sign(intent.signing_root().as_bytes()).to_bytes(),
        ))
    }

    fn broadcast_v1(&mut self, message: OutboundMessage) -> Result<(), Self::Error> {
        let (kind, root, signature) = match message {
            OutboundMessage::Vote(vote) => {
                ("vote", vote.signing_root(), *vote.signature().as_bytes())
            }
            OutboundMessage::TimeoutVote(vote) => (
                "timeout_vote",
                vote.signing_root(),
                *vote.signature().as_bytes(),
            ),
        };
        let line = format!(
            "v=1\tindex={}\tkind={}\troot={}\tsignature={}\n",
            self.broadcasts,
            kind,
            hex::encode(root.as_bytes()),
            hex::encode(signature),
        );
        append_durable(&self.root.join(OUTBOUND_WAL_V1), line.as_bytes())
            .map_err(|error| format!("broadcast WAL: {error:?}"))?;
        self.broadcasts = self.broadcasts.saturating_add(1);
        Ok(())
    }

    fn arm_view_timer_v1(&mut self, epoch: Epoch, view: View) -> Result<(), Self::Error> {
        let line = format!("v=1\tepoch={}\tview={}\n", epoch.get(), view.get());
        append_durable(&self.root.join(TIMER_WAL_V1), line.as_bytes())
            .map_err(|error| format!("timer WAL: {error:?}"))
    }

    fn safety_halted_v1(&mut self, halt: &SafetyHalt) -> Result<(), Self::Error> {
        let line = format!("v=1\tsafety_halt={halt:?}\n");
        append_durable(&self.root.join(ROOT_MARKER_V1), line.as_bytes())
            .map_err(|error| format!("halt marker: {error:?}"))
    }
}

fn append_durable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no UTF-8 name"))?;
    let temp = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut file = File::create(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    // Syncing the parent closes the rename durability window on Unix.  Some
    // non-Unix test filesystems reject opening a directory; the file itself
    // is still synchronously written in that case.
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn fresh_root(root: &Path) -> Result<(), EffectDriverProcessErrorV1> {
    if !root.is_absolute() {
        return Err(EffectDriverProcessErrorV1::new(
            "root",
            "candidate process requires an absolute run root",
        ));
    }
    if root == Path::new("/") || root.components().count() < 3 {
        return Err(EffectDriverProcessErrorV1::new(
            "root",
            "refusing a broad filesystem root",
        ));
    }
    fs::create_dir_all(root)?;
    for name in [
        ROOT_MARKER_V1,
        TRANSITION_WAL_V1,
        SAFETY_STATE_V1,
        CHECKPOINT_V1,
        OUTBOUND_WAL_V1,
        TIMER_WAL_V1,
    ] {
        let path = root.join(name);
        if path.is_file() && fs::metadata(&path)?.len() != 0 {
            return Err(EffectDriverProcessErrorV1::new(
                "recovery_required",
                format!(
                    "non-empty candidate state {} requires an explicit recovery owner",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn build_core_v1() -> Result<Core, EffectDriverProcessErrorV1> {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let validators = (1_u8..=4)
        .map(|index| {
            let key = SigningKey::from_bytes(&[index.saturating_add(40); 32]);
            Validator::new(
                ValidatorId::new([index; 32]),
                ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                VotingPower::new(1).expect("positive fixture voting power"),
            )
            .expect("strict fixture validator")
        })
        .collect();
    let validator_set = ValidatorSet::new(
        GenesisHash::new([0x91; 32]),
        ChainId::from_static(CHAIN_ID_V1),
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("core", format!("validator set: {error}")))?;
    let config = CoreConfig::new(
        ValidatorId::new([1; 32]),
        validator_set,
        parameters,
        17,
        32,
        64,
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("core", format!("config: {error}")))?;
    let genesis_qc = GenesisQcV0::new(
        config.validator_set().genesis_hash(),
        config.validator_set().chain_id(),
        config.validator_set(),
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("core", format!("genesis QC: {error}")))?;
    Core::new(config, genesis_qc, &StrictEd25519Verifier)
        .map_err(|error| EffectDriverProcessErrorV1::new("core", format!("construct: {error}")))
}

fn facts_json(facts: CandidateEffectDriverFactsV1, broadcasts: u64) -> Value {
    let status = match facts.status() {
        CandidateEffectDriverStatusV1::Active => "active",
        CandidateEffectDriverStatusV1::Halted => "halted",
        CandidateEffectDriverStatusV1::FailStopped => "fail_stopped",
    };
    json!({
        "status": status,
        "generation": facts.generation(),
        "queue_depth": facts.queue_depth(),
        "queue_capacity": facts.queue_capacity(),
        "processed_ingress": facts.processed_ingress(),
        "processed_effects": facts.processed_effects(),
        "stale_generation_rejections": facts.stale_generation_rejections(),
        "backpressure_rejections": facts.backpressure_rejections(),
        "broadcasts": broadcasts,
        "candidate_only": facts.candidate_only(),
        "production_activation": EFFECT_DRIVER_PROCESS_PRODUCTION_ACTIVATION_V1,
        "finality_verified": facts.finality_verified(),
    })
}

fn admission_json(admission: CandidateEffectDriverAdmissionV1) -> Value {
    match admission {
        CandidateEffectDriverAdmissionV1::Accepted {
            generation,
            queue_depth,
        } => json!({"admission":"accepted","generation":generation,"queue_depth":queue_depth}),
        CandidateEffectDriverAdmissionV1::StaleGeneration {
            expected_generation,
            received_generation,
        } => json!({
            "admission":"stale_generation",
            "expected_generation":expected_generation,
            "received_generation":received_generation,
        }),
        CandidateEffectDriverAdmissionV1::Backpressure {
            capacity,
            queue_depth,
        } => json!({
            "admission":"backpressure",
            "capacity":capacity,
            "queue_depth":queue_depth,
        }),
    }
}

fn driver_error_json(error: &CandidateEffectDriverErrorV1) -> Value {
    json!({"status":"fail_stopped","reason":error.to_string(),"candidate_only":true})
}

/// Run the candidate process over line-delimited JSON stdin/stdout.
pub fn run_stdio_v1<R: BufRead, W: Write>(
    root: PathBuf,
    mut reader: R,
    mut writer: W,
) -> Result<EffectDriverProcessSummaryV1, EffectDriverProcessErrorV1> {
    fresh_root(&root)?;
    atomic_replace(
        &root.join(ROOT_MARKER_V1),
        b"v=1\tprocess=candidate-effect-driver\tstate=fresh\n",
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("root", format!("start marker: {error:?}")))?;
    let core = build_core_v1()?;
    let store = FileTransitionStoreV1::open(&root)?;
    let authority = core
        .issue_safety_rules_authority_v1(store, &StrictEd25519Verifier)
        .map_err(|error| EffectDriverProcessErrorV1::new("authority", error.to_string()))?;
    let hooks = FileHooksV1::new(&root);
    let mut driver = CandidateEffectDriverV1::new(
        core,
        authority,
        hooks,
        EFFECT_DRIVER_PROCESS_QUEUE_CAPACITY_V1,
    )
    .map_err(|error| EffectDriverProcessErrorV1::new("driver", error.to_string()))?;

    let mut line = String::new();
    let mut shutdown = false;
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        if bytes > EFFECT_DRIVER_PROCESS_MAX_FRAME_BYTES_V1
            || (!line.ends_with('\n') && bytes == EFFECT_DRIVER_PROCESS_MAX_FRAME_BYTES_V1)
        {
            let response =
                json!({"status":"rejected","reason":"frame_too_large","candidate_only":true});
            serde_json::to_writer(&mut writer, &response)
                .map_err(|error| EffectDriverProcessErrorV1::new("json", format!("{error:?}")))?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            continue;
        }
        let raw = line.trim_end_matches(['\r', '\n']).as_bytes();
        if let Err(error) = validate_strict_json_structure_v0(raw) {
            let response = json!({"status":"rejected","reason":"malformed_json","detail":error.to_string(),"candidate_only":true});
            serde_json::to_writer(&mut writer, &response).map_err(|json_error| {
                EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
            })?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            continue;
        }
        let command = match serde_json::from_slice::<CommandV1>(raw) {
            Ok(command) => command,
            Err(error) => {
                let response = json!({"status":"rejected","reason":"unknown_command","detail":error.to_string(),"candidate_only":true});
                serde_json::to_writer(&mut writer, &response).map_err(|json_error| {
                    EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
                })?;
                writer.write_all(b"\n")?;
                writer.flush()?;
                continue;
            }
        };

        let response = match command {
            CommandV1::EnqueueTimeout { generation } => match driver.enqueue_timeout_v1(generation)
            {
                Ok(admission) => {
                    let mut value = admission_json(admission);
                    if let Value::Object(object) = &mut value {
                        object.insert("status".to_owned(), Value::String("accepted".to_owned()));
                    }
                    value
                }
                Err(error) => {
                    let value = driver_error_json(&error);
                    serde_json::to_writer(&mut writer, &value).map_err(|json_error| {
                        EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
                    })?;
                    writer.write_all(b"\n")?;
                    writer.flush()?;
                    return Err(EffectDriverProcessErrorV1::new("driver", error.to_string()));
                }
            },
            CommandV1::Drive => match driver.drive_v1() {
                Ok(facts) => facts_json(facts, broadcast_count(&root)),
                Err(error) => {
                    let value = driver_error_json(&error);
                    serde_json::to_writer(&mut writer, &value).map_err(|json_error| {
                        EffectDriverProcessErrorV1::new("json", format!("{json_error:?}"))
                    })?;
                    writer.write_all(b"\n")?;
                    writer.flush()?;
                    return Err(EffectDriverProcessErrorV1::new("driver", error.to_string()));
                }
            },
            CommandV1::Status => facts_json(driver.facts_v1(), broadcast_count(&root)),
            CommandV1::Shutdown => {
                shutdown = true;
                let mut value = facts_json(driver.facts_v1(), broadcast_count(&root));
                if let Value::Object(object) = &mut value {
                    object.insert("shutdown".to_owned(), Value::Bool(true));
                }
                value
            }
        };
        serde_json::to_writer(&mut writer, &response)
            .map_err(|error| EffectDriverProcessErrorV1::new("json", format!("{error:?}")))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        if shutdown {
            break;
        }
    }

    let facts = driver.facts_v1();
    Ok(EffectDriverProcessSummaryV1 {
        generation: facts.generation(),
        processed_ingress: facts.processed_ingress(),
        processed_effects: facts.processed_effects(),
        broadcasts: broadcast_count(&root),
        status: facts.status(),
    })
}

fn broadcast_count(root: &Path) -> u64 {
    fs::read_to_string(root.join(OUTBOUND_WAL_V1))
        .map(|value| value.lines().count() as u64)
        .unwrap_or(0)
}
