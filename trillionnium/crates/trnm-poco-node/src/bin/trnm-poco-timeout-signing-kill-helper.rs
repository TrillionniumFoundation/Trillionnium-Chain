#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

#[path = "../recovery_process_watermark.rs"]
mod recovery_process_watermark;

use std::{
    env, fs,
    io::{self, BufRead, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use ed25519_dalek::{Signer, SigningKey};
use recovery_process_watermark::RecoveryProcessFileWatermarkV0;
use trnm_consensus_core::{CoreConfig, OutboundMessage, SafetyStateRecordLimitsV0, SignIntent};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_signer_journal::{
    SignatureProducerErrorV0, SignatureProducerV0, SignatureRequestV0,
};
use trnm_consensus_types::{
    CanonicalSignIntentV0, CanonicalSignable, ChainId, ConsensusParametersV0, ConsensusPublicKey,
    Epoch, GenesisHash, GenesisQcV0, MessageKind, ProtocolVersion, QcRef, SignIntentFingerprintV0,
    SignatureBytes, SigningRoot, TimeoutVote, Validator, ValidatorId, ValidatorSet, View,
    VotingPower,
};
use trnm_poco_node::{
    PocoNodeHostActionV0, PocoNodeHostV0, PocoNodeSignedOutboundV0, PocoNodeStartConfigV0,
    PocoNodeTimeoutSigningProcessCheckpointPhaseV0,
};

const TEST_CHAIN: ChainId = ChainId::from_static("trnm-poco-node-g1f-process-test");
const GENESIS_TIMESTAMP_MS: u64 = 0;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_SAFETY_DATABASE_BYTES: usize = 192 * 1024 * 1024;
const MAXIMUM_SIGNER_INTENTS: u64 = 64;
const MAXIMUM_SIGNER_INTENT_BYTES: usize = 4096;
const MAXIMUM_SIGNER_DATABASE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperCommandV0 {
    Prepare,
    Recover,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpectedIntentV0 {
    fingerprint: SignIntentFingerprintV0,
    authorizing_safety_revision: u64,
    signing_root: SigningRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PersistedStageV0 {
    intent_count: u64,
    event_count: u64,
    watermark_sequence: u64,
}

impl PersistedStageV0 {
    fn exact_text_v0(self) -> String {
        format!(
            "{}:{}:{}",
            self.intent_count, self.event_count, self.watermark_sequence
        )
    }
}

struct StrictTimeoutFixtureV0 {
    local_signing_key: SigningKey,
    validator_set: ValidatorSet,
    core_config: CoreConfig,
    genesis_qc: GenesisQcV0,
}

impl StrictTimeoutFixtureV0 {
    fn new() -> Self {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let keys = (1_u8..=4)
            .map(|index| {
                (
                    ValidatorId::new([index; 32]),
                    SigningKey::from_bytes(&[index.saturating_add(40); 32]),
                )
            })
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .map(|(id, key)| {
                Validator::new(
                    *id,
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("positive process-test voting power"),
                )
                .expect("valid strict-Ed25519 process-test validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa6; 32]),
            TEST_CHAIN,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid strict-Ed25519 process-test validator set");
        let core_config = CoreConfig::new(
            keys[0].0,
            validator_set.clone(),
            parameters,
            GENESIS_TIMESTAMP_MS,
            32,
            64,
        )
        .expect("valid strict-Ed25519 process-test Core config");
        let genesis_qc = GenesisQcV0::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            &validator_set,
        )
        .expect("valid process-test genesis anchor");
        Self {
            local_signing_key: SigningKey::from_bytes(&[41; 32]),
            validator_set,
            core_config,
            genesis_qc,
        }
    }

    fn expected_intent_v0(&self) -> ExpectedIntentV0 {
        let high_qc = self.high_qc_v0();
        let intent = CanonicalSignIntentV0::timeout_vote(
            &self.validator_set,
            self.core_config.local_validator(),
            1,
            View::new(1),
            high_qc,
        )
        .expect("valid process-test timeout sign intent");
        ExpectedIntentV0 {
            fingerprint: intent.fingerprint(),
            authorizing_safety_revision: intent.authorizing_safety_revision(),
            signing_root: intent.signing_root(),
        }
    }

    fn expected_timeout_vote_v0(&self) -> TimeoutVote {
        let high_qc = self.high_qc_v0();
        let signing_root =
            TimeoutVote::signing_root_for_set(&self.validator_set, View::new(1), high_qc)
                .expect("valid independent timeout signing root");
        let signature = SignatureBytes::from_array(
            self.local_signing_key
                .sign(signing_root.as_bytes())
                .to_bytes(),
        );
        TimeoutVote::new(
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            View::new(1),
            self.validator_set.id(),
            high_qc,
            self.core_config.local_validator(),
            signature,
            &self.validator_set,
        )
        .expect("valid independently constructed timeout vote")
    }

    fn high_qc_v0(&self) -> QcRef {
        QcRef::new(
            self.genesis_qc.id(),
            self.genesis_qc.epoch(),
            self.genesis_qc.view(),
            self.genesis_qc.height(),
            self.genesis_qc.block_id(),
            self.genesis_qc.validator_set_hash(),
        )
    }
}

struct CheckpointingProducerV0 {
    signing_key: SigningKey,
    expected: ExpectedIntentV0,
    selected_phase: Option<PocoNodeTimeoutSigningProcessCheckpointPhaseV0>,
    calls: Arc<AtomicU64>,
}

impl SignatureProducerV0 for CheckpointingProducerV0 {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        if request.fingerprint() != self.expected.fingerprint
            || request.intent().authorizing_safety_revision()
                != self.expected.authorizing_safety_revision
            || request.signing_root() != self.expected.signing_root
        {
            return Err(SignatureProducerErrorV0::Rejected);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.maybe_hold_v0(
            PocoNodeTimeoutSigningProcessCheckpointPhaseV0::ProducerEnteredAfterIntentWatermark,
        );
        let signature = SignatureBytes::from_array(
            self.signing_key
                .sign(request.signing_root().as_bytes())
                .to_bytes(),
        );
        self.maybe_hold_v0(
            PocoNodeTimeoutSigningProcessCheckpointPhaseV0::ProducerGeneratedBeforeReturn,
        );
        Ok(signature)
    }
}

impl CheckpointingProducerV0 {
    fn maybe_hold_v0(&self, phase: PocoNodeTimeoutSigningProcessCheckpointPhaseV0) {
        if self.selected_phase == Some(phase) {
            announce_and_wait_v0(phase, self.expected);
        }
    }
}

struct CasePathsV0 {
    safety_database: PathBuf,
    signer_database: PathBuf,
    watermark_record: PathBuf,
}

fn main() {
    match run_v0() {
        Ok(Some(output)) => println!("{output}"),
        Ok(None) => {}
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}

fn run_v0() -> Result<Option<String>, String> {
    let mut arguments = env::args().skip(1);
    let command = parse_command_v0(
        &arguments
            .next()
            .ok_or_else(|| "missing helper command".to_owned())?,
    )?;
    let root = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| "missing helper root".to_owned())?,
    );
    let phase = parse_phase_v0(
        &arguments
            .next()
            .ok_or_else(|| "missing checkpoint phase".to_owned())?,
    )?;
    if arguments.next().is_some() {
        return Err("unexpected helper arguments".to_owned());
    }
    match command {
        HelperCommandV0::Prepare => {
            prepare_v0(&root, phase)?;
            Ok(None)
        }
        HelperCommandV0::Recover => recover_or_verify_v0(&root, phase, false).map(Some),
        HelperCommandV0::Verify => recover_or_verify_v0(&root, phase, true).map(Some),
    }
}

fn prepare_v0(
    root: &Path,
    selected_phase: PocoNodeTimeoutSigningProcessCheckpointPhaseV0,
) -> Result<(), String> {
    let paths = create_case_paths_v0(root)?;
    let fixture = StrictTimeoutFixtureV0::new();
    let expected = fixture.expected_intent_v0();
    let mut watermark = RecoveryProcessFileWatermarkV0::new(&paths.watermark_record)
        .map_err(|error| format!("initialize process watermark: {error:?}"))?;
    if watermark.path() != paths.watermark_record
        || watermark
            .current_v0()
            .map_err(|error| format!("read fresh process watermark: {error:?}"))?
            .is_some()
    {
        return Err("fresh process watermark path/state was not exact".to_owned());
    }
    let calls = Arc::new(AtomicU64::new(0));
    let producer = CheckpointingProducerV0 {
        signing_key: fixture.local_signing_key,
        expected,
        selected_phase: Some(selected_phase),
        calls,
    };
    let mut host = PocoNodeHostV0::initialize_new(
        node_start_config_v0(&paths, fixture.core_config)?,
        fixture.genesis_qc,
        watermark,
        producer,
    )
    .map_err(|error| format!("initialize official timeout host: {error}"))?;
    let timer = host
        .resume_v0()
        .map_err(|error| format!("resume fresh timeout host: {error}"))?;
    if !matches!(
        timer.as_slice(),
        [PocoNodeHostActionV0::ArmViewTimer { epoch, view }]
            if *epoch == Epoch::new(0) && *view == View::new(1)
    ) {
        return Err(format!("fresh timeout host did not arm (0,1): {timer:?}"));
    }
    let mut reached = false;
    let result = host.on_local_timeout_with_process_checkpoint_observer_v0(&mut |phase| {
        if phase == selected_phase {
            reached = true;
            announce_and_wait_v0(phase, expected);
        }
    });
    if reached {
        return Err("checkpoint observer returned after acknowledgement".to_owned());
    }
    match result {
        Ok(actions) => Err(format!(
            "official timeout host returned before target {}: {actions:?}",
            selected_phase.as_str()
        )),
        Err(error) => Err(format!(
            "official timeout host failed before target {}: {error}",
            selected_phase.as_str()
        )),
    }
}

fn recover_or_verify_v0(
    root: &Path,
    phase: PocoNodeTimeoutSigningProcessCheckpointPhaseV0,
    verify: bool,
) -> Result<String, String> {
    let paths = existing_case_paths_v0(root)?;
    let fixture = StrictTimeoutFixtureV0::new();
    let expected = fixture.expected_intent_v0();
    let expected_timeout_vote = fixture.expected_timeout_vote_v0();
    let calls = Arc::new(AtomicU64::new(0));
    let producer = CheckpointingProducerV0 {
        signing_key: fixture.local_signing_key,
        expected,
        selected_phase: None,
        calls: Arc::clone(&calls),
    };
    let mut watermark = RecoveryProcessFileWatermarkV0::new(&paths.watermark_record)
        .map_err(|error| format!("open process watermark: {error:?}"))?;
    if watermark.path() != paths.watermark_record
        || watermark
            .current_v0()
            .map_err(|error| format!("authenticate existing process watermark: {error:?}"))?
            .is_none()
    {
        return Err("existing process watermark path/state was not exact".to_owned());
    }
    let mut host = PocoNodeHostV0::open_existing(
        node_start_config_v0(&paths, fixture.core_config)?,
        watermark,
        producer,
    )
    .map_err(|error| format!("open official timeout host: {error}"))?;
    let expected_stage = if verify {
        PersistedStageV0 {
            intent_count: 1,
            event_count: 2,
            watermark_sequence: 2,
        }
    } else {
        expected_stage_for_phase_v0(phase)
    };
    let actual_stage = persisted_stage_v0(&mut host)?;
    if actual_stage != expected_stage {
        return Err(format!(
            "persisted stage mismatch for {}: expected={} actual={}",
            phase.as_str(),
            expected_stage.exact_text_v0(),
            actual_stage.exact_text_v0()
        ));
    }
    let actions = host
        .resume_v0()
        .map_err(|error| format!("resume official timeout host: {error}"))?;
    let [PocoNodeHostActionV0::Broadcast(outbound)] = actions.as_slice() else {
        return Err(format!(
            "resume did not return one exact broadcast: {actions:?}"
        ));
    };
    let identity = exact_outbound_identity_v0(
        outbound,
        &fixture.validator_set,
        expected,
        &expected_timeout_vote,
    )?;
    let producer_calls = calls.load(Ordering::SeqCst);
    let expected_calls = if verify
        || matches!(
            phase,
            PocoNodeTimeoutSigningProcessCheckpointPhaseV0::SignaturePersistedBeforeSignatureReady
                | PocoNodeTimeoutSigningProcessCheckpointPhaseV0::BroadcastProducedBeforeReturn
        ) {
        0
    } else {
        1
    };
    if producer_calls != expected_calls {
        return Err(format!(
            "producer call mismatch for {}: expected={expected_calls} actual={producer_calls}",
            phase.as_str()
        ));
    }
    Ok(format!(
        "{}_v0={};pre_stage={};producer_calls={producer_calls};{identity}",
        if verify { "verified" } else { "recovered" },
        phase.as_str(),
        actual_stage.exact_text_v0(),
    ))
}

fn persisted_stage_v0<W, P>(host: &mut PocoNodeHostV0<W, P>) -> Result<PersistedStageV0, String>
where
    W: trnm_consensus_signer_journal::ExternalMonotonicWatermarkV0,
    P: SignatureProducerV0,
{
    let safety = host
        .safety_head()
        .map_err(|error| format!("authenticate process-test Safety head: {error}"))?;
    if safety.revision() != 1 {
        return Err(format!(
            "process-test Safety revision is not one: {}",
            safety.revision()
        ));
    }
    let Some(SignIntent::TimeoutVote {
        authorizing_safety_revision,
        view,
        ..
    }) = safety.state().pending_sign()
    else {
        return Err("process-test Safety head lacks the exact timeout outbox".to_owned());
    };
    if *authorizing_safety_revision != 1 || *view != View::new(1) {
        return Err("process-test timeout outbox revision/view mismatch".to_owned());
    }
    let capacity = host
        .signer_journal_capacity()
        .map_err(|error| format!("read process-test signer capacity: {error}"))?;
    let expected_maximum = (capacity.intent_count() != 0).then_some(1);
    if capacity.maximum_safety_revision() != expected_maximum
        || capacity.maximum_timeout_view() != expected_maximum
        || capacity.maximum_vote_view().is_some()
    {
        return Err("process-test signer revision/view maxima were not exact".to_owned());
    }
    let watermark = host
        .signer_journal_head()
        .map_err(|error| format!("authenticate process-test signer head: {error}"))?;
    Ok(PersistedStageV0 {
        intent_count: capacity.intent_count(),
        event_count: capacity.event_count(),
        watermark_sequence: watermark.sequence(),
    })
}

fn exact_outbound_identity_v0(
    outbound: &PocoNodeSignedOutboundV0,
    validator_set: &ValidatorSet,
    expected: ExpectedIntentV0,
    expected_timeout_vote: &TimeoutVote,
) -> Result<String, String> {
    if outbound.intent_fingerprint() != expected.fingerprint
        || outbound.authorizing_safety_revision() != expected.authorizing_safety_revision
    {
        return Err("outbound signer authorization does not match the fixture".to_owned());
    }
    let OutboundMessage::TimeoutVote(timeout) = outbound.message() else {
        return Err("bounded timeout host returned a non-timeout message".to_owned());
    };
    if timeout != expected_timeout_vote {
        return Err("recovered timeout vote differs from the independent typed oracle".to_owned());
    }
    timeout
        .verify(validator_set, &StrictEd25519Verifier)
        .map_err(|error| format!("strictly verify recovered timeout vote: {error}"))?;
    if timeout.signing_root() != expected.signing_root {
        return Err("recovered timeout signing root changed".to_owned());
    }
    let context = timeout.context();
    if context.message_kind() != MessageKind::Timeout {
        return Err("recovered timeout message kind changed".to_owned());
    }
    let high_qc = timeout.high_qc();
    Ok(format!(
        concat!(
            "identity_v0=fingerprint:{};auth_revision:{};signing_root:{};",
            "schema:{};genesis:{};chain:{};protocol:{};epoch:{};view:{};kind:{};",
            "validator_set:{};high_qc_digest:{};high_qc_epoch:{};high_qc_view:{};",
            "high_qc_height:{};high_qc_block:{};high_qc_validator_set:{};author:{};signature:{}"
        ),
        hex_v0(outbound.intent_fingerprint().as_bytes()),
        outbound.authorizing_safety_revision(),
        hex_v0(timeout.signing_root().as_bytes()),
        context.schema_version(),
        hex_v0(context.genesis_hash().as_bytes()),
        hex_v0(context.chain_id().as_bytes()),
        context.protocol_version().get(),
        context.epoch().get(),
        context.view().get(),
        context.message_kind() as u8,
        hex_v0(timeout.validator_set_id().as_bytes()),
        hex_v0(high_qc.qc_digest().as_bytes()),
        high_qc.epoch().get(),
        high_qc.view().get(),
        high_qc.height().get(),
        hex_v0(high_qc.block_id().as_bytes()),
        hex_v0(high_qc.validator_set_id().as_bytes()),
        hex_v0(timeout.author().as_bytes()),
        hex_v0(timeout.signature().as_bytes()),
    ))
}

fn announce_and_wait_v0(
    phase: PocoNodeTimeoutSigningProcessCheckpointPhaseV0,
    expected: ExpectedIntentV0,
) -> ! {
    println!(
        "checkpoint_v0={};fingerprint={};auth_revision={};signing_root={}",
        phase.as_str(),
        hex_v0(expected.fingerprint.as_bytes()),
        expected.authorizing_safety_revision,
        hex_v0(expected.signing_root.as_bytes()),
    );
    io::stdout().flush().unwrap_or_else(|error| {
        eprintln!("flush checkpoint output failed: {error}");
        process::exit(70);
    });
    let mut acknowledgement = String::new();
    io::stdin()
        .lock()
        .read_line(&mut acknowledgement)
        .unwrap_or_else(|error| {
            eprintln!("read checkpoint acknowledgement failed: {error}");
            process::exit(71);
        });
    if acknowledgement != format!("ACK {}\n", phase.as_str()) {
        eprintln!("checkpoint acknowledgement was missing or inexact");
        process::exit(72);
    }
    eprintln!("checkpoint helper must be killed, not acknowledged");
    process::exit(73);
}

fn node_start_config_v0(
    paths: &CasePathsV0,
    core_config: CoreConfig,
) -> Result<PocoNodeStartConfigV0, String> {
    PocoNodeStartConfigV0::new(
        &paths.safety_database,
        &paths.signer_database,
        core_config,
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES, MAXIMUM_BLOB_BYTES)
            .map_err(|error| format!("construct process-test record limits: {error}"))?,
        MAXIMUM_SAFETY_DATABASE_BYTES,
        MAXIMUM_SIGNER_INTENTS,
        MAXIMUM_SIGNER_INTENT_BYTES,
        MAXIMUM_SIGNER_DATABASE_BYTES,
    )
    .map_err(|error| format!("construct process-test node config: {error}"))
}

fn create_case_paths_v0(root: &Path) -> Result<CasePathsV0, String> {
    if !root.is_absolute() || !root.is_dir() {
        return Err("process-test root must be an existing absolute directory".to_owned());
    }
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect process-test root: {error}"))?;
    if root_metadata.permissions().mode() & 0o777 != 0o700 {
        return Err("process-test root must have mode 0700".to_owned());
    }
    let safety = protected_namespace_v0(root, "safety")?;
    let signer = protected_namespace_v0(root, "signer")?;
    let watermark = protected_namespace_v0(root, "watermark")?;
    Ok(CasePathsV0 {
        safety_database: safety.join("safety.sqlite"),
        signer_database: signer.join("signer.sqlite"),
        watermark_record: watermark.join("signer-watermark.v0"),
    })
}

fn existing_case_paths_v0(root: &Path) -> Result<CasePathsV0, String> {
    let root = fs::canonicalize(root)
        .map_err(|error| format!("canonicalize process-test root: {error}"))?;
    let paths = CasePathsV0 {
        safety_database: root.join("safety/safety.sqlite"),
        signer_database: root.join("signer/signer.sqlite"),
        watermark_record: root.join("watermark/signer-watermark.v0"),
    };
    for path in [
        &paths.safety_database,
        &paths.signer_database,
        &paths.watermark_record,
    ] {
        if !path.is_file() {
            return Err(format!(
                "missing process-test durable file: {}",
                path.display()
            ));
        }
    }
    Ok(paths)
}

fn protected_namespace_v0(root: &Path, name: &str) -> Result<PathBuf, String> {
    let path = root.join(name);
    fs::create_dir(&path).map_err(|error| format!("create {name} namespace: {error}"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protect {name} namespace: {error}"))?;
    fs::canonicalize(&path).map_err(|error| format!("canonicalize {name} namespace: {error}"))
}

const fn expected_stage_for_phase_v0(
    phase: PocoNodeTimeoutSigningProcessCheckpointPhaseV0,
) -> PersistedStageV0 {
    match phase {
        PocoNodeTimeoutSigningProcessCheckpointPhaseV0::SafetyPersistedBeforeStorageAck
        | PocoNodeTimeoutSigningProcessCheckpointPhaseV0::SignatureRequestedBeforeJournal => {
            PersistedStageV0 {
                intent_count: 0,
                event_count: 0,
                watermark_sequence: 0,
            }
        }
        PocoNodeTimeoutSigningProcessCheckpointPhaseV0::ProducerEnteredAfterIntentWatermark
        | PocoNodeTimeoutSigningProcessCheckpointPhaseV0::ProducerGeneratedBeforeReturn => {
            PersistedStageV0 {
                intent_count: 1,
                event_count: 1,
                watermark_sequence: 1,
            }
        }
        PocoNodeTimeoutSigningProcessCheckpointPhaseV0::SignaturePersistedBeforeSignatureReady
        | PocoNodeTimeoutSigningProcessCheckpointPhaseV0::BroadcastProducedBeforeReturn => {
            PersistedStageV0 {
                intent_count: 1,
                event_count: 2,
                watermark_sequence: 2,
            }
        }
    }
}

fn parse_command_v0(value: &str) -> Result<HelperCommandV0, String> {
    match value {
        "prepare" => Ok(HelperCommandV0::Prepare),
        "recover" => Ok(HelperCommandV0::Recover),
        "verify" => Ok(HelperCommandV0::Verify),
        _ => Err(format!("unknown helper command: {value}")),
    }
}

fn parse_phase_v0(value: &str) -> Result<PocoNodeTimeoutSigningProcessCheckpointPhaseV0, String> {
    use PocoNodeTimeoutSigningProcessCheckpointPhaseV0 as Phase;
    match value {
        "safety_persisted_before_storage_ack" => Ok(Phase::SafetyPersistedBeforeStorageAck),
        "signature_requested_before_journal" => Ok(Phase::SignatureRequestedBeforeJournal),
        "producer_entered_after_intent_watermark" => Ok(Phase::ProducerEnteredAfterIntentWatermark),
        "producer_generated_before_return" => Ok(Phase::ProducerGeneratedBeforeReturn),
        "signature_persisted_before_signature_ready" => {
            Ok(Phase::SignaturePersistedBeforeSignatureReady)
        }
        "broadcast_produced_before_return" => Ok(Phase::BroadcastProducedBeforeReturn),
        _ => Err(format!("unknown checkpoint phase: {value}")),
    }
}

fn hex_v0(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
