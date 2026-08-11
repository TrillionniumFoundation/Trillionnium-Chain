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
};

use ed25519_dalek::{Signer, SigningKey};
use recovery_process_watermark::RecoveryProcessFileWatermarkV0;
use trnm_consensus_app::{
    initialize_native_validation_recovery_test_fixture_v0,
    NativeValidationRecoveredInvalidReasonV0, NativeValidationRecoveryTestFixtureConfigV0,
    NativeValidationRecoveryTestFixtureStateV0,
};
use trnm_consensus_core::{
    leader_for, Core, CoreConfig, DurablePayloadValidationResultV1, Effect, Input, OutboundMessage,
    PayloadValidationResult, PayloadValidationRouteV0, SafetyStateRecordLimitsV0, SignId,
    ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{SafetyTransitionContextV0, SqliteSafetyStateStoreV0};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, SignerWatermarkV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader,
    BlockId, BlockKind, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
    ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, GenesisHash, GenesisQcV0, Height,
    ProposalWitnessV0, ProtocolVersion, QcReferenceV0, QuorumCertificate, SignatureBytes,
    SignedProposalV0, SigningRoot, StateRoot, ValidatedBlockCommitmentsV0, Validator, ValidatorId,
    ValidatorSet, View, Vote, VotingPower,
};
use trnm_poco_node::{
    PocoNodeStartConfigV0, PocoNodeValidationRecoveryConfigV0, PocoNodeValidationRecoveryHostV0,
    ValidationRecoveryBootstrapV0, ValidationRecoveryProcessCheckpointPhaseV0,
    ValidationRecoveryProcessCheckpointV0, ValidationRecoverySourceStateV0,
};

const TEST_CHAIN: ChainId = ChainId::from_static("trnm-poco-node-g1e-process-test");
const GENESIS_TIMESTAMP_MS: u64 = 0;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_SAFETY_DATABASE_BYTES: usize = 192 * 1024 * 1024;
const MAXIMUM_SIGNER_INTENTS: u64 = 64;
const MAXIMUM_SIGNER_INTENT_BYTES: usize = 4096;
const MAXIMUM_SIGNER_DATABASE_BYTES: usize = 32 * 1024 * 1024;
const SIGNER_POLICY_HASH: [u8; 32] = [0x77; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperCommandV0 {
    Prepare,
    Recover,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaseSpecV0 {
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
    phase: Option<ValidationRecoveryProcessCheckpointPhaseV0>,
}

impl CaseSpecV0 {
    fn case_id(self) -> String {
        format!(
            "{}/{}/{}",
            route_name_v0(self.route),
            reason_name_v0(self.reason),
            self.phase
                .map(ValidationRecoveryProcessCheckpointPhaseV0::as_str)
                .unwrap_or("completion_acked")
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaseIdentityV0 {
    validation_id: ValidationId,
    completion_revision: u64,
    signer_watermark: SignerWatermarkV0,
}

impl CaseIdentityV0 {
    fn exact_text_v0(self) -> String {
        format!(
            "identity_v0={}:{}:{};completion_revision={};watermark_v0={}:{}:{}:{}",
            hex_v0(self.validation_id.block_id().as_bytes()),
            self.validation_id.view().get(),
            self.validation_id.generation(),
            self.completion_revision,
            hex_v0(&self.signer_watermark.scope()),
            hex_v0(&self.signer_watermark.journal_id()),
            self.signer_watermark.sequence(),
            hex_v0(&self.signer_watermark.chain_checksum()),
        )
    }
}

struct StrictConsensusFixtureV0 {
    keys: Vec<(ValidatorId, SigningKey)>,
    parameters: ConsensusParametersV0,
    validator_set: ValidatorSet,
    core_config: CoreConfig,
}

impl StrictConsensusFixtureV0 {
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
            GenesisHash::new([0xa5; 32]),
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
        Self {
            keys,
            parameters,
            validator_set,
            core_config,
        }
    }

    fn key(&self, author: ValidatorId) -> &SigningKey {
        self.keys
            .iter()
            .find_map(|(id, key)| (*id == author).then_some(key))
            .expect("validator has a process-test signing key")
    }

    fn genesis_qc(&self) -> GenesisQcV0 {
        GenesisQcV0::new(
            self.validator_set.genesis_hash(),
            self.validator_set.chain_id(),
            &self.validator_set,
        )
        .expect("valid process-test genesis anchor")
    }

    fn sign(&self, author: ValidatorId, root: SigningRoot) -> SignatureBytes {
        SignatureBytes::from_array(self.key(author).sign(root.as_bytes()).to_bytes())
    }

    fn proposal(&self, justify: QcReferenceV0, view: u64, payload: &[u8]) -> SignedProposalV0 {
        let justify_ref = justify.qc_ref();
        let height = justify_ref
            .height()
            .get()
            .checked_add(1)
            .expect("process-test height does not overflow");
        let proposer = leader_for(&self.validator_set, View::new(view));
        let block = canonical_block_v0(
            &self.validator_set,
            view,
            height,
            justify_ref.block_id(),
            payload,
            proposer,
        );
        let root = ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
            .expect("valid process-test proposal signing preimage");
        let witness = ProposalWitnessV0::new(
            block.header(),
            justify,
            None,
            None,
            self.sign(proposer, root),
            &self.validator_set,
            None,
            &self.parameters,
            justify_ref.height().get().saturating_mul(100),
        )
        .expect("valid strict-Ed25519 process-test proposal witness");
        SignedProposalV0::new(
            block,
            witness,
            &self.validator_set,
            None,
            &self.parameters,
            justify_ref.height().get().saturating_mul(100),
        )
        .expect("valid strict-Ed25519 process-test proposal")
    }

    fn parent_qc(&self, parent: &SignedProposalV0) -> QuorumCertificate {
        let header = parent.block().header();
        let votes = self
            .keys
            .iter()
            .take(3)
            .map(|(author, _)| {
                let root = Vote::signing_root_for_set(
                    &self.validator_set,
                    header.view(),
                    header.height(),
                    parent.block().id(),
                )
                .expect("valid process-test vote signing preimage");
                Vote::new(
                    self.validator_set.chain_id(),
                    self.validator_set.protocol_version(),
                    self.validator_set.epoch(),
                    header.view(),
                    header.height(),
                    parent.block().id(),
                    self.validator_set.id(),
                    *author,
                    self.sign(*author, root),
                    &self.validator_set,
                )
                .expect("valid strict-Ed25519 process-test vote")
            })
            .collect();
        QuorumCertificate::new(
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            header.view(),
            header.height(),
            parent.block().id(),
            self.validator_set.id(),
            votes,
            &self.validator_set,
        )
        .expect("valid strict-Ed25519 process-test parent QC")
    }
}

#[derive(Debug, Clone)]
struct CasePathsV0 {
    start: PocoNodeStartConfigV0,
    application_status: PathBuf,
    watermark_record: PathBuf,
}

fn main() {
    if let Err(error) = run_v0() {
        eprintln!("trnm-poco recovery SIGKILL helper failed: {error}");
        process::exit(2);
    }
}

fn run_v0() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() < 4 || arguments.len() > 5 {
        return Err(
            "usage: <prepare|recover|verify> <root> <proposal|synced> <state|receipts> [phase]"
                .to_owned(),
        );
    }
    let command = parse_command_v0(&arguments[0])?;
    let root = PathBuf::from(&arguments[1]);
    let route = parse_route_v0(&arguments[2])?;
    let reason = parse_reason_v0(&arguments[3])?;
    let phase = arguments
        .get(4)
        .map(|value| parse_phase_v0(value))
        .transpose()?;
    let spec = CaseSpecV0 {
        route,
        reason,
        phase,
    };
    match command {
        HelperCommandV0::Prepare => {
            let target =
                phase.ok_or_else(|| "prepare requires an exact checkpoint phase".to_owned())?;
            prepare_initial_case_v0(&root, route, reason)?;
            let paths = existing_case_paths_v0(&root)?;
            let recovery = recovery_config_v0(&paths)?;
            let mut watermark = RecoveryProcessFileWatermarkV0::new(&paths.watermark_record)
                .map_err(|error| format!("open process watermark for prepare: {error:?}"))?;
            let signer_watermark = watermark
                .current_v0()
                .map_err(|error| format!("read process watermark for prepare: {error:?}"))?
                .ok_or_else(|| "process watermark was not initialized".to_owned())?;
            let mut reached_target = false;
            let result =
                PocoNodeValidationRecoveryHostV0::open_existing_with_process_checkpoint_observer_v0(
                    recovery,
                    watermark,
                    |checkpoint| {
                        validate_observed_checkpoint_v0(checkpoint, spec);
                        if checkpoint.phase() == target {
                            reached_target = true;
                            announce_and_wait_v0(spec, checkpoint, signer_watermark);
                        }
                    },
                );
            if reached_target {
                return Err("checkpoint observer returned after an acknowledgement".to_owned());
            }
            match result {
                Ok(_) => Err(format!(
                    "official host returned before target checkpoint {}",
                    target.as_str()
                )),
                Err(error) => Err(format!(
                    "official host failed before target checkpoint {}: {error:?}",
                    target.as_str()
                )),
            }
        }
        HelperCommandV0::Recover => {
            let target =
                phase.ok_or_else(|| "recover requires the killed checkpoint phase".to_owned())?;
            let paths = existing_case_paths_v0(&root)?;
            let host = open_official_host_v0(&paths)?;
            let identity = validate_recovery_result_v0(&host, spec, target)?;
            println!(
                "recovered_v0={};{}",
                spec.case_id(),
                identity.exact_text_v0()
            );
            io::stdout()
                .flush()
                .map_err(|error| format!("flush recovery output: {error}"))?;
            Ok(())
        }
        HelperCommandV0::Verify => {
            if phase.is_some() {
                return Err("verify does not accept a checkpoint phase".to_owned());
            }
            let paths = existing_case_paths_v0(&root)?;
            let host = open_official_host_v0(&paths)?;
            let identity = validate_final_acked_v0(&host, route, reason)?;
            println!(
                "verified_v0={}/{}/completion_acked;{}",
                route_name_v0(route),
                reason_name_v0(reason),
                identity.exact_text_v0()
            );
            io::stdout()
                .flush()
                .map_err(|error| format!("flush verification output: {error}"))?;
            Ok(())
        }
    }
}

fn prepare_initial_case_v0(
    root: &Path,
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) -> Result<(), String> {
    protect_existing_directory_v0(root)?;
    let safety_path = create_private_namespace_v0(root, "safety")?.join("safety.sqlite3");
    let signer_path = create_private_namespace_v0(root, "signer")?.join("signer.sqlite3");
    let application_status = create_private_namespace_v0(root, "application")?.join("state.json");
    let watermark_record = create_private_namespace_v0(root, "watermark")?.join("watermark.v0");
    let fixture = StrictConsensusFixtureV0::new();
    let start = node_start_config_v0(&safety_path, &signer_path, fixture.core_config.clone());
    let watermark = RecoveryProcessFileWatermarkV0::new(&watermark_record)
        .map_err(|error| format!("initialize process watermark adapter: {error:?}"))?;
    assert_eq!(watermark.path(), watermark_record.as_path());
    let (core, safety_store, signer_journal) =
        create_obligation_head_v0(&fixture, route, &start, watermark);
    let head = safety_store
        .head()
        .expect("read exact process-test obligation head");
    let session = Core::begin_payload_validation_obligation_recovery_v0(
        fixture.core_config,
        head.state().clone(),
        &StrictEd25519Verifier,
    )
    .expect("construct authentic process-test Core recovery challenge");
    let application_fixture = NativeValidationRecoveryTestFixtureConfigV0::new(
        &application_status,
        TEST_CHAIN,
        SIGNER_POLICY_HASH,
        safety_store.journal_id_v0(),
        safety_store.verifier_profile_ref_v0(),
    )
    .expect("valid process-test application recovery fixture config");
    let pending = initialize_native_validation_recovery_test_fixture_v0(
        &application_fixture,
        session.challenge(),
        reason,
    )
    .expect("create real process-test CallbackPending application row");
    assert_eq!(
        pending.state(),
        NativeValidationRecoveryTestFixtureStateV0::CallbackPending
    );
    assert_eq!(pending.route(), route);
    assert_eq!(pending.reason(), reason);
    drop(session);
    drop(core);
    drop(safety_store);
    drop(signer_journal);
    Ok(())
}

fn existing_case_paths_v0(root: &Path) -> Result<CasePathsV0, String> {
    protect_existing_directory_v0(root)?;
    let safety_path = root.join("safety").join("safety.sqlite3");
    let signer_path = root.join("signer").join("signer.sqlite3");
    let application_status = root.join("application").join("state.json");
    let watermark_record = root.join("watermark").join("watermark.v0");
    for parent in [
        safety_path.parent(),
        signer_path.parent(),
        application_status.parent(),
        watermark_record.parent(),
    ] {
        let parent = parent.ok_or_else(|| "case path lost its parent".to_owned())?;
        let metadata = fs::symlink_metadata(parent).map_err(|error| {
            format!("read process-test namespace {}: {error}", parent.display())
        })?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(format!(
                "invalid process-test namespace {}",
                parent.display()
            ));
        }
    }
    let fixture = StrictConsensusFixtureV0::new();
    let start = node_start_config_v0(&safety_path, &signer_path, fixture.core_config);
    Ok(CasePathsV0 {
        start,
        application_status,
        watermark_record,
    })
}

fn recovery_config_v0(paths: &CasePathsV0) -> Result<PocoNodeValidationRecoveryConfigV0, String> {
    PocoNodeValidationRecoveryConfigV0::new(
        paths.start.clone(),
        &paths.application_status,
        SIGNER_POLICY_HASH,
    )
    .map_err(|error| format!("construct process-test recovery config: {error:?}"))
}

fn open_official_host_v0(
    paths: &CasePathsV0,
) -> Result<PocoNodeValidationRecoveryHostV0<RecoveryProcessFileWatermarkV0>, String> {
    let recovery = recovery_config_v0(paths)?;
    let watermark = RecoveryProcessFileWatermarkV0::new(&paths.watermark_record)
        .map_err(|error| format!("open process watermark after SIGKILL: {error:?}"))?;
    PocoNodeValidationRecoveryHostV0::open_existing(recovery, watermark)
        .map_err(|error| format!("official host recovery failed: {error:?}"))
}

fn validate_observed_checkpoint_v0(
    checkpoint: ValidationRecoveryProcessCheckpointV0,
    spec: CaseSpecV0,
) {
    assert_eq!(checkpoint.route(), spec.route);
    assert_eq!(checkpoint.reason(), spec.reason);
    match checkpoint.phase() {
        ValidationRecoveryProcessCheckpointPhaseV0::ObligationCallbackPending
        | ValidationRecoveryProcessCheckpointPhaseV0::ObligationDelivered => {
            assert_eq!(
                checkpoint.safety_revision(),
                checkpoint.obligation_revision()
            );
        }
        ValidationRecoveryProcessCheckpointPhaseV0::CompletionDelivered
        | ValidationRecoveryProcessCheckpointPhaseV0::CompletionAcked => {
            assert_eq!(
                checkpoint.safety_revision(),
                checkpoint
                    .obligation_revision()
                    .checked_add(1)
                    .expect("process-test safety revision does not overflow")
            );
        }
    }
}

fn validate_recovery_result_v0(
    host: &PocoNodeValidationRecoveryHostV0<RecoveryProcessFileWatermarkV0>,
    spec: CaseSpecV0,
    killed_phase: ValidationRecoveryProcessCheckpointPhaseV0,
) -> Result<CaseIdentityV0, String> {
    let (route, validation_id, completion_revision, source) = match host.recovery() {
        ValidationRecoveryBootstrapV0::ObligationCompleted {
            route,
            validation_id,
            completion_revision,
            source,
        } => {
            if !matches!(
                killed_phase,
                ValidationRecoveryProcessCheckpointPhaseV0::ObligationCallbackPending
                    | ValidationRecoveryProcessCheckpointPhaseV0::ObligationDelivered
            ) {
                return Err(format!(
                    "completion source disagrees with killed phase {}",
                    killed_phase.as_str()
                ));
            }
            (route, validation_id, completion_revision, source)
        }
        ValidationRecoveryBootstrapV0::CompletionConfirmed {
            route,
            validation_id,
            completion_revision,
            source,
        } => {
            if !matches!(
                killed_phase,
                ValidationRecoveryProcessCheckpointPhaseV0::CompletionDelivered
                    | ValidationRecoveryProcessCheckpointPhaseV0::CompletionAcked
            ) {
                return Err(format!(
                    "obligation source disagrees with killed phase {}",
                    killed_phase.as_str()
                ));
            }
            (route, validation_id, completion_revision, source)
        }
        ValidationRecoveryBootstrapV0::NotRequired => {
            return Err("official host reported no bounded recovery work".to_owned());
        }
    };
    let expected_source = match killed_phase {
        ValidationRecoveryProcessCheckpointPhaseV0::ObligationCallbackPending => {
            ValidationRecoverySourceStateV0::CallbackPending
        }
        ValidationRecoveryProcessCheckpointPhaseV0::ObligationDelivered
        | ValidationRecoveryProcessCheckpointPhaseV0::CompletionDelivered => {
            ValidationRecoverySourceStateV0::Delivered
        }
        ValidationRecoveryProcessCheckpointPhaseV0::CompletionAcked => {
            ValidationRecoverySourceStateV0::Acked
        }
    };
    if route != spec.route || source != expected_source {
        return Err(format!(
            "unexpected recovery result: route={route:?} source={source:?} expected={expected_source:?}"
        ));
    }
    validate_final_head_v0(
        host,
        spec.route,
        spec.reason,
        validation_id,
        completion_revision,
    )?;
    Ok(CaseIdentityV0 {
        validation_id,
        completion_revision,
        signer_watermark: host.signer_journal_head(),
    })
}

fn validate_final_acked_v0(
    host: &PocoNodeValidationRecoveryHostV0<RecoveryProcessFileWatermarkV0>,
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) -> Result<CaseIdentityV0, String> {
    let ValidationRecoveryBootstrapV0::CompletionConfirmed {
        route: recovered_route,
        validation_id,
        completion_revision,
        source: ValidationRecoverySourceStateV0::Acked,
    } = host.recovery()
    else {
        return Err(format!(
            "fresh-process verification did not observe C+K: {:?}",
            host.recovery()
        ));
    };
    if recovered_route != route {
        return Err("fresh-process C+K route mismatch".to_owned());
    }
    validate_final_head_v0(host, route, reason, validation_id, completion_revision)?;
    Ok(CaseIdentityV0 {
        validation_id,
        completion_revision,
        signer_watermark: host.signer_journal_head(),
    })
}

fn validate_final_head_v0(
    host: &PocoNodeValidationRecoveryHostV0<RecoveryProcessFileWatermarkV0>,
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
    validation_id: ValidationId,
    completion_revision: u64,
) -> Result<(), String> {
    if host.pending_inert_effect_count() != 0 {
        return Err("bounded recovery escaped a non-inert effect".to_owned());
    }
    let head = host
        .safety_head()
        .map_err(|error| format!("authenticate recovered SafetyStore head: {error:?}"))?;
    let native = head
        .transition_context()
        .native_invalid()
        .ok_or_else(|| "recovered head lacks native-invalid transition context".to_owned())?;
    if native.route() != route
        || native.validation_id() != validation_id
        || native.reason_code() != reason.code_v0()
        || native.completion_revision() != completion_revision
        || head.revision() != completion_revision
        || !head.state().payload_validation_obligations().is_empty()
    {
        return Err("recovered C+K facts do not match the killed case".to_owned());
    }
    let matching_completions = head
        .state()
        .payload_validation_completions()
        .iter()
        .filter(|completion| completion.route() == route && completion.id() == validation_id)
        .collect::<Vec<_>>();
    let [completion] = matching_completions.as_slice() else {
        return Err("recovered head lacks one exact completion tombstone".to_owned());
    };
    if completion.result() != DurablePayloadValidationResultV1::DeterministicallyInvalid
        || completion.first_recorded_revision() != completion_revision
    {
        return Err("recovered completion tombstone is not exact".to_owned());
    }
    Ok(())
}

fn announce_and_wait_v0(
    spec: CaseSpecV0,
    checkpoint: ValidationRecoveryProcessCheckpointV0,
    signer_watermark: SignerWatermarkV0,
) -> ! {
    let case_id = spec.case_id();
    let identity = CaseIdentityV0 {
        validation_id: checkpoint.validation_id(),
        completion_revision: checkpoint
            .obligation_revision()
            .checked_add(1)
            .expect("process-test completion revision does not overflow"),
        signer_watermark,
    };
    println!("checkpoint_v0={case_id};{}", identity.exact_text_v0());
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
    if acknowledgement != format!("ACK {case_id}\n") {
        eprintln!("checkpoint acknowledgement was missing or inexact");
        process::exit(72);
    }
    eprintln!("checkpoint helper must be killed, not acknowledged");
    process::exit(73);
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

fn canonical_block_v0(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    parent: BlockId,
    payload: &[u8],
    proposer: ValidatorId,
) -> Block {
    let application_payload =
        ApplicationPayloadV0::new(vec![payload.to_vec()]).expect("canonical process-test payload");
    let receipt =
        ExecutionReceiptCommitmentV0::for_transaction(&application_payload, 0, 0, 0, Vec::new())
            .expect("canonical process-test receipt");
    let receipts = ExecutionReceiptsV0::new(&application_payload, vec![receipt])
        .expect("canonical process-test receipts");
    let body =
        BlockBodyV0::new(application_payload, Vec::new()).expect("canonical process-test body");
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        BlockKind::Regular,
        parent,
        proposer,
        set.id(),
        set.consensus_parameters_hash(),
        body.payload_root().expect("canonical payload root"),
        StateRoot::new([height as u8; 32]),
        receipts.receipts_root().expect("canonical receipts root"),
        body.evidence_root().expect("canonical evidence root"),
        height.saturating_mul(100),
        None,
    )
    .expect("valid strict-Ed25519 process-test header");
    Block::new(
        header,
        body.application_payload()
            .try_cev0_bytes()
            .expect("canonical process-test payload bytes"),
        Vec::new(),
    )
    .expect("body matches strict-Ed25519 process-test header")
}

fn valid_commitments_v0(core: &Core, block: &Block) -> ValidatedBlockCommitmentsV0 {
    let application_payload = decode_application_payload_v0_exact(
        block.application_payload(),
        core.config().consensus_parameters(),
    )
    .expect("decode canonical process-test application payload");
    let receipts = ExecutionReceiptsV0::new(
        &application_payload,
        (0..application_payload.transaction_count())
            .map(|index| {
                ExecutionReceiptCommitmentV0::for_transaction(
                    &application_payload,
                    index,
                    0,
                    0,
                    Vec::new(),
                )
                .expect("canonical process-test receipt")
            })
            .collect(),
    )
    .expect("canonical process-test receipts");
    let body =
        BlockBodyV0::new(application_payload, Vec::new()).expect("canonical process-test body");
    body.validate_ordinary_commitments(
        block.header(),
        &receipts,
        core.config().consensus_parameters(),
        core.config().validator_set(),
        &StrictEd25519Verifier,
    )
    .expect("strict verifier validates canonical process-test commitments")
}

fn node_start_config_v0(
    safety_path: &Path,
    signer_path: &Path,
    core_config: CoreConfig,
) -> PocoNodeStartConfigV0 {
    PocoNodeStartConfigV0::new(
        safety_path,
        signer_path,
        core_config,
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES, MAXIMUM_BLOB_BYTES)
            .expect("valid process-test record bounds"),
        MAXIMUM_SAFETY_DATABASE_BYTES,
        MAXIMUM_SIGNER_INTENTS,
        MAXIMUM_SIGNER_INTENT_BYTES,
        MAXIMUM_SIGNER_DATABASE_BYTES,
    )
    .expect("valid process-test node start config")
}

fn persist_and_ack_v0(
    core: &mut Core,
    store: &mut SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    effects: Vec<Effect>,
) -> Vec<Effect> {
    let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
        panic!("expected one exact process-test Core persistence request: {effects:?}");
    };
    let barrier = request.barrier();
    store
        .persist_exact_v0(request, &SafetyTransitionContextV0::ordinary())
        .expect("persist exact process-test Core request in SafetyStore");
    let head = store
        .head()
        .expect("authenticate exact process-test persisted head");
    assert_eq!(head.state(), request.state());
    assert!(matches!(
        head.transition_context(),
        SafetyTransitionContextV0::Ordinary
    ));
    core.step(Input::StorageAck { barrier }, &StrictEd25519Verifier)
        .expect("ack only the exact durable process-test Core request")
}

fn create_obligation_head_v0<W: ExternalMonotonicWatermarkV0>(
    fixture: &StrictConsensusFixtureV0,
    route: PayloadValidationRouteV0,
    start: &PocoNodeStartConfigV0,
    watermark: W,
) -> (
    Core,
    SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    SqliteSignerJournalV0<W>,
) {
    let verifier = StrictEd25519Verifier;
    let mut core = Core::new(fixture.core_config.clone(), fixture.genesis_qc(), &verifier)
        .expect("initialize strict-Ed25519 process-test Core");
    let mut safety_store = SqliteSafetyStateStoreV0::initialize_new(
        start.safety_store_path(),
        start.recovery_process_safety_store_profile_v0(),
        verifier,
        core.safety_state(),
    )
    .expect("initialize real process-test SafetyStore");
    safety_store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .expect("bind process-test SafetyStore to exact Core");
    let signer_journal = SqliteSignerJournalV0::initialize_new(
        start.signer_journal_path(),
        start.recovery_process_signer_journal_profile_v0(),
        watermark,
    )
    .expect("initialize real process-test signer journal");

    let parent = fixture.proposal(
        QcReferenceV0::genesis_anchor(fixture.genesis_qc()),
        1,
        b"strict process parent",
    );
    let effects = core
        .step(
            Input::Proposal(Box::new(parent.clone())),
            &StrictEd25519Verifier,
        )
        .expect("register process-test parent validation obligation");
    let released = persist_and_ack_v0(&mut core, &mut safety_store, effects);
    let parent_id = match released.as_slice() {
        [Effect::ArmViewTimer { .. }, Effect::ValidatePayload(request)] => request.id(),
        _ => panic!("parent persistence did not release exact process validation: {released:?}"),
    };
    let commitments = valid_commitments_v0(&core, parent.block());
    let effects = core
        .step(
            Input::PayloadValidated {
                id: parent_id,
                result: PayloadValidationResult::Valid { commitments },
            },
            &StrictEd25519Verifier,
        )
        .expect("accept valid process-test parent payload");
    let released = persist_and_ack_v0(&mut core, &mut safety_store, effects);
    let intent = match released.as_slice() {
        [Effect::RequestSignature { intent }] => intent,
        _ => panic!("parent validation did not release process vote intent: {released:?}"),
    };
    let signing_root = intent.signing_root();
    let local_signature = fixture.sign(fixture.core_config.local_validator(), signing_root);
    let broadcast = core
        .step(
            Input::SignatureReady {
                id: SignId::new(signing_root),
                signature: local_signature,
            },
            &StrictEd25519Verifier,
        )
        .expect("strictly verify process-test local vote signature");
    assert!(matches!(
        broadcast.as_slice(),
        [Effect::Broadcast(OutboundMessage::Vote(_))]
    ));

    let parent_qc = fixture.parent_qc(&parent);
    let effects = core
        .step(
            Input::QuorumCertificate(parent_qc.clone()),
            &StrictEd25519Verifier,
        )
        .expect("strictly verify and persist process-test parent QC");
    let released = persist_and_ack_v0(&mut core, &mut safety_store, effects);
    assert!(matches!(released.as_slice(), [Effect::ArmViewTimer { .. }]));

    let target = fixture.proposal(
        QcReferenceV0::ordinary(parent_qc),
        2,
        b"strict invalid process target",
    );
    let input = match route {
        PayloadValidationRouteV0::Proposal => Input::Proposal(Box::new(target.clone())),
        PayloadValidationRouteV0::Synced => Input::SyncedProposal(Box::new(target.clone())),
    };
    let target_effects = core
        .step(input, &StrictEd25519Verifier)
        .expect("register process-test target validation obligation");
    let released = persist_and_ack_v0(&mut core, &mut safety_store, target_effects);
    match (route, released.as_slice()) {
        (
            PayloadValidationRouteV0::Proposal,
            [Effect::ArmViewTimer { .. }, Effect::ValidatePayload(_)],
        )
        | (PayloadValidationRouteV0::Synced, [Effect::ValidateSyncedPayload(_)]) => {}
        _ => panic!("target persistence did not release exact process validation: {released:?}"),
    }
    let head = safety_store
        .head()
        .expect("authenticate process-test obligation head");
    let [obligation] = head.state().payload_validation_obligations() else {
        panic!("process-test target must leave exactly one durable obligation");
    };
    assert_eq!(obligation.route(), route);
    assert_eq!(obligation.proposal(), &target);
    (core, safety_store, signer_journal)
}

fn protect_existing_directory_v0(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("process-test root must be absolute".to_owned());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read process-test root {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("process-test root must be a real directory".to_owned());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protect process-test root {}: {error}", path.display()))?;
    Ok(())
}

fn create_private_namespace_v0(root: &Path, name: &str) -> Result<PathBuf, String> {
    let namespace = root.join(name);
    fs::create_dir(&namespace).map_err(|error| {
        format!(
            "create process-test namespace {}: {error}",
            namespace.display()
        )
    })?;
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!(
            "protect process-test namespace {}: {error}",
            namespace.display()
        )
    })?;
    Ok(namespace)
}

fn parse_command_v0(value: &str) -> Result<HelperCommandV0, String> {
    match value {
        "prepare" => Ok(HelperCommandV0::Prepare),
        "recover" => Ok(HelperCommandV0::Recover),
        "verify" => Ok(HelperCommandV0::Verify),
        _ => Err(format!("unknown helper command: {value}")),
    }
}

fn parse_route_v0(value: &str) -> Result<PayloadValidationRouteV0, String> {
    match value {
        "proposal" => Ok(PayloadValidationRouteV0::Proposal),
        "synced" => Ok(PayloadValidationRouteV0::Synced),
        _ => Err(format!("unknown process-test route: {value}")),
    }
}

fn route_name_v0(route: PayloadValidationRouteV0) -> &'static str {
    match route {
        PayloadValidationRouteV0::Proposal => "proposal",
        PayloadValidationRouteV0::Synced => "synced",
    }
}

fn parse_reason_v0(value: &str) -> Result<NativeValidationRecoveredInvalidReasonV0, String> {
    match value {
        "state" => Ok(NativeValidationRecoveredInvalidReasonV0::ComputedStateRootMismatch),
        "receipts" => Ok(NativeValidationRecoveredInvalidReasonV0::ComputedReceiptsRootMismatch),
        _ => Err(format!("unknown process-test invalid reason: {value}")),
    }
}

fn reason_name_v0(reason: NativeValidationRecoveredInvalidReasonV0) -> &'static str {
    match reason {
        NativeValidationRecoveredInvalidReasonV0::ComputedStateRootMismatch => "state",
        NativeValidationRecoveredInvalidReasonV0::ComputedReceiptsRootMismatch => "receipts",
    }
}

fn parse_phase_v0(value: &str) -> Result<ValidationRecoveryProcessCheckpointPhaseV0, String> {
    match value {
        "obligation_callback_pending" => {
            Ok(ValidationRecoveryProcessCheckpointPhaseV0::ObligationCallbackPending)
        }
        "obligation_delivered" => {
            Ok(ValidationRecoveryProcessCheckpointPhaseV0::ObligationDelivered)
        }
        "completion_delivered" => {
            Ok(ValidationRecoveryProcessCheckpointPhaseV0::CompletionDelivered)
        }
        "completion_acked" => Ok(ValidationRecoveryProcessCheckpointPhaseV0::CompletionAcked),
        _ => Err(format!("unknown process-test checkpoint phase: {value}")),
    }
}
