use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use trnm_consensus_app::{
    initialize_native_validation_recovery_test_fixture_v0,
    NativeValidationRecoveredInvalidCallbackFactsV0, NativeValidationRecoveredInvalidReasonV0,
    NativeValidationRecoveredInvalidStateV0, NativeValidationRecoveryStoreConfigV0,
    NativeValidationRecoveryStoreV0, NativeValidationRecoveryTestFixtureConfigV0,
    NativeValidationRecoveryTestFixtureStateV0,
};
use trnm_consensus_core::{
    leader_for, Core, DurablePayloadValidationResultV1, Effect, Input, OutboundMessage,
    PayloadTerminalResult, PayloadValidationRecoverySessionV0, PayloadValidationResult,
    PayloadValidationRouteV0, SafetyState, SafetyStatePersistenceV0, SignId, ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    SafetyStoreErrorV0, SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignatureProducerErrorV0,
    SignatureProducerV0, SignatureRequestV0, SignerWatermarkV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader,
    BlockId, BlockKind, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
    ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, GenesisHash, GenesisQcV0, Height,
    ProposalWitnessV0, ProtocolVersion, QcReferenceV0, QuorumCertificate, SignatureBytes,
    SignedProposalV0, SigningRoot, StateRoot, ValidatedBlockCommitmentsV0, Validator, ValidatorId,
    ValidatorSet, View, Vote, VotingPower,
};

use super::*;

const TEST_CHAIN: ChainId = ChainId::from_static("trnm-poco-node-g1c-test");
const GENESIS_TIMESTAMP_MS: u64 = 0;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_SAFETY_DATABASE_BYTES: usize = 192 * 1024 * 1024;
const MAXIMUM_SIGNER_INTENTS: u64 = 64;
const MAXIMUM_SIGNER_INTENT_BYTES: usize = 4096;
const MAXIMUM_SIGNER_DATABASE_BYTES: usize = 32 * 1024 * 1024;
const SIGNER_POLICY_HASH: [u8; 32] = [0x77; 32];

#[derive(Debug, Clone, Default)]
struct MemoryWatermark(Arc<Mutex<Option<SignerWatermarkV0>>>);

impl ExternalMonotonicWatermarkV0 for MemoryWatermark {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let value = *self.0.lock().expect("test watermark lock");
        if value.is_some_and(|watermark| watermark.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(value)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        let mut value = self.0.lock().expect("test watermark lock");
        if *value != expected {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        match expected {
            None if target.sequence() == 0 => {}
            Some(source)
                if source.scope() == target.scope()
                    && source.journal_id() == target.journal_id()
                    && source.sequence().checked_add(1) == Some(target.sequence()) => {}
            _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
        }
        *value = Some(target);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct UnavailableProducerV0;

impl SignatureProducerV0 for UnavailableProducerV0 {
    fn sign(
        &mut self,
        _request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        Err(SignatureProducerErrorV0::Unavailable)
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
                    VotingPower::new(1).expect("positive test voting power"),
                )
                .expect("valid strict-Ed25519 test validator")
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
        .expect("valid strict-Ed25519 validator set");
        let core_config = CoreConfig::new(
            keys[0].0,
            validator_set.clone(),
            parameters,
            GENESIS_TIMESTAMP_MS,
            32,
            64,
        )
        .expect("valid strict-Ed25519 Core config");
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
            .expect("validator has a fixture signing key")
    }

    fn genesis_qc(&self) -> GenesisQcV0 {
        GenesisQcV0::new(
            self.validator_set.genesis_hash(),
            self.validator_set.chain_id(),
            &self.validator_set,
        )
        .expect("valid genesis anchor")
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
            .expect("test height does not overflow");
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
            .expect("valid proposal signing preimage");
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
        .expect("valid strict-Ed25519 proposal witness");
        SignedProposalV0::new(
            block,
            witness,
            &self.validator_set,
            None,
            &self.parameters,
            justify_ref.height().get().saturating_mul(100),
        )
        .expect("valid strict-Ed25519 proposal")
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
                .expect("valid vote signing preimage");
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
                .expect("valid strict-Ed25519 vote")
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
        .expect("valid strict-Ed25519 parent QC")
    }
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
        ApplicationPayloadV0::new(vec![payload.to_vec()]).expect("canonical test payload");
    let receipt =
        ExecutionReceiptCommitmentV0::for_transaction(&application_payload, 0, 0, 0, Vec::new())
            .expect("canonical test receipt");
    let receipts = ExecutionReceiptsV0::new(&application_payload, vec![receipt])
        .expect("canonical test receipts");
    let body = BlockBodyV0::new(application_payload, Vec::new()).expect("canonical test body");
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
    .expect("valid strict-Ed25519 test header");
    Block::new(
        header,
        body.application_payload()
            .try_cev0_bytes()
            .expect("canonical application payload bytes"),
        Vec::new(),
    )
    .expect("body matches strict-Ed25519 test header")
}

fn valid_commitments_v0(core: &Core, block: &Block) -> ValidatedBlockCommitmentsV0 {
    let application_payload = decode_application_payload_v0_exact(
        block.application_payload(),
        core.config().consensus_parameters(),
    )
    .expect("decode canonical application payload");
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
                .expect("canonical test receipt")
            })
            .collect(),
    )
    .expect("canonical test receipts");
    let body = BlockBodyV0::new(application_payload, Vec::new()).expect("canonical test body");
    body.validate_ordinary_commitments(
        block.header(),
        &receipts,
        core.config().consensus_parameters(),
        core.config().validator_set(),
        &StrictEd25519Verifier,
    )
    .expect("strict verifier validates canonical commitments")
}

fn protected_temp_dir_v0() -> TempDir {
    let directory = TempDir::new().expect("temporary recovery root");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("protect temporary recovery root");
    directory
}

fn protected_namespace_v0(root: &TempDir, name: &str) -> PathBuf {
    let namespace = root.path().join(name);
    fs::create_dir(&namespace).expect("create isolated recovery namespace");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700))
        .expect("protect isolated recovery namespace");
    namespace
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
            .expect("valid test record bounds"),
        MAXIMUM_SAFETY_DATABASE_BYTES,
        MAXIMUM_SIGNER_INTENTS,
        MAXIMUM_SIGNER_INTENT_BYTES,
        MAXIMUM_SIGNER_DATABASE_BYTES,
    )
    .expect("valid recovery node start config")
}

fn persist_and_ack_v0(
    core: &mut Core,
    store: &mut SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    effects: Vec<Effect>,
) -> Vec<Effect> {
    let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
        panic!("expected one exact Core persistence request: {effects:?}");
    };
    let barrier = request.barrier();
    store
        .persist_exact_v0(request, &SafetyTransitionContextV0::ordinary())
        .expect("persist exact Core request in the real SafetyStore");
    let head = store.head().expect("authenticate exact persisted head");
    assert_eq!(head.state(), request.state());
    assert!(matches!(
        head.transition_context(),
        SafetyTransitionContextV0::Ordinary
    ));
    core.step(Input::StorageAck { barrier }, &StrictEd25519Verifier)
        .expect("ack only the exact durable Core request")
}

fn create_obligation_head_v0(
    fixture: &StrictConsensusFixtureV0,
    route: PayloadValidationRouteV0,
    start: &PocoNodeStartConfigV0,
    watermark: MemoryWatermark,
) -> (
    Core,
    SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    SqliteSignerJournalV0<MemoryWatermark>,
) {
    let verifier = StrictEd25519Verifier;
    let mut core = Core::new(fixture.core_config.clone(), fixture.genesis_qc(), &verifier)
        .expect("initialize strict-Ed25519 Core");
    let mut safety_store = SqliteSafetyStateStoreV0::initialize_new(
        start.safety_store_path.clone(),
        start.safety_store_profile.clone(),
        verifier,
        core.safety_state(),
    )
    .expect("initialize real SafetyStore");
    safety_store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .expect("bind SafetyStore to the exact fixture Core");
    let signer_journal = SqliteSignerJournalV0::initialize_new(
        start.signer_journal_path.clone(),
        start.signer_journal_profile.clone(),
        watermark,
    )
    .expect("initialize real signer journal");

    let parent = fixture.proposal(
        QcReferenceV0::genesis_anchor(fixture.genesis_qc()),
        1,
        b"strict parent",
    );
    let effects = core
        .step(
            Input::Proposal(Box::new(parent.clone())),
            &StrictEd25519Verifier,
        )
        .expect("register parent validation obligation");
    let released = persist_and_ack_v0(&mut core, &mut safety_store, effects);
    let parent_id = match released.as_slice() {
        [Effect::ArmViewTimer { .. }, Effect::ValidatePayload(request)] => request.id(),
        _ => panic!("parent persistence did not release exact validation: {released:?}"),
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
        .expect("accept valid parent payload");
    let released = persist_and_ack_v0(&mut core, &mut safety_store, effects);
    let intent = match released.as_slice() {
        [Effect::RequestSignature { intent }] => intent,
        _ => panic!("parent validation did not release vote intent: {released:?}"),
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
        .expect("strictly verify local vote signature");
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
        .expect("strictly verify and persist parent QC");
    let released = persist_and_ack_v0(&mut core, &mut safety_store, effects);
    assert!(matches!(released.as_slice(), [Effect::ArmViewTimer { .. }]));

    let target = fixture.proposal(
        QcReferenceV0::ordinary(parent_qc),
        2,
        b"strict invalid target",
    );
    let input = match route {
        PayloadValidationRouteV0::Proposal => Input::Proposal(Box::new(target.clone())),
        PayloadValidationRouteV0::Synced => Input::SyncedProposal(Box::new(target.clone())),
    };
    let target_effects = core
        .step(input, &StrictEd25519Verifier)
        .expect("register target validation obligation");
    let released = persist_and_ack_v0(&mut core, &mut safety_store, target_effects);
    match (route, released.as_slice()) {
        (
            PayloadValidationRouteV0::Proposal,
            [Effect::ArmViewTimer { .. }, Effect::ValidatePayload(_)],
        )
        | (PayloadValidationRouteV0::Synced, [Effect::ValidateSyncedPayload(_)]) => {}
        _ => panic!("target persistence did not release exact validation: {released:?}"),
    }
    let head = safety_store.head().expect("authenticate obligation head");
    let [obligation] = head.state().payload_validation_obligations() else {
        panic!("target must leave exactly one durable obligation");
    };
    assert_eq!(obligation.route(), route);
    assert_eq!(obligation.proposal(), &target);
    (core, safety_store, signer_journal)
}

struct PendingRecoveryCaseV0 {
    _root: TempDir,
    start: PocoNodeStartConfigV0,
    watermark: MemoryWatermark,
    application_status: PathBuf,
    original_core: Core,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    signer_journal: SqliteSignerJournalV0<MemoryWatermark>,
    recovery_session: PayloadValidationRecoverySessionV0,
    validation_id: ValidationId,
    obligation_revision: u64,
}

fn prepare_pending_recovery_case_v0(
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) -> PendingRecoveryCaseV0 {
    let root = protected_temp_dir_v0();
    let safety_path = protected_namespace_v0(&root, "safety").join("safety.sqlite3");
    let signer_path = protected_namespace_v0(&root, "signer").join("signer.sqlite3");
    let application_status = protected_namespace_v0(&root, "application").join("state.json");
    let fixture = StrictConsensusFixtureV0::new();
    let start = node_start_config_v0(&safety_path, &signer_path, fixture.core_config.clone());
    let watermark = MemoryWatermark::default();
    let (original_core, safety_store, signer_journal) =
        create_obligation_head_v0(&fixture, route, &start, watermark.clone());
    let head = safety_store.head().expect("read exact obligation head");
    let obligation_revision = head.revision();
    let recovery_session = Core::begin_payload_validation_obligation_recovery_v0(
        fixture.core_config,
        head.state().clone(),
        &StrictEd25519Verifier,
    )
    .expect("construct authentic Core recovery challenge");
    let application_fixture = NativeValidationRecoveryTestFixtureConfigV0::new(
        &application_status,
        TEST_CHAIN,
        SIGNER_POLICY_HASH,
        safety_store.journal_id_v0(),
        safety_store.verifier_profile_ref_v0(),
    )
    .expect("valid application recovery fixture config");
    let pending = initialize_native_validation_recovery_test_fixture_v0(
        &application_fixture,
        recovery_session.challenge(),
        reason,
    )
    .expect("create real CallbackPending application row");
    assert_eq!(
        pending.state(),
        NativeValidationRecoveryTestFixtureStateV0::CallbackPending
    );
    assert_eq!(pending.route(), route);
    assert_eq!(pending.reason(), reason);
    let validation_id = pending.validation_id();
    assert_eq!(validation_id, recovery_session.challenge().id());

    PendingRecoveryCaseV0 {
        _root: root,
        start,
        watermark,
        application_status,
        original_core,
        safety_store,
        signer_journal,
        recovery_session,
        validation_id,
        obligation_revision,
    }
}

fn application_recovery_config_v0(
    status_path: &Path,
    safety_store: &SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
) -> NativeValidationRecoveryStoreConfigV0 {
    NativeValidationRecoveryStoreConfigV0::new(
        status_path.to_path_buf(),
        TEST_CHAIN,
        SIGNER_POLICY_HASH,
        safety_store.journal_id_v0(),
        safety_store.verifier_profile_ref_v0(),
    )
}

fn exact_invalid_input_v0(route: PayloadValidationRouteV0, id: ValidationId) -> Input {
    match route {
        PayloadValidationRouteV0::Proposal => Input::PayloadValidated {
            id,
            result: PayloadValidationResult::DeterministicallyInvalid,
        },
        PayloadValidationRouteV0::Synced => Input::SyncedPayloadValidated {
            id,
            result: PayloadValidationResult::DeterministicallyInvalid,
        },
    }
}

fn assert_exact_invalid_completion_v0(
    state: &SafetyState,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    obligation_revision: u64,
) {
    assert_eq!(
        state.revision(),
        obligation_revision
            .checked_add(1)
            .expect("test obligation revision does not overflow")
    );
    assert!(state.payload_validation_obligations().is_empty());
    let matching = state
        .payload_validation_completions()
        .iter()
        .filter(|completion| completion.route() == route && completion.id() == validation_id)
        .collect::<Vec<_>>();
    let [completion] = matching.as_slice() else {
        panic!("expected exactly one matching completion tombstone: {matching:?}");
    };
    assert_eq!(
        completion.result(),
        DurablePayloadValidationResultV1::DeterministicallyInvalid
    );
    assert_eq!(completion.first_recorded_revision(), state.revision());
    assert_eq!(
        state.payload_terminal_result(validation_id.block_id()),
        Some(PayloadTerminalResult::DeterministicallyInvalid)
    );
}

fn activate_and_record_delivered_v0(
    session: PayloadValidationRecoverySessionV0,
    application: &mut NativeValidationRecoveryStoreV0,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    reason: NativeValidationRecoveredInvalidReasonV0,
    obligation_revision: u64,
) -> (
    Core,
    SafetyStatePersistenceV0,
    NativeValidationRecoveredInvalidCallbackFactsV0,
) {
    let mut recovered_core = session
        .reconcile_and_activate_v0(application)
        .expect("production application facade accepts its exact Core challenge");
    assert_eq!(
        application.recovered_obligation_state_v0(),
        Some(NativeValidationRecoveredInvalidStateV0::CallbackPending)
    );
    let effects = recovered_core
        .step(
            exact_invalid_input_v0(route, validation_id),
            &StrictEd25519Verifier,
        )
        .expect("recovered Core accepts the exact deterministic-invalid callback");
    let request = take_exact_recovery_persistence_v0(effects)
        .expect("recovered callback emits one opaque persistence request");
    assert_exact_invalid_completion_v0(request.state(), route, validation_id, obligation_revision);
    let callback_facts = application
        .record_recovered_core_acceptance_v0(&request)
        .expect("production application facade durably records Delivered");
    assert_eq!(callback_facts.route(), route);
    assert_eq!(callback_facts.validation_id(), validation_id);
    assert_eq!(callback_facts.reason(), reason);
    assert_eq!(callback_facts.delivery_attempt(), 1);
    assert_eq!(
        application.recovered_obligation_state_v0(),
        Some(NativeValidationRecoveredInvalidStateV0::Delivered)
    );
    application
        .final_exact_audit_v0()
        .expect("Delivered application row survives an exact audit");
    (recovered_core, request, callback_facts)
}

fn assert_live_host_holds_official_lock_v0(
    start: &PocoNodeStartConfigV0,
    application_status: &Path,
    watermark: MemoryWatermark,
) {
    let error = match PocoNodeValidationRecoveryHostV0::open_existing(
        PocoNodeValidationRecoveryConfigV0::new(
            start.clone(),
            application_status,
            SIGNER_POLICY_HASH,
        )
        .expect("valid competing recovery config"),
        watermark,
    ) {
        Ok(_) => panic!("a second official host acquired the live recovery namespace"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        PocoNodeHostErrorV0::SafetyStore(error)
            if matches!(error.as_ref(), SafetyStoreErrorV0::Locked)
    ));
}

fn assert_reopened_c_k_v0(
    start: &PocoNodeStartConfigV0,
    application_status: &Path,
    watermark: MemoryWatermark,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    obligation_revision: u64,
) {
    let repeated = PocoNodeValidationRecoveryHostV0::open_existing(
        PocoNodeValidationRecoveryConfigV0::new(
            start.clone(),
            application_status,
            SIGNER_POLICY_HASH,
        )
        .expect("valid repeated recovery config"),
        watermark,
    )
    .expect("C+K recovery must be exactly idempotent");
    assert_eq!(
        repeated.recovery(),
        ValidationRecoveryBootstrapV0::CompletionConfirmed {
            route,
            validation_id,
            completion_revision: obligation_revision + 1,
            source: ValidationRecoverySourceStateV0::Acked,
        }
    );
    assert_eq!(repeated.pending_inert_effect_count(), 0);
    assert_exact_invalid_completion_v0(
        repeated.safety_state(),
        route,
        validation_id,
        obligation_revision,
    );
    drop(repeated);
}

fn exercise_recovery_case_v0(
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) {
    let PendingRecoveryCaseV0 {
        _root,
        start,
        watermark,
        application_status,
        original_core,
        safety_store,
        signer_journal,
        recovery_session,
        validation_id,
        obligation_revision,
    } = prepare_pending_recovery_case_v0(route, reason);
    drop(recovery_session);
    drop(original_core);
    drop(safety_store);
    drop(signer_journal);

    let recovery_config = PocoNodeValidationRecoveryConfigV0::new(
        start.clone(),
        &application_status,
        SIGNER_POLICY_HASH,
    )
    .expect("valid three-store node recovery config");
    let host = PocoNodeValidationRecoveryHostV0::open_existing(recovery_config, watermark.clone())
        .expect("O+P recovery must durably reach C+K");
    assert_eq!(
        host.recovery(),
        ValidationRecoveryBootstrapV0::ObligationCompleted {
            route,
            validation_id,
            completion_revision: obligation_revision + 1,
            source: ValidationRecoverySourceStateV0::CallbackPending,
        }
    );
    assert_eq!(host.pending_inert_effect_count(), 0);
    assert_exact_invalid_completion_v0(
        host.safety_state(),
        route,
        validation_id,
        obligation_revision,
    );
    let completed_head = host
        .safety_head()
        .expect("authenticate completed safety head");
    let native = completed_head
        .transition_context()
        .native_invalid()
        .expect("completed head carries exact native-invalid context");
    assert_eq!(native.route(), route);
    assert_eq!(native.validation_id(), validation_id);
    assert_eq!(native.reason_code(), reason.code_v0());
    assert_eq!(native.completion_revision(), completed_head.revision());
    assert_live_host_holds_official_lock_v0(&start, &application_status, watermark.clone());
    drop(host);

    assert_reopened_c_k_v0(
        &start,
        &application_status,
        watermark.clone(),
        route,
        validation_id,
        obligation_revision,
    );

    let legacy_error = match PocoNodeHostV0::open_existing(start, watermark, UnavailableProducerV0)
    {
        Ok(_) => panic!("legacy host bypassed application-aware C+K recovery"),
        Err(error) => error,
    };
    assert!(matches!(
        legacy_error,
        PocoNodeHostErrorV0::ValidationRecoveryAwareOpenRequired { .. }
    ));
}

fn exercise_o_d_recovery_case_v0(
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) {
    let PendingRecoveryCaseV0 {
        _root,
        start,
        watermark,
        application_status,
        original_core,
        safety_store,
        signer_journal,
        recovery_session,
        validation_id,
        obligation_revision,
    } = prepare_pending_recovery_case_v0(route, reason);
    let mut application = NativeValidationRecoveryStoreV0::open_existing_v8(
        application_recovery_config_v0(&application_status, &safety_store),
    )
    .expect("production application recovery facade opens P");
    let (recovered_core, request, _) = activate_and_record_delivered_v0(
        recovery_session,
        &mut application,
        route,
        validation_id,
        reason,
        obligation_revision,
    );

    // Crash entry O+D: D is durable, but the exact Core request never reaches
    // the SafetyStore. The official host must replay that request from O.
    drop(request);
    drop(recovered_core);
    drop(application);
    drop(original_core);
    drop(safety_store);
    drop(signer_journal);

    let host = PocoNodeValidationRecoveryHostV0::open_existing(
        PocoNodeValidationRecoveryConfigV0::new(
            start.clone(),
            &application_status,
            SIGNER_POLICY_HASH,
        )
        .expect("valid O+D recovery config"),
        watermark.clone(),
    )
    .expect("O+D recovery must durably reach C+K");
    assert_eq!(
        host.recovery(),
        ValidationRecoveryBootstrapV0::ObligationCompleted {
            route,
            validation_id,
            completion_revision: obligation_revision + 1,
            source: ValidationRecoverySourceStateV0::Delivered,
        }
    );
    assert_eq!(host.pending_inert_effect_count(), 0);
    assert_exact_invalid_completion_v0(
        host.safety_state(),
        route,
        validation_id,
        obligation_revision,
    );
    assert_live_host_holds_official_lock_v0(&start, &application_status, watermark.clone());
    drop(host);

    assert_reopened_c_k_v0(
        &start,
        &application_status,
        watermark,
        route,
        validation_id,
        obligation_revision,
    );
}

fn exercise_c_d_recovery_case_v0(
    route: PayloadValidationRouteV0,
    reason: NativeValidationRecoveredInvalidReasonV0,
) {
    let PendingRecoveryCaseV0 {
        _root,
        start,
        watermark,
        application_status,
        original_core,
        safety_store,
        signer_journal,
        recovery_session,
        validation_id,
        obligation_revision,
    } = prepare_pending_recovery_case_v0(route, reason);
    let mut application = NativeValidationRecoveryStoreV0::open_existing_v8(
        application_recovery_config_v0(&application_status, &safety_store),
    )
    .expect("production application recovery facade opens P");
    let (recovered_core, request, callback_facts) = activate_and_record_delivered_v0(
        recovery_session,
        &mut application,
        route,
        validation_id,
        reason,
        obligation_revision,
    );

    // The initial store is affined to the pre-crash Core. Reopen and bind it
    // to the authentic recovery Core before persisting that Core's exact C.
    drop(original_core);
    drop(safety_store);
    let mut completion_store = SqliteSafetyStateStoreV0::open_existing(
        start.safety_store_path.clone(),
        start.safety_store_profile.clone(),
        StrictEd25519Verifier,
    )
    .expect("reopen real SafetyStore for recovered Core");
    completion_store
        .bind_core_v0(recovered_core.safety_state_persistence_binding_v0())
        .expect("bind exact recovered Core to SafetyStore");
    let context = native_invalid_transition_context_v0(&callback_facts, request.state().revision())
        .expect("construct complete application-derived transition context");
    completion_store
        .persist_exact_v0(&request, &context)
        .expect("persist exact C without acknowledging application or Core");
    let confirmed = completion_store
        .confirmed_native_deterministic_invalid_head_exact_v0(request.state(), &context)
        .expect("authenticate exact C readback");
    assert_eq!(confirmed.revision(), obligation_revision + 1);
    assert_eq!(confirmed.transition().route(), route);
    assert_eq!(confirmed.transition().validation_id(), validation_id);
    assert_eq!(confirmed.transition().reason_code(), reason.code_v0());
    assert_exact_invalid_completion_v0(
        confirmed.state(),
        route,
        validation_id,
        obligation_revision,
    );

    // Crash entry C+D: do not recover/ack the application row and do not send
    // StorageAck to Core. The official host must authenticate C and close K.
    application
        .final_exact_audit_v0()
        .expect("Delivered application row remains exact before simulated crash");
    drop(confirmed);
    drop(request);
    drop(recovered_core);
    drop(completion_store);
    drop(application);
    drop(signer_journal);

    let host = PocoNodeValidationRecoveryHostV0::open_existing(
        PocoNodeValidationRecoveryConfigV0::new(
            start.clone(),
            &application_status,
            SIGNER_POLICY_HASH,
        )
        .expect("valid C+D recovery config"),
        watermark.clone(),
    )
    .expect("C+D recovery must durably reach K without a synthetic StorageAck");
    assert_eq!(
        host.recovery(),
        ValidationRecoveryBootstrapV0::CompletionConfirmed {
            route,
            validation_id,
            completion_revision: obligation_revision + 1,
            source: ValidationRecoverySourceStateV0::Delivered,
        }
    );
    assert_eq!(host.pending_inert_effect_count(), 0);
    assert_exact_invalid_completion_v0(
        host.safety_state(),
        route,
        validation_id,
        obligation_revision,
    );
    assert_live_host_holds_official_lock_v0(&start, &application_status, watermark.clone());
    drop(host);

    assert_reopened_c_k_v0(
        &start,
        &application_status,
        watermark,
        route,
        validation_id,
        obligation_revision,
    );
}

#[test]
fn strict_three_store_recovery_matrix_closes_o_p_o_d_c_d_and_c_k() {
    for route in [
        PayloadValidationRouteV0::Proposal,
        PayloadValidationRouteV0::Synced,
    ] {
        for reason in [
            NativeValidationRecoveredInvalidReasonV0::ComputedStateRootMismatch,
            NativeValidationRecoveredInvalidReasonV0::ComputedReceiptsRootMismatch,
        ] {
            exercise_recovery_case_v0(route, reason);
            exercise_o_d_recovery_case_v0(route, reason);
            exercise_c_d_recovery_case_v0(route, reason);
        }
    }
}
