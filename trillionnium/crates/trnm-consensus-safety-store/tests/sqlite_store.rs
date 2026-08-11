use std::{
    fs,
    path::{Path, PathBuf},
};

use rusqlite::Connection;
use tempfile::TempDir;
use trnm_consensus_core::{
    leader_for, Core, CoreConfig, Effect, Input, PayloadValidationResult, SafetyState,
    SafetyStatePersistenceV0, SafetyStateRecordLimitsV0, ValidationId,
};
use trnm_consensus_safety_store::{
    NativeDeterministicInvalidTransitionV0, SafetyPersistDispositionV0, SafetyStateStoreProfileV0,
    SafetyStoreConflictV0, SafetyStoreErrorV0, SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
    NATIVE_INVALID_REASON_RECEIPTS_ROOT_MISMATCH_V0, NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0,
};
use trnm_consensus_types::{
    ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, BlockKind, ChainId,
    ConsensusParametersV0, ConsensusPublicKey, Epoch, ExecutionReceiptCommitmentV0,
    ExecutionReceiptsV0, GenesisHash, GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion,
    QcReferenceV0, SignatureBytes, SignatureVerifier, SignedProposalV0, SigningRoot, StateRoot,
    Validator, ValidatorId, ValidatorSet, View, VotingPower, SIGNATURE_BYTES,
};

const TRUSTED_GENESIS_TIMESTAMP_MS: u64 = 17;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_DATABASE_BYTES: usize = 192 * 1024 * 1024;

fn protected_temp_dir() -> TempDir {
    let directory = TempDir::new().expect("temporary directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("protect temporary safety-store directory");
    }
    directory
}

#[derive(Debug, Clone, Copy)]
struct AcceptSignatures;

impl SignatureVerifier for AcceptSignatures {
    fn verify(
        &self,
        _validator: &Validator,
        _signing_root: &SigningRoot,
        _signature: &SignatureBytes,
    ) -> bool {
        true
    }
}

fn validator_id(index: u8) -> ValidatorId {
    ValidatorId::new([index; 32])
}

fn test_config() -> CoreConfig {
    test_config_with_timestamp(TRUSTED_GENESIS_TIMESTAMP_MS)
}

fn test_config_with_timestamp(trusted_genesis_timestamp_ms: u64) -> CoreConfig {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let validators = (1u8..=4)
        .map(|index| {
            Validator::new(
                validator_id(index),
                ConsensusPublicKey::new([index.saturating_add(100); 32]),
                VotingPower::new(1).expect("positive voting power"),
            )
            .expect("valid validator")
        })
        .collect();
    let validator_set = ValidatorSet::new(
        GenesisHash::new([0xA5; 32]),
        ChainId::from_static("trnm-safety-store-integration"),
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .expect("valid validator set");
    CoreConfig::new(
        validator_id(1),
        validator_set,
        parameters,
        trusted_genesis_timestamp_ms,
        64,
        64,
    )
    .expect("valid Core config")
}

fn profile(config: &CoreConfig) -> SafetyStateStoreProfileV0 {
    profile_with_ref(config, [0x71; 32])
}

fn profile_with_ref(
    config: &CoreConfig,
    verifier_profile_ref: [u8; 32],
) -> SafetyStateStoreProfileV0 {
    SafetyStateStoreProfileV0::new(
        config.clone(),
        verifier_profile_ref,
        SafetyStateRecordLimitsV0::new(MAXIMUM_RECORD_BYTES, MAXIMUM_BLOB_BYTES)
            .expect("valid record limits"),
        MAXIMUM_DATABASE_BYTES,
    )
    .expect("capacity-compatible safety-store profile")
}

fn genesis_state(config: &CoreConfig) -> SafetyState {
    Core::new(
        config.clone(),
        genesis_qc(config.validator_set()),
        &AcceptSignatures,
    )
    .expect("valid genesis Core")
    .safety_state()
    .clone()
}

fn genesis_qc(set: &ValidatorSet) -> GenesisQcV0 {
    GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).expect("valid trusted GenesisQC")
}

fn open_error(path: &Path, profile: SafetyStateStoreProfileV0) -> SafetyStoreErrorV0 {
    match SqliteSafetyStateStoreV0::open_existing(path, profile, AcceptSignatures) {
        Ok(_) => panic!("opening the safety store unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut file_name = path
        .file_name()
        .expect("test database path has a file name")
        .to_os_string();
    file_name.push(suffix);
    path.with_file_name(file_name)
}

fn persistence_effect(effects: &[Effect]) -> SafetyStatePersistenceV0 {
    match effects {
        [Effect::PersistSafetyState(request)] => request.clone(),
        _ => panic!("expected exactly one persistence effect: {effects:?}"),
    }
}

fn validation_effect(effects: &[Effect]) -> ValidationId {
    effects
        .iter()
        .find_map(|effect| match effect {
            Effect::ValidatePayload(request) => Some(request.id()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected one payload-validation request: {effects:?}"))
}

fn invalid_proposal(config: &CoreConfig) -> SignedProposalV0 {
    let set = config.validator_set();
    let parameters = config.consensus_parameters();
    let justify = QcReferenceV0::genesis_anchor(genesis_qc(set));
    let application_payload =
        ApplicationPayloadV0::new(vec![b"durable-invalid".to_vec()]).expect("valid payload");
    let receipt =
        ExecutionReceiptCommitmentV0::for_transaction(&application_payload, 0, 0, 0, Vec::new())
            .expect("valid receipt");
    let receipts =
        ExecutionReceiptsV0::new(&application_payload, vec![receipt]).expect("valid receipt list");
    let body = BlockBodyV0::new(application_payload, Vec::new()).expect("valid block body");
    let view = View::new(1);
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        view,
        Height::new(1),
        BlockKind::Regular,
        justify.qc_ref().block_id(),
        leader_for(set, view),
        set.id(),
        set.consensus_parameters_hash(),
        body.payload_root().expect("payload root"),
        StateRoot::new([0x51; 32]),
        receipts.receipts_root().expect("receipts root"),
        body.evidence_root().expect("evidence root"),
        TRUSTED_GENESIS_TIMESTAMP_MS + 1,
        None,
    )
    .expect("valid target header");
    let block = Block::new(
        header,
        body.application_payload()
            .try_cev0_bytes()
            .expect("canonical application payload"),
        Vec::new(),
    )
    .expect("valid target block");
    let signing_root = ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
        .expect("valid proposal signing root");
    let mut signature = [0u8; SIGNATURE_BYTES];
    signature[..32].copy_from_slice(signing_root.as_bytes());
    signature[32..].copy_from_slice(signing_root.as_bytes());
    let witness = ProposalWitnessV0::new(
        block.header(),
        justify,
        None,
        None,
        SignatureBytes::from_array(signature),
        set,
        None,
        parameters,
        TRUSTED_GENESIS_TIMESTAMP_MS,
    )
    .expect("valid proposal witness");
    SignedProposalV0::new(
        block,
        witness,
        set,
        None,
        parameters,
        TRUSTED_GENESIS_TIMESTAMP_MS,
    )
    .expect("valid signed proposal")
}

fn native_invalid_context(
    id: ValidationId,
    revision: u64,
    reason_code: u32,
) -> SafetyTransitionContextV0 {
    SafetyTransitionContextV0::native_deterministic_invalid(
        NativeDeterministicInvalidTransitionV0::new(
            trnm_consensus_core::PayloadValidationRouteV0::Proposal,
            id,
            [0x21; 32],
            [0x22; 32],
            [0x23; 32],
            reason_code,
            [0x24; 32],
            [0x25; 32],
            [0x26; 32],
            1,
            [0x27; 32],
            [0x28; 32],
            revision,
        )
        .expect("valid native-invalid transition facts"),
    )
}

#[test]
fn initializes_reads_head_and_reopens_exactly() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("safety.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let genesis = genesis_state(&config);

    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize safety store");
    let head = store.head().expect("read initialized head");
    assert_eq!(head.revision(), 0);
    assert_eq!(head.state(), &genesis);
    assert_eq!(
        head.transition_context(),
        &SafetyTransitionContextV0::Ordinary
    );
    assert!(!head.requires_authenticated_obligation_replay());
    assert!(matches!(
        store.confirmed_native_deterministic_invalid_head_v0(),
        Err(SafetyStoreErrorV0::MissingNativeDeterministicInvalidTransition { revision: 0 })
    ));
    drop(store);

    let reopened = SqliteSafetyStateStoreV0::open_existing(&path, profile, AcceptSignatures)
        .expect("reopen initialized safety store");
    assert_eq!(
        reopened.head().expect("read reopened head").state(),
        &genesis
    );
}

#[test]
fn lifetime_lock_rejects_a_second_open_and_releases_on_drop() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("locked.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let genesis = genesis_state(&config);
    let first = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize first store");

    assert!(matches!(
        open_error(&path, profile.clone()),
        SafetyStoreErrorV0::Locked
    ));
    drop(first);
    SqliteSafetyStateStoreV0::open_existing(&path, profile, AcceptSignatures)
        .expect("lifetime lock is released with its store");
}

#[test]
fn exact_retries_preserve_two_revision_retention_and_reopen_head() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("retention.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let mut core = Core::new(
        config.clone(),
        genesis_qc(config.validator_set()),
        &AcceptSignatures,
    )
    .expect("valid Core");
    let genesis = core.safety_state().clone();
    let mut store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize safety store");
    store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .expect("bind designated Core");
    let effects = core
        .step(
            Input::Proposal(Box::new(invalid_proposal(&config))),
            &AcceptSignatures,
        )
        .expect("proposal creates first persistence request");
    let revision_one = persistence_effect(&effects);

    assert_eq!(
        store
            .persist_exact_v0(&revision_one, &SafetyTransitionContextV0::Ordinary)
            .expect("persist revision one"),
        SafetyPersistDispositionV0::Inserted
    );
    assert_eq!(
        store
            .persist_exact_v0(&revision_one, &SafetyTransitionContextV0::Ordinary)
            .expect("retry revision one"),
        SafetyPersistDispositionV0::Existing
    );
    let validation_effects = core
        .step(
            Input::StorageAck {
                barrier: revision_one.barrier(),
            },
            &AcceptSignatures,
        )
        .expect("release validation request");
    let id = validation_effect(&validation_effects);
    let effects = core
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &AcceptSignatures,
        )
        .expect("callback creates second persistence request");
    let revision_two = persistence_effect(&effects);
    let revision_two_context = native_invalid_context(
        id,
        revision_two.state().revision(),
        NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0,
    );
    assert_eq!(
        store
            .persist_exact_v0(&revision_two, &revision_two_context)
            .expect("persist revision two"),
        SafetyPersistDispositionV0::Inserted
    );
    let journal_id = store.journal_id_v0();
    let verifier_profile_ref = store.verifier_profile_ref_v0();
    assert_eq!(verifier_profile_ref, profile.verifier_profile_ref());
    let authenticated_head = store.head().expect("revision two head");
    assert_eq!(authenticated_head.state(), revision_two.state());
    let confirmed = store
        .confirmed_native_deterministic_invalid_head_v0()
        .expect("confirm native deterministic-invalid revision two head");
    assert_eq!(confirmed.journal_id_v0(), journal_id);
    assert_eq!(confirmed.verifier_profile_ref_v0(), verifier_profile_ref);
    assert_eq!(confirmed.revision(), authenticated_head.revision());
    assert_eq!(confirmed.state(), authenticated_head.state());
    assert_eq!(
        confirmed.transition_context(),
        authenticated_head.transition_context()
    );
    assert_eq!(
        confirmed.transition(),
        revision_two_context
            .native_invalid()
            .expect("native deterministic-invalid context")
    );
    assert_eq!(
        confirmed.state_record_checksum(),
        authenticated_head.state_record_checksum()
    );
    assert_eq!(
        confirmed.chain_checksum(),
        authenticated_head.chain_checksum()
    );
    let exact_confirmed = store
        .confirmed_native_deterministic_invalid_head_exact_v0(
            revision_two.state(),
            &revision_two_context,
        )
        .expect("confirm exact expected revision two head");
    assert_eq!(exact_confirmed.journal_id_v0(), journal_id);
    assert_eq!(
        exact_confirmed.verifier_profile_ref_v0(),
        verifier_profile_ref
    );
    assert_eq!(exact_confirmed.revision(), revision_two.state().revision());
    assert!(matches!(
        store.confirmed_native_deterministic_invalid_head_exact_v0(
            revision_one.state(),
            &revision_two_context,
        ),
        Err(SafetyStoreErrorV0::NativeDeterministicInvalidHeadMismatch {
            expected_revision: 1,
            actual_revision: 2,
        })
    ));
    let wrong_expected_context = native_invalid_context(
        id,
        revision_two.state().revision(),
        NATIVE_INVALID_REASON_RECEIPTS_ROOT_MISMATCH_V0,
    );
    assert!(matches!(
        store.confirmed_native_deterministic_invalid_head_exact_v0(
            revision_two.state(),
            &wrong_expected_context,
        ),
        Err(SafetyStoreErrorV0::NativeDeterministicInvalidHeadMismatch {
            expected_revision: 2,
            actual_revision: 2,
        })
    ));
    assert_eq!(
        store
            .confirmed_native_deterministic_invalid_head_exact_v0(
                revision_two.state(),
                &revision_two_context,
            )
            .expect("exact retry returns the same authenticated facts")
            .transition_context(),
        &revision_two_context
    );

    let unrelated_path = temporary.path().join("unrelated-fresh.sqlite3");
    let unrelated = SqliteSafetyStateStoreV0::initialize_new(
        &unrelated_path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize unrelated fresh safety store");
    assert_ne!(unrelated.journal_id_v0(), journal_id);
    assert_eq!(unrelated.verifier_profile_ref_v0(), verifier_profile_ref);
    drop(unrelated);
    drop(store);

    let reopened = SqliteSafetyStateStoreV0::open_existing(&path, profile, AcceptSignatures)
        .expect("reopen two-revision journal");
    let reopened_head = reopened.head().expect("reopened head");
    assert_eq!(reopened_head.state(), revision_two.state());
    let reopened_confirmed = reopened
        .confirmed_native_deterministic_invalid_head_v0()
        .expect("reopened store confirms native deterministic-invalid head");
    assert_eq!(reopened.journal_id_v0(), journal_id);
    assert_eq!(reopened.verifier_profile_ref_v0(), verifier_profile_ref);
    assert_eq!(reopened_confirmed.journal_id_v0(), journal_id);
    assert_eq!(
        reopened_confirmed.verifier_profile_ref_v0(),
        verifier_profile_ref
    );
    assert_eq!(reopened_confirmed.state(), reopened_head.state());
    assert_eq!(
        reopened_confirmed.transition_context(),
        reopened_head.transition_context()
    );
    assert_eq!(
        reopened_confirmed.state_record_checksum(),
        reopened_head.state_record_checksum()
    );
    assert_eq!(
        reopened_confirmed.chain_checksum(),
        reopened_head.chain_checksum()
    );

    let connection = Connection::open(&path).expect("open journal for read-only assertion");
    let revisions = connection
        .prepare("SELECT revision_be FROM safety_state_records_v0 ORDER BY revision_be")
        .expect("prepare retained revision query")
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query retained revisions")
        .map(|row| {
            let bytes: [u8; 8] = row
                .expect("read retained revision")
                .try_into()
                .expect("fixed-width revision");
            u64::from_be_bytes(bytes)
        })
        .collect::<Vec<_>>();
    assert_eq!(revisions, vec![1, 2]);
    drop(connection);

    let connection = Connection::open(&path).expect("open raw SQLite tamper connection");
    enable_persistent_wal_for_raw_connection(&connection);
    assert_eq!(
        connection
            .execute(
                "UPDATE safety_state_records_v0 \
                 SET transition_context_checksum=zeroblob(32) \
                 WHERE revision_be=x'0000000000000002'",
                [],
            )
            .expect("tamper native deterministic-invalid transition checksum"),
        1
    );
    drop(connection);
    assert!(matches!(
        reopened.confirmed_native_deterministic_invalid_head_v0(),
        Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "record-chain checksum"
        ))
    ));
}

#[test]
fn persistence_requires_the_one_designated_core_affinity() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("core-affinity.sqlite3");
    let config = test_config();
    let mut core = Core::new(
        config.clone(),
        genesis_qc(config.validator_set()),
        &AcceptSignatures,
    )
    .expect("valid designated Core");
    let mut foreign = core.clone();
    let genesis = core.safety_state().clone();
    let mut store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile(&config),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize unbound safety store");

    let foreign_request = persistence_effect(
        &foreign
            .step(
                Input::Proposal(Box::new(invalid_proposal(&config))),
                &AcceptSignatures,
            )
            .expect("foreign clone emits a genuine but foreign request"),
    );
    assert!(matches!(
        store.persist_exact_v0(&foreign_request, &SafetyTransitionContextV0::Ordinary),
        Err(SafetyStoreErrorV0::CoreNotBound)
    ));

    store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .expect("bind designated Core exactly once");
    assert!(matches!(
        store.bind_core_v0(foreign.safety_state_persistence_binding_v0()),
        Err(SafetyStoreErrorV0::CoreAlreadyBound)
    ));
    assert!(matches!(
        store.persist_exact_v0(&foreign_request, &SafetyTransitionContextV0::Ordinary),
        Err(SafetyStoreErrorV0::CoreAffinityMismatch)
    ));
    assert_eq!(
        store
            .head()
            .expect("foreign request changed no state")
            .revision(),
        0
    );

    let designated_request = persistence_effect(
        &core
            .step(
                Input::Proposal(Box::new(invalid_proposal(&config))),
                &AcceptSignatures,
            )
            .expect("designated Core emits its request"),
    );
    assert_eq!(designated_request.barrier(), foreign_request.barrier());
    assert_eq!(designated_request.state(), foreign_request.state());
    assert_eq!(
        store
            .persist_exact_v0(&designated_request, &SafetyTransitionContextV0::Ordinary,)
            .expect("persist designated request"),
        SafetyPersistDispositionV0::Inserted
    );
}

#[test]
fn same_revision_different_valid_context_durably_halts() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("context-conflict.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let mut core = Core::new(
        config.clone(),
        genesis_qc(config.validator_set()),
        &AcceptSignatures,
    )
    .expect("valid Core");
    let genesis = core.safety_state().clone();
    let mut store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize safety store");
    store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .expect("bind designated Core");

    let effects = core
        .step(
            Input::Proposal(Box::new(invalid_proposal(&config))),
            &AcceptSignatures,
        )
        .expect("proposal creates durable validation obligation");
    let obligation = persistence_effect(&effects);
    store
        .persist_exact_v0(&obligation, &SafetyTransitionContextV0::Ordinary)
        .expect("persist obligation state");
    let validation_effects = core
        .step(
            Input::StorageAck {
                barrier: obligation.barrier(),
            },
            &AcceptSignatures,
        )
        .expect("release validation request");
    let id = validation_effect(&validation_effects);
    let effects = core
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &AcceptSignatures,
        )
        .expect("invalid callback creates terminal persistence barrier");
    let completion = persistence_effect(&effects);
    let state_reason = native_invalid_context(
        id,
        completion.state().revision(),
        NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0,
    );
    let receipts_reason = native_invalid_context(
        id,
        completion.state().revision(),
        NATIVE_INVALID_REASON_RECEIPTS_ROOT_MISMATCH_V0,
    );
    store
        .persist_exact_v0(&completion, &state_reason)
        .expect("persist exact invalid callback context");

    assert!(matches!(
        store.persist_exact_v0(&completion, &receipts_reason),
        Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::SameRevisionDifferentRecord { revision }
        )) if revision == completion.state().revision()
    ));
    assert!(matches!(store.head(), Err(SafetyStoreErrorV0::DurableHalt)));
    drop(store);

    // Model power loss / a failed SQLite halt COMMIT after the terminal halt
    // latch reached the fsynced sidecar: the redundant halt row is absent,
    // but the exact conflict must never become retryable or resolve to Stable.
    let connection = Connection::open(&path).expect("open halted SQLite journal directly");
    enable_persistent_wal_for_raw_connection(&connection);
    assert_eq!(
        connection
            .execute("DELETE FROM safety_store_halt_v0 WHERE singleton=1", [])
            .expect("remove redundant SQLite halt row"),
        1
    );
    drop(connection);
    assert!(matches!(
        open_error(&path, profile.clone()),
        SafetyStoreErrorV0::DurableHalt
    ));

    // A terminal sidecar is not an excuse to skip validating the database it
    // names. Corruption must win over the final DurableHalt disposition.
    let connection = Connection::open(&path).expect("open halted journal for accounting tamper");
    enable_persistent_wal_for_raw_connection(&connection);
    assert_eq!(
        connection
            .execute(
                "UPDATE safety_state_accounting_v0 SET state_bytes=state_bytes+1 WHERE singleton=1",
                [],
            )
            .expect("tamper halted journal accounting"),
        1
    );
    drop(connection);
    assert!(matches!(
        open_error(&path, profile),
        SafetyStoreErrorV0::PersistedRepresentationMalformed("safety-store accounting mismatch")
    ));
}

#[test]
fn revision_gap_durably_halts_and_survives_reopen() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("revision-gap.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let mut core = Core::new(
        config.clone(),
        genesis_qc(config.validator_set()),
        &AcceptSignatures,
    )
    .expect("valid Core");
    let genesis = core.safety_state().clone();
    let mut store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize safety store");
    store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .expect("bind designated Core");
    let effects = core
        .step(
            Input::Proposal(Box::new(invalid_proposal(&config))),
            &AcceptSignatures,
        )
        .expect("proposal creates revision one");
    let revision_one = persistence_effect(&effects);
    let validation_effects = core
        .step(
            Input::StorageAck {
                barrier: revision_one.barrier(),
            },
            &AcceptSignatures,
        )
        .expect("release validation request without writing revision one");
    let id = validation_effect(&validation_effects);
    let effects = core
        .step(
            Input::PayloadValidated {
                id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            },
            &AcceptSignatures,
        )
        .expect("callback creates revision two");
    let revision_two = persistence_effect(&effects);
    let context = native_invalid_context(
        id,
        revision_two.state().revision(),
        NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0,
    );

    assert!(matches!(
        store.persist_exact_v0(&revision_two, &context),
        Err(SafetyStoreErrorV0::Conflict(
            SafetyStoreConflictV0::RevisionGap {
                active: 0,
                incoming: 2
            }
        ))
    ));
    assert!(matches!(store.head(), Err(SafetyStoreErrorV0::DurableHalt)));
    drop(store);
    assert!(matches!(
        open_error(&path, profile),
        SafetyStoreErrorV0::DurableHalt
    ));
}

#[test]
fn profile_and_core_binding_mismatches_fail_closed() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("binding.sqlite3");
    let config = test_config();
    let genesis = genesis_state(&config);
    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile(&config),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize safety store");
    drop(store);

    assert!(matches!(
        open_error(&path, profile_with_ref(&config, [0x72; 32])),
        SafetyStoreErrorV0::MetadataMismatch
    ));
    assert!(matches!(
        open_error(
            &path,
            profile(&test_config_with_timestamp(
                TRUSTED_GENESIS_TIMESTAMP_MS + 1
            )),
        ),
        SafetyStoreErrorV0::MetadataMismatch
    ));
}

fn initialize_then_tamper(path: &Path, sql: &str) -> SafetyStoreErrorV0 {
    let config = test_config();
    let profile = profile(&config);
    let genesis = genesis_state(&config);
    let store =
        SqliteSafetyStateStoreV0::initialize_new(path, profile.clone(), AcceptSignatures, &genesis)
            .expect("initialize tamper fixture");
    drop(store);
    let connection = Connection::open(path).expect("open raw SQLite tamper connection");
    enable_persistent_wal_for_raw_connection(&connection);
    assert_eq!(
        connection
            .execute(sql, [])
            .expect("apply raw SQLite tamper"),
        1
    );
    drop(connection);
    open_error(path, profile)
}

fn enable_persistent_wal_for_raw_connection(connection: &Connection) {
    let mut persistent_wal = 1i32;
    // SAFETY: the connection is live, `main` is a static NUL-terminated name,
    // and SQLite specifies an `int *` argument for this file-control opcode.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            (&mut persistent_wal as *mut i32).cast(),
        )
    };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    assert_eq!(persistent_wal, 1);
}

#[test]
fn raw_sqlite_accounting_head_and_record_tampering_is_rejected_on_reopen() {
    let temporary = protected_temp_dir();

    let accounting = initialize_then_tamper(
        &temporary.path().join("accounting.sqlite3"),
        "UPDATE safety_state_accounting_v0 SET state_bytes=state_bytes+1 WHERE singleton=1",
    );
    assert!(matches!(
        accounting,
        SafetyStoreErrorV0::PersistedRepresentationMalformed("safety-store accounting mismatch")
    ));

    let head = initialize_then_tamper(
        &temporary.path().join("head.sqlite3"),
        "UPDATE safety_state_head_v0 SET head_checksum=zeroblob(32) WHERE singleton=1",
    );
    assert!(matches!(
        head,
        SafetyStoreErrorV0::PersistedRepresentationMalformed("head checksum or retention floor")
    ));

    let record = initialize_then_tamper(
        &temporary.path().join("record.sqlite3"),
        "UPDATE safety_state_records_v0 SET transition_context_checksum=zeroblob(32)",
    );
    assert!(matches!(
        record,
        SafetyStoreErrorV0::PersistedRepresentationMalformed("record-chain checksum")
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn peer_writable_immediate_parent_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = protected_temp_dir();
    let parent = temporary.path().join("peer-writable");
    fs::create_dir(&parent).expect("create safety-store parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o770))
        .expect("make safety-store parent peer-writable");
    let path = parent.join("safety.sqlite3");
    let config = test_config();
    let genesis = genesis_state(&config);

    assert!(matches!(
        SqliteSafetyStateStoreV0::initialize_new(
            &path,
            profile(&config),
            AcceptSignatures,
            &genesis,
        ),
        Err(SafetyStoreErrorV0::InvalidProfile(
            "safety-store parent must be owner-controlled and non-writable by peers"
        ))
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn initialization_requires_a_preexisting_protected_parent_directory() {
    let temporary = protected_temp_dir();
    let missing_parent = temporary.path().join("not-created-by-store");
    let path = missing_parent.join("safety.sqlite3");
    let config = test_config();
    let genesis = genesis_state(&config);

    assert!(matches!(
        SqliteSafetyStateStoreV0::initialize_new(
            &path,
            profile(&config),
            AcceptSignatures,
            &genesis,
        ),
        Err(SafetyStoreErrorV0::Missing(
            "pre-existing safety-store parent directory"
        ))
    ));
    assert!(!missing_parent.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn sqlite_auxiliary_namespace_database_names_are_rejected_case_insensitively() {
    let temporary = protected_temp_dir();
    let config = test_config();
    let genesis = genesis_state(&config);

    for file_name in ["safety-WAL", "safety-ShM", "safety-JOURNAL"] {
        let path = temporary.path().join(file_name);
        assert!(matches!(
            SqliteSafetyStateStoreV0::initialize_new(
                &path,
                profile(&config),
                AcceptSignatures,
                &genesis,
            ),
            Err(SafetyStoreErrorV0::InvalidProfile(
                "database name collides with SQLite auxiliary namespace"
            ))
        ));

        fs::write(&path, []).expect("create existing reserved-name fixture");
        assert!(matches!(
            open_error(&path, profile(&config)),
            SafetyStoreErrorV0::InvalidProfile(
                "database name collides with SQLite auxiliary namespace"
            )
        ));
        fs::remove_file(&path).expect("remove existing reserved-name fixture");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn preplanted_sqlite_auxiliary_files_are_rejected_before_initialization() {
    let temporary = protected_temp_dir();
    let config = test_config();
    let genesis = genesis_state(&config);

    for (index, suffix) in ["-wal", "-shm", "-journal"].into_iter().enumerate() {
        let path = temporary.path().join(format!("preplanted-{index}.sqlite3"));
        let auxiliary_path = path_with_suffix(&path, suffix);
        fs::write(&auxiliary_path, b"untrusted preplanted bytes")
            .expect("preplant SQLite auxiliary file");

        assert!(matches!(
            SqliteSafetyStateStoreV0::initialize_new(
                &path,
                profile(&config),
                AcceptSignatures,
                &genesis,
            ),
            Err(SafetyStoreErrorV0::AlreadyExists("SQLite auxiliary file"))
        ));
        assert!(
            !path.exists(),
            "database must not be created after rejection"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn deleting_persistent_wal_or_shm_after_close_fails_reopen_closed() {
    let temporary = protected_temp_dir();
    let config = test_config();
    let genesis = genesis_state(&config);

    for (index, suffix, missing) in [(0, "-wal", "persistent WAL"), (1, "-shm", "persistent SHM")] {
        let path = temporary
            .path()
            .join(format!("missing-aux-{index}.sqlite3"));
        let store = SqliteSafetyStateStoreV0::initialize_new(
            &path,
            profile(&config),
            AcceptSignatures,
            &genesis,
        )
        .expect("initialize safety store");
        drop(store);

        let auxiliary_path = path_with_suffix(&path, suffix);
        assert!(
            auxiliary_path.is_file(),
            "persistent SQLite auxiliary must survive clean close"
        );
        fs::remove_file(&auxiliary_path).expect("remove persistent SQLite auxiliary");
        assert!(matches!(
            open_error(&path, profile(&config)),
            SafetyStoreErrorV0::Missing(target) if target == missing
        ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn tampered_only_valid_lock_watermark_slot_is_rejected_on_reopen() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("watermark.sqlite3");
    let config = test_config();
    let genesis = genesis_state(&config);
    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile(&config),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize safety store");
    drop(store);

    let lock_path = path_with_suffix(&path, ".safety.lock");
    let mut header = fs::read(&lock_path).expect("read lock header");
    let protected_byte = header
        .get_mut(42)
        .expect("first watermark slot contains protected bytes");
    *protected_byte ^= 1;
    fs::write(&lock_path, header).expect("tamper lock head watermark");

    assert!(matches!(
        open_error(&path, profile(&config)),
        SafetyStoreErrorV0::PersistedRepresentationMalformed("no valid lock watermark slot")
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn hard_linked_database_with_copied_lock_sidecar_cannot_bypass_lifetime_ownership() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("canonical-live.sqlite3");
    let alias = temporary.path().join("hardlink-live.sqlite3");
    let config = test_config();
    let genesis = genesis_state(&config);
    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile(&config),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize canonical store");

    fs::hard_link(&path, &alias).expect("create hard link to live database");
    fs::copy(
        path_with_suffix(&path, ".safety.lock"),
        path_with_suffix(&alias, ".safety.lock"),
    )
    .expect("copy lock sidecar into alias namespace");

    assert!(matches!(
        open_error(&alias, profile(&config)),
        SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "safety-store file identity or permissions"
        )
    ));
    drop(store);
}

#[cfg(unix)]
#[test]
fn symlink_alias_contends_on_the_same_lifetime_lock() {
    use std::os::unix::fs::symlink;

    let temporary = protected_temp_dir();
    let path = temporary.path().join("canonical.sqlite3");
    let alias = temporary.path().join("alias.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let genesis = genesis_state(&config);
    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize canonical store");
    symlink(&path, &alias).expect("create database symlink alias");

    assert!(matches!(
        open_error(&alias, profile),
        SafetyStoreErrorV0::Locked
    ));
    drop(store);
}

#[cfg(unix)]
#[test]
fn hard_linked_database_is_rejected_before_open() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("canonical.sqlite3");
    let alias = temporary.path().join("hardlink.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let genesis = genesis_state(&config);
    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize canonical store");
    drop(store);
    fs::hard_link(&path, &alias).expect("create hard link to database");

    assert!(matches!(
        open_error(&path, profile),
        SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "safety-store file identity or permissions"
        )
    ));
}
