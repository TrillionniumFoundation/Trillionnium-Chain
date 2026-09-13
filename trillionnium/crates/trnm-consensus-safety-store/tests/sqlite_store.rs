use std::{
    fs,
    path::{Path, PathBuf},
};

use rusqlite::Connection;
use tempfile::TempDir;
use trnm_consensus_core::{
    leader_for, safety_state_record_config_ref_v0, BlockIdOverlayRefV0, Core, CoreConfig,
    CoreIssuedApplicationSealAuthorityV0, Effect, Input, NativeFinalizationAppliedPostAckActionV0,
    PayloadValidationRequest, PayloadValidationResult, PayloadValidationRouteV0, SafetyState,
    SafetyStatePersistenceV0, SafetyStateRecordContextV0, SafetyStateRecordLimitsV0,
    ValidatedPayloadArtifactRefV0, ValidationId,
};
use trnm_consensus_safety_store::{
    native_valid_result_checksum_v0, NativeDeterministicInvalidTransitionV0,
    NativeFinalizationAppliedTransitionV0, NativeValidTransitionV0, SafetyPersistDispositionV0,
    SafetyStateStoreProfileV0, SafetyStoreConflictV0, SafetyStoreErrorV0,
    SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
    NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_STANDALONE_QC_SYNC_V0,
    NATIVE_INVALID_REASON_RECEIPTS_ROOT_MISMATCH_V0, NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0,
    NATIVE_VALID_POST_ACK_REQUEST_SIGNATURE_V0,
};
use trnm_consensus_types::{
    ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, BlockId, BlockKind, ChainId,
    ConsensusParametersV0, ConsensusPublicKey, Epoch, ExecutionReceiptCommitmentV0,
    ExecutionReceiptsV0, GenesisHash, GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion,
    QcReferenceV0, QuorumCertificate, SignatureBytes, SignatureVerifier, SignedProposalV0,
    SigningRoot, StateRoot, ValidatedBlockCommitmentsV0, Validator, ValidatorId, ValidatorSet,
    View, Vote, VotingPower, SIGNATURE_BYTES,
};

const TRUSTED_GENESIS_TIMESTAMP_MS: u64 = 17;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_DATABASE_BYTES: usize = 192 * 1024 * 1024;

// Frozen historical metadata DDL. The remaining journal tables are byte-for-
// byte identical across v2-v5; only this table binds the journal schema to the
// Core SafetyState schema. These fixtures are intentionally not produced by
// rewriting the current DDL.
const HISTORICAL_JOURNAL_V5_METADATA_DDL: &str = "
    CREATE TABLE safety_store_metadata_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        journal_schema INTEGER NOT NULL CHECK(journal_schema=5),
        journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
        core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
        safety_schema INTEGER NOT NULL CHECK(safety_schema=11),
        core_config_ref BLOB NOT NULL CHECK(length(core_config_ref)=32),
        verifier_profile_ref BLOB NOT NULL CHECK(length(verifier_profile_ref)=32),
        maximum_record_bytes_be BLOB NOT NULL CHECK(length(maximum_record_bytes_be)=8),
        maximum_blob_bytes_be BLOB NOT NULL CHECK(length(maximum_blob_bytes_be)=8),
        maximum_database_bytes_be BLOB NOT NULL CHECK(length(maximum_database_bytes_be)=8),
        transition_codec INTEGER NOT NULL CHECK(transition_codec=0),
        metadata_checksum BLOB NOT NULL CHECK(length(metadata_checksum)=32)
    ) STRICT;
";

const HISTORICAL_JOURNAL_V4_METADATA_DDL: &str = "
    CREATE TABLE safety_store_metadata_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        journal_schema INTEGER NOT NULL CHECK(journal_schema=4),
        journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
        core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
        safety_schema INTEGER NOT NULL CHECK(safety_schema=10),
        core_config_ref BLOB NOT NULL CHECK(length(core_config_ref)=32),
        verifier_profile_ref BLOB NOT NULL CHECK(length(verifier_profile_ref)=32),
        maximum_record_bytes_be BLOB NOT NULL CHECK(length(maximum_record_bytes_be)=8),
        maximum_blob_bytes_be BLOB NOT NULL CHECK(length(maximum_blob_bytes_be)=8),
        maximum_database_bytes_be BLOB NOT NULL CHECK(length(maximum_database_bytes_be)=8),
        transition_codec INTEGER NOT NULL CHECK(transition_codec=0),
        metadata_checksum BLOB NOT NULL CHECK(length(metadata_checksum)=32)
    ) STRICT;
";

const HISTORICAL_JOURNAL_V3_METADATA_DDL: &str = "
    CREATE TABLE safety_store_metadata_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        journal_schema INTEGER NOT NULL CHECK(journal_schema=3),
        journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
        core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
        safety_schema INTEGER NOT NULL CHECK(safety_schema=9),
        core_config_ref BLOB NOT NULL CHECK(length(core_config_ref)=32),
        verifier_profile_ref BLOB NOT NULL CHECK(length(verifier_profile_ref)=32),
        maximum_record_bytes_be BLOB NOT NULL CHECK(length(maximum_record_bytes_be)=8),
        maximum_blob_bytes_be BLOB NOT NULL CHECK(length(maximum_blob_bytes_be)=8),
        maximum_database_bytes_be BLOB NOT NULL CHECK(length(maximum_database_bytes_be)=8),
        transition_codec INTEGER NOT NULL CHECK(transition_codec=0),
        metadata_checksum BLOB NOT NULL CHECK(length(metadata_checksum)=32)
    ) STRICT;
";

const HISTORICAL_JOURNAL_V2_METADATA_DDL: &str = "
    CREATE TABLE safety_store_metadata_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        journal_schema INTEGER NOT NULL CHECK(journal_schema=2),
        journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
        core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
        safety_schema INTEGER NOT NULL CHECK(safety_schema=8),
        core_config_ref BLOB NOT NULL CHECK(length(core_config_ref)=32),
        verifier_profile_ref BLOB NOT NULL CHECK(length(verifier_profile_ref)=32),
        maximum_record_bytes_be BLOB NOT NULL CHECK(length(maximum_record_bytes_be)=8),
        maximum_blob_bytes_be BLOB NOT NULL CHECK(length(maximum_blob_bytes_be)=8),
        maximum_database_bytes_be BLOB NOT NULL CHECK(length(maximum_database_bytes_be)=8),
        transition_codec INTEGER NOT NULL CHECK(transition_codec=0),
        metadata_checksum BLOB NOT NULL CHECK(length(metadata_checksum)=32)
    ) STRICT;
";

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct JournalNamespaceFileImageV0 {
    bytes: Vec<u8>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    links: u64,
}

fn journal_namespace_image(path: &Path) -> Vec<(PathBuf, Option<JournalNamespaceFileImageV0>)> {
    [
        path.to_path_buf(),
        path_with_suffix(path, "-wal"),
        path_with_suffix(path, "-shm"),
        path_with_suffix(path, "-journal"),
        path_with_suffix(path, ".safety.lock"),
        path_with_suffix(path, ".safety.init.v0"),
        path_with_suffix(path, ".safety.init.v0.tmp"),
    ]
    .into_iter()
    .map(|component| {
        let image = match fs::symlink_metadata(&component) {
            Ok(metadata) => {
                #[cfg(unix)]
                use std::os::unix::fs::MetadataExt;

                #[cfg(not(unix))]
                let _ = &metadata;

                Some(JournalNamespaceFileImageV0 {
                    bytes: fs::read(&component).unwrap_or_else(|error| {
                        panic!(
                            "read safety-store namespace component {}: {error}",
                            component.display()
                        )
                    }),
                    #[cfg(unix)]
                    device: metadata.dev(),
                    #[cfg(unix)]
                    inode: metadata.ino(),
                    #[cfg(unix)]
                    mode: metadata.mode(),
                    #[cfg(unix)]
                    links: metadata.nlink(),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!(
                "snapshot safety-store namespace component {}: {error}",
                component.display()
            ),
        };
        (component, image)
    })
    .collect()
}

fn begin_historical_journal_rewrite(
    connection: &Connection,
    metadata_ddl: &str,
    journal_schema: i64,
    safety_schema: i64,
    empty: bool,
) {
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             BEGIN IMMEDIATE;
             ALTER TABLE safety_store_metadata_v0
                RENAME TO safety_store_metadata_current_fixture;",
        )
        .expect("begin historical journal fixture");
    connection
        .execute_batch(metadata_ddl)
        .expect("install frozen historical metadata DDL");
    if !empty {
        assert_eq!(
            connection
                .execute(
                    "INSERT INTO safety_store_metadata_v0(
                        singleton, journal_schema, journal_id, core_record_codec,
                        safety_schema, core_config_ref, verifier_profile_ref,
                        maximum_record_bytes_be, maximum_blob_bytes_be,
                        maximum_database_bytes_be, transition_codec, metadata_checksum
                     )
                     SELECT singleton, ?1, journal_id, core_record_codec, ?2,
                            core_config_ref, verifier_profile_ref,
                            maximum_record_bytes_be, maximum_blob_bytes_be,
                            maximum_database_bytes_be, transition_codec, metadata_checksum
                     FROM safety_store_metadata_current_fixture",
                    [journal_schema, safety_schema],
                )
                .expect("copy historical metadata row"),
            1
        );
    }
    connection
        .execute_batch("DROP TABLE safety_store_metadata_current_fixture;")
        .expect("drop current metadata fixture");
    if empty {
        connection
            .execute_batch(
                "DELETE FROM safety_state_head_v0 WHERE 1;
                 DELETE FROM safety_state_accounting_v0 WHERE 1;
                 DELETE FROM safety_state_records_v0 WHERE 1;",
            )
            .expect("empty historical journal tables");
    }
}

fn rewrite_as_historical_journal(
    path: &Path,
    metadata_ddl: &str,
    journal_schema: i64,
    safety_schema: i64,
    empty: bool,
) {
    let connection = Connection::open(path).expect("open journal for historical fixture");
    enable_persistent_wal_for_raw_connection(&connection);
    begin_historical_journal_rewrite(
        &connection,
        metadata_ddl,
        journal_schema,
        safety_schema,
        empty,
    );
    connection
        .execute_batch(
            "COMMIT;
             PRAGMA wal_checkpoint(TRUNCATE);
             BEGIN IMMEDIATE;
             ROLLBACK;",
        )
        .expect("finish historical journal fixture");
}

fn install_committed_historical_wal_shadow(
    path: &Path,
    metadata_ddl: &str,
    journal_schema: i64,
    safety_schema: i64,
) {
    let checkpointed_main = fs::read(path).expect("snapshot checkpointed current main database");
    let shm_path = path_with_suffix(path, "-shm");
    let connection = Connection::open(path).expect("open journal for historical WAL fixture");
    enable_persistent_wal_for_raw_connection(&connection);
    connection
        .execute_batch("PRAGMA wal_autocheckpoint=0;")
        .expect("disable WAL autocheckpoint for historical shadow fixture");
    begin_historical_journal_rewrite(
        &connection,
        metadata_ddl,
        journal_schema,
        safety_schema,
        false,
    );
    connection
        .execute_batch("COMMIT;")
        .expect("commit historical WAL shadow fixture");
    assert_eq!(
        fs::read(path).expect("read main database after WAL shadow commit"),
        checkpointed_main,
        "historical schema rewrite must remain solely in the committed WAL"
    );
    let wal_path = path_with_suffix(path, "-wal");
    let committed_wal = fs::read(&wal_path).expect("capture committed historical WAL shadow");
    assert!(
        committed_wal.len() > 32,
        "historical WAL shadow must contain committed frames"
    );
    let committed_shm = fs::read(&shm_path).expect("capture committed historical wal-index");
    assert!(
        committed_shm.len() >= 96,
        "committed historical wal-index contains both header copies"
    );
    assert_eq!(committed_shm[0..48], committed_shm[48..96]);
    assert_eq!(committed_shm[12], 1);
    assert_eq!(committed_shm[60], 1);
    drop(connection);

    // Closing the raw fixture connection may checkpoint or truncate its WAL.
    // Restore the exact checkpointed-v6 main plus the captured committed-v5
    // WAL and its coherent persisted wal-index. A correct preflight claims
    // the live SHM reset guard and resolves only an independent main+WAL copy;
    // it never trusts or mutates these persisted wal-index bytes.
    fs::write(path, &checkpointed_main).expect("restore checkpointed current main database");
    fs::write(&wal_path, &committed_wal).expect("restore committed historical WAL shadow");
    fs::write(&shm_path, &committed_shm).expect("restore coherent historical wal-index fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&wal_path, fs::Permissions::from_mode(0o600))
            .expect("protect restored historical WAL shadow");
        fs::set_permissions(&shm_path, fs::Permissions::from_mode(0o600))
            .expect("protect coherent historical wal-index fixture");
    }
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

fn validation_request(effects: &[Effect]) -> PayloadValidationRequest {
    effects
        .iter()
        .find_map(|effect| match effect {
            Effect::ValidatePayload(request) => Some(request.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected one payload-validation request: {effects:?}"))
}

fn synced_validation_request(effects: &[Effect]) -> PayloadValidationRequest {
    effects
        .iter()
        .find_map(|effect| match effect {
            Effect::ValidateSyncedPayload(request) => Some(request.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected one synced-payload validation request: {effects:?}"))
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

fn valid_commitments(config: &CoreConfig, block: &Block) -> ValidatedBlockCommitmentsV0 {
    let application_payload =
        ApplicationPayloadV0::new(vec![b"durable-invalid".to_vec()]).expect("valid payload");
    let receipt =
        ExecutionReceiptCommitmentV0::for_transaction(&application_payload, 0, 0, 0, Vec::new())
            .expect("valid receipt");
    let receipts =
        ExecutionReceiptsV0::new(&application_payload, vec![receipt]).expect("valid receipt list");
    let body = BlockBodyV0::new(application_payload, Vec::new()).expect("valid block body");
    body.validate_ordinary_commitments(
        block.header(),
        &receipts,
        config.consensus_parameters(),
        config.validator_set(),
        &AcceptSignatures,
    )
    .expect("validate ordinary commitments")
}

fn valid_artifact_ref(block: &Block) -> ValidatedPayloadArtifactRefV0 {
    ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(block.id(), block.header().parent_id(), [0x41; 32]),
        [0x42; 32],
    )
}

fn native_valid_context(
    state: &SafetyState,
    route: PayloadValidationRouteV0,
    id: ValidationId,
    post_ack_action_code: u32,
) -> SafetyTransitionContextV0 {
    let completion = state
        .payload_validation_completions()
        .iter()
        .find(|completion| completion.route() == route && completion.id() == id)
        .expect("exact native Valid completion");
    SafetyTransitionContextV0::native_valid(
        NativeValidTransitionV0::new(
            route,
            id,
            [0x31; 32],
            [0x32; 32],
            [0x33; 32],
            native_valid_result_checksum_v0(completion.result())
                .expect("canonical native Valid result checksum"),
            [0x35; 32],
            [0x36; 32],
            1,
            [0x37; 32],
            [0x38; 32],
            post_ack_action_code,
            state.revision(),
        )
        .expect("valid native Valid transition facts"),
    )
}

fn root_signature(signing_root: SigningRoot) -> SignatureBytes {
    let mut signature = [0u8; SIGNATURE_BYTES];
    signature[..32].copy_from_slice(signing_root.as_bytes());
    signature[32..].copy_from_slice(signing_root.as_bytes());
    SignatureBytes::from_array(signature)
}

fn signed_vote(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    block_id: BlockId,
    author: ValidatorId,
) -> Vote {
    let signing_root =
        Vote::signing_root_for_set(set, View::new(view), Height::new(height), block_id)
            .expect("valid vote signing root");
    Vote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        block_id,
        set.id(),
        author,
        root_signature(signing_root),
        set,
    )
    .expect("valid vote")
}

fn quorum_certificate(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    block_id: BlockId,
) -> QuorumCertificate {
    let votes = (1u8..=3)
        .map(|author| signed_vote(set, view, height, block_id, validator_id(author)))
        .collect();
    QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        block_id,
        set.id(),
        votes,
        set,
    )
    .expect("valid quorum certificate")
}

fn chained_proposal(config: &CoreConfig, justify: QcReferenceV0, view: u64) -> SignedProposalV0 {
    let set = config.validator_set();
    let parameters = config.consensus_parameters();
    let justify_ref = justify.qc_ref();
    let height = justify_ref.height().get() + 1;
    let application_payload =
        ApplicationPayloadV0::new(vec![b"durable-invalid".to_vec()]).expect("valid payload");
    let receipt =
        ExecutionReceiptCommitmentV0::for_transaction(&application_payload, 0, 0, 0, Vec::new())
            .expect("valid receipt");
    let receipts =
        ExecutionReceiptsV0::new(&application_payload, vec![receipt]).expect("valid receipts");
    let body = BlockBodyV0::new(application_payload, Vec::new()).expect("valid body");
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        BlockKind::Regular,
        justify_ref.block_id(),
        leader_for(set, View::new(view)),
        set.id(),
        set.consensus_parameters_hash(),
        body.payload_root().expect("payload root"),
        StateRoot::new([height as u8; 32]),
        receipts.receipts_root().expect("receipts root"),
        body.evidence_root().expect("evidence root"),
        TRUSTED_GENESIS_TIMESTAMP_MS + height,
        None,
    )
    .expect("valid chained header");
    let block = Block::new(
        header,
        body.application_payload()
            .try_cev0_bytes()
            .expect("canonical application payload"),
        Vec::new(),
    )
    .expect("valid chained block");
    let signing_root = ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
        .expect("valid proposal signing root");
    let witness = ProposalWitnessV0::new(
        block.header(),
        justify,
        None,
        None,
        root_signature(signing_root),
        set,
        None,
        parameters,
        TRUSTED_GENESIS_TIMESTAMP_MS + height - 1,
    )
    .expect("valid chained proposal witness");
    SignedProposalV0::new(
        block,
        witness,
        set,
        None,
        parameters,
        TRUSTED_GENESIS_TIMESTAMP_MS + height - 1,
    )
    .expect("valid chained proposal")
}

fn persist_ordinary_and_ack(
    core: &mut Core,
    store: &mut SqliteSafetyStateStoreV0<AcceptSignatures>,
    effects: Vec<Effect>,
) -> Vec<Effect> {
    let request = persistence_effect(&effects);
    assert_eq!(
        store
            .persist_exact_v0(&request, &SafetyTransitionContextV0::Ordinary)
            .expect("persist genuine ordinary Core transition"),
        SafetyPersistDispositionV0::Inserted
    );
    core.step(
        Input::StorageAck {
            barrier: request.barrier(),
        },
        &AcceptSignatures,
    )
    .expect("acknowledge genuine ordinary Core transition")
}

fn insert_synced_valid(
    config: &CoreConfig,
    core: &mut Core,
    store: &mut SqliteSafetyStateStoreV0<AcceptSignatures>,
    application_seal_authority: &CoreIssuedApplicationSealAuthorityV0,
    proposal: SignedProposalV0,
) {
    let registration = core
        .step(Input::SyncedProposal(Box::new(proposal)), &AcceptSignatures)
        .expect("register synced proposal");
    let validation_effects = persist_ordinary_and_ack(core, store, registration);
    let request = synced_validation_request(&validation_effects);
    let block = request.block().clone();
    let (route, id, _block, _parent, permit) = request
        .try_claim()
        .expect("claim genuine synced validation request")
        .into_parts();
    let proof = application_seal_authority.seal_after_application_store_commit_v0(
        permit,
        valid_commitments(config, &block),
        valid_artifact_ref(&block),
    );
    let completion = persistence_effect(
        &core
            .step_application_sealed_valid_v0(&proof, &AcceptSignatures)
            .expect("Core accepts application-sealed synced Valid callback"),
    );
    let action = completion
        .native_valid_post_ack_action_v0()
        .expect("Core binds synced Valid post-ack action");
    let context = native_valid_context(completion.state(), route, id, action.code());
    assert_eq!(
        store
            .persist_exact_v0(&completion, &context)
            .expect("persist genuine synced Valid completion"),
        SafetyPersistDispositionV0::Inserted
    );
    let released = core
        .step(
            Input::StorageAck {
                barrier: completion.barrier(),
            },
            &AcceptSignatures,
        )
        .expect("acknowledge synced Valid completion");
    assert!(
        released
            .iter()
            .all(|effect| !matches!(effect, Effect::PersistSafetyState(_))),
        "one StorageAck must not cross another persistence barrier: {released:?}"
    );
}

fn finalization_context_with_action(
    exact: &NativeFinalizationAppliedTransitionV0,
    action_code: u32,
) -> SafetyTransitionContextV0 {
    SafetyTransitionContextV0::native_finalization_applied(
        NativeFinalizationAppliedTransitionV0::new(
            exact.source_route(),
            exact.source_validation_id(),
            exact.ordinal(),
            exact.application_host_config_ref(),
            exact.finalization_checksum(),
            exact.prior_head_checksum(),
            exact.new_head_checksum(),
            exact.source_artifact_checksum(),
            exact.accepted_source_checksum(),
            exact.applied_job_row_checksum(),
            exact.receipt_row_checksum(),
            action_code,
            exact.completion_revision(),
        )
        .expect("all nine finalization-applied action codes are canonical context facts"),
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
    assert!(matches!(
        store.confirmed_native_valid_head_v0(),
        Err(SafetyStoreErrorV0::MissingNativeValidTransition { revision: 0 })
    ));
    drop(store);

    let metadata = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open journal-v7 metadata readback");
    let versions: (i64, i64) = metadata
        .query_row(
            "SELECT journal_schema, safety_schema
             FROM safety_store_metadata_v0 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read journal-v7 metadata versions");
    assert_eq!(versions, (7, 13));
    drop(metadata);

    let reopened = SqliteSafetyStateStoreV0::open_existing(&path, profile, AcceptSignatures)
        .expect("reopen initialized safety store");
    assert_eq!(
        reopened.head().expect("read reopened head").state(),
        &genesis
    );
}

#[test]
fn node_checkpoint_head_confirmation_is_exact_inert_and_reopens_v0() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("node-checkpoint-head.sqlite3");
    let config = test_config();
    let selected_profile = profile(&config);
    let verifier_profile_ref = selected_profile.verifier_profile_ref();
    let expected_core_config_ref = safety_state_record_config_ref_v0(
        &SafetyStateRecordContextV0::new(
            &config,
            verifier_profile_ref,
            selected_profile.record_limits(),
        )
        .expect("construct expected Safety record context"),
    )
    .expect("derive expected Safety Core config reference");
    let genesis = genesis_state(&config);
    let foreign_genesis = genesis_state(&test_config_with_timestamp(
        TRUSTED_GENESIS_TIMESTAMP_MS + 1,
    ));
    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        selected_profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize node-checkpoint SafetyStore fixture");

    let journal_id = store.journal_id_v0();
    let head_before = store.head().expect("authenticate head before confirmation");
    let namespace_before = journal_namespace_image(&path);
    let confirmed = store
        .confirm_node_checkpoint_head_exact_v0(&genesis)
        .expect("confirm exact node-checkpoint Safety facts");
    assert_eq!(confirmed.state_v0(), &genesis);
    assert_eq!(confirmed.state_v0(), head_before.state());
    assert_eq!(confirmed.journal_id_v0(), journal_id);
    assert_eq!(confirmed.verifier_profile_ref_v0(), verifier_profile_ref);
    assert_eq!(confirmed.core_config_ref_v0(), expected_core_config_ref);
    assert_eq!(confirmed.revision_v0(), head_before.revision());
    assert_eq!(
        confirmed.state_record_checksum_v0(),
        head_before.state_record_checksum()
    );
    assert_eq!(confirmed.chain_checksum_v0(), head_before.chain_checksum());
    drop(confirmed);

    assert!(matches!(
        store.confirm_node_checkpoint_head_exact_v0(&foreign_genesis),
        Err(SafetyStoreErrorV0::SafetyNodeCheckpointHeadMismatch {
            expected_revision: 0,
            actual_revision: 0,
        })
    ));
    let head_after = store
        .head()
        .expect("authenticate unchanged head after confirmation attempts");
    assert_eq!(head_after, head_before);
    assert_eq!(
        journal_namespace_image(&path),
        namespace_before,
        "successful and rejected node-checkpoint confirmations must not change journal bytes"
    );
    drop(store);

    let reopened =
        SqliteSafetyStateStoreV0::open_existing(&path, selected_profile, AcceptSignatures)
            .expect("reopen node-checkpoint SafetyStore fixture");
    let reopened_head = reopened.head().expect("authenticate reopened head");
    let reopened_confirmed = reopened
        .confirm_node_checkpoint_head_exact_v0(&genesis)
        .expect("confirm exact facts after reopen");
    assert_eq!(reopened_confirmed.state_v0(), &genesis);
    assert_eq!(reopened_confirmed.state_v0(), reopened_head.state());
    assert_eq!(reopened_confirmed.journal_id_v0(), journal_id);
    assert_eq!(reopened_confirmed.revision_v0(), reopened_head.revision());
    assert_eq!(
        reopened_confirmed.state_record_checksum_v0(),
        reopened_head.state_record_checksum()
    );
    assert_eq!(
        reopened_confirmed.chain_checksum_v0(),
        reopened_head.chain_checksum()
    );
}

#[test]
fn persist_exact_and_confirm_node_checkpoint_head_reuses_authenticated_result() {
    let temporary = protected_temp_dir();
    let path = temporary
        .path()
        .join("persist-and-confirm-node-checkpoint.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let mut core = Core::new(
        config.clone(),
        genesis_qc(config.validator_set()),
        &AcceptSignatures,
    )
    .expect("valid Core");
    let genesis = core.safety_state().clone();
    let mut store =
        SqliteSafetyStateStoreV0::initialize_new(&path, profile, AcceptSignatures, &genesis)
            .expect("initialize SafetyStore");
    store
        .bind_core_v0(core.safety_state_persistence_binding_v0())
        .expect("bind designated Core");

    let effects = core
        .step(
            Input::Proposal(Box::new(invalid_proposal(&config))),
            &AcceptSignatures,
        )
        .expect("proposal creates one exact persistence request");
    let request = persistence_effect(&effects);

    let (inserted_disposition, inserted) = store
        .persist_exact_and_confirm_node_checkpoint_head_v0(
            &request,
            &SafetyTransitionContextV0::Ordinary,
        )
        .expect("persist and authenticate inserted head");
    assert_eq!(inserted_disposition, SafetyPersistDispositionV0::Inserted);
    assert_eq!(inserted.state_v0(), request.state());
    assert_eq!(inserted.revision_v0(), request.state().revision());
    assert!(inserted.belongs_to_store_at_path_v0(&store, &path));

    let (existing_disposition, existing) = store
        .persist_exact_and_confirm_node_checkpoint_head_v0(
            &request,
            &SafetyTransitionContextV0::Ordinary,
        )
        .expect("retry and authenticate existing head");
    assert_eq!(existing_disposition, SafetyPersistDispositionV0::Existing);
    assert_eq!(existing.state_v0(), inserted.state_v0());
    assert_eq!(existing.revision_v0(), inserted.revision_v0());
    assert_eq!(
        existing.state_record_checksum_v0(),
        inserted.state_record_checksum_v0()
    );
    assert_eq!(existing.chain_checksum_v0(), inserted.chain_checksum_v0());
    assert!(existing.belongs_to_store_at_path_v0(&store, &path));

    let head = store
        .head()
        .expect("authenticate persisted head independently");
    assert_eq!(head.state(), inserted.state_v0());
    assert_eq!(head.chain_checksum(), inserted.chain_checksum_v0());
}

#[test]
fn historical_journal_v3_is_rejected_before_any_namespace_mutation() {
    let temporary = protected_temp_dir();
    let config = test_config();
    let profile = profile(&config);
    let genesis = genesis_state(&config);

    for (fixture_name, empty) in [("nonempty", false), ("empty", true)] {
        let path = temporary
            .path()
            .join(format!("historical-v3-{fixture_name}.sqlite3"));
        let store = SqliteSafetyStateStoreV0::initialize_new(
            &path,
            profile.clone(),
            AcceptSignatures,
            &genesis,
        )
        .expect("initialize source journal");
        drop(store);
        rewrite_as_historical_journal(&path, HISTORICAL_JOURNAL_V3_METADATA_DDL, 3, 9, empty);

        let before = journal_namespace_image(&path);
        assert!(matches!(
            open_error(&path, profile.clone()),
            SafetyStoreErrorV0::SchemaMismatch
        ));
        assert_eq!(
            journal_namespace_image(&path),
            before,
            "rejected {fixture_name} journal-v3 open changed main/WAL/SHM/lock bytes"
        );
    }
}

#[test]
fn historical_journal_v5_is_rejected_before_any_namespace_mutation() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("historical-v5.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let genesis = genesis_state(&config);
    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize source journal");
    drop(store);
    rewrite_as_historical_journal(&path, HISTORICAL_JOURNAL_V5_METADATA_DDL, 5, 11, false);

    let before = journal_namespace_image(&path);
    assert!(matches!(
        open_error(&path, profile),
        SafetyStoreErrorV0::SchemaMismatch
    ));
    assert_eq!(
        journal_namespace_image(&path),
        before,
        "rejected journal-v5 open changed main/WAL/SHM/lock bytes"
    );
}

#[test]
fn historical_journal_v5_committed_wal_shadow_is_rejected_before_any_journal_namespace_mutation() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("historical-v5-wal-shadow.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let genesis = genesis_state(&config);
    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize current main database for historical WAL shadow");
    drop(store);
    install_committed_historical_wal_shadow(&path, HISTORICAL_JOURNAL_V5_METADATA_DDL, 5, 11);

    let before = journal_namespace_image(&path);
    assert!(matches!(
        open_error(&path, profile),
        SafetyStoreErrorV0::SchemaMismatch
    ));
    assert_eq!(
        journal_namespace_image(&path),
        before,
        "rejected committed journal-v5 WAL shadow changed journal namespace presence, bytes, dev/inode, mode, or nlink"
    );
}

#[test]
fn historical_journal_v4_is_rejected_before_any_namespace_mutation() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("historical-v4.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let genesis = genesis_state(&config);
    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize source journal");
    drop(store);
    rewrite_as_historical_journal(&path, HISTORICAL_JOURNAL_V4_METADATA_DDL, 4, 10, false);

    let before = journal_namespace_image(&path);
    assert!(matches!(
        open_error(&path, profile),
        SafetyStoreErrorV0::SchemaMismatch
    ));
    assert_eq!(
        journal_namespace_image(&path),
        before,
        "rejected journal-v4 open changed main/WAL/SHM/lock bytes"
    );
}

#[test]
fn historical_journal_v2_is_still_rejected_before_any_namespace_mutation() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("historical-v2.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let genesis = genesis_state(&config);
    let store = SqliteSafetyStateStoreV0::initialize_new(
        &path,
        profile.clone(),
        AcceptSignatures,
        &genesis,
    )
    .expect("initialize source journal");
    drop(store);
    rewrite_as_historical_journal(&path, HISTORICAL_JOURNAL_V2_METADATA_DDL, 2, 8, false);

    let before = journal_namespace_image(&path);
    assert!(matches!(
        open_error(&path, profile),
        SafetyStoreErrorV0::SchemaMismatch
    ));
    assert_eq!(
        journal_namespace_image(&path),
        before,
        "rejected journal-v2 open changed main/WAL/SHM/lock bytes"
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
    assert!(matches!(
        store.confirmed_native_valid_head_v0(),
        Err(SafetyStoreErrorV0::MissingNativeValidTransition { revision: 2 })
    ));
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
fn native_valid_exact_readback_is_authenticated_and_fail_closed() {
    let temporary = protected_temp_dir();
    let path = temporary.path().join("native-valid-readback.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let mut core = Core::new(
        config.clone(),
        genesis_qc(config.validator_set()),
        &AcceptSignatures,
    )
    .expect("valid Core");
    let application_seal_authority = core
        .issue_application_seal_authority_v0()
        .expect("issue fixture application seal authority");
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

    let revision_one = persistence_effect(
        &core
            .step(
                Input::Proposal(Box::new(invalid_proposal(&config))),
                &AcceptSignatures,
            )
            .expect("proposal registers durable validation obligation"),
    );
    store
        .persist_exact_v0(&revision_one, &SafetyTransitionContextV0::Ordinary)
        .expect("persist registered obligation");
    let validation_effects = core
        .step(
            Input::StorageAck {
                barrier: revision_one.barrier(),
            },
            &AcceptSignatures,
        )
        .expect("release validation request");
    let request = validation_request(&validation_effects);
    let block = request.block().clone();
    let (route, id, _block, _parent, permit) = request
        .try_claim()
        .expect("claim exact validation request")
        .into_parts();
    let proof = application_seal_authority.seal_after_application_store_commit_v0(
        permit,
        valid_commitments(&config, &block),
        valid_artifact_ref(&block),
    );
    let revision_two = persistence_effect(
        &core
            .step_application_sealed_valid_v0(&proof, &AcceptSignatures)
            .expect("Core accepts application-sealed Valid callback"),
    );
    let core_post_ack_action = revision_two
        .native_valid_post_ack_action_v0()
        .expect("Core attaches a native Valid post-ack manifest");
    assert_eq!(
        core_post_ack_action.code(),
        NATIVE_VALID_POST_ACK_REQUEST_SIGNATURE_V0
    );
    let context =
        native_valid_context(revision_two.state(), route, id, core_post_ack_action.code());
    let wrong_post_ack_action_code = (core_post_ack_action.code() + 1) % 8;
    let wrong_action_context =
        native_valid_context(revision_two.state(), route, id, wrong_post_ack_action_code);
    let invalid_context = native_invalid_context(
        id,
        revision_two.state().revision(),
        NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0,
    );
    let head_before_rejections = store.head().expect("read pre-Valid head");
    let namespace_before_rejections = journal_namespace_image(&path);
    let preflight = store
        .preflight_bound_native_valid_persistence_v0(&revision_two)
        .expect("preflight the exact bound native Valid persistence request");
    assert_eq!(preflight.journal_id_v0(), store.journal_id_v0());
    assert_eq!(
        preflight.verifier_profile_ref_v0(),
        store.verifier_profile_ref_v0()
    );
    assert_eq!(preflight.revision_v0(), revision_two.state().revision());
    assert_eq!(preflight.post_ack_action_v0(), core_post_ack_action);
    assert_eq!(
        journal_namespace_image(&path),
        namespace_before_rejections,
        "native Valid preflight must not change any journal namespace byte"
    );
    assert!(matches!(
        store.preflight_bound_native_valid_persistence_v0(&revision_one),
        Err(SafetyStoreErrorV0::MissingNativeValidPostAckAction { revision: 1 })
    ));
    assert_eq!(
        journal_namespace_image(&path),
        namespace_before_rejections,
        "rejected ordinary-state preflight must also be zero-write"
    );
    assert!(matches!(
        store.persist_exact_v0(&revision_two, &wrong_action_context),
        Err(SafetyStoreErrorV0::NativeValidPostAckActionMismatch {
            revision: 2,
            core_action_code: NATIVE_VALID_POST_ACK_REQUEST_SIGNATURE_V0,
            context_action_code,
        }) if context_action_code == wrong_post_ack_action_code
    ));
    assert_eq!(
        journal_namespace_image(&path),
        namespace_before_rejections,
        "a mismatched NativeValid manifest must be rejected before any journal byte changes"
    );
    assert!(matches!(
        store.persist_exact_v0(&revision_two, &SafetyTransitionContextV0::Ordinary),
        Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "new terminal payload completion lacks transition context"
        ))
    ));
    assert!(matches!(
        store.persist_exact_v0(&revision_two, &invalid_context),
        Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "callback transition is not congruent with Core state"
        ))
    ));
    let head_after_rejections = store.head().expect("read head after rejected writes");
    assert_eq!(
        head_after_rejections.state(),
        head_before_rejections.state()
    );
    assert_eq!(
        head_after_rejections.transition_context(),
        head_before_rejections.transition_context()
    );
    assert_eq!(
        head_after_rejections.state_record_checksum(),
        head_before_rejections.state_record_checksum()
    );
    assert_eq!(
        head_after_rejections.chain_checksum(),
        head_before_rejections.chain_checksum()
    );
    store
        .persist_exact_v0(&revision_two, &context)
        .expect("persist native Valid completion");
    let namespace_before_wrong_retry = journal_namespace_image(&path);
    assert!(matches!(
        store.persist_exact_v0(&revision_two, &wrong_action_context),
        Err(SafetyStoreErrorV0::NativeValidPostAckActionMismatch {
            revision: 2,
            core_action_code: NATIVE_VALID_POST_ACK_REQUEST_SIGNATURE_V0,
            context_action_code,
        }) if context_action_code == wrong_post_ack_action_code
    ));
    assert_eq!(
        journal_namespace_image(&path),
        namespace_before_wrong_retry,
        "an altered-code exact retry must be rejected before any journal byte changes"
    );

    let authenticated_head = store.head().expect("read authenticated native Valid head");
    let confirmed = store
        .confirmed_native_valid_head_v0()
        .expect("confirm native Valid head");
    assert_eq!(confirmed.journal_id_v0(), store.journal_id_v0());
    assert_eq!(
        confirmed.verifier_profile_ref_v0(),
        store.verifier_profile_ref_v0()
    );
    assert_eq!(confirmed.state(), revision_two.state());
    assert_eq!(confirmed.state(), authenticated_head.state());
    assert_eq!(confirmed.transition_context(), &context);
    assert_eq!(
        confirmed.transition(),
        context
            .native_valid_transition()
            .expect("native Valid context")
    );
    assert_eq!(
        confirmed.state_record_checksum(),
        authenticated_head.state_record_checksum()
    );
    assert_eq!(
        confirmed.state_record_checksum(),
        preflight.state_record_checksum_v0(),
        "preflight must bind the canonical Core state-record checksum persisted later"
    );
    assert_eq!(
        confirmed.chain_checksum(),
        authenticated_head.chain_checksum()
    );
    assert_eq!(confirmed.post_ack_action_v0(), core_post_ack_action);
    assert!(confirmed.belongs_to_store_at_path_v0(&store, &path));

    let exact = store
        .confirmed_native_valid_head_exact_v0(revision_two.state(), &context)
        .expect("confirm exact native Valid state/context");
    assert_eq!(exact.revision(), revision_two.state().revision());
    assert_eq!(exact.transition_context(), &context);

    let foreign_temporary = protected_temp_dir();
    let foreign_path = foreign_temporary
        .path()
        .join("foreign-native-valid.sqlite3");
    let foreign_core = Core::new(
        config.clone(),
        genesis_qc(config.validator_set()),
        &AcceptSignatures,
    )
    .expect("valid foreign Core");
    let foreign_genesis = foreign_core.safety_state().clone();
    let foreign_store = SqliteSafetyStateStoreV0::initialize_new(
        &foreign_path,
        profile.clone(),
        AcceptSignatures,
        &foreign_genesis,
    )
    .expect("initialize foreign SafetyStore owner");
    assert!(!exact.belongs_to_store_at_path_v0(&foreign_store, &foreign_path));
    assert!(!exact.belongs_to_store_at_path_v0(&store, &foreign_path));
    drop(foreign_store);
    // Keep the second Core live through the owner-affinity assertions so its
    // process-local identities cannot be optimized into fixture reuse.
    assert_eq!(foreign_core.safety_state(), &foreign_genesis);

    let namespace_before_exact_rejections = journal_namespace_image(&path);

    assert!(matches!(
        store.confirmed_native_valid_head_exact_v0(revision_one.state(), &context),
        Err(SafetyStoreErrorV0::NativeValidHeadMismatch {
            expected_revision: 1,
            actual_revision: 2,
        })
    ));

    let altered_context = SafetyTransitionContextV0::native_valid(
        NativeValidTransitionV0::new(
            route,
            id,
            [0x51; 32],
            [0x32; 32],
            [0x33; 32],
            context
                .native_valid_transition()
                .expect("native Valid context")
                .valid_result_checksum(),
            [0x35; 32],
            [0x36; 32],
            1,
            [0x37; 32],
            [0x38; 32],
            NATIVE_VALID_POST_ACK_REQUEST_SIGNATURE_V0,
            revision_two.state().revision(),
        )
        .expect("altered but canonical native Valid facts"),
    );
    assert!(matches!(
        store.confirmed_native_valid_head_exact_v0(revision_two.state(), &altered_context),
        Err(SafetyStoreErrorV0::NativeValidHeadMismatch {
            expected_revision: 2,
            actual_revision: 2,
        })
    ));
    assert!(matches!(
        store.confirmed_native_valid_head_exact_v0(
            revision_two.state(),
            &SafetyTransitionContextV0::Ordinary,
        ),
        Err(SafetyStoreErrorV0::NativeValidHeadMismatch {
            expected_revision: 2,
            actual_revision: 2,
        })
    ));
    assert!(matches!(
        store.confirmed_native_valid_head_exact_v0(revision_two.state(), &invalid_context),
        Err(SafetyStoreErrorV0::NativeValidHeadMismatch {
            expected_revision: 2,
            actual_revision: 2,
        })
    ));
    assert!(matches!(
        store.confirmed_native_deterministic_invalid_head_v0(),
        Err(SafetyStoreErrorV0::MissingNativeDeterministicInvalidTransition { revision: 2 })
    ));
    assert_eq!(
        journal_namespace_image(&path),
        namespace_before_exact_rejections,
        "stale, altered-context, and foreign-context confirmations must be read-only"
    );

    drop(store);
    let reopened =
        SqliteSafetyStateStoreV0::open_existing(&path, profile.clone(), AcceptSignatures)
            .expect("reopen native Valid journal");
    let reopened_confirmed = reopened
        .confirmed_native_valid_head_exact_v0(revision_two.state(), &context)
        .expect("reopened journal confirms exact native Valid head");
    assert_eq!(reopened_confirmed.state(), revision_two.state());
    assert_eq!(reopened_confirmed.transition_context(), &context);
    assert!(reopened_confirmed.belongs_to_store_at_path_v0(&reopened, &path));
    assert!(
        !exact.belongs_to_store_at_path_v0(&reopened, &path),
        "a capability from a dropped owner cannot bind a freshly reopened owner"
    );
    drop(reopened);

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
            .expect("tamper authenticated native Valid transition checksum"),
        1
    );
    drop(connection);
    assert!(matches!(
        SqliteSafetyStateStoreV0::open_existing(&path, profile, AcceptSignatures),
        Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "record-chain checksum"
        ))
    ));
}

#[test]
fn native_finalization_applied_exact_readback_persists_retries_and_reopens() {
    let temporary = protected_temp_dir();
    let path = temporary
        .path()
        .join("native-finalization-applied-readback.sqlite3");
    let config = test_config();
    let profile = profile(&config);
    let mut core = Core::new(
        config.clone(),
        genesis_qc(config.validator_set()),
        &AcceptSignatures,
    )
    .expect("valid Core");
    let application_seal_authority = core
        .issue_application_seal_authority_v0()
        .expect("issue fixture application seal authority");
    let finalization_apply_authority = core
        .issue_application_finalization_apply_authority_v0()
        .expect("issue fixture application finalization authority");
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

    let set = config.validator_set();
    let first = chained_proposal(&config, QcReferenceV0::genesis_anchor(genesis_qc(set)), 1);
    let first_id = first.block().id();
    insert_synced_valid(
        &config,
        &mut core,
        &mut store,
        &application_seal_authority,
        first,
    );
    let first_qc = quorum_certificate(set, 1, 1, first_id);
    let first_qc_effects = core
        .step(
            Input::QuorumCertificate(first_qc.clone()),
            &AcceptSignatures,
        )
        .expect("accept first QC");
    let _released = persist_ordinary_and_ack(&mut core, &mut store, first_qc_effects);

    let second = chained_proposal(&config, QcReferenceV0::ordinary(first_qc), 2);
    let second_id = second.block().id();
    insert_synced_valid(
        &config,
        &mut core,
        &mut store,
        &application_seal_authority,
        second,
    );
    let second_qc = quorum_certificate(set, 2, 2, second_id);
    let second_qc_effects = core
        .step(
            Input::QuorumCertificate(second_qc.clone()),
            &AcceptSignatures,
        )
        .expect("accept second QC");
    let _released = persist_ordinary_and_ack(&mut core, &mut store, second_qc_effects);

    let third = chained_proposal(&config, QcReferenceV0::ordinary(second_qc), 3);
    let third_id = third.block().id();
    insert_synced_valid(
        &config,
        &mut core,
        &mut store,
        &application_seal_authority,
        third,
    );
    let third_qc = quorum_certificate(set, 3, 3, third_id);
    let finality_effects = core
        .step(Input::QuorumCertificate(third_qc), &AcceptSignatures)
        .expect("complete genuine three-chain finality");
    let finality_request = persistence_effect(&finality_effects);
    assert_eq!(
        finality_request
            .state()
            .pending_finalization()
            .expect("Core persists an ordered finalization front")
            .proof()
            .finalized_block()
            .header()
            .id(),
        first_id
    );
    assert_eq!(
        store
            .persist_exact_v0(&finality_request, &SafetyTransitionContextV0::Ordinary,)
            .expect("persist genuine finality queue front"),
        SafetyPersistDispositionV0::Inserted
    );
    let released_finality = core
        .step(
            Input::StorageAck {
                barrier: finality_request.barrier(),
            },
            &AcceptSignatures,
        )
        .expect("release persisted finality front");
    assert!(released_finality
        .iter()
        .any(|effect| matches!(effect, Effect::Finalize(proof) if proof.finalized_block().header().id() == first_id)));

    let permit = core
        .issue_application_finalization_permit_v0()
        .expect("issue exact queue-front permit");
    let consumed_finalization = permit.finalization().clone();
    assert!(finalization_apply_authority.matches_application_finalization_permit_v0(&permit));
    let target = permit.finalization().proof().finalized_block().header();
    let source = core
        .safety_state()
        .payload_validation_completions()
        .iter()
        .find(|completion| {
            completion.result().artifact_ref().is_some_and(|artifact| {
                artifact.overlay() == permit.finalization().target_overlay_ref()
            })
        })
        .expect("finalization front has one exact durable Valid source");
    let source_artifact_checksum = source
        .result()
        .artifact_ref()
        .expect("finalization source is Valid")
        .source_artifact_checksum();
    let readback = finalization_apply_authority
        .application_store_apply_readback_v0(
            &permit,
            source.route(),
            source.id(),
            target.height().get(),
            [0x91; 32],
            [0x92; 32],
            [0x93; 32],
            source_artifact_checksum,
            [0x95; 32],
            [0x96; 32],
            [0x97; 32],
        )
        .expect("build inert projection from exact simulated AppStore readback");
    let receipt = finalization_apply_authority
        .receipt_after_application_store_apply_v0(permit, readback)
        .expect("consume exact permit after simulated durable application readback");
    let tag_three_effects = core
        .step_application_finalization_receipt_v0(receipt, &AcceptSignatures)
        .expect("Core accepts exact application finalization receipt");
    let tag_three_request = persistence_effect(&tag_three_effects);
    let manifest = tag_three_request
        .native_finalization_applied_v0()
        .expect("Core binds exact tag-3 persistence manifest");
    assert_eq!(manifest.successor().block_id(), first_id);
    assert_eq!(
        manifest.post_ack_action_v0(),
        NativeFinalizationAppliedPostAckActionV0::None,
        "a one-entry queue with no other durable outbox has no post-ack action"
    );

    let namespace_before_preflight = journal_namespace_image(&path);
    let preflight = store
        .preflight_bound_native_finalization_applied_persistence_v0(&tag_three_request)
        .expect("preflight genuine bound finalization-applied persistence request");
    assert_eq!(preflight.journal_id_v0(), store.journal_id_v0());
    assert_eq!(
        preflight.verifier_profile_ref_v0(),
        store.verifier_profile_ref_v0()
    );
    assert_eq!(
        preflight.revision_v0(),
        tag_three_request.state().revision()
    );
    assert_eq!(preflight.manifest_v0(), manifest);
    let exact_context = preflight
        .transition_context_v0()
        .expect("project exact canonical tag-3 transition context");
    let exact_transition = exact_context
        .native_finalization_applied_transition()
        .expect("preflight projects tag-3 facts");
    assert_eq!(
        exact_transition.post_ack_action_code(),
        manifest.post_ack_action_v0().code()
    );
    assert_eq!(
        journal_namespace_image(&path),
        namespace_before_preflight,
        "tag-3 preflight must not change any journal namespace byte"
    );

    // One genuine Core successor can have only one exact durable outbox
    // shape. Exercise all nine canonical action codes against that same
    // state/context closure: its exact `None` shape is accepted below, while
    // every other canonical shape is rejected before a journal write. The
    // remaining eight positive Core-state shapes require independent live
    // vote/sync/timer/queued-finality fixtures and cannot be manufactured by
    // changing inert transition bytes.
    let head_before_action_rejections = store.head().expect("read pre-tag-3 head");
    for action_code in
        0..=NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_STANDALONE_QC_SYNC_V0
    {
        assert!(NativeFinalizationAppliedPostAckActionV0::from_code(action_code).is_some());
        let shaped_context = finalization_context_with_action(exact_transition, action_code);
        if action_code == manifest.post_ack_action_v0().code() {
            assert_eq!(shaped_context, exact_context);
            continue;
        }
        assert!(matches!(
            store.persist_exact_v0(&tag_three_request, &shaped_context),
            Err(SafetyStoreErrorV0::NativeFinalizationAppliedManifestMismatch { revision })
                if revision == tag_three_request.state().revision()
        ));
    }
    let head_after_action_rejections = store.head().expect("read post-rejection head");
    assert_eq!(
        head_after_action_rejections.state(),
        head_before_action_rejections.state()
    );
    assert_eq!(
        head_after_action_rejections.transition_context(),
        head_before_action_rejections.transition_context()
    );
    assert_eq!(
        journal_namespace_image(&path),
        namespace_before_preflight,
        "all eight state-incongruent action shapes must be zero-write"
    );

    assert_eq!(
        store
            .persist_exact_v0(&tag_three_request, &exact_context)
            .expect("persist exact native finalization-applied transition"),
        SafetyPersistDispositionV0::Inserted
    );
    assert_eq!(
        store
            .persist_exact_v0(&tag_three_request, &exact_context)
            .expect("commit-uncertainty retry reads back the exact existing record"),
        SafetyPersistDispositionV0::Existing
    );

    let authenticated_head = store.head().expect("read authenticated tag-3 head");
    let confirmed = store
        .confirmed_native_finalization_applied_head_exact_v0(
            tag_three_request.state(),
            &exact_context,
        )
        .expect("confirm exact native finalization-applied head");
    assert_eq!(confirmed.journal_id_v0(), store.journal_id_v0());
    assert_eq!(
        confirmed.verifier_profile_ref_v0(),
        store.verifier_profile_ref_v0()
    );
    assert_eq!(confirmed.state(), tag_three_request.state());
    assert_eq!(confirmed.transition_context(), &exact_context);
    assert_eq!(confirmed.transition(), exact_transition);
    assert_eq!(
        confirmed.consumed_finalization_v0(),
        &consumed_finalization,
        "the capability retains the authenticated predecessor queue front",
    );
    let recovery_transition = confirmed.recovery_transition_v0();
    assert_eq!(recovery_transition.ordinal(), exact_transition.ordinal());
    assert_eq!(
        recovery_transition.proof_id(),
        consumed_finalization.proof_id()
    );
    assert_eq!(
        recovery_transition.parent_block_id(),
        consumed_finalization.authenticated_parent().block_id()
    );
    assert_eq!(
        recovery_transition.target_block_id(),
        consumed_finalization
            .proof()
            .finalized_block()
            .header()
            .id()
    );
    assert_eq!(
        recovery_transition.overlay_checksum(),
        consumed_finalization
            .target_overlay_ref()
            .overlay_checksum()
    );
    assert_eq!(
        recovery_transition.application_host_config_ref(),
        exact_transition.application_host_config_ref()
    );
    assert_eq!(
        recovery_transition.finalization_checksum(),
        exact_transition.finalization_checksum()
    );
    assert_eq!(
        recovery_transition.accepted_source_checksum(),
        exact_transition.accepted_source_checksum()
    );
    assert_eq!(
        confirmed.state_record_checksum(),
        authenticated_head.state_record_checksum()
    );
    assert_eq!(
        confirmed.state_record_checksum(),
        preflight.state_record_checksum_v0()
    );
    assert_eq!(
        confirmed.chain_checksum(),
        authenticated_head.chain_checksum()
    );
    let journal_id = confirmed.journal_id_v0();
    let verifier_profile_ref = confirmed.verifier_profile_ref_v0();
    drop(confirmed);
    drop(store);

    let reopened = SqliteSafetyStateStoreV0::open_existing(&path, profile, AcceptSignatures)
        .expect("reopen native finalization-applied journal");
    let reopened_confirmed = reopened
        .confirmed_native_finalization_applied_head_exact_v0(
            tag_three_request.state(),
            &exact_context,
        )
        .expect("reopened journal confirms exact native finalization-applied head");
    assert_eq!(reopened_confirmed.journal_id_v0(), journal_id);
    assert_eq!(
        reopened_confirmed.verifier_profile_ref_v0(),
        verifier_profile_ref
    );
    assert_eq!(reopened_confirmed.state(), tag_three_request.state());
    assert_eq!(reopened_confirmed.transition_context(), &exact_context);
    assert_eq!(
        reopened_confirmed.consumed_finalization_v0(),
        &consumed_finalization
    );
    assert_eq!(
        reopened_confirmed.recovery_transition_v0(),
        recovery_transition,
        "reopen reconstructs the same complete recovery projection",
    );
    assert_eq!(
        reopened_confirmed.state_record_checksum(),
        preflight.state_record_checksum_v0()
    );
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
    assert!(matches!(
        store.preflight_bound_native_valid_persistence_v0(&foreign_request),
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
    assert!(matches!(
        store.preflight_bound_native_valid_persistence_v0(&foreign_request),
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

#[test]
fn node_checkpoint_head_confirmation_cannot_bypass_tampered_reopen_v0() {
    let temporary = protected_temp_dir();
    let error = initialize_then_tamper(
        &temporary.path().join("node-checkpoint-tampered.sqlite3"),
        "UPDATE safety_state_records_v0 SET state_record_checksum=zeroblob(32)",
    );
    assert!(matches!(
        error,
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
