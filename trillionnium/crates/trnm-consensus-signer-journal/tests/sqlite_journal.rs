use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex},
};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignatureProducerErrorV0,
    SignatureProducerV0, SignatureRequestV0, SignerJournalConflictV0, SignerJournalErrorV0,
    SignerJournalProfileV0, SignerWatermarkV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    BlockId, CanonicalSignIntentV0, CertificateId, ChainId, ConsensusParametersHash,
    ConsensusPublicKey, Epoch, GenesisHash, Height, ProtocolVersion, QcRef, SignatureBytes,
    Validator, ValidatorId, ValidatorSet, View, VotingPower,
};

const MAXIMUM_DATABASE_BYTES: usize = 32 * 1024 * 1024;
const SIGNER_PROFILE_REF: [u8; 32] = [0x51; 32];
const WATERMARK_SCOPE: [u8; 32] = [0x72; 32];
const TEST_SEED: [u8; 32] = [0x19; 32];

#[derive(Debug, Default)]
struct WatermarkState {
    value: Option<SignerWatermarkV0>,
    fail_target_sequence_once: Option<u64>,
}

#[derive(Debug, Clone, Default)]
struct MemoryWatermark {
    state: Arc<Mutex<WatermarkState>>,
}

impl MemoryWatermark {
    fn fail_target_sequence_once(&self, sequence: u64) {
        self.state
            .lock()
            .expect("watermark test mutex")
            .fail_target_sequence_once = Some(sequence);
    }

    fn clear(&self) {
        self.state.lock().expect("watermark test mutex").value = None;
    }

    fn current(&self) -> Option<SignerWatermarkV0> {
        self.state.lock().expect("watermark test mutex").value
    }
}

impl ExternalMonotonicWatermarkV0 for MemoryWatermark {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let value = self.state.lock().expect("watermark test mutex").value;
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
        let mut state = self.state.lock().expect("watermark test mutex");
        if state.fail_target_sequence_once == Some(target.sequence()) {
            state.fail_target_sequence_once = None;
            return Err(ExternalWatermarkErrorV0::Unavailable);
        }
        if state.value != expected {
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
        state.value = Some(target);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct ProducerState {
    calls: u64,
    signatures: BTreeMap<[u8; 32], [u8; 64]>,
    fail_after_sign_once: bool,
}

#[derive(Clone)]
struct ExactTestProducer {
    key: Arc<SigningKey>,
    state: Arc<Mutex<ProducerState>>,
}

impl ExactTestProducer {
    fn new(key: SigningKey) -> Self {
        Self {
            key: Arc::new(key),
            state: Arc::new(Mutex::new(ProducerState::default())),
        }
    }

    fn fail_after_sign_once(&self) {
        self.state
            .lock()
            .expect("producer test mutex")
            .fail_after_sign_once = true;
    }

    fn calls(&self) -> u64 {
        self.state.lock().expect("producer test mutex").calls
    }
}

impl SignatureProducerV0 for ExactTestProducer {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        assert_eq!(request.signer_profile_ref(), SIGNER_PROFILE_REF);
        let fingerprint = request.fingerprint().into_bytes();
        let mut state = self.state.lock().expect("producer test mutex");
        state.calls += 1;
        let signature = *state
            .signatures
            .entry(fingerprint)
            .or_insert_with(|| self.key.sign(request.signing_root().as_bytes()).to_bytes());
        if state.fail_after_sign_once {
            state.fail_after_sign_once = false;
            return Err(SignatureProducerErrorV0::Unavailable);
        }
        Ok(SignatureBytes::from_array(signature))
    }
}

fn fixture() -> (SignerJournalProfileV0, ValidatorId, SigningKey) {
    let key = SigningKey::from_bytes(&TEST_SEED);
    let author = ValidatorId::from_bytes(b"validator-a").expect("fixture author");
    let validator = Validator::new(
        author,
        ConsensusPublicKey::new(key.verifying_key().to_bytes()),
        VotingPower::new(1).expect("positive fixture power"),
    )
    .expect("fixture validator");
    let second_key = SigningKey::from_bytes(&[0x29; 32]);
    let second_validator = Validator::new(
        ValidatorId::from_bytes(b"validator-b").expect("second fixture author"),
        ConsensusPublicKey::new(second_key.verifying_key().to_bytes()),
        VotingPower::new(1).expect("positive second fixture power"),
    )
    .expect("second fixture validator");
    let validator_set = ValidatorSet::new(
        GenesisHash::new([0x31; 32]),
        ChainId::new("trnm-signer-test-0").expect("fixture chain"),
        ProtocolVersion::V0,
        Epoch::new(0),
        ConsensusParametersHash::new([0x42; 32]),
        vec![validator, second_validator],
    )
    .expect("fixture validator set");
    let profile = SignerJournalProfileV0::new(
        validator_set,
        author,
        SIGNER_PROFILE_REF,
        WATERMARK_SCOPE,
        64,
        4096,
        MAXIMUM_DATABASE_BYTES,
    )
    .expect("fixture signer profile");
    (profile, author, key)
}

fn vote(
    profile: &SignerJournalProfileV0,
    revision: u64,
    view: u64,
    block_byte: u8,
) -> CanonicalSignIntentV0 {
    CanonicalSignIntentV0::vote(
        profile.validator_set(),
        profile.author(),
        revision,
        View::new(view),
        Height::new(view + 1),
        BlockId::new([block_byte; 32]),
    )
    .expect("fixture vote intent")
}

fn timeout(
    profile: &SignerJournalProfileV0,
    revision: u64,
    view: u64,
    qc_byte: u8,
) -> CanonicalSignIntentV0 {
    let high_qc = QcRef::new(
        CertificateId::new([qc_byte; 32]),
        profile.epoch(),
        View::new(view.saturating_sub(1)),
        Height::new(view),
        BlockId::new([qc_byte.wrapping_add(1); 32]),
        profile.validator_set_id(),
    );
    CanonicalSignIntentV0::timeout_vote(
        profile.validator_set(),
        profile.author(),
        revision,
        View::new(view),
        high_qc,
    )
    .expect("fixture timeout intent")
}

fn database_path(temporary: &TempDir) -> std::path::PathBuf {
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("protect signer test directory");
    temporary.path().join("signer.sqlite3")
}

#[test]
fn signature_is_persisted_before_return_and_exact_replay_skips_producer() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let mut producer = ExactTestProducer::new(key);
    let intent = vote(&profile, 1, 10, 0x61);
    let mut journal =
        SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
            .expect("initialize journal");

    let first = journal
        .sign_exact_v0(&intent, &mut producer)
        .expect("persist first signature");
    assert_eq!(producer.calls(), 1);
    let replay = journal
        .sign_exact_v0(&intent, &mut producer)
        .expect("same-process exact replay");
    assert_eq!(replay, first);
    assert_eq!(producer.calls(), 1);
    assert_eq!(journal.capacity().expect("capacity").intent_count(), 1);
    assert_eq!(journal.capacity().expect("capacity").event_count(), 2);
    assert_eq!(
        journal.capacity().expect("capacity").maximum_vote_view(),
        Some(10)
    );
    drop(journal);

    let mut reopened =
        SqliteSignerJournalV0::open_existing(&path, profile, watermark).expect("reopen journal");
    assert_eq!(
        reopened
            .sign_exact_v0(&intent, &mut producer)
            .expect("cross-restart exact replay"),
        first
    );
    assert_eq!(producer.calls(), 1);
}

#[test]
fn same_round_conflicts_and_per_kind_view_regressions_fail_closed() {
    let temporary = TempDir::new().expect("private temporary directory");
    let (profile, _, key) = fixture();
    let mut producer = ExactTestProducer::new(key);
    let mut journal = SqliteSignerJournalV0::initialize_new(
        database_path(&temporary),
        profile.clone(),
        MemoryWatermark::default(),
    )
    .expect("initialize journal");
    journal
        .sign_exact_v0(&vote(&profile, 10, 10, 1), &mut producer)
        .expect("sign first vote");

    let same_round = journal
        .sign_exact_v0(&vote(&profile, 11, 10, 2), &mut producer)
        .expect_err("different vote at same view must fail");
    assert!(matches!(
        same_round,
        SignerJournalErrorV0::Conflict(SignerJournalConflictV0::SameRoundDifferentIntent {
            epoch: 0,
            view: 10,
            kind: 0
        })
    ));

    let old_vote = journal
        .sign_exact_v0(&vote(&profile, 12, 9, 3), &mut producer)
        .expect_err("higher revision cannot authorize an old vote view");
    assert!(matches!(
        old_vote,
        SignerJournalErrorV0::Conflict(SignerJournalConflictV0::ViewRegression {
            kind: 0,
            maximum: 10,
            incoming: 9
        })
    ));

    journal
        .sign_exact_v0(&timeout(&profile, 13, 10, 4), &mut producer)
        .expect("timeout kind has an independent view watermark");
    let old_timeout = journal
        .sign_exact_v0(&timeout(&profile, 14, 9, 5), &mut producer)
        .expect_err("timeout view watermark must also be monotonic");
    assert!(matches!(
        old_timeout,
        SignerJournalErrorV0::Conflict(SignerJournalConflictV0::ViewRegression {
            kind: 1,
            maximum: 10,
            incoming: 9
        })
    ));
    let capacity = journal.capacity().expect("capacity");
    assert_eq!(capacity.maximum_vote_view(), Some(10));
    assert_eq!(capacity.maximum_timeout_view(), Some(10));
}

#[test]
fn lower_safety_revision_fails_even_at_a_higher_view() {
    let temporary = TempDir::new().expect("private temporary directory");
    let (profile, _, key) = fixture();
    let mut producer = ExactTestProducer::new(key);
    let mut journal = SqliteSignerJournalV0::initialize_new(
        database_path(&temporary),
        profile.clone(),
        MemoryWatermark::default(),
    )
    .expect("initialize journal");
    journal
        .sign_exact_v0(&vote(&profile, 20, 10, 1), &mut producer)
        .expect("sign first vote");
    let error = journal
        .sign_exact_v0(&vote(&profile, 19, 11, 2), &mut producer)
        .expect_err("SafetyState revision regression must fail");
    assert!(matches!(
        error,
        SignerJournalErrorV0::Conflict(SignerJournalConflictV0::SafetyRevisionRegression {
            maximum: 20,
            incoming: 19
        })
    ));
}

#[test]
fn chain_author_and_persisted_profile_drift_fail_before_signing() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let mut producer = ExactTestProducer::new(key);
    let mut journal =
        SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
            .expect("initialize journal");

    let other_author = ValidatorId::from_bytes(b"validator-b").expect("other fixture author");
    let author_drift = CanonicalSignIntentV0::vote(
        profile.validator_set(),
        other_author,
        1,
        View::new(1),
        Height::new(2),
        BlockId::new([1; 32]),
    )
    .expect("shape-valid foreign-author intent");
    assert!(matches!(
        journal.sign_exact_v0(&author_drift, &mut producer),
        Err(SignerJournalErrorV0::IntentProfileDrift("author"))
    ));

    let foreign_set = ValidatorSet::new(
        profile.validator_set().genesis_hash(),
        ChainId::new("trnm-foreign-chain-0").expect("foreign chain"),
        profile.protocol_version(),
        profile.epoch(),
        profile.validator_set().consensus_parameters_hash(),
        profile.validator_set().validators().to_vec(),
    )
    .expect("foreign validator set");
    let chain_drift = CanonicalSignIntentV0::vote(
        &foreign_set,
        profile.author(),
        1,
        View::new(1),
        Height::new(2),
        BlockId::new([2; 32]),
    )
    .expect("shape-valid foreign-chain intent");
    assert!(matches!(
        journal.sign_exact_v0(&chain_drift, &mut producer),
        Err(SignerJournalErrorV0::IntentProfileDrift("chain ID"))
    ));
    assert_eq!(producer.calls(), 0);
    drop(journal);

    let drifted_profile = SignerJournalProfileV0::new(
        profile.validator_set().clone(),
        profile.author(),
        [0x52; 32],
        profile.external_watermark_scope(),
        profile.maximum_intents(),
        profile.maximum_intent_bytes(),
        profile.maximum_database_bytes(),
    )
    .expect("shape-valid drifted profile");
    let error = match SqliteSignerJournalV0::open_existing(&path, drifted_profile, watermark) {
        Ok(_) => panic!("persisted signer profile drift must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, SignerJournalErrorV0::MetadataMismatch));
}

#[test]
fn prepared_intent_survives_producer_window_and_requires_exact_retry() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let mut producer = ExactTestProducer::new(key);
    producer.fail_after_sign_once();
    let intent = vote(&profile, 1, 4, 1);
    let mut journal =
        SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
            .expect("initialize journal");
    assert!(matches!(
        journal.sign_exact_v0(&intent, &mut producer),
        Err(SignerJournalErrorV0::SignatureProducer(
            SignatureProducerErrorV0::Unavailable
        ))
    ));
    assert_eq!(journal.capacity().expect("capacity").event_count(), 1);
    drop(journal);

    let mut reopened = SqliteSignerJournalV0::open_existing(&path, profile.clone(), watermark)
        .expect("reopen prepared intent");
    let different = reopened
        .sign_exact_v0(&vote(&profile, 2, 5, 2), &mut producer)
        .expect_err("a different intent cannot bypass prepared tail");
    assert!(matches!(
        different,
        SignerJournalErrorV0::Conflict(SignerJournalConflictV0::PreparedIntentPending)
    ));
    reopened
        .sign_exact_v0(&intent, &mut producer)
        .expect("exact producer retry completes prepared intent");
    assert_eq!(producer.calls(), 2);
}

#[test]
fn external_watermark_recovers_each_local_first_commit_window() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let mut producer = ExactTestProducer::new(key);
    let intent = vote(&profile, 1, 7, 1);
    let mut journal =
        SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
            .expect("initialize journal");
    watermark.fail_target_sequence_once(1);
    assert!(matches!(
        journal.sign_exact_v0(&intent, &mut producer),
        Err(SignerJournalErrorV0::ExternalWatermark { .. })
    ));
    assert_eq!(producer.calls(), 0, "producer cannot run before watermark");
    drop(journal);

    let mut reopened =
        SqliteSignerJournalV0::open_existing(&path, profile.clone(), watermark.clone())
            .expect("reconcile prepared local head");
    watermark.fail_target_sequence_once(2);
    assert!(matches!(
        reopened.sign_exact_v0(&intent, &mut producer),
        Err(SignerJournalErrorV0::ExternalWatermark { .. })
    ));
    assert_eq!(producer.calls(), 1);
    drop(reopened);

    let mut final_open = SqliteSignerJournalV0::open_existing(&path, profile, watermark)
        .expect("reconcile signed local head");
    final_open
        .sign_exact_v0(&intent, &mut producer)
        .expect("persisted signature replays after watermark recovery");
    assert_eq!(producer.calls(), 1, "persisted signature skips producer");
}

#[test]
fn whole_namespace_rollback_is_detected_by_external_watermark() {
    let temporary = TempDir::new().expect("private temporary directory");
    let backup = TempDir::new().expect("private backup directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let journal = SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
        .expect("initialize journal");
    drop(journal);
    copy_namespace(&path, backup.path());

    let mut producer = ExactTestProducer::new(key);
    let mut journal =
        SqliteSignerJournalV0::open_existing(&path, profile.clone(), watermark.clone())
            .expect("reopen before signing");
    journal
        .sign_exact_v0(&vote(&profile, 1, 2, 1), &mut producer)
        .expect("advance signer state");
    assert_eq!(watermark.current().expect("watermark").sequence(), 2);
    drop(journal);

    restore_namespace(&path, backup.path());
    let error = match SqliteSignerJournalV0::open_existing(&path, profile, watermark) {
        Ok(_) => panic!("rolled-back namespace must not open"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        SignerJournalErrorV0::Conflict(SignerJournalConflictV0::ExternalWatermarkAhead)
    ));
}

#[test]
fn missing_external_state_and_second_owner_fail_closed() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, _) = fixture();
    let watermark = MemoryWatermark::default();
    let journal = SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
        .expect("initialize journal");
    assert!(matches!(
        SqliteSignerJournalV0::open_existing(&path, profile.clone(), watermark.clone()),
        Err(SignerJournalErrorV0::Locked)
    ));
    drop(journal);
    watermark.clear();
    let error = match SqliteSignerJournalV0::open_existing(&path, profile, watermark) {
        Ok(_) => panic!("missing external watermark must block open"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        SignerJournalErrorV0::Conflict(SignerJournalConflictV0::ExternalWatermarkMissing)
    ));
}

fn copy_namespace(database: &Path, backup: &Path) {
    for suffix in ["", "-wal", "-shm", ".signer.lock"] {
        let source = path_with_suffix(database, suffix);
        let target = backup.join(source.file_name().expect("namespace file name"));
        fs::copy(source, target).expect("copy signer namespace");
    }
}

fn restore_namespace(database: &Path, backup: &Path) {
    for suffix in ["", "-wal", "-shm", ".signer.lock"] {
        let target = path_with_suffix(database, suffix);
        let source = backup.join(target.file_name().expect("namespace file name"));
        fs::copy(source, target).expect("restore signer namespace");
    }
}

fn path_with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    value.into()
}
