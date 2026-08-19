use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex},
};

use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use tempfile::TempDir;
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignatureProducerErrorV0,
    SignatureProducerV0, SignatureRequestV0, SignerExternalWatermarkRelationV0,
    SignerJournalConflictV0, SignerJournalErrorV0, SignerJournalProfileV0,
    SignerJournalTailStateV0, SignerWatermarkV0, SqliteSignerJournalV0,
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
    replace_before_compare_once: Option<SignerWatermarkV0>,
    compare_calls: u64,
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

    fn replace(&self, value: SignerWatermarkV0) {
        self.state.lock().expect("watermark test mutex").value = Some(value);
    }

    fn replace_before_compare_once(&self, value: SignerWatermarkV0) {
        self.state
            .lock()
            .expect("watermark test mutex")
            .replace_before_compare_once = Some(value);
    }

    fn compare_calls(&self) -> u64 {
        self.state
            .lock()
            .expect("watermark test mutex")
            .compare_calls
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
        state.compare_calls += 1;
        if let Some(replacement) = state.replace_before_compare_once.take() {
            state.value = Some(replacement);
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
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
fn lifetime_inventory_is_kind_exact_and_stable_across_pinned_activation() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let mut producer = ExactTestProducer::new(key);
    let first_vote = vote(&profile, 1, 3, 0x31);
    let mut journal =
        SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
            .expect("initialize journal");
    journal
        .sign_exact_v0(&first_vote, &mut producer)
        .expect("sign first Vote");
    journal
        .sign_exact_v0(&timeout(&profile, 2, 4, 0x41), &mut producer)
        .expect("sign TimeoutVote");
    journal
        .sign_exact_v0(&vote(&profile, 3, 5, 0x51), &mut producer)
        .expect("sign second Vote");
    journal
        .sign_exact_v0(&first_vote, &mut producer)
        .expect("exact Vote replay");
    assert_eq!(producer.calls(), 3, "exact replay cannot create an intent");

    let operational = journal
        .confirm_node_checkpoint_head_exact_v0()
        .expect("fresh operational inventory");
    let expected = operational.lifetime_inventory();
    assert_eq!(expected.durable_vote_intent_count(), 2);
    assert_eq!(expected.durable_timeout_intent_count(), 1);
    assert_eq!(expected.signed_vote_intent_count(), 2);
    assert_eq!(expected.signed_timeout_intent_count(), 1);
    assert_ne!(expected.inventory_digest(), [0; 32]);

    let mut pinned = journal.into_pinned_v0().expect("pin operational journal");
    assert_eq!(pinned.reconciliation_facts().lifetime_inventory(), expected);
    assert_eq!(
        pinned
            .confirm_node_checkpoint_head_exact_v0()
            .expect("fresh pinned inventory")
            .lifetime_inventory(),
        expected
    );
    let mut activated = pinned
        .activate_v0()
        .unwrap_or_else(|failure| panic!("activate exact inventory: {}", failure.error()));
    assert_eq!(
        activated
            .confirm_node_checkpoint_head_exact_v0()
            .expect("fresh reactivated inventory")
            .lifetime_inventory(),
        expected
    );
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

    let before = durable_namespace_bytes(&path);
    let compare_calls = watermark.compare_calls();
    let mut pinned =
        SqliteSignerJournalV0::pin_existing_v0(&path, profile.clone(), watermark.clone())
            .expect("pin exact prepared intent");
    let checkpoint = pinned
        .confirm_node_checkpoint_head_exact_v0()
        .expect("prepared exact head can produce inert checkpoint facts");
    assert_eq!(
        checkpoint.tail().expect("prepared checkpoint tail").state(),
        SignerJournalTailStateV0::Prepared
    );
    assert_eq!(
        checkpoint
            .pending_intent()
            .expect("prepared checkpoint intent")
            .fingerprint(),
        intent.fingerprint().into_bytes()
    );
    let pending_inventory = checkpoint.lifetime_inventory();
    assert_eq!(pending_inventory.durable_vote_intent_count(), 1);
    assert_eq!(pending_inventory.durable_timeout_intent_count(), 0);
    assert_eq!(pending_inventory.signed_vote_intent_count(), 0);
    assert_eq!(pending_inventory.signed_timeout_intent_count(), 0);
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);
    let mut reopened = pinned
        .activate_v0()
        .unwrap_or_else(|failure| panic!("activate exact prepared journal: {}", failure.error()));
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
    let completed_inventory = reopened
        .confirm_node_checkpoint_head_exact_v0()
        .expect("fresh completed inventory")
        .lifetime_inventory();
    assert_eq!(completed_inventory.durable_vote_intent_count(), 1);
    assert_eq!(completed_inventory.signed_vote_intent_count(), 1);
    assert_eq!(completed_inventory.durable_timeout_intent_count(), 0);
    assert_eq!(completed_inventory.signed_timeout_intent_count(), 0);
    assert_ne!(
        completed_inventory.inventory_digest(),
        pending_inventory.inventory_digest(),
        "signed lifecycle must change the bound inventory digest"
    );
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

#[test]
fn initialized_owner_transitions_through_pinned_confirmation_and_back_to_signing() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let journal = SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
        .expect("initialize journal");
    let before = durable_namespace_bytes(&path);
    let compare_calls = watermark.compare_calls();

    let mut pinned = journal
        .into_pinned_v0()
        .expect("transition initialized owner to a read-only pinned owner");
    let facts = pinned.reconciliation_facts();
    assert_eq!(
        facts.external_relation(),
        SignerExternalWatermarkRelationV0::Exact
    );
    assert_eq!(facts.local_watermark(), facts.observed_external_watermark());
    assert_eq!(facts.capacity().event_count(), 0);
    assert!(facts.tail().is_none());
    assert!(facts.pending_intent().is_none());
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);

    let checkpoint = pinned
        .confirm_node_checkpoint_head_exact_v0()
        .expect("confirm the transitioned pinned owner");
    assert_eq!(checkpoint.journal_id(), facts.journal_id());
    assert_eq!(checkpoint.exact_watermark(), facts.local_watermark());
    assert_eq!(checkpoint.capacity(), facts.capacity());
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);

    let mut activated = pinned.activate_v0().unwrap_or_else(|failure| {
        panic!(
            "reactivate the transitioned pinned owner: {}",
            failure.error()
        )
    });
    assert_eq!(watermark.compare_calls(), compare_calls);
    let mut producer = ExactTestProducer::new(key);
    activated
        .sign_exact_v0(&vote(&profile, 1, 3, 0x53), &mut producer)
        .expect("sign after initialized-to-pinned transition");
    assert_eq!(producer.calls(), 1);
    assert_eq!(activated.capacity().expect("capacity").event_count(), 2);
}

#[test]
fn pinned_exact_open_is_read_only_and_activation_needs_no_external_cas() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let mut journal =
        SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
            .expect("initialize journal");
    let mut producer = ExactTestProducer::new(key);
    journal
        .sign_exact_v0(&vote(&profile, 1, 3, 0x31), &mut producer)
        .expect("persist signed tail");
    drop(journal);

    let before = durable_namespace_bytes(&path);
    let compare_calls = watermark.compare_calls();
    let mut pinned =
        SqliteSignerJournalV0::pin_existing_v0(&path, profile.clone(), watermark.clone())
            .expect("pin existing exact journal");
    let facts = pinned.reconciliation_facts();
    assert_eq!(
        facts.external_relation(),
        SignerExternalWatermarkRelationV0::Exact
    );
    assert_eq!(facts.local_watermark(), facts.observed_external_watermark());
    assert_eq!(facts.capacity().event_count(), 2);
    assert!(facts.pending_intent().is_none());
    let tail = facts.tail().expect("signed tail facts");
    assert_eq!(tail.state(), SignerJournalTailStateV0::Signed);
    assert_eq!(tail.safety_revision(), 1);
    assert_eq!(tail.view(), 3);
    assert_eq!(tail.kind(), 0);
    assert_ne!(tail.fingerprint(), [0; 32]);
    assert_ne!(tail.signing_root(), [0; 32]);
    assert_ne!(tail.intent_checksum(), [0; 32]);
    assert!(tail.signature().is_some());
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);

    let checkpoint = pinned
        .confirm_node_checkpoint_head_exact_v0()
        .expect("confirm exact signer checkpoint facts");
    assert_eq!(checkpoint.journal_id(), facts.journal_id());
    assert_eq!(checkpoint.profile_checksum(), profile.profile_checksum());
    assert_eq!(checkpoint.exact_watermark(), facts.local_watermark());
    assert_eq!(checkpoint.capacity(), facts.capacity());
    assert_eq!(checkpoint.tail(), facts.tail());
    assert_eq!(checkpoint.pending_intent(), facts.pending_intent());
    let identity = checkpoint.identity();
    assert_eq!(identity.chain_id(), profile.chain_id());
    assert_eq!(identity.protocol_version(), profile.protocol_version());
    assert_eq!(identity.epoch(), profile.epoch());
    assert_eq!(identity.validator_set_id(), profile.validator_set_id());
    assert_eq!(identity.author(), profile.author());
    assert_eq!(identity.signer_profile_ref(), profile.signer_profile_ref());
    assert_eq!(
        identity.external_watermark_scope(),
        profile.external_watermark_scope()
    );
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);

    let activated = pinned
        .activate_v0()
        .unwrap_or_else(|failure| panic!("activate exact pinned journal: {}", failure.error()));
    assert_eq!(watermark.compare_calls(), compare_calls);
    drop(activated);
}

#[test]
fn node_checkpoint_confirmation_freshly_requires_exact_external_head_without_cas() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, _) = fixture();
    let watermark = MemoryWatermark::default();
    let journal = SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
        .expect("initialize journal");
    drop(journal);

    let mut pinned = SqliteSignerJournalV0::pin_existing_v0(&path, profile, watermark.clone())
        .expect("pin exact journal");
    let local = pinned.reconciliation_facts().local_watermark();
    let before = durable_namespace_bytes(&path);
    let compare_calls = watermark.compare_calls();

    watermark.clear();
    assert!(matches!(
        pinned.confirm_node_checkpoint_head_exact_v0(),
        Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkMissing
        ))
    ));
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);

    let ahead = SignerWatermarkV0::from_persisted_parts(
        local.scope(),
        local.journal_id(),
        local.sequence() + 1,
        [0xa4; 32],
    )
    .expect("shape-valid ahead watermark");
    watermark.replace(ahead);
    assert!(matches!(
        pinned.confirm_node_checkpoint_head_exact_v0(),
        Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkAhead
        ))
    ));
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);

    watermark.replace(local);
    let confirmed = pinned
        .confirm_node_checkpoint_head_exact_v0()
        .expect("fresh exact external head is admitted");
    assert_eq!(confirmed.exact_watermark(), local);
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);
}

#[test]
fn operational_node_checkpoint_confirmation_is_exact_and_never_repairs_watermark() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, _) = fixture();
    let watermark = MemoryWatermark::default();
    let mut journal =
        SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
            .expect("initialize operational journal");
    let initial = watermark.current().expect("initial external watermark");
    let compare_calls = watermark.compare_calls();
    let before = durable_namespace_bytes(&path);

    let confirmed = journal
        .confirm_node_checkpoint_head_exact_v0()
        .expect("exact operational head is admitted");
    assert_eq!(confirmed.exact_watermark(), initial);
    assert!(confirmed.belongs_to_operational_journal_at_path_v0(&journal, &path));
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);

    watermark.clear();
    assert!(matches!(
        journal.confirm_node_checkpoint_head_exact_v0(),
        Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkMissing
        ))
    ));
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);

    let ahead = SignerWatermarkV0::from_persisted_parts(
        initial.scope(),
        initial.journal_id(),
        initial.sequence() + 1,
        [0xc4; 32],
    )
    .expect("shape-valid foreign successor");
    watermark.replace(ahead);
    assert!(matches!(
        journal.confirm_node_checkpoint_head_exact_v0(),
        Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkRepairRequired
        ))
    ));
    assert_eq!(watermark.current(), Some(ahead));
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &before);
}

#[test]
fn pinned_one_behind_open_defers_external_repair_until_activation() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let mut producer = ExactTestProducer::new(key);
    let mut journal =
        SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
            .expect("initialize journal");
    watermark.fail_target_sequence_once(1);
    assert!(matches!(
        journal.sign_exact_v0(&vote(&profile, 1, 7, 1), &mut producer),
        Err(SignerJournalErrorV0::ExternalWatermark { .. })
    ));
    drop(journal);

    let external_before = watermark.current().expect("external predecessor");
    let bytes_before = durable_namespace_bytes(&path);
    let compare_calls = watermark.compare_calls();
    let mut pinned = SqliteSignerJournalV0::pin_existing_v0(&path, profile, watermark.clone())
        .expect("pin local-first journal");
    let facts = pinned.reconciliation_facts();
    assert_eq!(
        facts.external_relation(),
        SignerExternalWatermarkRelationV0::LocalOneAhead
    );
    assert_eq!(facts.observed_external_watermark(), external_before);
    assert_eq!(facts.local_watermark().sequence(), 1);
    let pending = facts.pending_intent().expect("prepared tail facts");
    let tail = facts.tail().expect("journal tail facts");
    assert_eq!(tail.state(), SignerJournalTailStateV0::Prepared);
    assert_eq!(tail.fingerprint(), pending.fingerprint());
    assert!(tail.signature().is_none());
    assert_eq!(pending.safety_revision(), 1);
    assert_eq!(pending.view(), 7);
    assert_eq!(pending.kind(), 0);
    assert_ne!(pending.fingerprint(), [0; 32]);
    assert_ne!(pending.signing_root(), [0; 32]);
    assert_ne!(pending.intent_checksum(), [0; 32]);
    assert_eq!(watermark.current(), Some(external_before));
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &bytes_before);

    assert!(matches!(
        pinned.confirm_node_checkpoint_head_exact_v0(),
        Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkRepairRequired
        ))
    ));
    assert_eq!(watermark.compare_calls(), compare_calls);
    assert_durable_namespace_unchanged(&path, &bytes_before);

    let activated = pinned.activate_v0().unwrap_or_else(|failure| {
        panic!("activate local-first pinned journal: {}", failure.error())
    });
    assert_eq!(watermark.current(), Some(facts.local_watermark()));
    assert_eq!(watermark.compare_calls(), compare_calls + 1);
    drop(activated);
}

#[test]
fn pinned_open_rejects_external_ahead_and_foreign_identity_without_local_writes() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, _) = fixture();
    let watermark = MemoryWatermark::default();
    let journal = SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
        .expect("initialize journal");
    drop(journal);
    let local = watermark.current().expect("initial external watermark");
    let before = durable_namespace_bytes(&path);

    let ahead = SignerWatermarkV0::from_persisted_parts(
        local.scope(),
        local.journal_id(),
        local.sequence() + 1,
        [0xa1; 32],
    )
    .expect("shape-valid ahead watermark");
    watermark.replace(ahead);
    assert!(matches!(
        SqliteSignerJournalV0::pin_existing_v0(&path, profile.clone(), watermark.clone()),
        Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkAhead
        ))
    ));
    assert_durable_namespace_unchanged(&path, &before);

    let foreign = SignerWatermarkV0::from_persisted_parts(
        local.scope(),
        [0xb2; 32],
        local.sequence(),
        local.chain_checksum(),
    )
    .expect("shape-valid foreign watermark");
    watermark.replace(foreign);
    assert!(matches!(
        SqliteSignerJournalV0::pin_existing_v0(&path, profile, watermark.clone()),
        Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkFork
        ))
    ));
    assert_eq!(watermark.current(), Some(foreign));
    assert_durable_namespace_unchanged(&path, &before);
}

#[test]
fn activation_cas_race_returns_the_unique_pinned_owner_without_local_writes() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let mut producer = ExactTestProducer::new(key);
    let mut journal =
        SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
            .expect("initialize journal");
    watermark.fail_target_sequence_once(1);
    assert!(matches!(
        journal.sign_exact_v0(&vote(&profile, 1, 8, 1), &mut producer),
        Err(SignerJournalErrorV0::ExternalWatermark { .. })
    ));
    drop(journal);

    let pinned = SqliteSignerJournalV0::pin_existing_v0(&path, profile.clone(), watermark.clone())
        .expect("pin local-first journal");
    let local = pinned.reconciliation_facts().local_watermark();
    let before = durable_namespace_bytes(&path);
    watermark.replace_before_compare_once(local);
    let failure = match pinned.activate_v0() {
        Ok(_) => panic!("raced activation must not return an operational owner"),
        Err(failure) => failure,
    };
    assert!(matches!(
        failure.error(),
        SignerJournalErrorV0::ExternalWatermark {
            source: ExternalWatermarkErrorV0::CompareFailed,
            ..
        }
    ));
    assert_durable_namespace_unchanged(&path, &before);
    let retained = failure.into_pinned();
    assert_eq!(
        retained.reconciliation_facts().external_relation(),
        SignerExternalWatermarkRelationV0::LocalOneAhead
    );
    assert!(matches!(
        SqliteSignerJournalV0::pin_existing_v0(&path, profile.clone(), watermark.clone()),
        Err(SignerJournalErrorV0::Locked)
    ));
    drop(retained);

    let reopened = SqliteSignerJournalV0::pin_existing_v0(&path, profile, watermark)
        .expect("race winner left an exact reopenable watermark");
    assert_eq!(
        reopened.reconciliation_facts().external_relation(),
        SignerExternalWatermarkRelationV0::Exact
    );
}

#[test]
fn pinned_open_deep_audits_local_state_and_holds_the_lifetime_lock() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, _) = fixture();
    let watermark = MemoryWatermark::default();
    let journal = SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
        .expect("initialize journal");
    drop(journal);

    let pinned = SqliteSignerJournalV0::pin_existing_v0(&path, profile.clone(), watermark.clone())
        .expect("pin authenticated journal");
    assert!(matches!(
        SqliteSignerJournalV0::open_existing(&path, profile.clone(), watermark.clone()),
        Err(SignerJournalErrorV0::Locked)
    ));
    let pinned_external = watermark.current();
    let pinned_durable = durable_namespace_bytes(&path);
    drop(pinned);
    assert_eq!(watermark.current(), pinned_external);
    assert_durable_namespace_unchanged(&path, &pinned_durable);

    let connection = Connection::open(&path).expect("open raw tamper connection");
    connection
        .execute(
            "UPDATE signer_journal_head_v0 SET head_checksum=zeroblob(32) WHERE singleton=1",
            [],
        )
        .expect("tamper head checksum");
    // Keep the raw WAL connection alive while the pinned opener audits the
    // tamper. Closing a non-persistent raw SQLite connection is allowed to
    // delete an empty `-wal`, which would correctly trip the namespace check
    // before reaching the intended head-checksum audit.
    let external_before = watermark.current();
    let error = match SqliteSignerJournalV0::pin_existing_v0(&path, profile, watermark.clone()) {
        Ok(_) => panic!("tampered head checksum must fail pinned open"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            SignerJournalErrorV0::PersistedRepresentationMalformed("head checksum")
        ),
        "unexpected tampered-head pinned-open error: {error:?}"
    );
    assert_eq!(watermark.current(), external_before);
    drop(connection);
}

#[test]
fn per_kind_inventory_tamper_is_rejected_by_the_full_pinned_audit() {
    let temporary = TempDir::new().expect("private temporary directory");
    let path = database_path(&temporary);
    let (profile, _, key) = fixture();
    let watermark = MemoryWatermark::default();
    let mut producer = ExactTestProducer::new(key);
    let mut journal =
        SqliteSignerJournalV0::initialize_new(&path, profile.clone(), watermark.clone())
            .expect("initialize journal");
    journal
        .sign_exact_v0(&vote(&profile, 1, 3, 0x61), &mut producer)
        .expect("persist one Vote intent");
    drop(journal);

    let connection = Connection::open(&path).expect("open raw tamper connection");
    connection
        .execute_batch(
            "DROP TRIGGER sign_intents_no_update_v0;
             UPDATE sign_intents_v0 SET intent_kind=1;
             CREATE TRIGGER sign_intents_no_update_v0
                 BEFORE UPDATE ON sign_intents_v0
                 BEGIN SELECT RAISE(ABORT, 'sign intents are append-only'); END;",
        )
        .expect("tamper kind while restoring the canonical trigger");
    let external_before = watermark.current();
    let error = match SqliteSignerJournalV0::pin_existing_v0(&path, profile, watermark.clone()) {
        Ok(_) => panic!("kind-substituted inventory must fail pinned open"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            SignerJournalErrorV0::PersistedRepresentationMalformed("canonical intent row")
        ),
        "unexpected kind-substitution error: {error:?}"
    );
    assert_eq!(watermark.current(), external_before);
    drop(connection);
}

fn copy_namespace(database: &Path, backup: &Path) {
    for suffix in ["", "-wal", "-shm", ".signer.lock"] {
        let source = path_with_suffix(database, suffix);
        let target = backup.join(source.file_name().expect("namespace file name"));
        fs::copy(source, target).expect("copy signer namespace");
    }
}

/// SQLite's `-shm` file is a volatile WAL-index/locking coordination region.
/// Opening a read-only WAL connection can legitimately rewrite those bytes;
/// they are neither journal history nor an anti-rollback root. The main DB,
/// WAL, and signer lifetime-lock sidecar are the durable namespace whose bytes
/// must remain exact before pinned activation.
fn durable_namespace_bytes(database: &Path) -> BTreeMap<String, Vec<u8>> {
    ["", "-wal", ".signer.lock"]
        .into_iter()
        .map(|suffix| {
            let path = path_with_suffix(database, suffix);
            (
                suffix.to_owned(),
                fs::read(path).expect("read signer namespace bytes"),
            )
        })
        .collect()
}

fn assert_durable_namespace_unchanged(database: &Path, before: &BTreeMap<String, Vec<u8>>) {
    let after = durable_namespace_bytes(database);
    for suffix in ["", "-wal", ".signer.lock"] {
        assert_eq!(
            after.get(suffix),
            before.get(suffix),
            "pinned signer startup changed durable namespace suffix {suffix:?}"
        );
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
