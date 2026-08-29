//! Review-only model for the signer journal's external watermark contract.
//!
//! This is a memory-only test double. It is not a filesystem service, HSM,
//! KMS, TPM, validator credential, or production anti-rollback implementation.
//! Its purpose is to make the required fail-stop boundary executable before a
//! real independently administered monotonic register is wired in.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};

use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, ExternalWatermarkSemanticFactsV0,
    SignatureProducerErrorV0, SignatureProducerV0, SignatureRequestV0, SignerJournalErrorV0,
    SignerJournalProfileV0, SignerWatermarkV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    BlockId, CanonicalSignIntentV0, ChainId, ConsensusParametersHash, ConsensusPublicKey, Epoch,
    GenesisHash, Height, ProtocolVersion, SignatureBytes, Validator, ValidatorId, ValidatorSet,
    View, VotingPower,
};

const SCOPE: [u8; 32] = [0x72; 32];
const PROFILE_REF: [u8; 32] = [0x51; 32];
const TEST_SEED: [u8; 32] = [0x19; 32];
const MAX_DATABASE_BYTES: usize = 32 * 1024 * 1024;
const RECORD_DOMAIN: &[u8] = b"trnm.review.external-watermark-record.v0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Record {
    value: SignerWatermarkV0,
    predecessor: [u8; 32],
    digest: [u8; 32],
}

#[derive(Debug, Default)]
struct RegisterState {
    records: Vec<Record>,
    // Models a head held outside the local SQLite/WAL namespace.
    committed_head: Option<(SignerWatermarkV0, [u8; 32])>,
}

#[derive(Debug, Clone, Default)]
struct AppendOnlyRegister {
    state: Arc<Mutex<RegisterState>>,
}

impl AppendOnlyRegister {
    fn digest(predecessor: [u8; 32], value: SignerWatermarkV0) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(RECORD_DOMAIN);
        hash.update(predecessor);
        hash.update(value.scope());
        hash.update(value.journal_id());
        hash.update(value.sequence().to_be_bytes());
        hash.update(value.chain_checksum());
        hash.finalize().into()
    }

    // Test-only fault injectors model an operator restoring or rewriting the
    // local journal. The committed head is intentionally not changed.
    fn tamper_record_for_test(&self, index: usize, value: SignerWatermarkV0) {
        self.state.lock().unwrap().records[index].value = value;
    }

    fn truncate_for_test(&self, length: usize) {
        self.state.lock().unwrap().records.truncate(length);
    }

    fn validate_locked(
        state: &RegisterState,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let mut predecessor = [0; 32];
        let mut previous: Option<SignerWatermarkV0> = None;
        for (index, record) in state.records.iter().enumerate() {
            let sequence =
                u64::try_from(index).map_err(|_| ExternalWatermarkErrorV0::CapacityExhausted)?;
            if record.value.scope() != scope
                || record.value.sequence() != sequence
                || record.predecessor != predecessor
                || record.digest != Self::digest(predecessor, record.value)
            {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            if let Some(old) = previous {
                if old.scope() != record.value.scope()
                    || old.journal_id() != record.value.journal_id()
                    || old.sequence().checked_add(1) != Some(record.value.sequence())
                {
                    return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
                }
            }
            previous = Some(record.value);
            predecessor = record.digest;
        }
        match (previous, state.committed_head) {
            (None, None) => Ok(None),
            (Some(value), Some((head, digest))) if value == head && predecessor == digest => {
                Ok(Some(value))
            }
            // Never reconstruct a head from local bytes after a mismatch.
            _ => Err(ExternalWatermarkErrorV0::InvalidPersistedState),
        }
    }
}

impl ExternalMonotonicWatermarkV0 for AppendOnlyRegister {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        Self::validate_locked(&self.state.lock().unwrap(), scope)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        let mut state = self.state.lock().unwrap();
        let current = Self::validate_locked(&state, target.scope())?;
        if current != expected {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        match expected {
            None if target.sequence() == 0 => {}
            Some(old)
                if old.scope() == target.scope()
                    && old.journal_id() == target.journal_id()
                    && old.sequence().checked_add(1) == Some(target.sequence()) => {}
            _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
        }
        let predecessor = state.records.last().map_or([0; 32], |r| r.digest);
        let digest = Self::digest(predecessor, target);
        state.records.push(Record {
            value: target,
            predecessor,
            digest,
        });
        // A real implementation would atomically advance an external device
        // or service here; this assignment is only the test model.
        state.committed_head = Some((target, digest));
        Ok(())
    }
}

/// Semantic test authority used to prove the journal dispatch boundary.  It
/// deliberately rejects every legacy opaque operation; the journal must use
/// the semantic methods for both genesis claim and each intent head.
#[derive(Debug, Clone, Default)]
struct SemanticRegister {
    state: Arc<Mutex<RegisterState>>,
    observations: Arc<Mutex<Vec<ExternalWatermarkSemanticFactsV0>>>,
    genesis_claims: Arc<Mutex<u64>>,
    semantic_facts: Arc<Mutex<BTreeMap<u64, ExternalWatermarkSemanticFactsV0>>>,
    per_reservation: bool,
}

impl SemanticRegister {
    fn per_reservation() -> Self {
        Self {
            per_reservation: true,
            ..Self::default()
        }
    }

    fn genesis_facts() -> ExternalWatermarkSemanticFactsV0 {
        ExternalWatermarkSemanticFactsV0::new(
            0,
            0,
            1,
            [0x71; 32],
            [0x72; 32],
            [0x73; 32],
            [0x74; 32],
        )
        .expect("valid semantic genesis facts")
    }

    fn tamper_semantic_facts_for_test(&self, sequence: u64) {
        let mut facts = self.semantic_facts.lock().unwrap();
        let mut value = facts
            .get(&sequence)
            .copied()
            .expect("semantic facts exist for tamper test");
        value.request_fingerprint[0] ^= 0x01;
        facts.insert(sequence, value);
    }

    fn current(
        &self,
        scope: [u8; 32],
        journal_id: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let state = self.state.lock().unwrap();
        let current = AppendOnlyRegister::validate_locked(&state, scope)?;
        if current.is_some_and(|value| value.journal_id() != journal_id) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(current)
    }
}

impl ExternalMonotonicWatermarkV0 for SemanticRegister {
    fn load(
        &mut self,
        _scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        Err(ExternalWatermarkErrorV0::InvalidPersistedState)
    }

    fn compare_and_advance(
        &mut self,
        _expected: Option<SignerWatermarkV0>,
        _target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        Err(ExternalWatermarkErrorV0::InvalidPersistedState)
    }

    fn semantic_mode_v0(&self) -> bool {
        true
    }

    fn semantic_per_reservation_v0(&self) -> bool {
        self.per_reservation
    }

    fn semantic_signer_journal_pair_v0(&self) -> bool {
        !self.per_reservation
    }

    fn load_semantic_v0(
        &mut self,
        scope: [u8; 32],
        journal_id: [u8; 32],
    ) -> Result<
        Option<(SignerWatermarkV0, ExternalWatermarkSemanticFactsV0)>,
        ExternalWatermarkErrorV0,
    > {
        let Some(value) = self.current(scope, journal_id)? else {
            return Ok(None);
        };
        let facts = self
            .semantic_facts
            .lock()
            .unwrap()
            .get(&value.sequence())
            .copied()
            .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
        Ok(Some((value, facts)))
    }

    fn compare_and_advance_semantic_v0(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
        facts: ExternalWatermarkSemanticFactsV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        assert_eq!(facts.capability, [0; 32]);
        self.observations.lock().unwrap().push(facts);
        let mut register = AppendOnlyRegister {
            state: Arc::clone(&self.state),
        };
        register.compare_and_advance(expected, target)?;
        let stored = ExternalWatermarkSemanticFactsV0::new(
            facts.epoch,
            facts.view,
            facts.safety_revision,
            facts.request_nonce,
            facts.request_fingerprint,
            facts.signing_root,
            [0x74; 32],
        )
        .expect("valid stored semantic facts");
        self.semantic_facts
            .lock()
            .unwrap()
            .insert(target.sequence(), stored);
        Ok(())
    }

    fn compare_and_advance_semantic_genesis_v0(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        assert_eq!(expected, None);
        assert_eq!(target.sequence(), 0);
        *self.genesis_claims.lock().unwrap() += 1;
        let mut register = AppendOnlyRegister {
            state: Arc::clone(&self.state),
        };
        register.compare_and_advance(expected, target)?;
        self.semantic_facts
            .lock()
            .unwrap()
            .insert(target.sequence(), Self::genesis_facts());
        Ok(())
    }
}

/// Adapter-shaped test double that deliberately omits the explicit pair
/// attestation.  The signer journal must reject it even though it reports
/// semantic mode and the legacy per-reservation bit is false.
#[derive(Debug, Clone, Default)]
struct UnattestedSemanticRegister(SemanticRegister);

impl ExternalMonotonicWatermarkV0 for UnattestedSemanticRegister {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        self.0.load(scope)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        self.0.compare_and_advance(expected, target)
    }

    fn semantic_mode_v0(&self) -> bool {
        self.0.semantic_mode_v0()
    }

    fn load_semantic_v0(
        &mut self,
        scope: [u8; 32],
        journal_id: [u8; 32],
    ) -> Result<
        Option<(SignerWatermarkV0, ExternalWatermarkSemanticFactsV0)>,
        ExternalWatermarkErrorV0,
    > {
        self.0.load_semantic_v0(scope, journal_id)
    }

    fn compare_and_advance_semantic_v0(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
        facts: ExternalWatermarkSemanticFactsV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        self.0
            .compare_and_advance_semantic_v0(expected, target, facts)
    }

    fn compare_and_advance_semantic_genesis_v0(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        self.0
            .compare_and_advance_semantic_genesis_v0(expected, target)
    }
}

/// Deliberately contradictory adapter: it advertises the pair bit while
/// remaining in opaque mode.  The signer boundary must reject this before it
/// consults or creates any local journal bytes.
#[derive(Debug, Clone, Default)]
struct ContradictorySemanticRegister;

impl ExternalMonotonicWatermarkV0 for ContradictorySemanticRegister {
    fn load(
        &mut self,
        _scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        Err(ExternalWatermarkErrorV0::InvalidPersistedState)
    }

    fn compare_and_advance(
        &mut self,
        _expected: Option<SignerWatermarkV0>,
        _target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        Err(ExternalWatermarkErrorV0::InvalidPersistedState)
    }

    fn semantic_signer_journal_pair_v0(&self) -> bool {
        true
    }
}

#[derive(Debug, Default)]
struct ProducerState {
    calls: u64,
    responses: BTreeMap<[u8; 32], ([u8; 32], [u8; 64])>,
}

#[derive(Clone)]
struct ReplayBoundProducer {
    key: Arc<SigningKey>,
    state: Arc<Mutex<ProducerState>>,
}

impl ReplayBoundProducer {
    fn new(key: SigningKey) -> Self {
        Self {
            key: Arc::new(key),
            state: Arc::new(Mutex::new(ProducerState::default())),
        }
    }

    fn calls(&self) -> u64 {
        self.state.lock().unwrap().calls
    }
}

impl SignatureProducerV0 for ReplayBoundProducer {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        assert_eq!(request.signer_profile_ref(), PROFILE_REF);
        let fingerprint = request.fingerprint().into_bytes();
        let root = *request.signing_root().as_bytes();
        let mut state = self.state.lock().unwrap();
        state.calls += 1;
        if let Some((stored_root, signature)) = state.responses.get(&fingerprint) {
            return if *stored_root == root {
                Ok(SignatureBytes::from_array(*signature))
            } else {
                Err(SignatureProducerErrorV0::Rejected)
            };
        }
        let signature = self.key.sign(&root).to_bytes();
        state.responses.insert(fingerprint, (root, signature));
        Ok(SignatureBytes::from_array(signature))
    }
}

fn fixture() -> (SignerJournalProfileV0, SigningKey) {
    let key = SigningKey::from_bytes(&TEST_SEED);
    let author = ValidatorId::from_bytes(b"validator-a").unwrap();
    let validator = Validator::new(
        author,
        ConsensusPublicKey::new(key.verifying_key().to_bytes()),
        VotingPower::new(1).unwrap(),
    )
    .unwrap();
    let second_key = SigningKey::from_bytes(&[0x29; 32]);
    let second = Validator::new(
        ValidatorId::from_bytes(b"validator-b").unwrap(),
        ConsensusPublicKey::new(second_key.verifying_key().to_bytes()),
        VotingPower::new(1).unwrap(),
    )
    .unwrap();
    let set = ValidatorSet::new(
        GenesisHash::new([0x31; 32]),
        ChainId::new("trnm-watermark-contract").unwrap(),
        ProtocolVersion::V0,
        Epoch::new(0),
        ConsensusParametersHash::new([0x42; 32]),
        vec![validator, second],
    )
    .unwrap();
    (
        SignerJournalProfileV0::new(
            set,
            author,
            PROFILE_REF,
            SCOPE,
            64,
            4096,
            MAX_DATABASE_BYTES,
        )
        .unwrap(),
        key,
    )
}

fn vote(
    profile: &SignerJournalProfileV0,
    revision: u64,
    view: u64,
    byte: u8,
) -> CanonicalSignIntentV0 {
    CanonicalSignIntentV0::vote(
        profile.validator_set(),
        profile.author(),
        revision,
        View::new(view),
        Height::new(view + 1),
        BlockId::new([byte; 32]),
    )
    .unwrap()
}

fn db_path(temp: &TempDir) -> std::path::PathBuf {
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temp.path().join("signer.sqlite3")
}

fn watermark(sequence: u64, checksum: u8) -> SignerWatermarkV0 {
    SignerWatermarkV0::from_persisted_parts(SCOPE, [0x33; 32], sequence, [checksum; 32]).unwrap()
}

#[test]
fn append_only_register_rejects_rollback_rewrite_and_tail_truncation() {
    let mut register = AppendOnlyRegister::default();
    let first = watermark(0, 0x11);
    let second = watermark(1, 0x22);
    register.compare_and_advance(None, first).unwrap();
    register.compare_and_advance(Some(first), second).unwrap();
    assert_eq!(register.load(SCOPE).unwrap(), Some(second));
    assert_eq!(
        register.compare_and_advance(Some(second), first),
        Err(ExternalWatermarkErrorV0::InvalidPersistedState)
    );

    register.tamper_record_for_test(1, first);
    assert_eq!(
        register.load(SCOPE),
        Err(ExternalWatermarkErrorV0::InvalidPersistedState)
    );

    let register = AppendOnlyRegister::default();
    let mut writer = register.clone();
    writer.compare_and_advance(None, first).unwrap();
    writer.compare_and_advance(Some(first), second).unwrap();
    register.truncate_for_test(1);
    assert_eq!(
        writer.load(SCOPE),
        Err(ExternalWatermarkErrorV0::InvalidPersistedState)
    );
}

#[test]
fn journal_replays_without_hsm_and_fails_closed_after_external_tamper() {
    let (profile, key) = fixture();
    let temp = TempDir::new().unwrap();
    let register = AppendOnlyRegister::default();
    let mut journal =
        SqliteSignerJournalV0::initialize_new(db_path(&temp), profile.clone(), register.clone())
            .unwrap();
    let mut producer = ReplayBoundProducer::new(key);
    let first = vote(&profile, 1, 1, 0x61);
    let signature = journal.sign_exact_v0(&first, &mut producer).unwrap();
    assert_eq!(
        journal.sign_exact_v0(&first, &mut producer).unwrap(),
        signature
    );
    assert_eq!(
        producer.calls(),
        1,
        "exact replay must not call producer twice"
    );

    // Simulate a local SQLite/WAL rollback. The external committed head is
    // newer, so the next request must stop before reaching the producer.
    register.truncate_for_test(1);
    let calls = producer.calls();
    let next = vote(&profile, 2, 2, 0x62);
    assert!(journal.sign_exact_v0(&next, &mut producer).is_err());
    assert_eq!(producer.calls(), calls);
}

#[test]
fn semantic_journal_dispatch_binds_exact_intent_facts_and_never_opaque() {
    let (profile, key) = fixture();
    let temp = TempDir::new().unwrap();
    let register = SemanticRegister::default();
    let observations = Arc::clone(&register.observations);
    let genesis_claims = Arc::clone(&register.genesis_claims);
    let mut journal =
        SqliteSignerJournalV0::initialize_new(db_path(&temp), profile.clone(), register)
            .expect("initialize semantic signer journal");
    assert_eq!(*genesis_claims.lock().unwrap(), 1);

    let mut producer = ReplayBoundProducer::new(key);
    let intent = vote(&profile, 7, 3, 0x73);
    journal
        .sign_exact_v0(&intent, &mut producer)
        .expect("semantic signer intent");
    let facts = observations.lock().unwrap();
    assert_eq!(
        facts.len(),
        2,
        "intent and signed head each use semantic CAS"
    );
    assert!(facts.iter().all(|facts| facts.capability == [0; 32]));
    assert!(facts
        .iter()
        .all(|facts| facts.epoch == intent.epoch().get()));
    assert!(facts.iter().all(|facts| facts.view == 3));
    assert!(facts
        .iter()
        .all(|facts| facts.request_fingerprint == intent.fingerprint().into_bytes()));
    assert!(facts
        .iter()
        .all(|facts| facts.signing_root == intent.signing_root().into_bytes()));
    assert_eq!(
        facts[0].request_nonce,
        trnm_consensus_signer_journal::signer_journal_lifecycle_nonce_v0(
            intent.epoch().get(),
            intent.view().get(),
            intent.authorizing_safety_revision(),
            intent.fingerprint().into_bytes(),
            intent.signing_root().into_bytes(),
            1,
        )
    );
    assert_eq!(
        facts[1].request_nonce,
        trnm_consensus_signer_journal::signer_journal_lifecycle_nonce_v0(
            intent.epoch().get(),
            intent.view().get(),
            intent.authorizing_safety_revision(),
            intent.fingerprint().into_bytes(),
            intent.signing_root().into_bytes(),
            2,
        )
    );
    assert_ne!(facts[0].request_nonce, facts[1].request_nonce);
}

#[test]
fn altered_loaded_semantic_facts_fail_before_next_producer_call() {
    let (profile, key) = fixture();
    let temp = TempDir::new().unwrap();
    let register = SemanticRegister::default();
    let mut journal =
        SqliteSignerJournalV0::initialize_new(db_path(&temp), profile.clone(), register.clone())
            .expect("initialize semantic signer journal");
    let mut producer = ReplayBoundProducer::new(key);
    let first = vote(&profile, 7, 3, 0x73);
    journal
        .sign_exact_v0(&first, &mut producer)
        .expect("first semantic signature");
    let calls = producer.calls();

    // Keep the external watermark and chain checksum unchanged, but alter a
    // semantic field. The next pre-sign synchronization must reject this
    // mixed cut before appending an intent or invoking the producer.
    register.tamper_semantic_facts_for_test(2);
    let next = vote(&profile, 8, 4, 0x74);
    let error = journal
        .sign_exact_v0(&next, &mut producer)
        .expect_err("altered semantic facts must fail closed");
    assert!(matches!(
        error,
        SignerJournalErrorV0::ExternalWatermark {
            source: ExternalWatermarkErrorV0::InvalidPersistedState,
            ..
        }
    ));
    assert_eq!(producer.calls(), calls, "producer must not see a mixed cut");
}

#[test]
fn per_reservation_external_authority_is_rejected_before_journal_creation() {
    let (profile, _) = fixture();
    let temp = TempDir::new().unwrap();
    let database = db_path(&temp);
    let result = SqliteSignerJournalV0::initialize_new(
        &database,
        profile,
        SemanticRegister::per_reservation(),
    );
    assert!(matches!(
        result,
        Err(SignerJournalErrorV0::InvalidProfile(
            "per-reservation semantic watermark cannot back signer-journal pair lifecycle"
        ))
    ));
    assert!(
        !database.exists(),
        "incompatible semantic authority must be rejected before creating a journal"
    );
}

#[test]
fn unattested_semantic_authority_is_rejected_before_journal_creation() {
    let (profile, _) = fixture();
    let temp = TempDir::new().unwrap();
    let database = db_path(&temp);
    let result = SqliteSignerJournalV0::initialize_new(
        &database,
        profile,
        UnattestedSemanticRegister::default(),
    );
    assert!(matches!(
        result,
        Err(SignerJournalErrorV0::InvalidProfile(
            "semantic watermark lacks explicit signer-journal pair lifecycle attestation"
        ))
    ));
    assert!(
        !database.exists(),
        "unattested semantic authority must be rejected before creating a journal"
    );
}

#[test]
fn contradictory_pair_attestation_is_rejected_before_journal_creation() {
    let (profile, _) = fixture();
    let temp = TempDir::new().unwrap();
    let database = db_path(&temp);
    let result = SqliteSignerJournalV0::initialize_new(
        &database,
        profile,
        ContradictorySemanticRegister,
    );
    assert!(matches!(
        result,
        Err(SignerJournalErrorV0::InvalidProfile(
            "signer-journal pair attestation requires semantic watermark mode"
        ))
    ));
    assert!(!database.exists());
}

#[test]
fn tampered_semantic_predecessor_fails_before_next_producer_call() {
    let (profile, key) = fixture();
    let temp = TempDir::new().unwrap();
    let database = db_path(&temp);
    let register = SemanticRegister::default();
    let mut journal = SqliteSignerJournalV0::initialize_new(
        &database,
        profile.clone(),
        register,
    )
    .expect("initialize semantic signer journal");
    let mut producer = ReplayBoundProducer::new(key);
    journal
        .sign_exact_v0(&vote(&profile, 7, 3, 0x73), &mut producer)
        .expect("persist first semantic signature");
    let calls = producer.calls();

    // Preserve the target head and its external facts, but substitute the
    // predecessor event checksum.  This models an in-place historical row
    // mutation that a pointer-only check would miss.
    let connection = Connection::open(&database).expect("open raw tamper connection");
    connection
        .execute_batch("DROP TRIGGER signer_events_no_update_v0;")
        .expect("drop immutable-event trigger for mutant");
    connection
        .execute(
            "UPDATE signer_journal_events_v0
                SET event_checksum=zeroblob(32)
              WHERE sequence_be=?1",
            [1_u64.to_be_bytes().as_slice()],
        )
        .expect("tamper predecessor checksum");
    connection
        .execute_batch(
            "CREATE TRIGGER signer_events_no_update_v0
                 BEFORE UPDATE ON signer_journal_events_v0
                 BEGIN SELECT RAISE(ABORT, 'signer events are append-only'); END;",
        )
        .expect("restore immutable-event trigger");
    let next = vote(&profile, 8, 4, 0x74);
    let error = journal
        .sign_exact_v0(&next, &mut producer)
        .expect_err("tampered predecessor must fail closed");
    assert!(matches!(
        error,
        SignerJournalErrorV0::PersistedRepresentationMalformed(_)
            |
        SignerJournalErrorV0::ExternalWatermark {
            source: ExternalWatermarkErrorV0::InvalidPersistedState,
            ..
        }
    ));
    assert_eq!(producer.calls(), calls);
    drop(connection);
}
