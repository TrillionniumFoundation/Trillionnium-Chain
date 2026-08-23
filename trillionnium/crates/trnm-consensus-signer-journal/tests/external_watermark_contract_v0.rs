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
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignatureProducerErrorV0,
    SignatureProducerV0, SignatureRequestV0, SignerJournalProfileV0, SignerWatermarkV0,
    SqliteSignerJournalV0,
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
