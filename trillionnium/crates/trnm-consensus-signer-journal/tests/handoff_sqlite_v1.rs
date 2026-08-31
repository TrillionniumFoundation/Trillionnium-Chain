use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use trnm_consensus_signer_journal::{
    inspect_signer_journal_schema_read_only_v1, ExternalMonotonicWatermarkV0,
    ExternalWatermarkErrorV0, HandoffSignatureProducerV1, HandoffSignatureRequestV1,
    HandoffSignerJournalConflictV1, HandoffSignerJournalErrorV1, HandoffSignerJournalProfileV1,
    SignatureProducerErrorV0, SignatureProducerV0, SignatureRequestV0, SignerJournalProfileV0,
    SignerJournalSchemaKindV1, SignerWatermarkV0, SqliteHandoffSignerJournalV1,
    SqliteSignerJournalV0, StrictOldSetHandoffAdmissionV1,
};
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_checkpoint_finality_proof_v0_exact,
    decode_consensus_parameters_v0_exact, decode_handoff_descriptor_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact, BlockHeader, BlockId,
    CanonicalHandoffSignIntentV1, CanonicalSignIntentV0, CertificateId, ConsensusParametersV0,
    HandoffDescriptorV0, Height, QcRef, SignatureBytes, StateRoot, Validator, ValidatorId,
    ValidatorSet, View,
};

const AUTHORITY_VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
);
const PACKAGE_MANIFEST: &str = include_str!("../Cargo.toml");
const SIGNER_PROFILE_REF: [u8; 32] = [0x51; 32];
const WATERMARK_SCOPE: [u8; 32] = [0x72; 32];
const MAXIMUM_DATABASE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WatermarkSnapshot {
    value: Option<SignerWatermarkV0>,
    loads: u64,
    compares: u64,
}

#[derive(Debug, Default)]
struct WatermarkState {
    value: Option<SignerWatermarkV0>,
    loads: u64,
    compares: u64,
    fail_before_apply: BTreeSet<u64>,
    apply_then_fail: BTreeSet<u64>,
}

#[derive(Debug, Clone, Default)]
struct MemoryWatermark {
    state: Arc<Mutex<WatermarkState>>,
}

impl MemoryWatermark {
    fn snapshot(&self) -> WatermarkSnapshot {
        let state = self.state.lock().expect("watermark mutex");
        WatermarkSnapshot {
            value: state.value,
            loads: state.loads,
            compares: state.compares,
        }
    }

    fn fail_before_apply(&self, sequence: u64) {
        self.state
            .lock()
            .expect("watermark mutex")
            .fail_before_apply
            .insert(sequence);
    }

    fn apply_then_fail(&self, sequence: u64) {
        self.state
            .lock()
            .expect("watermark mutex")
            .apply_then_fail
            .insert(sequence);
    }
}

impl ExternalMonotonicWatermarkV0 for MemoryWatermark {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let mut state = self.state.lock().expect("watermark mutex");
        state.loads += 1;
        if state.value.is_some_and(|value| value.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(state.value)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        let mut state = self.state.lock().expect("watermark mutex");
        state.compares += 1;
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
        if state.fail_before_apply.remove(&target.sequence()) {
            return Err(ExternalWatermarkErrorV0::Unavailable);
        }
        state.value = Some(target);
        if state.apply_then_fail.remove(&target.sequence()) {
            return Err(ExternalWatermarkErrorV0::Unavailable);
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct ProducerState {
    normal_calls: u64,
    handoff_calls: u64,
    signatures: BTreeMap<[u8; 32], [u8; 64]>,
    fail_after_sign_once: bool,
    install_sql_once: Option<(PathBuf, String)>,
}

#[derive(Clone)]
struct ExactProducer {
    key: Arc<SigningKey>,
    state: Arc<Mutex<ProducerState>>,
}

impl ExactProducer {
    fn new(key: SigningKey) -> Self {
        Self {
            key: Arc::new(key),
            state: Arc::new(Mutex::new(ProducerState::default())),
        }
    }

    fn calls(&self) -> (u64, u64) {
        let state = self.state.lock().expect("producer mutex");
        (state.normal_calls, state.handoff_calls)
    }

    fn fail_after_sign_once(&self) {
        self.state
            .lock()
            .expect("producer mutex")
            .fail_after_sign_once = true;
    }

    fn install_sql_once(&self, path: PathBuf, sql: impl Into<String>) {
        self.state.lock().expect("producer mutex").install_sql_once = Some((path, sql.into()));
    }

    fn sign_root(
        &self,
        root: [u8; 32],
        handoff: bool,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        let (signature, fail, hook) = {
            let mut state = self.state.lock().expect("producer mutex");
            if handoff {
                state.handoff_calls += 1;
            } else {
                state.normal_calls += 1;
            }
            let signature = *state
                .signatures
                .entry(root)
                .or_insert_with(|| self.key.sign(&root).to_bytes());
            let fail = std::mem::take(&mut state.fail_after_sign_once);
            let hook = state.install_sql_once.take();
            (signature, fail, hook)
        };
        if let Some((path, sql)) = hook {
            Connection::open(path)
                .expect("open injected SQLite fault connection")
                .execute_batch(&sql)
                .expect("install injected SQLite fault");
        }
        if fail {
            return Err(SignatureProducerErrorV0::Unavailable);
        }
        Ok(SignatureBytes::from_array(signature))
    }
}

impl SignatureProducerV0 for ExactProducer {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        assert_eq!(request.signer_profile_ref(), SIGNER_PROFILE_REF);
        self.sign_root(*request.signing_root().as_bytes(), false)
    }
}

impl HandoffSignatureProducerV1 for ExactProducer {
    fn sign_handoff(
        &mut self,
        request: HandoffSignatureRequestV1<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        assert_eq!(request.signer_profile_ref(), SIGNER_PROFILE_REF);
        self.sign_root(*request.signing_root().as_bytes(), true)
    }
}

#[derive(Clone)]
struct AuthorityFixture {
    old_parameters: ConsensusParametersV0,
    new_parameters: ConsensusParametersV0,
    old_set: ValidatorSet,
    new_set: ValidatorSet,
    commitment: trnm_consensus_types::NextEpochCommitmentV0,
    checkpoint_parent: BlockHeader,
    finality: trnm_consensus_types::FinalityProofV0,
    descriptor: HandoffDescriptorV0,
    author: ValidatorId,
    signing_key: SigningKey,
}

impl AuthorityFixture {
    fn profile(&self) -> HandoffSignerJournalProfileV1 {
        HandoffSignerJournalProfileV1::new(
            self.old_set.clone(),
            self.new_set.clone(),
            self.old_parameters,
            self.new_parameters,
            self.author,
            SIGNER_PROFILE_REF,
            WATERMARK_SCOPE,
            64,
            16 * 1024,
            MAXIMUM_DATABASE_BYTES,
        )
        .expect("valid inert schema1 profile")
    }

    fn old_handoff_intent(&self) -> CanonicalHandoffSignIntentV1 {
        CanonicalHandoffSignIntentV1::old_set(
            &self.descriptor,
            &self.old_set,
            &self.new_set,
            &self.old_parameters,
            &self.new_parameters,
            self.author,
        )
        .expect("old handoff intent")
    }

    fn new_handoff_intent(&self) -> CanonicalHandoffSignIntentV1 {
        CanonicalHandoffSignIntentV1::new_set(
            &self.descriptor,
            &self.old_set,
            &self.new_set,
            &self.old_parameters,
            &self.new_parameters,
            self.author,
        )
        .expect("new handoff intent")
    }

    fn admission(&self) -> StrictOldSetHandoffAdmissionV1 {
        StrictOldSetHandoffAdmissionV1::verify(
            &self.old_handoff_intent(),
            &self.finality,
            &self.commitment,
            &self.old_set,
            &self.old_parameters,
            &self.new_set,
            &self.new_parameters,
            &self.checkpoint_parent,
        )
        .expect("strict old-set pre-certificate admission")
    }
}

fn authority_fixture() -> AuthorityFixture {
    let root: Value = serde_json::from_str(AUTHORITY_VECTOR).expect("authority vector JSON");
    let case = object(&root, "positive");
    let preheader = object(case, "preheader");
    let checkpoint_finality = object(case, "checkpoint_finality");
    let handoff = object(case, "handoff");
    let old_parameters =
        decode_consensus_parameters_v0_exact(&raw(preheader, "old_parameters_cev0_hex"))
            .expect("old parameters");
    let new_parameters =
        decode_consensus_parameters_v0_exact(&raw(preheader, "new_parameters_cev0_hex"))
            .expect("new parameters");
    let old_set = decode_validator_set_v0_exact(&raw(preheader, "old_validator_set_cev0_hex"))
        .expect("old validator set");
    let new_set = decode_validator_set_v0_exact(&raw(preheader, "new_validator_set_cev0_hex"))
        .expect("new validator set");
    let commitment = decode_next_epoch_commitment_v0_exact(&raw(preheader, "commitment_cev0_hex"))
        .expect("next-epoch commitment");
    let checkpoint_parent =
        decode_block_header_v0_exact(&raw(preheader, "checkpoint_parent_header_cev0_hex"))
            .expect("checkpoint parent header");
    let finality = decode_checkpoint_finality_proof_v0_exact(
        &raw(checkpoint_finality, "raw_finality_proof_cev0_hex"),
        &old_set,
        &old_parameters,
        &commitment,
        checkpoint_parent.timestamp_ms(),
    )
    .expect("strictly shaped checkpoint/two-seal finality");
    let descriptor = decode_handoff_descriptor_v0_exact(&raw(handoff, "descriptor_cev0_hex"))
        .expect("handoff descriptor");
    let author = ValidatorId::from_bytes(b"validator-a").expect("fixture author");
    let seed: [u8; 32] =
        Sha256::digest(b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:validator-a").into();
    let signing_key = SigningKey::from_bytes(&seed);
    assert_eq!(
        old_set
            .validator(author)
            .expect("old-set fixture author")
            .consensus_key()
            .as_bytes(),
        &signing_key.verifying_key().to_bytes(),
        "the checker-only deterministic seed must match committed public corpus material",
    );
    AuthorityFixture {
        old_parameters,
        new_parameters,
        old_set,
        new_set,
        commitment,
        checkpoint_parent,
        finality,
        descriptor,
        author,
        signing_key,
    }
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .and_then(Value::as_object)
        .map(|_| &value[key])
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn raw(value: &Value, key: &str) -> Vec<u8> {
    let hex = string(value, key).as_bytes();
    assert_eq!(hex.len() % 2, 0, "hex must have complete bytes");
    hex.chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("canonical hex")
        })
        .collect()
}

fn protected_path(temporary: &TempDir, name: &str) -> PathBuf {
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("protect temporary signer directory");
    temporary.path().join(name)
}

fn vote(
    profile: &HandoffSignerJournalProfileV1,
    revision: u64,
    view: u64,
    block_byte: u8,
) -> CanonicalSignIntentV0 {
    CanonicalSignIntentV0::vote(
        profile.old_validator_set(),
        profile.author(),
        revision,
        View::new(view),
        Height::new(view + 1),
        BlockId::new([block_byte; 32]),
    )
    .expect("fixture vote")
}

fn timeout(
    profile: &HandoffSignerJournalProfileV1,
    revision: u64,
    view: u64,
    qc_byte: u8,
) -> CanonicalSignIntentV0 {
    let high_qc = QcRef::new(
        CertificateId::new([qc_byte; 32]),
        profile.old_validator_set().epoch(),
        View::new(view - 1),
        Height::new(view),
        BlockId::new([qc_byte.wrapping_add(1); 32]),
        profile.old_validator_set().id(),
    );
    CanonicalSignIntentV0::timeout_vote(
        profile.old_validator_set(),
        profile.author(),
        revision,
        View::new(view),
        high_qc,
    )
    .expect("fixture timeout")
}

fn rebuild_parent_header(
    header: &BlockHeader,
    timestamp_ms: u64,
    state_root: StateRoot,
) -> BlockHeader {
    BlockHeader::new(
        header.genesis_hash(),
        header.chain_id(),
        header.protocol_version(),
        header.epoch(),
        header.view(),
        header.height(),
        header.block_kind(),
        header.parent_id(),
        header.proposer_id(),
        header.validator_set_id(),
        header.consensus_parameters_hash(),
        header.payload_digest(),
        state_root,
        header.receipts_root(),
        header.evidence_root(),
        timestamp_ms,
        header.next_epoch_commitment_hash(),
    )
    .expect("structurally valid substituted parent header")
}

fn table_counts(path: &Path) -> (i64, i64, i64) {
    let connection = Connection::open(path).expect("open count connection");
    (
        connection
            .query_row("SELECT count(*) FROM signer_intents_v1", [], |row| {
                row.get(0)
            })
            .expect("intent count"),
        connection
            .query_row("SELECT count(*) FROM signer_events_v1", [], |row| {
                row.get(0)
            })
            .expect("event count"),
        connection
            .query_row(
                "SELECT count(*) FROM terminal_old_epoch_fence_v1",
                [],
                |row| row.get(0),
            )
            .expect("fence count"),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    name: String,
    device: u64,
    inode: u64,
    mode: u32,
    bytes: Vec<u8>,
}

fn namespace_snapshot(directory: &Path) -> Vec<FileSnapshot> {
    let mut snapshots = fs::read_dir(directory)
        .expect("read journal namespace")
        .map(|entry| {
            let entry = entry.expect("namespace entry");
            let metadata = entry.metadata().expect("entry metadata");
            FileSnapshot {
                name: entry.file_name().to_string_lossy().into_owned(),
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                bytes: fs::read(entry.path()).expect("entry bytes"),
            }
        })
        .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| left.name.cmp(&right.name));
    snapshots
}

#[test]
fn profile_truths_and_strict_checkpoint_parent_admission_are_closed_and_exact() {
    let fixture = authority_fixture();
    let profile = fixture.profile();
    assert!(!profile.safety_rules_evaluation());
    assert!(!profile.safe_vote_authority());
    assert!(!profile.production_activation());
    assert!(PACKAGE_MANIFEST.contains("safety_rules_evaluation = false"));
    assert!(PACKAGE_MANIFEST.contains("safe_vote_authority = false"));
    assert!(PACKAGE_MANIFEST.contains("production_activation = false"));

    StrictOldSetHandoffAdmissionV1::verify(
        &fixture.old_handoff_intent(),
        &fixture.finality,
        &fixture.commitment,
        &fixture.old_set,
        &fixture.old_parameters,
        &fixture.new_set,
        &fixture.new_parameters,
        &fixture.checkpoint_parent,
    )
    .expect("real Ed25519 checkpoint -> seal1 -> seal2 admission");

    let wrong_time = rebuild_parent_header(
        &fixture.checkpoint_parent,
        fixture.checkpoint_parent.timestamp_ms() + 1,
        fixture.checkpoint_parent.state_root(),
    );
    assert!(StrictOldSetHandoffAdmissionV1::verify(
        &fixture.old_handoff_intent(),
        &fixture.finality,
        &fixture.commitment,
        &fixture.old_set,
        &fixture.old_parameters,
        &fixture.new_set,
        &fixture.new_parameters,
        &wrong_time,
    )
    .is_err());
    let wrong_state = rebuild_parent_header(
        &fixture.checkpoint_parent,
        fixture.checkpoint_parent.timestamp_ms(),
        StateRoot::new([0x7f; 32]),
    );
    assert!(StrictOldSetHandoffAdmissionV1::verify(
        &fixture.old_handoff_intent(),
        &fixture.finality,
        &fixture.commitment,
        &fixture.old_set,
        &fixture.old_parameters,
        &fixture.new_set,
        &fixture.new_parameters,
        &wrong_state,
    )
    .is_err());

    let mut old_production_fields = fixture.old_parameters.fields();
    old_production_fields.production_activation = true;
    let old_production = ConsensusParametersV0::new(old_production_fields)
        .expect("future-shaped production parameter value");
    let mut new_production_fields = fixture.new_parameters.fields();
    new_production_fields.production_activation = true;
    let new_production = ConsensusParametersV0::new(new_production_fields)
        .expect("future-shaped production parameter value");
    let old_production_set = ValidatorSet::new(
        fixture.old_set.genesis_hash(),
        fixture.old_set.chain_id(),
        fixture.old_set.protocol_version(),
        fixture.old_set.epoch(),
        old_production.hash(),
        fixture.old_set.validators().to_vec(),
    )
    .expect("old production-bound set");
    let new_production_set = ValidatorSet::new(
        fixture.new_set.genesis_hash(),
        fixture.new_set.chain_id(),
        fixture.new_set.protocol_version(),
        fixture.new_set.epoch(),
        new_production.hash(),
        fixture.new_set.validators().to_vec(),
    )
    .expect("new production-bound set");
    assert!(matches!(
        HandoffSignerJournalProfileV1::new(
            old_production_set,
            new_production_set,
            old_production,
            new_production,
            fixture.author,
            SIGNER_PROFILE_REF,
            WATERMARK_SCOPE,
            64,
            16 * 1024,
            MAXIMUM_DATABASE_BYTES,
        ),
        Err(HandoffSignerJournalErrorV1::InvalidProfile(
            "production activation remains closed"
        ))
    ));

    let replacement_author = ValidatorId::from_bytes(b"validator-z").expect("new-only author");
    let mut new_validators = fixture.new_set.validators().to_vec();
    let replaced = new_validators.pop().expect("four-validator fixture");
    new_validators.push(
        Validator::new(
            replacement_author,
            replaced.consensus_key(),
            replaced.voting_power(),
        )
        .expect("new-only validator"),
    );
    let new_only_set = ValidatorSet::new(
        fixture.new_set.genesis_hash(),
        fixture.new_set.chain_id(),
        fixture.new_set.protocol_version(),
        fixture.new_set.epoch(),
        fixture.new_parameters.hash(),
        new_validators,
    )
    .expect("new-only author set");
    assert!(matches!(
        HandoffSignerJournalProfileV1::new(
            fixture.old_set,
            new_only_set,
            fixture.old_parameters,
            fixture.new_parameters,
            replacement_author,
            SIGNER_PROFILE_REF,
            WATERMARK_SCOPE,
            64,
            16 * 1024,
            MAXIMUM_DATABASE_BYTES,
        ),
        Err(HandoffSignerJournalErrorV1::InvalidProfile(
            "new-set-only validator admission is closed"
        ))
    ));
}

#[test]
fn vote_timeout_replay_handoff_zero_effects_and_terminal_fence_are_exact() {
    let fixture = authority_fixture();
    let profile = fixture.profile();
    let temporary = TempDir::new().expect("temporary directory");
    let path = protected_path(&temporary, "schema1.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
            .expect("create schema1 journal");

    let first_vote = vote(&profile, 1, 10, 0x31);
    let first_signature = journal
        .sign_old_epoch_exact_v1(&first_vote, &mut producer)
        .expect("sign old-epoch Vote");
    assert_eq!(producer.calls(), (1, 0));
    assert_eq!(
        journal
            .sign_old_epoch_exact_v1(&first_vote, &mut producer)
            .expect("exact Vote replay"),
        first_signature
    );
    assert_eq!(producer.calls(), (1, 0));
    journal
        .sign_old_epoch_exact_v1(&timeout(&profile, 2, 11, 0x41), &mut producer)
        .expect("sign old-epoch Timeout");
    assert_eq!(producer.calls(), (2, 0));

    let same_round = journal
        .sign_old_epoch_exact_v1(&vote(&profile, 3, 10, 0x32), &mut producer)
        .expect_err("same Vote round must conflict");
    assert!(matches!(
        same_round,
        HandoffSignerJournalErrorV1::Conflict(
            HandoffSignerJournalConflictV1::SameRoundDifferentIntent { .. }
        )
    ));
    let same_timeout_round = journal
        .sign_old_epoch_exact_v1(&timeout(&profile, 3, 11, 0x42), &mut producer)
        .expect_err("same Timeout round must conflict");
    assert!(matches!(
        same_timeout_round,
        HandoffSignerJournalErrorV1::Conflict(
            HandoffSignerJournalConflictV1::SameRoundDifferentIntent { .. }
        )
    ));
    let revision_regression = journal
        .sign_old_epoch_exact_v1(&vote(&profile, 2, 12, 0x33), &mut producer)
        .expect_err("safety revision must be monotonic as an anti-replay key");
    assert!(matches!(
        revision_regression,
        HandoffSignerJournalErrorV1::Conflict(
            HandoffSignerJournalConflictV1::SafetyRevisionRegression { .. }
        )
    ));

    let admission = fixture.admission();
    let old_intent = fixture.old_handoff_intent();
    let before_bare = (
        fs::read(&path).expect("database bytes"),
        watermark.snapshot(),
        producer.calls(),
        table_counts(&path),
    );
    let _bare_data_only_intent = old_intent.clone();
    assert_eq!(
        before_bare,
        (
            fs::read(&path).expect("database bytes"),
            watermark.snapshot(),
            producer.calls(),
            table_counts(&path),
        ),
        "constructing a bare handoff intent has zero local/external/producer effect",
    );

    let before_new = (
        fs::read(&path).expect("database bytes"),
        watermark.snapshot(),
        producer.calls(),
        table_counts(&path),
    );
    assert!(matches!(
        journal.sign_old_set_handoff_exact_v1(
            &fixture.new_handoff_intent(),
            &admission,
            &mut producer,
        ),
        Err(HandoffSignerJournalErrorV1::NewSetAdmissionUnavailable)
    ));
    assert_eq!(
        before_new,
        (
            fs::read(&path).expect("database bytes"),
            watermark.snapshot(),
            producer.calls(),
            table_counts(&path),
        ),
        "new-set rejection must touch neither DB, watermark, nor producer",
    );

    let mut alternate_fields = fixture.descriptor.fields().clone();
    alternate_fields.terminal_old_view = View::new(
        alternate_fields
            .terminal_old_view
            .get()
            .checked_add(1)
            .expect("fixture view increment"),
    );
    let alternate_descriptor =
        HandoffDescriptorV0::new(alternate_fields).expect("shape-valid alternate descriptor");
    let alternate_intent = CanonicalHandoffSignIntentV1::old_set(
        &alternate_descriptor,
        &fixture.old_set,
        &fixture.new_set,
        &fixture.old_parameters,
        &fixture.new_parameters,
        fixture.author,
    )
    .expect("alternate data-only handoff intent");
    let before_alternate = (
        fs::read(&path).expect("database bytes"),
        watermark.snapshot(),
        producer.calls(),
        table_counts(&path),
    );
    assert!(matches!(
        journal.sign_old_set_handoff_exact_v1(&alternate_intent, &admission, &mut producer,),
        Err(HandoffSignerJournalErrorV1::AdmissionMismatch(
            "intent fingerprint"
        ))
    ));
    assert_eq!(
        before_alternate,
        (
            fs::read(&path).expect("database bytes"),
            watermark.snapshot(),
            producer.calls(),
            table_counts(&path),
        ),
    );

    let handoff_signature = journal
        .sign_old_set_handoff_exact_v1(&old_intent, &admission, &mut producer)
        .expect("persist old-set handoff and terminal fence");
    assert_eq!(producer.calls(), (2, 1));
    assert_eq!(table_counts(&path), (3, 6, 1));
    assert_eq!(
        journal
            .sign_old_set_handoff_exact_v1(&old_intent, &admission, &mut producer)
            .expect("exact completed handoff replay"),
        handoff_signature,
    );
    assert_eq!(producer.calls(), (2, 1));
    assert!(matches!(
        journal.sign_old_epoch_exact_v1(&vote(&profile, 3, 12, 0x34), &mut producer),
        Err(HandoffSignerJournalErrorV1::Conflict(
            HandoffSignerJournalConflictV1::TerminalOldEpochFence { .. }
        ))
    ));
    assert_eq!(
        journal
            .sign_old_epoch_exact_v1(&first_vote, &mut producer)
            .expect("completed exact Vote replay survives the fence"),
        first_signature,
    );
    assert_eq!(producer.calls(), (2, 1));
}

#[test]
fn schema0_is_read_only_identified_without_namespace_migration() {
    let fixture = authority_fixture();
    let temporary = TempDir::new().expect("temporary directory");
    let path = protected_path(&temporary, "legacy.sqlite3");
    let watermark = MemoryWatermark::default();
    let profile = SignerJournalProfileV0::new(
        fixture.old_set,
        fixture.author,
        SIGNER_PROFILE_REF,
        [0x99; 32],
        64,
        4096,
        MAXIMUM_DATABASE_BYTES,
    )
    .expect("legacy profile");
    drop(
        SqliteSignerJournalV0::initialize_new(&path, profile, watermark)
            .expect("create exact schema0 journal"),
    );
    let before = namespace_snapshot(temporary.path());
    assert_eq!(
        inspect_signer_journal_schema_read_only_v1(&path).expect("identify schema0"),
        SignerJournalSchemaKindV1::LegacyV0ReadOnly,
    );
    assert_eq!(before, namespace_snapshot(temporary.path()));

    let schema1_profile = fixture_profile_from_vector();
    assert!(matches!(
        SqliteHandoffSignerJournalV1::open_existing(
            &path,
            schema1_profile,
            MemoryWatermark::default(),
        ),
        Err(HandoffSignerJournalErrorV1::LegacySchemaReadOnly)
    ));
    assert_eq!(before, namespace_snapshot(temporary.path()));

    let mut wal_name = path.as_os_str().to_os_string();
    wal_name.push("-wal");
    fs::write(PathBuf::from(wal_name), [0x7f]).expect("inject unclassified live WAL byte");
    let unclassified_wal = namespace_snapshot(temporary.path());
    assert!(matches!(
        inspect_signer_journal_schema_read_only_v1(&path),
        Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "schema0 WAL contains live or unclassified frames"
            )
        )
    ));
    assert_eq!(unclassified_wal, namespace_snapshot(temporary.path()));
}

fn fixture_profile_from_vector() -> HandoffSignerJournalProfileV1 {
    authority_fixture().profile()
}

#[test]
fn schema_rejects_null_signed_event_at_insert_time() {
    let fixture = authority_fixture();
    let profile = fixture.profile();
    let temporary = TempDir::new().expect("temporary directory");
    let path = protected_path(&temporary, "null-signed-event.sqlite3");
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    producer.fail_after_sign_once();
    let mut journal = SqliteHandoffSignerJournalV1::create_new(
        &path,
        profile.clone(),
        MemoryWatermark::default(),
    )
    .expect("create journal");

    assert!(matches!(
        journal.sign_old_epoch_exact_v1(&vote(&profile, 1, 1, 0x10), &mut producer),
        Err(HandoffSignerJournalErrorV1::SignatureProducer(
            SignatureProducerErrorV0::Unavailable
        ))
    ));
    assert_eq!(table_counts(&path), (1, 1, 0));
    drop(journal);

    let connection = Connection::open(&path).expect("open pending journal");
    let error = connection
        .execute_batch(
            "INSERT INTO signer_events_v1(
                 sequence_be,
                 event_kind,
                 fingerprint,
                 signature,
                 predecessor_sequence_be,
                 predecessor_chain_checksum,
                 event_checksum,
                 chain_checksum
             )
             SELECT
                 x'0000000000000002',
                 1,
                 fingerprint,
                 NULL,
                 sequence_be,
                 chain_checksum,
                 zeroblob(32),
                 zeroblob(32)
             FROM signer_events_v1
             WHERE event_kind=0;",
        )
        .expect_err("schema must reject a signed event whose signature is SQL NULL");
    assert!(matches!(
        error,
        rusqlite::Error::SqliteFailure(ref failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation
    ));
    assert_eq!(table_counts(&path), (1, 1, 0));
}

#[test]
fn prepared_producer_signature_fence_and_external_fault_windows_fail_closed() {
    let fixture = authority_fixture();
    let profile = fixture.profile();

    let temporary = TempDir::new().expect("temporary directory");
    let path = protected_path(&temporary, "prepare-before-cas.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
            .expect("create journal");
    watermark.fail_before_apply(1);
    assert!(matches!(
        journal.sign_old_epoch_exact_v1(&vote(&profile, 1, 1, 0x11), &mut producer),
        Err(HandoffSignerJournalErrorV1::ExternalWatermark { .. })
    ));
    assert_eq!(producer.calls(), (0, 0));
    assert_eq!(table_counts(&path), (1, 1, 0));
    assert_eq!(
        watermark
            .snapshot()
            .value
            .expect("initial watermark")
            .sequence(),
        0
    );
    drop(journal);
    assert!(matches!(
        SqliteHandoffSignerJournalV1::open_existing(&path, profile.clone(), watermark.clone(),),
        Err(HandoffSignerJournalErrorV1::Conflict(
            HandoffSignerJournalConflictV1::PreparedIntentPending
        ))
    ));

    let temporary = TempDir::new().expect("temporary directory");
    let path = protected_path(&temporary, "prepare-response-loss.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
            .expect("create journal");
    watermark.apply_then_fail(1);
    let intent = vote(&profile, 1, 1, 0x12);
    assert!(matches!(
        journal.sign_old_epoch_exact_v1(&intent, &mut producer),
        Err(HandoffSignerJournalErrorV1::ExternalWatermark { .. })
    ));
    assert_eq!(producer.calls(), (0, 0));
    journal
        .sign_old_epoch_exact_v1(&intent, &mut producer)
        .expect("same-owner recovery after applied prepare CAS response loss");
    assert_eq!(producer.calls(), (1, 0));

    let temporary = TempDir::new().expect("temporary directory");
    let path = protected_path(&temporary, "producer-window.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    producer.fail_after_sign_once();
    let mut journal = SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark)
        .expect("create journal");
    let intent = vote(&profile, 1, 1, 0x13);
    assert!(matches!(
        journal.sign_old_epoch_exact_v1(&intent, &mut producer),
        Err(HandoffSignerJournalErrorV1::SignatureProducer(
            SignatureProducerErrorV0::Unavailable
        ))
    ));
    assert_eq!(table_counts(&path), (1, 1, 0));
    journal
        .sign_old_epoch_exact_v1(&intent, &mut producer)
        .expect("exact deterministic producer retry");
    assert_eq!(producer.calls(), (2, 0));

    let temporary = TempDir::new().expect("temporary directory");
    let path = protected_path(&temporary, "signature-response-loss.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
            .expect("create journal");
    watermark.apply_then_fail(2);
    let intent = vote(&profile, 1, 1, 0x14);
    assert!(matches!(
        journal.sign_old_epoch_exact_v1(&intent, &mut producer),
        Err(HandoffSignerJournalErrorV1::ExternalWatermark { .. })
    ));
    assert_eq!(table_counts(&path), (1, 2, 0));
    journal
        .sign_old_epoch_exact_v1(&intent, &mut producer)
        .expect("stored signature replay after applied CAS response loss");
    assert_eq!(producer.calls(), (1, 0));

    let temporary = TempDir::new().expect("temporary directory");
    let path = protected_path(&temporary, "fence-response-loss.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    let handoff_intent = fixture.old_handoff_intent();
    let admission = fixture.admission();
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
            .expect("create journal");
    watermark.apply_then_fail(2);
    assert!(matches!(
        journal.sign_old_set_handoff_exact_v1(&handoff_intent, &admission, &mut producer,),
        Err(HandoffSignerJournalErrorV1::ExternalWatermark { .. })
    ));
    assert_eq!(table_counts(&path), (1, 2, 1));
    assert_eq!(producer.calls(), (0, 1));
    drop(journal);
    let mut reopened =
        SqliteHandoffSignerJournalV1::open_existing(&path, profile.clone(), watermark)
            .expect("reopen after applied fence CAS response loss");
    reopened
        .sign_old_set_handoff_exact_v1(&handoff_intent, &admission, &mut producer)
        .expect("replay persisted fenced handoff without producer");
    assert_eq!(producer.calls(), (0, 1));

    let temporary = TempDir::new().expect("temporary directory");
    let path = protected_path(&temporary, "fence-transaction-fault.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    let mut journal = SqliteHandoffSignerJournalV1::create_new(&path, profile, watermark)
        .expect("create journal");
    producer.install_sql_once(
        path.clone(),
        "CREATE TRIGGER injected_fence_abort
         BEFORE INSERT ON terminal_old_epoch_fence_v1
         BEGIN SELECT RAISE(ABORT, 'injected fence fault'); END;",
    );
    assert!(matches!(
        journal.sign_old_set_handoff_exact_v1(
            &fixture.old_handoff_intent(),
            &fixture.admission(),
            &mut producer,
        ),
        Err(HandoffSignerJournalErrorV1::Sqlite { .. })
    ));
    assert_eq!(
        table_counts(&path),
        (1, 1, 0),
        "signature event, accounting/head advance, and fence must roll back together",
    );
}

#[test]
fn recomputed_audit_rejects_schema_accounting_head_fence_cev0_and_signature_mutants() {
    let fixture = authority_fixture();
    let profile = fixture.profile();
    let temporary = TempDir::new().expect("temporary directory");
    let source = protected_path(&temporary, "source.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&source, profile.clone(), watermark.clone())
            .expect("create source journal");
    journal
        .sign_old_epoch_exact_v1(&vote(&profile, 1, 10, 0x61), &mut producer)
        .expect("sign source Vote");
    journal
        .sign_old_set_handoff_exact_v1(
            &fixture.old_handoff_intent(),
            &fixture.admission(),
            &mut producer,
        )
        .expect("sign source handoff");
    drop(journal);

    let mutant = |name: &str| {
        let directory = TempDir::new().expect("mutant directory");
        let path = protected_path(&directory, name);
        fs::copy(&source, &path).expect("copy journal mutant");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("protect journal mutant");
        (directory, path)
    };
    let rejected = |path: &Path| {
        assert!(SqliteHandoffSignerJournalV1::open_existing(
            path,
            profile.clone(),
            watermark.clone(),
        )
        .is_err());
    };

    let (_directory, path) = mutant("extra-schema.sqlite3");
    Connection::open(&path)
        .expect("open schema mutant")
        .execute_batch("CREATE TABLE injected_schema(value INTEGER) STRICT;")
        .expect("install schema mutant");
    rejected(&path);

    let (_directory, path) = mutant("accounting.sqlite3");
    Connection::open(&path)
        .expect("open accounting mutant")
        .execute(
            "UPDATE signer_accounting_v1 SET intent_count=intent_count+1",
            [],
        )
        .expect("mutate accounting");
    rejected(&path);

    let (_directory, path) = mutant("head.sqlite3");
    Connection::open(&path)
        .expect("open head mutant")
        .execute(
            "UPDATE signer_head_v1 SET active_chain_checksum=zeroblob(32)",
            [],
        )
        .expect("mutate head");
    rejected(&path);

    let (_directory, path) = mutant("fence.sqlite3");
    mutate_behind_immutable_trigger(
        &path,
        "terminal_fence_no_update_v1",
        "UPDATE terminal_old_epoch_fence_v1 SET descriptor_digest=zeroblob(32)",
        [],
    );
    rejected(&path);

    let (_directory, path) = mutant("metadata-cev0.sqlite3");
    let connection = Connection::open(&path).expect("open metadata mutant");
    let mut bytes: Vec<u8> = connection
        .query_row(
            "SELECT old_validator_set_cev0 FROM handoff_signer_metadata_v1",
            [],
            |row| row.get(0),
        )
        .expect("stored validator set bytes");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    mutate_behind_immutable_trigger(
        &path,
        "handoff_metadata_no_update_v1",
        "UPDATE handoff_signer_metadata_v1 SET old_validator_set_cev0=?1",
        params![bytes],
    );
    rejected(&path);

    let (_directory, path) = mutant("parameters-cev0.sqlite3");
    let connection = Connection::open(&path).expect("open parameters mutant");
    let mut bytes: Vec<u8> = connection
        .query_row(
            "SELECT old_parameters_cev0 FROM handoff_signer_metadata_v1",
            [],
            |row| row.get(0),
        )
        .expect("stored consensus-parameter bytes");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    mutate_behind_immutable_trigger(
        &path,
        "handoff_metadata_no_update_v1",
        "UPDATE handoff_signer_metadata_v1 SET old_parameters_cev0=?1",
        params![bytes],
    );
    rejected(&path);

    let (_directory, path) = mutant("descriptor-cev0.sqlite3");
    let connection = Connection::open(&path).expect("open descriptor mutant");
    let mut bytes: Vec<u8> = connection
        .query_row(
            "SELECT descriptor_cev0 FROM signer_intents_v1 WHERE intent_class=1",
            [],
            |row| row.get(0),
        )
        .expect("stored descriptor bytes");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    mutate_behind_immutable_trigger(
        &path,
        "signer_intents_no_update_v1",
        "UPDATE signer_intents_v1 SET descriptor_cev0=?1 WHERE intent_class=1",
        params![bytes],
    );
    rejected(&path);

    let (_directory, path) = mutant("signature.sqlite3");
    let connection = Connection::open(&path).expect("open signature mutant");
    let mut signature: Vec<u8> = connection
        .query_row(
            "SELECT signature FROM signer_events_v1 WHERE event_kind=1 ORDER BY sequence_be LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("stored signature");
    signature[0] ^= 1;
    mutate_behind_immutable_trigger(
        &path,
        "signer_events_no_update_v1",
        "UPDATE signer_events_v1 SET signature=?1 WHERE event_kind=1 AND sequence_be=(
             SELECT min(sequence_be) FROM signer_events_v1 WHERE event_kind=1
         )",
        params![signature],
    );
    rejected(&path);
}

fn mutate_behind_immutable_trigger<P: rusqlite::Params>(
    path: &Path,
    trigger: &str,
    mutation: &str,
    parameters: P,
) {
    let connection = Connection::open(path).expect("open exact-schema mutant");
    let trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
            params![trigger],
            |row| row.get(0),
        )
        .expect("canonical trigger SQL");
    connection
        .execute_batch(&format!("DROP TRIGGER {trigger};"))
        .expect("drop immutable trigger for offline mutant");
    connection
        .execute(mutation, parameters)
        .expect("apply offline row mutant");
    connection
        .execute_batch(&trigger_sql)
        .expect("restore exact canonical trigger");
}
