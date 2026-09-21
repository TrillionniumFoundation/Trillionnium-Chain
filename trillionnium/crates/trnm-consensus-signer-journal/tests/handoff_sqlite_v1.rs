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
use trnm_consensus_crypto::verify_pre_handoff_context_strict_v1;
use trnm_consensus_signer_journal::{
    inspect_signer_journal_schema_read_only_v1, ExternalMonotonicWatermarkV0,
    ExternalWatermarkErrorV0, HandoffSignatureProducerV1, HandoffSignatureRequestV1,
    HandoffSignerJournalConflictV1, HandoffSignerJournalErrorV1, HandoffSignerJournalProfileV1,
    SignatureProducerErrorV0, SignatureProducerV0, SignatureRequestV0, SignerJournalProfileV0,
    SignerJournalSchemaKindV1, SignerWatermarkV0, SqliteHandoffSignerJournalV1,
    SqliteSignerJournalV0, StrictNewSetHandoffAdmissionV1, StrictOldSetHandoffAdmissionV1,
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
    retirement: Option<trnm_consensus_signer_journal::SignerRetirementRecordV1>,
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
        if state.retirement.is_some() {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
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
        if state.retirement.is_some() {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
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

    fn role_profile(&self) -> HandoffSignerJournalProfileV1 {
        HandoffSignerJournalProfileV1::for_epoch_handoff(
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
        .expect("explicit epoch role profile")
    }

    fn new_admission(&self) -> StrictNewSetHandoffAdmissionV1 {
        let context = verify_pre_handoff_context_strict_v1(
            &self.finality,
            &self.commitment,
            &self.descriptor,
            &self.old_set,
            &self.old_parameters,
            &self.new_set,
            &self.new_parameters,
            &self.checkpoint_parent,
        )
        .expect("strict pre-certificate context without joint signatures");
        StrictNewSetHandoffAdmissionV1::from_verified_context(&self.new_handoff_intent(), &context)
            .expect("new role admission")
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
    let error = journal
        .sign_old_set_handoff_exact_v1(
            &fixture.old_handoff_intent(),
            &fixture.admission(),
            &mut producer,
        )
        .unwrap_err();
    assert!(
        matches!(error, HandoffSignerJournalErrorV1::SchemaMismatch),
        "{error:?}"
    );
    assert_eq!(producer.calls(), (0, 1));
    assert_eq!(
        table_counts(&path),
        (1, 1, 0),
        "post-producer schema mutation must reject before signature/head/fence append",
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

#[test]
fn both_handoff_roles_survive_reopen_in_either_order_and_keep_old_vote_fenced() {
    for old_first in [true, false] {
        let fixture = authority_fixture();
        let profile = fixture.role_profile();
        assert!(profile.new_set_handoff_enabled());
        assert_ne!(
            profile.profile_checksum(),
            fixture.profile().profile_checksum()
        );
        let temporary = TempDir::new().unwrap();
        let path = protected_path(&temporary, "dual-role.sqlite3");
        let watermark = MemoryWatermark::default();
        let mut producer = ExactProducer::new(fixture.signing_key.clone());
        let old_intent = fixture.old_handoff_intent();
        let new_intent = fixture.new_handoff_intent();
        assert_ne!(old_intent.signing_root(), new_intent.signing_root());
        let old_admission = fixture.admission();
        let new_admission = fixture.new_admission();
        let mut journal =
            SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
                .unwrap();
        if old_first {
            journal
                .sign_old_set_handoff_exact_v1(&old_intent, &old_admission, &mut producer)
                .unwrap();
        } else {
            journal
                .sign_new_set_handoff_exact_v1(&new_intent, &new_admission, &mut producer)
                .unwrap();
        }
        drop(journal);
        let mut journal =
            SqliteHandoffSignerJournalV1::open_existing(&path, profile.clone(), watermark.clone())
                .unwrap();
        if old_first {
            journal
                .sign_new_set_handoff_exact_v1(&new_intent, &new_admission, &mut producer)
                .unwrap();
        } else {
            journal
                .sign_old_set_handoff_exact_v1(&old_intent, &old_admission, &mut producer)
                .unwrap();
        }
        assert_eq!(table_counts(&path), (2, 4, 1));
        assert_eq!(producer.calls(), (0, 2));
        drop(journal);
        let mut journal =
            SqliteHandoffSignerJournalV1::open_existing(&path, profile.clone(), watermark.clone())
                .unwrap();
        journal
            .sign_old_set_handoff_exact_v1(&old_intent, &old_admission, &mut producer)
            .unwrap();
        journal
            .sign_new_set_handoff_exact_v1(&new_intent, &new_admission, &mut producer)
            .unwrap();
        assert_eq!(
            producer.calls(),
            (0, 2),
            "completed replay never calls custody"
        );
        assert!(matches!(
            journal.sign_old_epoch_exact_v1(&vote(&profile, 1, 1, 9), &mut producer),
            Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::TerminalOldEpochFence { .. }
            ))
        ));
        drop(journal);
        assert!(
            SqliteHandoffSignerJournalV1::open_existing(&path, fixture.profile(), watermark,)
                .is_err(),
            "role policy cannot be changed during reopen"
        );
    }
}

#[test]
fn new_handoff_policy_and_exact_admission_reject_before_any_side_effect() {
    let fixture = authority_fixture();
    let temporary = TempDir::new().unwrap();
    let path = protected_path(&temporary, "old-only.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, fixture.profile(), watermark.clone())
            .unwrap();
    let before = (
        fs::read(&path).unwrap(),
        watermark.snapshot(),
        producer.calls(),
    );
    assert!(matches!(
        journal.sign_new_set_handoff_exact_v1(
            &fixture.new_handoff_intent(),
            &fixture.new_admission(),
            &mut producer,
        ),
        Err(HandoffSignerJournalErrorV1::NewSetAdmissionUnavailable)
    ));
    assert_eq!(
        before,
        (
            fs::read(&path).unwrap(),
            watermark.snapshot(),
            producer.calls()
        )
    );
    drop(journal);

    let path = protected_path(&temporary, "roles.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, fixture.role_profile(), watermark.clone())
            .unwrap();
    let before = (
        fs::read(&path).unwrap(),
        watermark.snapshot(),
        producer.calls(),
    );
    assert!(journal
        .sign_new_set_handoff_exact_v1(
            &fixture.old_handoff_intent(),
            &fixture.new_admission(),
            &mut producer,
        )
        .is_err());
    let mut fields = fixture.descriptor.fields().clone();
    fields.terminal_old_view = View::new(fields.terminal_old_view.get() + 1);
    let alternate = CanonicalHandoffSignIntentV1::new_set(
        &HandoffDescriptorV0::new(fields).unwrap(),
        &fixture.old_set,
        &fixture.new_set,
        &fixture.old_parameters,
        &fixture.new_parameters,
        fixture.author,
    )
    .unwrap();
    assert!(journal
        .sign_new_set_handoff_exact_v1(&alternate, &fixture.new_admission(), &mut producer,)
        .is_err());
    assert_eq!(
        before,
        (
            fs::read(&path).unwrap(),
            watermark.snapshot(),
            producer.calls()
        )
    );
}

#[test]
fn strict_new_role_recovers_each_durable_window_without_changing_decision() {
    // prepare-before-external, prepare-response-loss, custody-response-loss,
    // signature-before-external and signature-response-loss.
    for window in 0..5 {
        let fixture = authority_fixture();
        let profile = fixture.role_profile();
        let temporary = TempDir::new().unwrap();
        let path = protected_path(&temporary, "recover-new-role.sqlite3");
        let watermark = MemoryWatermark::default();
        let mut producer = ExactProducer::new(fixture.signing_key.clone());
        let mut journal =
            SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
                .unwrap();
        match window {
            0 => watermark.fail_before_apply(1),
            1 => watermark.apply_then_fail(1),
            2 => producer.fail_after_sign_once(),
            3 => watermark.fail_before_apply(2),
            4 => watermark.apply_then_fail(2),
            _ => unreachable!(),
        }
        let intent = fixture.new_handoff_intent();
        let admission = fixture.new_admission();
        assert!(journal
            .sign_new_set_handoff_exact_v1(&intent, &admission, &mut producer)
            .is_err());
        let prior_calls = producer.calls();
        drop(journal);
        let mut reopened = SqliteHandoffSignerJournalV1::recover_new_set_handoff_exact_v1(
            &path,
            profile.clone(),
            watermark.clone(),
            &intent,
            &fixture.new_admission(),
        )
        .expect("recover only the strictly reverified exact decision");
        let signature = reopened
            .sign_new_set_handoff_exact_v1(&intent, &fixture.new_admission(), &mut producer)
            .unwrap();
        assert_eq!(table_counts(&path), (1, 2, 0));
        assert_eq!(watermark.snapshot().value.unwrap().sequence(), 2);
        if window >= 3 {
            assert_eq!(producer.calls(), prior_calls);
        }
        let calls = producer.calls();
        drop(reopened);
        let mut reopened =
            SqliteHandoffSignerJournalV1::open_existing(&path, profile, watermark).unwrap();
        assert_eq!(
            reopened
                .sign_new_set_handoff_exact_v1(&intent, &fixture.new_admission(), &mut producer)
                .unwrap(),
            signature
        );
        assert_eq!(producer.calls(), calls);
    }
}

#[test]
fn new_role_recovery_rejects_rollback_foreign_role_and_invalid_custody_key() {
    let fixture = authority_fixture();
    let profile = fixture.role_profile();
    let temporary = TempDir::new().unwrap();
    let path = protected_path(&temporary, "rollback-role.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
            .unwrap();
    let clean_image = fs::read(&path).unwrap();
    let intent = fixture.new_handoff_intent();
    let mut wrong_key = ExactProducer::new(SigningKey::from_bytes(&[0xe7; 32]));
    assert!(matches!(
        journal.sign_new_set_handoff_exact_v1(&intent, &fixture.new_admission(), &mut wrong_key,),
        Err(HandoffSignerJournalErrorV1::InvalidProducedSignature)
    ));
    assert_eq!(table_counts(&path), (1, 1, 0));
    drop(journal);
    assert!(
        SqliteHandoffSignerJournalV1::recover_old_set_handoff_exact_v1(
            &path,
            profile.clone(),
            watermark.clone(),
            &fixture.old_handoff_intent(),
            &fixture.admission(),
        )
        .is_err()
    );
    let mut journal = SqliteHandoffSignerJournalV1::recover_new_set_handoff_exact_v1(
        &path,
        profile.clone(),
        watermark.clone(),
        &intent,
        &fixture.new_admission(),
    )
    .unwrap();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    journal
        .sign_new_set_handoff_exact_v1(&intent, &fixture.new_admission(), &mut producer)
        .unwrap();
    drop(journal);
    fs::write(&path, clean_image).unwrap();
    assert!(
        SqliteHandoffSignerJournalV1::open_existing(&path, profile.clone(), watermark.clone())
            .is_err()
    );
    assert!(
        SqliteHandoffSignerJournalV1::recover_new_set_handoff_exact_v1(
            &path,
            profile,
            watermark,
            &intent,
            &fixture.new_admission(),
        )
        .is_err(),
        "strict admission cannot reconstruct a missing durable decision"
    );
}

#[test]
fn explicit_new_only_profile_round_trips_without_creating_old_membership() {
    let fixture = authority_fixture();
    let author = ValidatorId::from_bytes(b"validator-z").unwrap();
    let mut validators = fixture.new_set.validators().to_vec();
    let replaced = validators.pop().unwrap();
    validators
        .push(Validator::new(author, replaced.consensus_key(), replaced.voting_power()).unwrap());
    let new_set = ValidatorSet::new(
        fixture.new_set.genesis_hash(),
        fixture.new_set.chain_id(),
        fixture.new_set.protocol_version(),
        fixture.new_set.epoch(),
        fixture.new_parameters.hash(),
        validators,
    )
    .unwrap();
    let profile = HandoffSignerJournalProfileV1::for_epoch_handoff(
        fixture.old_set,
        new_set,
        fixture.old_parameters,
        fixture.new_parameters,
        author,
        SIGNER_PROFILE_REF,
        WATERMARK_SCOPE,
        64,
        16 * 1024,
        MAXIMUM_DATABASE_BYTES,
    )
    .unwrap();
    assert!(profile.old_validator_set().validator(author).is_none());
    let temporary = TempDir::new().unwrap();
    let path = protected_path(&temporary, "new-only.sqlite3");
    let watermark = MemoryWatermark::default();
    let journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
            .unwrap();
    drop(journal);
    let journal = SqliteHandoffSignerJournalV1::open_existing(&path, profile, watermark).unwrap();
    assert!(journal
        .profile()
        .old_validator_set()
        .validator(author)
        .is_none());
    assert_eq!(table_counts(&path), (0, 0, 0));
}

#[test]
fn old_role_pending_recovery_installs_terminal_fence_before_new_role() {
    let fixture = authority_fixture();
    let profile = fixture.role_profile();
    let temporary = TempDir::new().unwrap();
    let path = protected_path(&temporary, "old-pending.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
            .unwrap();
    watermark.fail_before_apply(1);
    assert!(journal
        .sign_old_set_handoff_exact_v1(
            &fixture.old_handoff_intent(),
            &fixture.admission(),
            &mut producer,
        )
        .is_err());
    assert_eq!(producer.calls(), (0, 0));
    drop(journal);
    let mut journal = SqliteHandoffSignerJournalV1::recover_old_set_handoff_exact_v1(
        &path,
        profile,
        watermark,
        &fixture.old_handoff_intent(),
        &fixture.admission(),
    )
    .unwrap();
    journal
        .sign_old_set_handoff_exact_v1(
            &fixture.old_handoff_intent(),
            &fixture.admission(),
            &mut producer,
        )
        .unwrap();
    journal
        .sign_new_set_handoff_exact_v1(
            &fixture.new_handoff_intent(),
            &fixture.new_admission(),
            &mut producer,
        )
        .unwrap();
    assert_eq!(table_counts(&path), (2, 4, 1));
}

impl trnm_consensus_signer_journal::ExternalSignerRetirementV1 for MemoryWatermark {
    fn load_signer_retirement_v1(
        &mut self,
        scope: [u8; 32],
    ) -> Result<
        Option<trnm_consensus_signer_journal::SignerRetirementRecordV1>,
        ExternalWatermarkErrorV0,
    > {
        let state = self.state.lock().unwrap();
        if state.value.is_some_and(|v| v.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(state.retirement)
    }
    fn retire_signer_exact_v1(
        &mut self,
        record: &trnm_consensus_signer_journal::SignerRetirementRecordV1,
    ) -> Result<SignerWatermarkV0, ExternalWatermarkErrorV0> {
        let mut state = self.state.lock().unwrap();
        if state.retirement == Some(*record) {
            return Ok(record.terminal_watermark_v1());
        }
        if state.retirement.is_some() || state.value != Some(record.source_v1()) {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        state.retirement = Some(*record);
        Ok(record.terminal_watermark_v1())
    }
}

fn retirement_profile(f: &AuthorityFixture) -> SignerJournalProfileV0 {
    SignerJournalProfileV0::new(
        f.old_set.clone(),
        f.author,
        SIGNER_PROFILE_REF,
        WATERMARK_SCOPE,
        64,
        4096,
        MAXIMUM_DATABASE_BYTES,
    )
    .unwrap()
}
fn retirement_context(f: &AuthorityFixture) -> trnm_consensus_crypto::StrictPreHandoffContextV1 {
    verify_pre_handoff_context_strict_v1(
        &f.finality,
        &f.commitment,
        &f.descriptor,
        &f.old_set,
        &f.old_parameters,
        &f.new_set,
        &f.new_parameters,
        &f.checkpoint_parent,
    )
    .unwrap()
}
fn retirement_host() -> trnm_consensus_signer_journal::SignerRetirementHostCutV1 {
    trnm_consensus_signer_journal::SignerRetirementHostCutV1 {
        owner_generation: 1,
        native_committed_cut: [11; 32],
        safety_revision: 10,
        safety_record_checksum: [12; 32],
    }
}
#[test]
fn ordinary_retirement_consumes_real_owner_blocks_old_open_and_rechecks_readback() {
    use trnm_consensus_signer_journal::RetiredSqliteSignerJournalV1;
    let f = authority_fixture();
    let d = TempDir::new().unwrap();
    let path = protected_path(&d, "retired.sqlite3");
    let w = MemoryWatermark::default();
    let profile = retirement_profile(&f);
    let mut old = SqliteSignerJournalV0::initialize_new(&path, profile.clone(), w.clone()).unwrap();
    let genesis = old
        .confirm_node_checkpoint_head_exact_v0()
        .unwrap()
        .exact_watermark();
    let mut producer = ExactProducer::new(f.signing_key.clone());
    old.sign_exact_v0(&vote(&f.profile(), 1, 3, 21), &mut producer)
        .unwrap();
    let event_checksum: Vec<u8> = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT chain_checksum FROM signer_journal_events_v0 WHERE sequence_be=?1",
            rusqlite::params![1u64.to_be_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let first_event = SignerWatermarkV0::from_persisted_parts(
        genesis.scope(),
        genesis.journal_id(),
        1,
        event_checksum.try_into().unwrap(),
    )
    .unwrap();
    let ctx = retirement_context(&f);
    let intent = f.old_handoff_intent();
    let mut retired = old
        .retire_for_handoff_v1(&ctx, &intent, retirement_host())
        .unwrap();
    let record = *retired.record_v1();
    assert_eq!(record.source_v1().sequence(), 2);
    let receipt = retired.confirm_retirement_v1().unwrap();
    assert!(receipt.belongs_to_owner_v1(&mut retired));
    assert!(retired.confirms_ordinary_prefix_v1(genesis).unwrap());
    assert!(retired
        .confirms_ordinary_prefix_v1(record.source_v1())
        .unwrap());
    let forked_prefix = SignerWatermarkV0::from_persisted_parts(
        genesis.scope(),
        genesis.journal_id(),
        genesis.sequence(),
        [0x99; 32],
    )
    .unwrap();
    assert!(
        !retired.confirms_ordinary_prefix_v1(forked_prefix).unwrap(),
        "smaller sequence with foreign checksum must not count as ancestry"
    );
    assert!(retired.confirms_ordinary_prefix_v1(first_event).unwrap());
    let false_event = SignerWatermarkV0::from_persisted_parts(
        genesis.scope(),
        genesis.journal_id(),
        1,
        [0x77; 32],
    )
    .unwrap();
    assert!(!retired.confirms_ordinary_prefix_v1(false_event).unwrap());
    assert!(SqliteSignerJournalV0::open_existing(&path, profile.clone(), w.clone()).is_err());
    drop(retired);
    let before = namespace_snapshot(d.path());
    assert_eq!(
        inspect_signer_journal_schema_read_only_v1(&path).unwrap(),
        SignerJournalSchemaKindV1::RetiredOrdinaryV1
    );
    assert_eq!(before, namespace_snapshot(d.path()));
    assert!(SqliteSignerJournalV0::open_existing(&path, profile.clone(), w.clone()).is_err());
    let mut reopened =
        RetiredSqliteSignerJournalV1::open_existing_v1(&path, profile, w, record, &ctx, &intent)
            .unwrap();
    assert!(!receipt.belongs_to_owner_v1(&mut reopened));
    assert!(reopened.confirm_retirement_v1().is_ok());
    assert!(reopened.confirms_ordinary_prefix_v1(genesis).unwrap());
    assert!(reopened.confirms_ordinary_prefix_v1(first_event).unwrap());
    assert!(!reopened.confirms_ordinary_prefix_v1(false_event).unwrap());
    let c = Connection::open(&path).unwrap();
    assert!(c
        .execute("UPDATE signer_retirement_v1 SET record=zeroblob(354)", [])
        .is_err());
    assert!(c
        .execute("UPDATE signer_journal_head_v0 SET sequence=sequence", [])
        .is_err());
}
#[test]
fn ordinary_retirement_local_first_uncertainty_reopens_only_retired_owner() {
    use trnm_consensus_signer_journal::{RetiredSqliteSignerJournalV1, SignerRetirementCutV1};
    for cut in [
        SignerRetirementCutV1::AfterLocalWriteBeforeCommit,
        SignerRetirementCutV1::AfterLocalCommitBeforeSync,
        SignerRetirementCutV1::AfterLocalSyncBeforeExternal,
        SignerRetirementCutV1::AfterExternalBeforeReadback,
    ] {
        let f = authority_fixture();
        let d = TempDir::new().unwrap();
        let path = protected_path(&d, "cut.sqlite3");
        let w = MemoryWatermark::default();
        let profile = retirement_profile(&f);
        let old = SqliteSignerJournalV0::initialize_new(&path, profile.clone(), w.clone()).unwrap();
        let ctx = retirement_context(&f);
        let intent = f.old_handoff_intent();
        assert!(old
            .retire_with_observer_v1(
                &ctx,
                &intent,
                retirement_host(),
                |actual| if actual == cut {
                    Err(trnm_consensus_signer_journal::SignerJournalErrorV0::CapacityExhausted)
                } else {
                    Ok(())
                }
            )
            .is_err());
        if cut == SignerRetirementCutV1::AfterLocalWriteBeforeCommit {
            assert!(SqliteSignerJournalV0::open_existing(&path, profile, w).is_ok());
            continue;
        }
        assert!(SqliteSignerJournalV0::open_existing(&path, profile.clone(), w.clone()).is_err());
        let c =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let b: Vec<u8> = c
            .query_row("SELECT record FROM signer_retirement_v1", [], |r| r.get(0))
            .unwrap();
        drop(c);
        let record =
            trnm_consensus_signer_journal::SignerRetirementRecordV1::decode_v1_exact(&b).unwrap();
        // In this cut test the harness is the independent expected-record oracle.
        let mut retired = RetiredSqliteSignerJournalV1::open_existing_v1(
            &path,
            profile,
            w.clone(),
            record,
            &ctx,
            &intent,
        )
        .unwrap();
        assert!(retired.confirm_retirement_v1().is_ok());
        assert!(w.clone().load(WATERMARK_SCOPE).is_err());
    }
}
#[test]
fn ordinary_retirement_rejects_unresolved_signing_intent() {
    let f = authority_fixture();
    let d = TempDir::new().unwrap();
    let path = protected_path(&d, "pending.sqlite3");
    let w = MemoryWatermark::default();
    let profile = retirement_profile(&f);
    let mut old = SqliteSignerJournalV0::initialize_new(&path, profile.clone(), w.clone()).unwrap();
    let mut producer = ExactProducer::new(f.signing_key.clone());
    producer.fail_after_sign_once();
    let intent = vote(&f.profile(), 1, 3, 21);
    assert!(old.sign_exact_v0(&intent, &mut producer).is_err());
    assert!(old
        .retire_for_handoff_v1(
            &retirement_context(&f),
            &f.old_handoff_intent(),
            retirement_host()
        )
        .is_err());
    let mut old = SqliteSignerJournalV0::open_existing(&path, profile, w).unwrap();
    assert!(old.sign_exact_v0(&intent, &mut producer).is_ok());
}

#[test]
fn exact_handoff_head_binds_actual_owner_and_reopen_never_rebinds() {
    let dir = TempDir::new().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = authority_fixture();
    let profile = fixture.role_profile();
    let watermark = MemoryWatermark::default();
    let path = dir.path().join("selected.db");
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), watermark.clone())
            .unwrap();
    let selected = journal.confirm_head_exact_v1().unwrap();
    assert_eq!(selected.profile_checksum_v1(), profile.profile_checksum());
    assert_eq!(selected.exact_watermark_v1().sequence(), 0);
    assert_eq!(selected.pending_fingerprint_v1(), None);
    assert_eq!(selected.terminal_fence_checksum_v1(), None);
    assert!(selected.belongs_to_owner_at_path_v1(&mut journal, &path));
    let foreign_path = dir.path().join("foreign.db");
    let mut foreign = SqliteHandoffSignerJournalV1::create_new(
        &foreign_path,
        profile.clone(),
        MemoryWatermark::default(),
    )
    .unwrap();
    assert!(!selected.belongs_to_owner_at_path_v1(&mut foreign, &foreign_path));
    assert!(!selected.belongs_to_owner_at_path_v1(&mut journal, &foreign_path));
    let stored = selected.exact_watermark_v1();
    drop(journal);
    let mut reopened =
        SqliteHandoffSignerJournalV1::open_existing(&path, profile, watermark).unwrap();
    assert_eq!(
        reopened
            .confirm_head_exact_v1()
            .unwrap()
            .exact_watermark_v1(),
        stored
    );
    assert!(!selected.belongs_to_owner_at_path_v1(&mut reopened, &path));
}

#[test]
fn exact_handoff_head_observes_real_pending_signed_and_terminal_fence() {
    let dir = TempDir::new().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = authority_fixture();
    let path = dir.path().join("roles.db");
    let watermark = MemoryWatermark::default();
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, fixture.role_profile(), watermark.clone())
            .unwrap();
    let virgin = journal.confirm_head_exact_v1().unwrap();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    producer.fail_after_sign_once();
    let intent = fixture.old_handoff_intent();
    let admission = fixture.admission();
    assert!(journal
        .sign_old_set_handoff_exact_v1(&intent, &admission, &mut producer)
        .is_err());
    let pending = journal.confirm_head_exact_v1().unwrap();
    assert_eq!(pending.exact_watermark_v1().sequence(), 1);
    assert_eq!(
        pending.pending_fingerprint_v1(),
        Some(*intent.fingerprint().as_bytes())
    );
    assert_eq!(pending.terminal_fence_checksum_v1(), None);
    assert!(!virgin.belongs_to_owner_at_path_v1(&mut journal, &path));
    let signature = journal
        .sign_old_set_handoff_exact_v1(&intent, &admission, &mut producer)
        .unwrap();
    let signed = journal.confirm_head_exact_v1().unwrap();
    assert_eq!(signed.exact_watermark_v1().sequence(), 2);
    assert_eq!(signed.pending_fingerprint_v1(), None);
    assert!(signed.terminal_fence_checksum_v1().is_some());
    assert!(!pending.belongs_to_owner_at_path_v1(&mut journal, &path));
    let calls = producer.calls();
    assert_eq!(
        journal
            .sign_old_set_handoff_exact_v1(&intent, &admission, &mut producer)
            .unwrap(),
        signature
    );
    assert!(signed.matches_exact_head_v1(&journal.confirm_head_exact_v1().unwrap()));
    assert_eq!(producer.calls(), calls);
    // The existing immutable trigger itself refuses removal; the exact head
    // must still be auditable and unchanged after that failed mutation.
    assert!(Connection::open(&path)
        .unwrap()
        .execute("DELETE FROM terminal_old_epoch_fence_v1", [])
        .is_err());
    assert!(signed.matches_exact_head_v1(&journal.confirm_head_exact_v1().unwrap()));
}

#[test]
fn exact_handoff_head_rejects_external_rollback_and_replaced_namespace() {
    let dir = TempDir::new().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = authority_fixture();
    let path = dir.path().join("roles.db");
    let watermark = MemoryWatermark::default();
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, fixture.role_profile(), watermark.clone())
            .unwrap();
    let initial = journal.confirm_head_exact_v1().unwrap();
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    journal
        .sign_old_set_handoff_exact_v1(
            &fixture.old_handoff_intent(),
            &fixture.admission(),
            &mut producer,
        )
        .unwrap();
    let current = watermark.snapshot().value;
    watermark.state.lock().unwrap().value = Some(initial.exact_watermark_v1());
    assert!(matches!(
        journal.confirm_head_exact_v1(),
        Err(HandoffSignerJournalErrorV1::Conflict(
            HandoffSignerJournalConflictV1::ExternalWatermarkMismatch
        ))
    ));
    watermark.state.lock().unwrap().value = current;
    let selected = journal.confirm_head_exact_v1().unwrap();
    let moved = dir.path().join("displaced.db");
    fs::rename(&path, &moved).unwrap();
    fs::copy(&moved, &path).unwrap();
    assert!(!selected.belongs_to_owner_at_path_v1(&mut journal, &path));
}

#[test]
fn local_handoff_comparison_has_no_callback_and_rejects_stale_or_replaced_owner() {
    let dir = TempDir::new().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = authority_fixture();
    let path = dir.path().join("roles.db");
    let watermark = MemoryWatermark::default();
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, fixture.role_profile(), watermark.clone())
            .unwrap();
    let initial = journal.confirm_head_exact_v1().unwrap();
    let before = watermark.snapshot();
    initial.confirm_local_owner_v1(&journal).unwrap();
    initial.confirm_local_owner_v1(&journal).unwrap();
    assert_eq!(
        watermark.snapshot(),
        before,
        "pure local comparison must never call external service"
    );
    let foreign = SqliteHandoffSignerJournalV1::create_new(
        dir.path().join("foreign.db"),
        fixture.role_profile(),
        MemoryWatermark::default(),
    )
    .unwrap();
    assert!(initial.confirm_local_owner_v1(&foreign).is_err());
    let mut producer = ExactProducer::new(fixture.signing_key.clone());
    journal
        .sign_old_set_handoff_exact_v1(
            &fixture.old_handoff_intent(),
            &fixture.admission(),
            &mut producer,
        )
        .unwrap();
    assert!(initial.confirm_local_owner_v1(&journal).is_err());
    let signed = journal.confirm_head_exact_v1().unwrap();
    let before = watermark.snapshot();
    signed.confirm_local_owner_v1(&journal).unwrap();
    assert_eq!(watermark.snapshot(), before);
    let displaced = dir.path().join("displaced.db");
    fs::rename(&path, &displaced).unwrap();
    fs::copy(&displaced, &path).unwrap();
    assert!(signed.confirm_local_owner_v1(&journal).is_err());
    assert_eq!(watermark.snapshot(), before);
}

#[test]
fn local_retirement_comparison_preserves_affinity_without_refreshing_external_trust() {
    let fixture = authority_fixture();
    let directory = TempDir::new().unwrap();
    let path = protected_path(&directory, "retired-local.sqlite3");
    let watermark = MemoryWatermark::default();
    let old = SqliteSignerJournalV0::initialize_new(
        &path,
        retirement_profile(&fixture),
        watermark.clone(),
    )
    .unwrap();
    let mut retired = old
        .retire_for_handoff_v1(
            &retirement_context(&fixture),
            &fixture.old_handoff_intent(),
            retirement_host(),
        )
        .unwrap();
    let original = retired.confirm_retirement_v1().unwrap();
    original.confirm_local_owner_v1(&retired).unwrap();
    let record = watermark.state.lock().unwrap().retirement.take();
    // Local-only success explicitly does not refresh external authority.
    original.confirm_local_owner_v1(&retired).unwrap();
    assert!(!original.belongs_to_owner_v1(&mut retired));
    watermark.state.lock().unwrap().retirement = record;
    assert!(original.belongs_to_owner_v1(&mut retired));
    let displaced = directory.path().join("retired-displaced.sqlite3");
    fs::rename(&path, &displaced).unwrap();
    fs::copy(&displaced, &path).unwrap();
    assert!(original.confirm_local_owner_v1(&retired).is_err());
}

struct PendingGuardProducer {
    path: PathBuf,
    producer: ExactProducer,
    mutate_after_key: bool,
}
impl HandoffSignatureProducerV1 for PendingGuardProducer {
    fn sign_handoff(
        &mut self,
        request: HandoffSignatureRequestV1<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        request.confirm_local_prepared_v1().unwrap();
        let signature = if self.mutate_after_key {
            Some(self.producer.sign_handoff(request)?)
        } else {
            None
        };
        let displaced = self.path.with_extension("pending-displaced");
        fs::rename(&self.path, &displaced).unwrap();
        fs::copy(&displaced, &self.path).unwrap();
        request
            .confirm_local_prepared_v1()
            .map_err(|_| SignatureProducerErrorV0::Rejected)?;
        match signature {
            Some(signature) => Ok(signature),
            None => self.producer.sign_handoff(request),
        }
    }
}

#[test]
fn borrowed_pending_guard_binds_actual_namespace_before_and_after_key() {
    let fixture = authority_fixture();
    for after_key in [false, true] {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("roles.db");
        let watermark = MemoryWatermark::default();
        let mut journal = SqliteHandoffSignerJournalV1::create_new(
            &path,
            fixture.role_profile(),
            watermark.clone(),
        )
        .unwrap();
        let mut producer = PendingGuardProducer {
            path: path.clone(),
            producer: ExactProducer::new(fixture.signing_key.clone()),
            mutate_after_key: after_key,
        };
        let result = journal.sign_old_set_handoff_exact_v1(
            &fixture.old_handoff_intent(),
            &fixture.admission(),
            &mut producer,
        );
        assert!(matches!(
            result,
            Err(HandoffSignerJournalErrorV1::SignatureProducer(
                SignatureProducerErrorV0::Rejected
            ))
        ));
        assert_eq!(producer.producer.calls().1, u64::from(after_key));
        assert_eq!(watermark.snapshot().value.unwrap().sequence(), 1);
        assert_eq!(table_counts(&path), (1, 1, 0));
    }
}
