use std::{
    env, fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;
use trnm_consensus_external_watermark::{
    ExternalWatermarkAuthorityError, ExternalWatermarkSemanticFactsV1, ReplayBindingErrorV1,
    ReplayBindingStoreV1, ReplayBoundTimeoutProducer, TimeoutOnlySignerAdapter,
    UnixWatermarkClient,
};
use trnm_consensus_signer_journal::{
    SignatureProducerErrorV0, SignatureProducerV0, SignatureRequestV0, SignerJournalConflictV0,
    SignerJournalErrorV0, SignerJournalProfileV0, SignerWatermarkV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    BlockId, CanonicalSignIntentV0, CertificateId, ChainId, ConsensusParametersHash,
    ConsensusPublicKey, Epoch, GenesisHash, Height, ProtocolVersion, QcRef, SignatureBytes,
    Validator, ValidatorId, ValidatorSet, View, VotingPower,
};

const SCOPE: [u8; 32] = [0x11; 32];
const JOURNAL: [u8; 32] = [0x22; 32];
const MAXIMUM_DATABASE_BYTES: usize = 32 * 1024 * 1024;
const TEST_SEED: [u8; 32] = [0x19; 32];

struct AuthorityProcess {
    child: Child,
    socket: PathBuf,
    log: PathBuf,
    client: UnixWatermarkClient,
}

impl AuthorityProcess {
    fn start(root: &Path) -> Self {
        let socket = root.join("authority.sock");
        let log = root.join("authority.log");
        let binary = env!("CARGO_BIN_EXE_trnm-external-watermark-v0");
        let child = Command::new(binary)
            .args([
                "--socket",
                socket.to_str().expect("socket path"),
                "--log",
                log.to_str().expect("log path"),
            ])
            .spawn()
            .expect("spawn external authority");
        let client = UnixWatermarkClient::new(&socket).expect("authority client");
        let process = Self {
            child,
            socket,
            log,
            client,
        };
        process.wait_ready();
        process
    }

    fn wait_ready(&self) {
        for _ in 0..100 {
            match self.client.load_checked(SCOPE) {
                Err(ExternalWatermarkAuthorityError::Io { .. })
                | Err(ExternalWatermarkAuthorityError::Unavailable) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Ok(Some(_)) => return,
                other => panic!("authority did not start cleanly: {other:?}"),
            }
        }
        panic!("timed out waiting for authority socket");
    }

    fn restart(&mut self) {
        self.child.kill().expect("kill authority");
        let _ = self.child.wait();
        let replacement = Self::start(self.socket.parent().expect("authority parent"));
        self.child = replacement.child;
        self.socket = replacement.socket;
        self.log = replacement.log;
        self.client = replacement.client;
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn mark(sequence: u64, checksum: u8) -> SignerWatermarkV0 {
    SignerWatermarkV0::from_persisted_parts(SCOPE, JOURNAL, sequence, [checksum; 32])
        .expect("valid watermark")
}

#[test]
fn two_process_restart_rejects_stale_cas_and_log_tamper() {
    let root = tempdir().expect("private test directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start(root.path());
    assert_eq!(authority.client.load_checked(SCOPE).unwrap(), None);
    authority
        .client
        .compare_and_advance_checked(None, mark(0, 0x31))
        .unwrap();
    authority.restart();
    assert_eq!(
        authority.client.load_checked(SCOPE).unwrap(),
        Some(mark(0, 0x31))
    );
    authority
        .client
        .compare_and_advance_checked(Some(mark(0, 0x31)), mark(1, 0x32))
        .unwrap();
    assert!(matches!(
        authority
            .client
            .compare_and_advance_checked(Some(mark(0, 0x31)), mark(2, 0x33)),
        Err(ExternalWatermarkAuthorityError::CompareFailed)
    ));
    authority.stop();

    // Removing a complete final record is also detected by the independent
    // durable head anchor (a bare hash chain alone cannot detect this).
    let complete_log = fs::read(&authority.log).expect("read complete authority log");
    let record_bytes = complete_log.len() / 2;
    fs::write(&authority.log, &complete_log[..record_bytes]).expect("truncate full record");
    let binary = env!("CARGO_BIN_EXE_trnm-external-watermark-v0");
    let failed = Command::new(binary)
        .args([
            "--socket",
            authority.socket.to_str().unwrap(),
            "--log",
            authority.log.to_str().unwrap(),
        ])
        .output()
        .expect("restart authority after full truncation");
    assert!(
        !failed.status.success(),
        "full-record truncation must fail closed"
    );
    fs::write(&authority.log, complete_log).expect("restore complete log");

    // A kill-9/half-write style tail is never silently repaired.
    let mut log = fs::OpenOptions::new()
        .append(true)
        .open(&authority.log)
        .expect("open authority log for injected partial");
    log.write_all(&[0x7f]).expect("append partial record");
    log.sync_all().expect("sync partial record");
    let failed = Command::new(binary)
        .args([
            "--socket",
            authority.socket.to_str().unwrap(),
            "--log",
            authority.log.to_str().unwrap(),
        ])
        .output()
        .expect("restart authority after partial");
    assert!(!failed.status.success(), "partial log must fail closed");

    // Restore the complete log, mutate one authenticated byte, and require a
    // second independent process to reject the namespace as corrupted.
    let bytes = fs::read(&authority.log).expect("read partial log");
    fs::write(&authority.log, &bytes[..bytes.len() - 1]).expect("remove partial tail");
    let mut bytes = fs::read(&authority.log).expect("read complete log");
    bytes[20] ^= 1;
    fs::write(&authority.log, bytes).expect("tamper log");
    let failed = Command::new(binary)
        .args([
            "--socket",
            authority.socket.to_str().unwrap(),
            "--log",
            authority.log.to_str().unwrap(),
        ])
        .output()
        .expect("restart authority after tamper");
    assert!(!failed.status.success(), "tampered log must fail closed");
}

#[test]
fn semantic_cas_persists_round_order_across_restart_and_rejects_sidecar_tamper() {
    let root = tempdir().expect("private semantic test directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start(root.path());
    let first = mark(0, 0x41);
    let first_facts = ExternalWatermarkSemanticFactsV1::new(7, 3, 5).unwrap();
    authority
        .client
        .compare_and_advance_semantic_checked(None, first, first_facts)
        .expect("first semantic reservation");
    authority.restart();
    assert_eq!(authority.client.load_checked(SCOPE).unwrap(), Some(first));

    let lower_view = mark(1, 0x42);
    assert!(matches!(
        authority.client.compare_and_advance_semantic_checked(
            Some(first),
            lower_view,
            ExternalWatermarkSemanticFactsV1::new(7, 2, 6).unwrap(),
        ),
        Err(ExternalWatermarkAuthorityError::CompareFailed)
    ));
    let lower_revision = mark(1, 0x43);
    assert!(matches!(
        authority.client.compare_and_advance_semantic_checked(
            Some(first),
            lower_revision,
            ExternalWatermarkSemanticFactsV1::new(7, 4, 5).unwrap(),
        ),
        Err(ExternalWatermarkAuthorityError::CompareFailed)
    ));
    let next_epoch = mark(1, 0x44);
    authority
        .client
        .compare_and_advance_semantic_checked(
            Some(first),
            next_epoch,
            ExternalWatermarkSemanticFactsV1::new(8, 0, 6).unwrap(),
        )
        .expect("higher epoch may reset view");
    authority.stop();

    let semantic_log = root.path().join(".authority.log.semantic-v1");
    let bytes = fs::read(&semantic_log).expect("read semantic sidecar");
    fs::write(&semantic_log, &bytes[..bytes.len() - 1]).expect("truncate semantic sidecar");
    let binary = env!("CARGO_BIN_EXE_trnm-external-watermark-v0");
    let failed = Command::new(binary)
        .args([
            "--socket",
            authority.socket.to_str().unwrap(),
            "--log",
            authority.log.to_str().unwrap(),
        ])
        .output()
        .expect("restart tampered semantic authority");
    assert!(
        !failed.status.success(),
        "semantic sidecar rollback must fail closed"
    );
}

#[derive(Clone)]
struct OrderingProducer {
    key: Arc<SigningKey>,
    client: UnixWatermarkClient,
    calls: Arc<Mutex<u64>>,
}

impl SignatureProducerV0 for OrderingProducer {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        let head = self
            .client
            .load_checked(SCOPE)
            .map_err(|_| SignatureProducerErrorV0::Unavailable)?
            .ok_or(SignatureProducerErrorV0::Unavailable)?;
        // Local journal intent event is sequence 1; producer is not reached
        // until the external authority has accepted that event's watermark.
        if head.sequence() != 1 {
            return Err(SignatureProducerErrorV0::Rejected);
        }
        *self.calls.lock().expect("producer calls") += 1;
        Ok(SignatureBytes::from_array(
            self.key.sign(request.signing_root().as_bytes()).to_bytes(),
        ))
    }
}

fn signer_fixture() -> (SignerJournalProfileV0, SigningKey) {
    let key = SigningKey::from_bytes(&TEST_SEED);
    let author = ValidatorId::from_bytes(b"validator-a").expect("author");
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
        ChainId::new("trnm-external-signer-test").unwrap(),
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
            [0x51; 32],
            SCOPE,
            64,
            4096,
            MAXIMUM_DATABASE_BYTES,
        )
        .unwrap(),
        key,
    )
}

fn timeout_intent(profile: &SignerJournalProfileV0) -> CanonicalSignIntentV0 {
    CanonicalSignIntentV0::timeout_vote(
        profile.validator_set(),
        profile.author(),
        1,
        View::new(1),
        QcRef::new(
            CertificateId::new([0x70; 32]),
            profile.epoch(),
            View::new(0),
            Height::new(1),
            BlockId::new([0x71; 32]),
            profile.validator_set_id(),
        ),
    )
    .unwrap()
}

fn vote_intent(profile: &SignerJournalProfileV0) -> CanonicalSignIntentV0 {
    CanonicalSignIntentV0::vote(
        profile.validator_set(),
        profile.author(),
        2,
        View::new(2),
        Height::new(3),
        BlockId::new([0x72; 32]),
    )
    .unwrap()
}

#[test]
fn timeout_adapter_orders_external_cas_before_fixture_key_and_replays_exactly() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut authority = AuthorityProcess::start(root.path());
    let client = authority.client.clone();
    let (profile, key) = signer_fixture();
    let database = root.path().join("signer.sqlite3");
    let journal = SqliteSignerJournalV0::initialize_new(&database, profile.clone(), client.clone())
        .expect("initialize signer journal against external authority");
    let initial_db = fs::read(&database).expect("snapshot local signer database");
    let initial_wal = fs::read(database.with_extension("sqlite3-wal")).ok();
    let initial_shm = fs::read(database.with_extension("sqlite3-shm")).ok();
    let calls = Arc::new(Mutex::new(0));
    let producer = OrderingProducer {
        key: Arc::new(key),
        client: client.clone(),
        calls: Arc::clone(&calls),
    };
    let mut adapter = TimeoutOnlySignerAdapter::new(journal, producer);
    let timeout = timeout_intent(&profile);
    adapter
        .sign_timeout_only(&timeout)
        .expect("timeout signer path");
    assert_eq!(*calls.lock().unwrap(), 1);
    assert_eq!(client.load_checked(SCOPE).unwrap().unwrap().sequence(), 2);
    adapter
        .sign_timeout_only(&timeout)
        .expect("exact timeout replay");
    assert_eq!(*calls.lock().unwrap(), 1, "replay must not call producer");
    assert!(matches!(
        adapter.sign_timeout_only(&vote_intent(&profile)),
        Err(SignerJournalErrorV0::InvalidProfile(_))
    ));
    drop(adapter);

    // Restore the pre-sign local DB while the external authority remains at
    // sequence 2. Opening it must fail closed instead of signing from rollback.
    let database_wal = database.with_extension("sqlite3-wal");
    let database_shm = database.with_extension("sqlite3-shm");
    fs::remove_file(&database_wal).ok();
    fs::remove_file(&database_shm).ok();
    fs::write(&database, initial_db).unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
    if let Some(bytes) = initial_wal {
        fs::write(&database_wal, bytes).unwrap();
        fs::set_permissions(&database_wal, fs::Permissions::from_mode(0o600)).unwrap();
    }
    if let Some(bytes) = initial_shm {
        fs::write(&database_shm, bytes).unwrap();
        fs::set_permissions(&database_shm, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let result = SqliteSignerJournalV0::open_existing(&database, profile, client);
    assert!(matches!(
        result,
        Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkAhead
                | SignerJournalConflictV0::ExternalWatermarkFork
                | SignerJournalConflictV0::ExternalWatermarkRepairRequired
        ))
    ));
    authority.stop();
}

#[derive(Clone)]
struct CountingProducer {
    key: Arc<SigningKey>,
    calls: Arc<Mutex<u64>>,
}

impl SignatureProducerV0 for CountingProducer {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        *self.calls.lock().expect("producer calls") += 1;
        Ok(SignatureBytes::from_array(
            self.key.sign(request.signing_root().as_bytes()).to_bytes(),
        ))
    }
}

struct RejectingProducer {
    calls: Arc<Mutex<u64>>,
}

impl SignatureProducerV0 for RejectingProducer {
    fn sign(
        &mut self,
        _request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        *self.calls.lock().expect("rejecting producer calls") += 1;
        Err(SignatureProducerErrorV0::Rejected)
    }
}

struct CrashAfterResponseProducer<P> {
    inner: P,
}

impl<P: SignatureProducerV0> SignatureProducerV0 for CrashAfterResponseProducer<P> {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        let _signature = self.inner.sign(request)?;
        // Test-only crash boundary: ReplayBoundTimeoutProducer has durably
        // recorded the response, while the outer journal has not appended its
        // signature event yet.
        std::process::abort();
        #[allow(unreachable_code)]
        Ok(_signature)
    }
}

#[test]
fn durable_timeout_response_binding_recovers_after_process_kill() {
    let root = tempdir().expect("private test directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start(root.path());
    let client = authority.client.clone();
    let (profile, _key) = signer_fixture();
    let database = root.path().join("crash-signer.sqlite3");
    let response_log = root.path().join("crash-timeout-response.log");
    let journal = SqliteSignerJournalV0::initialize_new(&database, profile.clone(), client.clone())
        .expect("initialize crash signer journal");
    drop(journal);

    let child = Command::new(env::current_exe().expect("current authority test executable"))
        .arg("--exact")
        .arg("durable_timeout_response_binding_crash_child")
        .arg("--nocapture")
        .env("TRNM_TIMEOUT_CRASH_ROOT", root.path())
        .env("TRNM_TIMEOUT_CRASH_DATABASE", &database)
        .env("TRNM_TIMEOUT_CRASH_RESPONSE_LOG", &response_log)
        .spawn()
        .expect("spawn timeout crash child");
    let output = child.wait_with_output().expect("wait timeout crash child");
    assert!(
        !output.status.success(),
        "child must die after response binding and before journal signature event"
    );

    let journal = SqliteSignerJournalV0::open_existing(&database, profile.clone(), client.clone())
        .expect("reopen signer journal after child kill");
    let replay_calls = Arc::new(Mutex::new(0));
    let producer = ReplayBoundTimeoutProducer::open(
        &response_log,
        RejectingProducer {
            calls: Arc::clone(&replay_calls),
        },
    )
    .expect("reopen response binding after child kill");
    let mut adapter = TimeoutOnlySignerAdapter::new(journal, producer);
    let timeout = timeout_intent(&profile);
    adapter
        .sign_timeout_only(&timeout)
        .expect("recover exact response after child kill");
    assert_eq!(*replay_calls.lock().unwrap(), 0);
    drop(adapter);
    authority.stop();
}

#[test]
fn durable_timeout_response_binding_crash_child() {
    let Ok(root) = env::var("TRNM_TIMEOUT_CRASH_ROOT") else {
        return;
    };
    let database = env::var("TRNM_TIMEOUT_CRASH_DATABASE").expect("crash database");
    let response_log = env::var("TRNM_TIMEOUT_CRASH_RESPONSE_LOG").expect("crash response log");
    let socket = PathBuf::from(root).join("authority.sock");
    let client = UnixWatermarkClient::new(&socket).expect("crash authority client");
    let (profile, key) = signer_fixture();
    let journal = SqliteSignerJournalV0::open_existing(&database, profile.clone(), client)
        .expect("open child signer journal");
    let producer = ReplayBoundTimeoutProducer::open(
        response_log,
        OrderingProducer {
            key: Arc::new(key),
            client: UnixWatermarkClient::new(&socket).expect("child producer client"),
            calls: Arc::new(Mutex::new(0)),
        },
    )
    .expect("open child response binding");
    let producer = CrashAfterResponseProducer { inner: producer };
    let mut adapter = TimeoutOnlySignerAdapter::new(journal, producer);
    let timeout = timeout_intent(&profile);
    let _ = adapter.sign_timeout_only(&timeout);
}

#[test]
fn durable_timeout_response_binding_survives_restart_and_fails_closed_on_rollback() {
    let root = tempdir().expect("private test directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start(root.path());
    let client = authority.client.clone();
    let (profile, key) = signer_fixture();
    let database = root.path().join("restart-signer.sqlite3");
    let response_log = root.path().join("timeout-response.log");
    let journal = SqliteSignerJournalV0::initialize_new(&database, profile.clone(), client.clone())
        .expect("initialize signer journal");
    let first_calls = Arc::new(Mutex::new(0));
    let producer = ReplayBoundTimeoutProducer::open(
        &response_log,
        CountingProducer {
            key: Arc::new(key),
            calls: Arc::clone(&first_calls),
        },
    )
    .expect("open durable response binding");
    let mut adapter = TimeoutOnlySignerAdapter::new(journal, producer);
    let timeout = timeout_intent(&profile);
    let first_signature = adapter
        .sign_timeout_only(&timeout)
        .expect("first timeout response");
    assert_eq!(*first_calls.lock().unwrap(), 1);
    drop(adapter);

    // A fresh journal owner and a fresh response producer process can resume
    // the pending/replay path. The rejecting producer proves the response was
    // recovered from the durable binding rather than regenerated.
    let journal = SqliteSignerJournalV0::open_existing(&database, profile.clone(), client.clone())
        .expect("reopen signer journal after process restart");
    let replay_calls = Arc::new(Mutex::new(0));
    let producer = ReplayBoundTimeoutProducer::open(
        &response_log,
        RejectingProducer {
            calls: Arc::clone(&replay_calls),
        },
    )
    .expect("reopen durable response binding");
    let mut adapter = TimeoutOnlySignerAdapter::new(journal, producer);
    let replayed_signature = adapter
        .sign_timeout_only(&timeout)
        .expect("exact response replay after restart");
    assert_eq!(replayed_signature, first_signature);
    assert_eq!(
        *replay_calls.lock().unwrap(),
        0,
        "duplicate response must not reach the producer"
    );
    drop(adapter);
    authority.stop();

    // The independent response log has its own durable anchor. Rewinding its
    // tail while retaining the anchor is a hard startup failure.
    let bytes = fs::read(&response_log).expect("read response binding log");
    assert!(bytes.len() > 1);
    fs::write(&response_log, &bytes[..bytes.len() - 1]).expect("truncate response binding log");
    assert!(matches!(
        ReplayBindingStoreV1::open(&response_log),
        Err(ReplayBindingErrorV1::InvalidLog(_)) | Err(ReplayBindingErrorV1::InvalidConfig(_))
    ));
}
