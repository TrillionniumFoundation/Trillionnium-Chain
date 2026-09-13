#![cfg(feature = "test-fixture")]

use std::{
    fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    process::{Child, Command},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;
use trnm_consensus_remote_signer_service::{
    fixture_proposal_service_config, fixture_service_config, Fixture as ServiceFixture,
    PurposePolicyV1, RemoteSignerService,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, ProposalSignatureRequestV0,
    SignerJournalProfileV0, SignerWatermarkV0, SqliteSignerJournalV0,
};
use trnm_consensus_types::SignatureVerifier;
use trnm_consensus_unix_remote_signer::{
    test_fixture::{fixture_config, fixture_intent},
    UnixRemoteProposalSignerProducer, UnixRemoteProposalSignerProducerConfig,
    UnixRemoteSignerError, UnixRemoteSignerProducer, UnixRemoteSignerProducerConfig,
};

fn spawn_server(temp: &TempDir, mode: &str, requests: usize) -> (Child, std::path::PathBuf) {
    let socket = temp.path().join("private").join("signer.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_trnm-remote-signer-test-fixture"))
        .arg(&socket)
        .arg(mode)
        .arg(requests.to_string())
        .spawn()
        .expect("spawn feature-gated signer fixture");
    wait_for_socket(&socket);
    (child, socket)
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            assert!(metadata.file_type().is_socket());
            assert_eq!(metadata.permissions().mode() & 0o077, 0);
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("fixture socket did not appear: {}", path.display());
}

fn finish(mut child: Child) {
    let status = child.wait().expect("wait for signer fixture");
    assert!(status.success(), "fixture server exited with {status}");
}

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Clone, Default)]
struct MemoryWatermark {
    value: Arc<Mutex<Option<SignerWatermarkV0>>>,
}

impl ExternalMonotonicWatermarkV0 for MemoryWatermark {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let value = *self.value.lock().expect("watermark mutex");
        if value.is_some_and(|head| head.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(value)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        let mut value = self.value.lock().expect("watermark mutex");
        if *value != expected {
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
        *value = Some(target);
        Ok(())
    }
}

#[test]
fn subprocess_valid_signature_and_exact_idempotent_retry() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (child, socket) = spawn_server(&temp, "valid", 2);
    let mut producer = UnixRemoteSignerProducer::new(fixture_config(&socket)).unwrap();
    let intent = fixture_intent(0);
    let first = producer
        .sign_intent_exact(&intent)
        .expect("first signature");
    let second = producer.sign_intent_exact(&intent).expect("exact retry");
    assert_eq!(first, second);
    finish(child);
}

#[test]
fn cross_request_replay_is_rejected_by_protocol_binding() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (child, socket) = spawn_server(&temp, "replay-first", 2);
    let mut producer = UnixRemoteSignerProducer::new(fixture_config(&socket)).unwrap();
    producer
        .sign_intent_exact(&fixture_intent(0))
        .expect("first signature");
    let error = producer
        .sign_intent_exact(&fixture_intent(1))
        .expect_err("response from another request must fail closed");
    assert!(matches!(error, UnixRemoteSignerError::Protocol(_)));
    finish(child);
}

#[test]
fn malformed_mutated_and_invalid_signature_responses_fail_closed() {
    for mode in [
        "mutated-response",
        "invalid-signature",
        "zero-length-response",
    ] {
        let temp = tempfile::tempdir().expect("tempdir");
        let (child, socket) = spawn_server(&temp, mode, 1);
        let mut producer = UnixRemoteSignerProducer::new(fixture_config(&socket)).unwrap();
        let error = producer
            .sign_intent_exact(&fixture_intent(0))
            .expect_err("malformed response must fail closed");
        match mode {
            "invalid-signature" => {
                assert!(matches!(error, UnixRemoteSignerError::InvalidSignature))
            }
            "zero-length-response" => {
                assert!(matches!(error, UnixRemoteSignerError::EmptyFrame))
            }
            _ => assert!(matches!(error, UnixRemoteSignerError::Protocol(_))),
        }
        finish(child);
    }
}

#[test]
fn truncated_and_oversized_frames_fail_closed() {
    for mode in ["truncated-response", "oversized-response"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let (child, socket) = spawn_server(&temp, mode, 1);
        let mut producer = UnixRemoteSignerProducer::new(fixture_config(&socket)).unwrap();
        let error = producer
            .sign_intent_exact(&fixture_intent(0))
            .expect_err("bad frame must fail closed");
        assert!(matches!(
            error,
            UnixRemoteSignerError::TruncatedFrame | UnixRemoteSignerError::FrameTooLarge { .. }
        ));
        finish(child);
    }
}

#[test]
fn signer_journal_composes_with_child_remote_signer_and_replays_locally() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("protect journal directory");
    let (child, socket) = spawn_server(&temp, "valid", 1);
    let config = fixture_config(&socket);
    let profile = SignerJournalProfileV0::new(
        config.validator_set.clone(),
        config.author,
        config.signer_profile_ref,
        [0x99; 32],
        16,
        4096,
        32 * 1024 * 1024,
    )
    .expect("journal profile");
    let database = temp.path().join("journal.sqlite3");
    let watermark = MemoryWatermark::default();
    let mut journal = SqliteSignerJournalV0::initialize_new(&database, profile, watermark)
        .expect("initialize journal");
    let mut producer = UnixRemoteSignerProducer::new(config).expect("producer config");
    let intent = fixture_intent(0);
    let first = journal
        .sign_exact_v0(&intent, &mut producer)
        .expect("journal delegates to child signer");
    let replay = journal
        .sign_exact_v0(&intent, &mut producer)
        .expect("journal exact replay");
    assert_eq!(first, replay);
    drop(journal);
    finish(child);
}

#[test]
fn socket_symlink_and_non_private_parent_are_rejected_before_connect() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (child, socket) = spawn_server(&temp, "valid", 1);
    let alias = temp.path().join("alias.sock");
    std::os::unix::fs::symlink(&socket, &alias).expect("create socket symlink");
    let symlink_producer = UnixRemoteSignerProducer::new(fixture_config(&alias)).unwrap();
    assert!(matches!(
        symlink_producer.preflight(),
        Err(UnixRemoteSignerError::InvalidConfig(_))
    ));
    stop(child);

    let temp = tempfile::tempdir().expect("tempdir");
    let (child, socket) = spawn_server(&temp, "valid", 1);
    let parent = socket.parent().expect("socket parent");
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
        .expect("make parent non-private");
    let producer = UnixRemoteSignerProducer::new(fixture_config(&socket)).unwrap();
    assert!(matches!(
        producer.preflight(),
        Err(UnixRemoteSignerError::SocketNotPrivate)
    ));
    stop(child);
}

#[test]
fn client_accepts_signature_from_real_service_process_boundary() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("protect service namespace");
    let service_directory = temp.path().join("service");
    fs::create_dir(&service_directory).expect("create service namespace");
    fs::set_permissions(&service_directory, fs::Permissions::from_mode(0o700))
        .expect("protect service namespace");
    let socket = service_directory.join("signer.sock");
    let watermark = service_directory.join("watermark.bin");
    let service_fixture = ServiceFixture::new();
    let mut service = RemoteSignerService::open(fixture_service_config(
        &watermark,
        PurposePolicyV1::vote_only(),
    ))
    .expect("open real signer service");
    let server_socket = socket.clone();
    let server = thread::spawn(move || service.serve_unix_once(&server_socket));
    wait_for_socket(&socket);

    let binding = service_fixture.binding;
    let config = UnixRemoteSignerProducerConfig {
        socket_path: socket,
        validator_set: service_fixture.validator_set.clone(),
        author: binding.author(),
        signer_profile_ref: [0xA1; 32],
        role_profile_ref: binding.role_profile_ref(),
        service_profile_ref: binding.service_profile_ref(),
        client_profile_ref: binding.client_profile_ref(),
        process_generation: binding.process_generation(),
        lease_id: binding.lease_id(),
        checkpoint_witness: binding.checkpoint_witness(),
        timeout: Duration::from_secs(2),
    };
    let mut producer = UnixRemoteSignerProducer::new(config).expect("client config");
    let intent = trnm_consensus_types::CanonicalSignIntentV0::vote(
        &service_fixture.validator_set,
        binding.author(),
        1,
        trnm_consensus_types::View::new(0),
        trnm_consensus_types::Height::new(1),
        trnm_consensus_types::BlockId::new([0xD1; 32]),
    )
    .expect("service-compatible intent");
    let signature = producer
        .sign_intent_exact(&intent)
        .expect("real service response must verify");
    let verifier = trnm_consensus_crypto::StrictEd25519Verifier;
    let validator = service_fixture
        .validator_set
        .validator(binding.author())
        .expect("service fixture author")
        .clone();
    assert!(verifier.verify(&validator, &intent.signing_root(), &signature));
    server
        .join()
        .expect("service thread")
        .expect("service request");
}

#[test]
fn client_accepts_isolated_proposal_signature_from_real_service_boundary() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("protect service namespace");
    let socket = temp.path().join("proposal-signer.sock");
    let watermark = temp.path().join("proposal-watermark.sqlite3");
    let service_fixture = ServiceFixture::new();
    let mut service = RemoteSignerService::open(
        fixture_proposal_service_config(&watermark).expect("proposal service config"),
    )
    .expect("open proposal-only service");
    let server_socket = socket.clone();
    let server = thread::spawn(move || service.serve_unix_once(&server_socket));
    wait_for_socket(&socket);

    let binding = service_fixture.binding;
    let config = UnixRemoteProposalSignerProducerConfig {
        socket_path: socket,
        validator_set: service_fixture.validator_set.clone(),
        author: binding.author(),
        signer_profile_ref: [0xA4; 32],
        role_profile_ref: binding.role_profile_ref(),
        service_profile_ref: binding.service_profile_ref(),
        client_profile_ref: binding.client_profile_ref(),
        process_generation: binding.process_generation(),
        lease_id: binding.lease_id(),
        checkpoint_witness: binding.checkpoint_witness(),
        timeout: Duration::from_secs(2),
    };
    let mut producer =
        UnixRemoteProposalSignerProducer::new(config).expect("proposal client config");
    let validator = service_fixture
        .validator_set
        .validator(binding.author())
        .expect("service fixture author");
    let request = ProposalSignatureRequestV0::new(
        trnm_consensus_types::BlockId::new([0xE1; 32]),
        trnm_consensus_types::BlockId::new([0xE2; 32]),
        service_fixture.validator_set.id(),
        binding.author(),
        service_fixture.validator_set.epoch(),
        trnm_consensus_types::View::new(1),
        trnm_consensus_types::Height::new(1),
        trnm_consensus_types::SigningRoot::new([0xE3; 32]),
        *validator.consensus_key().as_bytes(),
        [0xA4; 32],
    )
    .expect("proposal request shape");
    let signature = producer
        .sign_proposal_exact(request)
        .expect("isolated proposal response must verify");
    assert!(trnm_consensus_crypto::StrictEd25519Verifier.verify(
        validator,
        &request.signing_root(),
        &signature
    ));
    server
        .join()
        .expect("proposal service thread")
        .expect("proposal request");
}

#[test]
fn vote_timeout_client_cannot_cross_into_proposal_service() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("protect service namespace");
    let socket = temp.path().join("proposal-only.sock");
    let watermark = temp.path().join("proposal-only.sqlite3");
    let service_fixture = ServiceFixture::new();
    let mut service = RemoteSignerService::open(
        fixture_proposal_service_config(&watermark).expect("proposal service config"),
    )
    .expect("open proposal-only service");
    let server_socket = socket.clone();
    let server = thread::spawn(move || service.serve_unix_once(&server_socket));
    wait_for_socket(&socket);

    // The ordinary client carries the Vote/Timeout binding profile.  It must
    // be rejected by the proposal-only service before any proposal table or
    // signer path is touched; there is no purpose downgrade or fallback.
    let mut config = fixture_config(&socket);
    config.validator_set = service_fixture.validator_set.clone();
    config.author = service_fixture.binding.author();
    config.role_profile_ref = service_fixture.binding.role_profile_ref();
    config.service_profile_ref = service_fixture.binding.service_profile_ref();
    config.client_profile_ref = service_fixture.binding.client_profile_ref();
    config.process_generation = service_fixture.binding.process_generation();
    config.lease_id = service_fixture.binding.lease_id();
    config.checkpoint_witness = service_fixture.binding.checkpoint_witness();
    let mut producer = UnixRemoteSignerProducer::new(config).expect("ordinary client config");
    let intent = trnm_consensus_types::CanonicalSignIntentV0::vote(
        &service_fixture.validator_set,
        service_fixture.binding.author(),
        1,
        trnm_consensus_types::View::new(0),
        trnm_consensus_types::Height::new(1),
        trnm_consensus_types::BlockId::new([0xD4; 32]),
    )
    .expect("service-compatible intent");
    let error = producer
        .sign_intent_exact(&intent)
        .expect_err("Vote/Timeout client must not reach proposal-only service");
    assert!(matches!(
        error,
        UnixRemoteSignerError::ServiceRejected(_) | UnixRemoteSignerError::Protocol(_)
    ));
    server
        .join()
        .expect("proposal-only service thread")
        .expect("proposal-only request handling");
}
