use std::{
    env, fs,
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;
use trnm_consensus_external_watermark::{
    ExternalWatermarkAuthorityError, ExternalWatermarkSemanticBindingV1,
    ExternalWatermarkSemanticFactsV1, ExternalWatermarkSemanticLifecycleModeV1,
    ReplayBindingErrorV1, ReplayBindingStoreV1, ReplayBoundTimeoutProducer,
    TimeoutOnlySignerAdapter, UnixWatermarkClient,
};
use trnm_consensus_signer_journal::{
    signer_journal_lifecycle_nonce_v0, SignatureProducerErrorV0, SignatureProducerV0,
    SignatureRequestV0, SignerJournalConflictV0, SignerJournalErrorV0, SignerJournalProfileV0,
    SignerWatermarkV0, SqliteSignerJournalV0,
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
const CAPABILITY: [u8; 32] = [0x33; 32];

fn semantic_binding() -> ExternalWatermarkSemanticBindingV1 {
    ExternalWatermarkSemanticBindingV1::new(SCOPE, JOURNAL, CAPABILITY)
        .expect("valid semantic test binding")
}

fn per_reservation_binding() -> ExternalWatermarkSemanticBindingV1 {
    ExternalWatermarkSemanticBindingV1::new_per_reservation(SCOPE, JOURNAL, CAPABILITY)
        .expect("valid per-reservation test binding")
}

struct AuthorityProcess {
    child: Child,
    socket: PathBuf,
    log: PathBuf,
    client: UnixWatermarkClient,
    semantic: bool,
    lifecycle_mode: ExternalWatermarkSemanticLifecycleModeV1,
}

impl AuthorityProcess {
    fn start(root: &Path) -> Self {
        Self::start_with_mode(
            root,
            false,
            ExternalWatermarkSemanticLifecycleModeV1::SignerJournalPair,
        )
    }

    fn start_semantic(root: &Path) -> Self {
        Self::start_with_mode(
            root,
            true,
            ExternalWatermarkSemanticLifecycleModeV1::SignerJournalPair,
        )
    }

    fn start_per_reservation(root: &Path) -> Self {
        Self::start_with_mode(
            root,
            true,
            ExternalWatermarkSemanticLifecycleModeV1::PerReservation,
        )
    }

    fn start_with_mode(
        root: &Path,
        semantic: bool,
        lifecycle_mode: ExternalWatermarkSemanticLifecycleModeV1,
    ) -> Self {
        let socket = root.join("authority.sock");
        let log = root.join("authority.log");
        let binary = env!("CARGO_BIN_EXE_trnm-external-watermark-v0");
        let mut command = Command::new(binary);
        if semantic {
            command.arg("semantic");
            if lifecycle_mode == ExternalWatermarkSemanticLifecycleModeV1::PerReservation {
                command.arg("--per-reservation");
            }
            command.args([
                "--scope",
                &hex32(SCOPE),
                "--journal-id",
                &hex32(JOURNAL),
                "--capability",
                &hex32(CAPABILITY),
            ]);
        } else {
            // Opaque CAS is retained only as an explicit fixture path.  The
            // production-shaped CLI refuses to start it without this marker,
            // preventing a semantic authority from being downgraded by a
            // stale supervisor command line.
            command.args(["opaque", "--fixture-opaque"]);
        }
        let child = command
            .args([
                "--socket",
                socket.to_str().expect("socket path"),
                "--log",
                log.to_str().expect("log path"),
            ])
            .spawn()
            .expect("spawn external authority");
        let client = UnixWatermarkClient::new(&socket).expect("authority client");
        let client = if semantic {
            let binding =
                if lifecycle_mode == ExternalWatermarkSemanticLifecycleModeV1::PerReservation {
                    per_reservation_binding()
                } else {
                    semantic_binding()
                };
            client.with_semantic_binding(binding)
        } else {
            client
        };
        let process = Self {
            child,
            socket,
            log,
            client,
            semantic,
            lifecycle_mode,
        };
        process.wait_ready();
        process
    }

    fn wait_ready(&self) {
        // Parallel Rust test processes can briefly contend for the build
        // machine's filesystem and scheduler.  Readiness is still bounded,
        // but a one-second window made an otherwise healthy daemon flaky.
        for _ in 0..500 {
            let result = if self.semantic {
                let binding = if self.lifecycle_mode
                    == ExternalWatermarkSemanticLifecycleModeV1::PerReservation
                {
                    per_reservation_binding()
                } else {
                    semantic_binding()
                };
                self.client
                    .load_semantic_checked(binding)
                    .map(|value| value.map(|(watermark, _)| watermark))
            } else {
                self.client.load_checked(SCOPE)
            };
            match result {
                Err(ExternalWatermarkAuthorityError::Io { .. })
                | Err(ExternalWatermarkAuthorityError::Unavailable) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Ok(Some(_)) => return,
                Err(ExternalWatermarkAuthorityError::InvalidLog(_)) if self.semantic => {
                    use trnm_consensus_signer_journal::ExternalSignerRetirementV1;
                    if self
                        .client
                        .clone()
                        .load_signer_retirement_v1(SCOPE)
                        .is_ok_and(|r| r.is_some())
                    {
                        return;
                    }
                    panic!("authority rejected both active and retired readiness");
                }
                other => panic!("authority did not start cleanly: {other:?}"),
            }
        }
        panic!("timed out waiting for authority socket");
    }

    fn restart(&mut self) {
        self.child.kill().expect("kill authority");
        let _ = self.child.wait();
        let replacement = Self::start_with_mode(
            self.socket.parent().expect("authority parent"),
            self.semantic,
            self.lifecycle_mode,
        );
        self.child = replacement.child;
        self.socket = replacement.socket;
        self.log = replacement.log;
        self.client = replacement.client;
        self.semantic = replacement.semantic;
        self.lifecycle_mode = replacement.lifecycle_mode;
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn assert_authority_exited(authority: &mut AuthorityProcess) {
    for _ in 0..200 {
        if let Some(status) = authority.child.try_wait().expect("poll authority process") {
            assert!(!status.success(), "tampered authority must fail closed");
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("tampered authority stayed alive instead of poisoning");
}

fn hex32(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn semantic_facts(
    epoch: u64,
    view: u64,
    revision: u64,
    nonce: u8,
    fingerprint: u8,
) -> ExternalWatermarkSemanticFactsV1 {
    ExternalWatermarkSemanticFactsV1::new(epoch, view, revision)
        .and_then(|facts| {
            facts.with_request([nonce; 32], [fingerprint; 32], [0x66; 32], CAPABILITY)
        })
        .expect("valid semantic facts")
}

fn semantic_lifecycle_facts(
    epoch: u64,
    view: u64,
    revision: u64,
    sequence: u64,
    fingerprint: u8,
) -> ExternalWatermarkSemanticFactsV1 {
    let fingerprint = [fingerprint; 32];
    let root = [0x66; 32];
    let nonce =
        signer_journal_lifecycle_nonce_v0(epoch, view, revision, fingerprint, root, sequence);
    ExternalWatermarkSemanticFactsV1::new(epoch, view, revision)
        .and_then(|facts| facts.with_request(nonce, fingerprint, root, CAPABILITY))
        .expect("valid lifecycle semantic facts")
}

fn mark(sequence: u64, checksum: u8) -> SignerWatermarkV0 {
    SignerWatermarkV0::from_persisted_parts(SCOPE, JOURNAL, sequence, [checksum; 32])
        .expect("valid watermark")
}

fn read_raw_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .expect("fake socket frame length");
    let mut body = vec![0_u8; u32::from_be_bytes(length) as usize];
    stream
        .read_exact(&mut body)
        .expect("fake socket frame body");
    body
}

fn write_raw_frame(stream: &mut UnixStream, body: &[u8]) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .expect("fake socket frame");
}

#[test]
fn same_uid_fake_semantic_socket_cannot_answer_capability_challenge() {
    let root = tempdir().expect("private fake socket directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let socket = root.path().join("authority.sock");
    let listener = UnixListener::bind(&socket).expect("bind fake authority socket");
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).expect("socket mode");
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake authority client");
        let hello = read_raw_frame(&mut stream);
        assert_eq!(&hello[..4], b"EWA1");
        assert_eq!(hello[5], 0, "client must begin with a hello challenge");
        let mut challenge = vec![0_u8; 40];
        challenge[..4].copy_from_slice(b"EWA1");
        challenge[4] = 1;
        challenge[5] = 1;
        challenge[8..].fill(0x44);
        write_raw_frame(&mut stream, &challenge);
        let proof = read_raw_frame(&mut stream);
        assert_eq!(
            proof[5], 2,
            "client must prove possession, not send capability"
        );
        let mut fake_ack = vec![0_u8; 40];
        fake_ack[..4].copy_from_slice(b"EWA1");
        fake_ack[4] = 1;
        fake_ack[5] = 3;
        fake_ack[8..].fill(0xaa);
        write_raw_frame(&mut stream, &fake_ack);
    });
    let binding = semantic_binding();
    let client = UnixWatermarkClient::new(&socket)
        .expect("fake socket client")
        .with_semantic_binding(binding);
    let error = client
        .load_semantic_checked(binding)
        .expect_err("same-UID fake socket must not authenticate");
    assert!(
        matches!(error, ExternalWatermarkAuthorityError::Protocol(_)),
        "unexpected fake socket error: {error:?}"
    );
    thread.join().expect("fake socket thread");
}

#[test]
fn replacing_bound_socket_path_poison_daemon_on_next_original_connection() {
    let root = tempdir().expect("private socket replacement directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start_semantic(root.path());
    let journal_before = fs::read(&authority.log).expect("read original authority journal");
    let original_socket = root.path().join("authority.original.sock");
    fs::rename(&authority.socket, &original_socket).expect("rename bound socket path");

    // A same-UID process can now bind the old public pathname, but the daemon
    // must not continue advertising that replacement as its authority.
    let fake_listener = UnixListener::bind(&authority.socket).expect("bind replacement socket");
    fs::set_permissions(&authority.socket, fs::Permissions::from_mode(0o600))
        .expect("replacement socket mode");
    let fake_thread = thread::spawn(move || {
        let _ = fake_listener.accept();
    });
    let fake_client = UnixWatermarkClient::new(&authority.socket)
        .expect("replacement socket client")
        .with_semantic_binding(semantic_binding());
    assert!(
        fake_client
            .load_semantic_checked(semantic_binding())
            .is_err(),
        "replacement socket must not answer semantic authority requests"
    );

    // The prior readiness request can discover replacement in its post-request
    // check before this connection. Both an already-closed listener and one
    // woken here must lead to the same bounded, non-success daemon exit.
    match UnixStream::connect(&original_socket) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(error) => panic!("unexpected original-listener error: {error}"),
    }
    assert_authority_exited(&mut authority);
    assert_eq!(
        fs::read(&authority.log).expect("read journal after rejection"),
        journal_before,
        "socket substitution must not mutate the authority journal"
    );
    fake_thread.join().expect("replacement socket thread");
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
    let mut authority = AuthorityProcess::start_semantic(root.path());
    let first = mark(0, 0x41);
    let wrong_binding = ExternalWatermarkSemanticBindingV1::new(SCOPE, JOURNAL, [0x44; 32])
        .expect("valid alternate semantic binding");
    assert!(
        authority
            .client
            .load_semantic_checked(wrong_binding)
            .is_err(),
        "semantic head reads must require the exact immutable binding"
    );
    assert!(
        authority.client.load_checked(SCOPE).is_err(),
        "semantic namespaces reject the opaque load operation"
    );
    assert!(
        authority
            .client
            .compare_and_advance_checked(None, first)
            .is_err(),
        "semantic namespaces reject the opaque CAS operation"
    );
    assert_eq!(
        fs::metadata(&authority.log).unwrap().len(),
        0,
        "opaque downgrade must not write the main log"
    );
    let first_facts = semantic_facts(7, 3, 5, 1, 0x51);
    authority
        .client
        .compare_and_advance_semantic_checked(None, first, first_facts)
        .expect("first semantic reservation");
    authority.restart();
    assert_eq!(
        authority
            .client
            .load_semantic_checked(semantic_binding())
            .unwrap()
            .map(|(watermark, _)| watermark),
        Some(first)
    );

    let lower_view = mark(1, 0x42);
    assert!(matches!(
        authority.client.compare_and_advance_semantic_checked(
            Some(first),
            lower_view,
            semantic_facts(7, 2, 6, 2, 0x52),
        ),
        Err(ExternalWatermarkAuthorityError::CompareFailed)
    ));
    let lower_revision = mark(1, 0x43);
    assert!(matches!(
        authority.client.compare_and_advance_semantic_checked(
            Some(first),
            lower_revision,
            semantic_facts(7, 4, 5, 3, 0x53),
        ),
        Err(ExternalWatermarkAuthorityError::CompareFailed)
    ));
    let next_epoch = mark(1, 0x44);
    authority
        .client
        .compare_and_advance_semantic_checked(
            Some(first),
            next_epoch,
            semantic_facts(8, 0, 6, 4, 0x54),
        )
        .expect("higher epoch may reset view");
    authority.stop();

    let semantic_log = root.path().join(".authority.log.semantic-v1");
    let bytes = fs::read(&semantic_log).expect("read semantic sidecar");
    fs::write(&semantic_log, &bytes[..bytes.len() - 1]).expect("truncate semantic sidecar");
    let binary = env!("CARGO_BIN_EXE_trnm-external-watermark-v0");
    let failed = Command::new(binary)
        .args([
            "semantic",
            "--socket",
            authority.socket.to_str().unwrap(),
            "--log",
            authority.log.to_str().unwrap(),
            "--scope",
            &hex32(SCOPE),
            "--journal-id",
            &hex32(JOURNAL),
            "--capability",
            &hex32(CAPABILITY),
        ])
        .output()
        .expect("restart tampered semantic authority");
    assert!(
        !failed.status.success(),
        "semantic sidecar rollback must fail closed"
    );
}

#[test]
fn semantic_namespace_cannot_downgrade_or_rebind_capability() {
    let root = tempdir().expect("private semantic mode directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start_semantic(root.path());
    let first = mark(0, 0x71);
    authority
        .client
        .compare_and_advance_semantic_checked(None, first, semantic_facts(1, 1, 1, 0x71, 0x81))
        .expect("bound semantic reservation");
    let wrong_capability = ExternalWatermarkSemanticFactsV1::new(1, 2, 2)
        .and_then(|facts| facts.with_request([0x72; 32], [0x82; 32], [0x66; 32], [0x44; 32]))
        .expect("wrong capability facts");
    assert!(matches!(
        authority.client.compare_and_advance_semantic_checked(
            Some(first),
            mark(1, 0x72),
            wrong_capability,
        ),
        Err(ExternalWatermarkAuthorityError::InvalidLog(_))
    ));
    authority.stop();

    // The immutable semantic mode marker rejects the legacy opaque opener,
    // even though the caller can still see the same Unix socket/log paths.
    let failed = Command::new(env!("CARGO_BIN_EXE_trnm-external-watermark-v0"))
        .args([
            "--socket",
            root.path().join("opaque.sock").to_str().unwrap(),
            "--log",
            root.path().join("authority.log").to_str().unwrap(),
        ])
        .output()
        .expect("spawn attempted opaque downgrade");
    assert!(!failed.status.success(), "semantic mode must not downgrade");
}

#[test]
fn per_reservation_mode_accepts_three_cas_records_across_restart_and_tamper() {
    let root = tempdir().expect("private per-reservation directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start_per_reservation(root.path());
    let binding = per_reservation_binding();
    let mut expected = None;
    for (sequence, epoch, view, revision, nonce, fingerprint, checksum) in [
        (0, 1, 1, 1, 0x81, 0x91, 0x41),
        (1, 1, 1, 2, 0x82, 0x92, 0x42),
        (2, 1, 2, 3, 0x83, 0x93, 0x43),
    ] {
        let target = mark(sequence, checksum);
        authority
            .client
            .compare_and_advance_semantic_checked(
                expected,
                target,
                ExternalWatermarkSemanticFactsV1::new(epoch, view, revision)
                    .and_then(|facts| {
                        facts.with_request([nonce; 32], [fingerprint; 32], [0x66; 32], CAPABILITY)
                    })
                    .expect("per-reservation facts"),
            )
            .unwrap_or_else(|error| panic!("per-reservation CAS sequence={sequence}: {error:?}"));
        expected = Some(target);
        if sequence == 1 {
            authority.restart();
            assert_eq!(
                authority
                    .client
                    .load_semantic_checked(binding)
                    .expect("reopen per-reservation head")
                    .map(|(watermark, _)| watermark),
                Some(target)
            );
        }
    }
    authority.stop();
    let semantic_log = root.path().join(".authority.log.semantic-v1");
    let bytes = fs::read(&semantic_log).expect("read per-reservation sidecar");
    fs::write(&semantic_log, &bytes[..bytes.len() - 1]).expect("tamper sidecar tail");
    let failed = Command::new(env!("CARGO_BIN_EXE_trnm-external-watermark-v0"))
        .args([
            "semantic",
            "--per-reservation",
            "--socket",
            authority.socket.to_str().unwrap(),
            "--log",
            authority.log.to_str().unwrap(),
            "--scope",
            &hex32(SCOPE),
            "--journal-id",
            &hex32(JOURNAL),
            "--capability",
            &hex32(CAPABILITY),
        ])
        .output()
        .expect("restart tampered per-reservation authority");
    assert!(
        !failed.status.success(),
        "tampered sidecar must fail closed"
    );
}

#[test]
fn semantic_journal_lifecycle_accepts_prepared_signed_pair_and_rejects_third_event() {
    let root = tempdir().expect("private semantic lifecycle directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start_semantic(root.path());

    // A direct sequence-zero semantic reservation models a service-owned
    // first request (the explicit journal-genesis path uses its own synthetic
    // facts).  The next odd sequence is a new intent and must advance the
    // authenticated round/revision.
    let first = mark(0, 0x91);
    authority
        .client
        .compare_and_advance_semantic_checked(None, first, semantic_facts(3, 1, 1, 0x91, 0xa1))
        .expect("first semantic reservation");
    let prepared = mark(1, 0x92);
    authority
        .client
        .compare_and_advance_semantic_checked(
            Some(first),
            prepared,
            semantic_facts(3, 2, 2, 0x92, 0xa2),
        )
        .expect("prepared lifecycle event");

    // Reusing the intent facts with an arbitrary nonce is not a valid signed
    // lifecycle transition; the nonce must be derived from the target event
    // sequence and exact intent identity.
    let signed = mark(2, 0x93);
    assert!(matches!(
        authority.client.compare_and_advance_semantic_checked(
            Some(prepared),
            signed,
            semantic_facts(3, 2, 2, 0x93, 0xa2),
        ),
        Err(ExternalWatermarkAuthorityError::CompareFailed)
    ));
    authority
        .client
        .compare_and_advance_semantic_checked(
            Some(prepared),
            signed,
            semantic_lifecycle_facts(3, 2, 2, 2, 0xa2),
        )
        .expect("exact prepared-to-signed lifecycle event");

    // A third event for the same intent would violate the journal's two-event
    // lifecycle and must fail closed even with a fresh nonce.
    assert!(matches!(
        authority.client.compare_and_advance_semantic_checked(
            Some(signed),
            mark(3, 0x94),
            semantic_facts(3, 3, 3, 0x94, 0xa2),
        ),
        Err(ExternalWatermarkAuthorityError::CompareFailed)
    ));
    authority.restart();
    assert_eq!(
        authority
            .client
            .load_semantic_checked(semantic_binding())
            .expect("reopen semantic lifecycle authority")
            .map(|(watermark, _)| watermark),
        Some(signed)
    );
    authority.stop();
}

#[test]
fn live_log_tamper_poison_fails_before_next_request() {
    let root = tempdir().expect("private live-tamper directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start(root.path());
    authority
        .client
        .compare_and_advance_checked(None, mark(0, 0xa1))
        .expect("initial watermark");

    // Mutating the authenticated tail while the daemon is still serving must
    // not be deferred until restart: the next Unix request must poison the
    // process before it can return a watermark.
    let mut bytes = fs::read(&authority.log).expect("read live authority log");
    let last = bytes.last_mut().expect("non-empty authority log");
    *last ^= 0x01;
    fs::write(&authority.log, bytes).expect("tamper live authority log");
    assert!(
        authority.client.load_checked(SCOPE).is_err(),
        "live log tamper must not receive a successful response"
    );
    assert_authority_exited(&mut authority);
}

#[test]
fn live_semantic_log_append_poison_fails_before_next_request() {
    let root = tempdir().expect("private live semantic-tamper directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start_semantic(root.path());
    authority
        .client
        .compare_and_advance_semantic_checked(
            None,
            mark(0, 0xb1),
            semantic_facts(2, 1, 1, 0xb1, 0xc1),
        )
        .expect("initial semantic watermark");
    let semantic_log = root.path().join(".authority.log.semantic-v1");
    let mut log = fs::OpenOptions::new()
        .append(true)
        .open(&semantic_log)
        .expect("open semantic log for live append");
    log.write_all(&[0u8; 1]).expect("append semantic byte");
    log.sync_all().expect("sync semantic append");
    assert!(
        authority
            .client
            .load_semantic_checked(semantic_binding())
            .is_err(),
        "live semantic append must not receive a successful response"
    );
    assert_authority_exited(&mut authority);
}

#[test]
fn live_semantic_log_interior_tamper_poison_fails_before_next_request() {
    let root = tempdir().expect("private live semantic interior directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let mut authority = AuthorityProcess::start_semantic(root.path());
    let first = mark(0, 0xd1);
    authority
        .client
        .compare_and_advance_semantic_checked(None, first, semantic_facts(4, 1, 1, 0xd1, 0xe1))
        .expect("first semantic watermark");
    authority
        .client
        .compare_and_advance_semantic_checked(
            Some(first),
            mark(1, 0xd2),
            semantic_facts(4, 2, 2, 0xd2, 0xe2),
        )
        .expect("second semantic watermark");
    let semantic_log = root.path().join(".authority.log.semantic-v1");
    let mut bytes = fs::read(&semantic_log).expect("read semantic log");
    // The first record is no longer the tail.  Full online chain replay is
    // required so an interior rewrite cannot hide behind an unchanged head.
    let record_len = bytes.len() / 2;
    let interior_index = record_len / 2;
    bytes[interior_index] ^= 0x01;
    fs::write(&semantic_log, bytes).expect("tamper semantic interior");
    assert!(
        authority
            .client
            .load_semantic_checked(semantic_binding())
            .is_err(),
        "live semantic interior tamper must not receive a successful response"
    );
    assert_authority_exited(&mut authority);
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

#[test]
fn response_binding_log_rejects_oversized_file_before_replay() {
    let root = tempdir().expect("private test directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let response_log = root.path().join("oversized-response.log");
    let file = fs::File::create(&response_log).expect("create response binding log");
    file.set_len(64 * 1024 * 1024 + 1)
        .expect("sparsely extend response binding log");
    drop(file);
    fs::set_permissions(&response_log, fs::Permissions::from_mode(0o600))
        .expect("private response log mode");

    assert!(matches!(
        ReplayBindingStoreV1::open(&response_log),
        Err(ReplayBindingErrorV1::InvalidLog(reason))
            if reason == "response binding log exceeds configured bound"
    ));
}

fn strict_retirement_fixture() -> (
    SignerJournalProfileV0,
    SigningKey,
    trnm_consensus_crypto::StrictPreHandoffContextV1,
    trnm_consensus_types::CanonicalHandoffSignIntentV1,
) {
    use sha2::{Digest, Sha256};
    use trnm_consensus_types::{
        decode_block_header_v0_exact, decode_checkpoint_finality_proof_v0_exact,
        decode_consensus_parameters_v0_exact, decode_handoff_descriptor_v0_exact,
        decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact,
        CanonicalHandoffSignIntentV1,
    };
    let root:serde_json::Value=serde_json::from_str(include_str!("../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json")).unwrap();
    let p = &root["positive"]["preheader"];
    let bytes = |v: &serde_json::Value| {
        v.as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let old_params =
        decode_consensus_parameters_v0_exact(&bytes(&p["old_parameters_cev0_hex"])).unwrap();
    let new_params =
        decode_consensus_parameters_v0_exact(&bytes(&p["new_parameters_cev0_hex"])).unwrap();
    let old = decode_validator_set_v0_exact(&bytes(&p["old_validator_set_cev0_hex"])).unwrap();
    let new = decode_validator_set_v0_exact(&bytes(&p["new_validator_set_cev0_hex"])).unwrap();
    let commitment =
        decode_next_epoch_commitment_v0_exact(&bytes(&p["commitment_cev0_hex"])).unwrap();
    let parent =
        decode_block_header_v0_exact(&bytes(&p["checkpoint_parent_header_cev0_hex"])).unwrap();
    let finality = decode_checkpoint_finality_proof_v0_exact(
        &bytes(&root["positive"]["checkpoint_finality"]["raw_finality_proof_cev0_hex"]),
        &old,
        &old_params,
        &commitment,
        parent.timestamp_ms(),
    )
    .unwrap();
    let descriptor = decode_handoff_descriptor_v0_exact(&bytes(
        &root["positive"]["handoff"]["descriptor_cev0_hex"],
    ))
    .unwrap();
    let context = trnm_consensus_crypto::verify_pre_handoff_context_strict_v1(
        &finality,
        &commitment,
        &descriptor,
        &old,
        &old_params,
        &new,
        &new_params,
        &parent,
    )
    .unwrap();
    let author = ValidatorId::from_bytes(b"validator-a").unwrap();
    let intent = CanonicalHandoffSignIntentV1::old_set(
        &descriptor,
        &old,
        &new,
        &old_params,
        &new_params,
        author,
    )
    .unwrap();
    let key = SigningKey::from_bytes(
        &Sha256::digest(b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:validator-a").into(),
    );
    assert_eq!(
        old.validator(author).unwrap().consensus_key().as_bytes(),
        &key.verifying_key().to_bytes()
    );
    (
        SignerJournalProfileV0::new(
            old,
            author,
            [0x51; 32],
            SCOPE,
            64,
            4096,
            MAXIMUM_DATABASE_BYTES,
        )
        .unwrap(),
        key,
        context,
        intent,
    )
}
fn retirement_host_cut() -> trnm_consensus_signer_journal::SignerRetirementHostCutV1 {
    trnm_consensus_signer_journal::SignerRetirementHostCutV1 {
        owner_generation: 1,
        native_committed_cut: [41; 32],
        safety_revision: 10,
        safety_record_checksum: [42; 32],
    }
}
#[test]
fn retirement_real_local_owner_and_daemon_reject_restored_ordinary_snapshot() {
    use trnm_consensus_signer_journal::{ExternalSignerRetirementV1, RetiredSqliteSignerJournalV1};
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut authority = AuthorityProcess::start_semantic(root.path());
    let local = root.path().join("local");
    fs::create_dir(&local).unwrap();
    fs::set_permissions(&local, fs::Permissions::from_mode(0o700)).unwrap();
    let (profile, key, context, intent) = strict_retirement_fixture();
    let path = local.join("ordinary.sqlite3");
    let mut old = SqliteSignerJournalV0::initialize_new_prebound_semantic_v1(
        &path,
        profile.clone(),
        authority.client.clone(),
        JOURNAL,
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(0));
    let mut producer = CountingProducer {
        key: Arc::new(key),
        calls: Arc::clone(&calls),
    };
    old.sign_exact_v0(&vote_intent(&profile), &mut producer)
        .unwrap();
    let snapshot = fs::read_dir(&local)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let b = fs::read(&p).unwrap();
            (p, b)
        })
        .collect::<Vec<_>>();
    let mut retired = old
        .retire_for_handoff_v1(&context, &intent, retirement_host_cut())
        .unwrap();
    let record = *retired.record_v1();
    assert_eq!(record.source_v1().sequence(), 2);
    let receipt = retired.confirm_retirement_v1().unwrap();
    assert!(receipt.belongs_to_owner_v1(&mut retired));
    assert!(authority
        .client
        .load_semantic_checked(semantic_binding())
        .is_err());
    assert!(authority.client.load_checked(SCOPE).is_err());
    assert!(authority
        .client
        .compare_and_advance_semantic_checked(
            Some(record.source_v1()),
            mark(3, 79),
            semantic_facts(profile.epoch().get(), 3, 11, 17, 18)
        )
        .is_err());
    assert_eq!(
        authority.client.load_signer_retirement_v1(SCOPE).unwrap(),
        Some(record)
    );
    drop(retired);
    let mut retired = RetiredSqliteSignerJournalV1::open_existing_v1(
        &path,
        profile.clone(),
        authority.client.clone(),
        record,
        &context,
        &intent,
    )
    .unwrap();
    assert!(retired.confirm_retirement_v1().is_ok());
    drop(retired);
    for (p, b) in snapshot {
        fs::write(p, b).unwrap();
    }
    assert!(
        SqliteSignerJournalV0::open_existing(&path, profile.clone(), authority.client.clone())
            .is_err()
    );
    authority.restart();
    assert!(
        SqliteSignerJournalV0::open_existing(&path, profile, authority.client.clone()).is_err()
    );
    assert_eq!(
        authority.client.retire_signer_exact_v1(&record).unwrap(),
        record.terminal_watermark_v1()
    );
    assert_eq!(*calls.lock().unwrap(), 1);
    assert_eq!(
        fs::metadata(root.path().join(".authority.log.mode-v1"))
            .unwrap()
            .len(),
        494
    );
    authority.stop();
}
#[test]
fn retirement_daemon_exact_retry_after_lost_local_confirmation_and_mode_tamper() {
    use trnm_consensus_signer_journal::{ExternalSignerRetirementV1, SignerRetirementCutV1};
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut authority = AuthorityProcess::start_semantic(root.path());
    let (profile, _, context, intent) = strict_retirement_fixture();
    let path = root.path().join("ordinary.sqlite3");
    let old = SqliteSignerJournalV0::initialize_new_prebound_semantic_v1(
        &path,
        profile,
        authority.client.clone(),
        JOURNAL,
    )
    .unwrap();
    assert!(old
        .retire_with_observer_v1(&context, &intent, retirement_host_cut(), |cut| {
            if cut == SignerRetirementCutV1::AfterExternalBeforeReadback {
                Err(SignerJournalErrorV0::CapacityExhausted)
            } else {
                Ok(())
            }
        })
        .is_err());
    let record = authority
        .client
        .load_signer_retirement_v1(SCOPE)
        .unwrap()
        .unwrap();
    authority.restart();
    assert_eq!(
        authority.client.retire_signer_exact_v1(&record).unwrap(),
        record.terminal_watermark_v1()
    );
    let mode = root.path().join(".authority.log.mode-v1");
    let mut bytes = fs::read(&mode).unwrap();
    bytes[116] ^= 1;
    fs::write(&mode, bytes).unwrap();
    assert!(authority.client.load_signer_retirement_v1(SCOPE).is_err());
    assert_authority_exited(&mut authority);
    authority.stop();
}

// Comparison-only external-policy fixture. Real strict-context retirement is
// tested above; this builder grants no local signer/host authority.
fn retirement_policy_fixture(
    source: SignerWatermarkV0,
    generation: u64,
) -> trnm_consensus_signer_journal::SignerRetirementRecordV1 {
    use sha2::{Digest, Sha256};
    let mut b = b"TRNMSR01".to_vec();
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&source.scope());
    b.extend_from_slice(&source.journal_id());
    b.extend_from_slice(&source.sequence().to_be_bytes());
    b.extend_from_slice(&source.chain_checksum());
    b.extend_from_slice(&generation.to_be_bytes());
    for v in [41, 42, 43, 44, 45] {
        b.extend_from_slice(&[v; 32]);
    }
    b.extend_from_slice(&10u64.to_be_bytes());
    b.extend_from_slice(&[46; 32]);
    let domain = b"trnm.consensus-signer-journal.retirement-record.v1";
    let mut h = Sha256::new();
    h.update(b"trnm.domain.hash.v1");
    h.update((domain.len() as u64).to_be_bytes());
    h.update(domain);
    h.update((b.len() as u64).to_be_bytes());
    h.update(&b);
    b.extend_from_slice(&h.finalize());
    trnm_consensus_signer_journal::SignerRetirementRecordV1::decode_v1_exact(&b).unwrap()
}
fn retirement_terminal_event_detects_mode_only_rollback_and_conflicting_retry_impl() {
    use trnm_consensus_external_watermark::ExternalWatermarkAuthority;
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("authority.log");
    let mut authority =
        ExternalWatermarkAuthority::open_semantic(&path, semantic_binding()).unwrap();
    let source = mark(0, 53);
    authority
        .compare_and_advance_semantic(None, source, semantic_facts(7, 0, 1, 11, 12))
        .unwrap();
    let mode = root.path().join(".authority.log.mode-v1");
    let original = fs::read(&mode).unwrap();
    let record = retirement_policy_fixture(source, 1);
    assert!(authority
        .retire_signer_exact_v1(per_reservation_binding(), record)
        .is_err());
    authority
        .retire_signer_exact_v1(semantic_binding(), record)
        .unwrap();
    assert!(authority
        .retire_signer_exact_v1(semantic_binding(), retirement_policy_fixture(source, 2))
        .is_err());
    drop(authority);
    let retired = fs::read(&mode).unwrap();
    fs::write(&mode, &original).unwrap();
    assert!(ExternalWatermarkAuthority::open_semantic(&path, semantic_binding()).is_err());
    fs::write(&mode, retired).unwrap();
    let mut authority =
        ExternalWatermarkAuthority::open_semantic(&path, semantic_binding()).unwrap();
    assert_eq!(
        authority
            .load_signer_retirement_v1(semantic_binding())
            .unwrap(),
        Some(record)
    );
    // A complete terminal event must bind its source chain, never just a file name.
    drop(authority);
    let mut log = fs::read(&path).unwrap();
    let last = log.len() - 1;
    log[last] ^= 1;
    fs::write(&path, log).unwrap();
    assert!(ExternalWatermarkAuthority::open_semantic(&path, semantic_binding()).is_err());
}

#[test]
fn retirement_terminal_event_mode_rollback_child() {
    if env::var_os("TRNM_RETIREMENT_MODE_ROLLBACK_CHILD").is_none() {
        return;
    }
    retirement_terminal_event_detects_mode_only_rollback_and_conflicting_retry_impl();
}

#[test]
fn retirement_terminal_event_detects_mode_only_rollback_and_conflicting_retry() {
    // Isolate the cold reopen sequence in its own exec'd process. The production
    // authority intentionally uses a fail-fast lifetime flock. In a parallel
    // Rust test process, an unrelated Command::spawn can fork while this test
    // owns the namespace and transiently inherit that flock until exec despite
    // O_CLOEXEC. Reopening in this multithreaded parent can therefore observe
    // EWOULDBLOCK even after the intended owner was dropped. The isolated child
    // has no sibling test threads/forks and exercises the unchanged production
    // fail-fast open/rollback behavior without adding retries or timeouts.
    let mut child = RetirementTestChild(
        Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "retirement_terminal_event_mode_rollback_child",
                "--nocapture",
            ])
            .env("TRNM_RETIREMENT_MODE_ROLLBACK_CHILD", "1")
            .spawn()
            .unwrap(),
    );
    let status = child.0.wait().unwrap();
    assert!(
        status.success(),
        "isolated mode rollback test failed: {status}"
    );
}

#[test]
fn retirement_pending_source_cannot_be_skipped() {
    use trnm_consensus_external_watermark::ExternalWatermarkAuthority;
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut authority = ExternalWatermarkAuthority::open_semantic(
        root.path().join("authority.log"),
        semantic_binding(),
    )
    .unwrap();
    let source = mark(0, 53);
    authority
        .compare_and_advance_semantic(None, source, semantic_facts(7, 0, 1, 11, 12))
        .unwrap();
    authority
        .compare_and_advance_semantic(Some(source), mark(1, 54), semantic_facts(7, 1, 2, 13, 14))
        .unwrap();
    assert!(authority
        .retire_signer_exact_v1(semantic_binding(), retirement_policy_fixture(source, 1))
        .is_err());
    assert_eq!(
        authority
            .load_signer_retirement_v1(semantic_binding())
            .unwrap(),
        None
    );
}
fn retirement_cut_index(
    cut: trnm_consensus_external_watermark::SignerRetirementAuthorityCutV1,
) -> usize {
    use trnm_consensus_external_watermark::SignerRetirementAuthorityCutV1::*;
    match cut {
        AfterWriteBeforeFileSync => 0,
        AfterFileSyncBeforeRename => 1,
        AfterRenameBeforeDirectorySync => 2,
        AfterDirectorySyncBeforeReadback => 3,
        AfterTerminalAppendBeforeSync => 4,
        AfterTerminalSyncBeforeReadback => 5,
        BeforeRecoveredTerminalSync => 6,
    }
}
#[test]
fn retirement_sigkill_child() {
    use trnm_consensus_external_watermark::ExternalWatermarkAuthority;
    let Ok(root) = env::var("TRNM_RETIREMENT_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let cut: usize = env::var("TRNM_RETIREMENT_CRASH_CUT")
        .unwrap()
        .parse()
        .unwrap();
    let mut authority =
        ExternalWatermarkAuthority::open_semantic(root.join("authority.log"), semantic_binding())
            .unwrap();
    let source = mark(0, 53);
    authority
        .compare_and_advance_semantic(None, source, semantic_facts(7, 0, 1, 11, 12))
        .unwrap();
    let record = retirement_policy_fixture(source, 1);
    authority
        .retire_signer_with_observer_v1(semantic_binding(), record, |actual| {
            if retirement_cut_index(actual) == cut {
                let mut ready = fs::File::create(root.join("cut.ready"))?;
                ready.write_all(b"at-cut")?;
                ready.sync_all()?;
                loop {
                    thread::sleep(Duration::from_millis(10));
                }
            }
            Ok(())
        })
        .unwrap();
    panic!("requested retirement crash cut was not reached");
}
// A test-owned child is always reaped, including assertion/panic paths. This
// changes no production lock behavior and does not turn failed opens into retries.
struct RetirementTestChild(Child);

impl Drop for RetirementTestChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn retirement_recovery_child() {
    use trnm_consensus_external_watermark::ExternalWatermarkAuthority;
    let Ok(root) = env::var("TRNM_RETIREMENT_RECOVERY_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let cut: usize = env::var("TRNM_RETIREMENT_CRASH_CUT")
        .unwrap()
        .parse()
        .unwrap();
    assert!(cut < 6);
    let mut authority =
        ExternalWatermarkAuthority::open_semantic(root.join("authority.log"), semantic_binding())
            .unwrap();
    let source = mark(0, 53);
    let record = retirement_policy_fixture(source, 1);
    if cut >= 2 {
        assert!(authority
            .compare_and_advance_semantic(
                Some(source),
                mark(1, 54),
                semantic_facts(7, 1, 2, 13, 14)
            )
            .is_err());
    }
    if (2..4).contains(&cut) {
        assert!(authority
            .load_signer_retirement_v1(semantic_binding())
            .is_err());
    }
    assert_eq!(
        authority
            .retire_signer_exact_v1(semantic_binding(), record)
            .unwrap(),
        record.terminal_watermark_v1()
    );
    assert_eq!(
        authority
            .load_signer_retirement_v1(semantic_binding())
            .unwrap(),
        Some(record)
    );
    drop(authority);
    let mut reopened =
        ExternalWatermarkAuthority::open_semantic(root.join("authority.log"), semantic_binding())
            .unwrap();
    assert_eq!(
        reopened
            .load_signer_retirement_v1(semantic_binding())
            .unwrap(),
        Some(record)
    );
    assert!(reopened
        .compare_and_advance_semantic(Some(source), mark(1, 54), semantic_facts(7, 1, 2, 13, 14))
        .is_err());
}

#[test]
fn retirement_sigkill_six_cuts_recover_exactly_and_never_revive_after_mode_cut() {
    use std::os::unix::process::ExitStatusExt;
    for cut in 0..6 {
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = RetirementTestChild(
            Command::new(env::current_exe().unwrap())
                .args(["--exact", "retirement_sigkill_child", "--nocapture"])
                .env("TRNM_RETIREMENT_CRASH_ROOT", root.path())
                .env("TRNM_RETIREMENT_CRASH_CUT", cut.to_string())
                .spawn()
                .unwrap(),
        );
        for _ in 0..500 {
            if root.path().join("cut.ready").exists() {
                break;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before cut {cut}"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(root.path().join("cut.ready").exists(), "cut {cut} deadline");
        child.0.kill().unwrap();
        assert_eq!(child.0.wait().unwrap().signal(), Some(9));

        // Keep *all* namespace owners out of this multithreaded parent.
        // Parallel tests may fork another daemon while an in-process owner
        // exists. O_CLOEXEC closes its inherited flock only at exec, so a
        // parent drop/immediate reopen can otherwise see EWOULDBLOCK even
        // after the deliberately killed child has been reaped. This exact
        // recovery child spawns no descendants and still uses fail-fast
        // production opens for both recovery and the second cold reopen.
        let mut recovery = RetirementTestChild(
            Command::new(env::current_exe().unwrap())
                .args(["--exact", "retirement_recovery_child", "--nocapture"])
                .env("TRNM_RETIREMENT_RECOVERY_ROOT", root.path())
                .env("TRNM_RETIREMENT_CRASH_CUT", cut.to_string())
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = recovery.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "recovery failed after SIGKILL cut {cut}: {status}"
                );
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "recovery child deadline after SIGKILL cut {cut}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn retirement_recovered_confirmation_sync_failure_impl(root: &Path) {
    use trnm_consensus_external_watermark::{
        ExternalWatermarkAuthority, SignerRetirementAuthorityCutV1,
    };
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("authority.log");
    let mut authority =
        ExternalWatermarkAuthority::open_semantic(&path, semantic_binding()).unwrap();
    let source = mark(0, 53);
    authority
        .compare_and_advance_semantic(None, source, semantic_facts(7, 0, 1, 11, 12))
        .unwrap();
    let record = retirement_policy_fixture(source, 1);
    authority
        .retire_signer_exact_v1(semantic_binding(), record)
        .unwrap();
    drop(authority);
    let mut reopened =
        ExternalWatermarkAuthority::open_semantic(&path, semantic_binding()).unwrap();
    let mut barrier_called = false;
    assert!(reopened
        .retire_signer_with_observer_v1(semantic_binding(), record, |cut| {
            if cut == SignerRetirementAuthorityCutV1::BeforeRecoveredTerminalSync {
                barrier_called = true;
                Err(std::io::Error::other(
                    "injected failure before recovered sync",
                ))
            } else {
                Ok(())
            }
        })
        .is_err());
    assert!(barrier_called);
    assert!(reopened
        .load_signer_retirement_v1(semantic_binding())
        .is_err());
    drop(reopened);
    let mut reopened =
        ExternalWatermarkAuthority::open_semantic(&path, semantic_binding()).unwrap();
    assert_eq!(
        reopened
            .retire_signer_exact_v1(semantic_binding(), record)
            .unwrap(),
        record.terminal_watermark_v1()
    );
}

#[test]
fn retirement_recovered_confirmation_sync_failure_child() {
    let Ok(raw_root) = env::var("TRNM_RECOVERED_CONFIRMATION_ROOT") else {
        return;
    };
    retirement_recovered_confirmation_sync_failure_impl(Path::new(&raw_root));
}

#[test]
fn retirement_recovered_confirmation_sync_failure_never_acknowledges() {
    let root = tempdir().unwrap();
    let mut child = RetirementTestChild(
        Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "retirement_recovered_confirmation_sync_failure_child",
                "--nocapture",
            ])
            .env("TRNM_RECOVERED_CONFIRMATION_ROOT", root.path())
            .spawn()
            .unwrap(),
    );
    let status = child.0.wait().unwrap();
    assert!(status.success(), "isolated recovery test failed: {status}");
}

#[test]
fn authority_startup_rejects_oversized_and_symlink_fixed_anchors() {
    use std::os::unix::fs::symlink;
    use trnm_consensus_external_watermark::ExternalWatermarkAuthority;
    for name in [".authority.log.head-v1", ".authority.log.semantic-head-v1"] {
        let root = tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("authority.log");
        drop(ExternalWatermarkAuthority::open_semantic(&path, semantic_binding()).unwrap());
        let anchor = root.path().join(name);
        let original = fs::read(&anchor).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&anchor)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();
        assert!(ExternalWatermarkAuthority::open_semantic(&path, semantic_binding()).is_err());
        fs::remove_file(&anchor).unwrap();
        let target = root.path().join("untrusted-anchor");
        fs::write(&target, &original).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &anchor).unwrap();
        assert!(ExternalWatermarkAuthority::open_semantic(&path, semantic_binding()).is_err());
    }
}
