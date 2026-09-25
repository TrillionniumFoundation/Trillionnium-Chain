#![cfg(feature = "test-fixture")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command},
    thread,
    time::Duration,
};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use trnm_consensus_types::ValidatorId;
use trnm_consensus_unix_fleet_signer::{
    test_fixture::{fixture_public_key_v1, FixtureModeV1},
    DurableFleetRootSignerAuthorityV1, FleetRootAuthorityErrorV1, FleetRootAuthoritySignerV1,
    FleetRootPurposeV1, FleetRootRequestV1, UnixFleetRootAuthorityServerV1,
    UnixFleetRootSignerConfig, UnixFleetRootSignerProducerV1, UnixFleetSignerErrorV1,
};

fn origin() -> ValidatorId {
    ValidatorId::from_bytes(b"fleet-fixture-validator").expect("bounded origin")
}

fn config(socket: &Path) -> UnixFleetRootSignerConfig {
    config_with(socket, origin(), [0x31; 32])
}

fn config_with(
    socket: &Path,
    request_origin: ValidatorId,
    validator_set_id: [u8; 32],
) -> UnixFleetRootSignerConfig {
    UnixFleetRootSignerConfig {
        socket_path: socket.to_path_buf(),
        origin: request_origin,
        validator_set_id,
        verifying_key: fixture_public_key_v1(),
        timeout: Duration::from_secs(2),
    }
}

fn spawn_fixture(dir: &TempDir, mode: FixtureModeV1, count: usize) -> (Child, std::path::PathBuf) {
    let socket = dir.path().join("fleet-root.sock");
    let binary = env!("CARGO_BIN_EXE_trnm-fleet-root-signer-test-fixture");
    let child = Command::new(binary)
        .arg(&socket)
        .arg(match mode {
            FixtureModeV1::Valid => "valid",
            FixtureModeV1::ReplayFirst => "replay-first",
            FixtureModeV1::MutatedResponse => "mutated-response",
            FixtureModeV1::InvalidSignature => "invalid-signature",
            FixtureModeV1::TruncatedResponse => "truncated-response",
            FixtureModeV1::OversizedResponse => "oversized-response",
            FixtureModeV1::ZeroLengthResponse => "zero-length-response",
        })
        .arg(count.to_string())
        .spawn()
        .expect("spawn fleet fixture");
    wait_for_socket(&socket);
    (child, socket)
}

fn wait_for_socket(socket: &Path) {
    for _ in 0..200 {
        if socket.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("fixture did not create socket: {}", socket.display());
}

fn spawn_authority(dir: &TempDir, count: usize) -> (Child, std::path::PathBuf, std::path::PathBuf) {
    let socket = dir.path().join("fleet-root-authority.sock");
    let log = dir.path().join("fleet-root-authority.log");
    let binary = env!("CARGO_BIN_EXE_trnm-fleet-root-signer-authority-fixture");
    let mut child = Command::new(binary)
        .arg(&socket)
        .arg(&log)
        .arg(count.to_string())
        .spawn()
        .expect("spawn durable fleet authority fixture");
    for _ in 0..400 {
        if socket.exists() {
            return (child, socket, log);
        }
        if let Some(status) = child.try_wait().expect("poll durable fixture") {
            panic!("durable fixture exited before socket: {status}");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!(
        "durable fixture did not create socket: {}",
        socket.display()
    );
}

fn assert_authority_start_fails(socket: &Path, log: &Path) {
    let binary = env!("CARGO_BIN_EXE_trnm-fleet-root-signer-authority-fixture");
    let mut child = Command::new(binary)
        .arg(socket)
        .arg(log)
        .arg("1")
        .spawn()
        .expect("spawn tampered durable authority fixture");
    for _ in 0..400 {
        if let Some(status) = child.try_wait().expect("poll tampered fixture") {
            assert!(!status.success(), "tampered authority unexpectedly started");
            assert!(!socket.exists(), "tampered authority exposed a socket");
            return;
        }
        assert!(!socket.exists(), "tampered authority exposed a socket");
        thread::sleep(Duration::from_millis(5));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("tampered authority stayed alive");
}

fn authority_request(
    producer: &mut UnixFleetRootSignerProducerV1,
    purpose: FleetRootPurposeV1,
    root: u8,
    nonce: u8,
) -> Result<[u8; 64], UnixFleetSignerErrorV1> {
    producer.sign_fleet_root_v1(purpose, [root; 32], [nonce; 32])
}

struct GenericAuthoritySignerV1 {
    key: SigningKey,
}

impl FleetRootAuthoritySignerV1 for GenericAuthoritySignerV1 {
    fn sign_fleet_root_authority_v1(
        &mut self,
        request: &trnm_consensus_unix_fleet_signer::FleetRootRequestV1,
    ) -> Result<[u8; 64], FleetRootAuthorityErrorV1> {
        Ok(self.key.sign(&request.signing_root()).to_bytes())
    }
}

struct FailingAuthoritySignerV1;

impl FleetRootAuthoritySignerV1 for FailingAuthoritySignerV1 {
    fn sign_fleet_root_authority_v1(
        &mut self,
        _request: &FleetRootRequestV1,
    ) -> Result<[u8; 64], FleetRootAuthorityErrorV1> {
        Err(FleetRootAuthorityErrorV1::Conflict(
            "synthetic signer failure after preparation",
        ))
    }
}

#[test]
fn generic_authority_server_routes_durable_exact_replay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("generic-authority.sock");
    let log = dir.path().join("generic-authority.log");
    let origin = origin();
    let validator_set_id = [0x31; 32];
    let key = SigningKey::from_bytes(&[0x4a; 32]);
    let authority = DurableFleetRootSignerAuthorityV1::open(
        &log,
        origin,
        validator_set_id,
        key.verifying_key().to_bytes(),
        GenericAuthoritySignerV1 { key: key.clone() },
    )
    .expect("open generic durable authority");
    let mut server = UnixFleetRootAuthorityServerV1::new(authority, &socket)
        .expect("construct generic authority server");
    let join = std::thread::spawn(move || {
        let result = server.serve_n(2);
        (result, server)
    });
    wait_for_socket(&socket);
    let mut producer = UnixFleetRootSignerProducerV1::new(UnixFleetRootSignerConfig {
        socket_path: socket.clone(),
        origin,
        validator_set_id,
        verifying_key: key.verifying_key().to_bytes(),
        timeout: Duration::from_secs(2),
    })
    .expect("construct generic authority client");
    let first = producer
        .sign_fleet_root_v1(FleetRootPurposeV1::Ready, [0x91; 32], [0xa1; 32])
        .expect("first generic authority signature");
    let replay = producer
        .sign_fleet_root_v1(FleetRootPurposeV1::Ready, [0x91; 32], [0xa1; 32])
        .expect("exact generic authority replay");
    assert_eq!(first, replay);
    let (result, server) = join.join().expect("generic authority server join");
    result.expect("generic authority server success");
    assert_eq!(server.authority().sequence(), 1);
    assert!(!socket.exists());
}

#[test]
fn subprocess_exact_replay_returns_identical_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket) = spawn_fixture(&dir, FixtureModeV1::Valid, 2);
    let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    let first = producer
        .sign_fleet_root_v1(FleetRootPurposeV1::Ready, [0x90; 32], [1; 32])
        .expect("first signature");
    let replay = producer
        .sign_fleet_root_v1(FleetRootPurposeV1::Ready, [0x90; 32], [1; 32])
        .expect("exact replay");
    assert_eq!(first, replay);
    assert!(child.wait().expect("fixture wait").success());
}

#[test]
fn conflicting_nonce_is_rejected_before_signature_escape() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket) = spawn_fixture(&dir, FixtureModeV1::Valid, 2);
    let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    producer
        .sign_fleet_root_v1(FleetRootPurposeV1::Start, [0xa0; 32], [2; 32])
        .expect("first signature");
    let error = producer
        .sign_fleet_root_v1(FleetRootPurposeV1::Start, [0xa1; 32], [2; 32])
        .expect_err("nonce conflict must reject");
    assert!(matches!(error, UnixFleetSignerErrorV1::Protocol(_)));
    assert!(child.wait().expect("fixture wait").success());
}

#[test]
fn binding_mutation_and_bad_signature_fail_closed() {
    for (mode, root, nonce) in [
        (FixtureModeV1::MutatedResponse, [0xc0; 32], [4; 32]),
        (FixtureModeV1::InvalidSignature, [0xd0; 32], [5; 32]),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut child, socket) = spawn_fixture(&dir, mode, 1);
        let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
        let error = producer
            .sign_fleet_root_v1(FleetRootPurposeV1::Relay, root, nonce)
            .expect_err("fixture mutation must fail closed");
        assert!(matches!(error, UnixFleetSignerErrorV1::Protocol(_)));
        assert!(child.wait().expect("fixture wait").success());
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket) = spawn_fixture(&dir, FixtureModeV1::ReplayFirst, 2);
    let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    producer
        .sign_fleet_root_v1(FleetRootPurposeV1::Relay, [0xb0; 32], [3; 32])
        .expect("first response");
    let error = producer
        .sign_fleet_root_v1(FleetRootPurposeV1::Relay, [0xb1; 32], [6; 32])
        .expect_err("wrong replay response must fail closed");
    assert!(matches!(error, UnixFleetSignerErrorV1::Protocol(_)));
    assert!(child.wait().expect("fixture wait").success());
}

#[test]
fn socket_and_frame_boundaries_are_private_and_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket) = spawn_fixture(&dir, FixtureModeV1::Valid, 1);
    let mut permissions = fs::metadata(&socket)
        .expect("socket metadata")
        .permissions();
    permissions.set_mode(0o660);
    fs::set_permissions(&socket, permissions).expect("relax fixture socket");
    let producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    assert!(matches!(
        producer.preflight(),
        Err(UnixFleetSignerErrorV1::SocketNotPrivate)
    ));
    child.kill().expect("stop fixture");
    let _ = child.wait();
}

#[test]
fn durable_authority_exact_replay_does_not_append_or_resign() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket, log) = spawn_authority(&dir, 2);
    let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    let first = authority_request(&mut producer, FleetRootPurposeV1::Ready, 0x91, 0x11)
        .expect("first durable signature");
    let first_len = fs::metadata(&log).expect("authority log metadata").len();
    let pending = log.parent().expect("log parent").join(format!(
        ".{}.pending",
        log.file_name().unwrap().to_string_lossy()
    ));
    assert!(
        !pending.exists(),
        "successful append must retire preparation marker"
    );
    let replay = authority_request(&mut producer, FleetRootPurposeV1::Ready, 0x91, 0x11)
        .expect("exact durable replay");
    assert_eq!(
        first, replay,
        "replay must return persisted signature bytes"
    );
    assert_eq!(
        fs::metadata(&log).expect("authority log metadata").len(),
        first_len,
        "exact replay must not append a second authority record"
    );
    assert!(
        !pending.exists(),
        "exact replay must not recreate preparation marker"
    );
    assert!(child.wait().expect("authority wait").success());
}

#[test]
fn durable_authority_prepares_before_signer_and_reopens_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("prepared-authority.log");
    let authority = DurableFleetRootSignerAuthorityV1::open(
        &log,
        origin(),
        [0x31; 32],
        fixture_public_key_v1(),
        FailingAuthoritySignerV1,
    )
    .expect("open failing authority");
    let request = FleetRootRequestV1::new(
        FleetRootPurposeV1::Ready,
        origin(),
        [0x31; 32],
        [0xd1; 32],
        [0xe1; 32],
    )
    .expect("request");
    let mut authority = authority;
    let error = authority
        .sign_fleet_root_v1(&request)
        .expect_err("synthetic signer must fail after preparation");
    assert!(matches!(
        error,
        FleetRootAuthorityErrorV1::Conflict("synthetic signer failure after preparation")
    ));
    let pending = log.parent().expect("log parent").join(format!(
        ".{}.pending",
        log.file_name().unwrap().to_string_lossy()
    ));
    assert!(
        pending.is_file(),
        "prepared marker must survive signer failure"
    );
    drop(authority);

    let reopened = DurableFleetRootSignerAuthorityV1::open(
        &log,
        origin(),
        [0x31; 32],
        fixture_public_key_v1(),
        GenericAuthoritySignerV1 {
            key: SigningKey::from_bytes(&[0x4a; 32]),
        },
    );
    assert!(
        matches!(
            &reopened,
            Err(FleetRootAuthorityErrorV1::InvalidLog(
                "unresolved prepared signing intent"
            ))
        ),
        "unresolved prepared intent must fence reopen, observed error: {:?}",
        reopened.as_ref().err()
    );
}

#[test]
fn durable_authority_survives_sigkill_and_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket, log) = spawn_authority(&dir, 1);
    let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    let first = authority_request(&mut producer, FleetRootPurposeV1::Ready, 0x92, 0x21)
        .expect("first durable signature");
    child.kill().expect("kill authority");
    let _ = child.wait();

    let (mut reopened, socket, _) = spawn_authority(&dir, 1);
    let mut replay_producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    let replay = authority_request(&mut replay_producer, FleetRootPurposeV1::Ready, 0x92, 0x21)
        .expect("replayed signature after reopen");
    assert_eq!(first, replay);
    assert!(reopened.wait().expect("reopen wait").success());

    let (mut next, socket, _) = spawn_authority(&dir, 1);
    let mut next_producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    authority_request(&mut next_producer, FleetRootPurposeV1::Start, 0x93, 0x22)
        .expect("new post-reopen signature");
    assert!(next.wait().expect("next wait").success());
    assert!(fs::metadata(log).expect("log remains").len() > 0);
}

#[test]
fn durable_authority_conflicting_nonce_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket, _) = spawn_authority(&dir, 2);
    let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    authority_request(&mut producer, FleetRootPurposeV1::Start, 0xa0, 0x31)
        .expect("first durable signature");
    let error = authority_request(&mut producer, FleetRootPurposeV1::Start, 0xa1, 0x31)
        .expect_err("conflicting nonce must reject");
    assert!(matches!(
        error,
        UnixFleetSignerErrorV1::Protocol(
            trnm_consensus_unix_fleet_signer::FleetSignerProtocolErrorV1::Rejected(9)
        )
    ));
    assert!(child.wait().expect("authority wait").success());
}

#[test]
fn durable_authority_origin_and_set_bindings_are_immutable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket, _) = spawn_authority(&dir, 3);
    let mut good = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    authority_request(&mut good, FleetRootPurposeV1::Ready, 0xa2, 0x32).expect("bound request");

    let other_origin = ValidatorId::from_bytes(b"other-fleet-validator").expect("origin");
    let mut wrong_origin =
        UnixFleetRootSignerProducerV1::new(config_with(&socket, other_origin, [0x31; 32]))
            .expect("wrong-origin client");
    let origin_error = authority_request(&mut wrong_origin, FleetRootPurposeV1::Ready, 0xa3, 0x33)
        .expect_err("wrong origin must reject");
    assert!(matches!(
        origin_error,
        UnixFleetSignerErrorV1::Protocol(
            trnm_consensus_unix_fleet_signer::FleetSignerProtocolErrorV1::Rejected(7)
        )
    ));

    let mut wrong_set =
        UnixFleetRootSignerProducerV1::new(config_with(&socket, origin(), [0x32; 32]))
            .expect("wrong-set client");
    let set_error = authority_request(&mut wrong_set, FleetRootPurposeV1::Ready, 0xa4, 0x34)
        .expect_err("wrong validator set must reject");
    assert!(matches!(
        set_error,
        UnixFleetSignerErrorV1::Protocol(
            trnm_consensus_unix_fleet_signer::FleetSignerProtocolErrorV1::Rejected(7)
        )
    ));
    assert!(child.wait().expect("authority wait").success());
}

#[test]
fn durable_authority_rejects_log_anchor_and_tail_tamper_before_bind() {
    // A changed record must fail before the fixture creates a socket.
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket, log) = spawn_authority(&dir, 1);
    let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    authority_request(&mut producer, FleetRootPurposeV1::Ready, 0xb0, 0x41)
        .expect("seed authority log");
    assert!(child.wait().expect("authority wait").success());
    let mut bytes = fs::read(&log).expect("read authority log");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&log, bytes).expect("tamper authority log");
    assert_authority_start_fails(&socket, &log);

    // An anchor mismatch is independently rejected.
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket, log) = spawn_authority(&dir, 1);
    let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    authority_request(&mut producer, FleetRootPurposeV1::Ready, 0xb1, 0x42)
        .expect("seed authority anchor");
    assert!(child.wait().expect("authority wait").success());
    let anchor = log.parent().expect("log parent").join(format!(
        ".{}.anchor",
        log.file_name().unwrap().to_string_lossy()
    ));
    let mut anchor_bytes = fs::read(&anchor).expect("read authority anchor");
    let last = anchor_bytes.len() - 1;
    anchor_bytes[last] ^= 1;
    fs::write(&anchor, anchor_bytes).expect("tamper authority anchor");
    assert_authority_start_fails(&socket, &log);

    // A partial record tail is not recoverable and must fail closed.
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut child, socket, log) = spawn_authority(&dir, 1);
    let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    authority_request(&mut producer, FleetRootPurposeV1::Ready, 0xb2, 0x43)
        .expect("seed authority tail");
    assert!(child.wait().expect("authority wait").success());
    let length = fs::metadata(&log).expect("authority log metadata").len();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&log)
        .expect("open authority log for truncation");
    file.set_len(length - 1).expect("truncate authority log");
    assert_authority_start_fails(&socket, &log);
}

#[test]
fn durable_authority_namespace_lock_is_private_and_exclusive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut first, socket, log) = spawn_authority(&dir, 1);
    let binary = env!("CARGO_BIN_EXE_trnm-fleet-root-signer-authority-fixture");
    let mut second = Command::new(binary)
        .arg(&socket)
        .arg(&log)
        .arg("1")
        .spawn()
        .expect("spawn second authority");
    let status = second.wait().expect("second authority wait");
    assert!(
        !status.success(),
        "second authority acquired namespace lock"
    );
    let mut producer = UnixFleetRootSignerProducerV1::new(config(&socket)).expect("client");
    authority_request(&mut producer, FleetRootPurposeV1::Ready, 0xc1, 0x51)
        .expect("first authority remains available");
    assert!(first.wait().expect("first authority wait").success());

    // A pre-existing lock with a broad mode is rejected before locking.
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("fleet-root-authority.log");
    let lock = dir.path().join(".fleet-root-authority.log.lock");
    fs::write(&lock, []).expect("create broad lock");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o640)).expect("broaden lock");
    let socket = dir.path().join("fleet-root-authority.sock");
    assert_authority_start_fails(&socket, &log);
}

fn fragmented_response_has_one_deadline(fragment_header: bool) {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixListener,
        time::Instant,
    };
    let dir = tempfile::tempdir().expect("deadline tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("deadline.sock");
    let listener = UnixListener::bind(&socket).expect("bind deadline peer");
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let accept_deadline = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < accept_deadline, "client never connected");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut header = [0; 4];
        stream.read_exact(&mut header).expect("request header");
        let mut body = vec![0; u32::from_be_bytes(header) as usize];
        stream.read_exact(&mut body).expect("request body");
        FleetRootRequestV1::decode_exact(&body).expect("real exact request");
        // Each 80ms fragment fits the 120ms per-syscall timeout, but the
        // full frame exceeds the caller's one operation deadline.
        let header = 2u32.to_be_bytes();
        if !fragment_header {
            stream.write_all(&header).unwrap();
        }
        let fragments: &[u8] = if fragment_header { &header } else { &[1, 7] };
        for byte in fragments {
            thread::sleep(Duration::from_millis(80));
            if stream.write_all(&[*byte]).is_err() {
                return;
            }
        }
        if fragment_header {
            let _ = stream.write_all(&[1, 7]);
        }
    });
    let mut settings = config(&socket);
    settings.timeout = Duration::from_millis(120);
    let mut client = UnixFleetRootSignerProducerV1::new(settings).unwrap();
    let start = Instant::now();
    let result = authority_request(&mut client, FleetRootPurposeV1::Ready, 0x91, 0x71);
    let elapsed = start.elapsed();
    server.join().expect("bounded peer finished");
    assert!(
        matches!(&result, Err(UnixFleetSignerErrorV1::Io { source, .. })
        if source.kind() == std::io::ErrorKind::TimedOut),
        "operation deadline was renewed: elapsed={elapsed:?}, result={result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "deadline response must stay bounded"
    );
}

#[test]
fn fragmented_header_cannot_renew_client_deadline() {
    fragmented_response_has_one_deadline(true);
}

#[test]
fn fragmented_body_cannot_renew_client_deadline() {
    fragmented_response_has_one_deadline(false);
}

#[cfg(target_os = "linux")]
#[test]
fn full_listener_backlog_cannot_block_public_client() {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    use std::{os::unix::net::UnixListener, time::Instant};
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("full.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    rustix::net::listen(&listener, 1).unwrap();
    let address = SocketAddrUnix::new(&path).unwrap();
    let mut queued = Vec::new();
    let mut full = false;
    for _ in 0..8 {
        let fd = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        match rustix::net::connect(&fd, &address) {
            Ok(()) => queued.push(fd),
            Err(rustix::io::Errno::AGAIN) => {
                full = true;
                break;
            }
            Err(error) => panic!("unexpected backlog error: {error}"),
        }
    }
    assert!(full, "test must actually exhaust the accept queue");
    let mut settings = config(&path);
    settings.timeout = Duration::from_millis(120);
    let mut client = UnixFleetRootSignerProducerV1::new(settings).unwrap();
    let start = Instant::now();
    let result = authority_request(&mut client, FleetRootPurposeV1::Ready, 0x92, 0x72);
    assert!(
        matches!(&result, Err(UnixFleetSignerErrorV1::Io { stage: "connect", source })
        if source.kind() == std::io::ErrorKind::TimedOut),
        "{result:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    // The timeout must not establish a false connection or send a request.
    listener.set_nonblocking(true).unwrap();
    for _ in 0..queued.len() {
        let _ = listener.accept().unwrap();
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
