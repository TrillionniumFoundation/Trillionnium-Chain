//! OS-process crash/restart evidence for the timeout pending-reservation seam.
//!
//! The helper process reserves an exact timeout request and then waits.  The
//! parent kills it with SIGKILL before the response is bound, reopens the
//! adapter in a different process, and completes the exact retry.  A second
//! namespace proves that mutating the pending sidecar is a startup
//! fail-stop.  This is fixture-only evidence; it does not claim Core,
//! SafetyRules, HSM, or production signer authority.

use std::{
    env, fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::Duration,
};

use ed25519_dalek::Signer;
use tempfile::TempDir;
use trnm_consensus_external_watermark::{
    run_per_reservation_daemon, ExternalWatermarkSemanticBindingV1,
};
use trnm_consensus_remote_signer_service::{
    fixture_request, fixture_service_config, ExternalAuthorityAdapterV1, Fixture, PurposePolicyV1,
    RemoteSignerService, UnixExternalTimeoutAuthorityV1,
};

const CAPABILITY: [u8; 32] = [0x33; 32];
const HELPER_MODE: &str = "TRNM_PENDING_RESERVATION_HELPER_MODE";
const HELPER_AUTHORITY_SOCKET: &str = "TRNM_PENDING_RESERVATION_AUTHORITY_SOCKET";
const HELPER_RESPONSE_LOG: &str = "TRNM_PENDING_RESERVATION_RESPONSE_LOG";
const HELPER_MARKER: &str = "TRNM_PENDING_RESERVATION_MARKER";

const FRAME_OK: u8 = 0;
const AUTHORITY_CHILD_ENV: &str = "TRNM_PENDING_RESERVATION_AUTHORITY_CHILD";
const AUTHORITY_LOG_ENV: &str = "TRNM_PENDING_RESERVATION_AUTHORITY_LOG";
const AUTHORITY_SCOPE_ENV: &str = "TRNM_PENDING_RESERVATION_AUTHORITY_SCOPE";
const AUTHORITY_JOURNAL_ENV: &str = "TRNM_PENDING_RESERVATION_AUTHORITY_JOURNAL";
const AUTHORITY_CAPABILITY_ENV: &str = "TRNM_PENDING_RESERVATION_AUTHORITY_CAPABILITY";

fn authority_command(
    socket: &Path,
    log: &Path,
    binding: trnm_consensus_remote_signer_protocol::RemoteSignerRequestBindingV1,
) -> Command {
    let scope = UnixExternalTimeoutAuthorityV1::scope_for_binding(binding);
    let journal = UnixExternalTimeoutAuthorityV1::journal_id_for_binding(binding);
    let mut command =
        Command::new(env::current_exe().expect("resolve pending reservation OS test executable"));
    command
        .args([
            "--exact",
            "pending_reservation_authority_child",
            "--nocapture",
        ])
        .env(AUTHORITY_CHILD_ENV, "1")
        .env(HELPER_AUTHORITY_SOCKET, socket)
        .env(AUTHORITY_LOG_ENV, log)
        .env(AUTHORITY_SCOPE_ENV, hex32(scope))
        .env(AUTHORITY_JOURNAL_ENV, hex32(journal))
        .env(AUTHORITY_CAPABILITY_ENV, hex32(CAPABILITY));
    command
}

fn signer_command(
    socket: &Path,
    watermark: &Path,
    authority_socket: &Path,
    response_log: &Path,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-remote-signer-p0"));
    command
        .arg("serve-external-timeout")
        .arg("--socket")
        .arg(socket)
        .arg("--watermark")
        .arg(watermark)
        .arg("--authority-socket")
        .arg(authority_socket)
        .arg("--response-log")
        .arg(response_log)
        .arg("--capability")
        .arg(hex32(CAPABILITY));
    command
}

fn hex32(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct AuthorityOnly {
    child: Child,
    socket: PathBuf,
}

impl AuthorityOnly {
    fn start(root: &Path) -> Self {
        let fixture = Fixture::new();
        let socket = root.join("authority.sock");
        let log = root.join("authority.log");
        let child = authority_command(&socket, &log, fixture.binding)
            .spawn()
            .expect("spawn external watermark authority child process");
        wait_socket(&socket);
        Self { child, socket }
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_socket(path: &Path) {
    for _ in 0..500 {
        if path.exists() && UnixStream::connect(path).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for socket {}", path.display());
}

fn timeout_request_and_facts(
    root: &Path,
) -> (
    Fixture,
    Vec<u8>,
    trnm_consensus_remote_signer_service::ExternalAuthorityRequestV1,
) {
    let fixture = Fixture::new();
    let request = fixture_request(&fixture, "timeout", 3, b"os-pending-crash")
        .expect("construct timeout request");
    let request_bytes = request.try_exact_bytes().expect("encode timeout request");
    let service = RemoteSignerService::open(fixture_service_config(
        &root.join("facts.sqlite3"),
        PurposePolicyV1::timeout_vote_only(),
    ))
    .expect("open facts-only fixture service");
    let facts = service
        .external_authority_request_v1(&request_bytes)
        .expect("derive external timeout facts");
    (fixture, request_bytes, facts)
}

fn spawn_pending_helper(
    mode: &str,
    authority_socket: &Path,
    response_log: &Path,
    marker: Option<&Path>,
) -> Child {
    let mut command = Command::new(env::current_exe().expect("current test executable"));
    command
        .args(["--exact", "pending_reservation_os_helper", "--nocapture"])
        .env(HELPER_MODE, mode)
        .env(HELPER_AUTHORITY_SOCKET, authority_socket)
        .env(HELPER_RESPONSE_LOG, response_log);
    if let Some(marker) = marker {
        command.env(HELPER_MARKER, marker);
    } else {
        command.env_remove(HELPER_MARKER);
    }
    command.spawn().expect("spawn pending reservation helper")
}

fn wait_for_marker(path: &Path) {
    for _ in 0..500 {
        if path.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for helper reservation marker");
}

fn signer_request(socket: &Path, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).expect("connect remote signer");
    stream
        .write_all(&(request.len() as u32).to_be_bytes())
        .expect("write signer request length");
    stream.write_all(request).expect("write signer request");
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .expect("read signer response length");
    let mut response = vec![0_u8; u32::from_be_bytes(length) as usize];
    stream
        .read_exact(&mut response)
        .expect("read signer response");
    response
}

fn authority_env_path(name: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("missing authority child environment variable {name}"))
}

fn authority_env_hex32(name: &str) -> [u8; 32] {
    let value = env::var(name)
        .unwrap_or_else(|_| panic!("missing authority child environment variable {name}"));
    assert_eq!(value.len(), 64, "{name} must contain exactly 32 bytes");
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("{name} must contain canonical hexadecimal"));
    }
    assert_ne!(output, [0_u8; 32], "{name} must not be the zero identifier");
    output
}

#[test]
fn pending_reservation_authority_child() {
    if env::var_os(AUTHORITY_CHILD_ENV).is_none() {
        return;
    }
    let binding = ExternalWatermarkSemanticBindingV1::new(
        authority_env_hex32(AUTHORITY_SCOPE_ENV),
        authority_env_hex32(AUTHORITY_JOURNAL_ENV),
        authority_env_hex32(AUTHORITY_CAPABILITY_ENV),
    )
    .expect("pending authority child semantic binding");
    run_per_reservation_daemon(
        authority_env_path(HELPER_AUTHORITY_SOCKET),
        authority_env_path(AUTHORITY_LOG_ENV),
        binding,
    )
    .expect("pending authority child must fail closed on invalid durable state");
}

#[test]
fn pending_reservation_os_helper() {
    let Some(mode) = env::var_os(HELPER_MODE) else {
        return;
    };
    let authority_socket = PathBuf::from(
        env::var_os(HELPER_AUTHORITY_SOCKET).expect("helper authority socket environment"),
    );
    let response_log =
        PathBuf::from(env::var_os(HELPER_RESPONSE_LOG).expect("helper response log environment"));
    let root = response_log.parent().expect("helper response root");
    match mode.to_str().expect("helper mode") {
        "reserve" => {
            let fixture = Fixture::new();
            let request = fixture_request(&fixture, "timeout", 3, b"os-pending-crash")
                .expect("construct helper timeout request");
            let request_bytes = request
                .try_exact_bytes()
                .expect("encode helper timeout request");
            let service = RemoteSignerService::open(fixture_service_config(
                &root.join("helper-facts.sqlite3"),
                PurposePolicyV1::timeout_vote_only(),
            ))
            .expect("open helper facts service");
            let facts = service
                .external_authority_request_v1(&request_bytes)
                .expect("derive helper timeout facts");
            let mut adapter = UnixExternalTimeoutAuthorityV1::from_binding_per_reservation(
                fixture.binding,
                &authority_socket,
                &response_log,
            )
            .expect("open helper external adapter")
            .with_capability(CAPABILITY);
            let reservation = adapter.reserve_v1(facts).expect("reserve pending timeout");
            let marker =
                PathBuf::from(env::var_os(HELPER_MARKER).expect("helper marker environment"));
            fs::write(marker, reservation.sequence().to_be_bytes()).expect("write helper marker");
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        "reopen-tampered" => {
            let fixture = Fixture::new();
            let reopened = UnixExternalTimeoutAuthorityV1::from_binding_per_reservation(
                fixture.binding,
                &authority_socket,
                &response_log,
            );
            assert!(
                reopened.is_err(),
                "tampered pending sidecar must fail closed on OS reopen"
            );
        }
        other => panic!("unknown pending helper mode {other}"),
    }
}

#[test]
fn pending_reservation_os_crash_retry_and_sidecar_tamper_fail_stop() {
    let root = TempDir::new().expect("temporary pending reservation root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("private pending root");
    let mut authority = AuthorityOnly::start(root.path());
    let response_log = root.path().join("responses.log");
    let marker = root.path().join("reserved.marker");
    let mut crashed =
        spawn_pending_helper("reserve", &authority.socket, &response_log, Some(&marker));
    wait_for_marker(&marker);
    crashed.kill().expect("SIGKILL pending helper");
    let status = crashed.wait().expect("wait killed pending helper");
    assert!(
        !status.success(),
        "helper must be killed before response bind"
    );

    let (fixture, request_bytes, facts) = timeout_request_and_facts(root.path());
    let mut adapter = UnixExternalTimeoutAuthorityV1::from_binding_per_reservation(
        fixture.binding,
        &authority.socket,
        &response_log,
    )
    .expect("reopen adapter after OS crash")
    .with_capability(CAPABILITY);
    let reservation = adapter
        .reserve_v1(facts)
        .expect("exact pending reservation retry");
    assert_eq!(reservation.sequence(), 0);
    let signature = fixture.signing_key.sign(&facts.signing_root).to_bytes();
    adapter
        .bind_response_v1(reservation, &signature)
        .expect("bind exact response after retry");
    drop(adapter);

    // Run the actual signer fixture binary after the adapter process has
    // crashed/restarted.  It must replay the response from the durable log;
    // no second CAS or key-side reservation is allowed.
    let signer_socket = root.path().join("signer.sock");
    let mut signer = signer_command(
        &signer_socket,
        &root.path().join("signer.sqlite3"),
        &authority.socket,
        &response_log,
    )
    .spawn()
    .expect("spawn signer after adapter crash");
    wait_socket(&signer_socket);
    let response = signer_request(&signer_socket, &request_bytes);
    assert_eq!(
        response[0], FRAME_OK,
        "restarted signer must replay exact response"
    );
    assert!(response.len() > 2);
    signer.kill().expect("stop restarted signer");
    let _ = signer.wait();
    authority.stop();

    // A separate namespace proves that a pending sidecar rewrite is a hard
    // startup failure rather than an invitation to reconstruct a token.
    let tamper_root = TempDir::new().expect("temporary tamper pending root");
    fs::set_permissions(tamper_root.path(), fs::Permissions::from_mode(0o700))
        .expect("private tamper root");
    let mut tamper_authority = AuthorityOnly::start(tamper_root.path());
    let tamper_response_log = tamper_root.path().join("responses.log");
    let tamper_marker = tamper_root.path().join("reserved.marker");
    let mut tampered = spawn_pending_helper(
        "reserve",
        &tamper_authority.socket,
        &tamper_response_log,
        Some(&tamper_marker),
    );
    wait_for_marker(&tamper_marker);
    tampered.kill().expect("kill tamper helper");
    let _ = tampered.wait();
    let pending_path = tamper_root.path().join(".responses.log.pending");
    let mut pending = fs::read(&pending_path).expect("read pending sidecar");
    let last = pending.last_mut().expect("non-empty pending sidecar");
    *last ^= 0x01;
    fs::write(&pending_path, pending).expect("tamper pending sidecar");
    let reopen = spawn_pending_helper(
        "reopen-tampered",
        &tamper_authority.socket,
        &tamper_response_log,
        None,
    );
    let reopen_status = reopen
        .wait_with_output()
        .expect("wait tamper reopen helper");
    assert!(
        reopen_status.status.success(),
        "tampered sidecar helper must explicitly observe fail-stop: stdout={} stderr={}",
        String::from_utf8_lossy(&reopen_status.stdout),
        String::from_utf8_lossy(&reopen_status.stderr)
    );
    tamper_authority.stop();
}
