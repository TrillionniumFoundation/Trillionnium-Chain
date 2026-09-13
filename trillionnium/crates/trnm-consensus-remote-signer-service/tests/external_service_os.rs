//! Real two-daemon timeout path.
//!
//! This is deliberately a bounded fixture composition: the external daemon
//! owns semantic CAS and the signer daemon owns the fixture key, but neither
//! is a Core/SafetyRules authority.  The test exists to prevent an in-process
//! adapter from being mistaken for the Unix service wiring.

use std::{
    env, fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    thread,
    time::Duration,
};

use tempfile::TempDir;
use trnm_consensus_external_watermark::{
    run_per_reservation_daemon, ExternalWatermarkSemanticBindingV1,
};
use trnm_consensus_remote_signer_service::{
    fixture_request, Fixture, UnixExternalTimeoutAuthorityV1,
};

const CAPABILITY: [u8; 32] = [0x33; 32];
const FRAME_OK: u8 = 0;
const FRAME_REJECT: u8 = 1;
const AUTHORITY_CHILD_ENV: &str = "TRNM_EXTERNAL_SERVICE_OS_AUTHORITY_CHILD";
const AUTHORITY_SOCKET_ENV: &str = "TRNM_EXTERNAL_SERVICE_OS_AUTHORITY_SOCKET";
const AUTHORITY_LOG_ENV: &str = "TRNM_EXTERNAL_SERVICE_OS_AUTHORITY_LOG";
const AUTHORITY_SCOPE_ENV: &str = "TRNM_EXTERNAL_SERVICE_OS_AUTHORITY_SCOPE";
const AUTHORITY_JOURNAL_ENV: &str = "TRNM_EXTERNAL_SERVICE_OS_AUTHORITY_JOURNAL";
const AUTHORITY_CAPABILITY_ENV: &str = "TRNM_EXTERNAL_SERVICE_OS_AUTHORITY_CAPABILITY";

fn authority_command(
    socket: &Path,
    log: &Path,
    binding: trnm_consensus_remote_signer_protocol::RemoteSignerRequestBindingV1,
) -> Command {
    let scope = UnixExternalTimeoutAuthorityV1::scope_for_binding(binding);
    let journal = UnixExternalTimeoutAuthorityV1::journal_id_for_binding(binding);
    let mut command =
        Command::new(env::current_exe().expect("resolve external service OS test executable"));
    command
        .args([
            "--exact",
            "external_service_os_authority_child",
            "--nocapture",
        ])
        .env(AUTHORITY_CHILD_ENV, "1")
        .env(AUTHORITY_SOCKET_ENV, socket)
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
    capability: [u8; 32],
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
        .arg(hex32(capability));
    command
}

struct Daemons {
    root: TempDir,
    authority: Child,
    signer: Child,
    authority_socket: PathBuf,
    signer_socket: PathBuf,
}

impl Daemons {
    fn start() -> Self {
        let root = TempDir::new().expect("temporary daemon root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private daemon root");
        let (authority, signer, authority_socket, signer_socket) = Self::launch(root.path());
        Self {
            root,
            authority,
            signer,
            authority_socket,
            signer_socket,
        }
    }

    fn launch(root: &Path) -> (Child, Child, PathBuf, PathBuf) {
        let fixture = Fixture::new();
        let authority_socket = root.join("authority.sock");
        let authority_log = root.join("authority.log");
        let authority = authority_command(&authority_socket, &authority_log, fixture.binding)
            .spawn()
            .expect("spawn semantic authority child process");
        wait_socket(&authority_socket);

        let signer_socket = root.join("signer.sock");
        let signer = signer_command(
            &signer_socket,
            &root.join("signer.sqlite3"),
            &authority_socket,
            &root.join("responses.log"),
            CAPABILITY,
        )
        .spawn()
        .expect("spawn external timeout signer");
        wait_socket(&signer_socket);
        (authority, signer, authority_socket, signer_socket)
    }

    fn restart(&mut self) {
        let _ = self.authority.kill();
        let _ = self.authority.wait();
        let _ = self.signer.kill();
        let _ = self.signer.wait();
        let (authority, signer, authority_socket, signer_socket) = Self::launch(self.root.path());
        self.authority = authority;
        self.signer = signer;
        self.authority_socket = authority_socket;
        self.signer_socket = signer_socket;
    }
}

fn wait_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() && UnixStream::connect(path).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for socket {}", path.display());
}

fn wait_exit(child: &mut Child) -> ExitStatus {
    for _ in 0..200 {
        if let Some(status) = child.try_wait().expect("poll child status") {
            return status;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("child did not fail closed during startup");
}

fn request(socket: &Path, bytes: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).expect("connect signer");
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .expect("write request length");
    stream.write_all(bytes).expect("write request");
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .expect("read response length");
    let mut response = vec![0_u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut response).expect("read response");
    response
}

fn hex32(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
fn external_service_os_authority_child() {
    if env::var_os(AUTHORITY_CHILD_ENV).is_none() {
        return;
    }
    let binding = ExternalWatermarkSemanticBindingV1::new(
        authority_env_hex32(AUTHORITY_SCOPE_ENV),
        authority_env_hex32(AUTHORITY_JOURNAL_ENV),
        authority_env_hex32(AUTHORITY_CAPABILITY_ENV),
    )
    .expect("authority child semantic binding");
    run_per_reservation_daemon(
        authority_env_path(AUTHORITY_SOCKET_ENV),
        authority_env_path(AUTHORITY_LOG_ENV),
        binding,
    )
    .expect("authority child must fail closed on invalid durable state");
}

#[test]
fn external_timeout_service_is_two_process_and_replays_exactly() {
    let mut daemons = Daemons::start();
    let fixture = Fixture::new();
    let timeout = fixture_request(&fixture, "timeout", 3, b"os-timeout").expect("timeout");
    let timeout_bytes = timeout.try_exact_bytes().expect("encode timeout");
    let first = request(&daemons.signer_socket, &timeout_bytes);
    assert_eq!(first[0], FRAME_OK);
    assert!(first.len() > 2);

    let vote = fixture_request(&fixture, "vote", 3, b"os-vote").expect("vote");
    let vote_bytes = vote.try_exact_bytes().expect("encode vote");
    let rejected = request(&daemons.signer_socket, &vote_bytes);
    assert_eq!(rejected[0], FRAME_REJECT);

    daemons.restart();
    let replay = request(&daemons.signer_socket, &timeout_bytes);
    assert_eq!(replay, first, "restart must return exact durable response");

    let higher = fixture_request(&fixture, "timeout", 5, b"os-timeout-higher").expect("higher");
    let higher_bytes = higher.try_exact_bytes().expect("encode higher");
    let higher_response = request(&daemons.signer_socket, &higher_bytes);
    assert_eq!(higher_response[0], FRAME_OK);

    // Explicit external mode uses one semantic CAS reservation per timeout;
    // a third distinct request must advance the same durable namespace rather
    // than being mistaken for the even half of a signer-journal pair.
    let third = fixture_request(&fixture, "timeout", 7, b"os-timeout-third").expect("third");
    let third_bytes = third.try_exact_bytes().expect("encode third");
    let third_response = request(&daemons.signer_socket, &third_bytes);
    assert_eq!(third_response[0], FRAME_OK);

    // The explicit service mode must not fall back to its local SQLite path
    // when the independent authority disappears. A fresh timeout therefore
    // rejects while the signer process itself is still alive.
    let _ = daemons.authority.kill();
    let _ = daemons.authority.wait();
    let unavailable = fixture_request(&fixture, "timeout", 6, b"os-authority-down")
        .expect("authority-down timeout");
    let unavailable_bytes = unavailable
        .try_exact_bytes()
        .expect("encode authority-down timeout");
    let rejected_without_authority = request(&daemons.signer_socket, &unavailable_bytes);
    assert_eq!(
        rejected_without_authority[0], FRAME_REJECT,
        "external mode must fail closed without local fallback"
    );

    let _ = daemons.signer.kill();
    let _ = daemons.signer.wait();
}

#[test]
fn external_timeout_service_rejects_unbound_authority_before_socket_ready() {
    let root = TempDir::new().expect("temporary startup preflight root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("private startup root");
    let fixture = Fixture::new();
    let authority_socket = root.path().join("authority.sock");
    let authority_log = root.path().join("authority.log");
    let authority = authority_command(&authority_socket, &authority_log, fixture.binding)
        .spawn()
        .expect("spawn startup authority child process");
    let mut authority = authority;
    wait_socket(&authority_socket);

    let wrong_capability = [0x44_u8; 32];
    let wrong_socket = root.path().join("wrong-signer.sock");
    let mut wrong_signer = signer_command(
        &wrong_socket,
        &root.path().join("wrong.sqlite3"),
        &authority_socket,
        &root.path().join("wrong-responses.log"),
        wrong_capability,
    )
    .spawn()
    .expect("spawn wrong-capability signer");
    let wrong_status = wait_exit(&mut wrong_signer);
    assert!(
        !wrong_status.success(),
        "wrong authority binding must fail closed"
    );
    assert!(
        !wrong_socket.exists(),
        "a signer must not publish a socket before authority preflight"
    );
    assert!(
        !root.path().join("wrong.sqlite3").exists(),
        "failed authority preflight must happen before local signer state is opened"
    );

    let unavailable_socket = root.path().join("unavailable-signer.sock");
    let missing_authority = root.path().join("missing-authority.sock");
    let mut unavailable_signer = signer_command(
        &unavailable_socket,
        &root.path().join("unavailable.sqlite3"),
        &missing_authority,
        &root.path().join("unavailable-responses.log"),
        CAPABILITY,
    )
    .spawn()
    .expect("spawn unavailable-authority signer");
    let unavailable_status = wait_exit(&mut unavailable_signer);
    assert!(!unavailable_status.success());
    assert!(!unavailable_socket.exists());
    assert!(!root.path().join("unavailable.sqlite3").exists());

    let _ = authority.kill();
    let _ = authority.wait();
}
