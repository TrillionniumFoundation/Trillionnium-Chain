#![cfg(unix)]

//! OS-process lifecycle coverage for the deterministic remote-signer fixture.
//!
//! This deliberately targets the standalone `trnm-remote-signer-p0` binary,
//! not the continuous validator authority.  It proves only that the fixture
//! service's Unix transport and local SQLite reservation survive a SIGKILL,
//! reject an exact replay after restart, and fail closed when its local
//! namespace is corrupted.  It is not external watermark, HSM, or production
//! consensus-signer evidence.

use std::{
    env, fs,
    io::{Read, Write},
    os::unix::{fs::FileTypeExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;
use trnm_consensus_remote_signer_service::{
    fixture_request, fixture_service_config, Fixture, PurposePolicyV1, RemoteSignerService,
};

const FRAME_OK: u8 = 0;
const FRAME_REJECT: u8 = 1;
const REJECT_DUPLICATE_REQUEST: u8 = 5;

fn service_command(socket: &Path, watermark: &Path) -> Command {
    let binary = env::var_os("CARGO_BIN_EXE_trnm_remote_signer_p0")
        .map(PathBuf::from)
        .or_else(|| {
            let test_binary = env::current_exe().ok()?;
            Some(
                test_binary
                    .parent()?
                    .parent()?
                    .join("trnm-remote-signer-p0"),
            )
        })
        .expect("resolve trnm-remote-signer-p0 fixture binary");
    assert!(
        binary.is_file(),
        "fixture binary is not built: {} (run cargo build -p trnm-consensus-remote-signer-service --bin trnm-remote-signer-p0)",
        binary.display()
    );
    let mut command = Command::new(binary);
    command
        .arg("serve-fixture")
        .arg("--socket")
        .arg(socket)
        .arg("--watermark")
        .arg(watermark)
        .arg("--purpose")
        .arg("both")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

fn spawn_service(socket: &Path, watermark: &Path) -> Child {
    let mut child = service_command(socket, watermark)
        .spawn()
        .expect("spawn remote-signer fixture OS process");
    wait_for_socket(&mut child, socket);
    child
}

fn wait_for_socket(child: &mut Child, socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if fs::symlink_metadata(socket)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
            && UnixStream::connect(socket).is_ok()
        {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll fixture process") {
            panic!(
                "fixture process exited before socket readiness: {} ({status})",
                child_stderr(child)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for fixture socket {}", socket.display());
}

fn child_stderr(child: &mut Child) -> String {
    child
        .stderr
        .take()
        .map(|mut stream| {
            let mut bytes = Vec::new();
            let _ = stream.read_to_end(&mut bytes);
            String::from_utf8_lossy(&bytes).into_owned()
        })
        .unwrap_or_default()
}

fn kill_and_wait(child: &mut Child) -> ExitStatus {
    if child
        .try_wait()
        .expect("poll fixture process before kill")
        .is_none()
    {
        child.kill().expect("SIGKILL fixture process");
    }
    child.wait().expect("wait killed fixture process")
}

fn read_exact(stream: &mut UnixStream, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .expect("read complete fixture response frame");
    bytes
}

fn send_frame(socket: &Path, payload: &[u8]) -> Result<Vec<u8>, u8> {
    let mut stream = UnixStream::connect(socket).expect("connect fixture signer socket");
    stream
        .write_all(
            &(u32::try_from(payload.len())
                .expect("bounded request")
                .to_be_bytes()),
        )
        .expect("write fixture frame length");
    stream.write_all(payload).expect("write fixture frame body");
    stream.flush().expect("flush fixture frame");
    let response_length = u32::from_be_bytes(
        read_exact(&mut stream, 4)
            .try_into()
            .expect("fixture response frame header"),
    ) as usize;
    let response = read_exact(&mut stream, response_length);
    assert!(
        !response.is_empty(),
        "fixture returned an empty response frame"
    );
    match response[0] {
        FRAME_OK => Ok(response[1..].to_vec()),
        FRAME_REJECT => {
            assert_eq!(response.len(), 2, "fixture rejection frame is exact");
            Err(response[1])
        }
        other => panic!("unexpected fixture response frame tag {other}"),
    }
}

fn request_bytes(fixture: &Fixture, kind: &str, view: u64, nonce: &[u8]) -> Vec<u8> {
    fixture_request(fixture, kind, view, nonce)
        .expect("construct fixture request")
        .try_exact_bytes()
        .expect("encode exact fixture request")
}

#[test]
fn fixture_service_os_process_restart_replay_and_tamper_fail_stop() {
    let temp = TempDir::new().expect("create fixture process temp root");
    let socket = temp.path().join("signer.sock");
    let watermark = temp.path().join("watermark.sqlite3");
    let fixture = Fixture::new();
    let first = request_bytes(&fixture, "vote", 10, b"os-first");
    let next = request_bytes(&fixture, "vote", 11, b"os-next");

    // First child: commit one request, then terminate it without a graceful
    // socket shutdown.  SQLite FULL/WAL persistence must retain the request.
    let mut first_child = spawn_service(&socket, &watermark);
    let response = send_frame(&socket, &first).expect("first OS-process request succeeds");
    assert!(response.starts_with(b"TRNMRS01"));
    let first_status = kill_and_wait(&mut first_child);
    assert!(
        !first_status.success(),
        "SIGKILL fixture must be non-success"
    );

    // Second child reopens the same namespace.  The exact request is rejected
    // as a durable duplicate, while a strictly newer round is accepted.
    let mut restarted_child = spawn_service(&socket, &watermark);
    assert_eq!(
        send_frame(&socket, &first).expect_err("replayed request must reject"),
        REJECT_DUPLICATE_REQUEST
    );
    assert!(send_frame(&socket, &next)
        .map(|response| response.starts_with(b"TRNMRS01"))
        .expect("newer request succeeds after restart"));
    let restarted_status = kill_and_wait(&mut restarted_child);
    assert!(
        !restarted_status.success(),
        "second SIGKILL fixture must be non-success"
    );

    // Reopen in-process only to inspect the durable sequence before tampering;
    // the signing service under test remains the OS child above.
    let snapshot =
        RemoteSignerService::open(fixture_service_config(&watermark, PurposePolicyV1::both()))
            .expect("reopen fixture watermark after child restart")
            .watermark_snapshot()
            .expect("read fixture watermark snapshot");
    assert_eq!(snapshot.sequence, 2);

    // Corruption must prevent a new child from binding/serving.  Remove the
    // stale socket first so a leftover inode cannot be mistaken for readiness.
    let mut bytes = fs::read(&watermark).expect("read fixture SQLite namespace");
    assert!(!bytes.is_empty());
    bytes[0] ^= 0x01;
    fs::write(&watermark, bytes).expect("tamper fixture SQLite namespace");
    let _ = fs::remove_file(&socket);
    let mut tampered_child = service_command(&socket, &watermark)
        .spawn()
        .expect("spawn tampered fixture process");
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = tampered_child.try_wait().expect("poll tampered fixture") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "tampered fixture process did not fail closed"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert!(
        !status.success(),
        "tampered fixture process must fail closed"
    );
    let stderr = child_stderr(&mut tampered_child);
    assert!(
        stderr.contains("integrity")
            || stderr.contains("invalid")
            || stderr.contains("SQLite")
            || stderr.contains("database"),
        "tampered fixture must identify persisted-state failure: {stderr}"
    );
}
