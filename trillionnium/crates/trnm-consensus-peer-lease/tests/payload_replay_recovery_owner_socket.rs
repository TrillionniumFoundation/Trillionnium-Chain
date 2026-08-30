#![cfg(unix)]
#![allow(clippy::zombie_processes)]

//! Black-box process coverage for the candidate persistent recovery owner.
//! The test verifies the new socket boundary and endpoint pin, while keeping
//! the supplied Core acknowledgement explicitly synthetic/candidate-only.

use std::{
    fs,
    io::Write,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

use trnm_consensus_peer_lease::{
    PayloadReplayCoreAcknowledgementV1, PayloadReplayDirectionV1, PayloadReplayFrameV1,
    PayloadReplayNamespaceV1, PayloadReplayRecoveryClientV1, PayloadReplayRecoveryOwnerV1,
    PayloadReplayRecoveryStatusV1, PayloadReplayRecoveryTargetV1, PayloadReplayStoreV1,
};

const OWNER_BINARY: &str = env!("CARGO_BIN_EXE_trnm-payload-replay-recovery-owner-v1");

fn private_directory(path: &Path) {
    fs::create_dir(path).expect("private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("directory mode");
}

fn namespace() -> PayloadReplayNamespaceV1 {
    PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [4; 32]).expect("valid namespace")
}

fn seed(
    root: &Path,
) -> (
    PathBuf,
    PathBuf,
    PayloadReplayNamespaceV1,
    PayloadReplayRecoveryTargetV1,
) {
    let payload = root.join("frames.wal");
    let acknowledgements = root.join("core-acks");
    private_directory(&acknowledgements);
    let namespace = namespace();
    let frame = PayloadReplayFrameV1::new(
        namespace
            .scope_for([9; 32], PayloadReplayDirectionV1::Inbound)
            .expect("scope"),
        namespace.run_id_hash(),
        namespace.network_context_hash(),
        [5; 32],
        1,
        0,
        2,
        11,
        [10; 32],
    )
    .expect("frame");
    let receipt = {
        let mut store = PayloadReplayStoreV1::open(&payload, namespace).expect("payload store");
        store.admit(&frame).expect("payload admission")
    };
    let target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);
    (payload, acknowledgements, namespace, target)
}

fn hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn owner_args(
    socket: &Path,
    payload: &Path,
    acknowledgements: &Path,
    namespace: PayloadReplayNamespaceV1,
    target: PayloadReplayRecoveryTargetV1,
) -> Vec<String> {
    vec![
        socket.display().to_string(),
        payload.display().to_string(),
        acknowledgements.display().to_string(),
        hex32(namespace.local_id()),
        namespace.epoch().to_string(),
        hex32(namespace.validator_set_id()),
        hex32(namespace.run_id_hash()),
        hex32(namespace.network_context_hash()),
        target.record_index().to_string(),
        hex32(target.record_hash()),
        hex32(target.remote_id()),
        match target.direction() {
            PayloadReplayDirectionV1::Inbound => "inbound".to_owned(),
            PayloadReplayDirectionV1::Outbound => "outbound".to_owned(),
        },
        hex32(target.session_id()),
        target.generation().to_string(),
        target.sequence().to_string(),
        target.frame_kind().to_string(),
        target.payload_len().to_string(),
        hex32(target.frame_fingerprint()),
    ]
}

fn spawn_owner(
    socket: &Path,
    payload: &Path,
    acknowledgements: &Path,
    namespace: PayloadReplayNamespaceV1,
    target: PayloadReplayRecoveryTargetV1,
) -> Child {
    Command::new(OWNER_BINARY)
        .args(owner_args(
            socket,
            payload,
            acknowledgements,
            namespace,
            target,
        ))
        .spawn()
        .expect("spawn recovery owner")
}

fn wait_for_socket(child: &mut Child, socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if socket.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll owner") {
            panic!("owner exited before binding socket: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("owner did not bind socket before deadline");
}

fn stop_owner(mut child: Child, socket: &Path) {
    child.kill().expect("kill owner");
    let status = child.wait().expect("wait owner");
    assert!(!status.success(), "SIGKILL owner unexpectedly succeeded");
    // SIGKILL cannot run the cleanup guard.  Remove only this test's private
    // temporary endpoint before starting the deliberate replacement case.
    fs::remove_file(socket).expect("remove test-owned stale socket");
}

fn exercise_malformed_client_disconnects(socket: &Path) {
    // A same-UID peer can reach this private candidate socket.  Closing
    // before a frame is complete must be scoped to that accepted stream; it
    // must not terminate the owner listener.
    drop(UnixStream::connect(socket).expect("connect then EOF"));

    // Also cover a fully connected peer that sends an invalid frame and then
    // disconnects before the daemon can write its bounded error response.
    let mut malformed = UnixStream::connect(socket).expect("connect malformed peer");
    malformed
        .write_all(b"NOPE\x01\x01\x00\x00\x00\x00\x00\x00")
        .expect("write malformed frame");
}

#[test]
fn persistent_owner_serves_status_ack_and_pins_endpoint_identity() {
    let root = tempfile::Builder::new()
        .prefix("trnm-recovery-owner-socket-")
        .tempdir()
        .expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
    let (payload, acknowledgements, namespace, target) = seed(root.path());
    let socket = root.path().join("owner.sock");

    let mut owner = spawn_owner(&socket, &payload, &acknowledgements, namespace, target);
    wait_for_socket(&mut owner, &socket);
    let metadata = fs::symlink_metadata(&socket).expect("socket metadata");
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);

    let client = PayloadReplayRecoveryClientV1::connect(&socket);
    exercise_malformed_client_disconnects(&socket);
    let status = client.status().expect("socket status");
    assert!(status.endpoint_identity() != [0; 32]);
    assert!(matches!(
        status.projection().status(),
        PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged { .. }
    ));
    let pinned = PayloadReplayRecoveryClientV1::connect(&socket)
        .with_expected_endpoint_identity(status.endpoint_identity());
    let repeated = pinned.status().expect("pinned status");
    assert_eq!(repeated.endpoint_identity(), status.endpoint_identity());

    let ack = client
        .acknowledge(9, [11; 32])
        .expect("explicit candidate Core acknowledgement");
    assert!(!ack.receipt().idempotent_replay());
    assert_eq!(ack.endpoint_identity(), status.endpoint_identity());
    let replay = pinned.acknowledge(9, [11; 32]).expect("idempotent ack");
    assert!(replay.receipt().idempotent_replay());

    stop_owner(owner, &socket);

    // A fresh daemon receives a new socket inode.  A supervisor retaining the
    // previous identity must reject it until an explicit operator re-pin.
    let mut replacement = spawn_owner(&socket, &payload, &acknowledgements, namespace, target);
    wait_for_socket(&mut replacement, &socket);
    let replacement_client = PayloadReplayRecoveryClientV1::connect(&socket);
    let replacement_status = replacement_client.status().expect("replacement status");
    assert_ne!(
        replacement_status.endpoint_identity(),
        status.endpoint_identity(),
        "socket restart must produce a new endpoint pin"
    );
    assert!(matches!(
        pinned.status(),
        Err(trnm_consensus_peer_lease::PayloadReplayRecoverySocketErrorV1::EndpointIdentityChanged)
    ));
    stop_owner(replacement, &socket);

    // Keep the direct owner API boundary exercised as well: the socket's
    // acknowledgement is still caller-supplied and never claims atomic Core
    // integration.
    let _ = PayloadReplayCoreAcknowledgementV1::new(target, 9, [11; 32])
        .expect("synthetic acknowledgement remains structurally valid");
    let _ = PayloadReplayRecoveryOwnerV1::open(&payload, &acknowledgements, namespace, target)
        .expect("owner reopens after daemon release");
}
