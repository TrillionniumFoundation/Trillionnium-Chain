#![cfg(feature = "test-fixture")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command},
    thread,
    time::Duration,
};

use tempfile::TempDir;
use trnm_consensus_types::ValidatorId;
use trnm_consensus_unix_fleet_signer::{
    test_fixture::{fixture_public_key_v1, FixtureModeV1},
    FleetRootPurposeV1, UnixFleetRootSignerConfig, UnixFleetRootSignerProducerV1,
    UnixFleetSignerErrorV1,
};

fn origin() -> ValidatorId {
    ValidatorId::from_bytes(b"fleet-fixture-validator").expect("bounded origin")
}

fn config(socket: &Path) -> UnixFleetRootSignerConfig {
    UnixFleetRootSignerConfig {
        socket_path: socket.to_path_buf(),
        origin: origin(),
        validator_set_id: [0x31; 32],
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
