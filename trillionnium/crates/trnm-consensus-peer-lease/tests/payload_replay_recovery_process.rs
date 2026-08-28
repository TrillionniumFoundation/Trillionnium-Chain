#![cfg(unix)]

//! Black-box coverage for the candidate replay-recovery command.  The test
//! deliberately starts the compiled binary rather than calling the owner in
//! process: an operator wrapper must preserve the same path and JSON
//! boundaries after a process hand-off.

use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

use trnm_consensus_peer_lease::{
    PayloadReplayDirectionV1, PayloadReplayFrameV1, PayloadReplayNamespaceV1,
    PayloadReplayRecoveryTargetV1, PayloadReplayStoreV1,
};

fn hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn private_directory(path: &Path) {
    fs::create_dir(path).expect("private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("directory mode");
}

fn command_arguments(
    operation: &str,
    payload: &Path,
    acknowledgements: &Path,
    namespace: PayloadReplayNamespaceV1,
    target: PayloadReplayRecoveryTargetV1,
) -> Vec<String> {
    vec![
        "--json".to_owned(),
        operation.to_owned(),
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

#[test]
fn status_process_emits_one_machine_readable_json_object() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
    let payload = root.path().join("payload.wal");
    let acknowledgements = root.path().join("ack");
    private_directory(&acknowledgements);

    let namespace =
        PayloadReplayNamespaceV1::new([0x11; 32], 7, [0x22; 32], [0x33; 32], [0x44; 32])
            .expect("namespace");
    let scope = namespace
        .scope_for([0x55; 32], PayloadReplayDirectionV1::Outbound)
        .expect("scope");
    let frame = PayloadReplayFrameV1::new(
        scope,
        namespace.run_id_hash(),
        namespace.network_context_hash(),
        [0x66; 32],
        1,
        0,
        1,
        16,
        [0x77; 32],
    )
    .expect("frame");
    let mut store = PayloadReplayStoreV1::open(&payload, namespace).expect("replay store");
    let receipt = store.admit(&frame).expect("admission");
    drop(store);
    let target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);

    let output = Command::new(env!("CARGO_BIN_EXE_trnm-payload-replay-recovery-v1"))
        .args(command_arguments(
            "status",
            &payload,
            &acknowledgements,
            namespace,
            target,
        ))
        .output()
        .expect("spawn recovery process");
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    assert_eq!(stdout.lines().count(), 1, "expected one JSON line");
    let line = stdout.trim_end_matches(['\r', '\n']);
    assert!(line.starts_with('{') && line.ends_with('}'));
    assert!(
        !line.contains('='),
        "legacy key=value leaked into JSON output"
    );
    assert!(line.contains("\"schema\":\"trnm.payload-replay-recovery.v1\""));
    assert!(line.contains("\"operation\":\"status\""));
    assert!(line.contains("\"status\":\"admitted_unacknowledged\""));
    assert!(line.contains("\"candidate_only\":true"));
    assert!(line.contains("\"production\":false"));
    assert!(line.contains("\"atomic_with_core\":false"));
}

#[test]
fn json_process_rejects_relative_paths_without_opening_authority() {
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-payload-replay-recovery-v1"))
        .args([
            "--json",
            "status",
            "relative.wal",
            "/tmp/ack",
            &"11".repeat(32),
            "7",
            &"22".repeat(32),
            &"33".repeat(32),
            &"44".repeat(32),
            "1",
            &"55".repeat(32),
            &"66".repeat(32),
            "outbound",
            &"77".repeat(32),
            "1",
            "0",
            "1",
            "16",
            &"88".repeat(32),
        ])
        .output()
        .expect("spawn recovery process");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stderr.starts_with('{') && stderr.trim_end().ends_with('}'));
    assert!(stderr.contains("\"status\":\"error\""));
    assert!(stderr.contains("\"candidate_only\":true"));
    assert!(stderr.contains("\"production\":false"));
}
