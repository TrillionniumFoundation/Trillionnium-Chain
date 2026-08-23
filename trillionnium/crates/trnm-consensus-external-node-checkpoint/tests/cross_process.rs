use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;
use trnm_consensus_external_node_checkpoint::UnixExternalNodeCheckpointStoreV0;
use trnm_consensus_signer_journal::SignerWatermarkV0;
use trnm_consensus_types::{BlockId, StateRoot};
use trnm_poco_node::{
    ExternalNodeCheckpointFieldsV0, ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0,
};

fn checkpoint() -> ExternalNodeCheckpointV0 {
    ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
        scope: [1; 32],
        generation: 0,
        predecessor_checksum: [0; 32],
        safety_journal_id: [2; 32],
        safety_verifier_profile_ref: [3; 32],
        safety_revision: 1,
        safety_state_record_checksum: [4; 32],
        safety_record_chain_checksum: [5; 32],
        application_host_config_ref: [6; 32],
        application_projection_profile_ref: [7; 32],
        application_safety_binding_manifest_checksum: [8; 32],
        application_committed_head_row_checksum: [9; 32],
        application_recovery_closure_checksum: [10; 32],
        application_block_id: BlockId::new([11; 32]),
        application_height: 1,
        application_state_root: StateRoot::new([12; 32]),
        application_view: 1,
        application_timestamp_ms: 100,
        signer_journal_id: [13; 32],
        signer_profile_checksum: [14; 32],
        signer_exact_watermark: SignerWatermarkV0::from_persisted_parts(
            [1; 32], [13; 32], 0, [15; 32],
        )
        .unwrap(),
    })
    .unwrap()
}

fn private_tempdir() -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn standalone_daemon_is_cross_process_and_rejects_truncated_log() {
    let directory = private_tempdir();
    let socket = directory.path().join("checkpoint.sock");
    let log = directory.path().join("checkpoint.log");
    let binary = env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v0");
    let mut child = Command::new(binary)
        .arg(&socket)
        .arg(&log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "checkpoint daemon socket did not appear"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let mut client = UnixExternalNodeCheckpointStoreV0::new(&socket).unwrap();
    let first = checkpoint();
    client.compare_and_advance(None, first).unwrap();
    assert_eq!(client.load([1; 32]).unwrap(), Some(first));
    child.kill().unwrap();
    let _ = child.wait();

    let mut bytes = fs::read(&log).unwrap();
    bytes.pop();
    fs::write(&log, bytes).unwrap();
    let status = Command::new(binary)
        .arg(&socket)
        .arg(&log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "truncated journal must fail closed");
}
