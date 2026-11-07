use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;
use trnm_checkpoint_store::{
    read_external_journal_checkpoint_v1, write_new_external_journal_checkpoint_v1,
    ExternalCheckpointAuthorityV2, UnixExternalCheckpointStoreV2,
};
use trnm_checkpoint_types::EffectWatermarkV2;
use trnm_checkpoint_types::{BlockId, StateRoot};
use trnm_checkpoint_types::{
    ExternalCheckpointFieldsV2, ExternalCheckpointStoreV2, ExternalCheckpointV2,
};

fn checkpoint() -> ExternalCheckpointV2 {
    checkpoint_generation(0, [0; 32])
}

fn checkpoint_generation(generation: u64, predecessor: [u8; 32]) -> ExternalCheckpointV2 {
    ExternalCheckpointV2::new(ExternalCheckpointFieldsV2 {
        scope: [1; 32],
        generation,
        predecessor_checksum: predecessor,
        authority_journal_id: [2; 32],
        authority_verifier_profile_ref: [3; 32],
        authority_revision: generation + 1,
        authority_state_record_checksum: [4; 32],
        authority_record_chain_checksum: [5; 32],
        application_host_config_ref: [6; 32],
        application_projection_profile_ref: [7; 32],
        application_authority_binding_manifest_checksum: [8; 32],
        application_committed_head_row_checksum: [9; 32],
        application_recovery_closure_checksum: [10; 32],
        application_block_id: BlockId::new([11; 32]),
        application_height: generation + 1,
        application_state_root: StateRoot::new([12; 32]),
        application_generation: generation + 1,
        application_timestamp_ms: 100 + generation,
        effect_journal_id: [13; 32],
        effect_profile_checksum: [14; 32],
        effect_exact_watermark: EffectWatermarkV2::from_persisted_parts(
            [1; 32], [13; 32], generation, [15; 32],
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

struct RunningDaemon(Child);

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn daemon(command: &mut Command, socket: &Path) -> RunningDaemon {
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut running = RunningDaemon(child);
    let client = UnixExternalCheckpointStoreV2::new(socket)
        .unwrap()
        .with_timeout(Duration::from_millis(50));
    let deadline = Instant::now() + Duration::from_secs(5);
    while client.journal_checkpoint_v1().is_err() {
        assert!(running.0.try_wait().unwrap().is_none(), "daemon exited");
        assert!(Instant::now() < deadline, "daemon did not become ready");
        thread::sleep(Duration::from_millis(10));
    }
    running
}

fn failed_command(command: &mut Command) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            assert!(!output.status.success(), "command unexpectedly succeeded");
            return output;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("rejected command kept running: {output:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn export_live_checkpoint(socket: &Path, export: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v2"))
        .arg("journal-checkpoint")
        .arg(socket)
        .arg(export)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "checkpoint export failed: {output:?}"
    );
}

#[test]
fn standalone_daemon_is_cross_process_and_rejects_truncated_log() {
    let directory = private_tempdir();
    let socket = directory.path().join("checkpoint.sock");
    let log = directory.path().join("checkpoint.log");
    let independent = private_tempdir();
    let expected_file = independent.path().join("journal-checkpoint.bin");
    let binary = env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v2");
    let child = daemon(
        Command::new(binary)
            .arg("register-new")
            .arg(&socket)
            .arg(&log),
        &socket,
    );
    let mut client = UnixExternalCheckpointStoreV2::new(&socket).unwrap();
    let first = checkpoint();
    client.compare_and_advance(None, first).unwrap();
    assert_eq!(client.load([1; 32]).unwrap(), Some(first));
    export_live_checkpoint(&socket, &expected_file);
    drop(child);

    let mut bytes = fs::read(&log).unwrap();
    bytes.pop();
    fs::write(&log, bytes).unwrap();
    let output = failed_command(
        Command::new(binary)
            .arg("reopen")
            .arg(&socket)
            .arg(&log)
            .arg(&expected_file),
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("external journal checkpoint mismatch")
    );
}

#[test]
fn daemon_cold_restart_requires_external_pin_and_rejects_complete_snapshot_rollback() {
    let directory = private_tempdir();
    let independent = private_tempdir();
    let socket = directory.path().join("checkpoint.sock");
    let log = directory.path().join("checkpoint.log");
    let anchor = directory.path().join(".checkpoint.log.head-v2");
    let expected_file = independent.path().join("fresh-journal-checkpoint.bin");
    let binary = env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v2");
    let child = daemon(
        Command::new(binary)
            .arg("register-new")
            .arg(&socket)
            .arg(&log),
        &socket,
    );
    let mut client = UnixExternalCheckpointStoreV2::new(&socket).unwrap();
    let first = checkpoint();
    let second = checkpoint_generation(1, first.checkpoint_checksum());
    client.compare_and_advance(None, first).unwrap();
    let old_log = fs::read(&log).unwrap();
    let old_anchor = fs::read(&anchor).unwrap();
    client.compare_and_advance(Some(first), second).unwrap();
    let live_head = client.journal_checkpoint_v1().unwrap();
    export_live_checkpoint(&socket, &expected_file);
    assert_eq!(
        read_external_journal_checkpoint_v1(&expected_file).unwrap(),
        live_head
    );
    assert_eq!(live_head.record_count(), 2);
    drop(child);

    // Healthy real-process restart consumes exactly the external input.
    let restarted = daemon(
        Command::new(binary)
            .arg("reopen")
            .arg(&socket)
            .arg(&log)
            .arg(&expected_file),
        &socket,
    );
    assert_eq!(client.load([1; 32]).unwrap(), Some(second));
    drop(restarted);

    fs::write(&log, &old_log).unwrap();
    fs::write(&anchor, &old_anchor).unwrap();
    let output = failed_command(
        Command::new(binary)
            .arg("reopen")
            .arg(&socket)
            .arg(&log)
            .arg(&expected_file),
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("external journal checkpoint mismatch")
    );
    assert_eq!(fs::read(&log).unwrap(), old_log);
    assert_eq!(fs::read(&anchor).unwrap(), old_anchor);
    assert!(
        client.load([1; 32]).is_err(),
        "rolled-back daemon must not serve"
    );
}

#[test]
fn cli_missing_expected_and_legacy_implicit_start_fail_without_repair() {
    let directory = private_tempdir();
    let socket = directory.path().join("checkpoint.sock");
    let log = directory.path().join("checkpoint.log");
    let binary = env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v2");
    let output = failed_command(Command::new(binary).arg("reopen").arg(&socket).arg(&log));
    assert_eq!(output.status.code(), Some(64));
    let output = failed_command(Command::new(binary).arg(&socket).arg(&log));
    assert_eq!(output.status.code(), Some(64));
    let missing = directory.path().join("missing-independent-checkpoint.bin");
    let output = failed_command(
        Command::new(binary)
            .arg("reopen")
            .arg(&socket)
            .arg(&log)
            .arg(&missing),
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("open external journal checkpoint"));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn competing_owner_cannot_reopen_or_reregister_a_live_namespace() {
    let directory = private_tempdir();
    let independent = private_tempdir();
    let socket = directory.path().join("checkpoint.sock");
    let log = directory.path().join("checkpoint.log");
    let expected_file = independent.path().join("journal-checkpoint.bin");
    let binary = env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v2");
    let child = daemon(
        Command::new(binary)
            .arg("register-new")
            .arg(&socket)
            .arg(&log),
        &socket,
    );
    export_live_checkpoint(&socket, &expected_file);
    let output = failed_command(
        Command::new(binary)
            .arg("reopen")
            .arg(&socket)
            .arg(&log)
            .arg(&expected_file),
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("lock authority namespace"));
    let output = failed_command(
        Command::new(binary)
            .arg("register-new")
            .arg(&socket)
            .arg(&log),
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("namespace already exists"));
    // Failed contenders must not unlink or replace the active owner's socket.
    let mut client = UnixExternalCheckpointStoreV2::new(&socket).unwrap();
    let first = checkpoint();
    client.compare_and_advance(None, first).unwrap();
    assert_eq!(client.load([1; 32]).unwrap(), Some(first));
    drop(child);
}

#[test]
fn cli_rejects_complete_old_image_before_attempting_transport() {
    let directory = private_tempdir();
    let independent = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let anchor = directory.path().join(".checkpoint.log.head-v2");
    let socket = directory.path().join("checkpoint.sock");
    let expected_file = independent.path().join("fresh-checkpoint.bin");
    let mut owner = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
    let first = checkpoint();
    let second = checkpoint_generation(1, first.checkpoint_checksum());
    owner.compare_and_advance_checked(None, first).unwrap();
    let old_log = fs::read(&log).unwrap();
    let old_anchor = fs::read(&anchor).unwrap();
    owner
        .compare_and_advance_checked(Some(first), second)
        .unwrap();
    write_new_external_journal_checkpoint_v1(
        &expected_file,
        owner.journal_checkpoint_v1().unwrap(),
    )
    .unwrap();
    drop(owner);
    fs::write(&log, &old_log).unwrap();
    fs::write(&anchor, &old_anchor).unwrap();

    let output = failed_command(
        Command::new(env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v2"))
            .arg("reopen")
            .arg(&socket)
            .arg(&log)
            .arg(&expected_file),
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("external journal checkpoint mismatch")
    );
    assert!(!socket.exists());
    assert_eq!(fs::read(&log).unwrap(), old_log);
    assert_eq!(fs::read(&anchor).unwrap(), old_anchor);
}

#[test]
fn cli_second_process_cannot_open_while_the_owner_holds_its_lock() {
    let directory = private_tempdir();
    let independent = private_tempdir();
    let log = directory.path().join("checkpoint.log");
    let socket = directory.path().join("checkpoint.sock");
    let expected_file = independent.path().join("current-checkpoint.bin");
    let mut owner = ExternalCheckpointAuthorityV2::register_new(&log).unwrap();
    write_new_external_journal_checkpoint_v1(
        &expected_file,
        owner.journal_checkpoint_v1().unwrap(),
    )
    .unwrap();
    let output = failed_command(
        Command::new(env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v2"))
            .arg("reopen")
            .arg(&socket)
            .arg(&log)
            .arg(&expected_file),
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("lock authority namespace"));
    assert!(!socket.exists());
    let first = checkpoint();
    owner.compare_and_advance_checked(None, first).unwrap();
    assert_eq!(owner.load_checked([1; 32]).unwrap(), Some(first));
}
