#![forbid(unsafe_code)]
#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
    process::{Command, Output, Stdio},
};

use tempfile::TempDir;

#[cfg(feature = "g2-process-test-support")]
use std::{
    io::{BufRead, BufReader, Read},
    os::unix::process::ExitStatusExt,
    process::Child,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
#[cfg(feature = "g2-process-test-support")]
use trnm_poco_node::PocoNodeG2ProcessFixtureV2;

const NODE: &str = env!("CARGO_BIN_EXE_trnm-poco-node");
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const PROCESS_SOURCE: &str = include_str!("../src/g2_manifest_bound_process_v2.rs");
#[cfg(feature = "g2-process-test-support")]
const READY_TIMEOUT_V2: Duration = Duration::from_secs(30);
#[cfg(feature = "g2-process-test-support")]
const EXIT_TIMEOUT_V2: Duration = Duration::from_secs(10);

fn private_root_v2() -> TempDir {
    let root = tempfile::tempdir().expect("create private G2 process contract root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("set private G2 process contract root mode");
    root
}

fn run_node_v2(arguments: &[&str]) -> Output {
    Command::new(NODE)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run normal trnm-poco-node binary")
}

fn stderr_v2(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("node stderr is UTF-8")
}

#[test]
fn normal_node_default_and_unknown_commands_remain_fail_closed_v2() {
    for arguments in [&[][..], &["unknown-g2-command"][..]] {
        let output = run_node_v2(arguments);
        assert!(!output.status.success());
        let stderr = stderr_v2(&output);
        assert!(stderr.contains("trnm-poco-node startup refused"));
        assert!(stderr.contains("production_candidate=false"));
        assert!(stderr.contains("host_complete=false"));
    }
}

#[test]
fn candidate_commands_require_their_complete_explicit_contract_v2() {
    let prepare = run_node_v2(&["prepare-g2-manifest-bound-candidate-v2"]);
    assert!(!prepare.status.success());
    assert!(stderr_v2(&prepare)
        .contains("expected <absolute-run-root> <absolute-manifest> <manifest-sha256>"));

    let run = run_node_v2(&["run-g2-manifest-bound-candidate-v2"]);
    assert!(!run.status.success());
    assert!(stderr_v2(&run).contains(
        "expected <absolute-run-root> <absolute-manifest> <manifest-sha256> <process-pin-checksum>"
    ));
}

#[test]
fn missing_and_symlink_manifest_fail_before_any_durable_process_state_v2() {
    let root = private_root_v2();
    let missing = root.path().join("missing-manifest.bin");
    let output = run_node_v2(&[
        "prepare-g2-manifest-bound-candidate-v2",
        root.path().to_str().expect("root UTF-8"),
        missing.to_str().expect("missing path UTF-8"),
        ZERO_SHA256,
    ]);
    assert!(!output.status.success());
    assert!(stderr_v2(&output).contains("candidate prepare refused"));
    require_no_process_state_v2(root.path());

    let direct = root.path().join("direct-manifest.bin");
    fs::write(&direct, b"not-a-canonical-manifest").expect("write direct manifest bytes");
    fs::set_permissions(&direct, fs::Permissions::from_mode(0o600))
        .expect("set direct manifest mode");
    let linked = root.path().join("linked-manifest.bin");
    symlink(&direct, &linked).expect("create manifest symlink");
    let output = run_node_v2(&[
        "prepare-g2-manifest-bound-candidate-v2",
        root.path().to_str().expect("root UTF-8"),
        linked.to_str().expect("symlink path UTF-8"),
        ZERO_SHA256,
    ]);
    assert!(!output.status.success());
    assert!(stderr_v2(&output).contains("candidate prepare refused"));
    require_no_process_state_v2(root.path());
}

fn require_no_process_state_v2(root: &Path) {
    for name in [
        "g2-manifest-bound-process-v2.lock",
        "g2-manifest-bound-process-pin-v2.bin",
        ".g2-manifest-bound-process-pin-v2.tmp",
    ] {
        assert!(
            !root.join(name).exists(),
            "unexpected process state: {name}"
        );
    }
}

#[test]
fn source_contract_contains_idempotent_prepare_and_response_loss_reconciliation_v2() {
    for required in [
        "enum PrepareDurablePrefixV2",
        "PrepareDurablePrefixV2::Empty",
        "PrepareDurablePrefixV2::LockOnly",
        "PrepareDurablePrefixV2::LockAndT0dAnchor",
        "PrepareDurablePrefixV2::CompleteAnchors",
        "revalidate_fresh_anchor_only_v2",
        "ExternalProcessPinAuthenticationV2::AnchorOfCurrentUniqueSuccessor",
        "advance_or_reconcile_v2",
        "current process target is accompanied by a foreign temporary state",
        "old external anchor did not authenticate the exact durable successor",
        "wait_for_control_eof_v2",
    ] {
        assert!(
            PROCESS_SOURCE.contains(required),
            "missing contract: {required}"
        );
    }
    assert!(!PROCESS_SOURCE.contains("thread::park()"));
}

#[test]
fn source_contract_binds_target_to_exact_t0d_successor_v2() {
    for required in [
        "target_t0d.journal_id_v2() == t0d_anchor.journal_id_v2()",
        "target_t0d.scope_v2() == t0d_anchor.scope_v2()",
        "target_t0d.scope_v2() == self.body.process_scope",
        "target_t0d.generation_v2() == expected_target_generation",
        "target_t0d.checksum_v2() != t0d_anchor.checksum_v2()",
        "target.predecessor_process_checksum == self.anchor_checksum_v2()?",
        "target.candidate_height == expected_candidate_height",
    ] {
        assert!(
            PROCESS_SOURCE.contains(required),
            "missing schema bind: {required}"
        );
    }
}

#[cfg(feature = "g2-process-test-support")]
fn prepare_real_fixture_v2(fixture: &PocoNodeG2ProcessFixtureV2) -> (String, String) {
    let output = Command::new(NODE)
        .arg("prepare-g2-manifest-bound-candidate-v2")
        .arg(fixture.run_root_v2())
        .arg(fixture.manifest_path_v2())
        .arg(fixture.manifest_sha256_v2())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("prepare real G2 process fixture");
    assert!(
        output.status.success(),
        "real prepare failed: {}",
        stderr_v2(&output)
    );
    let line = String::from_utf8(output.stdout).expect("PREPARED output is UTF-8");
    assert!(line.starts_with("PREPARED candidate_only=true "));
    assert!(line.ends_with('\n'));
    assert!(line.contains("network=false signing=false voting=false core=false production=false"));
    let anchor = field_v2(&line, "process_pin_checksum");
    assert_eq!(anchor.len(), 64);
    (line, anchor)
}

#[cfg(feature = "g2-process-test-support")]
fn spawn_real_run_v2(fixture: &PocoNodeG2ProcessFixtureV2, process_pin: &str) -> Child {
    Command::new(NODE)
        .arg("run-g2-manifest-bound-candidate-v2")
        .arg(fixture.run_root_v2())
        .arg(fixture.manifest_path_v2())
        .arg(fixture.manifest_sha256_v2())
        .arg(process_pin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn real G2 candidate process")
}

#[cfg(feature = "g2-process-test-support")]
fn run_real_output_v2(fixture: &PocoNodeG2ProcessFixtureV2, process_pin: &str) -> Output {
    Command::new(NODE)
        .arg("run-g2-manifest-bound-candidate-v2")
        .arg(fixture.run_root_v2())
        .arg(fixture.manifest_path_v2())
        .arg(fixture.manifest_sha256_v2())
        .arg(process_pin)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run real G2 candidate process to completion")
}

#[cfg(feature = "g2-process-test-support")]
fn read_ready_v2(child: &mut Child, label: &str) -> String {
    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("{label} stdout missing"));
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut line = String::new();
        let result = stdout.read_line(&mut line).map(|count| (count, line));
        let _ = sender.send(result);
    });
    let line = match receiver.recv_timeout(READY_TIMEOUT_V2) {
        Ok(Ok((count, line))) if count > 0 => line,
        Ok(Ok((_count, _line))) => terminate_child_v2(child, label, "stdout closed before READY"),
        Ok(Err(cause)) => terminate_child_v2(child, label, &format!("READY read failed: {cause}")),
        Err(cause) => terminate_child_v2(child, label, &format!("READY timeout: {cause}")),
    };
    reader.join().expect("READY reader thread does not panic");
    assert!(
        line.starts_with("READY candidate_only=true "),
        "{label}: {line:?}"
    );
    assert!(line.ends_with('\n'));
    assert!(line.contains("network=false signing=false voting=false core=false production=false"));
    assert!(child.try_wait().expect("poll READY child").is_none());
    line
}

#[cfg(feature = "g2-process-test-support")]
fn terminate_child_v2(child: &mut Child, label: &str, detail: &str) -> ! {
    let _ = child.kill();
    let status = child.wait().ok();
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        let _ = stream.read_to_string(&mut stderr);
    }
    panic!("{label}: {detail}; status={status:?}; stderr={stderr}")
}

#[cfg(feature = "g2-process-test-support")]
fn wait_for_exit_v2(child: &mut Child, label: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + EXIT_TIMEOUT_V2;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => terminate_child_v2(child, label, "clean EOF exit timed out"),
            Err(cause) => terminate_child_v2(child, label, &format!("exit poll failed: {cause}")),
        }
    }
}

#[cfg(feature = "g2-process-test-support")]
fn field_v2(line: &str, name: &str) -> String {
    let prefix = format!("{name}=");
    line.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing {name} in {line:?}"))
        .to_owned()
}

#[cfg(feature = "g2-process-test-support")]
fn assert_refused_without_ready_v2(output: Output, label: &str) {
    assert!(!output.status.success(), "{label} unexpectedly succeeded");
    let stderr = stderr_v2(&output);
    assert!(
        !String::from_utf8(output.stdout)
            .expect("refusal stdout is UTF-8")
            .contains("READY candidate_only=true"),
        "{label} emitted READY"
    );
    assert!(stderr.contains("candidate run refused"));
}

#[cfg(feature = "g2-process-test-support")]
fn reach_target_and_kill_v2(
    fixture: &PocoNodeG2ProcessFixtureV2,
    anchor: &str,
    label: &str,
) -> String {
    let mut child = spawn_real_run_v2(fixture, anchor);
    let ready = read_ready_v2(&mut child, label);
    let target = field_v2(&ready, "process_pin_checksum");
    assert_ne!(target, anchor, "process target must differ from its anchor");
    child.kill().expect("SIGKILL real G2 candidate process");
    let status = child.wait().expect("reap SIGKILLed G2 candidate process");
    assert_eq!(status.signal(), Some(9));
    target
}

#[cfg(feature = "g2-process-test-support")]
fn persist_replacement_v2(path: &Path, raw: &[u8]) {
    fs::write(path, raw).unwrap_or_else(|cause| panic!("replace {}: {cause}", path.display()));
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .unwrap_or_else(|cause| panic!("fsync {}: {cause}", path.display()));
    fs::File::open(path.parent().expect("replacement path has parent"))
        .and_then(|directory| directory.sync_all())
        .expect("fsync replacement parent");
}

#[cfg(feature = "g2-process-test-support")]
#[test]
fn real_five_source_two_process_response_loss_matrix_v2() {
    let fixture = PocoNodeG2ProcessFixtureV2::build_v2();
    let (prepared, anchor) = prepare_real_fixture_v2(&fixture);
    let (prepared_retry, retry_anchor) = prepare_real_fixture_v2(&fixture);
    assert_eq!(
        prepared_retry, prepared,
        "prepare retry must be byte-stable"
    );
    assert_eq!(retry_anchor, anchor);

    let mut process_one = spawn_real_run_v2(&fixture, &anchor);
    let ready_one = read_ready_v2(&mut process_one, "P1");
    let target_one = field_v2(&ready_one, "process_pin_checksum");
    let pid_one = field_v2(&ready_one, "pid");
    assert_ne!(
        target_one, anchor,
        "PREPARED anchor is not the READY target"
    );

    let duplicate = run_real_output_v2(&fixture, &anchor);
    assert!(
        stderr_v2(&duplicate).contains("process lock is already held or unavailable"),
        "duplicate process did not fail at the retained OS lock"
    );
    assert_refused_without_ready_v2(duplicate, "duplicate lock contender");

    process_one.kill().expect("SIGKILL P1");
    let killed = process_one.wait().expect("reap P1");
    assert_eq!(killed.signal(), Some(9));

    let mut process_two = spawn_real_run_v2(&fixture, &anchor);
    let ready_two = read_ready_v2(&mut process_two, "P2 old-anchor recovery");
    assert_eq!(field_v2(&ready_two, "process_pin_checksum"), target_one);
    assert_ne!(field_v2(&ready_two, "pid"), pid_one);
    drop(process_two.stdin.take());
    let clean = wait_for_exit_v2(&mut process_two, "P2 EOF shutdown");
    assert!(clean.success(), "P2 EOF shutdown failed: {clean:?}");
}

#[cfg(feature = "g2-process-test-support")]
#[test]
fn real_fixture_drift_temp_and_rollback_subset_fail_before_ready_v2() {
    let source_drift = PocoNodeG2ProcessFixtureV2::build_v2();
    let (_prepared, source_anchor) = prepare_real_fixture_v2(&source_drift);
    fs::set_permissions(source_drift.da_path_v2(), fs::Permissions::from_mode(0o660))
        .expect("make DA source mode unsafe");
    assert_refused_without_ready_v2(
        run_real_output_v2(&source_drift, &source_anchor),
        "DA source drift",
    );

    let canonical_drift = PocoNodeG2ProcessFixtureV2::build_v2();
    let (_prepared, canonical_anchor) = prepare_real_fixture_v2(&canonical_drift);
    fs::set_permissions(
        canonical_drift.canonical_order_path_v2(),
        fs::Permissions::from_mode(0o660),
    )
    .expect("make canonical Order mode unsafe");
    assert_refused_without_ready_v2(
        run_real_output_v2(&canonical_drift, &canonical_anchor),
        "canonical Order drift",
    );

    let malformed_temp = PocoNodeG2ProcessFixtureV2::build_v2();
    let (_prepared, temp_anchor) = prepare_real_fixture_v2(&malformed_temp);
    let temp_path = malformed_temp.process_pin_temp_path_v2();
    fs::write(&temp_path, b"foreign-process-target").expect("write malformed process temp");
    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
        .expect("set malformed process temp mode");
    fs::File::open(malformed_temp.run_root_v2())
        .and_then(|directory| directory.sync_all())
        .expect("fsync malformed process temp parent");
    assert_refused_without_ready_v2(
        run_real_output_v2(&malformed_temp, &temp_anchor),
        "malformed process temp",
    );

    let process_rollback = PocoNodeG2ProcessFixtureV2::build_v2();
    let (_prepared, process_anchor) = prepare_real_fixture_v2(&process_rollback);
    let anchor_bytes = fs::read(process_rollback.process_pin_path_v2())
        .expect("read durable process anchor bytes");
    let process_target =
        reach_target_and_kill_v2(&process_rollback, &process_anchor, "process rollback setup");
    persist_replacement_v2(&process_rollback.process_pin_path_v2(), &anchor_bytes);
    assert_refused_without_ready_v2(
        run_real_output_v2(&process_rollback, &process_target),
        "externally observed process target rollback",
    );

    let t0d_rollback = PocoNodeG2ProcessFixtureV2::build_v2();
    let (_prepared, t0d_anchor) = prepare_real_fixture_v2(&t0d_rollback);
    let t0d_anchor_bytes =
        fs::read(t0d_rollback.t0d_journal_path_v2()).expect("read durable T0-D anchor bytes");
    let t0d_target = reach_target_and_kill_v2(&t0d_rollback, &t0d_anchor, "T0-D rollback setup");
    persist_replacement_v2(t0d_rollback.t0d_journal_path_v2(), &t0d_anchor_bytes);
    assert_refused_without_ready_v2(
        run_real_output_v2(&t0d_rollback, &t0d_target),
        "externally observed T0-D target rollback",
    );
}
