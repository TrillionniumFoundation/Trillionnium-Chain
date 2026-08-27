#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Read},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;

const HELPER: &str = env!("CARGO_BIN_EXE_trnm-poco-timeout-signing-kill-helper");
const SIGKILL: i32 = 9;
const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(30);
const RESTART_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const PHASES: &[&str] = &[
    "safety_persisted_before_storage_ack",
    "signature_requested_before_journal",
    "producer_entered_after_intent_watermark",
    "producer_generated_before_return",
    "signature_persisted_before_signature_ready",
    "broadcast_produced_before_return",
];
const EXPECTED_PHASES: &[&str] = &[
    "safety_persisted_before_storage_ack",
    "signature_requested_before_journal",
    "producer_entered_after_intent_watermark",
    "producer_generated_before_return",
    "signature_persisted_before_signature_ready",
    "broadcast_produced_before_return",
];

#[test]
fn real_process_sigkill_matrix_replays_exact_bounded_timeout_signing() {
    let mut completed = BTreeSet::new();
    for phase in PHASES {
        assert!(
            completed.insert((*phase).to_owned()),
            "duplicate timeout SIGKILL phase: {phase}"
        );
        exercise_sigkill_phase_v0(phase);
    }
    let expected = EXPECTED_PHASES
        .iter()
        .map(|phase| (*phase).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(EXPECTED_PHASES.len(), 6);
    assert_eq!(completed, expected);
}

#[test]
fn real_process_reopen_rejects_valid_lower_watermark_after_recovery() {
    // Stop after the intent watermark has been durably advanced to sequence
    // one.  The recovered process advances to sequence two; restoring only
    // the old, still-valid record must then be fenced by the independent
    // watermark anchor on the next process open.
    let phase = "producer_entered_after_intent_watermark";
    let root = protected_temp_root_v0();
    let mut child = Command::new(HELPER)
        .args([
            "prepare",
            root.path().to_str().expect("root path is UTF-8"),
            phase,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn timeout helper for rollback test: {error}"));

    let stdout = child
        .stdout
        .take()
        .expect("rollback helper stdout must exist");
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut checkpoint = String::new();
        let result = reader
            .read_line(&mut checkpoint)
            .map(|bytes| (bytes != 0).then_some(checkpoint));
        let _ = sender.send(result);
    });
    let checkpoint = match receiver.recv_timeout(CHECKPOINT_TIMEOUT) {
        Ok(Ok(Some(checkpoint))) => checkpoint,
        Ok(Ok(None)) => terminate_after_checkpoint_failure_v0(
            &mut child,
            phase,
            "rollback helper closed checkpoint output before checkpoint",
        ),
        Ok(Err(error)) => terminate_after_checkpoint_failure_v0(
            &mut child,
            phase,
            &format!("rollback helper checkpoint read failed: {error}"),
        ),
        Err(error) => terminate_after_checkpoint_failure_v0(
            &mut child,
            phase,
            &format!("rollback helper checkpoint timeout: {error}"),
        ),
    };
    reader
        .join()
        .expect("rollback checkpoint reader thread must not panic");
    assert!(
        checkpoint.starts_with("checkpoint_v0=producer_entered_after_intent_watermark;"),
        "rollback helper emitted an unexpected checkpoint: {checkpoint:?}"
    );

    let watermark_path = root.path().join("watermark/signer-watermark.v0");
    let lower_record = fs::read(&watermark_path)
        .expect("read sequence-one watermark before killing rollback helper");
    child
        .kill()
        .expect("SIGKILL rollback helper after sequence-one checkpoint");
    let status = child.wait().expect("wait for killed rollback helper");
    let stderr = take_child_stderr_v0(&mut child);
    assert_eq!(
        status.signal(),
        Some(SIGKILL),
        "rollback helper was not SIGKILLed: status={status:?} stderr={stderr}"
    );

    let recovered = run_helper_v0("recover", root.path(), phase);
    assert_success_v0(&recovered, "recover watermark before rollback");
    fs::write(&watermark_path, lower_record)
        .expect("restore a coherent but lower watermark record");

    let rejected = run_helper_v0("recover", root.path(), phase);
    assert!(
        !rejected.status.success(),
        "reopening after a valid lower watermark unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr),
    );
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("InvalidPersistedState"),
        "rollback rejection did not identify the persisted-state fence: stdout={} stderr={}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr),
    );
}

fn exercise_sigkill_phase_v0(phase: &str) {
    let root = protected_temp_root_v0();
    let mut child = Command::new(HELPER)
        .args(["prepare"])
        .arg(root.path())
        .arg(phase)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn timeout SIGKILL helper for {phase}: {error}"));

    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("timeout helper stdout missing for {phase}"));
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut checkpoint = String::new();
        let result = reader
            .read_line(&mut checkpoint)
            .map(|bytes| (bytes != 0).then_some(checkpoint));
        let _ = sender.send(result);
    });
    let checkpoint = match receiver.recv_timeout(CHECKPOINT_TIMEOUT) {
        Ok(Ok(Some(checkpoint))) => checkpoint,
        Ok(Ok(None)) => terminate_after_checkpoint_failure_v0(
            &mut child,
            phase,
            "helper closed checkpoint output before checkpoint",
        ),
        Ok(Err(error)) => terminate_after_checkpoint_failure_v0(
            &mut child,
            phase,
            &format!("read checkpoint failed: {error}"),
        ),
        Err(error) => terminate_after_checkpoint_failure_v0(
            &mut child,
            phase,
            &format!("checkpoint timeout: {error}"),
        ),
    };
    reader
        .join()
        .expect("timeout checkpoint reader thread must not panic");
    let prefix = format!("checkpoint_v0={phase};fingerprint=");
    if !checkpoint.starts_with(&prefix)
        || !checkpoint.contains(";auth_revision=1;signing_root=")
        || !checkpoint.ends_with('\n')
    {
        terminate_after_checkpoint_failure_v0(
            &mut child,
            phase,
            &format!("checkpoint did not bind exact phase/intent facts: {checkpoint:?}"),
        );
    }
    match child.try_wait() {
        Ok(None) => {}
        Ok(Some(status)) => {
            let stderr = take_child_stderr_v0(&mut child);
            panic!(
                "timeout helper exited instead of retaining its stores at {phase}; status={status:?} stderr={stderr}"
            );
        }
        Err(error) => terminate_after_checkpoint_failure_v0(
            &mut child,
            phase,
            &format!("poll timeout helper failed: {error}"),
        ),
    }

    child
        .kill()
        .unwrap_or_else(|error| panic!("send SIGKILL for timeout phase {phase}: {error}"));
    let status = child
        .wait()
        .unwrap_or_else(|error| panic!("wait for killed timeout helper {phase}: {error}"));
    let stderr = take_child_stderr_v0(&mut child);
    assert_eq!(
        status.signal(),
        Some(SIGKILL),
        "timeout child was not killed by SIGKILL for {phase}; status={status:?} stderr={stderr}"
    );

    let recovered = run_helper_v0("recover", root.path(), phase);
    assert_success_v0(&recovered, &format!("recover timeout phase {phase}"));
    let recovered_stdout =
        String::from_utf8(recovered.stdout).expect("timeout recovery output is UTF-8");
    assert!(
        recovered_stdout.starts_with(&expected_recovery_prefix_v0(phase)),
        "unexpected timeout recovery facts for {phase}: {recovered_stdout:?}"
    );
    let recovered_identity = exact_identity_v0(&recovered_stdout, phase);

    let verified = run_helper_v0("verify", root.path(), phase);
    assert_success_v0(&verified, &format!("verify timeout phase {phase}"));
    let verified_stdout =
        String::from_utf8(verified.stdout).expect("timeout verification output is UTF-8");
    let verify_prefix = format!("verified_v0={phase};pre_stage=1:2:2;producer_calls=0;");
    assert!(
        verified_stdout.starts_with(&verify_prefix),
        "unexpected timeout verification facts for {phase}: {verified_stdout:?}"
    );
    let verified_identity = exact_identity_v0(&verified_stdout, phase);
    assert_eq!(recovered_identity, verified_identity);
    assert!(recovered_identity.contains(";auth_revision:1;"));
    assert!(recovered_identity.contains(";epoch:0;view:1;kind:2;"));
    assert!(recovered_identity.contains(";high_qc_epoch:0;high_qc_view:0;"));
    assert!(recovered_identity.contains(";high_qc_height:0;"));
    assert!(recovered_identity.contains(";signature:"));
}

fn expected_recovery_prefix_v0(phase: &str) -> String {
    let (stage, calls) = match phase {
        "safety_persisted_before_storage_ack" | "signature_requested_before_journal" => {
            ("0:0:0", 1)
        }
        "producer_entered_after_intent_watermark" | "producer_generated_before_return" => {
            ("1:1:1", 1)
        }
        "signature_persisted_before_signature_ready" | "broadcast_produced_before_return" => {
            ("1:2:2", 0)
        }
        _ => panic!("unknown timeout SIGKILL phase: {phase}"),
    };
    format!("recovered_v0={phase};pre_stage={stage};producer_calls={calls};")
}

fn exact_identity_v0<'a>(output: &'a str, phase: &str) -> &'a str {
    let start = output
        .find("identity_v0=")
        .unwrap_or_else(|| panic!("timeout output lacks exact identity for {phase}: {output:?}"));
    output[start..]
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("timeout output lacks one terminal newline for {phase}"))
}

fn protected_temp_root_v0() -> TempDir {
    let root = TempDir::new().expect("create timeout SIGKILL matrix root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("protect timeout SIGKILL matrix root");
    root
}

fn run_helper_v0(command: &str, root: &Path, phase: &str) -> Output {
    let mut child = Command::new(HELPER)
        .arg(command)
        .arg(root)
        .arg(phase)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn timeout helper command {command}: {error}"));
    let deadline = Instant::now() + RESTART_TIMEOUT;
    let status = loop {
        match child
            .try_wait()
            .unwrap_or_else(|error| panic!("poll timeout helper command {command}: {error}"))
        {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let status = child.wait().unwrap_or_else(|error| {
                    panic!("reap timed-out timeout helper command {command}: {error}")
                });
                let stderr = take_child_stderr_v0(&mut child);
                panic!(
                    "timeout helper command {command} exceeded {RESTART_TIMEOUT:?}; status={status:?} stderr={stderr}"
                );
            }
            None => thread::sleep(PROCESS_POLL_INTERVAL),
        }
    };
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("completed timeout helper stdout must exist")
        .read_to_end(&mut stdout)
        .unwrap_or_else(|error| panic!("read timeout helper {command} stdout: {error}"));
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("completed timeout helper stderr must exist")
        .read_to_end(&mut stderr)
        .unwrap_or_else(|error| panic!("read timeout helper {command} stderr: {error}"));
    Output {
        status,
        stdout,
        stderr,
    }
}

fn assert_success_v0(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: status={:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn terminate_after_checkpoint_failure_v0(child: &mut Child, phase: &str, reason: &str) -> ! {
    let _ = child.kill();
    let status = child
        .wait()
        .unwrap_or_else(|error| panic!("wait after timeout checkpoint failure {phase}: {error}"));
    let stderr = take_child_stderr_v0(child);
    panic!("{reason}; phase={phase} status={status:?} stderr={stderr}");
}

fn take_child_stderr_v0(child: &mut Child) -> String {
    let mut stderr = Vec::new();
    if let Some(mut handle) = child.stderr.take() {
        handle
            .read_to_end(&mut stderr)
            .expect("read timeout helper stderr");
    }
    String::from_utf8_lossy(&stderr).into_owned()
}
