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

const HELPER: &str = env!("CARGO_BIN_EXE_trnm-poco-recovery-kill-helper");
const SIGKILL: i32 = 9;
const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(30);
const RESTART_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const ROUTES: &[&str] = &["proposal", "synced"];
const REASONS: &[&str] = &["state", "receipts"];
const PHASES: &[&str] = &[
    "obligation_callback_pending",
    "obligation_delivered",
    "completion_delivered",
    "completion_acked",
];
const EXPECTED_CASES: &[&str] = &[
    "proposal/state/obligation_callback_pending",
    "proposal/state/obligation_delivered",
    "proposal/state/completion_delivered",
    "proposal/state/completion_acked",
    "proposal/receipts/obligation_callback_pending",
    "proposal/receipts/obligation_delivered",
    "proposal/receipts/completion_delivered",
    "proposal/receipts/completion_acked",
    "synced/state/obligation_callback_pending",
    "synced/state/obligation_delivered",
    "synced/state/completion_delivered",
    "synced/state/completion_acked",
    "synced/receipts/obligation_callback_pending",
    "synced/receipts/obligation_delivered",
    "synced/receipts/completion_delivered",
    "synced/receipts/completion_acked",
];

#[test]
fn real_process_sigkill_matrix_recovers_o_p_o_d_c_d_and_c_k() {
    let mut completed_cases = BTreeSet::new();
    for route in ROUTES {
        for reason in REASONS {
            for phase in PHASES {
                let case_id = format!("{route}/{reason}/{phase}");
                assert!(
                    completed_cases.insert(case_id.clone()),
                    "duplicate SIGKILL matrix case: {case_id}"
                );
                exercise_sigkill_case_v0(route, reason, phase);
            }
        }
    }
    let expected_cases = EXPECTED_CASES
        .iter()
        .map(|case| (*case).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(EXPECTED_CASES.len(), 16);
    assert_eq!(completed_cases, expected_cases);
}

fn exercise_sigkill_case_v0(route: &str, reason: &str, phase: &str) {
    let root = protected_temp_root_v0();
    let case_id = format!("{route}/{reason}/{phase}");
    let mut child = Command::new(HELPER)
        .args(["prepare"])
        .arg(root.path())
        .args([route, reason, phase])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn SIGKILL helper for {case_id}: {error}"));

    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("helper stdout missing for {case_id}"));
    let (checkpoint_sender, checkpoint_receiver) = mpsc::channel();
    let checkpoint_reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut checkpoint = String::new();
        let result = reader
            .read_line(&mut checkpoint)
            .map(|bytes| (bytes != 0).then_some(checkpoint));
        let _ = checkpoint_sender.send(result);
    });
    let checkpoint = match checkpoint_receiver.recv_timeout(CHECKPOINT_TIMEOUT) {
        Ok(Ok(Some(checkpoint))) => checkpoint,
        Ok(Ok(None)) => {
            let status = child
                .wait()
                .unwrap_or_else(|error| panic!("wait for early helper exit {case_id}: {error}"));
            let stderr = take_child_stderr_v0(&mut child);
            panic!(
                "helper exited before checkpoint: case={case_id} status={status:?} stderr={stderr}"
            );
        }
        Ok(Err(error)) => {
            let _ = child.kill();
            let status = child.wait().unwrap_or_else(|wait_error| {
                panic!("wait after checkpoint read failure {case_id}: {wait_error}")
            });
            let stderr = take_child_stderr_v0(&mut child);
            panic!(
                "read helper checkpoint for {case_id}: {error}; status={status:?} stderr={stderr}"
            );
        }
        Err(error) => {
            let _ = child.kill();
            let status = child.wait().unwrap_or_else(|wait_error| {
                panic!("wait after checkpoint timeout {case_id}: {wait_error}")
            });
            let stderr = take_child_stderr_v0(&mut child);
            panic!("checkpoint timeout for {case_id}: {error}; status={status:?} stderr={stderr}");
        }
    };
    checkpoint_reader
        .join()
        .expect("checkpoint reader thread must not panic");
    let checkpoint_prefix = format!("checkpoint_v0={case_id};");
    let exact_identity = checkpoint
        .strip_prefix(&checkpoint_prefix)
        .and_then(|value| value.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("checkpoint identity was missing for {case_id}: {checkpoint:?}"));
    assert!(exact_identity.starts_with("identity_v0="));
    assert!(exact_identity.contains(";completion_revision="));
    assert!(exact_identity.contains(";watermark_v0="));
    assert!(
        child
            .try_wait()
            .unwrap_or_else(|error| panic!("poll helper for {case_id}: {error}"))
            .is_none(),
        "helper must still hold every store at {case_id}"
    );

    child
        .kill()
        .unwrap_or_else(|error| panic!("send SIGKILL for {case_id}: {error}"));
    let status = child
        .wait()
        .unwrap_or_else(|error| panic!("wait for killed helper {case_id}: {error}"));
    let stderr = take_child_stderr_v0(&mut child);
    assert_eq!(
        status.signal(),
        Some(SIGKILL),
        "checkpoint child was not killed by SIGKILL for {case_id}; status={status:?} stderr={stderr}"
    );

    let recovered = run_helper_v0("recover", root.path(), route, reason, Some(phase));
    assert_success_v0(&recovered, &format!("recover {case_id}"));
    assert_eq!(
        String::from_utf8(recovered.stdout).expect("recovery output is UTF-8"),
        format!("recovered_v0={case_id};{exact_identity}\n")
    );

    let verified = run_helper_v0("verify", root.path(), route, reason, None);
    assert_success_v0(&verified, &format!("verify {case_id}"));
    assert_eq!(
        String::from_utf8(verified.stdout).expect("verification output is UTF-8"),
        format!("verified_v0={route}/{reason}/completion_acked;{exact_identity}\n")
    );
}

fn protected_temp_root_v0() -> TempDir {
    let root = TempDir::new().expect("create SIGKILL matrix root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("protect SIGKILL matrix root");
    root
}

fn run_helper_v0(
    command: &str,
    root: &Path,
    route: &str,
    reason: &str,
    phase: Option<&str>,
) -> Output {
    let mut process = Command::new(HELPER);
    process.arg(command).arg(root).args([route, reason]);
    if let Some(phase) = phase {
        process.arg(phase);
    }
    let mut child = process
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn helper command {command}: {error}"));
    let deadline = Instant::now() + RESTART_TIMEOUT;
    let status = loop {
        match child
            .try_wait()
            .unwrap_or_else(|error| panic!("poll helper command {command}: {error}"))
        {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let status = child.wait().unwrap_or_else(|error| {
                    panic!("reap timed-out helper command {command}: {error}")
                });
                let stderr = take_child_stderr_v0(&mut child);
                panic!(
                    "helper command {command} exceeded {RESTART_TIMEOUT:?}; status={status:?} stderr={stderr}"
                );
            }
            None => thread::sleep(PROCESS_POLL_INTERVAL),
        }
    };
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("completed helper stdout must exist")
        .read_to_end(&mut stdout)
        .unwrap_or_else(|error| panic!("read helper command {command} stdout: {error}"));
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("completed helper stderr must exist")
        .read_to_end(&mut stderr)
        .unwrap_or_else(|error| panic!("read helper command {command} stderr: {error}"));
    Output {
        status,
        stdout,
        stderr,
    }
}

fn assert_success_v0(output: &Output, stage: &str) {
    assert!(
        output.status.success(),
        "{stage} failed: status={:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn take_child_stderr_v0(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        stream
            .read_to_string(&mut stderr)
            .expect("read killed helper stderr");
    }
    stderr
}
