#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;

const HELPER: &str = env!("CARGO_BIN_EXE_trnm-poco-finalization-intent-kill-helper");
const SIGKILL: i32 = 9;
const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(30);
const RESTART_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const STORE_NAME: &str = "validation.sqlite3";
const MARKER_SUFFIX: &str = ".finalization.pending.v0";
const TEMP_SUFFIX: &str = ".finalization.pending.v0.tmp";

const WRITE_PHASES: &[&str] = &[
    "write_temp_fsynced_before_publish",
    "write_published_before_temp_cleanup",
    "write_complete_before_return",
];
const CLEAR_PHASES: &[&str] = &[
    "clear_unlinked_before_parent_fsync",
    "clear_complete_before_return",
];

#[test]
fn finalization_intent_real_process_sigkill_matrix_repairs_only_the_exact_tuple_v1() {
    let mut completed = BTreeSet::new();
    for phase in WRITE_PHASES {
        assert!(completed.insert((*phase).to_owned()));
        exercise_sigkill_phase_v1("write", phase);
    }
    for phase in CLEAR_PHASES {
        assert!(completed.insert((*phase).to_owned()));
        exercise_sigkill_phase_v1("clear", phase);
    }
    let expected = WRITE_PHASES
        .iter()
        .chain(CLEAR_PHASES)
        .map(|phase| (*phase).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(completed, expected);
}

#[test]
fn finalization_intent_temp_tamper_after_sigkill_is_retained_and_rejected_v1() {
    let phase = "write_temp_fsynced_before_publish";
    let root = protected_temp_root_v1();
    let mut child = spawn_prepare_v1("write", root.path(), phase);
    let checkpoint = read_checkpoint_v1(&mut child, phase);
    assert_checkpoint_shape_v1(&checkpoint, phase);
    kill_at_checkpoint_v1(&mut child, phase);

    let store = root.path().join(STORE_NAME);
    let temp = suffixed_path_v1(&store, TEMP_SUFFIX);
    let marker = suffixed_path_v1(&store, MARKER_SUFFIX);
    assert!(temp.is_file());
    assert!(!marker.exists());

    let mut bytes = fs::read(&temp).expect("read exact temporary finalization marker");
    bytes[17] ^= 1;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&temp)
        .expect("reopen temporary marker for deterministic corruption");
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .expect("persist temporary marker corruption");
    drop(file);

    let rejected = run_helper_v1("recover-write", root.path(), phase);
    assert!(
        !rejected.status.success(),
        "tampered temporary publication unexpectedly recovered: stdout={} stderr={}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr),
    );
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        stderr.contains("checksum mismatch") || stderr.contains("differs from the exact fixture"),
        "tamper rejection did not identify the exact marker mismatch: {stderr}"
    );
    assert!(
        temp.is_file(),
        "failed recovery must retain the temporary evidence"
    );
    assert!(
        !marker.exists(),
        "failed recovery must not fabricate a published marker"
    );
}

fn exercise_sigkill_phase_v1(kind: &str, phase: &str) {
    let root = protected_temp_root_v1();
    let mut child = spawn_prepare_v1(kind, root.path(), phase);
    let checkpoint = read_checkpoint_v1(&mut child, phase);
    assert_checkpoint_shape_v1(&checkpoint, phase);
    let checkpoint_fingerprint = exact_fingerprint_v1(&checkpoint, phase);
    kill_at_checkpoint_v1(&mut child, phase);

    let recovered = run_helper_v1(&format!("recover-{kind}"), root.path(), phase);
    assert_success_v1(&recovered, &format!("recover {kind} phase {phase}"));
    let recovered_stdout = String::from_utf8(recovered.stdout).expect("recovery output is UTF-8");
    assert!(
        recovered_stdout.starts_with(&format!("recovered_{kind}_v1={phase};")),
        "unexpected recovery output for {phase}: {recovered_stdout:?}"
    );
    assert_eq!(
        exact_fingerprint_v1(&recovered_stdout, phase),
        checkpoint_fingerprint
    );
    let stable = if kind == "write" {
        (true, false, 1, 0, false)
    } else {
        (false, false, 0, 0, false)
    };
    assert_residue_fields_v1(&recovered_stdout, phase, stable);

    let verified = run_helper_v1(&format!("verify-{kind}"), root.path(), phase);
    assert_success_v1(&verified, &format!("verify {kind} phase {phase}"));
    let verified_stdout = String::from_utf8(verified.stdout).expect("verification output is UTF-8");
    assert!(
        verified_stdout.starts_with(&format!("verified_{kind}_v1={phase};")),
        "unexpected verification output for {phase}: {verified_stdout:?}"
    );
    assert_eq!(
        exact_fingerprint_v1(&verified_stdout, phase),
        checkpoint_fingerprint
    );
    assert_residue_fields_v1(&verified_stdout, phase, stable);
}

fn spawn_prepare_v1(kind: &str, root: &Path, phase: &str) -> Child {
    Command::new(HELPER)
        .arg(format!("prepare-{kind}"))
        .arg(root)
        .arg(phase)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn finalization-intent helper for {phase}: {error}"))
}

fn read_checkpoint_v1(child: &mut Child, phase: &str) -> String {
    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("helper stdout missing for {phase}"));
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
        Ok(Ok(None)) => terminate_after_checkpoint_failure_v1(
            child,
            phase,
            "helper closed stdout before its selected checkpoint",
        ),
        Ok(Err(error)) => terminate_after_checkpoint_failure_v1(
            child,
            phase,
            &format!("checkpoint read failed: {error}"),
        ),
        Err(error) => terminate_after_checkpoint_failure_v1(
            child,
            phase,
            &format!("checkpoint timeout: {error}"),
        ),
    };
    reader
        .join()
        .expect("checkpoint reader thread must not panic");
    match child.try_wait() {
        Ok(None) => checkpoint,
        Ok(Some(status)) => {
            let stderr = take_child_stderr_v1(child);
            panic!("helper exited instead of holding {phase}: status={status:?} stderr={stderr}");
        }
        Err(error) => terminate_after_checkpoint_failure_v1(
            child,
            phase,
            &format!("checkpoint process poll failed: {error}"),
        ),
    }
}

fn kill_at_checkpoint_v1(child: &mut Child, phase: &str) {
    child
        .kill()
        .unwrap_or_else(|error| panic!("send SIGKILL at {phase}: {error}"));
    let status = child
        .wait()
        .unwrap_or_else(|error| panic!("wait for SIGKILLed helper at {phase}: {error}"));
    let stderr = take_child_stderr_v1(child);
    assert_eq!(
        status.signal(),
        Some(SIGKILL),
        "helper was not SIGKILLed at {phase}: status={status:?} stderr={stderr}"
    );
}

fn expected_checkpoint_residue_v1(phase: &str) -> (bool, bool, u64, u64, bool) {
    match phase {
        "write_temp_fsynced_before_publish" => (false, true, 0, 1, false),
        "write_published_before_temp_cleanup" => (true, true, 2, 2, true),
        "write_complete_before_return" => (true, false, 1, 0, false),
        "clear_unlinked_before_parent_fsync" | "clear_complete_before_return" => {
            (false, false, 0, 0, false)
        }
        _ => panic!("unknown finalization-intent process phase: {phase}"),
    }
}

fn assert_checkpoint_shape_v1(output: &str, phase: &str) {
    assert!(
        output.starts_with(&format!("checkpoint_v1={phase};fingerprint=")),
        "unexpected checkpoint for {phase}: {output:?}"
    );
    assert_eq!(exact_fingerprint_v1(output, phase).len(), 64);
    assert_residue_fields_v1(output, phase, expected_checkpoint_residue_v1(phase));
    assert!(output.ends_with('\n'));
}

fn assert_residue_fields_v1(
    output: &str,
    phase: &str,
    expected_facts: (bool, bool, u64, u64, bool),
) {
    let (marker_exists, temp_exists, marker_links, temp_links, same_inode) = expected_facts;
    let expected = format!(
        ";marker={};temp={};marker_links={marker_links};temp_links={temp_links};same_inode={}",
        u8::from(marker_exists),
        u8::from(temp_exists),
        u8::from(same_inode),
    );
    assert!(
        output.contains(&expected),
        "unexpected residue fields for {phase}: expected {expected:?}, output={output:?}"
    );
}

fn exact_fingerprint_v1(output: &str, phase: &str) -> String {
    let start = output
        .find("fingerprint=")
        .unwrap_or_else(|| panic!("output lacks fingerprint for {phase}: {output:?}"))
        + "fingerprint=".len();
    let tail = &output[start..];
    let end = tail
        .find(';')
        .unwrap_or_else(|| panic!("fingerprint lacks terminator for {phase}: {output:?}"));
    let value = &tail[..end];
    assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    value.to_owned()
}

fn protected_temp_root_v1() -> TempDir {
    let root = TempDir::new().expect("create finalization-intent SIGKILL root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("protect finalization-intent SIGKILL root");
    root
}

fn run_helper_v1(command: &str, root: &Path, phase: &str) -> Output {
    let mut child = Command::new(HELPER)
        .arg(command)
        .arg(root)
        .arg(phase)
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
                let status = child
                    .wait()
                    .unwrap_or_else(|error| panic!("reap timed-out command {command}: {error}"));
                let stderr = take_child_stderr_v1(&mut child);
                panic!(
                    "helper command {command} exceeded {RESTART_TIMEOUT:?}: status={status:?} stderr={stderr}"
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
        .unwrap_or_else(|error| panic!("read helper {command} stdout: {error}"));
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("completed helper stderr must exist")
        .read_to_end(&mut stderr)
        .unwrap_or_else(|error| panic!("read helper {command} stderr: {error}"));
    Output {
        status,
        stdout,
        stderr,
    }
}

fn assert_success_v1(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: status={:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn terminate_after_checkpoint_failure_v1(child: &mut Child, phase: &str, reason: &str) -> ! {
    let _ = child.kill();
    let status = child
        .wait()
        .unwrap_or_else(|error| panic!("wait after checkpoint failure {phase}: {error}"));
    let stderr = take_child_stderr_v1(child);
    panic!("{reason}; phase={phase} status={status:?} stderr={stderr}");
}

fn take_child_stderr_v1(child: &mut Child) -> String {
    let mut stderr = Vec::new();
    if let Some(mut handle) = child.stderr.take() {
        handle
            .read_to_end(&mut stderr)
            .expect("read finalization-intent helper stderr");
    }
    String::from_utf8_lossy(&stderr).into_owned()
}

fn suffixed_path_v1(store: &Path, suffix: &str) -> PathBuf {
    let mut value = store.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}
