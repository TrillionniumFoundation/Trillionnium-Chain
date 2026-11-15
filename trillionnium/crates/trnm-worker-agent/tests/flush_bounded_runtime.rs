//! Exercise the compiled FlushSubmissions entry point, including both stages.
#![cfg(unix)]
use std::{
    fs,
    path::Path,
    process::{Command, Output},
    time::{Duration, Instant},
};

fn create_submission(root: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-worker-agent"))
        .args([
            "run-once",
            "--worker",
            "bounded-flush",
            "--payload",
            "private-result",
            "--submit",
        ])
        .arg("--state")
        .arg(root.join("state.json"))
        .arg("--submit-log")
        .arg(root.join("submission.jsonl"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn flush(root: &Path, mode: &str) -> (Output, Duration) {
    let adapter = root.join("adapter.py");
    fs::write(
        &adapter,
        r#"import pathlib, sys, time
root, mode, action = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
with (root / 'calls.txt').open('a') as log:
    log.write(action + '\n')
if mode == 'output':
    sys.stdout.write('x' * (9 * 1024 * 1024))
    sys.stdout.flush()
if mode == action or mode == 'output':
    time.sleep(4)
print('tx_hash=0x' + 'ab' * 32)
"#,
    )
    .unwrap();
    let spec = format!(
        "python3 {} {} {}",
        shell_escape::escape(adapter.to_string_lossy()),
        shell_escape::escape(root.to_string_lossy()),
        mode
    );
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-worker-agent"))
        .args([
            "flush-submissions",
            "--execute",
            "--adapter-cmd",
            &spec,
            "--max-retries",
            "3",
            "--backoff-ms",
            "1",
        ])
        .arg("--submit-log")
        .arg(root.join("submission.jsonl"))
        .arg("--ingress-file")
        .arg(root.join("ingress.jsonl"))
        .arg("--ack-log")
        .arg(root.join("acks.jsonl"))
        .arg("--event-log")
        .arg(root.join("events.jsonl"))
        .arg("--progress-log")
        .arg(root.join("progress.jsonl"))
        .env(
            "TRNM_TX_ADAPTER_TIMEOUT_MS",
            if mode == "output" { "2000" } else { "250" },
        )
        .output()
        .unwrap();
    (output, started.elapsed())
}

fn assert_bounded_stage(mode: &str, calls: &str, diagnostic: &str) {
    let dir = tempfile::tempdir().unwrap();
    create_submission(dir.path());
    let original = fs::read(dir.path().join("submission.jsonl")).unwrap();
    let (output, elapsed) = flush(dir.path(), mode);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(diagnostic),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "unbounded stage: {elapsed:?}"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("calls.txt")).unwrap(),
        calls
    );
    assert!(
        !dir.path().join("acks.jsonl").exists(),
        "uncertain adapter result cannot acknowledge a task"
    );
    assert_eq!(
        fs::read(dir.path().join("submission.jsonl")).unwrap(),
        original
    );
}

#[test]
fn real_commit_timeout_stops_without_retry_or_reveal() {
    assert_bounded_stage("commit", "commit\n", "adapter timeout");
}

#[test]
fn real_reveal_timeout_stops_without_retry_or_acknowledgement() {
    assert_bounded_stage("reveal", "commit\nreveal\n", "adapter timeout");
}

#[test]
fn real_transaction_adapter_output_limit_is_enforced() {
    assert_bounded_stage("output", "commit\n", "output limit exceeded");
}

#[test]
fn replay_byte_and_record_limits_precede_adapter_effects() {
    for records in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("submission.jsonl");
        if records {
            fs::write(&path, "{}\n".repeat(100_001)).unwrap();
        } else {
            fs::File::create(&path)
                .unwrap()
                .set_len(64 * 1024 * 1024 + 1)
                .unwrap();
        }
        let (output, _) = flush(dir.path(), "commit");
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(if records {
                "bounded record count"
            } else {
                "bounded replay size"
            })
        );
        assert!(!dir.path().join("calls.txt").exists());
        assert!(!dir.path().join("progress.jsonl").exists());
    }
}

#[test]
fn fifo_replay_is_rejected_without_waiting_for_a_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("submission.jsonl");
    assert!(Command::new("python3")
        .args(["-c", "import os,sys; os.mkfifo(sys.argv[1])"])
        .arg(&path)
        .status()
        .unwrap()
        .success());
    let (output, elapsed) = flush(dir.path(), "commit");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("regular file"));
    assert!(elapsed < Duration::from_secs(3));
    assert!(!dir.path().join("calls.txt").exists());
}
