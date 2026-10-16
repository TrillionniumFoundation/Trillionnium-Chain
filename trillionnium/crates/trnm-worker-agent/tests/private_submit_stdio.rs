//! Real CLI behavior: a private committed salt must not leak to job streams.
#![cfg(unix)]

use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

fn cli(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-worker-agent"))
        .args(args)
        .output()
        .expect("launch actual worker binary");
    assert!(
        output.status.success(),
        "worker exited {:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn one_record(path: &Path) -> Value {
    let bytes = fs::read(path).expect("private journal");
    assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(bytes.ends_with(b"\n"));
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
    serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap()
}

#[test]
fn automatic_submit_keeps_reveal_secret_only_in_private_journal() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state.json");
    let journal = root.path().join("submitted.jsonl");
    let worker = "w';$(echo not-executed)";
    let output = cli(&[
        "run-once",
        "--state",
        state.to_str().unwrap(),
        "--worker",
        worker,
        "--payload",
        "fixed-synthetic-result",
        "--submit",
        "--submit-log",
        journal.to_str().unwrap(),
    ]);
    let stdout: Value = serde_json::from_slice(&output.stdout).unwrap();
    let record = one_record(&journal);
    let salt = record["salt_hex"].as_str().unwrap();
    assert_eq!(salt.len(), 64);
    assert_eq!(record["worker"], worker);
    assert_eq!(stdout["worker"], worker);
    assert_eq!(stdout["salt_hex"], Value::Null);
    assert_eq!(stdout["template_reveal"], Value::Null);
    assert_eq!(stdout["commit_hash"], record["commit_hash"]);
    assert_eq!(stdout["template_commit"], record["commit_cmd"]);
    for stream in [&output.stdout[..], &output.stderr[..]] {
        let rendered = String::from_utf8_lossy(stream);
        assert!(!rendered.contains(salt), "committed salt leaked to job stream");
        assert!(
            !rendered.contains("reveal-result"),
            "pre-reveal command leaked to job stream"
        );
    }
}

#[test]
fn explicit_manual_submit_hides_reveal_template_but_retains_chosen_salt() {
    let root = tempfile::tempdir().unwrap();
    let journal = root.path().join("manual.jsonl");
    let chosen_salt = "manual-private-salt-for-test";
    let result_hash = "ab".repeat(32);
    let output = cli(&[
        "commit-reveal",
        "--task-id",
        "713",
        "--worker",
        "manual-worker",
        "--result-hash",
        &result_hash,
        "--salt-hex",
        chosen_salt,
        "--submit",
        "--submit-log",
        journal.to_str().unwrap(),
    ]);
    let record = one_record(&journal);
    assert_eq!(record["salt_hex"], chosen_salt);
    assert_eq!(record["task_id"], 713);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("template_commit="));
    assert!(!text.contains(chosen_salt));
    assert!(!text.contains("template_reveal="));
    assert!(!text.contains("reveal-result"));
}

#[test]
fn explicit_non_submit_workflow_keeps_existing_manual_reveal_output() {
    let output = cli(&[
        "commit-reveal",
        "--task-id",
        "714",
        "--worker",
        "manual-worker",
        "--result-hash",
        &"cd".repeat(32),
        "--salt-hex",
        "explicit-manual-salt",
    ]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("template_reveal="));
    assert!(text.contains("explicit-manual-salt"));
}
