//! Exercise the actual opt-in command line without a network service or fallback.
use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Output},
};
use trnm_mvcc_fee::continuity_v1::PROFILE;

fn command(store: &Path, output: &Path, profile: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    cmd.arg("mine")
        .args([
            "--development",
            "--genesis-time",
            "1",
            "--logical-now",
            "1000",
            "--evaluation-policy",
            "native-public-evaluation-dev-v1",
            "--task-profile",
            profile,
        ])
        .arg("--store")
        .arg(store)
        .arg("--output")
        .arg(output);
    cmd
}
fn rejected(result: Output, code: &str) {
    assert_eq!(result.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&result.stderr).contains(code),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn explicit_cli_choice_is_required_and_old_profiles_never_change() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("node");
    let output = temp.path().join("first.packet");
    let result = command(&store, &output, PROFILE)
        .args(["--timestamp", "11", "--consensus-maintenance"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["result"]["state"]["height"], 1);
    assert_eq!(result["result"]["admitted"], true);
    assert!(output.is_file());
    rejected(
        command(&store, &temp.path().join("not-created.packet"), PROFILE)
            .args(["--timestamp", "21"])
            .output()
            .unwrap(),
        "TASK_MATERIAL_REQUIRED",
    );
    rejected(
        command(&store, &temp.path().join("not-created.packet"), PROFILE)
            .args([
                "--timestamp",
                "21",
                "--consensus-maintenance",
                "--task-bootstrap",
            ])
            .output()
            .unwrap(),
        "TASK_OPTIONS",
    );
    assert!(!temp.path().join("not-created.packet").exists());
    rejected(
        command(
            &temp.path().join("old"),
            &temp.path().join("old.packet"),
            "legacy-task-v1",
        )
        .args(["--timestamp", "11", "--consensus-maintenance"])
        .output()
        .unwrap(),
        "CONTINUITY_PROFILE",
    );
}
