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

fn observe(store: &Path, profile: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    cmd.arg("capacity-observe")
        .args([
            "--development",
            "--genesis-time",
            "1",
            "--evaluation-policy",
            "native-public-evaluation-dev-v1",
            "--task-profile",
            profile,
        ])
        .arg("--store")
        .arg(store);
    cmd
}

#[test]
fn local_capacity_command_binds_the_checked_state_and_rejects_old_profiles_before_open() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("current");
    let packet = temp.path().join("first.packet");
    let mined = command(&store, &packet, PROFILE)
        .args(["--timestamp", "11", "--consensus-maintenance"])
        .output()
        .unwrap();
    assert!(
        mined.status.success(),
        "{}",
        String::from_utf8_lossy(&mined.stderr)
    );
    let mined: Value = serde_json::from_slice(&mined.stdout).unwrap();
    let state = &mined["result"]["state"];
    let output = observe(&store, PROFILE).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observation: Value = serde_json::from_slice(&output.stdout).unwrap();
    let report = &observation["result"];
    assert_eq!(report["schema"], "pon-continuity-capacity-observation-v1");
    assert_eq!(report["observed_tip"], state["tip"]);
    assert_eq!(report["active_generation"], state["generation"]);
    assert_eq!(report["state_root"], state["state_root"]);
    assert_eq!(report["actual_keys"], state["state_keys"]);
    assert_eq!(report["observed_height"], 1);
    assert_eq!(report["retained_account_keys"], 4);
    assert_eq!(report["credit_account_reserve"], 0);
    assert_eq!(report["archive_reserve"], 0);
    assert_eq!(report["reward_queue_reserve"], 19);
    assert_eq!(
        report["required_keys"].as_u64().unwrap(),
        state["state_keys"].as_u64().unwrap() + 19
    );
    assert_eq!(report["next_block_admission_guaranteed"], false);
    let reopened = observe(&store, PROFILE).output().unwrap();
    assert!(reopened.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&reopened.stdout).unwrap(),
        observation
    );

    let legacy = temp.path().join("legacy-not-created");
    rejected(
        observe(&legacy, "legacy-task-v1").output().unwrap(),
        "CONTINUITY_PROFILE",
    );
    assert!(!legacy.exists());
    let unknown = temp.path().join("peer-not-created");
    rejected(
        observe(&unknown, PROFILE)
            .args(["--peer", "127.0.0.1:1"])
            .output()
            .unwrap(),
        "UNKNOWN_OPTION:--peer",
    );
    assert!(!unknown.exists());
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
