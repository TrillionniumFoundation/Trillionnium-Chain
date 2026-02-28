use serde_json::Value;
use std::fs;
use std::process::Command;

fn run_ok(args: &[&str]) -> String {
    let output = Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(args)
        .output()
        .expect("failed to execute trnm-rpc");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_fail(args: &[&str]) -> String {
    let output = Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(args)
        .output()
        .expect("failed to execute trnm-rpc");
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn market_submit_bid_and_match_task_m1_happy_path() {
    let _ = fs::remove_dir_all("run/market");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "100",
        "--description",
        "m1 submit/match",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    let bid_out = run_ok(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-a",
        "--price",
        "88",
    ]);
    assert!(bid_out.contains("\"worker\": \"worker-a\""));

    let match_out = run_ok(&["market.match_task", "--task-id", &task_id]);
    assert!(match_out.contains("\"status\":\"matched\""));
    assert!(match_out.contains("\"winner\":\"worker-a\""));
}

#[test]
fn market_submit_bid_missing_task_returns_structured_code() {
    let _ = fs::remove_dir_all("run/market");

    let stderr = run_fail(&[
        "market.submit_bid",
        "--task-id",
        "99999",
        "--worker",
        "worker-a",
        "--price",
        "88",
    ]);
    assert!(stderr.contains("\"code\": \"task-not-found\""));
}
