use serde_json::Value;
use std::fs;
use std::process::Command;

fn run_ok(args: &[&str]) -> String {
    let output = Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(args)
        .output()
        .expect("failed to execute trnm-rpc");
    if !output.status.success() {
        panic!("RPC failed: {}", String::from_utf8_lossy(&output.stderr));
    }
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
fn market_match_error_contract_prefers_code_field() {
    let _ = fs::remove_dir_all("run/market");

    // no-bids
    let create_out = run_ok(&[
        "market-create-task",
        "--creator",
        "alice",
        "--bounty",
        "100",
        "--description",
        "no bids",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id");
    let task_id_s = task_id.to_string();

    let stderr = run_fail(&["market-match-task", "--task-id", &task_id_s]);
    assert!(stderr.contains("\"code\": \"no-bids\""));

    // task-not-open
    run_ok(&[
        "market-submit-bid",
        "--task-id",
        &task_id_s,
        "--worker",
        "worker1",
        "--price",
        "90",
    ]);
    run_ok(&["market-match-task", "--task-id", &task_id_s]);
    let stderr = run_fail(&["market-match-task", "--task-id", &task_id_s]);
    assert!(stderr.contains("\"code\": \"task-not-open\""));
}
