use serde_json::Value;
use std::fs;
use std::process::Command;

fn run_ok_with_env(args: &[&str], envs: &[(&str, &str)]) -> String {
    let mut command = Command::new("cargo");
    command.args(["run", "-p", "trnm-rpc", "--"]).args(args);
    for (k, v) in envs {
        command.env(k, v);
    }
    let output = command.output().expect("failed to execute trnm-rpc");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_fail_with_env(args: &[&str], envs: &[(&str, &str)]) -> String {
    let mut command = Command::new("cargo");
    command.args(["run", "-p", "trnm-rpc", "--"]).args(args);
    for (k, v) in envs {
        command.env(k, v);
    }
    let output = command.output().expect("failed to execute trnm-rpc");
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn market_submit_bid_and_match_task_m1_happy_path() {
    let _ = fs::remove_dir_all("run/market_test_m1");
    fs::create_dir_all("run/market_test_m1").expect("create market test m1 dir");
    let tasks_file = "run/market_test_m1/tasks.jsonl";
    let bids_file = "run/market_test_m1/bids.jsonl";
    let market_env = [
        ("TRNM_RPC_MARKET_TASKS_FILE", tasks_file),
        ("TRNM_RPC_MARKET_BIDS_FILE", bids_file),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "m1 submit/match",
        ],
        &market_env,
    );
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    let bid_out = run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_id,
            "--worker",
            "worker-a",
            "--price",
            "88",
        ],
        &market_env,
    );
    assert!(bid_out.contains("\"worker\": \"worker-a\""));

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &market_env);
    assert!(match_out.contains("\"status\":\"matched\""));
    assert!(match_out.contains("\"winner\":\"worker-a\""));
}

#[test]
fn market_submit_bid_missing_task_returns_structured_code() {
    let _ = fs::remove_dir_all("run/market_test_missing");
    fs::create_dir_all("run/market_test_missing").expect("create market test missing dir");
    let tasks_file = "run/market_test_missing/tasks.jsonl";
    let bids_file = "run/market_test_missing/bids.jsonl";
    let market_env = [
        ("TRNM_RPC_MARKET_TASKS_FILE", tasks_file),
        ("TRNM_RPC_MARKET_BIDS_FILE", bids_file),
    ];

    let stderr = run_fail_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            "99999",
            "--worker",
            "worker-a",
            "--price",
            "88",
        ],
        &market_env,
    );
    assert!(stderr.contains("\"code\": \"task-not-found\""));
}

#[test]
fn market_match_prefers_higher_reputation_when_weighted_score_is_better() {
    let _ = fs::remove_dir_all("run/market_test_m2");
    fs::create_dir_all("run/market_test_m2").expect("create market test dir");
    let tasks_file = "run/market_test_m2/tasks.jsonl";
    let bids_file = "run/market_test_m2/bids.jsonl";
    let market_env = [
        ("TRNM_RPC_MARKET_TASKS_FILE", tasks_file),
        ("TRNM_RPC_MARKET_BIDS_FILE", bids_file),
    ];
    let rep_file = "run/market_test_m2/reputation.json";
    fs::write(
        rep_file,
        r#"{"worker-low":0,"worker-high":200}"#,
    )
    .expect("write reputation file");

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "m2 weighted matching",
        ],
        &market_env,
    );
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_id,
            "--worker",
            "worker-low",
            "--price",
            "100",
        ],
        &market_env,
    );
    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_id,
            "--worker",
            "worker-high",
            "--price",
            "101",
        ],
        &market_env,
    );

    let match_out = run_ok_with_env(
        &["market.match_task", "--task-id", &task_id],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", tasks_file),
            ("TRNM_RPC_MARKET_BIDS_FILE", bids_file),
            ("TRNM_RPC_MARKET_REPUTATION_FILE", rep_file),
        ],
    );
    assert!(match_out.contains("\"winner\":\"worker-high\""));
    assert!(match_out.contains("\"match_policy\":\"price_reputation_weighted\""));
    assert!(match_out.contains("\"winner_reputation\":200"));
}

#[test]
fn market_match_m2_policy_gate_clamps_invalid_env_values() {
    let _ = fs::remove_dir_all("run/market_test_m2_policy_gate");
    fs::create_dir_all("run/market_test_m2_policy_gate").expect("create market test dir");
    let tasks_file = "run/market_test_m2_policy_gate/tasks.jsonl";
    let bids_file = "run/market_test_m2_policy_gate/bids.jsonl";
    let market_env = [
        ("TRNM_RPC_MARKET_TASKS_FILE", tasks_file),
        ("TRNM_RPC_MARKET_BIDS_FILE", bids_file),
    ];
    let rep_file = "run/market_test_m2_policy_gate/reputation.json";
    fs::write(rep_file, r#"{"worker-low":0,"worker-high":200}"#).expect("write reputation file");

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "m2 policy gate clamps invalid env",
        ],
        &market_env,
    );
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_id,
            "--worker",
            "worker-low",
            "--price",
            "100",
        ],
        &market_env,
    );
    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_id,
            "--worker",
            "worker-high",
            "--price",
            "101",
        ],
        &market_env,
    );

    let match_out = run_ok_with_env(
        &["market.match_task", "--task-id", &task_id],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", tasks_file),
            ("TRNM_RPC_MARKET_BIDS_FILE", bids_file),
            ("TRNM_RPC_MARKET_REPUTATION_FILE", rep_file),
            ("TRNM_RPC_MARKET_PRICE_WEIGHT", "0"),
            ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", "0"),
            ("TRNM_RPC_MARKET_REPUTATION_CLAMP", "0"),
        ],
    );
    assert!(match_out.contains("\"winner\":\"worker-low\""));
    assert!(match_out.contains("\"effective_score\":100"));
}
