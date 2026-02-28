use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::{Builder, TempDir};

struct MarketSandbox {
    _tmp: TempDir,
    tasks_file: String,
    bids_file: String,
    reputation_file: String,
}

impl MarketSandbox {
    fn new(prefix: &str) -> Self {
        let tmp = Builder::new().prefix(prefix).tempdir().expect("tempdir");
        let tasks_file = tmp.path().join("tasks.jsonl").display().to_string();
        let bids_file = tmp.path().join("bids.jsonl").display().to_string();
        let reputation_file = tmp.path().join("reputation.json").display().to_string();
        Self {
            _tmp: tmp,
            tasks_file,
            bids_file,
            reputation_file,
        }
    }
}

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
    let sandbox = MarketSandbox::new("market-test-m1-");
    let market_env = [
        ("TRNM_RPC_MARKET_TASKS_FILE", sandbox.tasks_file.as_str()),
        ("TRNM_RPC_MARKET_BIDS_FILE", sandbox.bids_file.as_str()),
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
    let sandbox = MarketSandbox::new("market-test-missing-");
    let market_env = [
        ("TRNM_RPC_MARKET_TASKS_FILE", sandbox.tasks_file.as_str()),
        ("TRNM_RPC_MARKET_BIDS_FILE", sandbox.bids_file.as_str()),
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
    let sandbox = MarketSandbox::new("market-test-m2-");
    let market_env = [
        ("TRNM_RPC_MARKET_TASKS_FILE", sandbox.tasks_file.as_str()),
        ("TRNM_RPC_MARKET_BIDS_FILE", sandbox.bids_file.as_str()),
    ];
    fs::write(&sandbox.reputation_file, r#"{"worker-low":0,"worker-high":200}"#)
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
            ("TRNM_RPC_MARKET_TASKS_FILE", sandbox.tasks_file.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", sandbox.bids_file.as_str()),
            (
                "TRNM_RPC_MARKET_REPUTATION_FILE",
                sandbox.reputation_file.as_str(),
            ),
        ],
    );
    assert!(match_out.contains("\"winner\":\"worker-high\""));
    assert!(match_out.contains("\"match_policy\":\"price_reputation_weighted\""));
    assert!(match_out.contains("\"winner_reputation\":200"));
    let matched: Value = serde_json::from_str(&match_out).expect("match task JSON");
    assert!(matched["winner_reputation_applied"].is_i64());
    assert!(matched["score_weights"]["price"].is_u64());
    assert!(matched["score_weights"]["reputation"].is_u64());
    assert!(matched["score_weights"]["reputation_clamp"].is_i64());
}

#[test]
fn market_match_m2_policy_gate_clamps_invalid_env_values() {
    let sandbox = MarketSandbox::new("market-test-m2-policy-");
    let market_env = [
        ("TRNM_RPC_MARKET_TASKS_FILE", sandbox.tasks_file.as_str()),
        ("TRNM_RPC_MARKET_BIDS_FILE", sandbox.bids_file.as_str()),
    ];
    fs::write(&sandbox.reputation_file, r#"{"worker-low":0,"worker-high":200}"#)
        .expect("write reputation file");

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
            ("TRNM_RPC_MARKET_TASKS_FILE", sandbox.tasks_file.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", sandbox.bids_file.as_str()),
            (
                "TRNM_RPC_MARKET_REPUTATION_FILE",
                sandbox.reputation_file.as_str(),
            ),
            ("TRNM_RPC_MARKET_PRICE_WEIGHT", "0"),
            ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", "0"),
            ("TRNM_RPC_MARKET_REPUTATION_CLAMP", "0"),
        ],
    );
    assert!(match_out.contains("\"winner\":\"worker-low\""));
    assert!(match_out.contains("\"effective_score\":100"));
    let matched: Value = serde_json::from_str(&match_out).expect("match task JSON");
    assert!(matched["score_weights"]["reputation_clamp"].is_i64());
}

#[test]
fn market_isolated_envs_prevent_shared_directory_conflicts() {
    let sandbox_a = MarketSandbox::new("market-isolation-a-");
    let sandbox_b = MarketSandbox::new("market-isolation-b-");

    let create_a = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "isolation-a",
        ],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", sandbox_a.tasks_file.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", sandbox_a.bids_file.as_str()),
        ],
    );
    let create_b = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "bob",
            "--bounty",
            "100",
            "--description",
            "isolation-b",
        ],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", sandbox_b.tasks_file.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", sandbox_b.bids_file.as_str()),
        ],
    );

    let task_a = serde_json::from_str::<Value>(&create_a)
        .expect("create_a json")["task_id"]
        .as_u64()
        .expect("task_id a")
        .to_string();
    let task_b = serde_json::from_str::<Value>(&create_b)
        .expect("create_b json")["task_id"]
        .as_u64()
        .expect("task_id b")
        .to_string();

    assert_eq!(task_a, task_b);

    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_a,
            "--worker",
            "worker-a",
            "--price",
            "90",
        ],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", sandbox_a.tasks_file.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", sandbox_a.bids_file.as_str()),
        ],
    );
    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_b,
            "--worker",
            "worker-b",
            "--price",
            "91",
        ],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", sandbox_b.tasks_file.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", sandbox_b.bids_file.as_str()),
        ],
    );

    let match_a = run_ok_with_env(
        &["market.match_task", "--task-id", &task_a],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", sandbox_a.tasks_file.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", sandbox_a.bids_file.as_str()),
        ],
    );
    let match_b = run_ok_with_env(
        &["market.match_task", "--task-id", &task_b],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", sandbox_b.tasks_file.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", sandbox_b.bids_file.as_str()),
        ],
    );

    assert!(match_a.contains("\"winner\":\"worker-a\""));
    assert!(match_b.contains("\"winner\":\"worker-b\""));
}
