use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
struct TestEnv {
    root: String,
    accounts_file: String,
    tx_file: String,
    market_tasks_file: String,
    market_bids_file: String,
}

fn test_env(prefix: &str) -> TestEnv {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let root = format!("run/market_test/{prefix}_{}_{}", std::process::id(), seq);
    let _ = fs::remove_dir_all(&root);
    TestEnv {
        accounts_file: format!("{root}/accounts.json"),
        tx_file: format!("{root}/txs.json"),
        market_tasks_file: format!("{root}/tasks.jsonl"),
        market_bids_file: format!("{root}/bids.jsonl"),
        root,
    }
}

fn run_rpc(env: &TestEnv, args: &[&str]) -> String {
    let output = Command::new("cargo")
        .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(args)
        .env("TRNM_RPC_ACCOUNTS_FILE", &env.accounts_file)
        .env("TRNM_RPC_TX_FILE", &env.tx_file)
        .env("TRNM_RPC_MARKET_TASKS_FILE", &env.market_tasks_file)
        .env("TRNM_RPC_MARKET_BIDS_FILE", &env.market_bids_file)
        .output()
        .expect("failed to execute trnm-rpc");

    if !output.status.success() {
        panic!("RPC failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_rpc_fail(env: &TestEnv, args: &[&str]) -> String {
    let output = Command::new("cargo")
        .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(args)
        .env("TRNM_RPC_ACCOUNTS_FILE", &env.accounts_file)
        .env("TRNM_RPC_TX_FILE", &env.tx_file)
        .env("TRNM_RPC_MARKET_TASKS_FILE", &env.market_tasks_file)
        .env("TRNM_RPC_MARKET_BIDS_FILE", &env.market_bids_file)
        .output()
        .expect("failed to execute trnm-rpc");

    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn test_market_lifecycle() {
    let env = test_env("lifecycle");

    let out = run_rpc(
        &env,
        &[
            "market-create-task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "test task",
        ],
    );
    assert!(out.contains("\"creator\": \"alice\""));
    assert!(out.contains("\"bounty\": 100"));
    assert!(out.contains("\"status\": \"open\""));

    run_rpc(
        &env,
        &[
            "market-submit-bid",
            "--task-id",
            "20001",
            "--worker",
            "worker1",
            "--price",
            "90",
        ],
    );
    let out = run_rpc(
        &env,
        &[
            "market-submit-bid",
            "--task-id",
            "20001",
            "--worker",
            "worker2",
            "--price",
            "80",
        ],
    );
    assert!(out.contains("\"worker\": \"worker2\""));
    assert!(out.contains("\"price\": 80"));

    let out = run_rpc(&env, &["market-match-task", "--task-id", "20001"]);
    assert!(out.contains("\"winner\":\"worker2\""));
    assert!(out.contains("\"price\":80"));
    assert!(out.contains("\"status\":\"matched\""));

    let tasks_json = fs::read_to_string(&env.market_tasks_file).unwrap();
    assert!(tasks_json.contains("\"status\":\"matched\""));

    let _ = fs::remove_dir_all(&env.root);
}

#[test]
fn test_market_match_non_existent_task() {
    let env = test_env("no_task");
    let stderr = run_rpc_fail(&env, &["market-match-task", "--task-id", "99999"]);
    assert!(stderr.contains("\"code\": \"task-not-found\""));

    let _ = fs::remove_dir_all(&env.root);
}

#[test]
fn test_market_match_no_bids() {
    let env = test_env("no_bids");
    run_rpc(
        &env,
        &[
            "market-create-task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "no bids task",
        ],
    );

    let stderr = run_rpc_fail(&env, &["market-match-task", "--task-id", "20001"]);
    assert!(stderr.contains("\"code\": \"no-bids\""));

    let _ = fs::remove_dir_all(&env.root);
}

#[test]
fn test_market_match_task_not_open_prefers_code_field() {
    let env = test_env("task_not_open");
    run_rpc(
        &env,
        &[
            "market-create-task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "task not open",
        ],
    );
    run_rpc(
        &env,
        &[
            "market-submit-bid",
            "--task-id",
            "20001",
            "--worker",
            "worker1",
            "--price",
            "90",
        ],
    );
    run_rpc(&env, &["market-match-task", "--task-id", "20001"]);

    let stderr = run_rpc_fail(&env, &["market-match-task", "--task-id", "20001"]);
    assert!(stderr.contains("\"code\": \"task-not-open\""));

    let _ = fs::remove_dir_all(&env.root);
}

#[test]
fn test_market_submit_bid_task_not_open_prefers_code_field() {
    let env = test_env("submit_bid_task_not_open");
    run_rpc(
        &env,
        &[
            "market-create-task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "submit bid task not open",
        ],
    );
    run_rpc(
        &env,
        &[
            "market-submit-bid",
            "--task-id",
            "20001",
            "--worker",
            "worker1",
            "--price",
            "90",
        ],
    );
    run_rpc(&env, &["market-match-task", "--task-id", "20001"]);

    let stderr = run_rpc_fail(
        &env,
        &[
            "market-submit-bid",
            "--task-id",
            "20001",
            "--worker",
            "worker2",
            "--price",
            "80",
        ],
    );
    assert!(stderr.contains("\"code\": \"task-not-open\""));

    let _ = fs::remove_dir_all(&env.root);
}
