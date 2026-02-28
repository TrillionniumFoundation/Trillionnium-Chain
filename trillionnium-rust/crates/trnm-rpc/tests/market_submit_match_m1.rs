use serde_json::Value;
use std::fs;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

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
    let _guard = test_lock().lock().expect("test lock");
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
    let _guard = test_lock().lock().expect("test lock");
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

#[test]
fn market_submit_bid_above_bounty_returns_structured_code() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "100",
        "--description",
        "m1 bid cap",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    let stderr = run_fail(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-a",
        "--price",
        "101",
    ]);
    assert!(stderr.contains("\"code\": \"bid-above-bounty\""));
}

#[test]
fn market_submit_bid_zero_price_returns_structured_code() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "100",
        "--description",
        "m1 positive bid floor",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    let stderr = run_fail(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-a",
        "--price",
        "0",
    ]);
    assert!(stderr.contains("\"code\": \"bid-price-invalid\""));
}

#[test]
fn market_submit_bid_empty_worker_returns_structured_code() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "100",
        "--description",
        "m1 worker id guard",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    let stderr = run_fail(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "   ",
        "--price",
        "88",
    ]);
    assert!(stderr.contains("\"code\": \"worker-id-invalid\""));
}

#[test]
fn market_submit_bid_duplicate_worker_returns_structured_code() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "100",
        "--description",
        "m1 duplicate bid guard",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    run_ok(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-a",
        "--price",
        "88",
    ]);

    let stderr = run_fail(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-a",
        "--price",
        "87",
    ]);
    assert!(stderr.contains("\"code\": \"duplicate-bid\""));
}

#[test]
fn market_submit_bid_duplicate_worker_is_case_and_whitespace_insensitive() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "100",
        "--description",
        "m1 canonical duplicate worker guard",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    run_ok(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "Worker-A",
        "--price",
        "88",
    ]);

    let stderr = run_fail(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "  worker-a  ",
        "--price",
        "87",
    ]);
    assert!(stderr.contains("\"code\": \"duplicate-bid\""));
}

#[test]
fn market_match_prefers_higher_reputation_when_weighted_score_is_better() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");
    fs::create_dir_all("run/market").expect("create market dir");
    fs::write(
        "run/market/reputation.json",
        r#"{"worker-low":0,"worker-high":200}"#,
    )
    .expect("write reputation file");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "101",
        "--description",
        "m2 weighted matching",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    run_ok(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-low",
        "--price",
        "100",
    ]);
    run_ok(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-high",
        "--price",
        "101",
    ]);

    let match_out = run_ok_with_env(
        &["market.match_task", "--task-id", &task_id],
        &[(
            "TRNM_RPC_MARKET_REPUTATION_FILE",
            "run/market/reputation.json",
        )],
    );
    assert!(match_out.contains("\"winner\":\"worker-high\""));
    assert!(match_out.contains("\"match_policy\":\"price_reputation_weighted\""));
    assert!(match_out.contains("\"winner_reputation\":200"));
}

#[test]
fn market_match_reputation_lookup_normalizes_case_and_whitespace_keys() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");
    fs::create_dir_all("run/market").expect("create market dir");
    fs::write(
        "run/market/reputation.json",
        r#"{"  Worker-High  ":200}"#,
    )
    .expect("write reputation file");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "101",
        "--description",
        "m2 normalized reputation key lookup",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    run_ok(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-low",
        "--price",
        "100",
    ]);
    run_ok(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-high",
        "--price",
        "101",
    ]);

    let match_out = run_ok_with_env(
        &["market.match_task", "--task-id", &task_id],
        &[(
            "TRNM_RPC_MARKET_REPUTATION_FILE",
            "run/market/reputation.json",
        )],
    );
    assert!(match_out.contains("\"winner\":\"worker-high\""));
    assert!(match_out.contains("\"winner_reputation\":200"));
}

#[test]
fn market_match_output_is_valid_json_when_winner_contains_quotes() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "100",
        "--description",
        "m1 json escaping",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    run_ok(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-\"quoted\"",
        "--price",
        "88",
    ]);

    let match_out = run_ok(&["market.match_task", "--task-id", &task_id]);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match output JSON");
    assert_eq!(matched["winner"], "worker-\"quoted\"");
    assert_eq!(matched["status"], "matched");
}
