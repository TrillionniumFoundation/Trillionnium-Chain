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

fn unique_market_fixture_path(name: &str, ext: &str) -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("trnm_rpc_{}_{}.{}", name, ts, ext))
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
    assert!(match_out.contains("\"matched_bid_count\":1"));
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
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match output json");
    assert_eq!(matched["winner"], "worker-high");
    assert_eq!(matched["match_policy"], "price_reputation_weighted");
    assert_eq!(matched["winner_reputation"], 200);
    assert_eq!(matched["base_score"], 101000);
    assert_eq!(matched["reputation_weight"], 20000);
    assert_eq!(matched["penalty"], 0);
    assert_eq!(matched["final_score"], 81000);
    assert_eq!(matched["effective_score"], 81000);
}

#[test]
fn market_match_reputation_lookup_normalizes_case_and_whitespace_keys() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");
    fs::create_dir_all("run/market").expect("create market dir");
    fs::write("run/market/reputation.json", r#"{"  Worker-High  ":200}"#)
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
fn market_match_reputation_alias_collision_uses_max_signal() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");
    fs::create_dir_all("run/market").expect("create market dir");
    fs::write(
        "run/market/reputation.json",
        r#"{"worker-high":5,"  WORKER-HIGH  ":220,"worker-low":0}"#,
    )
    .expect("write reputation file");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "101",
        "--description",
        "m2 alias collision max reputation",
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
    assert!(match_out.contains("\"winner_reputation\":220"));
}

#[test]
fn market_match_task_without_bids_returns_structured_code() {
    let _guard = test_lock().lock().expect("test lock");
    let _ = fs::remove_dir_all("run/market");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "100",
        "--description",
        "m1 no bids guard",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    let stderr = run_fail(&["market.match_task", "--task-id", &task_id]);
    assert!(stderr.contains("\"code\": \"no-bids\""));
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

#[test]
fn market_report_returns_zeroed_metrics_for_empty_state() {
    let _guard = test_lock().lock().expect("test lock");

    let tasks = unique_market_fixture_path("market_report_empty_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_report_empty_bids", "jsonl");
    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();

    let out = run_ok_with_env(
        &["market.report"],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ],
    );
    let report: Value = serde_json::from_str(&out).expect("market report json");

    assert_eq!(report["task_count"], 0);
    assert_eq!(report["open_task_count"], 0);
    assert_eq!(report["matched_task_count"], 0);
    assert_eq!(report["bid_count"], 0);
    assert_eq!(report["unique_bidder_count"], 0);
    assert_eq!(report["avg_bids_per_task"], 0.0);
    assert_eq!(report["match_rate"], 0.0);
}

#[test]
fn market_report_summarizes_tasks_bids_and_unique_bidders() {
    let _guard = test_lock().lock().expect("test lock");

    let tasks = unique_market_fixture_path("market_report_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_report_bids", "jsonl");
    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let envs = [
        ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
        ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
    ];

    let create_1 = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "m3 report task 1",
        ],
        &envs,
    );
    let task_1: Value = serde_json::from_str(&create_1).expect("create task1 json");
    let task_1_id = task_1["task_id"].as_u64().expect("task1 id").to_string();

    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_1_id,
            "--worker",
            "Worker-A",
            "--price",
            "88",
        ],
        &envs,
    );
    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_1_id,
            "--worker",
            "worker-b",
            "--price",
            "90",
        ],
        &envs,
    );
    run_ok_with_env(&["market.match_task", "--task-id", &task_1_id], &envs);

    let create_2 = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "bob",
            "--bounty",
            "120",
            "--description",
            "m3 report task 2",
        ],
        &envs,
    );
    let task_2: Value = serde_json::from_str(&create_2).expect("create task2 json");
    let task_2_id = task_2["task_id"].as_u64().expect("task2 id").to_string();

    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_2_id,
            "--worker",
            " worker-a ",
            "--price",
            "110",
        ],
        &envs,
    );

    let out = run_ok_with_env(&["market.report"], &envs);
    let report: Value = serde_json::from_str(&out).expect("market report json");

    assert_eq!(report["task_count"], 2);
    assert_eq!(report["open_task_count"], 1);
    assert_eq!(report["matched_task_count"], 1);
    assert_eq!(report["bid_count"], 3);
    assert_eq!(report["unique_bidder_count"], 2);
    assert_eq!(report["avg_bids_per_task"], 1.5);
    assert_eq!(report["match_rate"], 0.5);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_report_counts_status_case_and_whitespace_variants() {
    let _guard = test_lock().lock().expect("test lock");

    let tasks = unique_market_fixture_path("market_report_status_norm_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_report_status_norm_bids", "jsonl");
    fs::write(
        &tasks,
        concat!(
            r#"{"task_id":31001,"creator":"alice","bounty":100,"description":"norm","status":" Open ","created_at_unix_ms":1}"#,
            "\n",
            r#"{"task_id":31002,"creator":"bob","bounty":100,"description":"norm","status":"MATCHED\t","created_at_unix_ms":2}"#,
            "\n",
            r#"{"task_id":31003,"creator":"carol","bounty":100,"description":"norm","status":"closed","created_at_unix_ms":3}"#,
            "\n"
        ),
    )
    .expect("write tasks fixture");
    fs::write(&bids, "").expect("write bids fixture");

    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let out = run_ok_with_env(
        &["market.report"],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ],
    );
    let report: Value = serde_json::from_str(&out).expect("market report json");

    assert_eq!(report["task_count"], 3);
    assert_eq!(report["open_task_count"], 1);
    assert_eq!(report["matched_task_count"], 1);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_report_normalizes_and_ignores_invalid_bidder_keys() {
    let _guard = test_lock().lock().expect("test lock");

    let tasks = unique_market_fixture_path("market_report_norm_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_report_norm_bids", "jsonl");
    fs::write(
        &tasks,
        r#"{"task_id":30001,"creator":"alice","bounty":100,"description":"norm","status":"open","created_at_unix_ms":1}"#,
    )
    .expect("write tasks fixture");
    fs::write(
        &bids,
        concat!(
            r#"{"task_id":30001,"worker":" Worker-A ","price":90,"created_at_unix_ms":1700000000000}"#,
            "\n",
            r#"{"task_id":30001,"worker":"worker-a","price":91,"created_at_unix_ms":1700000000001}"#,
            "\n",
            r#"{"task_id":30001,"worker":"\t\t","price":92,"created_at_unix_ms":1700000000002}"#,
            "\n",
            r#"{"task_id":30001,"worker":"WORKER-B","price":93,"created_at_unix_ms":1700000000003}"#,
            "\n"
        ),
    )
    .expect("write bids fixture");

    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let out = run_ok_with_env(
        &["market.report"],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ],
    );
    let report: Value = serde_json::from_str(&out).expect("market report json");

    assert_eq!(report["bid_count"], 4);
    assert_eq!(report["unique_bidder_count"], 2);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_match_uses_worker_key_as_final_tie_breaker_for_equal_scores() {
    let _guard = test_lock().lock().expect("test lock");

    let tasks = unique_market_fixture_path("market_match_tie_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_match_tie_bids", "jsonl");
    fs::write(
        &tasks,
        r#"{"task_id":20001,"creator":"alice","bounty":100,"description":"tie-break","status":"open","created_at_unix_ms":1}"#,
    )
    .expect("write tasks fixture");
    fs::write(
        &bids,
        concat!(
            r#"{"task_id":20001,"worker":"worker-b","price":90,"created_at_unix_ms":1700000000000}"#,
            "\n",
            r#"{"task_id":20001,"worker":"worker-a","price":90,"created_at_unix_ms":1700000000000}"#,
            "\n"
        ),
    )
    .expect("write bids fixture");

    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let out = run_ok_with_env(
        &["market.match_task", "--task-id", "20001"],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ],
    );
    let matched: Value = serde_json::from_str(out.trim()).expect("match output json");
    assert_eq!(matched["winner"], "worker-a");
    assert_eq!(matched["effective_score"], 90000);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}
