use super::*;

#[test]
fn market_submit_bid_and_match_task_m1_happy_path() {
    let _guard = lock_test_guard();
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
    let _guard = lock_test_guard();
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
    let _guard = lock_test_guard();
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
    let _guard = lock_test_guard();
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
    let _guard = lock_test_guard();
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
    let _guard = lock_test_guard();
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
    let _guard = lock_test_guard();
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
fn market_submit_bid_accepts_open_status_after_hidden_separator_normalization() {
    let _guard = lock_test_guard();
    let tasks = unique_market_fixture_path("market_submit_hidden_open_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_submit_hidden_open_bids", "jsonl");
    fs::write(
        &tasks,
        r#"{"task_id":33001,"creator":"alice","bounty":100,"description":"normalized open status","status":"\uFEFFopen\u200B","created_at_unix_ms":1}"#,
    )
    .expect("write tasks fixture");
    fs::write(&bids, "").expect("write bids fixture");

    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let bid_out = run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            "33001",
            "--worker",
            "worker-a",
            "--price",
            "88",
        ],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ],
    );
    assert!(bid_out.contains("\"worker\": \"worker-a\""));

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}
