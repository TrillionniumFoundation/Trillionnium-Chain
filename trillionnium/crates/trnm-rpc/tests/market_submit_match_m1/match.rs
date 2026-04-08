use super::*;

#[test]
fn market_match_prefers_higher_reputation_when_weighted_score_is_better() {
    let _guard = lock_test_guard();
    let _ = fs::remove_dir_all("run/market");
    fs::create_dir_all("run/market").expect("create market dir");
    fs::write(
        market_reputation_fixture_path(),
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

    let match_out = run_ok(&["market.match_task", "--task-id", &task_id]);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match output json");
    assert_eq!(matched["winner"], "worker-high");
    assert_eq!(matched["match_policy"], "price_reputation_weighted");
    assert_eq!(matched["winner_reputation"], 200);
    assert_eq!(matched["base_score"], 101000);
    assert_eq!(matched["reputation_weight_unit"], 100);
    assert_eq!(matched["reputation_weight"], 20000);
    assert_eq!(matched["penalty"], 0);
    assert_eq!(matched["reputation_score_delta"], -20000);
    assert_eq!(matched["final_score"], 81000);
    assert_eq!(matched["effective_score"], 81000);
}

#[test]
fn market_match_negative_reputation_exposes_penalty_breakdown_fields() {
    let _guard = lock_test_guard();
    let _ = fs::remove_dir_all("run/market");
    fs::create_dir_all("run/market").expect("create market dir");
    fs::write(market_reputation_fixture_path(), r#"{"worker-risk":-50}"#)
        .expect("write reputation file");

    let create_out = run_ok(&[
        "market.create_task",
        "--creator",
        "alice",
        "--bounty",
        "100",
        "--description",
        "m2 negative reputation breakdown",
    ]);
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    run_ok(&[
        "market.submit_bid",
        "--task-id",
        &task_id,
        "--worker",
        "worker-risk",
        "--price",
        "50",
    ]);

    let match_out = run_ok(&["market.match_task", "--task-id", &task_id]);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match output json");
    assert_eq!(matched["winner"], "worker-risk");
    assert_eq!(matched["winner_reputation"], -50);
    assert_eq!(matched["winner_reputation_effective"], -50);
    assert_eq!(matched["winner_reputation_clamp_limit"], 1000);
    assert_eq!(matched["base_score"], 50000);
    assert_eq!(matched["reputation_weight_unit"], 100);
    assert_eq!(matched["reputation_weight"], 0);
    assert_eq!(matched["penalty"], 5000);
    assert_eq!(matched["reputation_score_delta"], 5000);
    assert_eq!(matched["final_score"], 55000);
    assert_eq!(matched["effective_score"], 55000);
}

#[test]
fn market_match_reputation_lookup_normalizes_case_and_whitespace_keys() {
    let _guard = lock_test_guard();
    let _ = fs::remove_dir_all("run/market");
    fs::create_dir_all("run/market").expect("create market dir");
    fs::write(
        market_reputation_fixture_path(),
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

    let match_out = run_ok(&["market.match_task", "--task-id", &task_id]);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");
    assert_eq!(matched["winner"], "worker-high");
    assert_eq!(matched["winner_reputation"], 200);
    assert_eq!(matched["winner_reputation_lookup_key"], "worker-high");
}

#[test]
fn market_match_reputation_alias_collision_uses_max_signal() {
    let _guard = lock_test_guard();
    let _ = fs::remove_dir_all("run/market");
    fs::create_dir_all("run/market").expect("create market dir");
    fs::write(
        market_reputation_fixture_path(),
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

    let match_out = run_ok(&["market.match_task", "--task-id", &task_id]);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");
    assert_eq!(matched["winner"], "worker-high");
    assert_eq!(matched["winner_reputation"], 220);
    assert_eq!(matched["winner_reputation_lookup_key"], "worker-high");
}

#[test]
fn market_match_task_without_bids_returns_structured_code() {
    let _guard = lock_test_guard();
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
    let _guard = lock_test_guard();
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
fn market_match_uses_open_status_after_hidden_separator_normalization() {
    let _guard = lock_test_guard();

    let tasks = unique_market_fixture_path("market_match_hidden_open_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_match_hidden_open_bids", "jsonl");
    fs::write(
        &tasks,
        r#"{"task_id":33002,"creator":"alice","bounty":100,"description":"normalized open status","status":"open\u2060","created_at_unix_ms":1}"#,
    )
    .expect("write tasks fixture");
    fs::write(
        &bids,
        r#"{"task_id":33002,"worker":"worker-a","price":88,"created_at_unix_ms":2}"#,
    )
    .expect("write bids fixture");

    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let match_out = run_ok_with_env(
        &["market.match_task", "--task-id", "33002"],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ],
    );
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match output JSON");
    assert_eq!(matched["winner"], "worker-a");
    assert_eq!(matched["status"], "matched");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_match_uses_worker_key_as_final_tie_breaker_for_equal_scores() {
    let _guard = lock_test_guard();

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

#[test]
fn market_match_prefers_earlier_bid_before_worker_key_tie_breaker() {
    let _guard = lock_test_guard();

    let tasks = unique_market_fixture_path("market_match_created_at_tie_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_match_created_at_tie_bids", "jsonl");
    fs::write(
        &tasks,
        r#"{"task_id":20002,"creator":"alice","bounty":100,"description":"created-at-tie-break","status":"open","created_at_unix_ms":1}"#,
    )
    .expect("write tasks fixture");
    fs::write(
        &bids,
        concat!(
            r#"{"task_id":20002,"worker":"worker-a","price":90,"created_at_unix_ms":1700000000005}"#,
            "\n",
            r#"{"task_id":20002,"worker":"worker-z","price":90,"created_at_unix_ms":1700000000000}"#,
            "\n"
        ),
    )
    .expect("write bids fixture");

    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let out = run_ok_with_env(
        &["market.match_task", "--task-id", "20002"],
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
            ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ],
    );
    let matched: Value = serde_json::from_str(out.trim()).expect("match output json");
    assert_eq!(matched["winner"], "worker-z");
    assert_eq!(matched["effective_score"], 90000);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}
