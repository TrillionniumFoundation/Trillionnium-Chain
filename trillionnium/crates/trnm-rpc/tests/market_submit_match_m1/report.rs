use super::*;

#[test]
fn market_report_returns_zeroed_metrics_for_empty_state() {
    let _guard = lock_test_guard();

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
    assert_eq!(report["unmatched_task_count"], 0);
    assert_eq!(report["bid_count"], 0);
    assert_eq!(report["orphan_bid_count"], 0);
    assert_eq!(report["unique_bidder_count"], 0);
    assert_eq!(report["tasks_with_bids_count"], 0);
    assert_eq!(report["bid_coverage_rate"], 0.0);
    assert_eq!(report["avg_bids_per_task"], 0.0);
    assert_eq!(report["match_rate"], 0.0);
    assert_eq!(report["match_config"]["price_weight"], 1000);
    assert_eq!(report["match_config"]["reputation_weight"], 100);
    assert_eq!(report["match_config"]["reputation_clamp"], 1000);
    assert_eq!(report["match_config"]["max_reputation_score_delta"], 100000);
    assert_eq!(
        report["match_config"]["min_reputation_score_delta"],
        -100000
    );
}

#[test]
fn market_report_normalizes_nested_wrapped_below_floor_clamp_in_output_config() {
    let _guard = lock_test_guard();

    let tasks = unique_market_fixture_path("market_report_wrapped_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_report_wrapped_bids", "jsonl");
    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let envs = [
        ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
        ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ("TRNM_RPC_MARKET_PRICE_WEIGHT", " '7' "),
        ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", " \"11\" "),
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", " ' \"-2\" ' "),
    ];

    let out = run_ok_with_env(&["market.report"], &envs);
    let report: Value = serde_json::from_str(&out).expect("market report json");

    assert_eq!(report["match_config"]["price_weight"], 7);
    assert_eq!(report["match_config"]["reputation_weight"], 11);
    assert_eq!(report["match_config"]["reputation_clamp"], 1);
    assert_eq!(report["match_config"]["max_reputation_score_delta"], 11);
    assert_eq!(report["match_config"]["min_reputation_score_delta"], -11);
    assert_eq!(report["task_count"], 0);
    assert_eq!(report["bid_count"], 0);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_report_summarizes_tasks_bids_and_unique_bidders() {
    let _guard = lock_test_guard();

    let tasks = unique_market_fixture_path("market_report_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_report_bids", "jsonl");
    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let envs = [
        ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
        ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ("TRNM_RPC_MARKET_PRICE_WEIGHT", "7"),
        ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", "11"),
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", "13"),
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
    assert_eq!(report["unmatched_task_count"], 1);
    assert_eq!(report["bid_count"], 3);
    assert_eq!(report["orphan_bid_count"], 0);
    assert_eq!(report["unique_bidder_count"], 2);
    assert_eq!(report["tasks_with_bids_count"], 2);
    assert_eq!(report["bid_coverage_rate"], 1.0);
    assert_eq!(report["avg_bids_per_task"], 1.5);
    assert_eq!(report["match_rate"], 0.5);
    assert_eq!(report["match_config"]["price_weight"], 7);
    assert_eq!(report["match_config"]["reputation_weight"], 11);
    assert_eq!(report["match_config"]["reputation_clamp"], 13);
    assert_eq!(report["match_config"]["max_reputation_score_delta"], 143);
    assert_eq!(report["match_config"]["min_reputation_score_delta"], -143);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_report_ignores_orphan_bid_task_ids_for_coverage_metrics() {
    let _guard = lock_test_guard();

    let tasks = unique_market_fixture_path("market_report_orphan_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_report_orphan_bids", "jsonl");
    fs::write(
        &tasks,
        concat!(
            r#"{"task_id":41001,"creator":"alice","bounty":100,"description":"coverage","status":"open","created_at_unix_ms":1}"#,
            "\n",
            r#"{"task_id":41002,"creator":"bob","bounty":100,"description":"coverage","status":"matched","created_at_unix_ms":2}"#,
            "\n"
        ),
    )
    .expect("write tasks fixture");
    fs::write(
        &bids,
        concat!(
            r#"{"task_id":41001,"worker":"worker-a","price":90,"created_at_unix_ms":1700000000000}"#,
            "\n",
            r#"{"task_id":49999,"worker":"worker-b","price":91,"created_at_unix_ms":1700000000001}"#,
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

    assert_eq!(report["task_count"], 2);
    assert_eq!(report["bid_count"], 2);
    assert_eq!(report["orphan_bid_count"], 1);
    assert_eq!(report["tasks_with_bids_count"], 1);
    assert_eq!(report["bid_coverage_rate"], 0.5);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_report_counts_status_case_and_whitespace_variants() {
    let _guard = lock_test_guard();

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
            "\n",
            r#"{"task_id":31004,"creator":"dave","bounty":100,"description":"norm","status":"\uFEFFopen","created_at_unix_ms":4}"#,
            "\n",
            r#"{"task_id":31005,"creator":"erin","bounty":100,"description":"norm","status":"matched\u200B","created_at_unix_ms":5}"#,
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

    assert_eq!(report["task_count"], 5);
    assert_eq!(report["open_task_count"], 2);
    assert_eq!(report["matched_task_count"], 2);
    assert_eq!(report["unmatched_task_count"], 3);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_report_normalizes_and_ignores_invalid_bidder_keys() {
    let _guard = lock_test_guard();

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
    assert_eq!(report["orphan_bid_count"], 0);
    assert_eq!(report["unique_bidder_count"], 2);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_report_normalizes_soft_hyphen_bidder_aliases_into_single_identity() {
    let _guard = lock_test_guard();

    let tasks = unique_market_fixture_path("market_report_soft_hyphen_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_report_soft_hyphen_bids", "jsonl");
    fs::write(
        &tasks,
        r#"{"task_id":31001,"creator":"alice","bounty":100,"description":"soft-hyphen","status":"open","created_at_unix_ms":1}"#,
    )
    .expect("write tasks fixture");
    fs::write(
        &bids,
        concat!(
            r#"{"task_id":31001,"worker":"Worker\u00ad A","price":90,"created_at_unix_ms":1700000000000}"#,
            "\n",
            r#"{"task_id":31001,"worker":"worker a","price":91,"created_at_unix_ms":1700000000001}"#,
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

    assert_eq!(report["bid_count"], 2);
    assert_eq!(report["unique_bidder_count"], 1);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_report_coverage_ignores_bids_with_invalid_worker_keys() {
    let _guard = lock_test_guard();

    let tasks = unique_market_fixture_path("market_report_coverage_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_report_coverage_bids", "jsonl");
    fs::write(
        &tasks,
        concat!(
            r#"{"task_id":32001,"creator":"alice","bounty":100,"description":"coverage","status":"open","created_at_unix_ms":1}"#,
            "\n",
            r#"{"task_id":32002,"creator":"bob","bounty":100,"description":"coverage","status":"open","created_at_unix_ms":2}"#,
            "\n"
        ),
    )
    .expect("write tasks fixture");
    fs::write(
        &bids,
        concat!(
            r#"{"task_id":32001,"worker":"\t\t","price":90,"created_at_unix_ms":1700000000000}"#,
            "\n",
            r#"{"task_id":32002,"worker":"worker-b","price":91,"created_at_unix_ms":1700000000001}"#,
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

    assert_eq!(report["tasks_with_bids_count"], 1);
    assert_eq!(report["bid_coverage_rate"], 0.5);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}

#[test]
fn market_report_counts_orphan_bids_without_inflating_task_coverage() {
    let _guard = lock_test_guard();

    let tasks = unique_market_fixture_path("market_report_orphan_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_report_orphan_bids", "jsonl");
    fs::write(
        &tasks,
        r#"{"task_id":21001,"creator":"alice","bounty":100,"description":"coverage","status":"open","created_at_unix_ms":1}"#,
    )
    .expect("write task fixture");
    fs::write(
        &bids,
        concat!(
            r#"{"task_id":21001,"worker":"worker-a","price":90,"created_at_unix_ms":1700000000000}"#,
            "\n",
            r#"{"task_id":99999,"worker":"worker-orphan","price":80,"created_at_unix_ms":1700000000001}"#,
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
    let report: Value = serde_json::from_str(out.trim()).expect("market report json");

    assert_eq!(report["task_count"], 1);
    assert_eq!(report["bid_count"], 2);
    assert_eq!(report["orphan_bid_count"], 1);
    assert_eq!(report["tasks_with_bids_count"], 1);
    assert_eq!(report["bid_coverage_rate"], 1.0);
    assert_eq!(report["avg_bids_per_task"], 2.0);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
}
