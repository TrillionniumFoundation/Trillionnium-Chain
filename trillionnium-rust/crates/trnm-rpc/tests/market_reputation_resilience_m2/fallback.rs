use super::*;

#[test]
fn market_match_falls_back_to_zero_reputation_when_reputation_file_is_malformed_json() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    assert_match_falls_back_to_price_order_with_invalid_reputation_fixture(
        "{not valid json",
        "m2 malformed reputation fallback",
    );
}

#[test]
fn market_match_falls_back_to_zero_reputation_when_reputation_file_is_valid_json_but_wrong_shape() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    assert_match_falls_back_to_price_order_with_invalid_reputation_fixture(
        "[{\"worker\":\"worker-high\",\"reputation\":900}]",
        "m2 wrong-shape reputation fallback",
    );
}

#[test]
fn market_match_salvages_valid_reputation_entries_when_fixture_has_partial_invalid_values() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-low": "NaN",
  "worker-high": 10
}"#,
    )
    .expect("write partial-invalid reputation fixture");

    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let reputation_env = reputation.to_string_lossy().into_owned();
    let envs = [
        ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
        ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ("TRNM_RPC_MARKET_REPUTATION_FILE", reputation_env.as_str()),
        ("TRNM_RPC_MARKET_PRICE_WEIGHT", "1"),
        ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", "2"),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 partial-invalid reputation salvage",
        ],
        &envs,
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
        &envs,
    );

    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_id,
            "--worker",
            "worker-high",
            "--price",
            "105",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-high");
    assert_eq!(matched["winner_reputation"], 10);
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}
