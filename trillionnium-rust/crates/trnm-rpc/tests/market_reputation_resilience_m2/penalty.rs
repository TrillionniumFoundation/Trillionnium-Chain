use super::*;

#[test]
fn market_match_clamps_negative_reputation_penalty_explainability_to_configured_boundary() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-low": -30,
  "worker-high": 0
}"#,
    )
    .expect("write reputation fixture");

    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let reputation_env = reputation.to_string_lossy().into_owned();
    let envs = [
        ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
        ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ("TRNM_RPC_MARKET_REPUTATION_FILE", reputation_env.as_str()),
        ("TRNM_RPC_MARKET_PRICE_WEIGHT", "1"),
        ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", "2"),
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", "4"),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 penalty clamp explainability fields",
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
            "80",
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
            "100",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-low");
    assert_eq!(matched["winner_reputation"], -30);
    assert_eq!(matched["winner_reputation_effective"], -4);
    assert_eq!(matched["winner_reputation_clamped"], true);

    let cfg = matched["match_config"]
        .as_object()
        .expect("match_config object");
    let reputation_weight_unit = cfg
        .get("reputation_weight")
        .and_then(Value::as_u64)
        .expect("reputation_weight") as u128;
    assert_eq!(
        cfg.get("reputation_clamp").and_then(Value::as_i64),
        Some(4),
        "match output should expose the configured negative-reputation clamp"
    );

    let base_score = matched["base_score"].as_u64().expect("base_score") as u128;
    let reputation_weight = matched["reputation_weight"]
        .as_u64()
        .expect("reputation_weight") as u128;
    let penalty = matched["penalty"].as_u64().expect("penalty") as u128;
    let final_score = matched["final_score"].as_u64().expect("final_score") as u128;
    let effective_score = matched["effective_score"]
        .as_u64()
        .expect("effective_score") as u128;

    assert_eq!(base_score, 80);
    assert_eq!(reputation_weight, 0);
    assert_eq!(penalty, 4u128 * reputation_weight_unit);
    assert_eq!(
        matched["reputation_penalty"].as_u64().expect("reputation_penalty") as u128,
        penalty
    );
    assert_eq!(
        matched["penalty_amount"].as_u64().expect("penalty_amount") as u128,
        penalty
    );
    assert_eq!(matched["reputation_score_delta"], 8);
    assert_eq!(final_score, base_score + penalty);
    assert_eq!(effective_score, final_score);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_exposes_penalty_explainability_fields_for_negative_reputation_winner() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-low": -3,
  "worker-high": 0
}"#,
    )
    .expect("write reputation fixture");

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
            "m2 explainability penalty fields",
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
            "80",
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
            "100",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-low");
    assert_eq!(matched["winner_reputation"], -3);
    assert_eq!(matched["winner_reputation_effective"], -3);
    assert_eq!(matched["winner_reputation_clamped"], false);

    let cfg = matched["match_config"]
        .as_object()
        .expect("match_config object");
    let price_weight = cfg
        .get("price_weight")
        .and_then(Value::as_u64)
        .expect("price_weight") as u128;
    let reputation_weight_unit = cfg
        .get("reputation_weight")
        .and_then(Value::as_u64)
        .expect("reputation_weight") as u128;

    assert_eq!(price_weight, 1);
    assert_eq!(reputation_weight_unit, 2);

    let base_score = matched["base_score"].as_u64().expect("base_score") as u128;
    let reputation_weight = matched["reputation_weight"]
        .as_u64()
        .expect("reputation_weight") as u128;
    let penalty = matched["penalty"].as_u64().expect("penalty") as u128;
    let final_score = matched["final_score"].as_u64().expect("final_score") as u128;
    let effective_score = matched["effective_score"]
        .as_u64()
        .expect("effective_score") as u128;

    assert_eq!(base_score, 80);
    assert_eq!(reputation_weight, 0);
    assert_eq!(penalty, 3u128 * reputation_weight_unit);
    assert_eq!(
        matched["reputation_penalty"].as_u64().expect("reputation_penalty") as u128,
        penalty
    );
    assert_eq!(
        matched["penalty_amount"].as_u64().expect("penalty_amount") as u128,
        penalty
    );
    assert_eq!(
        matched["reputation_weight_applied"]
            .as_u64()
            .expect("reputation_weight_applied") as u128,
        penalty
    );
    assert_eq!(
        matched["reputation_component"]
            .as_u64()
            .expect("reputation_component") as u128,
        penalty
    );
    assert_eq!(matched["reputation_score_delta"], 6);
    assert_eq!(final_score, base_score + penalty);
    assert_eq!(effective_score, final_score);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}
