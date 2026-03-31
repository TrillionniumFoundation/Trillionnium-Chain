use super::*;

#[test]
fn market_match_applies_reputation_weighting_from_fixture_for_m2_priority() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-low": 0,
  "worker-high": 10
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
            "m2 reputation weighted winner",
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
    assert_eq!(matched["winner_reputation_lookup_missing"], false);
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_reports_missing_reputation_lookup_when_winner_defaults_to_zero() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(&reputation, "{}\n").expect("write empty reputation fixture");

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
            "m2 distinguishes missing reputation lookups from literal zero scores",
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
            "worker-missing",
            "--price",
            "100",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-missing");
    assert_eq!(matched["winner_reputation"], 0);
    assert_eq!(matched["winner_reputation_lookup_key"], "worker-missing");
    assert_eq!(matched["winner_reputation_lookup_missing"], true);
    assert_eq!(matched["winner_reputation_clamped"], false);
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_parses_integer_string_reputation_values_for_m2_weighting() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-low": "0",
  "worker-high": "10"
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
            "m2 string reputation values",
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
    assert_eq!(matched["winner_reputation_lookup_missing"], false);
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_exposes_score_floor_when_reputation_reward_exceeds_base_score() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-high": 10
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
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", "100"),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 exposes score floor when reputation reward dominates",
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
            "worker-high",
            "--price",
            "5",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-high");
    assert_eq!(matched["base_score"], 5);
    assert_eq!(matched["reputation_weight"], 20);
    assert_eq!(matched["effective_score"], 0);
    assert_eq!(matched["score_floor_applied"], true);
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_exposes_when_winner_reputation_was_clamped() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-high": 10
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
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", "2"),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 exposes clamped winner reputation",
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
            "worker-high",
            "--price",
            "100",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-high");
    assert_eq!(matched["winner_reputation"], 10);
    assert_eq!(matched["winner_reputation_effective"], 2);
    assert_eq!(matched["winner_reputation_clamp_limit"], 2);
    assert_eq!(matched["winner_reputation_clamped"], true);
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_respects_reputation_clamp_for_m2_score_stability() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-low": 0,
  "worker-high": 10
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
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", "2"),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 clamp keeps price dominant when rep spikes",
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

    assert_eq!(matched["winner"], "worker-low");
    assert_eq!(matched["winner_reputation"], 0);
    assert_eq!(matched["winner_reputation_clamped"], false);
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let cfg = matched["match_config"]
        .as_object()
        .expect("match_config object");
    assert_eq!(
        cfg.get("reputation_clamp").and_then(Value::as_i64),
        Some(2),
        "match output should expose the clamp that kept price dominant"
    );

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_normalizes_wrapped_weight_envs_in_output_config() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-high": 4
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
        ("TRNM_RPC_MARKET_PRICE_WEIGHT", " '7' "),
        ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", " \"11\" "),
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", " `13` "),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 normalizes wrapped weighting env values",
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
            "worker-high",
            "--price",
            "100",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    let cfg = matched["match_config"]
        .as_object()
        .expect("match_config object");
    assert_eq!(cfg.get("price_weight").and_then(Value::as_u64), Some(7));
    assert_eq!(
        cfg.get("reputation_weight").and_then(Value::as_u64),
        Some(11)
    );
    assert_eq!(
        cfg.get("reputation_clamp").and_then(Value::as_i64),
        Some(13)
    );
    assert_eq!(
        cfg.get("max_reputation_score_delta")
            .and_then(Value::as_u64),
        Some(143)
    );
    assert_eq!(
        cfg.get("min_reputation_score_delta")
            .and_then(Value::as_i64),
        Some(-143)
    );
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_fails_closed_for_invalid_wrapped_weight_envs_in_output_config() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-high": 4
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
        ("TRNM_RPC_MARKET_PRICE_WEIGHT", " 'oops' "),
        ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", " \"nan\" "),
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", " `bad` "),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 invalid wrapped weighting envs fail closed in output config",
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
            "worker-high",
            "--price",
            "100",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    let cfg = matched["match_config"]
        .as_object()
        .expect("match_config object");
    assert_eq!(cfg.get("price_weight").and_then(Value::as_u64), Some(1000));
    assert_eq!(
        cfg.get("reputation_weight").and_then(Value::as_u64),
        Some(100)
    );
    assert_eq!(cfg.get("reputation_clamp").and_then(Value::as_i64), Some(1000));
    assert_eq!(
        cfg.get("max_reputation_score_delta").and_then(Value::as_u64),
        Some(100_000)
    );
    assert_eq!(
        cfg.get("min_reputation_score_delta").and_then(Value::as_i64),
        Some(-100_000)
    );
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_clamps_wrapped_overflow_weight_envs_in_output_config() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-high": 3
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
        ("TRNM_RPC_MARKET_PRICE_WEIGHT", " '999999999' "),
        ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", " \"999999999\" "),
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", " `999999999` "),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 clamps wrapped overflow weighting env values to boundaries",
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
            "worker-high",
            "--price",
            "2",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    let cfg = matched["match_config"]
        .as_object()
        .expect("match_config object");
    assert_eq!(cfg.get("price_weight").and_then(Value::as_u64), Some(1_000_000));
    assert_eq!(
        cfg.get("reputation_weight").and_then(Value::as_u64),
        Some(1_000_000)
    );
    assert_eq!(
        cfg.get("reputation_clamp").and_then(Value::as_i64),
        Some(1_000_000)
    );
    assert_eq!(
        cfg.get("max_reputation_score_delta").and_then(Value::as_u64),
        Some(1_000_000_000_000)
    );
    assert_eq!(
        cfg.get("min_reputation_score_delta").and_then(Value::as_i64),
        Some(-1_000_000_000_000)
    );
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_normalizes_nested_wrapped_below_floor_clamp_in_output_config() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-low": -9
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
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", " ' \"-2\" ' "),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 normalizes nested wrapped below-floor clamp env values",
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

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-low");
    assert_eq!(matched["winner_reputation"], -9);
    assert_eq!(matched["winner_reputation_effective"], -1);
    assert_eq!(matched["winner_reputation_clamped"], true);
    assert_eq!(matched["penalty"], 2);
    assert_eq!(matched["effective_score"], 102);
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let cfg = matched["match_config"]
        .as_object()
        .expect("match_config object");
    assert_eq!(cfg.get("price_weight").and_then(Value::as_u64), Some(1));
    assert_eq!(
        cfg.get("reputation_weight").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(cfg.get("reputation_clamp").and_then(Value::as_i64), Some(1));

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_exposes_negative_clamp_without_leaking_raw_penalty_weight() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-low": -10,
  "worker-neutral": 0
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
        ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", "3"),
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", "2"),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 negative clamp exposes bounded penalty fields",
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

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-low");
    assert_eq!(matched["winner_reputation"], -10);
    assert_eq!(matched["winner_reputation_effective"], -2);
    assert_eq!(matched["winner_reputation_clamped"], true);
    assert_eq!(matched["base_score"], 100);
    assert_eq!(matched["reputation_weight"], 0);
    assert_eq!(matched["penalty"], 6);
    assert_eq!(matched["reputation_score_delta"], 6);
    assert_eq!(matched["effective_score"], 106);
    assert_eq!(matched["score_floor_applied"], false);
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let cfg = matched["match_config"]
        .as_object()
        .expect("match_config object");
    assert_eq!(
        cfg.get("reputation_clamp").and_then(Value::as_i64),
        Some(2),
        "match output should expose the clamp that bounded the negative penalty"
    );

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_normalizes_zero_reputation_clamp_to_fail_closed_output_limit() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-clamped": 9
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
        ("TRNM_RPC_MARKET_PRICE_WEIGHT", "3"),
        ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", "4"),
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", "0"),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 zero clamp reports fail-closed limit",
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
            "worker-clamped",
            "--price",
            "100",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-clamped");
    assert_eq!(matched["winner_reputation"], 9);
    assert_eq!(matched["winner_reputation_effective"], 1);
    assert_eq!(matched["winner_reputation_clamp_limit"], 1);
    assert_eq!(matched["winner_reputation_clamped"], true);
    assert_eq!(matched["base_score"], 300);
    assert_eq!(matched["reputation_reward"], 4);
    assert_eq!(matched["reputation_score_delta"], -4);
    assert_eq!(matched["effective_score"], 296);
    assert_eq!(matched["score_floor_applied"], false);

    let cfg = matched["match_config"]
        .as_object()
        .expect("match_config object");
    assert_eq!(
        cfg.get("reputation_clamp").and_then(Value::as_i64),
        Some(1),
        "match config should expose the normalized fail-closed clamp"
    );

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}

#[test]
fn market_match_treats_zero_effective_reputation_as_neutral_in_output_fields() {
    let _guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(
        &reputation,
        r#"{
  "worker-neutral": "0"
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
        ("TRNM_RPC_MARKET_PRICE_WEIGHT", "3"),
        ("TRNM_RPC_MARKET_REPUTATION_WEIGHT", "11"),
        ("TRNM_RPC_MARKET_REPUTATION_CLAMP", "2"),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "120",
            "--description",
            "m2 zero effective reputation stays neutral end-to-end",
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
            "worker-neutral",
            "--price",
            "100",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-neutral");
    assert_eq!(matched["winner_reputation"], 0);
    assert_eq!(matched["winner_reputation_effective"], 0);
    assert_eq!(matched["winner_reputation_lookup_missing"], false);
    assert_eq!(matched["winner_reputation_clamped"], false);
    assert_eq!(matched["base_score"], 300);
    assert_eq!(matched["reputation_reward"], 0);
    assert_eq!(matched["penalty"], 0);
    assert_eq!(matched["reputation_score_delta"], 0);
    assert_eq!(matched["effective_score"], 300);
    assert_eq!(matched["score_floor_applied"], false);

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}
