pub(crate) use super::*;

#[test]
fn clamp_limit_enforces_max() {
    let got = clamp_limit(
        "QueryEvents",
        QUERY_EVENTS_LIMIT_MAX + 1,
        QUERY_EVENTS_LIMIT_DEFAULT,
        QUERY_EVENTS_LIMIT_MAX,
    );
    assert_eq!(got, QUERY_EVENTS_LIMIT_MAX);
}

#[test]
fn clamp_limit_uses_default_when_zero() {
    let got = clamp_limit(
        "DispatchOpen",
        0,
        DISPATCH_OPEN_LIMIT_DEFAULT,
        DISPATCH_OPEN_LIMIT_MAX,
    );
    assert_eq!(got, DISPATCH_OPEN_LIMIT_DEFAULT);
}

#[test]
fn clamp_limit_keeps_in_range_value() {
    let got = clamp_limit(
        "QueryRequestFull",
        17,
        QUERY_FULL_LIMIT_DEFAULT,
        QUERY_FULL_LIMIT_MAX,
    );
    assert_eq!(got, 17);
}

#[test]
fn task_state_file_uses_trimmed_env_path() {
    with_market_path_env(
        &[(TASK_STATE_FILE_ENV, Some("  '/tmp/task-state.jsonl'  "))],
        || {
            assert_eq!(
                task_state_file(),
                Some(PathBuf::from("/tmp/task-state.jsonl"))
            );
        },
    );
}

#[test]
fn load_task_state_snapshot_tolerates_utf8_bom_prefixed_jsonl_rows() {
    let path = unique_tmp_path("rpc-task-state-bom", "jsonl");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        concat!(
            "\u{feff}{\"task_id\":77,\"status\":\"Open\",\"worker\":null,\"bounty\":7,\"result_hash\":null,\"version\":3}\n",
            "{\"task_id\":77,\"status\":\"Assigned\",\"worker\":\"worker-1\",\"bounty\":7,\"result_hash\":null,\"version\":4}\n"
        ),
    )
    .expect("write bom-prefixed task snapshot");

    with_market_path_env(&[(TASK_STATE_FILE_ENV, path.to_str())], || {
        let tasks = load_task_state_snapshot().expect("task snapshot should parse");
        assert_eq!(tasks.len(), 2, "BOM-prefixed first row should not hide durable task history");
        assert_eq!(tasks[0].task_id, 77);
        assert_eq!(tasks[0].version, 3);
        assert_eq!(tasks[1].version, 4);
    });

    let _ = fs::remove_file(&path);
}

#[test]
fn load_task_state_snapshot_tolerates_whitespace_prefixed_utf8_bom_rows() {
    let path = unique_tmp_path("rpc-task-state-bom-whitespace", "jsonl");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        concat!(
            "  \u{feff}{\"task_id\":88,\"status\":\"Open\",\"worker\":null,\"bounty\":8,\"result_hash\":null,\"version\":5}\n",
            "{\"task_id\":88,\"status\":\"Assigned\",\"worker\":\"worker-2\",\"bounty\":8,\"result_hash\":null,\"version\":6}\n"
        ),
    )
    .expect("write whitespace-prefixed bom task snapshot");

    with_market_path_env(&[(TASK_STATE_FILE_ENV, path.to_str())], || {
        let tasks = load_task_state_snapshot().expect("task snapshot should parse");
        assert_eq!(
            tasks.len(),
            2,
            "leading whitespace before BOM should not hide durable task history"
        );
        assert_eq!(tasks[0].task_id, 88);
        assert_eq!(tasks[0].version, 5);
        assert_eq!(tasks[1].version, 6);
    });

    let _ = fs::remove_file(&path);
}

#[test]
fn load_task_state_snapshot_tolerates_crlf_separated_whitespace_prefixed_utf8_bom_rows() {
    let path = unique_tmp_path("rpc-task-state-bom-whitespace-crlf", "jsonl");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        concat!(
            "\r\n  \u{feff}{\"task_id\":99,\"status\":\"Open\",\"worker\":null,\"bounty\":9,\"result_hash\":null,\"version\":7}\r\n",
            "{\"task_id\":99,\"status\":\"Assigned\",\"worker\":\"worker-3\",\"bounty\":9,\"result_hash\":null,\"version\":8}\r\n\r\n"
        ),
    )
    .expect("write crlf whitespace-prefixed bom task snapshot");

    with_market_path_env(&[(TASK_STATE_FILE_ENV, path.to_str())], || {
        let tasks = load_task_state_snapshot().expect("task snapshot should parse");
        assert_eq!(
            tasks.len(),
            2,
            "crlf-separated task snapshots with leading whitespace before BOM should keep durable task history readable"
        );
        assert_eq!(tasks[0].task_id, 99);
        assert_eq!(tasks[0].version, 7);
        assert_eq!(tasks[1].version, 8);
    });

    let _ = fs::remove_file(&path);
}

#[test]
fn load_task_state_snapshot_tolerates_invalid_utf8_prefix_before_valid_history_rows() {
    let path = unique_tmp_path("rpc-task-state-invalid-utf8-prefix", "jsonl");
    let _ = fs::remove_file(&path);
    fs::write(
        &path,
        b"\xff\xfe\xfa\n{\"task_id\":109,\"status\":\"Open\",\"worker\":null,\"bounty\":10,\"result_hash\":null,\"version\":9}\n{\"task_id\":109,\"status\":\"Assigned\",\"worker\":\"worker-4\",\"bounty\":10,\"result_hash\":null,\"version\":10}\n",
    )
    .expect("write invalid utf8-prefixed task snapshot");

    with_market_path_env(&[(TASK_STATE_FILE_ENV, path.to_str())], || {
        let tasks = load_task_state_snapshot().expect("task snapshot should parse after lossy utf8 recovery");
        assert_eq!(
            tasks.len(),
            2,
            "invalid utf-8 prefix bytes should not erase later durable task history rows"
        );
        assert_eq!(tasks[0].task_id, 109);
        assert_eq!(tasks[0].version, 9);
        assert_eq!(tasks[1].version, 10);
    });

    let _ = fs::remove_file(&path);
}

#[test]
fn push_tail_limited_keeps_only_most_recent_items_in_order() {
    let mut items = Vec::new();
    push_tail_limited(&mut items, 1, 3);
    push_tail_limited(&mut items, 2, 3);
    push_tail_limited(&mut items, 3, 3);
    push_tail_limited(&mut items, 4, 3);
    push_tail_limited(&mut items, 5, 3);
    assert_eq!(items, vec![3, 4, 5]);
}

#[test]
fn push_tail_limited_fail_closes_when_limit_is_zero() {
    let mut items = vec![1, 2, 3];
    push_tail_limited(&mut items, 4, 0);
    assert_eq!(items, vec![1, 2, 3]);
}

#[test]
fn normalized_path_from_env_trims_shell_wrapped_quotes() {
    with_market_path_env(
        &[(
            "TRNM_RPC_MARKET_TASKS_FILE",
            Some("  \"/tmp/tasks.jsonl\"  "),
        )],
        || {
            assert_eq!(
                normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                Some(PathBuf::from("/tmp/tasks.jsonl"))
            );
        },
    );

    with_market_path_env(
        &[("TRNM_RPC_MARKET_TASKS_FILE", Some("'`/tmp/tasks.jsonl`'"))],
        || {
            assert_eq!(
                normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                Some(PathBuf::from("/tmp/tasks.jsonl"))
            );
        },
    );
}

#[test]
fn market_path_file_helpers_fallback_when_env_is_empty_after_trim() {
    with_market_path_env(
        &[
            ("TRNM_RPC_MARKET_TASKS_FILE", Some("   ")),
            ("TRNM_RPC_MARKET_BIDS_FILE", Some(" \"\" ")),
            ("TRNM_RPC_INGRESS_FILE", Some(" `   ` ")),
            (MARKET_REPUTATION_FILE_ENV, Some("  ''  ")),
        ],
        || {
            assert_eq!(
                market_tasks_file(),
                run_root().join("run/market/tasks.jsonl")
            );
            assert_eq!(market_bids_file(), run_root().join("run/market/bids.jsonl"));
            assert_eq!(
                ingress_file(),
                run_root().join("run/message-gateway/requests.jsonl")
            );
            assert_eq!(
                market_reputation_file(),
                run_root().join("run/market/reputation.json")
            );
        },
    );
}

#[test]
fn rpc_state_paths_use_same_wrapped_env_and_empty_fallback_rules() {
    let _guard = lock_env();
    let keys = [
        "TRNM_RPC_ACCOUNTS_FILE",
        "TRNM_RPC_TX_FILE",
        "TRNM_RPC_FAUCET_LIMITS_FILE",
    ];
    let prev: Vec<(String, Option<String>)> = keys
        .iter()
        .map(|k| ((*k).to_string(), std::env::var(k).ok()))
        .collect();

    unsafe {
        std::env::set_var("TRNM_RPC_ACCOUNTS_FILE", "  \"/tmp/accounts.json\"  ");
        std::env::set_var("TRNM_RPC_TX_FILE", " '`/tmp/txs.json`' ");
        std::env::set_var("TRNM_RPC_FAUCET_LIMITS_FILE", "  /tmp/faucet_limits.json  ");
    }
    assert_eq!(account_state_file(), PathBuf::from("/tmp/accounts.json"));
    assert_eq!(tx_lifecycle_file(), PathBuf::from("/tmp/txs.json"));
    assert_eq!(
        faucet_limits_file(),
        PathBuf::from("/tmp/faucet_limits.json")
    );

    unsafe {
        std::env::set_var("TRNM_RPC_ACCOUNTS_FILE", "  \"\"  ");
        std::env::set_var("TRNM_RPC_TX_FILE", "  ''  ");
        std::env::set_var("TRNM_RPC_FAUCET_LIMITS_FILE", " `   ` ");
    }
    assert_eq!(
        account_state_file(),
        run_root().join("run/rpc/accounts.json")
    );
    assert_eq!(tx_lifecycle_file(), run_root().join("run/rpc/txs.json"));
    assert_eq!(
        faucet_limits_file(),
        run_root().join("run/rpc/faucet_limits.json")
    );

    for (k, v) in prev {
        match v {
            Some(val) => unsafe { std::env::set_var(&k, val) },
            None => unsafe { std::env::remove_var(&k) },
        }
    }
}

#[test]
fn acquire_market_file_lock_cleans_stale_lock_file() {
    let _guard = lock_env();
    let prev = std::env::var("TRNM_RPC_MARKET_LOCK_STALE_MS").ok();
    unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", "1000") };

    let path = unique_tmp_path("market-lock", "jsonl");
    let lock_path = market_lock_path(&path);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).expect("create lock dir");
    }
    fs::write(&lock_path, "stale").expect("seed stale lock");
    // Use extra margin above the 1000ms stale threshold to avoid filesystem
    // timestamp granularity edge-cases on slower CI runners.
    std::thread::sleep(Duration::from_millis(1200));

    {
        let _lock = acquire_market_file_lock(&path).expect("acquire cleans stale lock");
        assert!(lock_path.exists());
    }
    assert!(!lock_path.exists());

    match prev {
        Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", v) },
        None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_STALE_MS") },
    }
}

#[test]
fn acquire_market_file_lock_respects_timeout_when_lock_is_live() {
    let _guard = lock_env();
    let prev_timeout = std::env::var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS").ok();
    let prev_stale = std::env::var("TRNM_RPC_MARKET_LOCK_STALE_MS").ok();

    unsafe {
        // Keep timeout short for deterministic gate speed.
        std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "100");
        // Treat existing lock as live (not stale) for this check.
        std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", "60000");
    }

    let path = unique_tmp_path("market-lock-timeout", "jsonl");
    let lock_path = market_lock_path(&path);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).expect("create lock dir");
    }
    fs::write(&lock_path, "live").expect("seed live lock");

    let start = Instant::now();
    let err = match acquire_market_file_lock(&path) {
        Ok(_) => panic!("lock should time out while live lock exists"),
        Err(err) => err,
    };
    let elapsed = start.elapsed();
    let msg = err.to_string();

    assert!(msg.contains("timed out waiting for market file lock"));
    // Sleep interval is 10ms; allow scheduler jitter plus occasional heavily-loaded
    // CI runners while still catching hangs/regressions that overshoot timeout badly.
    let timeout_ms = market_lock_timeout_ms();
    let lower_bound_ms = timeout_ms.saturating_sub(10);
    let upper_bound_ms = timeout_ms.saturating_mul(8).saturating_add(200);
    assert!(elapsed >= Duration::from_millis(lower_bound_ms));
    assert!(elapsed < Duration::from_millis(upper_bound_ms));

    let _ = fs::remove_file(&lock_path);

    match prev_timeout {
        Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", v) },
        None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") },
    }
    match prev_stale {
        Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", v) },
        None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_STALE_MS") },
    }
}

#[test]
fn market_lock_timeout_ms_uses_wrapped_env_with_clamp_and_fallback() {
    let _guard = lock_env();
    let prev = std::env::var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS").ok();

    unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") };
    assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_DEFAULT);

    unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "  `50`  ") };
    assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_MIN);

    unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "  \"70000\"  ") };
    assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_MAX);

    unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "  not-a-number  ") };
    assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_DEFAULT);

    match prev {
        Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", v) },
        None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") },
    }
}

#[test]
fn env_u64_with_min_accepts_wrapped_values_and_empty_fallback() {
    let _guard = lock_env();
    let key = "TRNM_RPC_TEST_ENV_U64_WITH_MIN";
    let prev = std::env::var(key).ok();

    unsafe { std::env::set_var(key, "  \"12\"  ") };
    assert_eq!(env_u64_with_min(key, 8, 1), 12);

    unsafe { std::env::set_var(key, "  ''  ") };
    assert_eq!(env_u64_with_min(key, 8, 1), 8);

    unsafe { std::env::set_var(key, "  `0`  ") };
    assert_eq!(env_u64_with_min(key, 8, 3), 3);

    match prev {
        Some(v) => unsafe { std::env::set_var(key, v) },
        None => unsafe { std::env::remove_var(key) },
    }
}
