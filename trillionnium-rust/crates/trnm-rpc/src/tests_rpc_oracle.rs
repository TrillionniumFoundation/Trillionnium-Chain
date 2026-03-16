use super::*;

#[test]
fn oracle_validate_snapshot_response_accepts_valid_snapshot() {
    let policy_path = write_json_fixture("oracle-policy-accepted", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-accepted",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("accepted oracle validation response");

    assert!(out.ok);
    assert_eq!(out.now_ts_ms, 10_100);
    assert_eq!(out.observation.outcome, "accepted");
    assert_eq!(out.observation.feed_id, "btc/usd");
    assert_eq!(out.metrics.accepted_total, 1);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert!(out.error.is_none());

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_reports_drift_rejection() {
    let policy_path = write_json_fixture("oracle-policy-drift", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-drift",
        &oracle_snapshot_fixture(120_000, Some(100_000), 10_000),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("drift oracle validation response");

    assert!(!out.ok);
    assert_eq!(out.now_ts_ms, 10_100);
    assert_eq!(out.observation.outcome, "drift");
    assert_eq!(out.metrics.oracle_drift_reject_total, 1);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(out.metrics.accepted_total, 0);
    assert!(out
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("deviation exceeded"));

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn parse_http_query_params_decodes_percent_and_plus() {
    let params = parse_http_query_params(
            "/oracle/validate_snapshot?snapshot=%2Ftmp%2Foracle+snapshot.json&policy=%2Ftmp%2Fpolicy.json&now_ts_ms=10100",
        )
        .expect("query params");

    assert_eq!(
        params.get("snapshot").map(String::as_str),
        Some("/tmp/oracle snapshot.json")
    );
    assert_eq!(
        params.get("policy").map(String::as_str),
        Some("/tmp/policy.json")
    );
    assert_eq!(params.get("now_ts_ms").map(String::as_str), Some("10100"));
}

#[test]
fn parse_http_query_params_rejects_duplicate_keys() {
    assert!(
            parse_http_query_params(
                "/oracle/validate_snapshot?snapshot=/tmp/a.json&snapshot=/tmp/b.json&policy=/tmp/p.json"
            )
            .is_none(),
            "duplicate query keys must fail closed"
        );
}

#[test]
fn parse_oracle_validate_snapshot_target_returns_stable_request_schema() {
    let request = parse_oracle_validate_snapshot_target(
            "/oracle/validate_snapshot?snapshot=%2Ftmp%2Foracle+snapshot.json&policy=%2Ftmp%2Fpolicy.json&now_ts_ms=10100",
        )
        .expect("oracle request");

    assert_eq!(request.snapshot, "/tmp/oracle snapshot.json");
    assert_eq!(request.policy, "/tmp/policy.json");
    assert_eq!(request.now_ts_ms, Some(10_100));
}

#[test]
fn parse_oracle_validate_snapshot_target_rejects_unknown_query_keys() {
    let err = parse_oracle_validate_snapshot_target(
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=/tmp/p.json&feed_id=btc%2Fusd",
    )
    .expect_err("unknown key must fail closed");

    assert!(err.contains("unknown query parameter: feed_id"), "{err}");
}

#[test]
fn parse_oracle_validate_snapshot_target_rejects_empty_snapshot_or_policy() {
    let snapshot_err = parse_oracle_validate_snapshot_target(
        "/oracle/validate_snapshot?snapshot=&policy=/tmp/p.json",
    )
    .expect_err("empty snapshot must fail closed");
    assert_eq!(snapshot_err, "empty snapshot");

    let policy_err = parse_oracle_validate_snapshot_target(
        "/oracle/validate_snapshot?snapshot=/tmp/s.json&policy=+",
    )
    .expect_err("empty policy must fail closed");
    assert_eq!(policy_err, "empty policy");
}

#[test]
fn http_service_response_for_oracle_validate_snapshot_returns_structured_json() {
    let policy_path = write_json_fixture("oracle-policy-http", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-http",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );
    let target = format!(
        "/oracle/validate_snapshot?snapshot={}&policy={}&now_ts_ms=10100",
        snapshot_path.display(),
        policy_path.display()
    );

    let response = http_service_response_for_target(Some(&target));

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("\"ok\":true"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("\"outcome\":\"accepted\""),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("\"accepted_total\":1"),
        "unexpected response: {}",
        response
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn http_service_response_for_oracle_metrics_returns_prometheus_text() {
    let policy_path = write_json_fixture("oracle-policy-metrics", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-metrics",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );
    let target = format!(
        "/oracle/metrics?snapshot={}&policy={}&now_ts_ms=10100",
        snapshot_path.display(),
        policy_path.display()
    );

    let response = http_service_response_for_target(Some(&target));

    assert!(
        response.starts_with(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
        ),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("oracle_validation_ok{feed_id=\"btc/usd\",outcome=\"accepted\"} 1"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("accepted_total{feed_id=\"btc/usd\",outcome=\"accepted\"} 1"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("oracle_source_cardinality{feed_id=\"btc/usd\",outcome=\"accepted\"} 2"),
        "unexpected response: {}",
        response
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn http_service_response_for_oracle_metrics_rejects_unknown_query_keys() {
    let response = http_service_response_for_target(Some(
        "/oracle/metrics?snapshot=/tmp/s.json&policy=/tmp/p.json&feed_id=btc%2Fusd",
    ));

    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(
        response.contains("unknown query parameter: feed_id"),
        "{response}"
    );
}

#[test]
fn http_service_response_for_metrics_rejects_empty_oracle_query_values() {
    let response = http_service_response_for_target(Some("/metrics?snapshot=&policy=/tmp/p.json"));

    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(
        response.contains("\"message\":\"empty snapshot\""),
        "{response}"
    );
}

#[test]
fn http_service_response_for_metrics_returns_base_prometheus_text() {
    let response = http_service_response_for_target(Some("/metrics"));

    assert!(
        response.starts_with(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
        ),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("trnm_rpc_service_up{service=\"trnm-rpc\"} 1"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("trnm_rpc_service_info{service=\"trnm-rpc\",version=\"1\"} 1"),
        "unexpected response: {}",
        response
    );
}

#[test]
fn http_service_response_for_metrics_appends_oracle_metrics_when_queried() {
    let policy_path = write_json_fixture("oracle-policy-global-metrics", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-global-metrics",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );
    let target = format!(
        "/metrics?snapshot={}&policy={}&now_ts_ms=10100",
        snapshot_path.display(),
        policy_path.display()
    );

    let response = http_service_response_for_target(Some(&target));

    assert!(
        response.contains("trnm_rpc_service_up{service=\"trnm-rpc\"} 1"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("oracle_validation_ok{feed_id=\"btc/usd\",outcome=\"accepted\"} 1"),
        "unexpected response: {}",
        response
    );
    assert!(
        response.contains("accepted_total{feed_id=\"btc/usd\",outcome=\"accepted\"} 1"),
        "unexpected response: {}",
        response
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn resolve_capability_token_subject_or_token_strips_invisible_controls_before_lookup() {
    let mut registry = IdentityRegistry::default();
    registry
        .register_did(
            "did:org:lane-xi".to_string(),
            "org:lane-xi-admin".to_string(),
            10,
        )
        .expect("register did");
    let token_id = registry
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:org:lane-xi".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(120),
        )
        .expect("issue capability");

    assert_eq!(
        resolve_capability_token_subject_or_token(&registry, " \u{FEFF}did:org:lane-xi\u{200B} ",),
        Some(token_id)
    );
}

#[test]
fn resolve_capability_token_subject_or_token_rejects_noncanonical_subject_alias() {
    let mut registry = IdentityRegistry::default();
    registry
        .register_did(
            "did:org:lane-xi".to_string(),
            "org:lane-xi-admin".to_string(),
            10,
        )
        .expect("register did");
    let token_id = registry
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:org:lane-xi".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(120),
        )
        .expect("issue capability");

    assert_eq!(
        resolve_capability_token_subject_or_token(&registry, "did:org:lane-xi\n"),
        Some(token_id)
    );
    assert_eq!(
        resolve_capability_token_subject_or_token(&registry, "did:org:lane xi"),
        None,
        "non-canonical DID aliases must fail closed"
    );
}

#[test]
fn resolve_capability_token_subject_or_token_fail_closed_without_structured_token() {
    let mut registry = IdentityRegistry::default();
    registry
        .register_did(
            "did:org:lane-xi".to_string(),
            "org:lane-xi-admin".to_string(),
            10,
        )
        .expect("register did");
    let token_id = registry
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:org:lane-xi".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(120),
        )
        .expect("issue capability");

    let mut raw = serde_json::to_value(&registry).expect("serialize registry");
    raw["capabilities"] = serde_json::json!({});
    if let Some(events) = raw["audit_trail"].as_array_mut() {
        if let Some(last) = events.last_mut() {
            last["note"] = serde_json::json!(format!("legacy-note token_id={token_id}"));
        }
    }
    let imported: IdentityRegistry =
        serde_json::from_value(raw).expect("deserialize mutated registry");

    assert_eq!(
        resolve_capability_token_subject_or_token(&imported, "did:org:lane-xi"),
        None,
        "subject lookup must fail-closed when structured token mapping is missing"
    );
}

#[test]
fn parse_http_get_path_accepts_canonical_request_line() {
    assert_eq!(
        parse_http_get_path("GET /query-task/42?verbose=1 HTTP/1.1"),
        Some("/query-task/42")
    );
    assert_eq!(
            parse_http_get_target("GET /oracle/validate_snapshot?snapshot=%2Ftmp%2Fs.json&policy=%2Ftmp%2Fp.json HTTP/1.1"),
            Some("/oracle/validate_snapshot?snapshot=%2Ftmp%2Fs.json&policy=%2Ftmp%2Fp.json")
        );
}

#[test]
fn parse_http_get_path_rejects_non_get_or_malformed_lines() {
    assert_eq!(parse_http_get_path("POST /health HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health"), None);
    assert_eq!(parse_http_get_path("GET health HTTP/1.1"), None);
    assert_eq!(parse_http_get_path("GET /health\u{0001} HTTP/1.1"), None);
}

#[test]
fn read_http_request_head_times_out_on_partial_slowloris_client() {
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");

    let client = thread::spawn(move || {
        let mut client = TcpStream::connect(addr).expect("connect test listener");
        client
            .write_all(b"GET /health HTTP/1.1")
            .expect("write partial request");
        thread::sleep(Duration::from_millis(HEALTH_SOCKET_READ_TIMEOUT_MS + 250));
        let _ = client.shutdown(Shutdown::Both);
    });

    let (mut server_stream, _) = listener.accept().expect("accept test client");
    configure_health_stream(&server_stream).expect("configure timeouts");
    let err =
        read_http_request_head(&mut server_stream).expect_err("partial request must time out");
    assert!(matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ));

    client.join().expect("client thread join");
}

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
