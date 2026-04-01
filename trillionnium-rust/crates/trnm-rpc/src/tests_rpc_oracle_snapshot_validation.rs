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
fn oracle_validate_snapshot_response_rejects_exact_drift_boundary_fail_closed() {
    let policy_path = write_json_fixture("oracle-policy-drift-boundary", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-drift-boundary",
        &oracle_snapshot_fixture(105_000, Some(100_000), 10_000),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("boundary drift oracle validation response");

    assert!(!out.ok);
    assert_eq!(out.now_ts_ms, 10_100);
    assert_eq!(out.observation.outcome, "drift");
    assert_eq!(out.metrics.oracle_drift_reject_total, 1);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(out.metrics.accepted_total, 0);
    assert_eq!(out.error.as_deref(), Some("deviation exceeded"));

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_accepts_zero_deviation_exact_match() {
    let policy_path = write_json_fixture(
        "oracle-policy-zero-deviation-exact-match",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 2,
            "max_deviation_bps": 0,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-zero-deviation-exact-match",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("zero-deviation exact match should remain admissible");

    assert!(out.ok);
    assert_eq!(out.now_ts_ms, 10_100);
    assert_eq!(out.observation.outcome, "accepted");
    assert_eq!(out.metrics.oracle_drift_reject_total, 0);
    assert_eq!(out.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(out.metrics.oracle_stale_reject_total, 0);
    assert_eq!(out.metrics.accepted_total, 1);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert!(out.error.is_none());

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_uses_canonical_source_cardinality_for_duplicate_source_ids() {
    let policy_path = write_json_fixture("oracle-policy-duplicate-sources", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-duplicate-sources",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 100_000,
            "feed_id": "btc/usd",
            "sources": [
                {
                    "source_id": "binance",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                },
                {
                    "source_id": "BINANCE",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                },
                {
                    "source_id": "coinbase",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                }
            ]
        }),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("duplicate-source oracle validation response");

    assert!(out.ok);
    assert_eq!(out.observation.outcome, "accepted");
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert_eq!(out.metrics.accepted_total, 1);
    assert_eq!(out.metrics.sample_count, 1);
    assert!(out.error.is_none());

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_quorum_when_duplicate_source_ids_reduce_cardinality() {
    let policy_path = write_json_fixture("oracle-policy-duplicate-quorum", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-duplicate-quorum",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 100_000,
            "feed_id": "btc/usd",
            "sources": [
                {
                    "source_id": "binance",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                },
                {
                    "source_id": "BINANCE",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                }
            ]
        }),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("duplicate-quorum oracle validation response");

    assert!(!out.ok);
    assert_eq!(out.observation.outcome, "quorum");
    assert_eq!(out.metrics.oracle_source_cardinality, 1);
    assert_eq!(out.metrics.oracle_quorum_reject_total, 1);
    assert_eq!(out.metrics.accepted_total, 0);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(out.error.as_deref(), Some("quorum reject"));

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_quorum_when_whitespace_wrapped_source_ids_collapse_cardinality() {
    let policy_path = write_json_fixture("oracle-policy-whitespace-duplicate-quorum", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-whitespace-duplicate-quorum",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 100_000,
            "feed_id": "btc/usd",
            "sources": [
                {
                    "source_id": " binance ",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                },
                {
                    "source_id": "BINANCE",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                }
            ]
        }),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("whitespace-duplicate-quorum oracle validation response");

    assert!(!out.ok);
    assert_eq!(out.observation.outcome, "quorum");
    assert_eq!(out.metrics.oracle_source_cardinality, 1);
    assert_eq!(out.metrics.oracle_quorum_reject_total, 1);
    assert_eq!(out.metrics.accepted_total, 0);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(out.error.as_deref(), Some("quorum reject"));

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_excludes_blank_source_ids_from_canonical_cardinality() {
    let policy_path = write_json_fixture("oracle-policy-blank-source-cardinality", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-blank-source-cardinality",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 100_000,
            "feed_id": "btc/usd",
            "sources": [
                {
                    "source_id": "binance",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                },
                {
                    "source_id": "   ",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                },
                {
                    "source_id": "\t",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                }
            ]
        }),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("blank-source-cardinality oracle validation response");

    assert!(!out.ok);
    assert_eq!(out.observation.outcome, "quorum");
    assert_eq!(out.metrics.oracle_source_cardinality, 1);
    assert_eq!(out.metrics.oracle_quorum_reject_total, 1);
    assert_eq!(out.metrics.accepted_total, 0);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(out.error.as_deref(), Some("quorum reject"));

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_accepts_exact_staleness_boundary_without_quorum_or_drift_counter_noise() {
    let policy_path = write_json_fixture("oracle-policy-stale-boundary", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-stale-boundary",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 70_000)
        .expect("boundary staleness oracle validation response");

    assert!(out.ok);
    assert_eq!(out.observation.outcome, "accepted");
    assert_eq!(out.metrics.oracle_stale_reject_total, 0);
    assert_eq!(out.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(out.metrics.oracle_drift_reject_total, 0);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert_eq!(out.metrics.accepted_total, 1);
    assert_eq!(out.metrics.sample_count, 1);
    assert!(out.error.is_none());

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_future_snapshot_as_fail_closed_stale_outcome() {
    let policy_path = write_json_fixture("oracle-policy-future-snapshot", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-future-snapshot",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_001),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_000)
        .expect("future snapshot oracle validation response");

    assert!(!out.ok);
    assert_eq!(out.observation.outcome, "stale");
    assert_eq!(out.metrics.oracle_stale_reject_total, 1);
    assert_eq!(out.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(out.metrics.oracle_drift_reject_total, 0);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert_eq!(out.metrics.accepted_total, 0);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(
        out.error.as_deref(),
        Some("snapshot future: observed_at_ms=10001 now_ts_ms=10000")
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_prefers_stale_outcome_over_quorum_and_drift_failures() {
    let policy_path = write_json_fixture("oracle-policy-stale-precedence", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-stale-precedence",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 120_000,
            "reference_price": 100_000,
            "feed_id": "btc/usd",
            "sources": [
                {
                    "source_id": " binance ",
                    "price": 120_000,
                    "observed_at_ms": 10_000
                },
                {
                    "source_id": "BINANCE",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                }
            ]
        }),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 80_001)
        .expect("stale precedence oracle validation response");

    assert!(!out.ok);
    assert_eq!(out.observation.outcome, "stale");
    assert_eq!(out.metrics.oracle_stale_reject_total, 1);
    assert_eq!(out.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(out.metrics.oracle_drift_reject_total, 0);
    assert_eq!(out.metrics.oracle_source_cardinality, 1);
    assert_eq!(out.metrics.accepted_total, 0);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(
        out.error.as_deref(),
        Some("snapshot stale: observed_at_ms=10000 max_staleness_ms=60000")
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_non_canonical_snapshot_feed_id_fail_closed() {
    let policy_path = write_json_fixture("oracle-policy-feed-canonical", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-feed-noncanonical",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 100_000,
            "feed_id": " BTC/USD ",
            "sources": [
                {
                    "source_id": "binance",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                },
                {
                    "source_id": "coinbase",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                }
            ]
        }),
    );

    let err = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect_err("non-canonical snapshot feed id should fail closed");

    assert!(
        err.contains("feed id must be canonical lowercase+trim"),
        "unexpected error: {err}"
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_snapshot_policy_feed_mismatch() {
    let policy_path = write_json_fixture(
        "oracle-policy-feed-mismatch",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 2,
            "max_deviation_bps": 500,
            "feed_id": "eth/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-feed-mismatch",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );

    let err = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect_err("snapshot/policy feed mismatch should fail closed");

    assert_eq!(err, "feed id mismatch: snapshot=btc/usd, policy=eth/usd");

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}
