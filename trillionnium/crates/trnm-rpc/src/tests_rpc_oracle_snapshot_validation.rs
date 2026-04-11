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
    assert_eq!(out.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(out.metrics.oracle_stale_reject_total, 0);
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
fn oracle_validate_snapshot_response_rejects_zero_reference_baseline_as_drift_fail_closed() {
    let policy_path = write_json_fixture(
        "oracle-policy-zero-reference-baseline",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 2,
            "max_deviation_bps": 500,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-zero-reference-baseline",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 0,
            "feed_id": "btc/usd",
            "sources": [
                {
                    "source_id": "binance",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                },
                {
                    "source_id": "coinbase",
                    "price": 0,
                    "observed_at_ms": 10_000
                }
            ]
        }),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("zero-reference baseline should return a structured rejection");

    assert!(!out.ok);
    assert_eq!(out.now_ts_ms, 10_100);
    assert_eq!(out.observation.outcome, "drift");
    assert_eq!(out.metrics.oracle_stale_reject_total, 0);
    assert_eq!(out.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(out.metrics.oracle_drift_reject_total, 1);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert_eq!(out.metrics.accepted_total, 0);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(out.error.as_deref(), Some("deviation exceeded"));

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_accepts_zero_reference_baseline_at_guardrail_cap() {
    let policy_path = write_json_fixture(
        "oracle-policy-zero-reference-baseline-cap",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 2,
            "max_deviation_bps": 10_000,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-zero-reference-baseline-cap",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 0,
            "feed_id": "btc/usd",
            "sources": [
                {
                    "source_id": "binance",
                    "price": 100_000,
                    "observed_at_ms": 10_000
                },
                {
                    "source_id": "coinbase",
                    "price": 0,
                    "observed_at_ms": 10_000
                }
            ]
        }),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("guardrail-cap zero-reference baseline should remain admissible at the exact boundary");

    assert!(out.ok);
    assert_eq!(out.now_ts_ms, 10_100);
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
fn oracle_validate_snapshot_response_excludes_missing_or_non_string_source_ids_from_canonical_cardinality() {
    let policy_path = write_json_fixture("oracle-policy-malformed-source-cardinality", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-malformed-source-cardinality",
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
                    "source_id": 7,
                    "price": 100_000,
                    "observed_at_ms": 10_000
                },
                {
                    "price": 100_000,
                    "observed_at_ms": 10_000
                }
            ]
        }),
    );

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("malformed-source-cardinality oracle validation response");

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
fn oracle_validate_snapshot_response_rejects_snapshot_without_sources_fail_closed() {
    let policy_path = write_json_fixture("oracle-policy-no-sources", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-no-sources",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 100_000,
            "feed_id": "btc/usd",
            "sources": []
        }),
    );

    let err = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect_err("source-less snapshot must fail closed before structured counters");

    assert_eq!(err, "snapshot has no sources");

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
fn oracle_validate_snapshot_response_rejects_snapshot_feed_id_with_internal_whitespace() {
    let policy_path =
        write_json_fixture("oracle-policy-feed-internal-whitespace", &oracle_policy_fixture());
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-feed-internal-whitespace",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 100_000,
            "feed_id": "btc /usd",
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
        .expect_err("snapshot feed id with internal whitespace should fail closed");

    assert_eq!(
        err,
        "feed id must be canonical lowercase+trim: raw=btc /usd, canonical=btc /usd"
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_policy_feed_id_with_control_chars() {
    let policy_path = write_json_fixture(
        "oracle-policy-feed-control-char",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 2,
            "max_deviation_bps": 500,
            "feed_id": "btc\n/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-feed-control-char",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );

    let err = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect_err("policy feed id with control chars should fail closed");

    assert_eq!(
        err,
        "feed id must be canonical lowercase+trim: raw=btc\n/usd, canonical=btc\n/usd"
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

#[test]
fn oracle_validate_snapshot_response_rejects_zero_min_source_policy() {
    let policy_path = write_json_fixture(
        "oracle-policy-zero-min-sources",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 0,
            "max_deviation_bps": 500,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-zero-min-sources",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );

    let err = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect_err("zero min_source_count policy should fail closed");

    assert_eq!(err, "invalid policy: min_source_count must be > 0");

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_zero_staleness_policy() {
    let policy_path = write_json_fixture(
        "oracle-policy-zero-staleness",
        &serde_json::json!({
            "max_staleness_ms": 0,
            "min_source_count": 2,
            "max_deviation_bps": 500,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-zero-staleness",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );

    let err = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect_err("zero max_staleness_ms policy should fail closed");

    assert_eq!(err, "invalid policy: max_staleness_ms must be > 0");

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_policy_when_min_sources_exceed_rate_cap() {
    let policy_path = write_json_fixture(
        "oracle-policy-min-sources-exceed-rate-cap",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 3,
            "max_deviation_bps": 500,
            "max_update_rate_per_window": 2,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-min-sources-exceed-rate-cap",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );

    let err = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect_err("min_source_count greater than rate cap should fail closed");

    assert_eq!(
        err,
        "invalid policy: min_source_count must be <= max_update_rate_per_window"
    );

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_zero_update_rate_policy() {
    let policy_path = write_json_fixture(
        "oracle-policy-zero-update-rate",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 2,
            "max_deviation_bps": 500,
            "max_update_rate_per_window": 0,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-zero-update-rate",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );

    let err = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect_err("zero max_update_rate_per_window policy should fail closed");

    assert_eq!(err, "invalid policy: max_update_rate_per_window must be > 0");

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_deviation_cap_above_guardrail() {
    let policy_path = write_json_fixture(
        "oracle-policy-deviation-cap-overflow",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 2,
            "max_deviation_bps": 10_001,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-deviation-cap-overflow",
        &oracle_snapshot_fixture(100_000, Some(100_000), 10_000),
    );

    let err = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect_err("max_deviation_bps above guardrail should fail closed");

    assert_eq!(err, "invalid policy: max_deviation_bps must be <= 10000");

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_rejects_zero_sample_count_fail_closed() {
    let policy_path = write_json_fixture(
        "oracle-policy-zero-sample-count",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 2,
            "max_deviation_bps": 500,
            "max_update_rate_per_window": 2,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-zero-sample-count",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 100_000,
            "sample_count": 0,
            "feed_id": "btc/usd",
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
        .expect_err("zero sample count should fail closed before oracle ingest admission");

    assert_eq!(err, "invalid snapshot: sample_count must be > 0");

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_accepts_sample_count_at_exact_policy_cap() {
    let policy_path = write_json_fixture(
        "oracle-policy-rate-cap-boundary",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 2,
            "max_deviation_bps": 500,
            "max_update_rate_per_window": 2,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-rate-cap-boundary",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 100_000,
            "sample_count": 2,
            "feed_id": "btc/usd",
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

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("rate-cap boundary oracle validation response");

    assert!(out.ok);
    assert_eq!(out.now_ts_ms, 10_100);
    assert_eq!(out.observation.outcome, "accepted");
    assert_eq!(out.metrics.oracle_stale_reject_total, 0);
    assert_eq!(out.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(out.metrics.oracle_drift_reject_total, 0);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert_eq!(out.metrics.accepted_total, 1);
    assert_eq!(out.metrics.sample_count, 2);
    assert_eq!(out.error, None);

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}

#[test]
fn oracle_validate_snapshot_response_returns_structured_rate_rejection_when_sample_count_exceeds_policy_cap() {
    let policy_path = write_json_fixture(
        "oracle-policy-rate-cap",
        &serde_json::json!({
            "max_staleness_ms": 60_000,
            "min_source_count": 2,
            "max_deviation_bps": 500,
            "max_update_rate_per_window": 2,
            "feed_id": "btc/usd",
        }),
    );
    let snapshot_path = write_json_fixture(
        "oracle-snapshot-rate-cap",
        &serde_json::json!({
            "observed_at_ms": 10_000,
            "aggregate_price": 100_000,
            "reference_price": 100_000,
            "sample_count": 3,
            "feed_id": "btc/usd",
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

    let out = oracle_validate_snapshot_response(&snapshot_path, &policy_path, 10_100)
        .expect("rate-limited oracle validation response");

    assert!(!out.ok);
    assert_eq!(out.now_ts_ms, 10_100);
    assert_eq!(out.observation.outcome, "accepted");
    assert_eq!(out.metrics.oracle_stale_reject_total, 0);
    assert_eq!(out.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(out.metrics.oracle_drift_reject_total, 0);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert_eq!(out.metrics.accepted_total, 0);
    assert_eq!(out.metrics.sample_count, 3);
    assert_eq!(out.error.as_deref(), Some("rate"));

    let _ = fs::remove_file(snapshot_path);
    let _ = fs::remove_file(policy_path);
}
