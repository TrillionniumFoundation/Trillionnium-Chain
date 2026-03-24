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
