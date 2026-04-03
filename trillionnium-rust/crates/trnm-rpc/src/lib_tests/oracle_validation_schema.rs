use super::*;

#[test]
fn oracle_validate_snapshot_response_schema_smoke_stable() {
    let out = OracleValidateSnapshotResponse {
        ok: true,
        now_ts_ms: 123,
        observation: OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 0,
            drift_reject_total: 0,
            accepted_total: 1,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 0,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 2,
            accepted_total: 1,
            sample_count: 1,
        },
        error: None,
    };
    let v = serde_json::to_value(out).unwrap();
    let obj = v.as_object().unwrap();
    for k in ["ok", "now_ts_ms", "observation", "metrics"] {
        assert!(obj.contains_key(k), "missing key: {}", k);
    }
    assert!(!obj.contains_key("error"));
}

#[test]
fn oracle_validate_snapshot_response_nested_metric_keys_remain_stable() {
    let out = OracleValidateSnapshotResponse {
        ok: false,
        now_ts_ms: 456,
        observation: OracleValidationObservation {
            stale_reject_total: 1,
            quorum_reject_total: 0,
            drift_reject_total: 0,
            accepted_total: 0,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 1,
            oracle_quorum_reject_total: 0,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 2,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("stale".into()),
    };

    let v = serde_json::to_value(out).unwrap();
    let observation = v["observation"].as_object().unwrap();
    let metrics = v["metrics"].as_object().unwrap();

    let mut observation_keys = observation.keys().map(String::as_str).collect::<Vec<_>>();
    observation_keys.sort_unstable();
    let mut metrics_keys = metrics.keys().map(String::as_str).collect::<Vec<_>>();
    metrics_keys.sort_unstable();

    assert_eq!(
        observation_keys,
        vec![
            "accepted_total",
            "drift_reject_total",
            "quorum_reject_total",
            "stale_reject_total",
        ]
    );
    assert_eq!(
        metrics_keys,
        vec![
            "accepted_total",
            "oracle_drift_reject_total",
            "oracle_quorum_reject_total",
            "oracle_source_cardinality",
            "oracle_stale_reject_total",
            "sample_count",
        ]
    );
}

#[test]
fn oracle_validate_snapshot_response_deserializes_canonical_bridge_payload_without_error_field() {
    let payload = json!({
        "ok": true,
        "now_ts_ms": 1_710_000_000_123u64,
        "observation": {
            "stale_reject_total": 0,
            "quorum_reject_total": 0,
            "drift_reject_total": 0,
            "accepted_total": 1
        },
        "metrics": {
            "oracle_stale_reject_total": 0,
            "oracle_quorum_reject_total": 0,
            "oracle_drift_reject_total": 0,
            "oracle_source_cardinality": 3,
            "accepted_total": 1,
            "sample_count": 1
        }
    });

    let out: OracleValidateSnapshotResponse = serde_json::from_value(payload).unwrap();

    assert!(out.ok);
    assert_eq!(out.now_ts_ms, 1_710_000_000_123u64);
    assert_eq!(out.error, None);
    assert_eq!(out.observation.accepted_total, 1);
    assert_eq!(out.metrics.oracle_source_cardinality, 3);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(out.classified_reject_total(), 0);
    assert_eq!(out.observation_classified_reject_total(), 0);
    assert!(out.classified_outcome_conserves_sample_count());
    assert!(out.observation_classified_outcome_conserves_sample_count());
}

#[test]
fn oracle_validate_snapshot_response_deserializes_unclassified_error_payload_fail_closed() {
    let payload = json!({
        "ok": false,
        "now_ts_ms": 1_710_000_000_456u64,
        "observation": {
            "stale_reject_total": 0,
            "quorum_reject_total": 0,
            "drift_reject_total": 0,
            "accepted_total": 0
        },
        "metrics": {
            "oracle_stale_reject_total": 0,
            "oracle_quorum_reject_total": 0,
            "oracle_drift_reject_total": 0,
            "oracle_source_cardinality": 2,
            "accepted_total": 0,
            "sample_count": 1
        },
        "error": "rate"
    });

    let out: OracleValidateSnapshotResponse = serde_json::from_value(payload).unwrap();

    assert!(!out.ok);
    assert_eq!(out.now_ts_ms, 1_710_000_000_456u64);
    assert_eq!(out.error.as_deref(), Some("rate"));
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert_eq!(out.metrics.sample_count, 1);
    assert_eq!(out.classified_reject_total(), 0);
    assert_eq!(out.observation_classified_reject_total(), 0);
    assert_eq!(out.classified_outcome_total(), 0);
    assert_eq!(out.observation_classified_outcome_total(), 0);
    assert!(!out.classified_outcome_conserves_sample_count());
    assert!(!out.observation_classified_outcome_conserves_sample_count());
    assert!(out.observation_matches_metrics());
    assert!(out.bridge_contract_consistent());
}
