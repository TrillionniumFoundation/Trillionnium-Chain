use super::*;

#[test]
fn observed_report_preserves_zero_deviation_boundary_as_drift_label() {
    let p = OraclePolicy {
        min_sources: 2,
        max_staleness_ms: 5_000,
        max_deviation_bps: 0,
        max_update_rate_per_window: 60,
    };
    let snap = snapshot_with(100_100, Some(100_000), 10_000);

    let report = validate_snapshot_observed(&p, &snap, 10_100);
    assert!(!report.ok);
    assert_eq!(report.error.as_deref(), Some("drift"));
    assert_eq!(report.observation.drift_reject_total, 1);
    assert_eq!(report.metrics.oracle_drift_reject_total, 1);
    assert_eq!(report.metrics.accepted_total, 0);
    assert_eq!(report.metrics.sample_count, 1);
    assert!(report.classified_outcome_conserves_sample_count());
}

#[test]
fn observed_report_maps_success_to_stable_metrics_contract() {
    let p = policy();
    let snap = snapshot_with(100_000, Some(100_100), 10_000);

    let report = validate_snapshot_observed(&p, &snap, 10_100);
    assert!(report.ok);
    assert_eq!(report.error, None);
    assert_eq!(report.observation.accepted_total, 1);
    assert_eq!(report.metrics.oracle_stale_reject_total, 0);
    assert_eq!(report.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(report.metrics.oracle_drift_reject_total, 0);
    assert_eq!(report.metrics.oracle_source_cardinality, 2);
    assert_eq!(report.metrics.accepted_total, 1);
    assert_eq!(report.metrics.sample_count, 1);
}

#[test]
fn observed_report_maps_stale_rejection_to_stable_error_label() {
    let p = policy();
    let snap = snapshot_with(100_000, Some(100_100), 10_000);

    let report = validate_snapshot_observed(&p, &snap, 16_000);
    assert!(!report.ok);
    assert_eq!(report.error.as_deref(), Some("stale"));
    assert_eq!(report.observation.stale_reject_total, 1);
    assert_eq!(report.metrics.oracle_stale_reject_total, 1);
    assert_eq!(report.metrics.accepted_total, 0);
    assert_eq!(report.metrics.sample_count, 1);
}

#[test]
fn observed_report_maps_quorum_rejection_to_stable_error_label() {
    let p = policy();
    let snap = OracleSnapshot::new(
        "btc/usd",
        100_000,
        vec![source("coingecko")],
        1,
        Some(100_000),
        Some(120),
        1_000,
        2_000,
        10_000,
    )
    .expect("snapshot build");

    let report = validate_snapshot_observed(&p, &snap, 10_100);
    assert!(!report.ok);
    assert_eq!(report.error.as_deref(), Some("quorum"));
    assert_eq!(report.observation.quorum_reject_total, 1);
    assert_eq!(report.metrics.oracle_quorum_reject_total, 1);
    assert_eq!(report.metrics.oracle_source_cardinality, 1);
    assert_eq!(report.metrics.accepted_total, 0);
    assert_eq!(report.metrics.sample_count, 1);
}

#[test]
fn observed_report_maps_inconsistent_sample_count_to_stable_quorum_label() {
    let p = policy();
    let snap: OracleSnapshot = serde_json::from_value(serde_json::json!({
        "feed_id": "btc/usd",
        "value": 100000,
        "sources": ["coingecko", "chainlink"],
        "sample_count": 1,
        "median": 100000,
        "mad": 120,
        "window_start_ms": 1000,
        "window_end_ms": 2000,
        "snapshot_ts_ms": 10000,
        "snapshot_hash": "broken"
    }))
    .expect("snapshot deserialize");

    let report = validate_snapshot_observed(&p, &snap, 10_100);
    assert!(!report.ok);
    assert_eq!(report.error.as_deref(), Some("quorum"));
    assert_eq!(report.observation.quorum_reject_total, 1);
    assert_eq!(report.metrics.oracle_quorum_reject_total, 1);
    assert_eq!(report.metrics.oracle_source_cardinality, 2);
    assert_eq!(report.metrics.accepted_total, 0);
    assert_eq!(report.metrics.sample_count, 1);
}

#[test]
fn observed_report_maps_drift_rejection_to_stable_error_label() {
    let p = policy();
    let snap = snapshot_with(120_000, Some(100_000), 10_000);

    let report = validate_snapshot_observed(&p, &snap, 10_100);
    assert!(!report.ok);
    assert_eq!(report.error.as_deref(), Some("drift"));
    assert_eq!(report.observation.drift_reject_total, 1);
    assert_eq!(report.metrics.oracle_drift_reject_total, 1);
    assert_eq!(report.metrics.oracle_source_cardinality, 2);
    assert_eq!(report.metrics.accepted_total, 0);
    assert_eq!(report.metrics.sample_count, 1);
}

#[test]
fn observed_report_maps_update_rate_rejection_to_stable_error_label() {
    let p = policy();
    let snap = OracleSnapshot::new(
        "btc/usd",
        100_000,
        vec![source("coingecko"), source("chainlink")],
        61,
        Some(100_000),
        Some(120),
        1_000,
        2_000,
        10_000,
    )
    .expect("snapshot build");

    let report = validate_snapshot_observed(&p, &snap, 10_100);
    assert!(!report.ok);
    assert_eq!(report.error.as_deref(), Some("rate"));
    assert_eq!(report.observation.stale_reject_total, 0);
    assert_eq!(report.observation.quorum_reject_total, 0);
    assert_eq!(report.observation.drift_reject_total, 0);
    assert_eq!(report.observation.accepted_total, 0);
    assert_eq!(report.metrics.oracle_stale_reject_total, 0);
    assert_eq!(report.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(report.metrics.oracle_drift_reject_total, 0);
    assert_eq!(report.metrics.oracle_source_cardinality, 2);
    assert_eq!(report.metrics.accepted_total, 0);
    assert_eq!(report.metrics.sample_count, 1);
}

#[test]
fn observed_report_preserves_unmapped_bridge_error_string_without_counter_drift() {
    let p = policy();
    let mut snap = snapshot_with(100_000, Some(100_100), 10_000);
    snap.snapshot_hash.push('x');

    let report = validate_snapshot_observed(&p, &snap, 10_100);
    assert!(!report.ok);
    assert!(matches!(
        report.error.as_deref(),
        Some(err) if err.starts_with("snapshot hash mismatch:")
    ));
    assert_eq!(report.observation.stale_reject_total, 0);
    assert_eq!(report.observation.quorum_reject_total, 0);
    assert_eq!(report.observation.drift_reject_total, 0);
    assert_eq!(report.observation.accepted_total, 0);
    assert_eq!(report.metrics.oracle_stale_reject_total, 0);
    assert_eq!(report.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(report.metrics.oracle_drift_reject_total, 0);
    assert_eq!(report.metrics.oracle_source_cardinality, 2);
    assert_eq!(report.metrics.accepted_total, 0);
    assert_eq!(report.metrics.sample_count, 1);
}

#[test]
fn observed_report_preserves_single_snapshot_counter_conservation_for_classified_outcomes() {
    let reports = vec![
        validate_snapshot_observed(
            &policy(),
            &snapshot_with(100_000, Some(100_100), 10_000),
            10_100,
        ),
        validate_snapshot_observed(
            &policy(),
            &snapshot_with(100_000, Some(100_100), 10_000),
            16_000,
        ),
        validate_snapshot_observed(
            &policy(),
            &snapshot_with(120_000, Some(100_000), 10_000),
            10_100,
        ),
        validate_snapshot_observed(
            &policy(),
            &OracleSnapshot::new(
                "btc/usd",
                100_000,
                vec![source("coingecko")],
                1,
                Some(100_000),
                Some(120),
                1_000,
                2_000,
                10_000,
            )
            .expect("snapshot build"),
            10_100,
        ),
    ];

    for report in reports {
        assert_eq!(report.metrics.sample_count, 1);
        assert!(report.classified_outcome_conserves_sample_count());
        assert_eq!(
            report.metrics.classified_outcome_total(),
            report.metrics.sample_count
        );
        assert_eq!(
            report.observation.accepted_total, report.metrics.accepted_total,
            "observation/metrics accepted_total drifted for error {:?}",
            report.error
        );
    }
}

#[test]
fn observed_report_uses_canonical_source_cardinality_for_deserialized_duplicates() {
    let snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
        "feed_id": "btc/usd",
        "value": 100000,
        "sources": ["coingecko", "chainlink", "coingecko"],
        "sample_count": 3,
        "median": 100000,
        "mad": 120,
        "window_start_ms": 1000,
        "window_end_ms": 2000,
        "snapshot_ts_ms": 10000,
        "snapshot_hash": "broken"
    }))
    .expect("snapshot deserialize");

    let report = validate_snapshot_observed(&policy(), &snapshot, 10_100);

    assert!(!report.ok);
    assert!(matches!(
        report.error.as_deref(),
        Some(error) if error.starts_with("snapshot hash mismatch:")
    ));
    assert_eq!(report.metrics.oracle_source_cardinality, 2);
}

#[test]
fn observed_report_uses_canonical_source_cardinality_for_deserialized_source_aliases() {
    let snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
        "feed_id": "btc/usd",
        "value": 100000,
        "sources": ["coingecko", "ChainLink ", " chainlink"],
        "sample_count": 3,
        "median": 100000,
        "mad": 120,
        "window_start_ms": 1000,
        "window_end_ms": 2000,
        "snapshot_ts_ms": 10000,
        "snapshot_hash": "broken"
    }))
    .expect("snapshot deserialize");

    let report = validate_snapshot_observed(&policy(), &snapshot, 10_100);

    assert!(!report.ok);
    assert_eq!(
        report.error.as_deref(),
        Some("source id must be canonical: expected chainlink, got ChainLink ")
    );
    assert_eq!(report.metrics.oracle_source_cardinality, 2);
}
