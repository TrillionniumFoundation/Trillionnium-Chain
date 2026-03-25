use super::*;

#[test]
fn observed_report_preserves_invalid_policy_error_without_counter_drift() {
    let p = OraclePolicy {
        min_sources: 2,
        max_staleness_ms: 5_000,
        max_deviation_bps: 10_001,
        max_update_rate_per_window: 60,
    };
    let snap = snapshot_with(100_000, Some(100_100), 10_000);

    let report = validate_snapshot_observed(&p, &snap, 10_100);
    assert!(!report.ok);
    assert_eq!(
        report.error.as_deref(),
        Some("invalid policy: max_deviation_bps must be <= 10000")
    );
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
fn observed_report_keeps_single_snapshot_source_cardinality_on_unclassified_error() {
    let p = OraclePolicy {
        min_sources: 2,
        max_staleness_ms: 5_000,
        max_deviation_bps: 10_001,
        max_update_rate_per_window: 60,
    };
    let snap = OracleSnapshot::new(
        "btc/usd",
        100_000,
        vec![source("coingecko"), source("binance"), source("chainlink")],
        3,
        Some(100_100),
        Some(120),
        1_000,
        2_000,
        10_000,
    )
    .expect("snapshot should be valid");

    let report = validate_snapshot_observed(&p, &snap, 10_100);
    assert!(!report.ok);
    assert_eq!(
        report.error.as_deref(),
        Some("invalid policy: max_deviation_bps must be <= 10000")
    );
    assert_eq!(report.metrics.oracle_source_cardinality, 3);
    assert_eq!(report.metrics.accepted_total, 0);
    assert_eq!(report.metrics.classified_reject_total(), 0);
    assert_eq!(report.metrics.sample_count, 1);
}

#[test]
fn observed_report_helpers_exclude_unclassified_errors_from_reject_total() {
    let report = validate_snapshot_observed(
        &policy(),
        &OracleSnapshot::new(
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
        .expect("snapshot build"),
        10_100,
    );

    assert_eq!(report.error.as_deref(), Some("rate"));
    assert_eq!(report.metrics.classified_reject_total(), 0);
    assert_eq!(report.metrics.classified_outcome_total(), 0);
    assert!(!report.classified_outcome_conserves_sample_count());
    assert_eq!(report.metrics.sample_count, 1);
}

#[test]
fn observation_helpers_keep_unclassified_errors_out_of_classified_totals() {
    let report = validate_snapshot_observed(
        &policy(),
        &OracleSnapshot::new(
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
        .expect("snapshot build"),
        10_100,
    );

    assert_eq!(report.error.as_deref(), Some("rate"));
    assert_eq!(report.observation.classified_reject_total(), 0);
    assert_eq!(report.observation.classified_outcome_total(), 0);
    assert!(!report
        .observation
        .classified_outcome_conserves_sample_count(report.metrics.sample_count));
    assert_eq!(
        report.observation.classified_reject_total(),
        report.metrics.classified_reject_total()
    );
    assert_eq!(
        report.observation.classified_outcome_total(),
        report.metrics.classified_outcome_total()
    );
}

#[test]
fn observed_report_preserves_future_snapshot_as_unclassified_error_without_stale_counter_drift() {
    let report = validate_snapshot_observed(
        &policy(),
        &snapshot_with(100_000, Some(100_100), 10_001),
        10_000,
    );

    assert!(!report.ok);
    assert_eq!(
        report.error.as_deref(),
        Some("future snapshot: ts=10001, now=10000")
    );
    assert_eq!(report.observation.stale_reject_total, 0);
    assert_eq!(report.observation.quorum_reject_total, 0);
    assert_eq!(report.observation.drift_reject_total, 0);
    assert_eq!(report.observation.accepted_total, 0);
    assert_eq!(report.metrics.oracle_stale_reject_total, 0);
    assert_eq!(report.metrics.oracle_quorum_reject_total, 0);
    assert_eq!(report.metrics.oracle_drift_reject_total, 0);
    assert_eq!(report.metrics.accepted_total, 0);
    assert_eq!(report.metrics.sample_count, 1);
    assert_eq!(report.metrics.classified_reject_total(), 0);
    assert_eq!(report.metrics.classified_outcome_total(), 0);
}
