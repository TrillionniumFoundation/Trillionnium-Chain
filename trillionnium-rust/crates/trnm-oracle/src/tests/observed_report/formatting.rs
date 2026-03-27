use super::*;

#[test]
fn observation_helpers_match_metrics_helpers_for_classified_outcomes() {
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
            .expect("quorum snapshot build"),
            10_100,
        ),
        validate_snapshot_observed(
            &policy(),
            &snapshot_with(120_000, Some(100_000), 10_000),
            10_100,
        ),
    ];

    for report in reports {
        assert_eq!(
            report.observation_classified_reject_total(),
            report.classified_reject_total(),
            "classified reject totals drifted for error {:?}",
            report.error
        );
        assert_eq!(
            report.observation_classified_outcome_total(),
            report.classified_outcome_total(),
            "classified outcome totals drifted for error {:?}",
            report.error
        );
        assert_eq!(
            report.observation.classified_reject_total(),
            report.observation_classified_reject_total(),
            "observation helper drifted for error {:?}",
            report.error
        );
        assert_eq!(
            report.metrics.classified_reject_total(),
            report.classified_reject_total(),
            "metrics helper drifted for error {:?}",
            report.error
        );
        assert_eq!(
            report.observation.classified_outcome_total(),
            report.observation_classified_outcome_total(),
            "observation outcome helper drifted for error {:?}",
            report.error
        );
        assert_eq!(
            report.metrics.classified_outcome_total(),
            report.classified_outcome_total(),
            "metrics outcome helper drifted for error {:?}",
            report.error
        );
        assert_eq!(
            report
                .observation
                .classified_outcome_conserves_sample_count(report.metrics.sample_count),
            report.classified_outcome_conserves_sample_count(),
            "classified sample-count conservation drifted for error {:?}",
            report.error
        );
        assert!(
            report.observation_matches_metrics(),
            "observation/metrics bridge mapping drifted for error {:?}",
            report.error
        );
        assert!(
            report.bridge_contract_consistent(),
            "bridge contract drifted for error {:?}",
            report.error
        );
    }
}

#[test]
fn bridge_contract_consistent_rejects_metrics_sample_count_mismatch() {
    let mut report = validate_snapshot_observed(
        &policy(),
        &snapshot_with(100_000, Some(100_100), 10_000),
        10_100,
    );

    assert!(report.bridge_contract_consistent());
    report.metrics.sample_count = 0;

    assert!(!report.classified_outcome_conserves_sample_count());
    assert!(report.observation_matches_metrics());
    assert!(!report.observation_classified_outcome_conserves_sample_count());
    assert!(!report.bridge_contract_consistent());
}

#[test]
fn bridge_contract_consistent_rejects_empty_bridge_sample_even_when_counters_align() {
    let mut report = validate_snapshot_observed(
        &policy(),
        &snapshot_with(100_000, Some(100_100), 10_000),
        10_100,
    );

    assert!(report.bridge_contract_consistent());
    report.ok = false;
    report.error = Some("stale".to_string());
    report.observation.accepted_total = 0;
    report.observation.stale_reject_total = 0;
    report.metrics.accepted_total = 0;
    report.metrics.oracle_stale_reject_total = 0;
    report.metrics.sample_count = 0;

    assert!(report.observation_matches_metrics());
    assert!(report.classified_outcome_conserves_sample_count());
    assert!(report.observation_classified_outcome_conserves_sample_count());
    assert!(!report.bridge_contract_consistent());
}

#[test]
fn bridge_contract_consistent_rejects_ok_error_coherence_drift() {
    let mut success = validate_snapshot_observed(
        &policy(),
        &snapshot_with(100_000, Some(100_100), 10_000),
        10_100,
    );
    assert!(success.bridge_contract_consistent());
    success.error = Some("stale".to_string());
    assert!(!success.bridge_contract_consistent());

    let mut failure = validate_snapshot_observed(
        &policy(),
        &snapshot_with(100_000, Some(100_100), 10_000),
        16_000,
    );
    assert!(failure.bridge_contract_consistent());
    failure.error = None;
    assert!(!failure.bridge_contract_consistent());
}
