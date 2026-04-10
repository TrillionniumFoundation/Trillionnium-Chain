use super::*;

#[test]
fn oracle_validation_report_into_rpc_response_preserves_classified_sample_count_invariant() {
    let ok_report = OracleValidationReport {
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
    let stale_report = OracleValidationReport {
        ok: false,
        now_ts_ms: 124,
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

    let ok_out: OracleValidateSnapshotResponse = ok_report.into();
    let stale_out: OracleValidateSnapshotResponse = stale_report.into();

    assert_eq!(ok_out.classified_reject_total(), 0);
    assert_eq!(ok_out.observation_classified_reject_total(), 0);
    assert_eq!(ok_out.classified_outcome_total(), 1);
    assert_eq!(ok_out.observation_classified_outcome_total(), 1);
    assert!(ok_out.classified_outcome_conserves_sample_count());
    assert!(ok_out.observation_classified_outcome_conserves_sample_count());

    assert_eq!(stale_out.classified_reject_total(), 1);
    assert_eq!(stale_out.observation_classified_reject_total(), 1);
    assert_eq!(stale_out.classified_outcome_total(), 1);
    assert_eq!(stale_out.observation_classified_outcome_total(), 1);
    assert!(stale_out.classified_outcome_conserves_sample_count());
    assert!(stale_out.observation_classified_outcome_conserves_sample_count());
}

#[test]
fn oracle_validation_response_observation_helpers_keep_unclassified_errors_out_of_classified_totals(
) {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 792,
        observation: OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 0,
            drift_reject_total: 0,
            accepted_total: 0,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 0,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 3,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("rate".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();
    assert_eq!(out.classified_reject_total(), 0);
    assert_eq!(out.observation_classified_reject_total(), 0);
    assert_eq!(out.classified_outcome_total(), 0);
    assert_eq!(out.observation_classified_outcome_total(), 0);
    assert!(!out.classified_outcome_conserves_sample_count());
    assert!(!out.observation_classified_outcome_conserves_sample_count());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_allows_explicit_unclassified_failures() {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 793,
        observation: OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 0,
            drift_reject_total: 0,
            accepted_total: 0,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 0,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 3,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("rate".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(out.observation_matches_metrics());
    assert_eq!(out.classified_outcome_total(), 0);
    assert_eq!(out.observation_classified_outcome_total(), 0);
    assert!(!out.classified_outcome_conserves_sample_count());
    assert!(!out.observation_classified_outcome_conserves_sample_count());
    assert!(out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_for_duplicate_source_unclassified_failure() {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 793,
        observation: OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 0,
            drift_reject_total: 0,
            accepted_total: 0,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 0,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 2,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("duplicate source ids are not allowed".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(out.observation_matches_metrics());
    assert_eq!(out.classified_reject_total(), 0);
    assert_eq!(out.observation_classified_reject_total(), 0);
    assert_eq!(out.classified_outcome_total(), 0);
    assert_eq!(out.observation_classified_outcome_total(), 0);
    assert!(!out.classified_outcome_conserves_sample_count());
    assert!(!out.observation_classified_outcome_conserves_sample_count());
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert!(out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_rejects_blank_unclassified_error_label() {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 794,
        observation: OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 0,
            drift_reject_total: 0,
            accepted_total: 0,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 0,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 1,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some(" \n\t ".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(out.observation_matches_metrics());
    assert_eq!(out.classified_outcome_total(), 0);
    assert_eq!(out.observation_classified_outcome_total(), 0);
    assert!(!out.classified_outcome_conserves_sample_count());
    assert!(!out.observation_classified_outcome_conserves_sample_count());
    assert!(!out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_accepts_snapshot_hash_mismatch_detail_label() {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 795,
        observation: OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 1,
            drift_reject_total: 0,
            accepted_total: 0,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 1,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 2,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("snapshot hash mismatch: expected=abc, actual=def".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(out.observation_matches_metrics());
    assert_eq!(out.classified_reject_total(), 1);
    assert_eq!(out.observation_classified_reject_total(), 1);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert!(out.classified_outcome_conserves_sample_count());
    assert!(out.observation_classified_outcome_conserves_sample_count());
    assert!(out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_accepts_trimmed_classified_error_label() {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 795,
        observation: OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 1,
            drift_reject_total: 0,
            accepted_total: 0,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 1,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 2,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("\n\t snapshot hash mismatch: expected=abc, actual=def \t".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(out.observation_matches_metrics());
    assert_eq!(out.classified_reject_total(), 1);
    assert_eq!(out.observation_classified_reject_total(), 1);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert!(out.classified_outcome_conserves_sample_count());
    assert!(out.observation_classified_outcome_conserves_sample_count());
    assert!(out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_accepts_structural_whitespace_wrapped_classified_error_label(
) {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 795,
        observation: OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 1,
            drift_reject_total: 0,
            accepted_total: 0,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 1,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 2,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("\u{200B}\u{2060}\n snapshot hash mismatch: expected=abc, actual=def \t\u{FEFF}".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(out.observation_matches_metrics());
    assert_eq!(out.classified_reject_total(), 1);
    assert_eq!(out.observation_classified_reject_total(), 1);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    assert!(out.classified_outcome_conserves_sample_count());
    assert!(out.observation_classified_outcome_conserves_sample_count());
    assert!(out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_accepts_multi_source_single_snapshot_success() {
    let report = OracleValidationReport {
        ok: true,
        now_ts_ms: 789,
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

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(out.observation_matches_metrics());
    assert_eq!(out.classified_outcome_total(), 1);
    assert_eq!(out.observation_classified_outcome_total(), 1);
    assert!(out.classified_outcome_conserves_sample_count());
    assert!(out.observation_classified_outcome_conserves_sample_count());
    assert!(out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_accepts_unclassified_multi_source_single_snapshot_failure() {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 789,
        observation: OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 0,
            drift_reject_total: 0,
            accepted_total: 0,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 0,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 3,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("rate".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(out.observation_matches_metrics());
    assert_eq!(out.classified_outcome_total(), 0);
    assert_eq!(out.observation_classified_outcome_total(), 0);
    assert!(!out.classified_outcome_conserves_sample_count());
    assert!(!out.observation_classified_outcome_conserves_sample_count());
    assert!(out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_for_classified_outcomes() {
    let reports = [
        OracleValidationReport {
            ok: true,
            now_ts_ms: 790,
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
                oracle_source_cardinality: 1,
                accepted_total: 1,
                sample_count: 1,
            },
            error: None,
        },
        OracleValidationReport {
            ok: true,
            now_ts_ms: 790,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 3,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 3,
                sample_count: 3,
            },
            error: None,
        },
        OracleValidationReport {
            ok: false,
            now_ts_ms: 791,
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
        },
        OracleValidationReport {
            ok: false,
            now_ts_ms: 792,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 1,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 1,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 1,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("quorum".into()),
        },
        OracleValidationReport {
            ok: false,
            now_ts_ms: 793,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 1,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 1,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("drift".into()),
        },
    ];

    for report in reports {
        let out: OracleValidateSnapshotResponse = report.into();
        assert!(out.observation_matches_metrics());
        assert!(out.bridge_contract_consistent());
    }
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_rejects_counter_mismatch() {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 794,
        observation: OracleValidationObservation {
            stale_reject_total: 1,
            quorum_reject_total: 0,
            drift_reject_total: 0,
            accepted_total: 0,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 1,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 2,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("stale".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(!out.observation_matches_metrics());
    assert_eq!(out.classified_outcome_total(), 1);
    assert_eq!(out.observation_classified_outcome_total(), 1);
    assert!(out.classified_outcome_conserves_sample_count());
    assert!(out.observation_classified_outcome_conserves_sample_count());
    assert!(!out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_rejects_accepted_total_mismatch() {
    let report = OracleValidationReport {
        ok: true,
        now_ts_ms: 795,
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
            oracle_source_cardinality: 3,
            accepted_total: 0,
            sample_count: 0,
        },
        error: None,
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(!out.observation_matches_metrics());
    assert_eq!(out.classified_outcome_total(), 0);
    assert_eq!(out.observation_classified_outcome_total(), 1);
    assert!(out.classified_outcome_conserves_sample_count());
    assert!(!out.observation_classified_outcome_conserves_sample_count());
    assert!(!out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_accepts_repeated_observations_above_source_cardinality() {
    let report = OracleValidationReport {
        ok: true,
        now_ts_ms: 794,
        observation: OracleValidationObservation {
            stale_reject_total: 0,
            quorum_reject_total: 0,
            drift_reject_total: 0,
            accepted_total: 3,
        },
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: 0,
            oracle_quorum_reject_total: 0,
            oracle_drift_reject_total: 0,
            oracle_source_cardinality: 2,
            accepted_total: 3,
            sample_count: 3,
        },
        error: None,
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(out.observation_matches_metrics());
    assert_eq!(out.classified_reject_total(), 0);
    assert_eq!(out.observation_classified_reject_total(), 0);
    assert_eq!(out.classified_outcome_total(), 3);
    assert_eq!(out.observation_classified_outcome_total(), 3);
    assert!(out.classified_outcome_conserves_sample_count());
    assert!(out.observation_classified_outcome_conserves_sample_count());
    assert!(out.bridge_contract_consistent());
}

#[test]
fn oracle_validation_response_bridge_contract_consistent_rejects_non_empty_samples_without_sources() {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 796,
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
            oracle_source_cardinality: 0,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("stale".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();

    assert!(out.observation_matches_metrics());
    assert_eq!(out.classified_outcome_total(), 1);
    assert_eq!(out.observation_classified_outcome_total(), 1);
    assert!(out.classified_outcome_conserves_sample_count());
    assert!(out.observation_classified_outcome_conserves_sample_count());
    assert!(!out.bridge_contract_consistent());
}
