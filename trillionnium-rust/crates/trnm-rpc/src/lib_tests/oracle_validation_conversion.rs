use super::*;

#[test]
fn oracle_validation_report_into_rpc_response_preserves_contract_shape() {
    let report = OracleValidationReport {
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

    let out: OracleValidateSnapshotResponse = report.clone().into();
    assert_eq!(out.ok, report.ok);
    assert_eq!(out.now_ts_ms, report.now_ts_ms);
    assert_eq!(out.observation, report.observation);
    assert_eq!(out.metrics, report.metrics);
    assert_eq!(out.error, report.error);

    let v = serde_json::to_value(out).unwrap();
    assert_eq!(v["error"], "stale");
    assert_eq!(v["metrics"]["sample_count"], 1);
    assert_eq!(v["metrics"]["oracle_stale_reject_total"], 1);
}

#[test]
fn oracle_validation_report_into_rpc_response_omits_success_error_field() {
    let report = OracleValidationReport {
        ok: true,
        now_ts_ms: 457,
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

    let out: OracleValidateSnapshotResponse = report.clone().into();
    assert_eq!(out.ok, report.ok);
    assert_eq!(out.now_ts_ms, report.now_ts_ms);
    assert_eq!(out.observation, report.observation);
    assert_eq!(out.metrics, report.metrics);
    assert_eq!(out.error, None);

    let v = serde_json::to_value(out).unwrap();
    let obj = v.as_object().unwrap();
    assert!(!obj.contains_key("error"));
    assert_eq!(v["observation"]["accepted_total"], 1);
    assert_eq!(v["metrics"]["accepted_total"], 1);
}

#[test]
fn oracle_validation_report_into_rpc_response_preserves_quorum_and_drift_labels() {
    let quorum_report = OracleValidationReport {
        ok: false,
        now_ts_ms: 788,
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
    };
    let drift_report = OracleValidationReport {
        ok: false,
        now_ts_ms: 789,
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
    };

    let quorum_out: OracleValidateSnapshotResponse = quorum_report.into();
    let drift_out: OracleValidateSnapshotResponse = drift_report.into();

    assert_eq!(quorum_out.classified_reject_total(), 1);
    assert_eq!(quorum_out.classified_outcome_total(), 1);
    assert!(quorum_out.classified_outcome_conserves_sample_count());
    let quorum_json = serde_json::to_value(quorum_out).unwrap();
    assert_eq!(quorum_json["error"], "quorum");
    assert_eq!(quorum_json["metrics"]["oracle_quorum_reject_total"], 1);
    assert_eq!(quorum_json["metrics"]["oracle_source_cardinality"], 1);

    assert_eq!(drift_out.classified_reject_total(), 1);
    assert_eq!(drift_out.classified_outcome_total(), 1);
    assert!(drift_out.classified_outcome_conserves_sample_count());
    let drift_json = serde_json::to_value(drift_out).unwrap();
    assert_eq!(drift_json["error"], "drift");
    assert_eq!(drift_json["metrics"]["oracle_drift_reject_total"], 1);
    assert_eq!(drift_json["metrics"]["oracle_source_cardinality"], 2);
}

#[test]
fn oracle_validation_report_into_rpc_response_preserves_rate_error_label() {
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
            oracle_source_cardinality: 2,
            accepted_total: 0,
            sample_count: 1,
        },
        error: Some("rate".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();
    assert_eq!(out.classified_reject_total(), 0);
    assert_eq!(out.classified_outcome_total(), 0);
    assert!(!out.classified_outcome_conserves_sample_count());
    let v = serde_json::to_value(out).unwrap();
    assert_eq!(v["error"], "rate");
    assert_eq!(v["metrics"]["sample_count"], 1);
    assert_eq!(v["metrics"]["oracle_source_cardinality"], 2);
}

#[test]
fn oracle_validation_report_into_rpc_response_preserves_repeated_observation_cardinality_split() {
    let report = OracleValidationReport {
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
    };

    let out: OracleValidateSnapshotResponse = report.into();
    assert!(out.bridge_contract_consistent());
    assert_eq!(out.metrics.sample_count, 3);
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    let v = serde_json::to_value(out).unwrap();
    assert_eq!(v["metrics"]["accepted_total"], 3);
    assert_eq!(v["metrics"]["sample_count"], 3);
    assert_eq!(v["metrics"]["oracle_source_cardinality"], 2);
}

#[test]
fn oracle_validation_report_into_rpc_response_preserves_snapshot_hash_mismatch_label_and_quorum_accounting() {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 790,
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
    assert_eq!(out.classified_reject_total(), 1);
    assert_eq!(out.classified_outcome_total(), 1);
    assert!(out.classified_outcome_conserves_sample_count());
    let v = serde_json::to_value(out).unwrap();
    assert_eq!(
        v["error"],
        "snapshot hash mismatch: expected=abc, actual=def"
    );
    assert_eq!(v["metrics"]["sample_count"], 1);
    assert_eq!(v["metrics"]["oracle_quorum_reject_total"], 1);
    assert_eq!(v["metrics"]["oracle_source_cardinality"], 2);
}

#[test]
fn oracle_validation_report_into_rpc_response_keeps_single_snapshot_cardinality_on_unclassified_error(
) {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 791,
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
        error: Some("invalid policy: max_deviation_bps must be <= 10000".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();
    let v = serde_json::to_value(out).unwrap();
    assert_eq!(
        v["error"],
        "invalid policy: max_deviation_bps must be <= 10000"
    );
    assert_eq!(v["metrics"]["accepted_total"], 0);
    assert_eq!(v["metrics"]["oracle_source_cardinality"], 3);
    assert_eq!(v["metrics"]["sample_count"], 1);
}

#[test]
fn oracle_validation_response_preserves_canonical_source_cardinality_value() {
    let report = OracleValidationReport {
        ok: false,
        now_ts_ms: 791,
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
        error: Some("quorum".into()),
    };

    let out: OracleValidateSnapshotResponse = report.into();
    assert_eq!(out.metrics.oracle_source_cardinality, 2);
    let v = serde_json::to_value(out).unwrap();
    assert_eq!(v["metrics"]["oracle_source_cardinality"], 2);
}
