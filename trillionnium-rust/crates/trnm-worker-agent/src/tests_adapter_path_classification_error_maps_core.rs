use super::*;

#[test]
fn adapter_error_classification_maps_mv2_fail_closed_receipt_contract_codes_core() {
    let proof_missing = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "tee-receipt-missing-provider-request-id".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let proof_late = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "llm adapter timeout after 3000ms".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_late),
        ("ERR_M2V2_PROOF_LATE", "proof_late")
    );

    let proof_invalid = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "zk-receipt-missing-adapter-label".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_invalid),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid")
    );

    let no_json_line = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "no-json-line".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&no_json_line),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid")
    );

    let settlement_degraded_non_retriable = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "tee-receipt-settlement-degraded".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_non_retriable),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let settlement_degraded_retriable = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlement-degraded-retry-window-exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_retriable),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let settlement_degraded_timeout_overlap = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlement-degraded-timeout-window".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_timeout_overlap),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let proof_missing_underscore = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "tee_receipt_missing_provider_request_id".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_underscore),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let proof_late_underscore = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof_late_retry_window_exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_late_underscore),
        ("ERR_M2V2_PROOF_LATE", "proof_late")
    );

    let proof_late_with_spaces = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof late retry window exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_late_with_spaces),
        ("ERR_M2V2_PROOF_LATE", "proof_late")
    );

    let proof_late_with_nonbreaking_hyphen = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof‑late retry window exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_late_with_nonbreaking_hyphen),
        ("ERR_M2V2_PROOF_LATE", "proof_late")
    );

    let proof_missing_with_nonbreaking_hyphen = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "proof‑missing provider request id".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_with_nonbreaking_hyphen),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let settlement_degraded_with_em_dash = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlement—degraded timeout overlap".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_with_em_dash),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );
}
