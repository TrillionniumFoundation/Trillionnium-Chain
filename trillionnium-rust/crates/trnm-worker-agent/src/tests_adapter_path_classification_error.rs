use super::*;
#[test]
fn adapter_error_classification_is_unified_failed_adapter() {
    let retry_exhausted = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "llm adapter transient io failure".to_string(),
    };
    let non_retriable = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "llm adapter invalid json".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&retry_exhausted),
        ("adapter_error", "retry_exhausted")
    );
    assert_eq!(
        classify_adapter_error(&non_retriable),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid")
    );
}

#[test]
fn adapter_error_classification_maps_mv2_fail_closed_receipt_contract_codes() {
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

    let explicit_contract_proof_missing = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof-missing-from-verifier".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&explicit_contract_proof_missing),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let explicit_contract_proof_invalid = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof_invalid_signature".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&explicit_contract_proof_invalid),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid")
    );

    let proof_invalid_with_spaces = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof invalid signature".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_invalid_with_spaces),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid")
    );

    let settlement_degraded_underscore = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlement_degraded_retry_window_exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_underscore),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let proof_missing_uppercase = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "TEE-RECEIPT-MISSING-PROVIDER-REQUEST-ID".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_uppercase),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let proof_missing_with_spaces = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "tee receipt missing provider request id".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_with_spaces),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let proof_missing_with_punctuation = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "tee/receipt:missing.provider request-id".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_with_punctuation),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let proof_missing_compact = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "teeReceiptMissingProviderRequestId".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&proof_missing_compact),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing")
    );

    let settlement_degraded_mixed_case = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "Settlement_Degraded_retry_window_exhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_mixed_case),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );

    let settlement_degraded_camel_case = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlementDegradedRetryWindowExhausted".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&settlement_degraded_camel_case),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded")
    );
}

#[test]
fn adapter_error_classification_enforces_contract_precedence_for_ambiguous_contexts() {
    let missing_vs_invalid = AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: "proof-missing and proof-invalid in same envelope".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&missing_vs_invalid),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing"),
        "proof_missing must outrank proof_invalid for deterministic disputed reason"
    );

    let invalid_vs_late = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "proof-invalid timeout overlap".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&invalid_vs_late),
        ("ERR_M2V2_PROOF_INVALID", "proof_invalid"),
        "proof_invalid must outrank proof_late to avoid timeout masking malformed proofs"
    );

    let missing_vs_late = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "missing-provider-request-id timeout overlap".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&missing_vs_late),
        ("ERR_M2V2_PROOF_MISSING", "proof_missing"),
        "proof_missing must outrank proof_late when timeout co-occurs with missing receipt ids"
    );

    let degraded_vs_late = AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "settlement-degraded timeout overlap".to_string(),
    };
    assert_eq!(
        classify_adapter_error(&degraded_vs_late),
        ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded"),
        "settlement_degraded must outrank proof_late for stable downgrade signaling"
    );
}
