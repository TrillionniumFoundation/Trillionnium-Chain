use super::*;

#[test]
fn adapter_error_classification_maps_mv2_fail_closed_receipt_contract_codes_tail() {
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
