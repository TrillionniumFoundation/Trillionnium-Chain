use super::*;
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
