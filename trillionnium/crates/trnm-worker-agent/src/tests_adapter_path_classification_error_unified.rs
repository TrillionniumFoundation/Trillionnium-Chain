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
