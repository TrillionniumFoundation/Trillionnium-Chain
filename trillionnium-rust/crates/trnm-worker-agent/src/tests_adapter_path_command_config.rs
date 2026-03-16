use super::*;
#[test]
fn config_defaults_apply_when_cli_and_env_missing() {
    let llm = LlmAdapterPolicy {
        retry: RetryPolicy {
            max_retries: resolve_u32(None, None, DEFAULT_LLM_ADAPTER_MAX_RETRIES, 0),
            backoff_ms: resolve_u64(None, None, DEFAULT_LLM_ADAPTER_BACKOFF_MS, 0),
        },
        timeout_ms: resolve_u64(None, None, DEFAULT_LLM_ADAPTER_TIMEOUT_MS, 1),
    };
    let tx = RetryPolicy {
        max_retries: resolve_u32(None, None, DEFAULT_TX_ADAPTER_MAX_RETRIES, 0),
        backoff_ms: resolve_u64(None, None, DEFAULT_TX_ADAPTER_BACKOFF_MS, 0),
    };

    assert_eq!(llm.retry.max_retries, DEFAULT_LLM_ADAPTER_MAX_RETRIES);
    assert_eq!(llm.retry.backoff_ms, DEFAULT_LLM_ADAPTER_BACKOFF_MS);
    assert_eq!(llm.timeout_ms, DEFAULT_LLM_ADAPTER_TIMEOUT_MS);
    assert_eq!(tx.max_retries, DEFAULT_TX_ADAPTER_MAX_RETRIES);
    assert_eq!(tx.backoff_ms, DEFAULT_TX_ADAPTER_BACKOFF_MS);
}

#[test]
fn config_invalid_values_fallback_to_default() {
    assert_eq!(
        resolve_u32(None, Some("bad"), DEFAULT_LLM_ADAPTER_MAX_RETRIES, 0),
        DEFAULT_LLM_ADAPTER_MAX_RETRIES
    );
    assert_eq!(
        resolve_u64(None, Some("bad"), DEFAULT_LLM_ADAPTER_BACKOFF_MS, 0),
        DEFAULT_LLM_ADAPTER_BACKOFF_MS
    );
    assert_eq!(
        resolve_u64(None, Some("0"), DEFAULT_LLM_ADAPTER_TIMEOUT_MS, 1),
        DEFAULT_LLM_ADAPTER_TIMEOUT_MS
    );
    assert_eq!(
        resolve_u64(Some(0), Some("8000"), DEFAULT_LLM_ADAPTER_TIMEOUT_MS, 1),
        8000
    );
}
