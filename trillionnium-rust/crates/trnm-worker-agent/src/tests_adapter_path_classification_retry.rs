use super::*;

#[test]
fn tx_retry_policy_mixes_partial_cli_overrides_with_env_fallbacks() {
    let policy = resolve_tx_retry_policy_from_sources(Some(1), None, Some(" 4\n"), Some("\t250 "));
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 1,
            backoff_ms: 250,
        }
    );

    let policy = resolve_tx_retry_policy_from_sources(None, Some(0), Some(" 4\n"), Some("\t250 "));
    assert_eq!(
        policy,
        RetryPolicy {
            max_retries: 4,
            backoff_ms: 0,
        }
    );
}

#[test]
fn exp_backoff_delay_saturates_without_overflow() {
    assert_eq!(exp_backoff_delay_ms(25, 0), 25);
    assert_eq!(exp_backoff_delay_ms(25, 1), 50);
    assert_eq!(exp_backoff_delay_ms(25, 2), 100);

    // Very large attempts should saturate rather than overflow/panic.
    assert_eq!(exp_backoff_delay_ms(u64::MAX, 1), u64::MAX);
    assert_eq!(exp_backoff_delay_ms(1_000_000, 62), u64::MAX);
}

#[test]
fn llm_adapter_retry_succeeds_within_budget() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let res = run_llm_adapter_with_retry_inner(
        2,
        50,
        || {
            attempt += 1;
            if attempt < 3 {
                Err(AdapterError {
                    kind: AdapterErrorKind::Retriable,
                    context: format!("transient-{}", attempt),
                })
            } else {
                Ok(LlmAdapterResponse {
                    output_text: "ok".to_string(),
                    provider_request_id: None,
                    provider: None,
                    model: None,
                    adapter: None,
                    agent_protocol: None,
                    compliance_profile: None,
                })
            }
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .unwrap();

    assert_eq!(res.output_text, "ok");
    assert_eq!(attempt, 3);
    assert_eq!(slept, vec![50, 100]);
}

#[test]
fn llm_adapter_retry_budget_exhausted_returns_last_error() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let err = run_llm_adapter_with_retry_inner(
        2,
        20,
        || {
            attempt += 1;
            Err(AdapterError {
                kind: AdapterErrorKind::Retriable,
                context: format!("timeout-{}", attempt),
            })
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .unwrap_err();

    assert_eq!(attempt, 3);
    assert_eq!(slept, vec![20, 40]);
    assert_eq!(err.kind, AdapterErrorKind::Retriable);
    assert_eq!(err.context, "timeout-3");
}

#[test]
fn llm_adapter_non_retriable_fails_fast() {
    let mut attempt = 0u32;
    let mut slept = vec![];
    let err = run_llm_adapter_with_retry_inner(
        5,
        20,
        || {
            attempt += 1;
            Err(AdapterError {
                kind: AdapterErrorKind::NonRetriable,
                context: "invalid-json".to_string(),
            })
        },
        |d| slept.push(d.as_millis() as u64),
    )
    .unwrap_err();

    assert_eq!(attempt, 1);
    assert!(slept.is_empty());
    assert_eq!(err.kind, AdapterErrorKind::NonRetriable);
    assert_eq!(err.context, "invalid-json");
}
