use crate::{
    LlmAdapterPolicy, RetryPolicy, DEFAULT_LLM_ADAPTER_BACKOFF_MS, DEFAULT_LLM_ADAPTER_MAX_RETRIES,
    DEFAULT_LLM_ADAPTER_TIMEOUT_MS, DEFAULT_TX_ADAPTER_BACKOFF_MS, DEFAULT_TX_ADAPTER_MAX_RETRIES,
    LLM_ADAPTER_BACKOFF_MS_ENV, LLM_ADAPTER_MAX_RETRIES_ENV, LLM_ADAPTER_TIMEOUT_ENV,
    TX_ADAPTER_BACKOFF_MS_ENV, TX_ADAPTER_MAX_RETRIES_ENV,
};
use std::{env, time::Duration};

pub(crate) fn backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    base_ms.saturating_mul(attempt as u64 + 1)
}

pub(crate) fn exp_backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    base_ms.saturating_mul(1u64.checked_shl(attempt.min(62)).unwrap_or(u64::MAX))
}

fn parse_u32_with_min(raw: Option<&str>, default: u32, min: u32) -> u32 {
    raw.and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|v| *v >= min)
        .unwrap_or(default)
}

fn parse_u64_with_min(raw: Option<&str>, default: u64, min: u64) -> u64 {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|v| *v >= min)
        .unwrap_or(default)
}

pub(crate) fn resolve_u32(cli: Option<u32>, env_raw: Option<&str>, default: u32, min: u32) -> u32 {
    cli.filter(|v| *v >= min)
        .unwrap_or_else(|| parse_u32_with_min(env_raw, default, min))
}

pub(crate) fn resolve_u64(cli: Option<u64>, env_raw: Option<&str>, default: u64, min: u64) -> u64 {
    cli.filter(|v| *v >= min)
        .unwrap_or_else(|| parse_u64_with_min(env_raw, default, min))
}

pub(crate) fn resolve_tx_retry_policy(
    max_retries_cli: Option<u32>,
    backoff_ms_cli: Option<u64>,
) -> RetryPolicy {
    RetryPolicy {
        max_retries: resolve_u32(
            max_retries_cli,
            env::var(TX_ADAPTER_MAX_RETRIES_ENV).ok().as_deref(),
            DEFAULT_TX_ADAPTER_MAX_RETRIES,
            0,
        ),
        backoff_ms: resolve_u64(
            backoff_ms_cli,
            env::var(TX_ADAPTER_BACKOFF_MS_ENV).ok().as_deref(),
            DEFAULT_TX_ADAPTER_BACKOFF_MS,
            0,
        ),
    }
}

pub(crate) fn resolve_llm_adapter_policy(
    max_retries_cli: Option<u32>,
    backoff_ms_cli: Option<u64>,
    timeout_ms_cli: Option<u64>,
) -> LlmAdapterPolicy {
    LlmAdapterPolicy {
        retry: RetryPolicy {
            max_retries: resolve_u32(
                max_retries_cli,
                env::var(LLM_ADAPTER_MAX_RETRIES_ENV).ok().as_deref(),
                DEFAULT_LLM_ADAPTER_MAX_RETRIES,
                0,
            ),
            backoff_ms: resolve_u64(
                backoff_ms_cli,
                env::var(LLM_ADAPTER_BACKOFF_MS_ENV).ok().as_deref(),
                DEFAULT_LLM_ADAPTER_BACKOFF_MS,
                0,
            ),
        },
        timeout_ms: resolve_u64(
            timeout_ms_cli,
            env::var(LLM_ADAPTER_TIMEOUT_ENV).ok().as_deref(),
            DEFAULT_LLM_ADAPTER_TIMEOUT_MS,
            1,
        ),
    }
}

pub(crate) fn retry_delay(base_ms: u64, attempt: u32, exponential: bool) -> Duration {
    let millis = if exponential {
        exp_backoff_delay_ms(base_ms, attempt)
    } else {
        backoff_delay_ms(base_ms, attempt)
    };
    Duration::from_millis(millis)
}
