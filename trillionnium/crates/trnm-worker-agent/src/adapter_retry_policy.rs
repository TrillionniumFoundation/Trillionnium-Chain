use std::env;

use crate::state::{LlmAdapterPolicy, RetryPolicy};

use crate::{
    DEFAULT_LLM_ADAPTER_BACKOFF_MS, DEFAULT_LLM_ADAPTER_MAX_RETRIES,
    DEFAULT_LLM_ADAPTER_TIMEOUT_MS, DEFAULT_TX_ADAPTER_BACKOFF_MS, DEFAULT_TX_ADAPTER_MAX_RETRIES,
    LLM_ADAPTER_BACKOFF_MS_ENV, LLM_ADAPTER_MAX_RETRIES_ENV, LLM_ADAPTER_TIMEOUT_ENV,
    TX_ADAPTER_BACKOFF_MS_ENV, TX_ADAPTER_MAX_RETRIES_ENV,
};

pub(crate) fn backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    if base_ms == 0 {
        return 0;
    }
    if attempt >= 64 {
        return u64::MAX;
    }
    base_ms.saturating_mul(1u64 << attempt)
}

pub(crate) fn truncate_for_error(raw: &str, max_chars: usize) -> String {
    let total = raw.chars().count();
    if total <= max_chars {
        return raw.to_string();
    }
    let prefix: String = raw.chars().take(max_chars).collect();
    format!("{}…(truncated, {} chars total)", prefix, total)
}

fn is_invisible_filler(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
            | '\u{2060}'
            | '\u{2061}'
            | '\u{2062}'
            | '\u{2063}'
            | '\u{2064}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
            | '\u{00AD}'
            | '\u{034F}'
            | '\u{180E}'
            | '\u{FE0E}'
            | '\u{FE0F}'
            | '\u{FEFF}'
    )
}

fn trim_config_numeric_value(raw: &str) -> &str {
    raw.trim_matches(|c: char| c.is_whitespace() || is_invisible_filler(c))
}

fn parse_u32_with_min(raw: Option<&str>, default: u32, min: u32) -> u32 {
    raw.and_then(|s| trim_config_numeric_value(s).parse::<u32>().ok())
        .filter(|v| *v >= min)
        .unwrap_or(default)
}

fn parse_u64_with_min(raw: Option<&str>, default: u64, min: u64) -> u64 {
    raw.and_then(|s| trim_config_numeric_value(s).parse::<u64>().ok())
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

pub(crate) fn exp_backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    backoff_delay_ms(base_ms, attempt)
}
