use anyhow::Result;
use std::{env, process::Command as ProcCommand, thread, time::Duration};

use crate::adapter_parse::parse_tx_hash;
use crate::command_runtime::{parse_command_spec, run_command_with_timeout};
use crate::state::{AdapterExecResult, LlmAdapterPolicy, RetryPolicy};

use super::{
    AdapterError, AdapterErrorKind, LlmAdapterResponse, RC_OK, TX_ADAPTER_BACKOFF_MS_ENV,
    TX_ADAPTER_MAX_RETRIES_ENV,
};

pub(crate) fn backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    base_ms.saturating_mul(attempt as u64 + 1)
}

pub(crate) fn run_adapter_with_retry(
    adapter_cmd: &str,
    action_args: &[String],
    max_retries: u32,
    backoff_ms: u64,
) -> Result<AdapterExecResult> {
    let (program, base_args) = parse_command_spec(adapter_cmd)?;
    let mut last_rc = 1;
    let mut last_tx_hash: Option<String> = None;

    for attempt in 0..=max_retries {
        let out = ProcCommand::new(&program)
            .args(&base_args)
            .args(action_args)
            .output()?;
        let rc = out.status.code().unwrap_or(1);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tx_hash = parse_tx_hash(&stdout).or_else(|| parse_tx_hash(&stderr));

        if out.status.success() {
            return Ok(AdapterExecResult {
                ok: true,
                rc: RC_OK,
                tx_hash,
                terminal: true,
            });
        }

        last_rc = rc;
        if tx_hash.is_some() {
            last_tx_hash = tx_hash;
        }

        // deterministic rejections (duplicate/nonce_rejected) should not retry.
        if super::is_deterministic_rejection(rc) {
            return Ok(AdapterExecResult {
                ok: false,
                rc,
                tx_hash: last_tx_hash,
                terminal: true,
            });
        }

        if attempt < max_retries {
            thread::sleep(Duration::from_millis(backoff_delay_ms(backoff_ms, attempt)));
        }
    }

    Ok(AdapterExecResult {
        ok: false,
        rc: last_rc,
        tx_hash: last_tx_hash,
        terminal: false,
    })
}

pub(crate) fn truncate_for_error(raw: &str, max_chars: usize) -> String {
    let total = raw.chars().count();
    if total <= max_chars {
        return raw.to_string();
    }
    let prefix: String = raw.chars().take(max_chars).collect();
    format!("{}…(truncated, {} chars total)", prefix, total)
}

fn parse_u32_with_min(raw: Option<&str>, default: u32, min: u32) -> u32 {
    raw.and_then(|s| s.parse::<u32>().ok())
        .filter(|v| *v >= min)
        .unwrap_or(default)
}

fn parse_u64_with_min(raw: Option<&str>, default: u64, min: u64) -> u64 {
    raw.and_then(|s| s.parse::<u64>().ok())
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
            super::DEFAULT_TX_ADAPTER_MAX_RETRIES,
            0,
        ),
        backoff_ms: resolve_u64(
            backoff_ms_cli,
            env::var(TX_ADAPTER_BACKOFF_MS_ENV).ok().as_deref(),
            super::DEFAULT_TX_ADAPTER_BACKOFF_MS,
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
                env::var(super::LLM_ADAPTER_MAX_RETRIES_ENV).ok().as_deref(),
                super::DEFAULT_LLM_ADAPTER_MAX_RETRIES,
                0,
            ),
            backoff_ms: resolve_u64(
                backoff_ms_cli,
                env::var(super::LLM_ADAPTER_BACKOFF_MS_ENV).ok().as_deref(),
                super::DEFAULT_LLM_ADAPTER_BACKOFF_MS,
                0,
            ),
        },
        timeout_ms: resolve_u64(
            timeout_ms_cli,
            env::var(super::LLM_ADAPTER_TIMEOUT_ENV).ok().as_deref(),
            super::DEFAULT_LLM_ADAPTER_TIMEOUT_MS,
            1,
        ),
    }
}

pub(crate) fn exp_backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    base_ms.saturating_mul(1u64.checked_shl(attempt.min(62)).unwrap_or(u64::MAX))
}

pub(crate) fn run_llm_adapter_once(
    adapter_cmd: &str,
    prompt: &str,
    timeout: Duration,
    proof_adapter: &dyn crate::proof_adapter::ProofAdapter,
) -> std::result::Result<LlmAdapterResponse, AdapterError> {
    let (program, base_args) = parse_command_spec(adapter_cmd).map_err(|e| AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: format!("invalid llm adapter command: {e}"),
    })?;
    let prompt_arg = vec![prompt.to_string()];
    let out =
        run_command_with_timeout(&program, &base_args, &prompt_arg, timeout).map_err(|e| {
            AdapterError {
                kind: AdapterErrorKind::Retriable,
                context: e.to_string(),
            }
        })?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        return Err(AdapterError {
            kind: AdapterErrorKind::Retriable,
            context: format!(
                "llm adapter failed rc={:?} stderr={}",
                out.status.code(),
                truncate_for_error(&stderr, 512)
            ),
        });
    }
    proof_adapter
        .parse_response(&stdout)
        .map_err(|e| AdapterError {
            kind: AdapterErrorKind::NonRetriable,
            context: format!(
                "llm adapter invalid payload: {} raw={}",
                e,
                truncate_for_error(&stdout, 512)
            ),
        })
}

pub(crate) fn run_llm_adapter_with_retry_inner<F, S>(
    max_retries: u32,
    backoff_ms: u64,
    mut op: F,
    mut sleeper: S,
) -> std::result::Result<LlmAdapterResponse, AdapterError>
where
    F: FnMut() -> std::result::Result<LlmAdapterResponse, AdapterError>,
    S: FnMut(Duration),
{
    let mut last_error: Option<AdapterError> = None;
    for attempt in 0..=max_retries {
        match op() {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                let should_retry = err.kind == AdapterErrorKind::Retriable && attempt < max_retries;
                last_error = Some(err);
                if should_retry {
                    sleeper(Duration::from_millis(exp_backoff_delay_ms(
                        backoff_ms, attempt,
                    )));
                    continue;
                }
                break;
            }
        }
    }

    Err(last_error.unwrap_or(AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "llm adapter failed: unknown error".to_string(),
    }))
}

pub(crate) fn run_llm_adapter_with_retry(
    adapter_cmd: &str,
    prompt: &str,
    retry: RetryPolicy,
    timeout: Duration,
    proof_adapter: &dyn crate::proof_adapter::ProofAdapter,
) -> std::result::Result<LlmAdapterResponse, AdapterError> {
    run_llm_adapter_with_retry_inner(
        retry.max_retries,
        retry.backoff_ms,
        || run_llm_adapter_once(adapter_cmd, prompt, timeout, proof_adapter),
        thread::sleep,
    )
}
