use crate::{AdapterError, AdapterErrorKind, LlmAdapterResponse, ProofAdapter};

use super::llm_runtime_exec::{parse_command_spec, run_command_with_timeout};
use std::{thread, time::Duration};

use crate::llm_retry::retry_delay;

pub(crate) fn truncate_for_error(raw: &str, max_chars: usize) -> String {
    let total = raw.chars().count();
    if total <= max_chars {
        return raw.to_string();
    }
    let prefix: String = raw.chars().take(max_chars).collect();
    format!("{}…(truncated, {} chars total)", prefix, total)
}

fn run_llm_adapter_once(
    adapter_cmd: &str,
    prompt: &str,
    timeout: Duration,
    proof_adapter: &dyn ProofAdapter,
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
                    sleeper(retry_delay(backoff_ms, attempt, true));
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
    retry: crate::RetryPolicy,
    timeout: Duration,
    proof_adapter: &dyn ProofAdapter,
) -> std::result::Result<LlmAdapterResponse, AdapterError> {
    run_llm_adapter_with_retry_inner(
        retry.max_retries,
        retry.backoff_ms,
        || run_llm_adapter_once(adapter_cmd, prompt, timeout, proof_adapter),
        thread::sleep,
    )
}
