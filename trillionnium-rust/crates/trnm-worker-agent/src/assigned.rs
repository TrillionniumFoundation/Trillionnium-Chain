#[path = "assigned_runner.rs"]
mod assigned_runner;
use anyhow::{anyhow, Result};
use std::{env, path::PathBuf};

use self::assigned_runner::process_assigned_record;
use crate::proof_adapter::{build_proof_adapter, DEFAULT_PROOF_ADAPTER};
use crate::{
    load_ingress_records, resolve_llm_adapter_policy, save_ingress_records, PROOF_ADAPTER_ENV,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_run_assigned(
    worker: String,
    ingress_file: PathBuf,
    limit: usize,
    submit: bool,
    submit_log: PathBuf,
    llm_adapter_cmd: String,
    verifier_max_output_chars: usize,
    llm_adapter_max_retries: Option<u32>,
    llm_adapter_backoff_ms: Option<u64>,
    llm_adapter_timeout_ms: Option<u64>,
) -> Result<()> {
    let llm_policy = resolve_llm_adapter_policy(
        llm_adapter_max_retries,
        llm_adapter_backoff_ms,
        llm_adapter_timeout_ms,
    );
    let proof_adapter_name = env::var(PROOF_ADAPTER_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_PROOF_ADAPTER.to_string());
    let proof_adapter = build_proof_adapter(&proof_adapter_name).map_err(|e| {
        anyhow!(
            "invalid {PROOF_ADAPTER_ENV}={proof_adapter_name:?}: {e}; supported={DEFAULT_PROOF_ADAPTER}",
        )
    })?;
    let mut records = load_ingress_records(&ingress_file)?;
    let mut n = 0usize;

    for rec in records.iter_mut() {
        if n >= limit {
            break;
        }
        if rec.status != trnm_types::RequestStatus::Assigned.as_str() {
            continue;
        }
        if rec.assigned_worker.as_deref() != Some(worker.as_str()) {
            continue;
        }

        if process_assigned_record(
            rec,
            &worker,
            submit,
            &submit_log,
            &llm_adapter_cmd,
            verifier_max_output_chars,
            &llm_policy,
            proof_adapter.as_ref(),
        )? {
            n += 1;
        }
    }

    save_ingress_records(&ingress_file, &records)?;
    println!(
        "[agent] run-assigned processed={} ingress={} submit_log={} adapter={} adapter_retries={} adapter_backoff_ms={} adapter_timeout_ms={}",
        n,
        ingress_file.display(),
        submit_log.display(),
        llm_adapter_cmd,
        llm_policy.retry.max_retries,
        llm_policy.retry.backoff_ms,
        llm_policy.timeout_ms
    );
    Ok(())
}
