use anyhow::Result;
use std::path::PathBuf;

use crate::assigned::handle_run_assigned;

pub(crate) fn dispatch_run_assigned(
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
    handle_run_assigned(
        worker,
        ingress_file,
        limit,
        submit,
        submit_log,
        llm_adapter_cmd,
        verifier_max_output_chars,
        llm_adapter_max_retries,
        llm_adapter_backoff_ms,
        llm_adapter_timeout_ms,
    )
}
