use anyhow::Result;
use std::path::PathBuf;

use crate::flush::handle_flush_submissions;

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_flush_submissions(
    submit_log: PathBuf,
    ingress_file: PathBuf,
    update_ingress: bool,
    execute: bool,
    adapter_cmd: String,
    max_retries: Option<u32>,
    backoff_ms: Option<u64>,
    ack_log: PathBuf,
    event_log: PathBuf,
    progress_log: PathBuf,
) -> Result<()> {
    handle_flush_submissions(
        submit_log,
        ingress_file,
        update_ingress,
        execute,
        adapter_cmd,
        max_retries,
        backoff_ms,
        ack_log,
        event_log,
        progress_log,
    )
}
