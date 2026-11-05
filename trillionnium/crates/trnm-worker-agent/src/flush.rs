use anyhow::Result;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_SUBMIT_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SUBMISSION_RECORDS: usize = 100_000;

// Bind the byte limit to the opened descriptor, including a file that grows
// after metadata inspection. Validate the complete record count before effects.
fn read_submission_log(path: &Path) -> Result<String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "submission replay requires a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_SUBMIT_LOG_BYTES,
        "submission log exceeds bounded replay size"
    );
    let mut bytes = Vec::new();
    file.take(MAX_SUBMIT_LOG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_SUBMIT_LOG_BYTES,
        "submission log exceeds bounded replay size"
    );
    let raw = String::from_utf8(bytes)?;
    anyhow::ensure!(
        raw.lines()
            .filter(|line| !line.trim().is_empty())
            .take(MAX_SUBMISSION_RECORDS + 1)
            .count()
            <= MAX_SUBMISSION_RECORDS,
        "submission log exceeds bounded record count"
    );
    Ok(raw)
}

use crate::{
    flush_submission::{process_submission_record, FlushRecordOutcome},
    load_acked, now_ms, resolve_path_arg_from_env, resolve_tx_adapter_timeout_ms,
    resolve_tx_retry_policy, SubmissionRecord, WORKER_EVENT_LOG_ENV, WORKER_PROGRESS_LOG_ENV,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_flush_submissions(
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
    let tx_retry = resolve_tx_retry_policy(max_retries, backoff_ms);
    let tx_timeout_ms = resolve_tx_adapter_timeout_ms();
    let event_log = resolve_path_arg_from_env(
        event_log,
        WORKER_EVENT_LOG_ENV,
        "/tmp/trnm-worker-agent-events.jsonl",
    );
    let progress_log = resolve_path_arg_from_env(
        progress_log,
        WORKER_PROGRESS_LOG_ENV,
        "/tmp/trnm-worker-agent-progress.jsonl",
    );
    if !submit_log.exists() {
        println!("[agent] no submit log found: {}", submit_log.display());
        return Ok(());
    }
    let raw = read_submission_log(&submit_log)?;
    let mut n = 0usize;
    let mut skipped = 0usize;
    let mut acked = load_acked(&ack_log)?;
    let run_id = format!("flush-{}-{}", now_ms(), std::process::id());
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let rec: SubmissionRecord = serde_json::from_str(line)?;
        n += 1;

        match process_submission_record(
            &rec,
            &ingress_file,
            update_ingress,
            execute,
            &adapter_cmd,
            tx_retry.max_retries,
            tx_retry.backoff_ms,
            tx_timeout_ms,
            &ack_log,
            &event_log,
            &progress_log,
            &run_id,
            now_ms,
            &mut acked,
        )? {
            FlushRecordOutcome::Skipped => skipped += 1,
            FlushRecordOutcome::Processed => {}
        }
    }
    println!(
        "[agent] flushed_records={} skipped={} execute={} ack_log={} event_log={} progress_log={} run_id={}",
        n,
        skipped,
        execute,
        ack_log.display(),
        event_log.display(),
        progress_log.display(),
        run_id
    );
    Ok(())
}
