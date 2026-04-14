use anyhow::Result;
use std::{fs, path::PathBuf};

use crate::{
    flush_submission::{process_submission_record, FlushRecordOutcome},
    load_acked, now_ms, resolve_path_arg_from_env, resolve_tx_retry_policy, SubmissionRecord,
    WORKER_EVENT_LOG_ENV, WORKER_PROGRESS_LOG_ENV,
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
    let raw = fs::read_to_string(&submit_log)?;
    let mut n = 0usize;
    let mut skipped = 0usize;
    let mut acked = load_acked(&ack_log);
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
