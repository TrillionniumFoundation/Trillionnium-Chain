use anyhow::Result;

use crate::{append_event, append_progress, ProgressRecord, WorkerEvent};

pub(crate) fn append_skip_progress(
    progress_log: &std::path::PathBuf,
    run_id: &str,
    task_id: u64,
    note: &str,
    now_ms_fn: fn() -> u128,
    state: &str,
) -> Result<()> {
    append_progress(
        progress_log,
        &ProgressRecord {
            ts_unix_ms: now_ms_fn(),
            run_id: run_id.to_string(),
            task_id,
            state: state.to_string(),
            note: note.to_string(),
        },
    )
}

pub(crate) fn append_processing_progress(
    progress_log: &std::path::PathBuf,
    run_id: &str,
    task_id: u64,
    adapter_cmd: &str,
    tx_max_retries: u32,
    tx_backoff_ms: u64,
    now_ms_fn: fn() -> u128,
) -> Result<()> {
    append_progress(
        progress_log,
        &ProgressRecord {
            ts_unix_ms: now_ms_fn(),
            run_id: run_id.to_string(),
            task_id,
            state: "processing".to_string(),
            note: format!(
                "adapter={} retries={} backoff_ms={}",
                adapter_cmd, tx_max_retries, tx_backoff_ms
            ),
        },
    )
}

pub(crate) fn append_final_event_and_progress(
    event_log: &std::path::PathBuf,
    progress_log: &std::path::PathBuf,
    run_id: &str,
    task_id: u64,
    ack_status: &str,
    reason_code: &str,
    commit_rc: i32,
    reveal_rc: i32,
    now_ms_fn: fn() -> u128,
) -> Result<()> {
    append_event(
        event_log,
        &WorkerEvent {
            ts_unix_ms: now_ms_fn(),
            run_id: run_id.to_string(),
            event_type: "ack_written".to_string(),
            task_id,
            status: ack_status.to_string(),
            reason_code: reason_code.to_string(),
            commit_rc,
            reveal_rc,
        },
    )?;

    let progress_state = match ack_status {
        "accepted" => "done",
        "rejected" => "rejected",
        _ => "failed",
    };
    append_progress(
        progress_log,
        &ProgressRecord {
            ts_unix_ms: now_ms_fn(),
            run_id: run_id.to_string(),
            task_id,
            state: progress_state.to_string(),
            note: reason_code.to_string(),
        },
    )
}
