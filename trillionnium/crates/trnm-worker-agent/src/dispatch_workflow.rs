use anyhow::Result;
use std::path::PathBuf;

use crate::workflow::{handle_commit_reveal, handle_execute, handle_pull_task, handle_run_once};

pub(crate) fn dispatch_pull_task(state: PathBuf) -> Result<()> {
    handle_pull_task(state)
}

pub(crate) fn dispatch_execute(task_id: u64, worker: String, payload: String) -> Result<()> {
    handle_execute(task_id, worker, payload)
}

pub(crate) fn dispatch_commit_reveal(
    task_id: u64,
    worker: String,
    result_hash: String,
    salt_hex: String,
    submit: bool,
    submit_log: PathBuf,
) -> Result<()> {
    handle_commit_reveal(task_id, worker, result_hash, salt_hex, submit, submit_log)
}

pub(crate) fn dispatch_run_once(
    state: PathBuf,
    worker: String,
    payload: String,
    submit: bool,
    submit_log: PathBuf,
) -> Result<()> {
    handle_run_once(state, worker, payload, submit, submit_log)
}
