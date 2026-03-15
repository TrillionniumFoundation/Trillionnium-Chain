use anyhow::Result;
use std::path::PathBuf;

use crate::append_submission;
#[path = "workflow_ops.rs"]
mod workflow_ops;

use crate::next_task_id;
use workflow_ops::{
    build_run_once_output, commit_template, compute_commit_hash, compute_result_and_salt,
    reveal_template,
};

pub(crate) fn handle_pull_task(state: PathBuf) -> Result<()> {
    let task_id = next_task_id(&state)?;
    println!("[agent] pulled task_id={}", task_id);
    Ok(())
}

pub(crate) fn handle_execute(task_id: u64, worker: String, payload: String) -> Result<()> {
    let (result_hash, salt_hex) = compute_result_and_salt(task_id, &payload);
    println!("[agent] executed task_id={} worker={}", task_id, worker);
    println!("result_hash={}", result_hash);
    println!("salt_hex={}", salt_hex);
    Ok(())
}

pub(crate) fn handle_commit_reveal(
    task_id: u64,
    worker: String,
    result_hash: String,
    salt_hex: String,
    submit: bool,
    submit_log: PathBuf,
) -> Result<()> {
    let commit_hash = compute_commit_hash(task_id, &result_hash, &salt_hex, &worker);
    let commit_cmd = commit_template(task_id, &worker, &commit_hash, task_id);
    let reveal_cmd = reveal_template(task_id, &result_hash, &salt_hex);

    println!("[agent] task_id={} worker={}", task_id, worker);
    println!("commit_hash={}", commit_hash);
    println!("template_commit={}", commit_cmd);
    println!("template_reveal={}", reveal_cmd);
    if submit {
        append_submission(
            &submit_log,
            task_id,
            &worker,
            &commit_hash,
            &result_hash,
            &salt_hex,
        )?;
        println!("submitted=true submit_log={}", submit_log.display());
    }
    Ok(())
}

pub(crate) fn handle_run_once(
    state: PathBuf,
    worker: String,
    payload: String,
    submit: bool,
    submit_log: PathBuf,
) -> Result<()> {
    let task_id = next_task_id(&state)?;
    let (result_hash, salt_hex) = compute_result_and_salt(task_id, &payload);
    let commit_hash = compute_commit_hash(task_id, &result_hash, &salt_hex, &worker);
    if submit {
        append_submission(
            &submit_log,
            task_id,
            &worker,
            &commit_hash,
            &result_hash,
            &salt_hex,
        )?;
    }
    let out = build_run_once_output(task_id, &worker, &result_hash, &salt_hex, &commit_hash);
    println!("{}", serde_json::to_string_pretty(&out)?);
    if submit {
        eprintln!("submitted=true submit_log={}", submit_log.display());
    }
    Ok(())
}
