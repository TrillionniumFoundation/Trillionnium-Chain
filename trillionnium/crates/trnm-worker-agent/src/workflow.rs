use anyhow::Result;
use std::path::PathBuf;

use crate::{
    append_submission, next_task_id,
    workflow_ops::{
        build_run_once_output, commit_template, compute_commit_hash, compute_result_and_salt,
        reveal_template, submit_log_contract_line,
    },
};

pub(crate) fn handle_pull_task(state: PathBuf) -> Result<()> {
    let task_id = next_task_id(&state)?;
    println!("[agent] pulled task_id={}", task_id);
    Ok(())
}

pub(crate) fn handle_execute(task_id: u64, worker: String, payload: String) -> Result<()> {
    let (result_hash, salt_hex) = compute_result_and_salt(task_id, &payload)?;
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
    let c = compute_commit_hash(task_id, &result_hash, &salt_hex, &worker);
    println!("[agent] task_id={} worker={}", task_id, worker);
    println!("commit_hash={}", c);
    println!(
        "template_commit={}",
        commit_template(task_id, &worker, &c, task_id)
    );
    if submit {
        // Explicitly submitted salts are retained in the owner-only journal;
        // the ordinary stdout/stderr stream is not an unrevealed-salt vault.
        append_submission(&submit_log, task_id, &worker, &c, &result_hash, &salt_hex)?;
        println!("{}", submit_log_contract_line(&submit_log));
    } else {
        println!(
            "template_reveal={}",
            reveal_template(task_id, &result_hash, &salt_hex)
        );
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
    let (result_hash, salt_hex) = compute_result_and_salt(task_id, &payload)?;
    // The durable local submission record is the only source of an already
    // committed salt. On restart, a different proposed salt must not create a
    // second commitment under the same public task identity.
    let salt_hex = if submit {
        crate::commit_salt::journal_automatic_submission(
            &submit_log,
            task_id,
            &worker,
            &result_hash,
            &salt_hex,
        )?
    } else {
        salt_hex
    };
    let commit_hash = compute_commit_hash(task_id, &result_hash, &salt_hex, &worker);
    let out = build_run_once_output(task_id, &worker, &result_hash, &salt_hex, &commit_hash);
    let mut printable = serde_json::to_value(&out)?;
    if submit {
        // Preserve the JSON field names for consumers without exposing the
        // only retained reveal secret in stdout, stderr or captured job logs.
        printable["salt_hex"] = serde_json::Value::Null;
        printable["template_reveal"] = serde_json::Value::Null;
    }
    println!("{}", serde_json::to_string_pretty(&printable)?);
    if submit {
        eprintln!("{}", submit_log_contract_line(&submit_log));
    }
    Ok(())
}
