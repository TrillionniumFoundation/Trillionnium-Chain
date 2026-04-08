use anyhow::Result;

use crate::assigned::handle_run_assigned;
use crate::cli::Command;
use crate::flush::handle_flush_submissions;
use crate::workflow::{handle_commit_reveal, handle_execute, handle_pull_task, handle_run_once};
use crate::*;

pub(crate) fn dispatch_command(cmd: Command) -> Result<()> {
    match cmd {
        Command::PullTask { state } => handle_pull_task(state)?,
        Command::Execute {
            task_id,
            worker,
            payload,
        } => handle_execute(task_id, worker, payload)?,
        Command::CommitReveal {
            task_id,
            worker,
            result_hash,
            salt_hex,
            submit,
            submit_log,
        } => handle_commit_reveal(task_id, worker, result_hash, salt_hex, submit, submit_log)?,
        Command::RunOnce {
            state,
            worker,
            payload,
            submit,
            submit_log,
        } => handle_run_once(state, worker, payload, submit, submit_log)?,
        Command::RunAssigned {
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
        } => handle_run_assigned(
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
        )?,
        Command::FlushSubmissions {
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
        } => handle_flush_submissions(
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
        )?,
        Command::ExportAudit {
            ingress_file,
            output_file,
        } => handle_export_audit(ingress_file, output_file)?,
        Command::QueryAudit {
            output_file,
            task_id,
            provenance_fingerprint,
        } => handle_query_audit(output_file, task_id, provenance_fingerprint)?,
    }
    Ok(())
}
