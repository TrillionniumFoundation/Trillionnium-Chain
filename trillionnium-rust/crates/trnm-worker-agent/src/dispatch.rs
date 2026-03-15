use anyhow::Result;

use crate::cli::Command;

#[path = "dispatch_assigned.rs"]
mod dispatch_assigned;
#[path = "dispatch_audit.rs"]
mod dispatch_audit;
#[path = "dispatch_flush.rs"]
mod dispatch_flush;
#[path = "dispatch_workflow.rs"]
mod dispatch_workflow;

pub(crate) fn dispatch_command(cmd: Command) -> Result<()> {
    match cmd {
        Command::PullTask { state } => dispatch_workflow::dispatch_pull_task(state)?,
        Command::Execute {
            task_id,
            worker,
            payload,
        } => dispatch_workflow::dispatch_execute(task_id, worker, payload)?,
        Command::CommitReveal {
            task_id,
            worker,
            result_hash,
            salt_hex,
            submit,
            submit_log,
        } => dispatch_workflow::dispatch_commit_reveal(
            task_id,
            worker,
            result_hash,
            salt_hex,
            submit,
            submit_log,
        )?,
        Command::RunOnce {
            state,
            worker,
            payload,
            submit,
            submit_log,
        } => dispatch_workflow::dispatch_run_once(state, worker, payload, submit, submit_log)?,
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
        } => dispatch_assigned::dispatch_run_assigned(
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
        } => dispatch_flush::dispatch_flush_submissions(
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
        } => dispatch_audit::dispatch_export_audit(ingress_file, output_file)?,
        Command::QueryAudit {
            output_file,
            task_id,
            provenance_fingerprint,
        } => dispatch_audit::dispatch_query_audit(output_file, task_id, provenance_fingerprint)?,
    }
    Ok(())
}
