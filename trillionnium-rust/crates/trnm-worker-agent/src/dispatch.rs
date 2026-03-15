use anyhow::Result;

use crate::assigned::handle_run_assigned;
use crate::cli::Command;
use crate::flush::handle_flush_submissions;
use crate::*;

pub(crate) fn dispatch_command(cmd: Command) -> Result<()> {
    match cmd {
        Command::PullTask { state } => {
            let task_id = next_task_id(&state)?;
            println!("[agent] pulled task_id={}", task_id);
        }
        Command::Execute {
            task_id,
            worker,
            payload,
        } => {
            let (result_hash, salt_hex) = execute_payload(&payload, task_id);
            println!("[agent] executed task_id={} worker={}", task_id, worker);
            println!("result_hash={}", result_hash);
            println!("salt_hex={}", salt_hex);
        }
        Command::CommitReveal {
            task_id,
            worker,
            result_hash,
            salt_hex,
            submit,
            submit_log,
        } => {
            let c = commitment(task_id, &result_hash, &salt_hex, &worker);
            println!("[agent] task_id={} worker={}", task_id, worker);
            println!("commit_hash={}", c);
            println!(
                "template_commit=trnm-node tx commit-result {} {} {} {}",
                task_id, worker, c, task_id
            );
            println!(
                "template_reveal=trnm-node tx reveal-result {} {} {}",
                task_id, result_hash, salt_hex
            );
            if submit {
                append_submission(&submit_log, task_id, &worker, &c, &result_hash, &salt_hex)?;
                println!("submitted=true submit_log={}", submit_log.display());
            }
        }
        Command::RunOnce {
            state,
            worker,
            payload,
            submit,
            submit_log,
        } => {
            let task_id = next_task_id(&state)?;
            let (result_hash, salt_hex) = execute_payload(&payload, task_id);
            let commit_hash = commitment(task_id, &result_hash, &salt_hex, &worker);
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
            let out = RunOnceOutput {
                task_id,
                worker: worker.clone(),
                result_hash: result_hash.clone(),
                salt_hex: salt_hex.clone(),
                commit_hash: commit_hash.clone(),
                template_commit: format!(
                    "trnm-node tx commit-result {} {} {} {}",
                    task_id, worker, commit_hash, task_id
                ),
                template_reveal: format!(
                    "trnm-node tx reveal-result {} {} {}",
                    task_id, result_hash, salt_hex
                ),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
            if submit {
                eprintln!("submitted=true submit_log={}", submit_log.display());
            }
        }
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
