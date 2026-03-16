use std::collections::HashSet;

use anyhow::Result;

use crate::{
    append_ack, append_event, append_progress, is_idempotent_duplicate_ok, is_task_acked,
    load_ingress_records, persisted_ack_hashes_for_task, run_adapter_with_retry,
    save_ingress_records, should_execute_reveal, transition_request_status, try_acquire_task_lock,
    AdapterExecResult, ProgressRecord, SubmissionRecord, WorkerEvent, RC_SKIPPED,
};

#[derive(Debug, Clone, Copy)]
pub(crate) enum FlushRecordOutcome {
    Skipped,
    Processed,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn process_submission_record(
    rec: &SubmissionRecord,
    ingress_file: &std::path::PathBuf,
    update_ingress: bool,
    execute: bool,
    adapter_cmd: &str,
    tx_max_retries: u32,
    tx_backoff_ms: u64,
    ack_log: &std::path::PathBuf,
    event_log: &std::path::PathBuf,
    progress_log: &std::path::PathBuf,
    run_id: &str,
    now_ms_fn: fn() -> u128,
    acked: &mut HashSet<u64>,
) -> Result<FlushRecordOutcome> {
    if acked.contains(&rec.task_id) {
        append_progress(
            progress_log,
            &ProgressRecord {
                ts_unix_ms: now_ms_fn(),
                run_id: run_id.to_string(),
                task_id: rec.task_id,
                state: "done".to_string(),
                note: "already_acked_skip".to_string(),
            },
        )?;
        println!("[skip] task_id={} already_acked=true", rec.task_id);
        return Ok(FlushRecordOutcome::Skipped);
    }

    if !execute {
        append_progress(
            progress_log,
            &ProgressRecord {
                ts_unix_ms: now_ms_fn(),
                run_id: run_id.to_string(),
                task_id: rec.task_id,
                state: "pending".to_string(),
                note: "dry_run_only".to_string(),
            },
        )?;
        println!(
            "[dry-run] adapter={} commit {} {} {}",
            adapter_cmd, rec.task_id, rec.worker, rec.commit_hash
        );
        println!(
            "[dry-run] adapter={} reveal {} {} {}",
            adapter_cmd, rec.task_id, rec.result_hash, rec.salt_hex
        );
        return Ok(FlushRecordOutcome::Processed);
    }

    let Some(_task_lock) = try_acquire_task_lock(ack_log, rec.task_id)? else {
        append_progress(
            progress_log,
            &ProgressRecord {
                ts_unix_ms: now_ms_fn(),
                run_id: run_id.to_string(),
                task_id: rec.task_id,
                state: "pending".to_string(),
                note: "concurrent_replay_skip".to_string(),
            },
        )?;
        println!("[skip] task_id={} concurrent_replay=true", rec.task_id);
        return Ok(FlushRecordOutcome::Skipped);
    };

    if is_task_acked(ack_log, rec.task_id) {
        acked.insert(rec.task_id);
        append_progress(
            progress_log,
            &ProgressRecord {
                ts_unix_ms: now_ms_fn(),
                run_id: run_id.to_string(),
                task_id: rec.task_id,
                state: "done".to_string(),
                note: "already_acked_after_lock".to_string(),
            },
        )?;
        println!(
            "[skip] task_id={} already_acked_after_lock=true",
            rec.task_id
        );
        return Ok(FlushRecordOutcome::Skipped);
    }

    append_progress(
        progress_log,
        &ProgressRecord {
            ts_unix_ms: now_ms_fn(),
            run_id: run_id.to_string(),
            task_id: rec.task_id,
            state: "processing".to_string(),
            note: format!(
                "adapter={} retries={} backoff_ms={}",
                adapter_cmd, tx_max_retries, tx_backoff_ms
            ),
        },
    )?;

    let (commit_args, reveal_args) = submission_args(rec);
    let commit_res =
        run_adapter_with_retry(adapter_cmd, &commit_args, tx_max_retries, tx_backoff_ms)?;
    let reveal_executed = should_execute_reveal(&commit_res);
    let reveal_res = if reveal_executed {
        run_adapter_with_retry(adapter_cmd, &reveal_args, tx_max_retries, tx_backoff_ms)?
    } else {
        AdapterExecResult {
            ok: false,
            rc: RC_SKIPPED,
            tx_hash: None,
            terminal: true,
        }
    };

    println!(
        "[submitted] task_id={} commit_ok={} reveal_ok={} reveal_executed={} commit_rc={} reveal_rc={} commit_tx_hash={} reveal_tx_hash={} adapter={} retries={} backoff_ms={}",
        rec.task_id,
        commit_res.ok,
        reveal_res.ok,
        reveal_executed,
        commit_res.rc,
        reveal_res.rc,
        commit_res.tx_hash.as_deref().unwrap_or("-"),
        reveal_res.tx_hash.as_deref().unwrap_or("-"),
        adapter_cmd,
        tx_max_retries,
        tx_backoff_ms
    );

    let (ack_status, reason_code, ack_reason) =
        classify_flush_ack(&commit_res, &reveal_res, ack_log, rec.task_id);

    let previous_ack_hashes = persisted_ack_hashes_for_task(ack_log, rec.task_id);
    let previous_commit_tx_hash = previous_ack_hashes.commit_tx_hash;
    let previous_reveal_tx_hash = previous_ack_hashes.reveal_tx_hash;

    let commit_tx_hash_for_ack = commit_res.tx_hash.clone().or(previous_commit_tx_hash);
    let reveal_tx_hash_for_ack = reveal_res.tx_hash.clone().or(previous_reveal_tx_hash);

    append_ack(
        ack_log,
        rec.task_id,
        ack_status,
        commit_tx_hash_for_ack.clone(),
        reveal_tx_hash_for_ack.clone(),
        Some(reason_code.to_string()),
        Some(run_id.to_string()),
    )?;

    if update_ingress {
        let mut ingress = load_ingress_records(ingress_file)?;
        let mut changed = false;
        for ir in ingress.iter_mut() {
            if ir.task_id == rec.task_id {
                ir.commit_tx_hash = commit_tx_hash_for_ack.clone();
                ir.reveal_tx_hash = reveal_tx_hash_for_ack.clone();
                ir.resolution_code = Some(reason_code.to_string());
                ir.verifier_status = Some(if ack_status == "accepted" {
                    "accepted".to_string()
                } else {
                    "rejected".to_string()
                });
                ir.status = match ack_status {
                    "accepted" => transition_request_status(
                        &ir.status,
                        trnm_types::RequestStatus::RevealSubmitted,
                    )?,
                    "rejected" => {
                        transition_request_status(&ir.status, trnm_types::RequestStatus::Rejected)?
                    }
                    _ => transition_request_status(
                        &ir.status,
                        trnm_types::RequestStatus::FailedSubmission,
                    )?,
                };
                changed = true;
            }
        }
        if changed {
            save_ingress_records(ingress_file, &ingress)?;
        }
    }

    append_event(
        event_log,
        &WorkerEvent {
            ts_unix_ms: now_ms_fn(),
            run_id: run_id.to_string(),
            event_type: "ack_written".to_string(),
            task_id: rec.task_id,
            status: ack_status.to_string(),
            reason_code: reason_code.to_string(),
            commit_rc: commit_res.rc,
            reveal_rc: reveal_res.rc,
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
            task_id: rec.task_id,
            state: progress_state.to_string(),
            note: reason_code.to_string(),
        },
    )?;

    if ack_status == "accepted" {
        acked.insert(rec.task_id);
    }

    println!(
        "[ack] run_id={} task_id={} status={} reason={} reason_code={}",
        run_id, rec.task_id, ack_status, ack_reason, reason_code
    );

    Ok(FlushRecordOutcome::Processed)
}

fn submission_args(rec: &SubmissionRecord) -> (Vec<String>, Vec<String>) {
    let nonce = rec.nonce.unwrap_or(rec.task_id);
    let commit_args = vec![
        "commit".to_string(),
        rec.task_id.to_string(),
        rec.worker.clone(),
        rec.commit_hash.clone(),
        nonce.to_string(),
    ];
    let reveal_args = vec![
        "reveal".to_string(),
        rec.task_id.to_string(),
        rec.result_hash.clone(),
        rec.salt_hex.clone(),
    ];
    (commit_args, reveal_args)
}

fn classify_flush_ack(
    commit_res: &AdapterExecResult,
    reveal_res: &AdapterExecResult,
    ack_log: &std::path::PathBuf,
    task_id: u64,
) -> (&'static str, &'static str, String) {
    let previous_ack_hashes = persisted_ack_hashes_for_task(ack_log, task_id);
    let previous_commit_tx_hash = previous_ack_hashes.commit_tx_hash;
    let previous_reveal_tx_hash = previous_ack_hashes.reveal_tx_hash;

    let commit_idempotent_ok = should_execute_reveal(commit_res);
    let reveal_idempotent_ok = reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc);

    let commit_hash_observed = commit_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(commit_res.rc) && previous_commit_tx_hash.is_some());
    let reveal_hash_observed = reveal_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(reveal_res.rc) && previous_reveal_tx_hash.is_some());

    if commit_idempotent_ok && reveal_idempotent_ok && commit_hash_observed && reveal_hash_observed
    {
        (
            "accepted",
            "idempotent_ok",
            format!(
                "idempotent-ok commit_rc={} reveal_rc={}",
                commit_res.rc, reveal_res.rc
            ),
        )
    } else if commit_idempotent_ok
        && reveal_idempotent_ok
        && (!commit_hash_observed || !reveal_hash_observed)
    {
        (
            "failed",
            "missing_tx_hash_receipt",
            format!(
                "missing-tx-hash-receipt commit_tx_hash_present={} reveal_tx_hash_present={} commit_rc={} reveal_rc={}",
                commit_hash_observed,
                reveal_hash_observed,
                commit_res.rc,
                reveal_res.rc
            ),
        )
    } else if !commit_idempotent_ok && commit_res.terminal {
        (
            "rejected",
            "commit_rejected_skip_reveal",
            format!(
                "deterministic-commit-rejection-skip-reveal commit_rc={} reveal_rc={}",
                commit_res.rc, reveal_res.rc
            ),
        )
    } else if commit_res.terminal || reveal_res.terminal {
        (
            "rejected",
            "deterministic_rejection",
            format!(
                "deterministic-rejection commit_rc={} reveal_rc={}",
                commit_res.rc, reveal_res.rc
            ),
        )
    } else {
        (
            "failed",
            "retry_exhausted_or_transient",
            format!(
                "transient-or-exhausted-retries commit_rc={} reveal_rc={}",
                commit_res.rc, reveal_res.rc
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_flush_ack, AdapterExecResult};
    use crate::RC_OK;
    use crate::RC_SKIPPED;

    #[test]
    fn classify_flush_ack_prefers_rejection_on_terminal_commit() {
        let commit = AdapterExecResult {
            ok: false,
            rc: RC_SKIPPED,
            tx_hash: Some("c1".to_string()),
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: false,
            rc: RC_OK,
            tx_hash: None,
            terminal: false,
        };
        let (status, reason, _) =
            classify_flush_ack(&commit, &reveal, &std::path::PathBuf::from("/tmp"), 1);
        assert_eq!(status, "rejected");
        assert_eq!(reason, "commit_rejected_skip_reveal");
    }

    #[test]
    fn classify_flush_ack_reports_idempotent_when_hashes_present() {
        let commit = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("c1".to_string()),
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("r1".to_string()),
            terminal: true,
        };
        let (status, reason, _) =
            classify_flush_ack(&commit, &reveal, &std::path::PathBuf::from("/tmp"), 1);
        assert_eq!(status, "accepted");
        assert_eq!(reason, "idempotent_ok");
    }
}
