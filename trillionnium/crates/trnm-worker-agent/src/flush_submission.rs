use std::collections::HashSet;

use anyhow::Result;

use crate::{
    append_ack, append_event, append_progress, is_idempotent_duplicate_ok, is_task_acked,
    load_ingress_records, persisted_ack_hashes_for_task, run_adapter_with_retry,
    save_ingress_records, should_execute_reveal, transition_request_status,
    trim_boundary_audit_fillers, try_acquire_task_lock, AdapterExecResult, ProgressRecord,
    SubmissionRecord, WorkerEvent, RC_SKIPPED,
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

    let commit_tx_hash_for_ack = stage_tx_hash_for_ack(
        normalize_adapter_tx_hash(commit_res.tx_hash.as_deref()),
        previous_commit_tx_hash,
        commit_res.rc,
    );
    let reveal_tx_hash_for_ack = stage_tx_hash_for_ack(
        normalize_adapter_tx_hash(reveal_res.tx_hash.as_deref()),
        previous_reveal_tx_hash,
        reveal_res.rc,
    );

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
                ir.verifier_status = Some(verifier_status_for_ack_status(ack_status).to_string());
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

fn normalize_adapter_tx_hash(tx_hash: Option<&str>) -> Option<String> {
    tx_hash.and_then(|hash| {
        let trimmed = trim_boundary_audit_fillers(hash);
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn stage_tx_hash_for_ack(
    observed_tx_hash: Option<String>,
    previous_tx_hash: Option<String>,
    rc: i32,
) -> Option<String> {
    observed_tx_hash.or_else(|| {
        if is_idempotent_duplicate_ok(rc) {
            previous_tx_hash.and_then(|hash| {
                let trimmed = trim_boundary_audit_fillers(&hash);
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
        } else {
            None
        }
    })
}

fn receipt_hash_observed(
    observed_tx_hash: Option<String>,
    previous_tx_hash: Option<String>,
    rc: i32,
) -> bool {
    observed_tx_hash.is_some() || stage_tx_hash_for_ack(None, previous_tx_hash, rc).is_some()
}

fn verifier_status_for_ack_status(ack_status: &str) -> &'static str {
    match ack_status {
        "accepted" => "accepted",
        "rejected" => "rejected",
        _ => "failed",
    }
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
    let observed_commit_tx_hash = normalize_adapter_tx_hash(commit_res.tx_hash.as_deref());
    let observed_reveal_tx_hash = normalize_adapter_tx_hash(reveal_res.tx_hash.as_deref());

    let commit_idempotent_ok = should_execute_reveal(commit_res);
    let reveal_idempotent_ok = reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc);

    let commit_hash_observed = receipt_hash_observed(
        observed_commit_tx_hash,
        previous_commit_tx_hash,
        commit_res.rc,
    );
    let reveal_hash_observed = receipt_hash_observed(
        observed_reveal_tx_hash,
        previous_reveal_tx_hash,
        reveal_res.rc,
    );

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
    use super::{classify_flush_ack, verifier_status_for_ack_status, AdapterExecResult};
    use crate::{append_ack, now_ms, RC_DUPLICATE, RC_OK, RC_SKIPPED};

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

    #[test]
    fn classify_flush_ack_treats_blank_live_receipt_hashes_as_missing_evidence() {
        let commit = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("  \n\t ".to_string()),
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("   ".to_string()),
            terminal: true,
        };

        let (status, reason, _) =
            classify_flush_ack(&commit, &reveal, &std::path::PathBuf::from("/tmp"), 81);
        assert_eq!(status, "failed");
        assert_eq!(reason, "missing_tx_hash_receipt");
    }

    #[test]
    fn classify_flush_ack_keeps_blank_persisted_commit_receipt_fail_closed_during_duplicate_resume()
    {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-flush-blank-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            82,
            "failed",
            Some("   ".to_string()),
            Some("reveal-old".to_string()),
            Some("missing_tx_hash_receipt".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write prior ack with blank commit receipt hash");

        let commit = AdapterExecResult {
            ok: false,
            rc: RC_DUPLICATE,
            tx_hash: None,
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: false,
            rc: RC_DUPLICATE,
            tx_hash: None,
            terminal: true,
        };

        let (status, reason, _) = classify_flush_ack(&commit, &reveal, &ack_log, 82);
        assert_eq!(status, "failed");
        assert_eq!(reason, "missing_tx_hash_receipt");

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn classify_flush_ack_keeps_blank_persisted_reveal_receipt_fail_closed_during_duplicate_resume()
    {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-flush-blank-reveal-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            83,
            "failed",
            Some("commit-old".to_string()),
            Some(" \n\t ".to_string()),
            Some("missing_tx_hash_receipt".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write prior ack with blank reveal receipt hash");

        let commit = AdapterExecResult {
            ok: false,
            rc: RC_DUPLICATE,
            tx_hash: None,
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: false,
            rc: RC_DUPLICATE,
            tx_hash: None,
            terminal: true,
        };

        let (status, reason, _) = classify_flush_ack(&commit, &reveal, &ack_log, 83);
        assert_eq!(status, "failed");
        assert_eq!(reason, "missing_tx_hash_receipt");

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn classify_flush_ack_reuses_trimmed_persisted_hashes_during_duplicate_resume() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-flush-trimmed-duplicate-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            84,
            "failed",
            Some("  commit-old  ".to_string()),
            Some("\n\treveal-old\t ".to_string()),
            Some("missing_tx_hash_receipt".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write prior ack with padded persisted receipt hashes");

        let commit = AdapterExecResult {
            ok: false,
            rc: RC_DUPLICATE,
            tx_hash: None,
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: false,
            rc: RC_DUPLICATE,
            tx_hash: None,
            terminal: true,
        };

        let (status, reason, detail) = classify_flush_ack(&commit, &reveal, &ack_log, 84);
        assert_eq!(status, "accepted");
        assert_eq!(reason, "idempotent_ok");
        assert!(detail.contains("commit_rc="));
        assert!(detail.contains("reveal_rc="));

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn stage_tx_hash_for_ack_reuses_previous_hash_when_duplicate_receipt_is_blank() {
        let staged = super::stage_tx_hash_for_ack(
            super::normalize_adapter_tx_hash(Some("  \n\t ")),
            Some(" previous-commit ".to_string()),
            RC_DUPLICATE,
        );
        assert_eq!(staged.as_deref(), Some("previous-commit"));
    }

    #[test]
    fn stage_tx_hash_for_ack_does_not_reuse_previous_hash_for_non_duplicate_blank_receipt() {
        let staged = super::stage_tx_hash_for_ack(
            super::normalize_adapter_tx_hash(Some("   ")),
            Some("previous-commit".to_string()),
            RC_OK,
        );
        assert_eq!(staged, None);
    }

    #[test]
    fn normalize_adapter_tx_hash_trims_bom_and_zero_width_fillers() {
        let normalized = super::normalize_adapter_tx_hash(Some(
            "\u{feff}\u{200b}fresh-commit-hash\u{2060}\u{200d}",
        ));
        assert_eq!(normalized.as_deref(), Some("fresh-commit-hash"));
    }

    #[test]
    fn stage_tx_hash_for_ack_reuses_previous_hash_when_duplicate_receipt_has_only_invisible_fillers(
    ) {
        let staged = super::stage_tx_hash_for_ack(
            super::normalize_adapter_tx_hash(Some("\u{feff}\u{200b}\u{2060}")),
            Some("previous-commit".to_string()),
            RC_DUPLICATE,
        );
        assert_eq!(staged.as_deref(), Some("previous-commit"));
    }

    #[test]
    fn stage_tx_hash_for_ack_prefers_fresh_duplicate_receipt_over_persisted_hash() {
        let staged = super::stage_tx_hash_for_ack(
            super::normalize_adapter_tx_hash(Some("  fresh-commit-hash\n")),
            Some("previous-commit".to_string()),
            RC_DUPLICATE,
        );
        assert_eq!(staged.as_deref(), Some("fresh-commit-hash"));
    }

    #[test]
    fn stage_tx_hash_for_ack_canonicalizes_boundary_fillers_in_persisted_duplicate_receipts() {
        let staged = super::stage_tx_hash_for_ack(
            None,
            Some("\u{feff}\u{200b}previous-commit\u{2060}\u{200d}".to_string()),
            RC_DUPLICATE,
        );
        assert_eq!(staged.as_deref(), Some("previous-commit"));
    }

    #[test]
    fn receipt_hash_observed_only_reuses_trimmed_previous_hash_for_duplicates() {
        assert!(super::receipt_hash_observed(
            None,
            Some(" previous-commit ".to_string()),
            RC_DUPLICATE,
        ));
        assert!(!super::receipt_hash_observed(
            None,
            Some("   ".to_string()),
            RC_DUPLICATE,
        ));
        assert!(!super::receipt_hash_observed(
            None,
            Some("previous-commit".to_string()),
            RC_OK,
        ));
    }

    #[test]
    fn classify_flush_ack_does_not_reuse_persisted_reveal_hash_without_duplicate_receipt() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-flush-nonduplicate-reveal-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            84,
            "accepted",
            Some("commit-old".to_string()),
            Some("reveal-old".to_string()),
            Some("idempotent_ok".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write prior ack with persisted reveal receipt hash");

        let commit = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("commit-new".to_string()),
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: None,
            terminal: true,
        };

        let (status, reason, _) = classify_flush_ack(&commit, &reveal, &ack_log, 84);
        assert_eq!(status, "failed");
        assert_eq!(reason, "missing_tx_hash_receipt");

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn verifier_status_mapping_keeps_retryable_flush_failures_distinct_from_rejections() {
        assert_eq!(verifier_status_for_ack_status("accepted"), "accepted");
        assert_eq!(verifier_status_for_ack_status("rejected"), "rejected");
        assert_eq!(verifier_status_for_ack_status("failed"), "failed");
        assert_eq!(
            verifier_status_for_ack_status("missing_tx_hash_receipt"),
            "failed"
        );
    }
}
