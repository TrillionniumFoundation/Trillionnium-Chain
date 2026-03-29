use anyhow::Result;

use crate::{
    is_idempotent_duplicate_ok, persisted_ack_hashes_for_task, run_adapter_with_retry,
    should_execute_reveal, trim_boundary_audit_fillers, AdapterExecResult, SubmissionRecord,
    RC_SKIPPED,
};

pub(crate) struct SubmissionExecution {
    pub(crate) commit_res: AdapterExecResult,
    pub(crate) reveal_res: AdapterExecResult,
    pub(crate) reveal_executed: bool,
}

pub(crate) struct FlushAckDecision {
    pub(crate) ack_status: &'static str,
    pub(crate) reason_code: &'static str,
    pub(crate) ack_reason: String,
    pub(crate) commit_tx_hash_for_ack: Option<String>,
    pub(crate) reveal_tx_hash_for_ack: Option<String>,
}

pub(crate) fn execute_submission(
    rec: &SubmissionRecord,
    adapter_cmd: &str,
    tx_max_retries: u32,
    tx_backoff_ms: u64,
) -> Result<SubmissionExecution> {
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

    Ok(SubmissionExecution {
        commit_res,
        reveal_res,
        reveal_executed,
    })
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

/// Classify the final ack for the commit→reveal receipt chain.
///
/// NEAR-style async task flows may resume after one stage already reached a
/// terminal duplicate receipt on chain. In that replay-safe path we only accept
/// the task when each stage has an observable receipt hash, either from the
/// current adapter response or from a previously persisted ack record for the
/// same task. This keeps duplicate resumes idempotent without silently
/// accepting terminal outcomes that never produced auditable receipts.
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
            previous_tx_hash
        } else {
            None
        }
    })
}

pub(crate) fn classify_flush_ack(
    commit_res: &AdapterExecResult,
    reveal_res: &AdapterExecResult,
    ack_log: &std::path::PathBuf,
    task_id: u64,
) -> FlushAckDecision {
    let previous_ack_hashes = persisted_ack_hashes_for_task(ack_log, task_id);
    let previous_commit_tx_hash =
        normalize_adapter_tx_hash(previous_ack_hashes.commit_tx_hash.as_deref());
    let previous_reveal_tx_hash =
        normalize_adapter_tx_hash(previous_ack_hashes.reveal_tx_hash.as_deref());
    let observed_commit_tx_hash = normalize_adapter_tx_hash(commit_res.tx_hash.as_deref());
    let observed_reveal_tx_hash = normalize_adapter_tx_hash(reveal_res.tx_hash.as_deref());

    let commit_idempotent_ok = should_execute_reveal(commit_res);
    let reveal_idempotent_ok = reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc);

    // Duplicate receipts are only replay-safe when we can point to the original
    // on-chain evidence recorded for that stage. A bare duplicate without the
    // persisted hash stays fail-closed as missing receipt evidence.
    let commit_hash_observed = observed_commit_tx_hash.is_some()
        || (is_idempotent_duplicate_ok(commit_res.rc) && previous_commit_tx_hash.is_some());
    let reveal_hash_observed = observed_reveal_tx_hash.is_some()
        || (is_idempotent_duplicate_ok(reveal_res.rc) && previous_reveal_tx_hash.is_some());

    let commit_tx_hash_for_ack =
        stage_tx_hash_for_ack(observed_commit_tx_hash, previous_commit_tx_hash, commit_res.rc);
    let reveal_tx_hash_for_ack =
        stage_tx_hash_for_ack(observed_reveal_tx_hash, previous_reveal_tx_hash, reveal_res.rc);

    let (ack_status, reason_code, ack_reason) = if commit_idempotent_ok
        && reveal_idempotent_ok
        && commit_hash_observed
        && reveal_hash_observed
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
    };

    FlushAckDecision {
        ack_status,
        reason_code,
        ack_reason,
        commit_tx_hash_for_ack,
        reveal_tx_hash_for_ack,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_flush_ack, AdapterExecResult};
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
        let decision =
            classify_flush_ack(&commit, &reveal, &std::path::PathBuf::from("/tmp"), 1);
        assert_eq!(decision.ack_status, "rejected");
        assert_eq!(decision.reason_code, "commit_rejected_skip_reveal");
    }

    #[test]
    fn classify_flush_ack_trims_observed_receipt_hashes_before_acceptance() {
        let commit = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("  commit-hash  ".to_string()),
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("\treveal-hash\n".to_string()),
            terminal: true,
        };

        let decision =
            classify_flush_ack(&commit, &reveal, &std::path::PathBuf::from("/tmp"), 18);
        assert_eq!(decision.ack_status, "accepted");
        assert_eq!(decision.reason_code, "idempotent_ok");
        assert_eq!(decision.commit_tx_hash_for_ack.as_deref(), Some("commit-hash"));
        assert_eq!(decision.reveal_tx_hash_for_ack.as_deref(), Some("reveal-hash"));
    }

    #[test]
    fn classify_flush_ack_rejects_whitespace_only_observed_receipt_hashes() {
        let commit = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("   ".to_string()),
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("\n\t".to_string()),
            terminal: true,
        };

        let decision =
            classify_flush_ack(&commit, &reveal, &std::path::PathBuf::from("/tmp"), 19);
        assert_eq!(decision.ack_status, "failed");
        assert_eq!(decision.reason_code, "missing_tx_hash_receipt");
        assert_eq!(decision.commit_tx_hash_for_ack, None);
        assert_eq!(decision.reveal_tx_hash_for_ack, None);
    }

    #[test]
    fn classify_flush_ack_trims_bom_and_zero_width_fillers_from_observed_receipts() {
        let commit = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("\u{feff}\u{200b}commit-live\u{2060}".to_string()),
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("\u{200d}reveal-live\u{200c}".to_string()),
            terminal: true,
        };

        let decision =
            classify_flush_ack(&commit, &reveal, &std::path::PathBuf::from("/tmp"), 191);
        assert_eq!(decision.ack_status, "accepted");
        assert_eq!(decision.reason_code, "idempotent_ok");
        assert_eq!(decision.commit_tx_hash_for_ack.as_deref(), Some("commit-live"));
        assert_eq!(decision.reveal_tx_hash_for_ack.as_deref(), Some("reveal-live"));
    }

    #[test]
    fn classify_flush_ack_does_not_reuse_stale_receipts_for_non_duplicate_rejection() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-retry-outcome-stale-rejection-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            76,
            "accepted",
            Some("commit-old".to_string()),
            Some("reveal-old".to_string()),
            Some("idempotent_ok".to_string()),
            Some("run-0".to_string()),
        )
        .expect("write prior ack with stale persisted tx hashes");

        let commit = AdapterExecResult {
            ok: false,
            rc: RC_SKIPPED,
            tx_hash: None,
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: false,
            rc: RC_SKIPPED,
            tx_hash: None,
            terminal: true,
        };

        let decision = classify_flush_ack(&commit, &reveal, &ack_log, 76);
        assert_eq!(decision.ack_status, "rejected");
        assert_eq!(decision.reason_code, "commit_rejected_skip_reveal");
        assert_eq!(decision.commit_tx_hash_for_ack, None);
        assert_eq!(decision.reveal_tx_hash_for_ack, None);

        let _ = std::fs::remove_file(&ack_log);
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
        let decision =
            classify_flush_ack(&commit, &reveal, &std::path::PathBuf::from("/tmp"), 1);
        assert_eq!(decision.ack_status, "accepted");
        assert_eq!(decision.reason_code, "idempotent_ok");
    }

    #[test]
    fn classify_flush_ack_reuses_persisted_hashes_for_duplicate_resume_acceptance() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-retry-outcome-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            77,
            "failed",
            Some("commit-old".to_string()),
            Some("reveal-old".to_string()),
            Some("missing_tx_hash_receipt".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write prior ack with persisted tx hashes");

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

        let decision = classify_flush_ack(&commit, &reveal, &ack_log, 77);
        assert_eq!(decision.ack_status, "accepted");
        assert_eq!(decision.reason_code, "idempotent_ok");
        assert_eq!(decision.commit_tx_hash_for_ack.as_deref(), Some("commit-old"));
        assert_eq!(decision.reveal_tx_hash_for_ack.as_deref(), Some("reveal-old"));

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn classify_flush_ack_keeps_duplicate_resume_fail_closed_when_only_one_stage_has_receipt_evidence() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-retry-outcome-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            78,
            "failed",
            Some("commit-old".to_string()),
            None,
            Some("missing_tx_hash_receipt".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write prior ack with only commit receipt hash");

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

        let decision = classify_flush_ack(&commit, &reveal, &ack_log, 78);
        assert_eq!(decision.ack_status, "failed");
        assert_eq!(decision.reason_code, "missing_tx_hash_receipt");
        assert_eq!(decision.commit_tx_hash_for_ack.as_deref(), Some("commit-old"));
        assert_eq!(decision.reveal_tx_hash_for_ack, None);

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn classify_flush_ack_accepts_mixed_observed_and_persisted_receipt_evidence() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-retry-outcome-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            79,
            "failed",
            Some("commit-old".to_string()),
            None,
            Some("missing_tx_hash_receipt".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write prior ack with persisted commit receipt hash");

        let commit = AdapterExecResult {
            ok: false,
            rc: RC_DUPLICATE,
            tx_hash: None,
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("reveal-new".to_string()),
            terminal: true,
        };

        let decision = classify_flush_ack(&commit, &reveal, &ack_log, 79);
        assert_eq!(decision.ack_status, "accepted");
        assert_eq!(decision.reason_code, "idempotent_ok");
        assert_eq!(decision.commit_tx_hash_for_ack.as_deref(), Some("commit-old"));
        assert_eq!(decision.reveal_tx_hash_for_ack.as_deref(), Some("reveal-new"));

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn classify_flush_ack_trims_persisted_receipt_hashes_before_duplicate_resume_acceptance() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-retry-outcome-persisted-trim-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            790,
            "failed",
            Some("\u{feff}  commit-old\u{200b}".to_string()),
            Some("\t\u{200d}reveal-old\n".to_string()),
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

        let decision = classify_flush_ack(&commit, &reveal, &ack_log, 790);
        assert_eq!(decision.ack_status, "accepted");
        assert_eq!(decision.reason_code, "idempotent_ok");
        assert_eq!(decision.commit_tx_hash_for_ack.as_deref(), Some("commit-old"));
        assert_eq!(decision.reveal_tx_hash_for_ack.as_deref(), Some("reveal-old"));

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn classify_flush_ack_keeps_blank_persisted_receipts_fail_closed_for_duplicate_resume() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-retry-outcome-persisted-blank-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            7901,
            "failed",
            Some("\u{200b}\t ".to_string()),
            Some("\u{feff}\n".to_string()),
            Some("missing_tx_hash_receipt".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write prior ack with blank persisted receipt hashes");

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

        let decision = classify_flush_ack(&commit, &reveal, &ack_log, 7901);
        assert_eq!(decision.ack_status, "failed");
        assert_eq!(decision.reason_code, "missing_tx_hash_receipt");
        assert_eq!(decision.commit_tx_hash_for_ack, None);
        assert_eq!(decision.reveal_tx_hash_for_ack, None);

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn classify_flush_ack_does_not_reuse_stale_reveal_receipt_after_fresh_terminal_rejection() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-retry-outcome-reveal-rejection-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            791,
            "accepted",
            Some("commit-old".to_string()),
            Some("reveal-old".to_string()),
            Some("idempotent_ok".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write prior ack with stale persisted reveal receipt hash");

        let commit = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("commit-live".to_string()),
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: false,
            rc: RC_SKIPPED,
            tx_hash: None,
            terminal: true,
        };

        let decision = classify_flush_ack(&commit, &reveal, &ack_log, 791);
        assert_eq!(decision.ack_status, "rejected");
        assert_eq!(decision.reason_code, "deterministic_rejection");
        assert_eq!(decision.commit_tx_hash_for_ack.as_deref(), Some("commit-live"));
        assert_eq!(decision.reveal_tx_hash_for_ack, None);

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn classify_flush_ack_prefers_live_receipt_hashes_over_stale_persisted_values() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-retry-outcome-live-preferred-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            790,
            "accepted",
            Some("commit-old".to_string()),
            Some("reveal-old".to_string()),
            Some("idempotent_ok".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write prior ack with stale persisted receipt hashes");

        let commit = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("  commit-live  ".to_string()),
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("\treveal-live\n".to_string()),
            terminal: true,
        };

        let decision = classify_flush_ack(&commit, &reveal, &ack_log, 790);
        assert_eq!(decision.ack_status, "accepted");
        assert_eq!(decision.reason_code, "idempotent_ok");
        assert_eq!(decision.commit_tx_hash_for_ack.as_deref(), Some("commit-live"));
        assert_eq!(decision.reveal_tx_hash_for_ack.as_deref(), Some("reveal-live"));

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn classify_flush_ack_keeps_blank_persisted_commit_receipt_fail_closed_during_duplicate_resume() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-retry-outcome-blank-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            80,
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

        let decision = classify_flush_ack(&commit, &reveal, &ack_log, 80);
        assert_eq!(decision.ack_status, "failed");
        assert_eq!(decision.reason_code, "missing_tx_hash_receipt");
        assert_eq!(decision.commit_tx_hash_for_ack, None);
        assert_eq!(decision.reveal_tx_hash_for_ack.as_deref(), Some("reveal-old"));

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn classify_flush_ack_trims_persisted_receipt_hashes_before_duplicate_resume_acceptance() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-retry-outcome-trimmed-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            805,
            "failed",
            Some("  commit-old  ".to_string()),
            Some("\nreveal-old\t".to_string()),
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

        let decision = classify_flush_ack(&commit, &reveal, &ack_log, 805);
        assert_eq!(decision.ack_status, "accepted");
        assert_eq!(decision.reason_code, "idempotent_ok");
        assert_eq!(decision.commit_tx_hash_for_ack.as_deref(), Some("commit-old"));
        assert_eq!(decision.reveal_tx_hash_for_ack.as_deref(), Some("reveal-old"));

        let _ = std::fs::remove_file(&ack_log);
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

        let decision =
            classify_flush_ack(&commit, &reveal, &std::path::PathBuf::from("/tmp"), 81);
        assert_eq!(decision.ack_status, "failed");
        assert_eq!(decision.reason_code, "missing_tx_hash_receipt");
        assert_eq!(decision.commit_tx_hash_for_ack, None);
        assert_eq!(decision.reveal_tx_hash_for_ack, None);
    }

    #[test]
    fn classify_flush_ack_trims_live_receipt_hashes_before_persisting_ack() {
        let commit = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("  commit-live  ".to_string()),
            terminal: true,
        };
        let reveal = AdapterExecResult {
            ok: true,
            rc: RC_OK,
            tx_hash: Some("\nreveal-live\t".to_string()),
            terminal: true,
        };

        let decision =
            classify_flush_ack(&commit, &reveal, &std::path::PathBuf::from("/tmp"), 82);
        assert_eq!(decision.ack_status, "accepted");
        assert_eq!(decision.reason_code, "idempotent_ok");
        assert_eq!(decision.commit_tx_hash_for_ack.as_deref(), Some("commit-live"));
        assert_eq!(decision.reveal_tx_hash_for_ack.as_deref(), Some("reveal-live"));
    }
}
