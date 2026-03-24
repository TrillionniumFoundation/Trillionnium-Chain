use anyhow::Result;

use crate::{
    is_idempotent_duplicate_ok, persisted_ack_hashes_for_task, run_adapter_with_retry,
    should_execute_reveal, AdapterExecResult, SubmissionRecord, RC_SKIPPED,
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

pub(crate) fn classify_flush_ack(
    commit_res: &AdapterExecResult,
    reveal_res: &AdapterExecResult,
    ack_log: &std::path::PathBuf,
    task_id: u64,
) -> FlushAckDecision {
    let previous_ack_hashes = persisted_ack_hashes_for_task(ack_log, task_id);
    let previous_commit_tx_hash = previous_ack_hashes.commit_tx_hash;
    let previous_reveal_tx_hash = previous_ack_hashes.reveal_tx_hash;

    let commit_idempotent_ok = should_execute_reveal(commit_res);
    let reveal_idempotent_ok = reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc);

    let commit_hash_observed = commit_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(commit_res.rc) && previous_commit_tx_hash.is_some());
    let reveal_hash_observed = reveal_res.tx_hash.is_some()
        || (is_idempotent_duplicate_ok(reveal_res.rc) && previous_reveal_tx_hash.is_some());

    let commit_tx_hash_for_ack = commit_res.tx_hash.clone().or(previous_commit_tx_hash);
    let reveal_tx_hash_for_ack = reveal_res.tx_hash.clone().or(previous_reveal_tx_hash);

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
