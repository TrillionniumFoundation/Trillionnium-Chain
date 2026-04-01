use anyhow::{anyhow, Result};
use std::{collections::BTreeMap, env, path::{Path, PathBuf}, time::Duration};

use crate::proof_adapter::{build_proof_adapter, DEFAULT_PROOF_ADAPTER};
use crate::{
    adapter_error_signal, append_submission, apply_reputation_signal, attach_llm_provenance,
    classify_adapter_error, commitment, execute_payload, load_ingress_records,
    reputation_gap_bps_from_best, reputation_gap_bps_from_worst, resolve_llm_adapter_policy,
    run_llm_adapter_with_retry, save_ingress_records, transition_request_status,
    AdapterErrorKind, LlmAdapterPolicy, ReputationSignal, PROOF_ADAPTER_ENV,
};
use trnm_types::RequestStatus;

pub(crate) fn assigned_skip_reason(
    rec: &crate::MessageIngressRecord,
    worker: &str,
) -> Option<&'static str> {
    match RequestStatus::parse(&rec.status) {
        Ok(RequestStatus::Assigned) => {}
        _ => return Some("status_not_assigned"),
    }
    match rec.assigned_worker.as_deref() {
        Some(current) if current == worker => None,
        Some(_) => Some("assigned_worker_mismatch"),
        None => Some("assigned_worker_missing"),
    }
}

fn run_assigned_summary_line(
    processed: usize,
    skipped: &str,
    ingress_file: &Path,
    submit_log: &Path,
    llm_adapter_cmd: &str,
    adapter_retries: u32,
    adapter_backoff_ms: u64,
    adapter_timeout_ms: u64,
) -> String {
    format!(
        "[agent] run-assigned processed={} skipped={} ingress={} submit_log={} adapter={} adapter_retries={} adapter_backoff_ms={} adapter_timeout_ms={}",
        processed,
        skipped,
        ingress_file.display(),
        submit_log.display(),
        llm_adapter_cmd,
        adapter_retries,
        adapter_backoff_ms,
        adapter_timeout_ms
    )
}

fn format_skip_summary(skipped: &BTreeMap<&'static str, usize>) -> String {
    if skipped.is_empty() {
        "none".to_string()
    } else {
        skipped
            .iter()
            .map(|(reason, count)| format!("{}={}", reason, count))
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_run_assigned(
    worker: String,
    ingress_file: PathBuf,
    limit: usize,
    submit: bool,
    submit_log: PathBuf,
    llm_adapter_cmd: String,
    verifier_max_output_chars: usize,
    llm_adapter_max_retries: Option<u32>,
    llm_adapter_backoff_ms: Option<u64>,
    llm_adapter_timeout_ms: Option<u64>,
) -> Result<()> {
    let llm_policy: LlmAdapterPolicy = resolve_llm_adapter_policy(
        llm_adapter_max_retries,
        llm_adapter_backoff_ms,
        llm_adapter_timeout_ms,
    );
    let proof_adapter_name = env::var(PROOF_ADAPTER_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_PROOF_ADAPTER.to_string());
    let proof_adapter = build_proof_adapter(&proof_adapter_name).map_err(|e| {
        anyhow!(
            "invalid {PROOF_ADAPTER_ENV}={proof_adapter_name:?}: {e}; supported={DEFAULT_PROOF_ADAPTER}"
        )
    })?;
    let mut records = load_ingress_records(&ingress_file)?;
    let mut n = 0usize;
    let mut skipped: BTreeMap<&'static str, usize> = BTreeMap::new();
    for rec in records.iter_mut() {
        if n >= limit {
            break;
        }
        if let Some(reason) = assigned_skip_reason(rec, &worker) {
            *skipped.entry(reason).or_default() += 1;
            continue;
        }

        let llm = match run_llm_adapter_with_retry(
            &llm_adapter_cmd,
            &rec.text,
            llm_policy.retry,
            Duration::from_millis(llm_policy.timeout_ms),
            proof_adapter.as_ref(),
        ) {
            Ok(v) => v,
            Err(e) => {
                let (resolution_code, failure_tag) = classify_adapter_error(&e);
                let reputation_signal = adapter_error_signal(e.kind);
                let reputation_impact = apply_reputation_signal(rec, reputation_signal);
                rec.status = transition_request_status(&rec.status, RequestStatus::FailedAdapter)?;
                rec.verifier_status = Some("rejected".to_string());
                rec.resolution_code = Some(resolution_code.to_string());
                rec.adapter_error = Some(e.context.clone());
                n += 1;
                println!(
                    "[assigned] request_id={} task_id={} worker={} status=FAILED_ADAPTER({}) retryable={} reputation_signal={} reputation_delta={} reputation_tier={} reputation_weight_bps={} reputation_score_bps={} reputation_gap_bps_from_best={} reputation_gap_bps_from_worst={} error={}",
                    rec.request_id,
                    rec.task_id,
                    worker,
                    failure_tag,
                    matches!(e.kind, AdapterErrorKind::Retriable),
                    reputation_impact.label,
                    reputation_impact.delta,
                    reputation_impact.tier,
                    reputation_impact.weight_bps,
                    reputation_impact.score_bps,
                    reputation_gap_bps_from_best(reputation_signal),
                    reputation_gap_bps_from_worst(reputation_signal),
                    e.context
                );
                continue;
            }
        };
        let (verified, resolution_code) =
            proof_adapter.verify(&llm.output_text, verifier_max_output_chars);
        let v_status = if verified { "accepted" } else { "rejected" };
        attach_llm_provenance(rec, &llm);
        rec.model_output = Some(llm.output_text.clone());
        rec.verifier_status = Some(v_status.to_string());
        rec.resolution_code = Some(resolution_code.to_string());

        if v_status != "accepted" {
            let reputation_signal = ReputationSignal::VerifierRejected;
            let reputation_impact = apply_reputation_signal(rec, reputation_signal);
            rec.status = transition_request_status(&rec.status, RequestStatus::Rejected)?;
            n += 1;
            println!(
                "[assigned] request_id={} task_id={} worker={} verifier_status={} resolution_code={} reputation_signal={} reputation_delta={} reputation_tier={} reputation_weight_bps={} reputation_score_bps={} reputation_gap_bps_from_best={} reputation_gap_bps_from_worst={}",
                rec.request_id,
                rec.task_id,
                worker,
                v_status,
                resolution_code,
                reputation_impact.label,
                reputation_impact.delta,
                reputation_impact.tier,
                reputation_impact.weight_bps,
                reputation_impact.score_bps,
                reputation_gap_bps_from_best(reputation_signal),
                reputation_gap_bps_from_worst(reputation_signal)
            );
            continue;
        }

        let payload = llm.output_text;
        let (result_hash, salt_hex) = execute_payload(&payload, rec.task_id);
        let commit_hash = commitment(rec.task_id, &result_hash, &salt_hex, &worker);
        rec.result_hash = Some(result_hash.clone());
        if submit {
            append_submission(
                &submit_log,
                rec.task_id,
                &worker,
                &commit_hash,
                &result_hash,
                &salt_hex,
            )?;
        }
        let reputation_signal = ReputationSignal::Accepted;
        let reputation_impact = apply_reputation_signal(rec, reputation_signal);
        rec.status = transition_request_status(&rec.status, RequestStatus::CommitQueued)?;
        n += 1;
        println!(
            "[assigned] request_id={} task_id={} worker={} result_hash={} submit={} provider_request_id={} reputation_signal={} reputation_delta={} reputation_tier={} reputation_weight_bps={} reputation_score_bps={} reputation_gap_bps_from_best={} reputation_gap_bps_from_worst={}",
            rec.request_id,
            rec.task_id,
            worker,
            result_hash,
            submit,
            rec.provider_request_id.as_deref().unwrap_or("-"),
            reputation_impact.label,
            reputation_impact.delta,
            reputation_impact.tier,
            reputation_impact.weight_bps,
            reputation_impact.score_bps,
            reputation_gap_bps_from_best(reputation_signal),
            reputation_gap_bps_from_worst(reputation_signal)
        );
    }
    save_ingress_records(&ingress_file, &records)?;
    let skip_summary = format_skip_summary(&skipped);
    println!(
        "{}",
        run_assigned_summary_line(
            n,
            &skip_summary,
            &ingress_file,
            &submit_log,
            &llm_adapter_cmd,
            llm_policy.retry.max_retries,
            llm_policy.retry.backoff_ms,
            llm_policy.timeout_ms,
        )
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{format_skip_summary, run_assigned_summary_line};

    #[test]
    fn run_assigned_summary_line_keeps_operator_visible_handoff_tokens_stable() {
        let line = run_assigned_summary_line(
            3,
            "none",
            std::path::Path::new("logs/ingress.jsonl"),
            std::path::Path::new("logs/submit.jsonl"),
            "llm-adapter",
            2,
            150,
            5_000,
        );

        assert_eq!(
            line,
            "[agent] run-assigned processed=3 skipped=none ingress=logs/ingress.jsonl submit_log=logs/submit.jsonl adapter=llm-adapter adapter_retries=2 adapter_backoff_ms=150 adapter_timeout_ms=5000"
        );
        for token in [
            "processed=",
            "skipped=",
            "ingress=",
            "submit_log=",
            "adapter=",
            "adapter_retries=",
            "adapter_backoff_ms=",
            "adapter_timeout_ms=",
        ] {
            assert_eq!(line.matches(token).count(), 1, "token should appear once: {token}");
        }
    }

    #[test]
    fn format_skip_summary_preserves_none_sentinel_for_zero_skip_runs() {
        let skipped = BTreeMap::new();
        assert_eq!(format_skip_summary(&skipped), "none");
    }

    #[test]
    fn format_skip_summary_keeps_reason_counts_sorted_for_grep_stability() {
        let mut skipped = BTreeMap::new();
        skipped.insert("status_not_assigned", 2);
        skipped.insert("assigned_worker_missing", 1);
        skipped.insert("assigned_worker_mismatch", 4);

        assert_eq!(
            format_skip_summary(&skipped),
            "assigned_worker_mismatch=4,assigned_worker_missing=1,status_not_assigned=2"
        );
    }
}
