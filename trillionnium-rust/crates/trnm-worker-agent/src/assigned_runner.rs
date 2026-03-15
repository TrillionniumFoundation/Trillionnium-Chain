use anyhow::Result;
use std::{path::PathBuf, time::Duration};
use trnm_types::RequestStatus;

use crate::proof_adapter::ProofAdapter;
use crate::state::MessageIngressRecord;
use crate::{
    adapter_error_signal, append_submission, attach_llm_provenance, classify_adapter_error,
    commitment, execute_payload, reputation_delta, run_llm_adapter_with_retry,
    transition_request_status, AdapterErrorKind, LlmAdapterPolicy, ReputationSignal,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn process_assigned_record(
    rec: &mut MessageIngressRecord,
    worker: &str,
    submit: bool,
    submit_log: &PathBuf,
    llm_adapter_cmd: &str,
    verifier_max_output_chars: usize,
    llm_policy: &LlmAdapterPolicy,
    proof_adapter: &dyn ProofAdapter,
) -> Result<bool> {
    let llm = match run_llm_adapter_with_retry(
        llm_adapter_cmd,
        &rec.text,
        llm_policy.retry,
        Duration::from_millis(llm_policy.timeout_ms),
        proof_adapter,
    ) {
        Ok(v) => v,
        Err(e) => {
            let (resolution_code, failure_tag): (&str, &str) = classify_adapter_error(&e);
            rec.status = transition_request_status(&rec.status, RequestStatus::FailedAdapter)?;
            rec.verifier_status = Some("rejected".to_string());
            rec.resolution_code = Some(resolution_code.to_string());
            rec.adapter_error = Some(e.context.clone());
            rec.reputation_delta = Some(reputation_delta(adapter_error_signal(e.kind)));

            println!(
                "[assigned] request_id={} task_id={} worker={} status=FAILED_ADAPTER({}) retryable={} error={}",
                rec.request_id,
                rec.task_id,
                worker,
                failure_tag,
                matches!(e.kind, AdapterErrorKind::Retriable),
                e.context
            );
            return Ok(true);
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
        rec.status = transition_request_status(&rec.status, RequestStatus::Rejected)?;
        rec.reputation_delta = Some(reputation_delta(ReputationSignal::VerifierRejected));

        println!(
            "[assigned] request_id={} task_id={} worker={} verifier_status={} resolution_code={}",
            rec.request_id, rec.task_id, worker, v_status, resolution_code
        );
        return Ok(true);
    }

    let payload = llm.output_text;
    let (result_hash, salt_hex) = execute_payload(&payload, rec.task_id);
    let commit_hash = commitment(rec.task_id, &result_hash, &salt_hex, worker);
    rec.result_hash = Some(result_hash.clone());

    if submit {
        append_submission(
            submit_log,
            rec.task_id,
            worker,
            &commit_hash,
            &result_hash,
            &salt_hex,
        )?;
    }

    rec.status = transition_request_status(&rec.status, RequestStatus::CommitQueued)?;
    rec.reputation_delta = Some(reputation_delta(ReputationSignal::Accepted));

    println!(
        "[assigned] request_id={} task_id={} worker={} result_hash={} submit={} provider_request_id={}",
        rec.request_id,
        rec.task_id,
        worker,
        result_hash,
        submit,
        rec.provider_request_id.as_deref().unwrap_or("-")
    );
    Ok(true)
}
