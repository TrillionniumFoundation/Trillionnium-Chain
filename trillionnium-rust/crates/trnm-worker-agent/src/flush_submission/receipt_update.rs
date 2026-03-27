use anyhow::Result;
use trnm_types::RequestStatus;

use crate::{append_ack, load_ingress_records, save_ingress_records, transition_request_status};

use super::retry_outcome::FlushAckDecision;

pub(crate) fn persist_ack_and_update_ingress(
    ingress_file: &std::path::PathBuf,
    update_ingress: bool,
    ack_log: &std::path::PathBuf,
    task_id: u64,
    decision: &FlushAckDecision,
    run_id: &str,
) -> Result<()> {
    append_ack(
        ack_log,
        task_id,
        decision.ack_status,
        decision.commit_tx_hash_for_ack.clone(),
        decision.reveal_tx_hash_for_ack.clone(),
        Some(decision.reason_code.to_string()),
        Some(run_id.to_string()),
    )?;

    if update_ingress {
        let mut ingress = load_ingress_records(ingress_file)?;
        let mut changed = false;
        for ir in ingress.iter_mut() {
            if ir.task_id == task_id {
                if let Some(commit_tx_hash) = decision.commit_tx_hash_for_ack.clone() {
                    ir.commit_tx_hash = Some(commit_tx_hash);
                }
                if let Some(reveal_tx_hash) = decision.reveal_tx_hash_for_ack.clone() {
                    ir.reveal_tx_hash = Some(reveal_tx_hash);
                }
                ir.resolution_code = Some(decision.reason_code.to_string());
                ir.verifier_status = Some(if decision.ack_status == "accepted" {
                    "accepted".to_string()
                } else {
                    "rejected".to_string()
                });
                ir.status = match decision.ack_status {
                    "accepted" => {
                        transition_request_status(&ir.status, RequestStatus::RevealSubmitted)?
                    }
                    "rejected" => transition_request_status(&ir.status, RequestStatus::Rejected)?,
                    _ => transition_request_status(&ir.status, RequestStatus::FailedSubmission)?,
                };
                changed = true;
            }
        }
        if changed {
            save_ingress_records(ingress_file, &ingress)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use trnm_types::RequestStatus;

    use super::{persist_ack_and_update_ingress, FlushAckDecision};
    use crate::{load_ingress_records, now_ms, save_ingress_records, MessageIngressRecord};

    fn sample_ingress_record(task_id: u64) -> MessageIngressRecord {
        MessageIngressRecord {
            request_id: format!("request-{task_id}"),
            task_id,
            channel: "telegram".to_string(),
            user_id: "user-1".to_string(),
            session_id: "session-1".to_string(),
            text: "hello".to_string(),
            idempotency_key: format!("ik-{task_id}"),
            status: RequestStatus::CommitQueued.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: None,
            provenance_schema_version: None,
            llm_provenance: None,
            result_hash: Some("result-hash".to_string()),
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: Some("commit-existing".to_string()),
            reveal_tx_hash: Some("reveal-existing".to_string()),
            adapter_error: None,
            reputation_delta: None,
        }
    }

    #[test]
    fn persist_ack_and_update_ingress_keeps_existing_receipt_hashes_when_retry_decision_has_none() {
        let base = std::env::temp_dir().join(format!(
            "trnm-worker-agent-receipt-update-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let ingress_file = base.with_extension("ingress.jsonl");
        let ack_log = base.with_extension("ack.jsonl");
        let _ = fs::remove_file(&ingress_file);
        let _ = fs::remove_file(&ack_log);

        save_ingress_records(&ingress_file, &[sample_ingress_record(91)])
            .expect("write ingress fixture");

        let decision = FlushAckDecision {
            ack_status: "failed",
            reason_code: "missing_tx_hash_receipt",
            ack_reason: "missing-tx-hash-receipt commit_tx_hash_present=false reveal_tx_hash_present=false".to_string(),
            commit_tx_hash_for_ack: None,
            reveal_tx_hash_for_ack: None,
        };

        persist_ack_and_update_ingress(
            &ingress_file,
            true,
            &ack_log,
            91,
            &decision,
            "run-1",
        )
        .expect("persist failed retry outcome");

        let ingress = load_ingress_records(&ingress_file).expect("reload ingress");
        let record = ingress.into_iter().find(|record| record.task_id == 91).unwrap();
        assert_eq!(record.commit_tx_hash.as_deref(), Some("commit-existing"));
        assert_eq!(record.reveal_tx_hash.as_deref(), Some("reveal-existing"));
        assert_eq!(record.resolution_code.as_deref(), Some("missing_tx_hash_receipt"));
        assert_eq!(record.status, RequestStatus::FailedSubmission.as_str());

        let _ = fs::remove_file(&ingress_file);
        let _ = fs::remove_file(&ack_log);
    }
}
