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
                ir.commit_tx_hash = decision.commit_tx_hash_for_ack.clone();
                ir.reveal_tx_hash = decision.reveal_tx_hash_for_ack.clone();
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
