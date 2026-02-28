use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

pub struct TeeVerifier;

impl ProofVerifier for TeeVerifier {
    fn proof_type(&self) -> &str {
        "tee"
    }

    fn verify_proof(&self, _task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        if proof_data.len() < 8 {
            return VerificationResult::Invalid("TEE receipt too short".to_string());
        }

        // V2 micro patch hardening: require explicit TEE receipt prefix.
        // Accepted example: "TEE:...".
        if proof_data.starts_with(b"TEE:") {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid("Invalid TEE receipt prefix".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        }
    }

    #[test]
    fn tee_verifier_rejects_short_receipt() {
        let verifier = TeeVerifier;
        let task = mock_task();
        assert!(matches!(
            verifier.verify_proof(&task, b"TE"),
            VerificationResult::Invalid(msg) if msg.contains("too short")
        ));
    }

    #[test]
    fn tee_verifier_accepts_explicit_prefix_receipts_when_length_is_sufficient() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert_eq!(verifier.verify_proof(&task, b"TEE:quote"), VerificationResult::Valid);
    }

    #[test]
    fn tee_verifier_rejects_legacy_prefix_receipts() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TElegacy!"),
            VerificationResult::Invalid(msg) if msg.contains("prefix")
        ));
    }

    #[test]
    fn tee_verifier_rejects_unknown_prefix_even_if_receipt_is_long_enough() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"XXreceipt"),
            VerificationResult::Invalid(msg) if msg.contains("prefix")
        ));
    }
}
