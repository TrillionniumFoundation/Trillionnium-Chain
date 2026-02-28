use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

pub struct FraudVerifier;

impl ProofVerifier for FraudVerifier {
    fn proof_type(&self) -> &str {
        "fraud"
    }

    fn verify_proof(&self, _task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        if proof_data.is_empty() {
            return VerificationResult::Invalid("Fraud proof payload is empty".to_string());
        }

        // V1 micro-patch: require explicit fraud-proof envelope marker.
        // Accept case-insensitive variants to tolerate client casing drift.
        // Accepted examples: "FRAUD:...", "fraud:...".
        if proof_data.len() >= 6 && proof_data[..6].eq_ignore_ascii_case(b"FRAUD:") {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid("Invalid fraud proof envelope".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 7,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some("worker-fraud".into()),
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
    fn fraud_verifier_rejects_empty_payload() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b""),
            VerificationResult::Invalid(msg) if msg.contains("empty")
        ));
    }

    #[test]
    fn fraud_verifier_accepts_prefixed_envelope() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"FRAUD:challenge-proof"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn fraud_verifier_accepts_lowercase_prefixed_envelope() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"fraud:challenge-proof"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn fraud_verifier_rejects_non_prefixed_payload() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"challenge-proof"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }
}
