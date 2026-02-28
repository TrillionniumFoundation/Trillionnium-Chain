use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

pub struct ZkVerifier;

impl ProofVerifier for ZkVerifier {
    fn proof_type(&self) -> &str {
        "zk"
    }

    fn verify_proof(&self, _task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        // ZK logic: verify zk-SNARK/STARK proof against verifying key.
        // Requires task.metadata or implicit circuit ID.

        if proof_data.len() < 10 {
            return VerificationResult::Invalid("ZK proof too short".to_string());
        }

        // Mock check: must start with "ZK"
        if proof_data.starts_with(b"ZK") {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid("Invalid ZK proof bytes".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 99,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some("worker-zk".into()),
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
    fn zk_verifier_rejects_short_proof() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"ZKshort"),
            VerificationResult::Invalid(msg) if msg.contains("too short")
        ));
    }

    #[test]
    fn zk_verifier_accepts_prefixed_proof_when_length_is_sufficient() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert_eq!(verifier.verify_proof(&task, b"ZK:payload!"), VerificationResult::Valid);
    }

    #[test]
    fn zk_verifier_rejects_non_prefixed_proof_when_length_is_sufficient() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"XX:payload!"),
            VerificationResult::Invalid(msg) if msg.contains("Invalid ZK proof")
        ));
    }
}
