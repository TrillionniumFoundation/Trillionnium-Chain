pub mod registry;
pub mod verifiers;

use serde::{Deserialize, Serialize};
use trnm_types::TaskObject;

/// Result of a verification attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// The proof is valid and the task result is accepted.
    Valid,
    /// The proof is invalid (e.g., bad signature, bad zk-snark).
    Invalid(String),
    /// The verification could not be completed (e.g., network error, resource exhaustion).
    /// This might warrant a retry or a specific error state.
    Indeterminate(String),
}

/// A standardized receipt for verifiable execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReceipt {
    pub task_id: u64,
    pub proof_type: String,
    pub result: VerificationResult,
    pub verifier_id: String,
    pub timestamp_ms: u64,
}

/// A trait for pluggable verification logic (Fraud Proof, TEE, ZK).
///
/// This allows the market to be agnostic to *how* the work is verified.
pub trait ProofVerifier {
    /// Returns the type of proof this verifier handles.
    fn proof_type(&self) -> &str;

    /// Verifies a proof for a given task.
    ///
    /// # Arguments
    /// * `task` - The task object being verified.
    /// * `proof_data` - The proof payload (e.g., TEE quote, ZK proof bytes, fraud challenge data).
    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult;
}

/// A mock verifier for testing purposes.
pub struct MockVerifier {
    pub name: String,
    pub should_succeed: bool,
}

impl MockVerifier {
    pub fn new(name: &str, should_succeed: bool) -> Self {
        Self {
            name: name.to_string(),
            should_succeed,
        }
    }
}

impl ProofVerifier for MockVerifier {
    fn proof_type(&self) -> &str {
        &self.name
    }

    fn verify_proof(&self, _task: &TaskObject, _proof_data: &[u8]) -> VerificationResult {
        if self.should_succeed {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid(format!("Mock verification ({}) failed", self.name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 1,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Open,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: None,
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
    fn test_mock_verifier_success() {
        let verifier = MockVerifier::new("fraud", true);
        let task = mock_task();
        let result = verifier.verify_proof(&task, &[]);
        assert_eq!(result, VerificationResult::Valid);
        assert_eq!(verifier.proof_type(), "fraud");
    }

    #[test]
    fn test_mock_verifier_failure() {
        let verifier = MockVerifier::new("zk", false);
        let task = mock_task();
        let result = verifier.verify_proof(&task, &[]);
        assert!(matches!(result, VerificationResult::Invalid(msg) if msg.contains("zk")));
    }

    #[test]
    fn verification_receipt_json_roundtrip_preserves_fields() {
        let receipt = VerificationReceipt {
            task_id: 42,
            proof_type: "tee".to_string(),
            result: VerificationResult::Valid,
            verifier_id: "tee-sgx-sim".to_string(),
            timestamp_ms: 1_706_000_000_000,
        };

        let encoded = serde_json::to_string(&receipt).expect("serialize receipt");
        let decoded: VerificationReceipt =
            serde_json::from_str(&encoded).expect("deserialize receipt");

        assert_eq!(decoded, receipt);
    }
}
