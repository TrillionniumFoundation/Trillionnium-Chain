use trnm_types::ObjectRef;

/// Result of a verification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// The proof is valid and the task result is accepted.
    Valid,
    /// The proof is invalid (e.g., bad signature, bad zk-snark).
    Invalid(String),
    /// The verification could not be completed (e.g., network error, resource exhaustion).
    /// This might warrant a retry or a specific error state.
    Indeterminate(String),
}

/// A trait for pluggable verification logic (Fraud Proof, TEE, ZK).
///
/// This allows the market to be agnostic to *how* the work is verified.
pub trait ProofVerifier {
    /// Verifies a proof for a given task.
    ///
    /// # Arguments
    /// * `task` - The task object being verified.
    /// * `proof_data` - The proof payload (e.g., TEE quote, ZK proof bytes, fraud challenge data).
    fn verify_proof(&self, task: &ObjectRef, proof_data: &[u8]) -> VerificationResult;
}

/// A mock verifier for testing purposes.
pub struct MockVerifier {
    pub should_succeed: bool,
}

impl ProofVerifier for MockVerifier {
    fn verify_proof(&self, _task: &ObjectRef, _proof_data: &[u8]) -> VerificationResult {
        if self.should_succeed {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid("Mock verification failed".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ObjectRef, TaskObject, TaskStatus};

    fn mock_task_ref() -> ObjectRef {
        ObjectRef {
            id: 1,
            version: 1,
        }
    }

    #[test]
    fn test_mock_verifier_success() {
        let verifier = MockVerifier { should_succeed: true };
        let task = mock_task_ref();
        let result = verifier.verify_proof(&task, &[]);
        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    fn test_mock_verifier_failure() {
        let verifier = MockVerifier { should_succeed: false };
        let task = mock_task_ref();
        let result = verifier.verify_proof(&task, &[]);
        assert!(matches!(result, VerificationResult::Invalid(_)));
    }
}
