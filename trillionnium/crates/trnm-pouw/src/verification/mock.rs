use trnm_types::TaskObject;

use crate::verification::{ProofVerifier, VerificationResult};

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
