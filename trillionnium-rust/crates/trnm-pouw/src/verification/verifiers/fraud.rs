use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

pub struct FraudVerifier;

impl ProofVerifier for FraudVerifier {
    fn proof_type(&self) -> &str {
        "fraud"
    }

    fn verify_proof(&self, _task: &TaskObject, _proof_data: &[u8]) -> VerificationResult {
        // Optimistic Fraud Proofs are verified via the challenge-response game on-chain.
        // This verifier function is invoked when a challenge is resolved, or perhaps during the challenge itself.
        // For now, we return Valid as a placeholder, because the real logic is in apply_resolve.
        VerificationResult::Valid
    }
}
