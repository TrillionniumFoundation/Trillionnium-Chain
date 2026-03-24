mod constants;
mod evidence;
mod payload;
mod validation;

use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use validation::validate_fraud_proof;

/// Fraud stays as a semantic verifier in the V1 verification platform.
///
/// Unlike TEE/ZK, Fraud does not dispatch into a configurable cryptographic
/// backend family: verification is the fail-closed envelope/binding check
/// itself until a real fraud-proof backend contract exists.
pub struct FraudVerifier;

impl ProofVerifier for FraudVerifier {
    fn proof_type(&self) -> &str {
        "fraud"
    }

    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        validate_fraud_proof(task, proof_data)
    }
}

#[cfg(test)]
#[path = "implementation/tests.rs"]
mod tests;
