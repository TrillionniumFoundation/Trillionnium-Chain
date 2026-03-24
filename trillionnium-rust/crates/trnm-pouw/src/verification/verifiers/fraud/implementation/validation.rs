use crate::verification::VerificationResult;
use trnm_types::TaskObject;

use super::{evidence::verify_fraud_evidence, payload::fraud_payload_bytes};

pub(super) fn validate_fraud_proof(task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
    verify_fraud_evidence(task, fraud_payload_bytes(proof_data))
}
