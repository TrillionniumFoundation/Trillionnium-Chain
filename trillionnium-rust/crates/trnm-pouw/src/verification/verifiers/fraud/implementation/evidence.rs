use crate::verification::{verifiers::verify_bound_envelope, VerificationResult};
use trnm_types::TaskObject;

use super::constants::{FRAUD_ENVELOPE_PREFIX, FRAUD_PROOF_KIND};

pub(super) fn verify_fraud_evidence(task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
    verify_bound_envelope(task, proof_data, FRAUD_ENVELOPE_PREFIX, FRAUD_PROOF_KIND)
}
