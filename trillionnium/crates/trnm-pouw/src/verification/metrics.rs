use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_types::TaskObject;

use crate::verification::{proof_type_key, VerificationResult};

/// A lightweight, provider-agnostic verification observation for logs/metrics bridges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofVerificationObservation {
    pub task_id: u64,
    pub proof_type: String,
    pub verifier_id: String,
    pub outcome: String,
    pub payload_bytes: usize,
    pub timestamp_ms: u64,
}

impl ProofVerificationObservation {
    pub fn from_task(
        task: &TaskObject,
        result: &VerificationResult,
        verifier_id: impl AsRef<str>,
        payload_bytes: usize,
        timestamp_ms: u64,
    ) -> Self {
        let verifier = verifier_id.as_ref().trim();
        Self {
            task_id: task.task_id,
            proof_type: proof_type_key(task.proof_type).to_string(),
            verifier_id: if verifier.is_empty() {
                "unknown-verifier".to_string()
            } else {
                verifier.to_string()
            },
            outcome: match result {
                VerificationResult::Valid => "valid",
                VerificationResult::Invalid(_) => "invalid",
                VerificationResult::Indeterminate(_) => "indeterminate",
            }
            .to_string(),
            payload_bytes,
            timestamp_ms,
        }
    }

    pub fn labels(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("proof_type".to_string(), self.proof_type.clone()),
            ("verifier_id".to_string(), self.verifier_id.clone()),
            ("outcome".to_string(), self.outcome.clone()),
        ])
    }
}

pub fn emit_proof_verification_observation(
    task: &TaskObject,
    result: &VerificationResult,
    verifier_id: impl AsRef<str>,
    payload_bytes: usize,
) -> ProofVerificationObservation {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let observation = ProofVerificationObservation::from_task(
        task,
        result,
        verifier_id,
        payload_bytes,
        timestamp_ms,
    );
    eprintln!(
        "proof_verification_observation task_id={} proof_type={} verifier_id={} outcome={} payload_bytes={} timestamp_ms={}",
        observation.task_id,
        observation.proof_type,
        observation.verifier_id,
        observation.outcome,
        observation.payload_bytes,
        observation.timestamp_ms,
    );
    observation
}
