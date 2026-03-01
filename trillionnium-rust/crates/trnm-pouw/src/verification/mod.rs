pub mod registry;
pub mod verifiers;

use serde::{Deserialize, Serialize};
use trnm_types::{ProofType, TaskObject};

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

impl VerificationReceipt {
    /// Creates a canonical receipt shape for persistence and downstream analytics.
    ///
    /// - `proof_type` is normalized to lowercase + trimmed.
    /// - legacy receipt aliases (`fraud_proof|tee_receipt|zk_receipt`) collapse to canonical router keys.
    /// - `verifier_id` is trimmed and falls back to `unknown-verifier` when empty.
    pub fn new(
        task_id: u64,
        proof_type: impl AsRef<str>,
        result: VerificationResult,
        verifier_id: impl AsRef<str>,
        timestamp_ms: u64,
    ) -> Self {
        let normalized_proof_type = normalize_receipt_proof_type(proof_type.as_ref());
        let verifier = verifier_id.as_ref().trim();
        Self {
            task_id,
            proof_type: if normalized_proof_type.is_empty() {
                "unknown".to_string()
            } else {
                normalized_proof_type
            },
            result,
            verifier_id: if verifier.is_empty() {
                "unknown-verifier".to_string()
            } else {
                verifier.to_string()
            },
            timestamp_ms,
        }
    }

    /// Builds a canonical receipt directly from task metadata.
    ///
    /// This avoids proof-type string drift between V1 adapter routing and persisted V2 receipts.
    pub fn from_task(
        task: &TaskObject,
        result: VerificationResult,
        verifier_id: impl AsRef<str>,
        timestamp_ms: u64,
    ) -> Self {
        Self::new(
            task.task_id,
            proof_type_key(task.proof_type),
            result,
            verifier_id,
            timestamp_ms,
        )
    }
}

fn normalize_receipt_proof_type(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "fraud_proof" | "fraud-proof" | "fraud proof" => "fraud".to_string(),
        "tee_receipt" | "tee-receipt" | "tee receipt" => "tee".to_string(),
        "zk_receipt" | "zk-receipt" | "zk receipt" => "zk".to_string(),
        other => other.to_string(),
    }
}

/// Returns the canonical key used across verification routing and receipt persistence.
pub fn proof_type_key(proof_type: ProofType) -> &'static str {
    match proof_type {
        ProofType::Fraud => "fraud",
        ProofType::Tee => "tee",
        ProofType::Zk => "zk",
    }
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
        let receipt = VerificationReceipt::new(
            42,
            "tee",
            VerificationResult::Valid,
            "tee-sgx-sim",
            1_706_000_000_000,
        );

        let encoded = serde_json::to_string(&receipt).expect("serialize receipt");
        let decoded: VerificationReceipt =
            serde_json::from_str(&encoded).expect("deserialize receipt");

        assert_eq!(decoded, receipt);
    }

    #[test]
    fn verification_receipt_new_normalizes_fields() {
        let receipt = VerificationReceipt::new(7, " TEE ", VerificationResult::Valid, "   ", 123);

        assert_eq!(receipt.task_id, 7);
        assert_eq!(receipt.proof_type, "tee");
        assert_eq!(receipt.verifier_id, "unknown-verifier");
        assert_eq!(receipt.timestamp_ms, 123);
    }

    #[test]
    fn verification_receipt_new_defaults_unknown_proof_type_when_blank() {
        let receipt = VerificationReceipt::new(
            9,
            " \n\t ",
            VerificationResult::Indeterminate("deferred".into()),
            "tee-verifier-1",
            456,
        );

        assert_eq!(receipt.proof_type, "unknown");
        assert_eq!(receipt.verifier_id, "tee-verifier-1");
        assert!(matches!(
            receipt.result,
            VerificationResult::Indeterminate(msg) if msg == "deferred"
        ));
    }

    #[test]
    fn proof_type_key_returns_canonical_router_keys() {
        assert_eq!(proof_type_key(ProofType::Fraud), "fraud");
        assert_eq!(proof_type_key(ProofType::Tee), "tee");
        assert_eq!(proof_type_key(ProofType::Zk), "zk");
    }

    #[test]
    fn verification_receipt_from_task_uses_canonical_proof_key_and_task_id() {
        let mut task = mock_task();
        task.task_id = 77;
        task.proof_type = ProofType::Tee;

        let receipt =
            VerificationReceipt::from_task(&task, VerificationResult::Valid, " tee-verifier ", 789);

        assert_eq!(receipt.task_id, 77);
        assert_eq!(receipt.proof_type, "tee");
        assert_eq!(receipt.verifier_id, "tee-verifier");
        assert_eq!(receipt.timestamp_ms, 789);
        assert_eq!(receipt.result, VerificationResult::Valid);
    }

    #[test]
    fn verification_receipt_new_collapses_legacy_receipt_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "Fraud_Proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, " tee_receipt ", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "ZK_RECEIPT", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_hyphenated_legacy_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "fraud-proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, " tee-receipt ", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "ZK-RECEIPT", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }

    #[test]
    fn verification_receipt_new_collapses_space_delimited_legacy_aliases_to_router_keys() {
        let fraud = VerificationReceipt::new(1, "Fraud Proof", VerificationResult::Valid, "v", 1);
        let tee = VerificationReceipt::new(2, " tee receipt ", VerificationResult::Valid, "v", 2);
        let zk = VerificationReceipt::new(3, "ZK RECEIPT", VerificationResult::Valid, "v", 3);

        assert_eq!(fraud.proof_type, "fraud");
        assert_eq!(tee.proof_type, "tee");
        assert_eq!(zk.proof_type, "zk");
    }
}
