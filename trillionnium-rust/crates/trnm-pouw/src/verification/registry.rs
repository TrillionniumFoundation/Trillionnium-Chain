use std::collections::HashMap;
use std::sync::Arc;

use trnm_types::{ProofType, TaskObject};

use super::{ProofVerifier, VerificationResult};

pub struct VerifierRegistry {
    verifiers: HashMap<String, Arc<dyn ProofVerifier + Send + Sync>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    pub fn register(&mut self, verifier: Arc<dyn ProofVerifier + Send + Sync>) {
        self.verifiers
            .insert(verifier.proof_type().to_ascii_lowercase(), verifier);
    }

    pub fn verify(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        let key = match task.proof_type {
            ProofType::Fraud => "fraud",
            ProofType::Tee => "tee",
            ProofType::Zk => "zk",
        };

        match self.verifiers.get(key) {
            Some(verifier) => verifier.verify_proof(task, proof_data),
            None => VerificationResult::Indeterminate(format!(
                "no verifier registered for proof type: {}",
                key
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::MockVerifier;
    use std::sync::Arc;
    use trnm_types::{ProofType, TaskStatus};

    fn mock_task(proof_type: ProofType) -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Open,
            proof_type,
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
    fn verify_dispatches_to_registered_verifier() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(MockVerifier::new("FrAuD", true)));

        let out = registry.verify(&mock_task(ProofType::Fraud), b"ignored");
        assert_eq!(out, VerificationResult::Valid);
    }

    #[test]
    fn verify_returns_indeterminate_when_verifier_missing() {
        let registry = VerifierRegistry::new();

        let out = registry.verify(&mock_task(ProofType::Zk), b"proof");
        assert!(matches!(
            out,
            VerificationResult::Indeterminate(msg) if msg.contains("no verifier registered for proof type: zk")
        ));
    }
}
