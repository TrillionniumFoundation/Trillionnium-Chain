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

    fn normalize_key(proof_type: &str) -> Option<String> {
        let normalized = proof_type.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return None;
        }

        let canonical = match normalized.as_str() {
            "fraud_proof" | "fraud-proof" => "fraud",
            "tee_receipt" | "tee-receipt" => "tee",
            "zk_receipt" | "zk-receipt" => "zk",
            _ => normalized.as_str(),
        };

        Some(canonical.to_string())
    }

    pub fn register(&mut self, verifier: Arc<dyn ProofVerifier + Send + Sync>) {
        if let Some(key) = Self::normalize_key(verifier.proof_type()) {
            self.verifiers.insert(key, verifier);
        }
    }

    pub fn has_verifier(&self, proof_type: &str) -> bool {
        match Self::normalize_key(proof_type) {
            Some(key) => self.verifiers.contains_key(&key),
            None => false,
        }
    }

    /// Returns canonical proof types currently wired into the registry.
    ///
    /// Useful for V1 plugin-system diagnostics and CLI health checks.
    pub fn registered_proof_types(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.verifiers.keys().cloned().collect();
        keys.sort();
        keys
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

    #[test]
    fn has_verifier_is_case_insensitive() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(MockVerifier::new("TeE", true)));

        assert!(registry.has_verifier("tee"));
        assert!(registry.has_verifier("TEE"));
        assert!(!registry.has_verifier("zk"));
    }

    #[test]
    fn registry_normalizes_whitespace_in_verifier_keys() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(MockVerifier::new("  TeE  ", true)));

        assert!(registry.has_verifier("tee"));
        assert!(registry.has_verifier("  TEE  "));
        assert!(!registry.has_verifier("   "));
    }

    #[test]
    fn registry_accepts_web4_receipt_aliases() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(MockVerifier::new("tee_receipt", true)));

        assert!(registry.has_verifier("tee"));
        assert!(registry.has_verifier("tee_receipt"));
        assert!(registry.has_verifier("TEE-RECEIPT"));
    }

    #[test]
    fn verify_dispatches_from_alias_registration_to_canonical_proof_type() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(MockVerifier::new("fraud_proof", true)));

        let out = registry.verify(&mock_task(ProofType::Fraud), b"proof");
        assert_eq!(out, VerificationResult::Valid);
    }

    #[test]
    fn registered_proof_types_returns_sorted_canonical_keys() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(MockVerifier::new("  zk_receipt ", true)));
        registry.register(Arc::new(MockVerifier::new("tee-receipt", true)));
        registry.register(Arc::new(MockVerifier::new("FrAuD", true)));
        registry.register(Arc::new(MockVerifier::new("   ", true)));

        assert_eq!(
            registry.registered_proof_types(),
            vec!["fraud".to_string(), "tee".to_string(), "zk".to_string()]
        );
    }
}
