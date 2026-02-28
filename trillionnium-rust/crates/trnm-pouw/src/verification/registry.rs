use std::collections::HashMap;
use std::sync::Arc;

use trnm_types::{ProofType, TaskObject};

use super::{verifiers, ProofVerifier, VerificationResult};

pub struct VerifierRegistry {
    verifiers: HashMap<String, Arc<dyn ProofVerifier + Send + Sync>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    /// Initializes a registry with built-in verifiers for Fraud/TEE/ZK proof types.
    pub fn with_builtin_verifiers() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(verifiers::FraudVerifier));
        registry.register(Arc::new(verifiers::TeeVerifier));
        registry.register(Arc::new(verifiers::ZkVerifier));
        registry
    }

    fn normalize_key(raw: &str) -> Option<String> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        }
    }

    pub fn register(&mut self, verifier: Arc<dyn ProofVerifier + Send + Sync>) {
        if let Some(key) = Self::normalize_key(verifier.proof_type()) {
            self.verifiers.insert(key, verifier);
        }
    }

    /// Returns normalized proof-type keys currently registered in lexical order.
    ///
    /// This supports V1 plugin observability/debugging without exposing verifier internals.
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
    use std::sync::Arc;
    use trnm_types::{TaskStatus, TaskObject};

    struct AlwaysValidVerifier {
        kind: &'static str,
    }

    impl ProofVerifier for AlwaysValidVerifier {
        fn proof_type(&self) -> &str {
            self.kind
        }

        fn verify_proof(&self, _task: &TaskObject, _proof_data: &[u8]) -> VerificationResult {
            VerificationResult::Valid
        }
    }

    struct TaggedVerifier {
        kind: &'static str,
        tag: &'static str,
    }

    impl ProofVerifier for TaggedVerifier {
        fn proof_type(&self) -> &str {
            self.kind
        }

        fn verify_proof(&self, _task: &TaskObject, _proof_data: &[u8]) -> VerificationResult {
            VerificationResult::Invalid(self.tag.to_string())
        }
    }

    fn task_with_proof_type(proof_type: ProofType) -> TaskObject {
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
    fn registry_register_is_case_insensitive_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: "TEE" }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(registry.verify(&task, b"receipt"), VerificationResult::Valid);
    }

    #[test]
    fn registry_register_trims_verifier_key_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: " tee " }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(registry.verify(&task, b"receipt"), VerificationResult::Valid);
    }

    #[test]
    fn registry_ignores_empty_verifier_key_after_normalization() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: "   " }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Indeterminate("no verifier registered for proof type: tee".into())
        );
    }

    #[test]
    fn registry_re_register_replaces_verifier_for_normalized_key() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(TaggedVerifier {
            kind: "TEE",
            tag: "old",
        }));
        registry.register(Arc::new(TaggedVerifier {
            kind: " tee ",
            tag: "new",
        }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Invalid("new".to_string())
        );
    }

    #[test]
    fn registry_registered_proof_types_are_normalized_and_sorted() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: " ZK " }));
        registry.register(Arc::new(AlwaysValidVerifier { kind: "fraud" }));
        registry.register(Arc::new(AlwaysValidVerifier { kind: "TEE" }));

        assert_eq!(
            registry.registered_proof_types(),
            vec!["fraud".to_string(), "tee".to_string(), "zk".to_string()]
        );
    }

    #[test]
    fn registry_returns_indeterminate_when_verifier_is_missing() {
        let registry = VerifierRegistry::new();
        let task = task_with_proof_type(ProofType::Zk);

        assert_eq!(
            registry.verify(&task, b"proof"),
            VerificationResult::Indeterminate("no verifier registered for proof type: zk".into())
        );
    }

    #[test]
    fn registry_with_builtin_verifiers_registers_v1_stack() {
        let registry = VerifierRegistry::with_builtin_verifiers();

        let fraud_task = task_with_proof_type(ProofType::Fraud);
        let tee_task = task_with_proof_type(ProofType::Tee);
        let zk_task = task_with_proof_type(ProofType::Zk);

        assert_eq!(registry.verify(&fraud_task, b"FRAUD:challenge"), VerificationResult::Valid);
        assert_eq!(registry.verify(&tee_task, b"TEE:quote"), VerificationResult::Valid);
        assert_eq!(registry.verify(&zk_task, b"ZK:payload!"), VerificationResult::Valid);
    }
}

