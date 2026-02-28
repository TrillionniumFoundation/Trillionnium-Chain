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
