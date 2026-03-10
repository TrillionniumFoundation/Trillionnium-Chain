use std::sync::Arc;

use crate::verification::backend::{
    parse_zk_proof_payload, BackendExecutionError, BackendVerificationRequest,
    BackendVerificationSuccess, VerificationBackendError, VerificationBackendConfig, ZkBackend,
    ZkBackendKind, ZkBackendRegistry,
};
use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::verify_bound_envelope;

pub struct ZkVerifier {
    backend: ZkBackendKind,
    backends: Arc<ZkBackendRegistry>,
}

impl ZkVerifier {
    pub fn new(backend: ZkBackendKind, backends: Arc<ZkBackendRegistry>) -> Self {
        Self { backend, backends }
    }

    #[allow(dead_code)]
    pub fn from_config(config: &VerificationBackendConfig, backends: Arc<ZkBackendRegistry>) -> Self {
        Self::new(config.zk_backend.clone(), backends)
    }

    fn verify_backend(&self, task: &TaskObject, proof_data: &[u8]) -> Result<(), VerificationBackendError> {
        let backend = self.backends.resolve("zk", &self.backend)?;
        let zk_payload = if proof_data
            .iter()
            .position(|b| *b == b':')
            .and_then(|idx| proof_data.get(idx + 1..))
            .and_then(|body| std::str::from_utf8(body).ok())
            .map(|body| {
                let trimmed = body.trim_start();
                trimmed.starts_with('{')
                    && (trimmed.contains("\"vk_ref\"") || trimmed.contains("\"public_inputs\""))
            })
            .unwrap_or(false)
        {
            Some(parse_zk_proof_payload(task, proof_data)?)
        } else {
            None
        };
        backend.verify(BackendVerificationRequest {
            backend_family: "zk",
            task,
            proof_data,
            zk_payload: zk_payload.as_ref(),
        })?;
        Ok(())
    }
}

impl Default for ZkVerifier {
    fn default() -> Self {
        Self::new(ZkBackendKind::Noop, Arc::new(ZkBackendRegistry::new()))
    }
}

impl ProofVerifier for ZkVerifier {
    fn proof_type(&self) -> &str {
        "zk"
    }

    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        let verification = verify_bound_envelope(task, proof_data, b"ZK:", "ZK proof");
        if matches!(verification, VerificationResult::Valid) && task.result_hash.is_none() {
            return VerificationResult::Invalid(
                "Invalid ZK proof envelope: missing task result_hash binding context".to_string(),
            );
        }

        match verification {
            VerificationResult::Valid => match self.verify_backend(task, proof_data) {
                Ok(()) => VerificationResult::Valid,
                Err(VerificationBackendError::Execution(BackendExecutionError::InvalidProof { reason, .. })) => VerificationResult::Invalid(reason),
                Err(VerificationBackendError::Execution(BackendExecutionError::NotConfigured { .. })) => {
                    VerificationResult::Indeterminate(
                        "ZK proof cryptographic verification backend not configured".to_string(),
                    )
                }
                Err(err) => VerificationResult::Indeterminate(err.to_string()),
            },
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 99,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some("worker-zk".into()),
            committed_hash: None,
            result_hash: Some([0x11; 32]),
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

    struct MockSuccessBackend;
    impl ZkBackend for MockSuccessBackend {
        fn backend_id(&self) -> &str { "mock-zk" }
        fn verify(&self, request: BackendVerificationRequest<'_>) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            let payload = request.zk_payload.expect("zk payload required");
            assert_eq!(payload.public_inputs.order, vec!["task_id", "worker", "result_hash"]);
            assert_eq!(payload.public_inputs.values[0], "99");
            assert_eq!(payload.worker, "worker-zk");
            assert_eq!(payload.vk_ref, "vk://trnm/dev/mock-groth16/v1");
            Ok(BackendVerificationSuccess { backend_id: self.backend_id().into() })
        }
    }

    #[test]
    fn zk_verifier_requires_cryptographic_backend_after_bound_envelope_validation() {
        let verifier = ZkVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,proof_type=zk,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn zk_verifier_requires_cryptographic_backend_for_legacy_proof_type_alias() {
        let verifier = ZkVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,proof_type=zk_snark,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn zk_verifier_valid_proof_path_with_mock_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        let verifier = ZkVerifier::new(ZkBackendKind::Custom("mock-zk".into()), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","worker","result_hash"],"values":["99","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(verifier.verify_proof(&task, payload), VerificationResult::Valid));
    }

    #[test]
    fn zk_verifier_invalid_proof_path_rejects_mapped_public_inputs() {
        let verifier = ZkVerifier::default();
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","worker","result_hash"],"values":["99","worker-zk","2222222222222222222222222222222222222222222222222222222222222222"]}}"#;
        assert!(matches!(verifier.verify_proof(&task, payload), VerificationResult::Invalid(msg) if msg.contains("public_inputs mismatch")));
    }

    #[test]
    fn zk_verifier_malformed_envelope_fails_closed_before_crypto() {
        let verifier = ZkVerifier::default();
        let task = mock_task();
        let payload = b"ZK:   \n\t";
        assert!(matches!(verifier.verify_proof(&task, payload), VerificationResult::Invalid(msg) if msg.contains("Invalid ZK proof envelope")));
    }
}
