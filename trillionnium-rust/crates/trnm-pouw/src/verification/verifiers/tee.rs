use std::sync::Arc;

use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::verify_bound_envelope;
use crate::verification::backend::{
    BackendExecutionError, BackendVerificationRequest, VerificationBackendConfig,
    VerificationBackendError, VerificationBackendFamily, ZkBackendKind, ZkBackendRegistry,
};

pub struct TeeVerifier {
    backend: ZkBackendKind,
    backends: Arc<ZkBackendRegistry>,
}

impl TeeVerifier {
    pub fn new(backend: ZkBackendKind, backends: Arc<ZkBackendRegistry>) -> Self {
        Self { backend, backends }
    }

    #[allow(dead_code)]
    pub fn from_config(
        config: &VerificationBackendConfig,
        backends: Arc<ZkBackendRegistry>,
    ) -> Self {
        Self::new(config.tee_backend.clone(), backends)
    }

    fn verify_backend(
        &self,
        task: &TaskObject,
        proof_data: &[u8],
    ) -> Result<(), VerificationBackendError> {
        let backend = self
            .backends
            .resolve(VerificationBackendFamily::Tee, &self.backend)?;
        backend.verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task,
            proof_data,
            zk_payload: None,
            resolved_vk_ref: None,
        })?;
        Ok(())
    }
}

impl Default for TeeVerifier {
    fn default() -> Self {
        Self::new(ZkBackendKind::Noop, Arc::new(ZkBackendRegistry::new()))
    }
}

impl ProofVerifier for TeeVerifier {
    fn proof_type(&self) -> &str {
        "tee"
    }

    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        match verify_bound_envelope(task, proof_data, b"TEE:", "TEE receipt") {
            VerificationResult::Valid => match self.verify_backend(task, proof_data) {
                Ok(()) => VerificationResult::Valid,
                Err(VerificationBackendError::Execution(BackendExecutionError::InvalidProof {
                    reason,
                    ..
                })) => VerificationResult::Invalid(reason),
                Err(VerificationBackendError::Execution(
                    BackendExecutionError::NotConfigured { .. },
                )) => VerificationResult::Indeterminate(
                    "TEE receipt cryptographic verification backend not configured".to_string(),
                ),
                Err(err) => VerificationResult::Indeterminate(err.to_string()),
            },
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::backend::{
        BackendExecutionError, BackendVerificationSuccess, ZkBackend,
    };
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: Some([0xabu8; 32]),
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

    struct MockTeeSuccessBackend;
    impl ZkBackend for MockTeeSuccessBackend {
        fn backend_id(&self) -> &str {
            "mock-tee"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.family, VerificationBackendFamily::Tee);
            assert_eq!(request.task.task_id, 42);
            assert!(request.zk_payload.is_none());
            Ok(BackendVerificationSuccess {
                backend_id: self.backend_id().into(),
            })
        }
    }

    struct MockTeeInvalidBackend;
    impl ZkBackend for MockTeeInvalidBackend {
        fn backend_id(&self) -> &str {
            "mock-tee-invalid"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.family, VerificationBackendFamily::Tee);
            Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: "mock tee backend rejected proof".to_string(),
            })
        }
    }

    struct MockTeeUnavailableBackend;
    impl ZkBackend for MockTeeUnavailableBackend {
        fn backend_id(&self) -> &str {
            "mock-tee-unavailable"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.family, VerificationBackendFamily::Tee);
            Err(BackendExecutionError::Unavailable {
                backend: request.backend_label(self.backend_id()),
                reason: "mock tee backend unavailable".to_string(),
            })
        }
    }

    #[test]
    fn tee_verifier_requires_cryptographic_backend_after_bound_envelope_validation() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn tee_verifier_valid_receipt_path_with_mock_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockTeeSuccessBackend));
        let verifier =
            TeeVerifier::new(ZkBackendKind::Custom("mock-tee".into()), Arc::new(backends));
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Valid
        ));
    }

    #[test]
    fn tee_verifier_invalid_receipt_path_with_mock_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockTeeInvalidBackend));
        let verifier = TeeVerifier::new(
            ZkBackendKind::Custom("mock-tee-invalid".into()),
            Arc::new(backends),
        );
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("mock tee backend rejected proof")
        ));
    }

    #[test]
    fn tee_verifier_backend_unavailable_maps_to_indeterminate() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockTeeUnavailableBackend));
        let verifier = TeeVerifier::new(
            ZkBackendKind::Custom("mock-tee-unavailable".into()),
            Arc::new(backends),
        );
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Indeterminate(msg) if msg.contains("mock tee backend unavailable")
        ));
    }

    #[test]
    fn tee_verifier_rejects_task_id_mismatch() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:task_id=99,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"),
            VerificationResult::Invalid(msg) if msg.contains("task_id mismatch")
        ));
    }

    #[test]
    fn tee_verifier_rejects_missing_task_id_binding() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:quote=abc,nonce=1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab"),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_task_id_identifier_spoof() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:xtask_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_task_id_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_task_id_binding_with_quoted_leading_space_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=\" 42\",task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_task_id_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=\"42 \",task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_task_id_binding_with_single_quoted_alias_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id='42',task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_task_id_binding_with_double_quoted_alias_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=\"42\",task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_proof_type_mismatch_when_present() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab"),
            VerificationResult::Invalid(msg) if msg.contains("proof_type mismatch")
        ));
    }

    #[test]
    fn tee_verifier_rejects_missing_proof_type_binding() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:task_id=42,worker=worker1,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"),
            VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_case_variant_duplicate_proof_type_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,Proof_Type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_proof_type_binding_with_quoted_leading_space_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=\" tee\",proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_proof_type_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=\"tee \",proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_proof_type_binding_with_single_quoted_trailing_space_fail_closed(
    ) {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type='tee ',proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_proof_type_binding_with_single_quoted_leading_space_fail_closed(
    ) {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=' tee',proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_missing_result_hash_binding() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:task_id=42,worker=worker1,proof_type=tee,quote=abc"),
            VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_result_hash_mismatch_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("result_hash mismatch")
        ));
    }

    #[test]
    fn tee_verifier_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,Result_Hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_result_hash_with_repeated_hex_prefix_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=0x0xabababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("result_hash mismatch")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_result_hash_binding_with_quoted_leading_space_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=\" abababababababababababababababababababababababababababababababab\",result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_result_hash_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=\"abababababababababababababababababababababababababababababababab \",result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_result_hash_binding_with_single_quoted_alias_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,'result_hash'=abababababababababababababababababababababababababababababababab,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_result_hash_binding_with_double_quoted_alias_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,\"result_hash\"=abababababababababababababababababababababababababababababababab,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_unexpected_result_hash_binding_without_context_fail_closed() {
        let verifier = TeeVerifier::default();
        let mut task = mock_task();
        task.result_hash = None;

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_result_hash_binding_without_context_fail_closed() {
        let verifier = TeeVerifier::default();
        let mut task = mock_task();
        task.result_hash = None;

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=aa,result_hash=bb,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_missing_worker_binding() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:task_id=42,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_worker_binding_identifier_spoof() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,networker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_fullwidth_underscore_worker_identifier_spoof_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "TEE:task_id=42,work＿er=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_worker_case_mismatch() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=Worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("worker mismatch")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_worker_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,worker=worker1,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_case_variant_duplicate_worker_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,Worker=worker1,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_worker_binding_with_single_quoted_alias_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,'worker'=worker1,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,\"worker\"=worker1,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_worker_binding_with_single_quoted_trailing_space_alias_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,'worker '=worker1,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_worker_binding_with_unclosed_quoted_alias_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,\"worker=worker1,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_unexpected_worker_binding_without_context_fail_closed() {
        let verifier = TeeVerifier::default();
        let mut task = mock_task();
        task.worker = None;

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
        ));
    }

    #[test]
    fn tee_verifier_requires_cryptographic_backend_for_legacy_receipt_alias() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee_receipt,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn tee_verifier_rejects_fullwidth_equals_unexpected_worker_binding_without_context_fail_closed()
    {
        let verifier = TeeVerifier::default();
        let mut task = mock_task();
        task.worker = None;

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "TEE:task_id=42,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,worker＝worker1,quote=abc"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_fullwidth_equals_then_ascii_result_hash_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "TEE:task_id=42,worker=worker1,proof_type=tee,result_hash＝abababababababababababababababababababababababababababababababab,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_fullwidth_equals_then_ascii_task_id_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "TEE:task_id＝42,task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_fullwidth_equals_then_ascii_proof_type_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "TEE:task_id=42,worker=worker1,proof_type＝tee,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_fullwidth_colon_then_ascii_result_hash_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "TEE:task_id=42,worker=worker1,proof_type=tee,result_hash：abababababababababababababababababababababababababababababababab,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_fullwidth_colon_then_ascii_worker_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "TEE:task_id=42,worker：worker1,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }
}
