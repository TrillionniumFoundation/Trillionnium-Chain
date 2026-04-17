use std::sync::Arc;

use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::verify_bound_envelope;
use crate::verification::backend::{
    parse_tee_attestation_payload, BackendExecutionError, BackendVerificationRequest,
    VerificationBackendConfig, VerificationBackendError, VerificationBackendFamily, ZkBackendKind,
    ZkBackendRegistry,
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

    fn classify_backend_err(err: VerificationBackendError) -> VerificationResult {
        match err {
            VerificationBackendError::Selection(selection) => {
                VerificationResult::Indeterminate(format!("unavailable: {selection}"))
            }
            VerificationBackendError::Execution(BackendExecutionError::InvalidProof {
                reason, ..
            }) => VerificationResult::Invalid(reason),
            VerificationBackendError::Execution(BackendExecutionError::MalformedProof {
                reason, ..
            }) => VerificationResult::Invalid(format!("malformed: {reason}")),
            VerificationBackendError::Execution(BackendExecutionError::NotConfigured { .. }) => {
                VerificationResult::Indeterminate(
                    "unavailable: TEE receipt cryptographic verification backend not configured"
                        .to_string(),
                )
            }
            VerificationBackendError::Execution(BackendExecutionError::Unavailable {
                backend,
                reason,
            }) => VerificationResult::Indeterminate(format!(
                "unavailable: verification backend '{backend}' cannot currently verify receipt: {reason}"
            )),
            VerificationBackendError::Execution(BackendExecutionError::Internal {
                backend,
                reason,
            }) => VerificationResult::Indeterminate(format!(
                "backend_error: verification backend '{backend}' failed: {reason}"
            )),
        }
    }

    fn verify_backend(
        &self,
        task: &TaskObject,
        proof_data: &[u8],
    ) -> Result<(), VerificationBackendError> {
        let backend = self
            .backends
            .resolve(VerificationBackendFamily::Tee, &self.backend)?;
        let tee_payload = if matches!(self.backend, ZkBackendKind::Noop) {
            None
        } else {
            Some(parse_tee_attestation_payload(proof_data)?)
        };
        backend.verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task,
            proof_data,
            tee_payload: tee_payload.as_ref(),
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
                Err(err) => Self::classify_backend_err(err),
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

    fn mock_attested_receipt() -> &'static [u8] {
        b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel"
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
            let tee_payload = request
                .tee_payload
                .expect("tee handoff payload must be present");
            assert_eq!(tee_payload.attestation_target, "sgx-dcap");
            assert_eq!(tee_payload.verifier_kind, "quote-verifier");
            assert_eq!(tee_payload.measurement_field, "mrenclave");
            assert_eq!(tee_payload.evidence(), Some("quote-sgx-dcap-demo-v1"));
            assert_eq!(
                tee_payload.verifier_metadata.collateral.as_deref(),
                Some("intel-dcap-collateral-demo-v1")
            );
            assert_eq!(
                tee_payload.verifier_metadata.cert_chain.as_deref(),
                Some("intel-dcap-cert-chain-demo-v1")
            );
            assert_eq!(
                tee_payload.verifier_metadata.issuer.as_deref(),
                Some("intel")
            );
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

    struct MockTeeMalformedBackend;
    impl ZkBackend for MockTeeMalformedBackend {
        fn backend_id(&self) -> &str {
            "mock-tee-malformed"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.family, VerificationBackendFamily::Tee);
            Err(BackendExecutionError::MalformedProof {
                backend: request.backend_label(self.backend_id()),
                reason: "mock tee receipt malformed".to_string(),
            })
        }
    }

    struct MockTeeInternalBackend;
    impl ZkBackend for MockTeeInternalBackend {
        fn backend_id(&self) -> &str {
            "mock-tee-internal"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.family, VerificationBackendFamily::Tee);
            Err(BackendExecutionError::Internal {
                backend: request.backend_label(self.backend_id()),
                reason: "mock tee backend internal failure".to_string(),
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
            verifier.verify_proof(&task, mock_attested_receipt()),
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
                mock_attested_receipt()
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
                mock_attested_receipt()
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("unavailable:")
                    && msg.contains("mock-tee-unavailable")
                    && msg.contains("cannot currently verify receipt")
        ));
    }

    #[test]
    fn tee_verifier_backend_malformed_maps_to_invalid_fail_closed() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockTeeMalformedBackend));
        let verifier = TeeVerifier::new(
            ZkBackendKind::Custom("mock-tee-malformed".into()),
            Arc::new(backends),
        );
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                mock_attested_receipt()
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:") && msg.contains("mock tee receipt malformed")
        ));
    }

    #[test]
    fn tee_verifier_backend_internal_maps_to_indeterminate_with_backend_error_prefix() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockTeeInternalBackend));
        let verifier = TeeVerifier::new(
            ZkBackendKind::Custom("mock-tee-internal".into()),
            Arc::new(backends),
        );
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                mock_attested_receipt()
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("backend_error:")
                    && msg.contains("mock-tee-internal")
                    && msg.contains("mock tee backend internal failure")
        ));
    }

    #[test]
    fn tee_verifier_selection_error_maps_to_unavailable_prefix() {
        let verifier = TeeVerifier::new(
            ZkBackendKind::Custom("missing-tee-backend".into()),
            Arc::new(ZkBackendRegistry::new()),
        );
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("unavailable:") && msg.contains("missing-tee-backend")
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
    fn tee_verifier_rejects_duplicate_worker_binding_with_single_quoted_trailing_space_alias_fail_closed(
    ) {
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
    fn tee_verifier_rejects_legacy_receipt_alias_on_default_launch_path() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee_receipt,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("proof_type mismatch")
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
