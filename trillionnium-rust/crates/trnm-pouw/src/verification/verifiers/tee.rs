use std::sync::Arc;

use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::verify_bound_envelope;
use crate::verification::backend::{
    BackendExecutionError, BackendVerificationRequest, TeeBackendKind, TeeBackendRegistry,
    VerificationBackendConfig, VerificationBackendError, VerificationBackendFamily,
};

pub struct TeeVerifier {
    backend: TeeBackendKind,
    backends: Arc<TeeBackendRegistry>,
}

impl TeeVerifier {
    pub fn new(backend: TeeBackendKind, backends: Arc<TeeBackendRegistry>) -> Self {
        Self { backend, backends }
    }

    #[allow(dead_code)]
    pub fn from_config(
        config: &VerificationBackendConfig,
        backends: Arc<TeeBackendRegistry>,
    ) -> Self {
        Self::new(config.tee_backend.clone(), backends)
    }

    fn classify_backend_err(err: VerificationBackendError) -> VerificationResult {
        match err {
            VerificationBackendError::Selection(selection) => {
                VerificationResult::Indeterminate(format!("unavailable: {selection}"))
            }
            VerificationBackendError::Execution(exec_err) => Self::classify_execution_err(exec_err),
        }
    }

    fn classify_execution_err(err: BackendExecutionError) -> VerificationResult {
        let evidence_surface = Self::attestation_evidence_surface(err.reason());
        match err {
            BackendExecutionError::InvalidProof { reason, .. } => {
                VerificationResult::Invalid(format!(
                    "invalid TEE attestation {}: {reason}",
                    Self::invalid_surface_label(evidence_surface)
                ))
            }
            BackendExecutionError::MalformedProof { reason, .. } => {
                VerificationResult::Invalid(format!(
                    "malformed TEE attestation {}: {reason}",
                    Self::malformed_surface_label(evidence_surface)
                ))
            }
            BackendExecutionError::NotConfigured { .. } => VerificationResult::Indeterminate(
                "unavailable: TEE attestation cryptographic verification backend not configured"
                    .to_string(),
            ),
            BackendExecutionError::Unavailable { backend, reason } => {
                let message = format!(
                    "unavailable: verification backend '{backend}' cannot currently verify TEE attestation {evidence_surface}: {reason}"
                );
                if evidence_surface == "evidence/claims" {
                    VerificationResult::Indeterminate(format!(
                        "{message} (legacy: cannot currently verify TEE attestation evidence/claims)"
                    ))
                } else {
                    VerificationResult::Indeterminate(message)
                }
            }
            BackendExecutionError::Internal { backend, reason } => {
                let message = format!(
                    "backend_error: verification backend '{backend}' failed while verifying TEE attestation {evidence_surface}: {reason}"
                );
                if matches!(evidence_surface, "payload/claims" | "quote/report claims") {
                    VerificationResult::Indeterminate(format!(
                        "{message} (legacy: failed while verifying TEE attestation quote/report claims)"
                    ))
                } else {
                    VerificationResult::Indeterminate(message)
                }
            }
        }
    }

    fn invalid_surface_label(surface: &'static str) -> &'static str {
        match surface {
            "payload/claims" | "evidence/claims" => "claims",
            other => other,
        }
    }

    fn malformed_surface_label(surface: &'static str) -> &'static str {
        match surface {
            // For malformed TEE attestations we intentionally collapse all
            // evidence/claim variants to a single fail-closed surface so callers
            // do not accidentally build report-vs-quote branching on malformed
            // input text.
            "quote claims"
            | "report claims"
            | "quote/report claims"
            | "claims"
            | "evidence/claims"
            | "quote evidence"
            | "report evidence"
            | "quote/report evidence" => "payload/claims",
            other => other,
        }
    }

    fn attestation_evidence_surface(reason: Option<&str>) -> &'static str {
        let Some(reason) = reason else {
            return "evidence/claims";
        };
        let normalized = reason.to_ascii_lowercase();

        // Keep TEE attestation surface inference scoped to attestation-oriented
        // evidence labels first. ZK-style `payload` wording can appear in shared
        // backend plumbing, but for TEE we prefer quote/report/evidence/claims
        // surfaces unless the reason is explicitly payload-bound and lacks any
        // attestation context.
        let mentions_unavailable = normalized.contains("unavailable");
        let mentions_quote = normalized.contains("quote");
        let mentions_report = normalized.contains("report");
        let mentions_claims = normalized.contains("claim");
        let mentions_payload = normalized.contains("payload");
        let mentions_evidence = normalized.contains("evidence");
        let mentions_attestation = normalized.contains("attestation");
        let mentions_receipt = normalized.contains("receipt");

        if mentions_unavailable && !mentions_quote && !mentions_report && !mentions_claims {
            return "evidence/claims";
        }

        if mentions_quote && mentions_report {
            return if mentions_claims || mentions_payload {
                "quote/report claims"
            } else {
                "quote/report evidence"
            };
        }

        if mentions_quote {
            return if mentions_claims || mentions_payload {
                "quote claims"
            } else {
                "quote evidence"
            };
        }

        if mentions_report {
            return if mentions_claims || mentions_payload {
                "report claims"
            } else {
                "report evidence"
            };
        }

        if mentions_claims {
            return if mentions_attestation || mentions_receipt {
                "evidence/claims"
            } else {
                "claims"
            };
        }

        if mentions_payload {
            return if mentions_attestation || mentions_receipt {
                "evidence/claims"
            } else {
                "payload/claims"
            };
        }

        if mentions_evidence || mentions_attestation || mentions_receipt {
            return "evidence/claims";
        }

        // Generic TEE backend failures without explicit quote/report/payload cues
        // should still stay on attestation-oriented wording instead of falling
        // back to ZK-style payload terminology.
        "evidence/claims"
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
        Self::new(TeeBackendKind::Noop, Arc::new(TeeBackendRegistry::new()))
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
                reason: "mock tee attestation receipt malformed".to_string(),
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
                if msg.contains("TEE attestation cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn tee_verifier_valid_receipt_path_with_mock_backend() {
        let mut backends = TeeBackendRegistry::new();
        backends.register(Arc::new(MockTeeSuccessBackend));
        let verifier = TeeVerifier::new(
            TeeBackendKind::Custom("mock-tee".into()),
            Arc::new(backends),
        );
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
    fn tee_verifier_invalid_attestation_claims_path_with_mock_backend() {
        let mut backends = TeeBackendRegistry::new();
        backends.register(Arc::new(MockTeeInvalidBackend));
        let verifier = TeeVerifier::new(
            TeeBackendKind::Custom("mock-tee-invalid".into()),
            Arc::new(backends),
        );
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("invalid TEE attestation claims:")
                    && msg.contains("mock tee backend rejected proof")
        ));
    }

    #[test]
    fn tee_verifier_backend_unavailable_maps_to_indeterminate() {
        let mut backends = TeeBackendRegistry::new();
        backends.register(Arc::new(MockTeeUnavailableBackend));
        let verifier = TeeVerifier::new(
            TeeBackendKind::Custom("mock-tee-unavailable".into()),
            Arc::new(backends),
        );
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("unavailable:")
                    && msg.contains("mock-tee-unavailable")
                    && msg.contains("cannot currently verify TEE attestation evidence/claims")
        ));
    }

    #[test]
    fn tee_verifier_backend_malformed_attestation_payload_or_claims_maps_to_invalid_fail_closed() {
        let mut backends = TeeBackendRegistry::new();
        backends.register(Arc::new(MockTeeMalformedBackend));
        let verifier = TeeVerifier::new(
            TeeBackendKind::Custom("mock-tee-malformed".into()),
            Arc::new(backends),
        );
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed TEE attestation payload/claims:") && msg.contains("mock tee attestation receipt malformed")
        ));
    }

    #[test]
    fn tee_verifier_backend_malformed_quote_or_report_claims_maps_to_payload_invalid_fail_closed() {
        let mut backends = TeeBackendRegistry::new();
        backends.register(Arc::new(MockTeeMalformedBackend));
        let verifier = TeeVerifier::new(
            TeeBackendKind::Custom("mock-tee-malformed".into()),
            Arc::new(backends),
        );
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,report=claims"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed TEE attestation payload/claims:")
                    && !msg.contains("receipt:")
                    && msg.contains("mock tee attestation receipt malformed")
        ));
    }

    #[test]
    fn tee_verifier_backend_internal_maps_to_indeterminate_with_backend_error_prefix() {
        let mut backends = TeeBackendRegistry::new();
        backends.register(Arc::new(MockTeeInternalBackend));
        let verifier = TeeVerifier::new(
            TeeBackendKind::Custom("mock-tee-internal".into()),
            Arc::new(backends),
        );
        let task = mock_task();

        let result = verifier.verify_proof(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
        );
        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("mock-tee-internal"), "message: {msg}");
        assert!(
            msg.contains("mock tee backend internal failure"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_internal_report_evidence_keeps_report_surface_without_legacy_claims_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "report evidence verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("report evidence"), "message: {msg}");
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_quote_report_claims_keeps_combined_claims_surface_and_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote/report claims verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("quote/report claims"), "message: {msg}");
        assert!(
            msg.contains("legacy: failed while verifying TEE attestation quote/report claims"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_internal_quote_report_evidence_keeps_combined_evidence_surface_without_claims_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote/report evidence verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("quote/report evidence"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_attestation_claims_prefers_evidence_claims_surface_over_zk_payload_wording(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "TEE attestation claims payload verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_attestation_payload_without_claims_still_prefers_evidence_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "TEE attestation payload verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_generic_reason_defaults_to_evidence_claims_surface() {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "signature mismatch".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_invalid_generic_reason_keeps_claims_wording_without_payload_leakage() {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::InvalidProof {
            backend: "tee:mock-tee-invalid".to_string(),
            reason: "signature mismatch".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Invalid(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Invalid(msg) = result else {
            unreachable!()
        };
        assert!(
            msg.contains("invalid TEE attestation claims:"),
            "message: {msg}"
        );
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(msg.contains("signature mismatch"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_invalid_attestation_payload_keeps_claims_wording_without_zk_payload_surface_leakage(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::InvalidProof {
            backend: "tee:mock-tee-invalid".to_string(),
            reason: "TEE attestation payload signature mismatch".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Invalid(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Invalid(msg) = result else {
            unreachable!()
        };
        assert!(
            msg.contains("invalid TEE attestation claims:"),
            "message: {msg}"
        );
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
        assert!(
            msg.contains("TEE attestation payload signature mismatch"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_internal_quote_payload_prefers_quote_claims_surface_over_quote_evidence(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote payload verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("quote evidence"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_quote_receipt_prefers_quote_evidence_surface_without_claims_or_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote receipt verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(msg.contains("quote evidence"), "message: {msg}");
        assert!(!msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_report_receipt_prefers_report_evidence_surface_without_claims_or_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "report receipt verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(msg.contains("report evidence"), "message: {msg}");
        assert!(!msg.contains("report claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_quote_report_receipt_prefers_combined_evidence_surface_without_claims_or_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote/report receipt verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(msg.contains("quote/report evidence"), "message: {msg}");
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_quote_report_attestation_payload_prefers_combined_claims_surface_without_zk_payload_leakage(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote/report attestation payload verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("quote/report evidence"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_generic_payload_wording_still_prefers_attestation_evidence_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "payload verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("report claims"), "message: {msg}");
        assert!(
            msg.contains("legacy: cannot currently verify TEE attestation evidence/claims"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_internal_attestation_receipt_claims_prefers_evidence_claims_surface_without_quote_report_or_payload_leakage(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "TEE attestation receipt claims verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("report claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_report_payload_prefers_report_claims_surface_over_report_evidence(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "report payload verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("report claims"), "message: {msg}");
        assert!(!msg.contains("report evidence"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_quote_claims_keeps_quote_claims_surface_without_legacy_evidence_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote claims verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_quote_attestation_receipt_claims_still_prefers_quote_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote attestation receipt claims verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_report_attestation_receipt_claims_still_prefers_report_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "report attestation receipt claims verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(msg.contains("report claims"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_malformed_quote_evidence_collapses_to_payload_claims_surface() {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::MalformedProof {
            backend: "tee:mock-tee-malformed".to_string(),
            reason: "quote evidence malformed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Invalid(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Invalid(msg) = result else {
            unreachable!()
        };
        assert!(
            msg.contains("malformed TEE attestation payload/claims:"),
            "message: {msg}"
        );
        assert!(msg.contains("quote evidence malformed"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_malformed_quote_report_evidence_collapses_to_payload_claims_surface() {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::MalformedProof {
            backend: "tee:mock-tee-malformed".to_string(),
            reason: "quote/report evidence malformed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Invalid(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Invalid(msg) = result else {
            unreachable!()
        };
        assert!(
            msg.contains("malformed TEE attestation payload/claims:"),
            "message: {msg}"
        );
        assert!(
            msg.contains("quote/report evidence malformed"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_malformed_report_receipt_collapses_to_payload_claims_surface() {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::MalformedProof {
            backend: "tee:mock-tee-malformed".to_string(),
            reason: "report receipt malformed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Invalid(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Invalid(msg) = result else {
            unreachable!()
        };
        assert!(
            msg.contains("malformed TEE attestation payload/claims:"),
            "message: {msg}"
        );
        assert!(msg.contains("report receipt malformed"), "message: {msg}");
        assert!(!msg.contains("report evidence"), "message: {msg}");
        assert!(!msg.contains("report claims"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_malformed_attestation_payload_without_quote_or_report_still_collapses_to_payload_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::MalformedProof {
            backend: "tee:mock-tee-malformed".to_string(),
            reason: "TEE attestation payload malformed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Invalid(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Invalid(msg) = result else {
            unreachable!()
        };
        assert!(
            msg.contains("malformed TEE attestation payload/claims:"),
            "message: {msg}"
        );
        assert!(
            msg.contains("TEE attestation payload malformed"),
            "message: {msg}"
        );
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_malformed_report_claims_collapses_to_payload_claims_surface() {
        let mut backends = TeeBackendRegistry::new();
        backends.register(Arc::new(MockTeeMalformedBackend));
        let verifier = TeeVerifier::new(
            TeeBackendKind::Custom("mock-tee-malformed".into()),
            Arc::new(backends),
        );
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,report=claims"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed TEE attestation payload/claims:")
                    && !msg.contains("report claims")
                    && msg.contains("mock tee attestation receipt malformed")
        ));
    }

    #[test]
    fn tee_verifier_selection_error_maps_to_unavailable_prefix() {
        let verifier = TeeVerifier::new(
            TeeBackendKind::Custom("missing-tee-backend".into()),
            Arc::new(TeeBackendRegistry::new()),
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
    fn tee_verifier_requires_cryptographic_backend_for_legacy_receipt_alias() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee_receipt,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("TEE attestation cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn tee_verifier_requires_cryptographic_backend_for_attestation_report_alias() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=attestation_report,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("TEE attestation cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn tee_verifier_requires_cryptographic_backend_for_ra_quote_alias() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=ra_quote,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Indeterminate(msg)
                if msg.contains("TEE attestation cryptographic verification backend not configured")
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
