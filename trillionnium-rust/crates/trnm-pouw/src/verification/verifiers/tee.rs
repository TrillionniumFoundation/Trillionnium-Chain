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
                let legacy_suffix = match evidence_surface {
                    "evidence/claims" => {
                        Some("legacy: cannot currently verify TEE attestation evidence/claims")
                    }
                    "quote/report claims" => {
                        Some("legacy: cannot currently verify TEE attestation quote/report claims")
                    }
                    _ => None,
                };
                if let Some(legacy_suffix) = legacy_suffix {
                    VerificationResult::Indeterminate(format!("{message} ({legacy_suffix})"))
                } else {
                    VerificationResult::Indeterminate(message)
                }
            }
            BackendExecutionError::Internal { backend, reason } => {
                let message = format!(
                    "backend_error: verification backend '{backend}' failed while verifying TEE attestation {evidence_surface}: {reason}"
                );
                if evidence_surface == "quote/report claims" {
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
            // Invalid TEE attestations should collapse claim-oriented quote/report
            // sub-surfaces to the generic `claims` contract. Unlike availability
            // or internal backend errors, invalid proofs are caller-actionable
            // validation failures, so exposing quote-vs-report branching here
            // only encourages subtype-specific handling on a fail-closed path.
            "payload/claims"
            | "evidence/claims"
            | "quote claims"
            | "report claims"
            | "quote/report claims"
            | "claims" => "claims",
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

        let tokens = reason
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .filter(|token| !token.is_empty())
            .map(|token| token.to_ascii_lowercase())
            .collect::<Vec<_>>();

        let mentions = |predicate: fn(&str) -> bool| tokens.iter().any(|token| predicate(token));

        // Keep TEE attestation surface inference scoped to attestation-oriented
        // evidence labels first. ZK-style `payload` wording can appear in shared
        // backend plumbing, but for TEE we prefer quote/report/evidence/claims
        // surfaces unless the reason is explicitly payload-bound and lacks any
        // attestation context.
        let mentions_unavailable = mentions(|token| token == "unavailable");
        let mentions_quote = mentions(|token| token == "quote" || token == "quotes");
        let mentions_report = mentions(|token| token == "report" || token == "reports");
        let mentions_claims = mentions(|token| token == "claim" || token == "claims");
        let mentions_payload = mentions(|token| token == "payload");
        let mentions_evidence = mentions(|token| token == "evidence" || token == "evidences");
        let mentions_certificate =
            mentions(|token| matches!(token, "cert" | "certs" | "certificate" | "certificates"));
        let mentions_attestation =
            mentions(|token| token == "attestation" || token == "attestations");
        let mentions_receipt = mentions(|token| token == "receipt" || token == "receipts");

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
            return if mentions_attestation || mentions_receipt || mentions_certificate {
                "evidence/claims"
            } else {
                "claims"
            };
        }

        if mentions_payload {
            return if mentions_attestation || mentions_receipt || mentions_certificate {
                "evidence/claims"
            } else {
                "payload/claims"
            };
        }

        if mentions_evidence || mentions_attestation || mentions_receipt || mentions_certificate {
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
        BackendExecutionError, BackendVerificationSuccess, TeeBackend,
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
    impl TeeBackend for MockTeeSuccessBackend {
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
    impl TeeBackend for MockTeeInvalidBackend {
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
    impl TeeBackend for MockTeeUnavailableBackend {
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
    impl TeeBackend for MockTeeMalformedBackend {
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
    impl TeeBackend for MockTeeInternalBackend {
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
    fn tee_verifier_backend_internal_space_separated_quote_report_claims_still_maps_to_combined_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote report claims verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(
            msg.contains("failed while verifying TEE attestation quote/report claims:"),
            "message: {msg}"
        );
        assert!(
            msg.contains("legacy: failed while verifying TEE attestation quote/report claims"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_internal_hyphen_separated_quote_report_claims_still_maps_to_combined_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote-report claims verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(
            msg.contains("failed while verifying TEE attestation quote/report claims:"),
            "message: {msg}"
        );
        assert!(
            msg.contains("legacy: failed while verifying TEE attestation quote/report claims"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_internal_plus_separated_quote_report_claims_still_maps_to_combined_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote+report claims verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(
            msg.contains("failed while verifying TEE attestation quote/report claims:"),
            "message: {msg}"
        );
        assert!(
            msg.contains("legacy: failed while verifying TEE attestation quote/report claims"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report evidence"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_space_separated_quote_report_certificate_still_maps_to_combined_evidence_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote report certificate verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(
            msg.contains("cannot currently verify TEE attestation quote/report evidence:"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_quote_report_receipt_claims_keeps_combined_claims_surface_and_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote report receipt claims verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(
            msg.contains("cannot currently verify TEE attestation quote/report claims:"),
            "message: {msg}"
        );
        assert!(
            msg.contains("legacy: cannot currently verify TEE attestation quote/report claims"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report evidence"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_pluralized_quotes_reports_claims_still_map_to_combined_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quotes reports claims verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(
            msg.contains("failed while verifying TEE attestation quote/report claims:"),
            "message: {msg}"
        );
        assert!(
            msg.contains("legacy: failed while verifying TEE attestation quote/report claims"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report evidence"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_pluralized_quotes_reports_certificate_still_map_to_combined_evidence_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quotes reports certificate verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(
            msg.contains("cannot currently verify TEE attestation quote/report evidence:"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_pluralized_quotes_reports_certificates_still_map_to_combined_evidence_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quotes reports certificates verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(
            msg.contains("cannot currently verify TEE attestation quote/report evidence:"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
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
    fn tee_verifier_backend_internal_quote_report_certificate_prefers_combined_evidence_surface_without_claims_or_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote/report certificate verifier crashed".to_string(),
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
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
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
    fn tee_verifier_backend_internal_certified_payload_does_not_leak_into_certificate_evidence_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "TEE certified payload verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_pluralized_attestations_payload_still_prefers_evidence_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "TEE attestations payload verifier crashed".to_string(),
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
    fn tee_verifier_backend_unavailable_pluralized_receipts_payload_still_prefers_evidence_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "TEE receipts payload verifier unavailable".to_string(),
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
    fn tee_verifier_backend_invalid_quote_report_claims_collapse_to_generic_claims_surface() {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::InvalidProof {
            backend: "tee:mock-tee-invalid".to_string(),
            reason: "quote/report claims signature mismatch".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Invalid(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Invalid(msg) = result else {
            unreachable!()
        };
        assert!(
            msg.starts_with("invalid TEE attestation claims:"),
            "message: {msg}"
        );
        assert!(!msg.contains("invalid TEE attestation quote/report claims:"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(
            msg.contains("quote/report claims signature mismatch"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_invalid_quote_attestation_receipt_claims_collapse_to_generic_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::InvalidProof {
            backend: "tee:mock-tee-invalid".to_string(),
            reason: "quote attestation receipt claims signature mismatch".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Invalid(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Invalid(msg) = result else {
            unreachable!()
        };
        assert!(
            msg.starts_with("invalid TEE attestation claims:"),
            "message: {msg}"
        );
        assert!(!msg.contains("invalid TEE attestation quote claims:"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(
            msg.contains("quote attestation receipt claims signature mismatch"),
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
    fn tee_verifier_backend_internal_quote_attestation_payload_prefers_quote_claims_surface_without_evidence_or_zk_payload_leakage(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote attestation payload verifier crashed".to_string(),
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
    fn tee_verifier_backend_unavailable_quote_certificate_prefers_quote_evidence_surface_without_claims_or_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote certificate verifier unavailable".to_string(),
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
    fn tee_verifier_backend_unavailable_quote_report_certificate_prefers_combined_evidence_surface_without_claims_or_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote/report certificate verifier unavailable".to_string(),
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
    fn tee_verifier_backend_unavailable_hyphen_separated_quote_report_certificate_still_maps_to_combined_evidence_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote-report certificate verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(
            msg.contains("cannot currently verify TEE attestation quote/report evidence:"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_fullwidth_slash_quote_report_certificate_still_maps_to_combined_evidence_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote／report certificate verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(
            msg.contains("cannot currently verify TEE attestation quote/report evidence:"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_fullwidth_slash_quote_report_claims_still_maps_to_combined_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote／report claims verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(
            msg.contains("cannot currently verify TEE attestation quote/report claims:"),
            "message: {msg}"
        );
        assert!(
            msg.contains("legacy: cannot currently verify TEE attestation quote/report claims"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report evidence"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_fullwidth_slash_quote_report_certificate_still_maps_to_combined_evidence_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote／report certificate verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(
            msg.contains("failed while verifying TEE attestation quote/report evidence:"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_dot_colon_separated_quote_report_claims_still_maps_to_combined_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote.report:claims verifier unavailable".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("unavailable:"), "message: {msg}");
        assert!(
            msg.contains("cannot currently verify TEE attestation quote/report claims:"),
            "message: {msg}"
        );
        assert!(
            msg.contains("legacy: cannot currently verify TEE attestation quote/report claims"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report evidence"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_dot_colon_separated_quote_report_certificate_claims_still_prefer_combined_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote.report:certificate claims verifier crashed".to_string(),
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
        assert!(!msg.contains("quote/report evidence"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_quoted_reporting_terms_do_not_spoof_quote_or_report_surfaces()
    {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quoted reporting payload verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("quote evidence"), "message: {msg}");
        assert!(!msg.contains("report claims"), "message: {msg}");
        assert!(!msg.contains("report evidence"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_claimant_terms_do_not_spoof_claims_surface() {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote claimant verifier crashed".to_string(),
        });

        assert!(
            matches!(result, VerificationResult::Indeterminate(_)),
            "unexpected result: {result:?}"
        );
        let VerificationResult::Indeterminate(msg) = result else {
            unreachable!()
        };
        assert!(msg.contains("backend_error:"), "message: {msg}");
        assert!(msg.contains("quote evidence"), "message: {msg}");
        assert!(!msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_unavailable_quote_report_attestation_without_claims_or_payload_prefers_combined_evidence_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote/report attestation verifier unavailable".to_string(),
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
        assert!(
            msg.contains("legacy: cannot currently verify TEE attestation quote/report claims"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_internal_quote_report_attestation_payload_prefers_combined_claims_surface_without_zk_payload_leakage(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "quote/report attestation payload verifier crashed".to_string(),
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
        assert!(!msg.contains("quote/report evidence"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(
            msg.contains("legacy: failed while verifying TEE attestation quote/report claims"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_unavailable_quote_report_attestation_certificates_without_claims_or_payload_stays_on_combined_evidence_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote/report attestation certificates verifier unavailable".to_string(),
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
    fn tee_verifier_backend_unavailable_quote_report_certificate_claims_prefers_combined_claims_surface_with_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote/report certificate claims verifier unavailable".to_string(),
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
        assert!(
            msg.contains("legacy: cannot currently verify TEE attestation quote/report claims"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_unavailable_separator_heavy_quote_report_certificates_payload_still_prefers_combined_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "quote.report:certificates payload verifier unavailable".to_string(),
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
        assert!(
            msg.contains("legacy: cannot currently verify TEE attestation quote/report claims"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_internal_attestation_certificate_claims_prefers_evidence_claims_surface_without_zk_payload_leakage(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "TEE attestation certificate claims verifier crashed".to_string(),
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
        assert!(!msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("report claims"), "message: {msg}");
        assert!(!msg.contains("payload/claims"), "message: {msg}");
        assert!(!msg.contains("legacy:"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_internal_attestation_certificates_claims_still_prefers_evidence_claims_surface_without_quote_report_or_payload_leakage(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "TEE attestation certificates claims verifier crashed".to_string(),
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
        assert!(!msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("report claims"), "message: {msg}");
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
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
    fn tee_verifier_backend_internal_generic_receipt_claims_still_prefers_evidence_claims_surface()
    {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "receipt claims verifier crashed".to_string(),
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
    fn tee_verifier_backend_internal_certificate_payload_prefers_evidence_claims_surface() {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Internal {
            backend: "tee:mock-tee-internal".to_string(),
            reason: "TEE certificate payload verifier crashed".to_string(),
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
    fn tee_verifier_backend_unavailable_cert_claims_prefers_evidence_claims_surface_with_existing_legacy_suffix(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::Unavailable {
            backend: "tee:mock-tee-unavailable".to_string(),
            reason: "cert claims verifier unavailable".to_string(),
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
    fn tee_verifier_backend_invalid_certificate_claims_maps_to_claims_wording_without_payload_leakage(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::InvalidProof {
            backend: "tee:mock-tee-invalid".to_string(),
            reason: "certificate claims signature mismatch".to_string(),
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
            msg.contains("certificate claims signature mismatch"),
            "message: {msg}"
        );
    }

    #[test]
    fn tee_verifier_backend_malformed_generic_receipt_payload_still_collapses_to_payload_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::MalformedProof {
            backend: "tee:mock-tee-malformed".to_string(),
            reason: "receipt payload malformed".to_string(),
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
        assert!(msg.contains("receipt payload malformed"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("report claims"), "message: {msg}");
    }

    #[test]
    fn tee_verifier_backend_malformed_certificate_claims_still_collapses_to_payload_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::MalformedProof {
            backend: "tee:mock-tee-malformed".to_string(),
            reason: "certificate claims malformed".to_string(),
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
        assert!(msg.contains("certificate claims malformed"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
        assert!(!msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("report claims"), "message: {msg}");
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
    fn tee_verifier_backend_malformed_quote_certificate_collapses_to_payload_claims_surface() {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::MalformedProof {
            backend: "tee:mock-tee-malformed".to_string(),
            reason: "quote certificate malformed".to_string(),
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
            msg.contains("quote certificate malformed"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote evidence"), "message: {msg}");
        assert!(!msg.contains("quote claims"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
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
    fn tee_verifier_backend_malformed_separator_heavy_quote_report_certificate_collapses_to_payload_claims_surface(
    ) {
        let result = TeeVerifier::classify_execution_err(BackendExecutionError::MalformedProof {
            backend: "tee:mock-tee-malformed".to_string(),
            reason: "quote／report:certificate attestation malformed".to_string(),
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
            msg.contains("quote／report:certificate attestation malformed"),
            "message: {msg}"
        );
        assert!(!msg.contains("quote/report evidence"), "message: {msg}");
        assert!(!msg.contains("quote/report claims"), "message: {msg}");
        assert!(!msg.contains("evidence/claims"), "message: {msg}");
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
    fn tee_verifier_requires_cryptographic_backend_for_tee_remote_attestation_quote_alias() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee_remote_attestation_quote,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
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

    #[test]
    fn tee_verifier_rejects_fullwidth_colon_then_ascii_task_id_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "TEE:task_id：42,task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_fullwidth_colon_then_ascii_proof_type_binding_fail_closed() {
        let verifier = TeeVerifier::default();
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "TEE:task_id=42,worker=worker1,proof_type：tee,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }
}
