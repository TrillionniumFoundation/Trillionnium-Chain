//! Product boundary for the optional TEE verifier feature.
//!
//! The repository does not currently ship a commissioned Intel DCAP/QGS or
//! AMD SNP verifier service. Enabling `real-tee-backend` must therefore expose
//! the selector while remaining fail-closed. TEE payload parsing, target
//! normalization, evidence-shape checks and resource bounds live in
//! `verification::backend`; this module only binds that parsed evidence to the
//! task result before reporting the missing commissioned verifier.
//!
//! Historical fixture HTTP/session/planner stacks were private test scaffolding
//! with no product caller. They are intentionally not part of this feature
//! boundary. A future real verifier must arrive as an explicit product adapter
//! with authenticated endpoint/collateral policy and qualification, rather than
//! silently reviving fixture-backed verification here.

use std::sync::Arc;

use crate::verification::backend::{
    parse_tee_attestation_payload, BackendExecutionError, BackendVerificationRequest,
    BackendVerificationSuccess, VerificationBackend, VerificationBackendFamily, ZkBackendRegistry,
};

/// Optional TEE backend selector.
///
/// Until a commissioned vendor verifier exists, every well-formed request is
/// rejected as `NotConfigured` after the task/result binding is checked.
pub struct RealTeeBackend;

impl Default for RealTeeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl RealTeeBackend {
    pub const fn new() -> Self {
        Self
    }

    const fn backend_id_static() -> &'static str {
        "real-tee-backend"
    }
}

impl VerificationBackend for RealTeeBackend {
    fn backend_id(&self) -> &str {
        Self::backend_id_static()
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        if request.family != VerificationBackendFamily::Tee {
            return Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: "real tee backend only supports tee verification family".to_string(),
            });
        }

        let parsed = match request.tee_payload {
            Some(payload) => payload.clone(),
            None => parse_tee_attestation_payload(request.proof_data)?,
        };
        let expected_hash = request.task.result_hash.map(hex::encode).ok_or_else(|| {
            BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: "missing task result_hash binding context".to_string(),
            }
        })?;

        if parsed.report_data_hash != expected_hash {
            return Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: format!(
                    "attestation report_data_hash '{}' does not match task result hash",
                    parsed.report_data_hash
                ),
            });
        }

        Err(BackendExecutionError::NotConfigured {
            backend: request.backend_label(self.backend_id()),
        })
    }
}

/// Register the selector without granting verification authority.
pub fn register_optional_backends(registry: &mut ZkBackendRegistry) {
    registry.register(Arc::new(RealTeeBackend::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::backend::{
        ParsedTeeProofPayload, TeeEvidenceKind, TeeVerifierMetadata, VerificationBackendKind,
    };
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn task(result_hash: Option<[u8; 32]>) -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash,
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

    fn parsed(hash: &str) -> ParsedTeeProofPayload {
        ParsedTeeProofPayload {
            attestation_target: "sgx-dcap".into(),
            verifier_kind: "quote-verifier".into(),
            measurement_field: "mrenclave".into(),
            measurement: "mrenclave:fixture".into(),
            report_data_hash: hash.into(),
            evidence_kind: TeeEvidenceKind::Quote,
            quote: Some("opaque-quote".into()),
            report: None,
            verifier_metadata: TeeVerifierMetadata {
                collateral: Some("opaque-collateral".into()),
                cert_chain: Some("opaque-chain".into()),
                issuer: Some("issuer".into()),
                vcek: None,
                report_signer: None,
            },
        }
    }

    #[test]
    fn product_default_is_not_fixture_backed() {
        let task = task(Some([0x11; 32]));
        let payload = parsed(&"11".repeat(32));
        let result = RealTeeBackend::new().verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data: b"unused-when-preparsed",
            tee_payload: Some(&payload),
            zk_payload: None,
            resolved_vk_ref: None,
        });
        assert!(matches!(
            result,
            Err(BackendExecutionError::NotConfigured { backend })
                if backend.contains("real-tee-backend")
        ));
    }

    #[test]
    fn result_hash_mismatch_rejects_before_unconfigured_backend() {
        let task = task(Some([0x11; 32]));
        let payload = parsed(&"22".repeat(32));
        let result = RealTeeBackend::new().verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data: b"unused-when-preparsed",
            tee_payload: Some(&payload),
            zk_payload: None,
            resolved_vk_ref: None,
        });
        assert!(matches!(
            result,
            Err(BackendExecutionError::InvalidProof { reason, .. })
                if reason.contains("does not match task result hash")
        ));
    }

    #[test]
    fn missing_task_hash_rejects_before_unconfigured_backend() {
        let task = task(None);
        let payload = parsed(&"11".repeat(32));
        let result = RealTeeBackend::new().verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data: b"unused-when-preparsed",
            tee_payload: Some(&payload),
            zk_payload: None,
            resolved_vk_ref: None,
        });
        assert!(matches!(
            result,
            Err(BackendExecutionError::InvalidProof { reason, .. })
                if reason.contains("missing task result_hash")
        ));
    }

    #[test]
    fn non_tee_family_rejects_before_any_backend_use() {
        let task = task(Some([0x11; 32]));
        let result = RealTeeBackend::new().verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Zk,
            task: &task,
            proof_data: b"not-a-tee-payload",
            tee_payload: None,
            zk_payload: None,
            resolved_vk_ref: None,
        });
        assert!(matches!(
            result,
            Err(BackendExecutionError::InvalidProof { reason, .. })
                if reason.contains("only supports tee")
        ));
    }

    #[test]
    fn registry_exposes_selector_without_granting_authority() {
        let mut registry = ZkBackendRegistry::new();
        register_optional_backends(&mut registry);
        let backend = registry
            .resolve(
                VerificationBackendFamily::Tee,
                &VerificationBackendKind::Custom("real-tee-backend".into()),
            )
            .expect("selector must be registered");
        let task = task(Some([0x11; 32]));
        let payload = parsed(&"11".repeat(32));
        assert!(matches!(
            backend.verify(BackendVerificationRequest {
                family: VerificationBackendFamily::Tee,
                task: &task,
                proof_data: b"unused-when-preparsed",
                tee_payload: Some(&payload),
                zk_payload: None,
                resolved_vk_ref: None,
            }),
            Err(BackendExecutionError::NotConfigured { .. })
        ));
    }
}
