use std::sync::Arc;

use super::super::TeeVerifier;
use crate::verification::backend::{
    BackendExecutionError, BackendVerificationRequest, BackendVerificationSuccess, ZkBackend,
    ZkBackendKind, ZkBackendRegistry,
};
use trnm_types::{ProofType, TaskObject, TaskStatus};

pub(super) fn mock_task() -> TaskObject {
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

pub(super) fn mock_attested_receipt() -> &'static [u8] {
    b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel"
}

pub(super) struct MockTeeSuccessBackend;
impl ZkBackend for MockTeeSuccessBackend {
    fn backend_id(&self) -> &str {
        "mock-tee"
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        assert_eq!(request.family, crate::verification::backend::VerificationBackendFamily::Tee);
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
        assert_eq!(tee_payload.verifier_metadata.issuer.as_deref(), Some("intel"));
        assert!(request.zk_payload.is_none());
        Ok(BackendVerificationSuccess {
            backend_id: self.backend_id().into(),
        })
    }
}

pub(super) struct MockTeeInvalidBackend;
impl ZkBackend for MockTeeInvalidBackend {
    fn backend_id(&self) -> &str {
        "mock-tee-invalid"
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        assert_eq!(request.family, crate::verification::backend::VerificationBackendFamily::Tee);
        Err(BackendExecutionError::InvalidProof {
            backend: request.backend_label(self.backend_id()),
            reason: "mock tee backend rejected proof".to_string(),
        })
    }
}

pub(super) struct MockTeeUnavailableBackend;
impl ZkBackend for MockTeeUnavailableBackend {
    fn backend_id(&self) -> &str {
        "mock-tee-unavailable"
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        assert_eq!(request.family, crate::verification::backend::VerificationBackendFamily::Tee);
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(self.backend_id()),
            reason: "mock tee backend unavailable".to_string(),
        })
    }
}

pub(super) struct MockTeeMalformedBackend;
impl ZkBackend for MockTeeMalformedBackend {
    fn backend_id(&self) -> &str {
        "mock-tee-malformed"
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        assert_eq!(request.family, crate::verification::backend::VerificationBackendFamily::Tee);
        Err(BackendExecutionError::MalformedProof {
            backend: request.backend_label(self.backend_id()),
            reason: "mock tee receipt malformed".to_string(),
        })
    }
}

pub(super) struct MockTeeInternalBackend;
impl ZkBackend for MockTeeInternalBackend {
    fn backend_id(&self) -> &str {
        "mock-tee-internal"
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        assert_eq!(request.family, crate::verification::backend::VerificationBackendFamily::Tee);
        Err(BackendExecutionError::Internal {
            backend: request.backend_label(self.backend_id()),
            reason: "mock tee backend internal failure".to_string(),
        })
    }
}

pub(super) fn verifier_with_backend<B: ZkBackend + 'static>(
    backend_kind: ZkBackendKind,
    backend: B,
) -> TeeVerifier {
    let mut backends = ZkBackendRegistry::new();
    backends.register(Arc::new(backend));
    TeeVerifier::new(backend_kind, Arc::new(backends))
}
