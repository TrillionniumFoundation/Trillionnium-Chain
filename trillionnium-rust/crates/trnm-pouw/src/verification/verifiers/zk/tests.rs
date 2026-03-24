
use super::*;
use crate::verification::backend::{
    BackendExecutionError, BackendVerificationSuccess, VerificationBackendConfig, ZkBackend,
};
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
        result_hash: Some([0x11u8; 32]),
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

fn router_config() -> VerificationBackendConfig {
    let mut config = VerificationBackendConfig::default();
    config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
    config.zk_features.zk_platform_v0 = true;
    config.zk_features.zk_backend_router = true;
    config.zk_features.zk_payload_v0_envelope = true;
    config
}

struct MockSuccessBackend;
impl ZkBackend for MockSuccessBackend {
    fn backend_id(&self) -> &str {
        "mock-zk"
    }
    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        let payload = request.zk_payload.expect("zk payload required");
        let resolved_vk_ref = request
            .resolved_vk_ref
            .expect("resolved vk_ref metadata required");
        assert_eq!(request.family, VerificationBackendFamily::Zk);
        assert_eq!(
            payload.public_inputs.order,
            vec!["task_id", "proof_type", "worker", "result_hash"]
        );
        assert_eq!(payload.public_inputs.values[0], "99");
        assert_eq!(payload.worker, "worker-zk");
        assert_eq!(payload.vk_ref, "vk://trnm/dev/mock-groth16/v1");
        assert_eq!(resolved_vk_ref.zk_system.as_deref(), Some("groth16"));
        Ok(BackendVerificationSuccess {
            backend_id: self.backend_id().into(),
        })
    }
}

struct MockSystemSuccessBackend {
    backend_id: &'static str,
    expected_system: &'static str,
}

impl ZkBackend for MockSystemSuccessBackend {
    fn backend_id(&self) -> &str {
        self.backend_id
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        let payload = request.zk_payload.expect("zk payload required");
        let resolved_vk_ref = request
            .resolved_vk_ref
            .expect("resolved vk_ref metadata required");
        assert_eq!(request.family, VerificationBackendFamily::Zk);
        assert_eq!(payload.zk_system.as_deref(), Some(self.expected_system));
        assert_eq!(
            resolved_vk_ref.zk_system.as_deref(),
            Some(self.expected_system)
        );
        Ok(BackendVerificationSuccess {
            backend_id: self.backend_id().into(),
        })
    }
}

struct MockInvalidBackend;
impl ZkBackend for MockInvalidBackend {
    fn backend_id(&self) -> &str {
        "mock-zk-invalid"
    }
    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        assert_eq!(request.family, VerificationBackendFamily::Zk);
        Err(BackendExecutionError::InvalidProof {
            backend: request.backend_label(self.backend_id()),
            reason: "mock zk backend rejected proof".to_string(),
        })
    }
}

struct MockLegacySuccessBackend {
    backend_id: &'static str,
}

impl ZkBackend for MockLegacySuccessBackend {
    fn backend_id(&self) -> &str {
        self.backend_id
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        assert_eq!(request.family, VerificationBackendFamily::Zk);
        assert!(request.zk_payload.is_none());
        assert!(request.resolved_vk_ref.is_none());
        Ok(BackendVerificationSuccess {
            backend_id: self.backend_id.into(),
        })
    }
}

struct MockUnavailableBackend;
impl ZkBackend for MockUnavailableBackend {
    fn backend_id(&self) -> &str {
        "mock-zk-unavailable"
    }
    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        assert_eq!(request.family, VerificationBackendFamily::Zk);
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(self.backend_id()),
            reason: "mock zk backend unavailable".to_string(),
        })
    }
}

#[path = "tests/payload_structure.rs"]
mod payload_structure;
#[path = "tests/vk_resolution.rs"]
mod vk_resolution;
#[path = "tests/backend_failures.rs"]
mod backend_failures;
#[path = "tests/explicit_backend.rs"]
mod explicit_backend;
#[path = "tests/backend_id_hints.rs"]
mod backend_id_hints;
