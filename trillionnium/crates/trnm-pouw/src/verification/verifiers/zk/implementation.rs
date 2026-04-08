use std::sync::Arc;

use crate::verification::backend::{
    BackendVerificationRequest, VerificationBackendConfig, VerificationBackendError,
    VerificationBackendFamily, VkRefRegistry, ZkBackendKind, ZkBackendRegistry,
};
use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::super::verify_bound_envelope;
use super::{backend_selection, helpers, payload, vk_resolution};

pub struct ZkVerifier {
    backend: ZkBackendKind,
    backends: Arc<ZkBackendRegistry>,
    vk_refs: Arc<VkRefRegistry>,
    config: VerificationBackendConfig,
}

impl ZkVerifier {
    pub fn new(backend: ZkBackendKind, backends: Arc<ZkBackendRegistry>) -> Self {
        Self {
            backend: backend.clone(),
            backends,
            vk_refs: Arc::new(VkRefRegistry::new()),
            config: VerificationBackendConfig {
                zk_backend: backend,
                ..VerificationBackendConfig::default()
            },
        }
    }

    #[allow(dead_code)]
    pub fn from_config(
        config: &VerificationBackendConfig,
        backends: Arc<ZkBackendRegistry>,
    ) -> Self {
        Self {
            backend: config.zk_backend.clone(),
            backends,
            vk_refs: Arc::new(VkRefRegistry::new()),
            config: config.clone(),
        }
    }

    fn verify_backend(
        &self,
        task: &TaskObject,
        proof_data: &[u8],
    ) -> Result<(), VerificationBackendError> {
        let zk_payload = payload::parse_payload(&self.config, task, proof_data)?;
        let selected_backend =
            backend_selection::select_backend(&self.config, &self.backend, zk_payload.as_ref())?;
        let resolved_vk_ref = vk_resolution::resolve_vk_ref_for_backend(
            &self.config,
            self.vk_refs.as_ref(),
            &selected_backend,
            zk_payload.as_ref(),
        )?;

        let backend = self
            .backends
            .resolve(VerificationBackendFamily::Zk, &selected_backend)?;
        backend.verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Zk,
            task,
            proof_data,
            tee_payload: None,
            zk_payload: zk_payload.as_ref(),
            resolved_vk_ref: resolved_vk_ref.as_ref(),
        })?;
        Ok(())
    }
}

impl Default for ZkVerifier {
    fn default() -> Self {
        Self::from_config(
            &VerificationBackendConfig::default(),
            Arc::new(ZkBackendRegistry::new()),
        )
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
                Err(err) => helpers::classify_backend_err(err),
            },
            other => other,
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
