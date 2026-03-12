use std::sync::Arc;

use crate::verification::backend::{
    backend_token_zk_system_hints, normalize_backend_token, normalize_zk_system,
    parse_zk_proof_payload, resolve_zk_vk_ref, BackendExecutionError,
    BackendVerificationRequest, VerificationBackendConfig, VerificationBackendError,
    VerificationBackendFamily, VkRefRegistry, ZkBackendKind, ZkBackendRegistry,
};
use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::verify_bound_envelope;

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

    fn has_json_envelope(proof_data: &[u8]) -> bool {
        proof_data
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
                    "unavailable: ZK proof cryptographic verification backend not configured"
                        .to_string(),
                )
            }
            VerificationBackendError::Execution(BackendExecutionError::Unavailable {
                backend,
                reason,
            }) => VerificationResult::Indeterminate(format!(
                "unavailable: verification backend '{backend}' cannot currently verify proof: {reason}"
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
        let flags = &self.config.zk_features;
        let has_json_envelope = Self::has_json_envelope(proof_data);

        if flags.zk_payload_v0_envelope && !has_json_envelope {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: canonical JSON object is required when zk_payload_v0_envelope is enabled".to_string(),
            }
            .into());
        }

        let zk_payload = if has_json_envelope {
            let payload = parse_zk_proof_payload(task, proof_data)?;

            if flags.zk_payload_v0_envelope && payload.schema_version != "trnm.zk.payload.v0" {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: schema_version must be trnm.zk.payload.v0"
                        .to_string(),
                }
                .into());
            }

            if flags.zk_explicit_backend_required
                && payload
                    .backend_id
                    .as_deref()
                    .and_then(normalize_backend_token)
                    .is_none()
            {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: backend_id is required when zk_explicit_backend_required is enabled".to_string(),
                }
                .into());
            }

            Some(payload)
        } else {
            None
        };

        // v0 stays fail-closed here: even if zk_allow_backend_fallback exists as a
        // frozen config/doc knob, the router must not silently fall back when a
        // payload selects an explicit backend. Unknown/disabled backends remain an
        // unavailable route, not a cue to guess another verifier.
        let selected_backend = if flags.zk_platform_v0 && flags.zk_backend_router {
            if let Some(payload_backend_id) = zk_payload
                .as_ref()
                .and_then(|payload| payload.backend_id.as_deref())
                .map(str::trim)
                .filter(|raw| !raw.is_empty())
            {
                ZkBackendKind::Custom(payload_backend_id.to_string())
            } else {
                self.backend.clone()
            }
        } else {
            self.backend.clone()
        };

        let resolved_vk_ref = if let Some(payload) = zk_payload.as_ref() {
            let resolved = resolve_zk_vk_ref(self.vk_refs.as_ref(), payload)?;

            let resolved_system = match resolved.zk_system.as_deref().and_then(normalize_zk_system)
            {
                Some(system) => system,
                None => {
                    return Err(BackendExecutionError::MalformedProof {
                        backend: "zk:payload".to_string(),
                        reason: format!(
                            "invalid zk payload: vk_ref '{}' is missing canonical zk_system metadata",
                            resolved.vk_ref
                        ),
                    }
                    .into())
                }
            };

            if let Some(payload_system) = payload.zk_system.as_deref().and_then(normalize_zk_system)
            {
                if payload_system != resolved_system {
                    return Err(BackendExecutionError::InvalidProof {
                        backend: "zk:payload".to_string(),
                        reason: format!(
                            "invalid zk payload: zk_system '{payload_system}' does not match vk_ref '{}'",
                            resolved.vk_ref
                        ),
                    }
                    .into());
                }
            }

            if let Some(payload_backend_id) = payload
                .backend_id
                .as_deref()
                .map(str::trim)
                .filter(|backend| !backend.is_empty())
            {
                if let Some(payload_backend_system) = normalize_zk_system(payload_backend_id) {
                    if payload_backend_system != resolved_system {
                        return Err(BackendExecutionError::InvalidProof {
                            backend: "zk:payload".to_string(),
                            reason: format!(
                                "invalid zk payload: backend_id '{}' does not match vk_ref '{}'",
                                payload_backend_id,
                                resolved.vk_ref
                            ),
                        }
                        .into());
                    }
                } else if normalize_backend_token(payload_backend_id).is_some() {
                    let hinted_systems = backend_token_zk_system_hints(payload_backend_id);

                    if hinted_systems.len() > 1 {
                        return Err(BackendExecutionError::InvalidProof {
                            backend: "zk:payload".to_string(),
                            reason: format!(
                                "invalid zk payload: backend_id '{}' carries multiple zk_system hints and does not match vk_ref '{}'",
                                payload_backend_id,
                                resolved.vk_ref
                            ),
                        }
                        .into());
                    }

                    if let Some(payload_backend_system) = hinted_systems.into_iter().next() {
                        if payload_backend_system != resolved_system {
                            return Err(BackendExecutionError::InvalidProof {
                                backend: "zk:payload".to_string(),
                                reason: format!(
                                    "invalid zk payload: backend_id '{}' does not match vk_ref '{}'",
                                    payload_backend_id,
                                    resolved.vk_ref
                                ),
                            }
                            .into());
                        }
                    } else if flags.zk_explicit_backend_required {
                        return Err(BackendExecutionError::MalformedProof {
                            backend: "zk:payload".to_string(),
                            reason: format!(
                                "invalid zk payload: backend_id '{}' must carry a canonical zk_system hint when zk_explicit_backend_required is enabled",
                                payload_backend_id
                            ),
                        }
                        .into());
                    }
                } else if flags.zk_explicit_backend_required {
                    return Err(BackendExecutionError::MalformedProof {
                        backend: "zk:payload".to_string(),
                        reason: format!(
                            "invalid zk payload: backend_id '{}' must carry a canonical zk_system hint when zk_explicit_backend_required is enabled",
                            payload_backend_id
                        ),
                    }
                    .into());
                }
            }

            let selected_backend_hints = backend_token_zk_system_hints(selected_backend.key());
            if selected_backend_hints.len() > 1 {
                return Err(BackendExecutionError::InvalidProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: backend '{}' carries multiple zk_system hints and does not match vk_ref '{}'",
                        selected_backend.key(),
                        resolved.vk_ref
                    ),
                }
                .into());
            }

            if let Some(selected_backend_system) = selected_backend_hints.into_iter().next() {
                if selected_backend_system != resolved_system {
                    return Err(BackendExecutionError::InvalidProof {
                        backend: "zk:payload".to_string(),
                        reason: format!(
                            "invalid zk payload: backend '{}' does not match vk_ref '{}'",
                            selected_backend.key(),
                            resolved.vk_ref
                        ),
                    }
                    .into());
                }
            }

            Some(resolved)
        } else {
            None
        };

        let backend = self
            .backends
            .resolve(VerificationBackendFamily::Zk, &selected_backend)?;
        backend.verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Zk,
            task,
            proof_data,
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

    #[test]
    fn zk_verifier_valid_proof_path_with_mock_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_second_system_mock_plonk_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "plonk-demo",
            expected_system: "plonk",
        }));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"plonk","backend_id":"plonk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_rejects_second_system_vk_ref_mismatch_fail_closed() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "plonk-demo",
            expected_system: "plonk",
        }));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"plonk","backend_id":"plonk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("zk_system 'plonk'") && msg.contains("does not match vk_ref")
        ));
    }

    #[test]
    fn zk_verifier_rejects_backend_router_system_mismatch_with_vk_ref_fail_closed() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16-demo",
            expected_system: "groth16",
        }));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("zk_system 'groth16'") && msg.contains("does not match vk_ref")
        ));
    }

    #[test]
    fn zk_verifier_rejects_missing_zk_system_before_backend_router_mismatch_checks() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16-demo",
            expected_system: "groth16",
        }));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","backend_id":"groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:") && msg.contains("zk_system is required")
        ));
    }

    #[test]
    fn zk_verifier_rejects_vk_ref_without_canonical_system_metadata_when_payload_declares_system() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-no-system/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("missing canonical zk_system metadata")
                    && msg.contains("vk://trnm/dev/mock-no-system/v1")
        ));
    }

    #[test]
    fn zk_verifier_rejects_backend_system_hint_when_vk_ref_lacks_canonical_system_metadata() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16-demo",
            expected_system: "groth16",
        }));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-no-system/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("missing canonical zk_system metadata")
                    && msg.contains("vk://trnm/dev/mock-no-system/v1")
        ));
    }

    #[test]
    fn zk_verifier_invalid_proof_path_with_mock_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockInvalidBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-invalid","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("mock zk backend rejected proof")
        ));
    }

    #[test]
    fn zk_verifier_unavailable_backend_maps_to_indeterminate() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockUnavailableBackend));
        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("mock-zk-unavailable".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk-unavailable","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg)
                if msg.contains("unavailable:") && msg.contains("mock zk backend unavailable")
        ));
    }

    #[test]
    fn zk_verifier_requires_explicit_backend_when_feature_enabled() {
        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("backend_id is required")
        ));
    }

    #[test]
    fn zk_verifier_requires_non_noise_backend_when_feature_enabled() {
        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":" --- ","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("backend_id is required")
        ));
    }

    #[test]
    fn zk_verifier_treats_noop_backend_id_as_missing_when_explicit_backend_is_required() {
        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":" noop ","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("backend_id is required")
        ));
    }

    #[test]
    fn zk_verifier_requires_canonical_backend_system_hint_when_explicit_backend_enabled() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend_id 'mock-zk'")
                    && msg.contains("canonical zk_system hint")
        ));
    }

    #[test]
    fn zk_verifier_accepts_backend_id_prefix_system_hint_when_it_matches_vk_ref() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16-demo",
            expected_system: "groth16",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_rejects_backend_id_with_matching_prefix_but_mismatched_system_suffix() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16 plonk demo",
            expected_system: "groth16",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-plonk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend_id 'groth16-plonk-demo'")
                    && msg.contains("multiple zk_system hints")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_with_multiple_system_hints() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16 plonk demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("groth16-plonk-demo".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend 'groth16-plonk-demo'")
                    && msg.contains("multiple zk_system hints")
        ));
    }

    #[test]
    fn zk_verifier_rejects_backend_id_prefix_system_hint_when_it_mismatches_vk_ref() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "plonk-demo",
            expected_system: "plonk",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"plonk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend_id 'plonk-demo'") && msg.contains("does not match vk_ref")
        ));
    }

    #[test]
    fn zk_verifier_does_not_silently_fallback_when_payload_backend_is_unknown() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"missing-backend","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg)
                if msg.contains("verification backend 'missing-backend' is not registered")
        ));
    }

    #[test]
    fn zk_verifier_unknown_payload_backend_does_not_fallback_to_configured_default_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
        config.zk_features.zk_allow_backend_fallback = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"missing-backend","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg)
                if msg.contains("verification backend 'missing-backend' is not registered")
                    && !msg.contains("mock-zk")
        ));
    }

    #[test]
    fn zk_verifier_accepts_repeated_same_system_hints_in_backend_id() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16-groth16-demo",
            expected_system: "groth16",
        }));
        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_allow_backend_fallback_flag_does_not_override_explicit_payload_backend() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));
        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
        config.zk_features.zk_allow_backend_fallback = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"missing-backend","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg)
                if msg.contains("verification backend 'missing-backend' is not registered")
                    && !msg.contains("mock-zk")
        ));
    }
}
