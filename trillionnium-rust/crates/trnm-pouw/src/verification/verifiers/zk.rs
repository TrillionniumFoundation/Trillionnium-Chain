use std::sync::Arc;

use crate::verification::backend::{
    backend_token_family_hint, backend_token_zk_system_hints,
    contains_forbidden_opaque_token_chars, normalize_backend_token, normalize_zk_system,
    parse_zk_proof_payload, resolve_zk_vk_ref, BackendExecutionError, BackendVerificationRequest,
    VerificationBackendConfig, VerificationBackendError, VerificationBackendFamily, VkRefRegistry,
    ZkBackendKind, ZkBackendRegistry,
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

    fn validate_selected_backend_token(raw: &str) -> Result<(), VerificationBackendError> {
        if raw != raw.trim() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: backend '{}' must not contain surrounding whitespace",
                    raw
                ),
            }
            .into());
        }

        if raw.is_empty() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend must not be empty".to_string(),
            }
            .into());
        }

        if raw.eq_ignore_ascii_case("noop") {
            if raw != "noop" {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: legacy no-backend selector must use canonical lowercase token 'noop'".to_string(),
                }
                .into());
            }
        } else if normalize_backend_token(raw).is_none() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: backend '{}' must contain at least one canonical token segment",
                    raw
                ),
            }
            .into());
        }

        if contains_forbidden_opaque_token_chars(raw) {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: backend '{}' must be a single opaque token without embedded whitespace or control characters",
                    raw
                ),
            }
            .into());
        }

        match backend_token_family_hint(raw) {
            Some(VerificationBackendFamily::Tee) => {
                return Err(BackendExecutionError::InvalidProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: backend '{}' declares tee family and does not match zk router semantics",
                        raw
                    ),
                }
                .into())
            }
            Some(VerificationBackendFamily::Zk)
                if backend_token_zk_system_hints(raw).is_empty() =>
            {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: backend '{}' must not be a family-only zk router token without a canonical zk_system hint",
                        raw
                    ),
                }
                .into())
            }
            _ => {}
        }

        if backend_token_zk_system_hints(raw).len() > 1 {
            return Err(BackendExecutionError::InvalidProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: backend '{}' carries multiple zk_system hints and does not match fail-closed zk router semantics",
                    raw
                ),
            }
            .into());
        }

        Ok(())
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
            .map(|body| body.trim_start().starts_with('{'))
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

            if flags.zk_explicit_backend_required {
                let has_explicit_backend_selector = payload
                    .backend_id
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|backend_id| {
                        backend_id.eq_ignore_ascii_case("noop")
                            || normalize_backend_token(backend_id).is_some()
                    });

                if !has_explicit_backend_selector {
                    return Err(BackendExecutionError::MalformedProof {
                        backend: "zk:payload".to_string(),
                        reason: "invalid zk payload: backend_id is required when zk_explicit_backend_required is enabled".to_string(),
                    }
                    .into());
                }
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
            {
                if payload_backend_id.eq_ignore_ascii_case("noop") {
                    ZkBackendKind::Noop
                } else if normalize_backend_token(payload_backend_id).is_some() {
                    ZkBackendKind::Custom(payload_backend_id.to_string())
                } else {
                    Self::validate_selected_backend_token(self.backend.key())?;
                    self.backend.clone()
                }
            } else {
                Self::validate_selected_backend_token(self.backend.key())?;
                self.backend.clone()
            }
        } else {
            Self::validate_selected_backend_token(self.backend.key())?;
            self.backend.clone()
        };

        let resolved_vk_ref = if let Some(payload) = zk_payload.as_ref() {
            let resolved = resolve_zk_vk_ref(self.vk_refs.as_ref(), payload)?;

            let resolved_system = match resolved.zk_system.as_deref() {
                Some(raw_system) => {
                    let normalized = normalize_zk_system(raw_system).ok_or_else(|| {
                        BackendExecutionError::MalformedProof {
                            backend: "zk:payload".to_string(),
                            reason: format!(
                                "invalid zk payload: vk_ref '{}' is missing canonical zk_system metadata",
                                resolved.vk_ref
                            ),
                        }
                    })?;

                    if raw_system != normalized {
                        return Err(BackendExecutionError::MalformedProof {
                            backend: "zk:payload".to_string(),
                            reason: format!(
                                "invalid zk payload: vk_ref '{}' must use canonical zk_system metadata '{}'",
                                resolved.vk_ref, normalized
                            ),
                        }
                        .into());
                    }

                    normalized
                }
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
                match backend_token_family_hint(payload_backend_id) {
                    Some(VerificationBackendFamily::Tee) => {
                        return Err(BackendExecutionError::InvalidProof {
                            backend: "zk:payload".to_string(),
                            reason: format!(
                                "invalid zk payload: backend_id '{}' declares tee family and does not match zk vk_ref '{}'",
                                payload_backend_id, resolved.vk_ref
                            ),
                        }
                        .into());
                    }
                    Some(VerificationBackendFamily::Zk)
                        if backend_token_zk_system_hints(payload_backend_id).is_empty() =>
                    {
                        return Err(BackendExecutionError::MalformedProof {
                            backend: "zk:payload".to_string(),
                            reason: format!(
                                "invalid zk payload: backend_id '{}' must not be a family-only zk router token without a canonical zk_system hint",
                                payload_backend_id
                            ),
                        }
                        .into());
                    }
                    _ => {}
                }

                if let Some(payload_backend_system) = normalize_zk_system(payload_backend_id) {
                    if payload_backend_system != resolved_system {
                        return Err(BackendExecutionError::InvalidProof {
                            backend: "zk:payload".to_string(),
                            reason: format!(
                                "invalid zk payload: backend_id '{}' does not match vk_ref '{}'",
                                payload_backend_id, resolved.vk_ref
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
                    } else if flags.zk_explicit_backend_required
                        && !payload_backend_id.eq_ignore_ascii_case("noop")
                    {
                        return Err(BackendExecutionError::MalformedProof {
                            backend: "zk:payload".to_string(),
                            reason: format!(
                                "invalid zk payload: backend_id '{}' must carry a canonical zk_system hint when zk_explicit_backend_required is enabled",
                                payload_backend_id
                            ),
                        }
                        .into());
                    }
                } else if flags.zk_explicit_backend_required
                    && !payload_backend_id.eq_ignore_ascii_case("noop")
                {
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

            if let Some(VerificationBackendFamily::Tee) =
                backend_token_family_hint(selected_backend.key())
            {
                return Err(BackendExecutionError::InvalidProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: backend '{}' declares tee family and does not match zk vk_ref '{}'",
                        selected_backend.key(),
                        resolved.vk_ref
                    ),
                }
                .into());
            }

            let selected_backend_hints = backend_token_zk_system_hints(selected_backend.key());
            if matches!(
                backend_token_family_hint(selected_backend.key()),
                Some(VerificationBackendFamily::Zk)
            ) && selected_backend_hints.is_empty()
            {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: format!(
                        "invalid zk payload: backend '{}' must not be a family-only zk router token without a canonical zk_system hint",
                        selected_backend.key()
                    ),
                }
                .into());
            }
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
    fn zk_verifier_accepts_exact_configured_opaque_backend_when_payload_omits_backend_id() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

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
    fn zk_verifier_rejects_vk_ref_metadata_with_non_canonical_system_token_drift() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16-demo",
            expected_system: "groth16",
        }));
        let mut verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));

        let mut vk_refs = crate::verification::backend::VkRefRegistry::default();
        vk_refs.register(crate::verification::backend::ResolvedVkRef {
            vk_ref: "vk://trnm/dev/mock-groth16/noncanonical".into(),
            scope: "dev".into(),
            zk_system: Some(" Groth-16 ".into()),
        });
        verifier.vk_refs = Arc::new(vk_refs);

        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/noncanonical","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("must use canonical zk_system metadata 'groth16'")
                    && msg.contains("vk://trnm/dev/mock-groth16/noncanonical")
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
            VerificationResult::Invalid(msg) if msg.contains("backend_version requires backend_id")
        ));
    }

    #[test]
    fn zk_verifier_requires_non_noise_backend_when_feature_enabled() {
        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"---","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend_id '---'")
                    && msg.contains("visible canonical backend token segment")
        ));
    }

    #[test]
    fn zk_verifier_treats_noop_backend_id_with_backend_version_as_malformed_when_explicit_backend_is_required(
    ) {
        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"noop","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("backend_version must not be provided for legacy noop backend_id")
        ));
    }

    #[test]
    fn zk_verifier_treats_noop_backend_id_as_explicit_unavailable_selector_when_explicit_backend_is_required(
    ) {
        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"noop","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg)
                if msg.contains("unavailable:")
                    && msg.contains("cryptographic verification backend not configured")
        ));
    }

    #[test]
    fn zk_verifier_rejects_non_canonical_noop_backend_id_case() {
        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"NOOP","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("canonical lowercase token 'noop'")
        ));
    }

    #[test]
    fn zk_verifier_rejects_whitespace_wrapped_noop_backend_before_legacy_alias_canonicalization() {
        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":" noop ","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("must not contain surrounding whitespace")
                    && !msg.contains("canonical lowercase token 'noop'")
        ));
    }

    #[test]
    fn zk_verifier_explicit_noop_payload_backend_remains_authoritative_without_falling_back_to_configured_backend(
    ) {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16-demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("groth16-demo".into());
        config.zk_features.zk_allow_backend_fallback = true;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"noop","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Indeterminate(msg)
                if msg.contains("unavailable:")
                    && msg.contains("cryptographic verification backend not configured")
                    && !msg.contains("groth16-demo")
        ));
    }

    #[test]
    fn zk_verifier_treats_noop_backend_id_with_backend_version_as_malformed_for_backend_selection()
    {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("mock-zk".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"noop","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("backend_version must not be provided for legacy noop backend_id")
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
    fn zk_verifier_rejects_family_only_backend_id_when_explicit_backend_enabled() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        config.zk_backend = ZkBackendKind::Custom("zk-demo".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend_id 'zk-demo'")
                    && msg.contains("canonical zk_system hint")
        ));
    }

    #[test]
    fn zk_verifier_accepts_repeated_same_system_hints_with_explicit_backend_enabled() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "zk groth16 groth16 demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_features.zk_explicit_backend_required = true;
        config.zk_backend = ZkBackendKind::Custom("missing-backend".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"ZK-GROTH16-GROTH16-DEMO","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
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
    fn zk_verifier_rejects_payload_backend_with_explicit_zk_family_prefix_and_multiple_system_hints(
    ) {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "zk groth16 plonk demo",
            expected_system: "groth16",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-groth16-plonk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend_id 'zk-groth16-plonk-demo'")
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
    fn zk_verifier_rejects_payload_backend_with_explicit_tee_family_prefix() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "tee-groth16-demo",
            expected_system: "groth16",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"tee-groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend_id 'tee-groth16-demo'")
                    && msg.contains("declares tee family")
                    && msg.contains("does not match zk vk_ref")
        ));
    }

    #[test]
    fn zk_verifier_rejects_payload_backend_with_case_drifted_tee_family_prefix() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "tee-groth16-demo",
            expected_system: "groth16",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"TEE-GROTH16-DEMO","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend_id 'TEE-GROTH16-DEMO'")
                    && msg.contains("declares tee family")
                    && msg.contains("does not match zk vk_ref")
        ));
    }

    #[test]
    fn zk_verifier_rejects_payload_backend_that_is_exact_tee_family_token() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "tee",
            expected_system: "groth16",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"tee","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend_id 'tee'")
                    && msg.contains("declares tee family")
                    && msg.contains("does not match zk vk_ref")
        ));
    }

    #[test]
    fn zk_verifier_rejects_payload_backend_that_is_family_only_zk_router_token() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend_id 'zk-demo'")
                    && msg.contains("family-only zk router token")
        ));
    }

    #[test]
    fn zk_verifier_rejects_payload_backend_that_is_exact_family_only_zk_token() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend_id 'zk'")
                    && msg.contains("family-only zk router token")
        ));
    }

    #[test]
    fn zk_verifier_rejects_payload_backend_that_is_case_drifted_exact_family_only_zk_token() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"ZK","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend_id 'ZK'")
                    && msg.contains("family-only zk router token")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_with_explicit_tee_family_prefix() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "tee-groth16-demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("tee-groth16-demo".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend 'tee-groth16-demo'")
                    && msg.contains("declares tee family")
                    && msg.contains("zk router semantics")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_that_is_exact_tee_family_token() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "tee",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("tee".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend 'tee'")
                    && msg.contains("declares tee family")
                    && msg.contains("zk router semantics")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_that_is_case_drifted_exact_tee_family_token() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "tee",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("TEE".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend 'TEE'")
                    && msg.contains("declares tee family")
                    && msg.contains("zk router semantics")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_that_is_family_only_zk_router_token() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("zk-demo".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend 'zk-demo'")
                    && msg.contains("family-only zk router token")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_that_is_exact_family_only_zk_token() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("zk".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend 'zk'")
                    && msg.contains("family-only zk router token")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_that_is_case_drifted_exact_family_only_zk_token() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("ZK".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;
        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend 'ZK'")
                    && msg.contains("family-only zk router token")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_tee_family_backend_even_without_json_payload() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "tee-groth16-demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("tee-groth16-demo".into());
        config.zk_features.zk_payload_v0_envelope = false;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let legacy_payload = b"ZK:task_id=99;worker=worker-zk;result_hash=1111111111111111111111111111111111111111111111111111111111111111;proof_type=zk;receipt=legacy";

        assert!(matches!(
            verifier.verify_proof(&task, legacy_payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend 'tee-groth16-demo'")
                    && msg.contains("declares tee family")
                    && msg.contains("zk router semantics")
        ));
    }

    #[test]
    fn zk_verifier_rejects_family_only_selected_backend_even_without_json_payload() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("zk-demo".into());
        config.zk_features.zk_payload_v0_envelope = false;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let legacy_payload = b"ZK:task_id=99;worker=worker-zk;result_hash=1111111111111111111111111111111111111111111111111111111111111111;proof_type=zk;receipt=legacy";

        assert!(matches!(
            verifier.verify_proof(&task, legacy_payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend 'zk-demo'")
                    && msg.contains("family-only zk router token")
        ));
    }

    #[test]
    fn zk_verifier_rejects_case_drifted_family_only_selected_backend_even_without_json_payload() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSuccessBackend));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("ZK-DEMO".into());
        config.zk_features.zk_payload_v0_envelope = false;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let legacy_payload = b"ZK:task_id=99;worker=worker-zk;result_hash=1111111111111111111111111111111111111111111111111111111111111111;proof_type=zk;receipt=legacy";

        assert!(matches!(
            verifier.verify_proof(&task, legacy_payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend 'ZK-DEMO'")
                    && msg.contains("family-only zk router token")
        ));
    }

    #[test]
    fn zk_verifier_rejects_multi_hint_selected_backend_even_without_json_payload() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16 plonk demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("groth16-plonk-demo".into());
        config.zk_features.zk_payload_v0_envelope = false;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let legacy_payload = b"ZK:task_id=99;worker=worker-zk;result_hash=1111111111111111111111111111111111111111111111111111111111111111;proof_type=zk;receipt=legacy";

        assert!(matches!(
            verifier.verify_proof(&task, legacy_payload),
            VerificationResult::Invalid(msg)
                if msg.contains("backend 'groth16-plonk-demo'")
                    && msg.contains("multiple zk_system hints")
                    && msg.contains("fail-closed zk router semantics")
        ));
    }

    #[test]
    fn zk_verifier_accepts_selected_backend_with_explicit_zk_family_prefix() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "zk groth16 demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("zk-groth16-demo".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_payload_backend_with_explicit_zk_family_prefix() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "zk groth16 demo",
            expected_system: "groth16",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_payload_backend_with_explicit_zk_family_prefix_and_only_system_hint() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "zk groth16",
            expected_system: "groth16",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-groth16","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_explicit_opaque_payload_backend_without_family_or_system_hint() {
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
    fn zk_verifier_accepts_payload_backend_with_explicit_zk_family_prefix_and_repeated_same_system_hint(
    ) {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "zk groth16 groth16 demo",
            expected_system: "groth16",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"zk-groth16-groth16-demo","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_payload_backend_with_case_drifted_explicit_zk_family_prefix_and_repeated_same_system_hint(
    ) {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "zk groth16 groth16 demo",
            expected_system: "groth16",
        }));

        let verifier = ZkVerifier::from_config(&router_config(), Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"ZK-GROTH16-GROTH16-DEMO","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_selected_backend_with_explicit_zk_family_prefix_and_repeated_same_system_hint(
    ) {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "zk groth16 groth16 demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("zk-groth16-groth16-demo".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_selected_backend_with_case_drifted_explicit_zk_family_prefix_and_repeated_same_system_hint(
    ) {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "zk groth16 groth16 demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("ZK-GROTH16-GROTH16-DEMO".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_selected_backend_with_explicit_zk_family_prefix_and_repeated_same_system_hint_even_without_json_payload(
    ) {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockLegacySuccessBackend {
            backend_id: "zk groth16 groth16 demo",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("zk-groth16-groth16-demo".into());
        config.zk_features.zk_payload_v0_envelope = false;
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let legacy_payload = b"ZK:task_id=99;worker=worker-zk;result_hash=1111111111111111111111111111111111111111111111111111111111111111;proof_type=zk;receipt=legacy";

        assert_eq!(
            verifier.verify_proof(&task, legacy_payload),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_with_surrounding_whitespace_without_silent_trim() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16 demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("  groth16-demo  ".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend '  groth16-demo  '")
                    && msg.contains("surrounding whitespace")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_that_is_empty_after_config_selection() {
        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom(String::new());
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend must not be empty")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_with_non_canonical_noop_case() {
        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("NOOP".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("canonical lowercase token 'noop'")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_with_noise_only_token() {
        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("---".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend '---'")
                    && msg.contains("canonical token segment")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_with_embedded_control_whitespace() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16 demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("groth16-demo\nalt".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("backend 'groth16-demo")
                    && msg.contains("single opaque token")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_with_surrounding_unicode_whitespace() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16 demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("\u{2003}groth16-demo\u{2003}".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("groth16-demo")
                    && msg.contains("surrounding whitespace")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_with_embedded_unicode_whitespace() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16 demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("groth16-demo\u{2003}alt".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("single opaque token")
                    && msg.contains("embedded whitespace or control characters")
        ));
    }

    #[test]
    fn zk_verifier_rejects_selected_backend_with_embedded_zero_width_format_char() {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockSystemSuccessBackend {
            backend_id: "groth16 demo",
            expected_system: "groth16",
        }));

        let mut config = router_config();
        config.zk_backend = ZkBackendKind::Custom("groth16-demo\u{200b}alt".into());
        let verifier = ZkVerifier::from_config(&config, Arc::new(backends));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["99","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:")
                    && msg.contains("single opaque token")
                    && msg.contains("embedded whitespace or control characters")
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
    fn zk_verifier_treats_json_shaped_payload_without_vk_ref_as_malformed_contract_error() {
        let verifier =
            ZkVerifier::from_config(&router_config(), Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","proof_encoding":"hex","proof":"01020304"}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:") && msg.contains("canonical JSON object")
        ));
    }

    #[test]
    fn zk_verifier_treats_json_shaped_payload_without_public_inputs_as_malformed_contract_error() {
        let verifier =
            ZkVerifier::from_config(&router_config(), Arc::new(ZkBackendRegistry::new()));
        let task = mock_task();
        let payload = br#"ZK:{"task_id":99,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304"}"#;

        assert!(matches!(
            verifier.verify_proof(&task, payload),
            VerificationResult::Invalid(msg)
                if msg.contains("malformed:") && msg.contains("canonical JSON object")
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
