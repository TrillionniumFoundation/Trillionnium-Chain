use std::collections::HashMap;
use std::sync::Arc;

use trnm_types::TaskObject;

#[cfg(feature = "real-zk-backend")]
use super::real_zk_backend;
use super::{
    backend::{VerificationBackendConfig, ZkBackendRegistry},
    proof_type_key, verifiers, ProofVerifier, VerificationResult,
};

pub struct VerifierRegistry {
    verifiers: HashMap<String, Arc<dyn ProofVerifier + Send + Sync>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    /// Initializes a registry with the built-in verification platform stack.
    ///
    /// Routing contract:
    /// - Fraud is a backendless semantic verifier (fail-closed envelope/binding checks only).
    /// - TEE and ZK are semantic verifiers plus configurable backend families.
    /// - Backend selection is family-scoped (`tee` vs `zk`) so config hooks and
    ///   error surfaces stay aligned even when different proof systems share the
    ///   same platform registry implementation.
    pub fn with_builtin_verifiers() -> Self {
        Self::with_backend_config(VerificationBackendConfig::default())
    }

    pub fn with_backend_config(config: VerificationBackendConfig) -> Self {
        let backend_registry = Arc::new(ZkBackendRegistry::new());
        Self::with_backends(config, backend_registry)
    }

    pub fn with_backends(
        config: VerificationBackendConfig,
        backends: Arc<ZkBackendRegistry>,
    ) -> Self {
        let mut registry = Self::new();

        // Fraud is intentionally kept as the platform's built-in semantic verifier.
        // Only TEE/ZK consume configurable backend families today.
        registry.register(Arc::new(verifiers::FraudVerifier));
        registry.register(Arc::new(verifiers::TeeVerifier::from_config(
            &config,
            Arc::clone(&backends),
        )));
        registry.register(Arc::new(verifiers::ZkVerifier::from_config(
            &config, backends,
        )));
        registry
    }

    fn normalize_key(raw: &str) -> Option<String> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return None;
        }

        let delimiter_normalized = normalized
            .chars()
            .map(|ch| {
                if ch == '_'
                    || ch == '＿'
                    || ch == '-'
                    || ch == '－'
                    || ch == '–'
                    || ch == '—'
                    || ch == '―'
                    || ch == '‒'
                    || ch == '−'
                    || ch == '‐'
                    || ch == '‑'
                    || ch == '﹣'
                    || ch == '﹘'
                    || ch == '\u{00a0}'
                    || ch == '\u{00ad}'
                    || ch == '\u{3000}'
                    || ch == '\u{200b}'
                    || ch == '\u{200c}'
                    || ch == '\u{200d}'
                    || ch == '\u{2060}'
                    || ch == '\u{2061}'
                    || ch == '\u{2062}'
                    || ch == '\u{2063}'
                    || ch == '\u{180e}'
                    || ch == '\u{feff}'
                    || ch == '/'
                    || ch == '／'
                    || ch == '⁄'
                    || ch == '.'
                    || ch == '．'
                    || ch == ':'
                    || ch == '：'
                    || ch == '+'
                    || ch == '＋'
                    || ch == '|'
                    || ch == '｜'
                    || ch == '\\'
                    || ch == '＼'
                    || ch == ','
                    || ch == '，'
                    || ch == '、'
                    || ch == ';'
                    || ch == '；'
                    || ch == '。'
                    || ch == '．'
                    || ch == '·'
                    || ch == '・'
                    || ch == '∙'
                    || ch == '⋅'
                    || ch == '='
                    || ch == '@'
                    || ch == '#'
                    || ch == '`'
                    || ch == '%'
                    || ch == '$'
                    || ch == '&'
                    || ch == '('
                    || ch == ')'
                    || ch == '（'
                    || ch == '）'
                    || ch == '['
                    || ch == ']'
                    || ch == '［'
                    || ch == '］'
                    || ch == '{'
                    || ch == '}'
                    || ch == '｛'
                    || ch == '｝'
                    || ch == '<'
                    || ch == '>'
                    || ch == '"'
                    || ch == '\''
                    || ch == '“'
                    || ch == '”'
                    || ch == '‘'
                    || ch == '’'
                    || ch == '!'
                    || ch == '！'
                    || ch == '?'
                    || ch == '？'
                    || ch == '*'
                    || ch == '~'
                    || ch == '～'
                    || ch == '〜'
                    || ch == '^'
                    || ch == '®'
                    || ch == '™'
                {
                    ' '
                } else {
                    match ch {
                        '０' => '0',
                        '１' => '1',
                        '２' => '2',
                        '３' => '3',
                        '４' => '4',
                        '５' => '5',
                        '６' => '6',
                        '７' => '7',
                        '８' => '8',
                        '９' => '9',
                        _ => ch,
                    }
                }
            })
            .collect::<String>();
        let collapsed = delimiter_normalized
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if collapsed.is_empty() {
            return None;
        }

        let canonical = match collapsed.as_str() {
            // Backward-compatible aliases from early V1/V2 proof/receipt naming.
            "fraud proof" | "fraudproof" => "fraud",
            "fraud proof v1" | "fraudproofv1" | "fraud proof v 1" => "fraud",
            "fraud proof v2" | "fraudproofv2" | "fraud proof v 2" => "fraud",
            "fraud proof v3" | "fraudproofv3" | "fraud proof v 3" => "fraud",
            "fraud receipt" | "fraudreceipt" => "fraud",
            "fraud receipt v1" | "fraudreceiptv1" | "fraud receipt v 1" | "fraud receiptv1" => {
                "fraud"
            }
            "fraud receipt v2" | "fraudreceiptv2" | "fraud receipt v 2" | "fraud receiptv2" => {
                "fraud"
            }
            "fraud receipt v3" | "fraudreceiptv3" | "fraud receipt v 3" | "fraud receiptv3" => {
                "fraud"
            }
            "fraud challenge" | "fraudchallenge" => "fraud",
            "fraud challenge v1" | "fraudchallengev1" | "fraud challenge v 1" => "fraud",
            "fraud challenge v2" | "fraudchallengev2" | "fraud challenge v 2" => "fraud",
            "fraud challenge v3" | "fraudchallengev3" | "fraud challenge v 3" => "fraud",
            "tee proof" | "teeproof" => "tee",
            "tee proof v1" | "teeproofv1" | "tee proof v 1" => "tee",
            "tee proof v2" | "teeproofv2" | "tee proof v 2" => "tee",
            "tee proof v3" | "teeproofv3" | "tee proof v 3" => "tee",
            "tee receipt" | "teereceipt" => "tee",
            "tee receipt v1" | "teereceiptv1" | "tee receipt v 1" | "tee receiptv1" => "tee",
            "tee receipt v2" | "teereceiptv2" | "tee receipt v 2" | "tee receiptv2" => "tee",
            "tee receipt v3" | "teereceiptv3" | "tee receipt v 3" | "tee receiptv3" => "tee",
            "tee attestation" | "teeattestation" => "tee",
            "tee attestation v1" | "teeattestationv1" | "tee attestation v 1" => "tee",
            "tee attestation v2" | "teeattestationv2" | "tee attestation v 2" => "tee",
            "tee attestation v3" | "teeattestationv3" | "tee attestation v 3" => "tee",
            "tee quote" | "teequote" => "tee",
            "tee quote v1" | "teequotev1" | "tee quote v 1" => "tee",
            "tee quote v2" | "teequotev2" | "tee quote v 2" => "tee",
            "tee quote v3" | "teequotev3" | "tee quote v 3" => "tee",
            "tee report" | "teereport" => "tee",
            "tee report v1" | "teereportv1" | "tee report v 1" => "tee",
            "tee report v2" | "teereportv2" | "tee report v 2" => "tee",
            "tee report v3" | "teereportv3" | "tee report v 3" => "tee",
            "sgx quote" | "sgxquote" => "tee",
            "sgx quote v1" | "sgxquotev1" | "sgx quote v 1" => "tee",
            "sgx quote v2" | "sgxquotev2" | "sgx quote v 2" => "tee",
            "sgx quote v3" | "sgxquotev3" | "sgx quote v 3" => "tee",
            "enclave quote" | "enclavequote" => "tee",
            "sgx report" | "sgxreport" => "tee",
            "sgx report v1" | "sgxreportv1" | "sgx report v 1" => "tee",
            "sgx report v2" | "sgxreportv2" | "sgx report v 2" => "tee",
            "sgx report v3" | "sgxreportv3" | "sgx report v 3" => "tee",
            "tee evidence" | "teeevidence" => "tee",
            "remote attestation" | "remoteattestation" => "tee",
            "remote attestation v1" | "remoteattestationv1" | "remote attestation v 1" => "tee",
            "remote attestation v2" | "remoteattestationv2" | "remote attestation v 2" => "tee",
            "remote attestation v3" | "remoteattestationv3" | "remote attestation v 3" => "tee",
            "attestation report" | "attestationreport" => "tee",
            "attestation report v1" | "attestationreportv1" | "attestation report v 1" => "tee",
            "attestation report v2" | "attestationreportv2" | "attestation report v 2" => "tee",
            "attestation report v3" | "attestationreportv3" | "attestation report v 3" => "tee",
            "attestation quote" | "attestationquote" => "tee",
            "attestation quote v1" | "attestationquotev1" | "attestation quote v 1" => "tee",
            "attestation quote v2" | "attestationquotev2" | "attestation quote v 2" => "tee",
            "attestation quote v3" | "attestationquotev3" | "attestation quote v 3" => "tee",
            "tee attestation report" | "teeattestationreport" => "tee",
            "tee attestation report v1" | "teeattestationreportv1" | "tee attestation report v 1" => "tee",
            "tee attestation report v2" | "teeattestationreportv2" | "tee attestation report v 2" => "tee",
            "tee attestation report v3" | "teeattestationreportv3" | "tee attestation report v 3" => "tee",
            "tee attestation quote" | "teeattestationquote" => "tee",
            "tee attestation quote v1" | "teeattestationquotev1" | "tee attestation quote v 1" => "tee",
            "tee attestation quote v2" | "teeattestationquotev2" | "tee attestation quote v 2" => "tee",
            "tee attestation quote v3" | "teeattestationquotev3" | "tee attestation quote v 3" => "tee",
            "ra report" | "rareport" => "tee",
            "ra report v1" | "rareportv1" | "ra report v 1" => "tee",
            "ra report v2" | "rareportv2" | "ra report v 2" => "tee",
            "ra report v3" | "rareportv3" | "ra report v 3" => "tee",
            "ra quote" | "raquote" => "tee",
            "ra quote v1" | "raquotev1" | "ra quote v 1" => "tee",
            "ra quote v2" | "raquotev2" | "ra quote v 2" => "tee",
            "ra quote v3" | "raquotev3" | "ra quote v 3" => "tee",
            "dcap quote" | "dcapquote" => "tee",
            "tee dcap quote" | "teedcapquote" => "tee",
            "intel dcap quote" | "inteldcapquote" => "tee",
            "sgx dcap quote" | "sgxdcapquote" => "tee",
            "intel sgx dcap quote" | "intelsgxdcapquote" => "tee",
            "intel sgx report" | "intelsgxreport" => "tee",
            "tdx quote" | "tdxquote" => "tee",
            "tee tdx quote" | "teetdxquote" => "tee",
            "td quote" | "tdquote" => "tee",
            "tdx report" | "tdxreport" => "tee",
            "tee tdx report" | "teetdxreport" => "tee",
            "td report" | "tdreport" => "tee",
            "snp report" | "snpreport" => "tee",
            "tee snp report" | "teesnpreport" => "tee",
            "snp quote" | "snpquote" => "tee",
            "tee snp quote" | "teesnpquote" => "tee",
            "sev snp report" | "sevsnpreport" => "tee",
            "sev snp quote" | "sevsnpquote" => "tee",
            "amd sev snp report" | "amdsevsnpreport" => "tee",
            "amd sev snp quote" | "amdsevsnpquote" => "tee",
            "intel tdx quote" | "inteltdxquote" => "tee",
            "intel tdx report" | "inteltdxreport" => "tee",
            "tee cert" | "teecert" => "tee",
            "tee certificate" | "teecertificate" => "tee",
            "zk proof" | "zkproof" => "zk",
            "zk proof v1" | "zkproofv1" | "zk proof v 1" => "zk",
            "zk proof v2" | "zkproofv2" | "zk proof v 2" => "zk",
            "zk proof v3" | "zkproofv3" | "zk proof v 3" => "zk",
            "zk receipt" | "zkreceipt" => "zk",
            "zk receipt v1" | "zkreceiptv1" | "zk receipt v 1" | "zk receiptv1" => "zk",
            "zk receipt v2" | "zkreceiptv2" | "zk receipt v 2" | "zk receiptv2" => "zk",
            "zk receipt v3" | "zkreceiptv3" | "zk receipt v 3" | "zk receiptv3" => "zk",
            "zero knowledge" | "zeroknowledge" => "zk",
            "zero knowledge proof" | "zeroknowledgeproof" => "zk",
            "zero knowledge receipt" | "zeroknowledgereceipt" => "zk",
            _ => collapsed.as_str(),
        };

        Some(canonical.to_string())
    }

    pub fn register(&mut self, verifier: Arc<dyn ProofVerifier + Send + Sync>) {
        let key = Self::normalize_key(verifier.proof_type())
            .expect("proof verifier key must contain visible characters");
        self.verifiers.insert(key, verifier);
    }

    fn verifier_key_for_task(task: &TaskObject) -> String {
        proof_type_key(task.proof_type).to_string()
    }

    pub fn verify(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        let key = Self::verifier_key_for_task(task);
        if let Some(verifier) = self.verifiers.get(&key) {
            verifier.verify_proof(task, proof_data)
        } else {
            VerificationResult::Indeterminate(format!(
                "No verifier available for proof_type '{}'",
                key
            ))
        }
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::with_builtin_verifiers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::backend::{
        BackendExecutionError, BackendVerificationRequest, BackendVerificationSuccess,
        ZkBackendKind, ZkBackendRegistry,
    };
    use std::sync::Arc;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    struct AlwaysValidVerifier {
        kind: &'static str,
    }

    impl ProofVerifier for AlwaysValidVerifier {
        fn proof_type(&self) -> &str {
            self.kind
        }

        fn verify_proof(&self, _task: &TaskObject, _proof_data: &[u8]) -> VerificationResult {
            VerificationResult::Valid
        }
    }

    fn task_with_proof_type(proof_type: ProofType) -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Completed,
            proof_type,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: None,
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

    struct MockVectorBackend;
    impl crate::verification::backend::ZkBackend for MockVectorBackend {
        fn backend_id(&self) -> &str {
            "mock-zk-vectors"
        }

        fn verify(
            &self,
            request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(request.task.task_id, 42);
            let payload =
                request
                    .zk_payload
                    .ok_or_else(|| BackendExecutionError::MalformedProof {
                        backend: request.backend_label(self.backend_id()),
                        reason: "missing parsed payload".to_string(),
                    })?;
            match payload.vk_ref.as_str() {
                "vk://trnm/dev/mock-groth16/valid" => Ok(BackendVerificationSuccess {
                    backend_id: self.backend_id().into(),
                }),
                "vk://trnm/dev/mock-groth16/invalid" => Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(self.backend_id()),
                    reason: "mock vector rejected by backend".to_string(),
                }),
                other => Err(BackendExecutionError::MalformedProof {
                    backend: request.backend_label(self.backend_id()),
                    reason: format!("unexpected vk_ref '{other}'"),
                }),
            }
        }
    }

    fn registry_with_mock_zk_backend() -> VerifierRegistry {
        let mut backends = ZkBackendRegistry::new();
        backends.register(Arc::new(MockVectorBackend));
        VerifierRegistry::with_backends(
            VerificationBackendConfig {
                tee_backend: ZkBackendKind::Noop,
                zk_backend: ZkBackendKind::Custom("mock-zk-vectors".into()),
                zk_features: Default::default(),
            },
            Arc::new(backends),
        )
    }

    #[test]
    fn registry_zk_vector_valid_payload_reaches_backend_path() {
        let registry = registry_with_mock_zk_backend();
        let mut task = task_with_proof_type(ProofType::Zk);
        task.status = TaskStatus::Committed;
        task.worker = Some("worker-zk".into());
        task.result_hash = Some([0x11; 32]);

        let payload = br#"ZK:{"task_id":42,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/valid","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["42","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert_eq!(registry.verify(&task, payload), VerificationResult::Valid);
    }

    #[test]
    fn registry_zk_vector_invalid_payload_reaches_backend_rejection_path() {
        let registry = registry_with_mock_zk_backend();
        let mut task = task_with_proof_type(ProofType::Zk);
        task.status = TaskStatus::Committed;
        task.worker = Some("worker-zk".into());
        task.result_hash = Some([0x11; 32]);

        let payload = br#"ZK:{"task_id":42,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/invalid","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["42","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            registry.verify(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("mock vector rejected by backend")
        ));
    }

    #[test]
    fn registry_zk_vector_malformed_envelope_fails_closed_before_crypto() {
        let registry = registry_with_mock_zk_backend();
        let mut task = task_with_proof_type(ProofType::Zk);
        task.status = TaskStatus::Committed;
        task.worker = Some("worker-zk".into());
        task.result_hash = Some([0x11; 32]);

        assert!(matches!(
            registry.verify(&task, b"ZK:   \n\t"),
            VerificationResult::Invalid(msg) if msg.contains("Invalid ZK proof envelope")
        ));
    }

    #[test]
    fn registry_zk_vector_proof_type_mismatch_fails_closed_before_crypto() {
        let registry = registry_with_mock_zk_backend();
        let mut task = task_with_proof_type(ProofType::Zk);
        task.status = TaskStatus::Committed;
        task.worker = Some("worker-zk".into());
        task.result_hash = Some([0x11; 32]);

        let payload = br#"ZK:{"task_id":42,"worker":"worker-zk","proof_type":"tee","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/valid","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["42","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

        assert!(matches!(
            registry.verify(&task, payload),
            VerificationResult::Invalid(msg) if msg.contains("proof_type mismatch")
        ));
    }

    #[test]
    fn registry_register_is_case_insensitive_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: "TEE" }));

        let task = task_with_proof_type(ProofType::Tee);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_register_trims_verifier_key_for_lookup() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: "  zk  " }));

        let task = task_with_proof_type(ProofType::Zk);
        assert_eq!(
            registry.verify(&task, b"receipt"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn registry_supports_known_v1_v2_aliases() {
        let mut registry = VerifierRegistry::new();
        registry.register(Arc::new(AlwaysValidVerifier { kind: "fraud" }));
        registry.register(Arc::new(AlwaysValidVerifier { kind: "tee" }));
        registry.register(Arc::new(AlwaysValidVerifier { kind: "zk" }));

        for proof_type in [ProofType::Fraud, ProofType::Tee, ProofType::Zk] {
            let task = task_with_proof_type(proof_type);
            assert_eq!(
                registry.verify(&task, b"receipt"),
                VerificationResult::Valid
            );
        }
    }

    #[test]
    fn registry_normalize_key_maps_extended_tee_attestation_aliases_to_tee() {
        for alias in [
            "tee quote",
            "tee report v2",
            "sgx quote v3",
            "sgx report",
            "tee evidence",
            "tee attestation report",
            "attestation quote",
            "attestation quote v3",
            "tee attestation quote",
            "tee attestation quote v2",
            "ra quote",
            "ra report v2",
            "dcap quote",
            "intel dcap quote",
            "sgx dcap quote",
            "intel sgx dcap quote",
            "tdx quote",
            "td report",
            "snp report",
            "amd sev snp quote",
            "intel sgx report",
            "tee dcap quote",
            "intel tdx quote",
            "intel tdx report",
            "tee tdx quote",
            "tee tdx report",
            "tee snp report",
            "tee snp quote",
            "tee certificate",
            "teereportv3",
            "sgxquotev2",
            "sevsnpreport",
            "teecert",
        ] {
            assert_eq!(VerifierRegistry::normalize_key(alias).as_deref(), Some("tee"));
        }
    }
}
