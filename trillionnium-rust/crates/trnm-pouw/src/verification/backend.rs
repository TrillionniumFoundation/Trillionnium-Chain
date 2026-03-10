use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use trnm_types::{ProofType, TaskObject};

use crate::verification::proof_type_key;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationBackendFamily {
    Tee,
    Zk,
}

impl VerificationBackendFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tee => "tee",
            Self::Zk => "zk",
        }
    }

    pub fn from_proof_type(proof_type: ProofType) -> Option<Self> {
        match proof_type {
            ProofType::Fraud => None,
            ProofType::Tee => Some(Self::Tee),
            ProofType::Zk => Some(Self::Zk),
        }
    }
}

impl std::fmt::Display for VerificationBackendFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationBackendKind {
    Noop,
    Custom(String),
}

impl Default for VerificationBackendKind {
    fn default() -> Self {
        Self::Noop
    }
}

impl VerificationBackendKind {
    pub fn key(&self) -> &str {
        match self {
            Self::Noop => "noop",
            Self::Custom(key) => key.as_str(),
        }
    }
}

/// Back-compat alias kept because current verification wiring and tests already
/// speak in ZK-oriented terms, even though the platform registry now serves both
/// TEE and ZK families.
pub type ZkBackendKind = VerificationBackendKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkFeatureFlags {
    pub zk_platform_v0: bool,
    pub zk_backend_router: bool,
    pub zk_payload_v0_envelope: bool,
    pub zk_allow_legacy_receipt_aliases: bool,
    pub zk_allow_backend_fallback: bool,
    pub zk_explicit_backend_required: bool,
}

impl Default for ZkFeatureFlags {
    fn default() -> Self {
        Self {
            zk_platform_v0: false,
            zk_backend_router: false,
            zk_payload_v0_envelope: false,
            zk_allow_legacy_receipt_aliases: true,
            zk_allow_backend_fallback: false,
            zk_explicit_backend_required: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationBackendConfig {
    pub tee_backend: VerificationBackendKind,
    pub zk_backend: VerificationBackendKind,
    pub zk_features: ZkFeatureFlags,
}

impl Default for VerificationBackendConfig {
    fn default() -> Self {
        Self {
            tee_backend: VerificationBackendKind::Noop,
            zk_backend: VerificationBackendKind::Noop,
            zk_features: ZkFeatureFlags::default(),
        }
    }
}

impl VerificationBackendConfig {
    /// Selects the configured backend kind for a verification family.
    pub fn kind_for_family(&self, family: VerificationBackendFamily) -> &VerificationBackendKind {
        match family {
            VerificationBackendFamily::Tee => &self.tee_backend,
            VerificationBackendFamily::Zk => &self.zk_backend,
        }
    }

    /// Returns the backend selector for a proof type when that proof family is
    /// backend-capable. Fraud stays backendless by design.
    pub fn kind_for_proof_type(&self, proof_type: ProofType) -> Option<&VerificationBackendKind> {
        VerificationBackendFamily::from_proof_type(proof_type)
            .map(|family| self.kind_for_family(family))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPublicInputs {
    pub order: Vec<String>,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBytesEncoding {
    Base64,
    Hex,
}

fn default_proof_bytes_encoding() -> ProofBytesEncoding {
    ProofBytesEncoding::Base64
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ZkPayloadMeta {
    #[serde(default)]
    pub schema_version: String,
    #[serde(default)]
    pub circuit_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedZkProofPayload {
    pub task_id: u64,
    pub worker: String,
    pub proof_type: String,
    pub result_hash: String,
    #[serde(default)]
    pub zk_system: Option<String>,
    #[serde(default)]
    pub backend_id: Option<String>,
    #[serde(default)]
    pub backend_version: Option<String>,
    pub vk_ref: String,
    #[serde(default = "default_proof_bytes_encoding")]
    pub proof_encoding: ProofBytesEncoding,
    pub proof: String,
    pub public_inputs: ZkPublicInputs,
    #[serde(default)]
    pub meta: ZkPayloadMeta,
}

impl ParsedZkProofPayload {
    pub fn decode_proof_bytes(&self) -> Result<Vec<u8>, BackendExecutionError> {
        match self.proof_encoding {
            ProofBytesEncoding::Base64 => {
                decode_base64(&self.proof).map_err(|reason| BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason,
                })
            }
            ProofBytesEncoding::Hex => {
                hex::decode(self.proof.trim()).map_err(|_| BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: proof is not valid hex".to_string(),
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendVerificationRequest<'a> {
    pub family: VerificationBackendFamily,
    pub task: &'a TaskObject,
    pub proof_data: &'a [u8],
    /// Parsed canonical ZK payload, when the envelope is the structured JSON
    /// shape expected by platform backends.
    pub zk_payload: Option<&'a ParsedZkProofPayload>,
}

impl<'a> BackendVerificationRequest<'a> {
    pub fn backend_family(&self) -> &'static str {
        self.family.as_str()
    }

    pub fn backend_label(&self, backend_id: &str) -> String {
        format!("{}:{}", self.backend_family(), backend_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendVerificationSuccess {
    pub backend_id: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendSelectionError {
    #[error("verification backend '{backend}' is not registered for family '{family}'")]
    UnknownBackend {
        family: VerificationBackendFamily,
        backend: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationErrorClass {
    Invalid,
    Unavailable,
    BackendError,
    Malformed,
}

impl VerificationErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Unavailable => "unavailable",
            Self::BackendError => "backend_error",
            Self::Malformed => "malformed",
        }
    }
}

impl std::fmt::Display for VerificationErrorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStage {
    Envelope,
    Backend,
}

impl VerificationStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Envelope => "envelope",
            Self::Backend => "backend",
        }
    }
}

impl std::fmt::Display for VerificationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofVerificationObservation {
    pub proof_type: String,
    pub backend_family: Option<VerificationBackendFamily>,
    pub configured_backend: Option<String>,
    pub active_backend: Option<String>,
    pub zk_system: Option<String>,
    pub outcome: crate::verification::VerificationOutcomeLabel,
    pub error_class: Option<VerificationErrorClass>,
    pub stage: VerificationStage,
}

impl ProofVerificationObservation {
    /// Minimal, low-cardinality label set for metrics/tracing.
    pub fn label_pairs(&self) -> Vec<(&'static str, String)> {
        let mut labels = vec![
            ("proof_type", self.proof_type.clone()),
            ("outcome", self.outcome.as_str().to_string()),
            ("stage", self.stage.as_str().to_string()),
        ];
        if let Some(family) = self.backend_family {
            labels.push(("backend_family", family.as_str().to_string()));
        }
        if let Some(configured_backend) = &self.configured_backend {
            labels.push(("configured_backend", configured_backend.clone()));
        }
        if let Some(active_backend) = &self.active_backend {
            labels.push(("active_backend", active_backend.clone()));
        }
        if let Some(zk_system) = &self.zk_system {
            labels.push(("zk_system", zk_system.clone()));
        }
        if let Some(error_class) = self.error_class {
            labels.push(("error_class", error_class.as_str().to_string()));
        }
        labels
    }

    pub fn from_backend_error(
        proof_type: ProofType,
        family: VerificationBackendFamily,
        configured_backend: &VerificationBackendKind,
        request: Option<&BackendVerificationRequest<'_>>,
        error: &BackendExecutionError,
    ) -> Self {
        Self {
            proof_type: proof_type_key(proof_type).to_string(),
            backend_family: Some(family),
            configured_backend: Some(configured_backend.key().to_string()),
            active_backend: Some(match error {
                BackendExecutionError::NotConfigured { backend }
                | BackendExecutionError::InvalidProof { backend, .. }
                | BackendExecutionError::Unavailable { backend, .. }
                | BackendExecutionError::MalformedProof { backend, .. }
                | BackendExecutionError::Internal { backend, .. } => backend.clone(),
            }),
            zk_system: request
                .and_then(|req| req.zk_payload)
                .and_then(|payload| payload.zk_system.clone()),
            outcome: match error.error_class() {
                VerificationErrorClass::Invalid | VerificationErrorClass::Malformed => {
                    crate::verification::VerificationOutcomeLabel::Invalid
                }
                VerificationErrorClass::Unavailable | VerificationErrorClass::BackendError => {
                    crate::verification::VerificationOutcomeLabel::Indeterminate
                }
            },
            error_class: Some(error.error_class()),
            stage: VerificationStage::Backend,
        }
    }

    pub fn from_verification_result(
        proof_type: ProofType,
        result: &crate::verification::VerificationResult,
    ) -> Self {
        let proof_type_key = proof_type_key(proof_type).to_string();
        let reason = result.reason().unwrap_or_default().to_ascii_lowercase();
        let (stage, error_class) = match result {
            crate::verification::VerificationResult::Valid => (VerificationStage::Backend, None),
            crate::verification::VerificationResult::Invalid(_) => {
                let class = if reason.contains("malformed") {
                    VerificationErrorClass::Malformed
                } else {
                    VerificationErrorClass::Invalid
                };
                let stage = if reason.contains("backend") {
                    VerificationStage::Backend
                } else {
                    VerificationStage::Envelope
                };
                (stage, Some(class))
            }
            crate::verification::VerificationResult::Indeterminate(_) => {
                let class = if reason.contains("not configured")
                    || reason.contains("cannot currently verify")
                {
                    VerificationErrorClass::Unavailable
                } else {
                    VerificationErrorClass::BackendError
                };
                (VerificationStage::Backend, Some(class))
            }
        };

        Self {
            proof_type: proof_type_key,
            backend_family: VerificationBackendFamily::from_proof_type(proof_type),
            configured_backend: None,
            active_backend: None,
            zk_system: None,
            outcome: result.outcome_label(),
            error_class,
            stage,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendExecutionError {
    #[error("cryptographic verification backend not configured: {backend}")]
    NotConfigured { backend: String },
    #[error("verification backend '{backend}' rejected proof: {reason}")]
    InvalidProof { backend: String, reason: String },
    #[error("verification backend '{backend}' cannot currently verify proof: {reason}")]
    Unavailable { backend: String, reason: String },
    #[error("verification backend '{backend}' rejected malformed payload: {reason}")]
    MalformedProof { backend: String, reason: String },
    #[error("verification backend '{backend}' failed: {reason}")]
    Internal { backend: String, reason: String },
}

impl BackendExecutionError {
    pub fn error_class(&self) -> VerificationErrorClass {
        match self {
            Self::NotConfigured { .. } | Self::Unavailable { .. } => {
                VerificationErrorClass::Unavailable
            }
            Self::InvalidProof { .. } => VerificationErrorClass::Invalid,
            Self::MalformedProof { .. } => VerificationErrorClass::Malformed,
            Self::Internal { .. } => VerificationErrorClass::BackendError,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerificationBackendError {
    #[error(transparent)]
    Selection(#[from] BackendSelectionError),
    #[error(transparent)]
    Execution(#[from] BackendExecutionError),
}

pub trait VerificationBackend: Send + Sync {
    fn backend_id(&self) -> &str;
    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError>;
}

/// Back-compat shim: existing tests and local mock backends still import
/// `ZkBackend`, but the registry is now family-agnostic.
pub trait ZkBackend: Send + Sync {
    fn backend_id(&self) -> &str;
    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError>;
}

impl<T> VerificationBackend for T
where
    T: ZkBackend + ?Sized,
{
    fn backend_id(&self) -> &str {
        ZkBackend::backend_id(self)
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        ZkBackend::verify(self, request)
    }
}

#[derive(Default)]
pub struct VerificationBackendRegistry {
    backends: HashMap<String, Arc<dyn VerificationBackend>>,
}

impl VerificationBackendRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            backends: HashMap::new(),
        };
        registry.register(Arc::new(NoopVerificationBackend));
        registry
    }

    pub fn register(&mut self, backend: Arc<dyn VerificationBackend>) {
        self.backends
            .insert(backend.backend_id().trim().to_ascii_lowercase(), backend);
    }

    pub fn resolve(
        &self,
        family: VerificationBackendFamily,
        kind: &VerificationBackendKind,
    ) -> Result<Arc<dyn VerificationBackend>, BackendSelectionError> {
        let key = kind.key().trim().to_ascii_lowercase();
        self.backends
            .get(&key)
            .cloned()
            .ok_or_else(|| BackendSelectionError::UnknownBackend {
                family,
                backend: key,
            })
    }
}

/// Back-compat alias for the previous ZK-named registry type.
pub type ZkBackendRegistry = VerificationBackendRegistry;

pub struct NoopVerificationBackend;

impl VerificationBackend for NoopVerificationBackend {
    fn backend_id(&self) -> &str {
        "noop"
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        Err(BackendExecutionError::NotConfigured {
            backend: request.backend_label(self.backend_id()),
        })
    }
}

pub fn parse_zk_proof_payload(
    task: &TaskObject,
    proof_data: &[u8],
) -> Result<ParsedZkProofPayload, BackendExecutionError> {
    let raw =
        std::str::from_utf8(proof_data).map_err(|_| BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof envelope is not valid utf-8".to_string(),
        })?;
    let body = raw
        .strip_prefix("ZK:")
        .or_else(|| raw.strip_prefix("zk:"))
        .ok_or_else(|| BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: missing ZK: prefix".to_string(),
        })?;
    let payload: ParsedZkProofPayload =
        serde_json::from_str(body).map_err(|_| BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: body must be canonical JSON object".to_string(),
        })?;

    let expected_hash =
        hex::encode(
            task.result_hash
                .ok_or_else(|| BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: missing task result_hash binding context"
                        .to_string(),
                })?,
        );

    if payload.task_id != task.task_id {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: task_id mismatch".to_string(),
        });
    }
    if payload.worker != task.worker.as_deref().unwrap_or_default() {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: worker mismatch".to_string(),
        });
    }
    if !payload.proof_type.eq_ignore_ascii_case("zk") {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof_type must be zk".to_string(),
        });
    }
    if !payload.result_hash.eq_ignore_ascii_case(&expected_hash) {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: result_hash mismatch".to_string(),
        });
    }
    if payload.vk_ref.trim().is_empty() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: vk_ref is required".to_string(),
        });
    }
    if payload.proof.trim().is_empty() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof bytes are required".to_string(),
        });
    }
    let expected_public_inputs = vec![
        task.task_id.to_string(),
        task.worker.clone().unwrap_or_default(),
        expected_hash.clone(),
    ];
    let expected_order = vec![
        "task_id".to_string(),
        "worker".to_string(),
        "result_hash".to_string(),
    ];
    if payload.public_inputs.order != expected_order
        || payload.public_inputs.values != expected_public_inputs
    {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: public_inputs mismatch".to_string(),
        });
    }
    let _ = payload.decode_proof_bytes()?;
    Ok(payload)
}

fn decode_base64(raw: &str) -> Result<Vec<u8>, String> {
    let cleaned = raw
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if cleaned.is_empty() {
        return Err("invalid zk payload: proof bytes are required".to_string());
    }
    if cleaned.len() % 4 != 0 {
        return Err("invalid zk payload: proof is not valid base64".to_string());
    }

    let mut out = Vec::with_capacity((cleaned.len() / 4) * 3);
    for chunk in cleaned.chunks(4) {
        let mut vals = [0u8; 4];
        let mut padding = 0usize;
        for (idx, ch) in chunk.iter().copied().enumerate() {
            vals[idx] = match ch {
                b'A'..=b'Z' => ch - b'A',
                b'a'..=b'z' => ch - b'a' + 26,
                b'0'..=b'9' => ch - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    padding += 1;
                    0
                }
                _ => return Err("invalid zk payload: proof is not valid base64".to_string()),
            };
            if padding > 0 && idx < 2 {
                return Err("invalid zk payload: base64 padding must be terminal".to_string());
            }
            if padding > 0 && ch != b'=' {
                return Err("invalid zk payload: base64 padding must be terminal".to_string());
            }
        }
        if padding > 2 {
            return Err("invalid zk payload: proof is not valid base64".to_string());
        }

        let block = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);
        out.push(((block >> 16) & 0xff) as u8);
        if padding < 2 {
            out.push(((block >> 8) & 0xff) as u8);
        }
        if padding == 0 {
            out.push((block & 0xff) as u8);
        }
    }

    if out.is_empty() {
        return Err("invalid zk payload: proof bytes are required".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskStatus};

    #[test]
    fn proof_verification_observation_maps_backend_not_configured_to_unavailable() {
        let task = mock_task();
        let err = BackendExecutionError::NotConfigured {
            backend: "zk:noop".into(),
        };
        let observation = ProofVerificationObservation::from_backend_error(
            ProofType::Zk,
            VerificationBackendFamily::Zk,
            &VerificationBackendKind::Noop,
            Some(&BackendVerificationRequest {
                family: VerificationBackendFamily::Zk,
                task: &task,
                proof_data: b"ZK:...",
                zk_payload: None,
            }),
            &err,
        );
        assert_eq!(observation.proof_type, "zk");
        assert_eq!(observation.outcome.as_str(), "indeterminate");
        assert_eq!(
            observation.error_class,
            Some(VerificationErrorClass::Unavailable)
        );
        assert_eq!(observation.stage, VerificationStage::Backend);
        assert!(observation
            .label_pairs()
            .iter()
            .any(|(k, v)| *k == "active_backend" && v == "zk:noop"));
    }

    #[test]
    fn proof_verification_observation_maps_envelope_invalid_to_invalid_class() {
        let observation = ProofVerificationObservation::from_verification_result(
            ProofType::Fraud,
            &crate::verification::VerificationResult::Invalid("missing task_id binding".into()),
        );
        assert_eq!(observation.proof_type, "fraud");
        assert_eq!(observation.outcome.as_str(), "invalid");
        assert_eq!(
            observation.error_class,
            Some(VerificationErrorClass::Invalid)
        );
        assert_eq!(observation.stage, VerificationStage::Envelope);
    }

    #[test]
    fn proof_verification_observation_maps_malformed_zk_payload_to_malformed_class() {
        let observation = ProofVerificationObservation::from_verification_result(
            ProofType::Zk,
            &crate::verification::VerificationResult::Invalid(
                "verification backend 'zk:payload' rejected malformed payload: invalid zk payload: body must be canonical JSON object".into(),
            ),
        );
        assert_eq!(
            observation.error_class,
            Some(VerificationErrorClass::Malformed)
        );
        assert_eq!(observation.stage, VerificationStage::Backend);
    }

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 4242,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some("worker-zk".into()),
            committed_hash: None,
            result_hash: Some([0x11; 32]),
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

    #[test]
    fn backend_config_routes_backend_capable_families() {
        let config = VerificationBackendConfig {
            tee_backend: VerificationBackendKind::Custom("mock-tee".into()),
            zk_backend: VerificationBackendKind::Custom("mock-zk".into()),
            zk_features: Default::default(),
        };

        assert_eq!(
            config.kind_for_family(VerificationBackendFamily::Tee),
            &VerificationBackendKind::Custom("mock-tee".into())
        );
        assert_eq!(
            config.kind_for_family(VerificationBackendFamily::Zk),
            &VerificationBackendKind::Custom("mock-zk".into())
        );
        assert_eq!(config.kind_for_proof_type(ProofType::Fraud), None);
    }

    #[test]
    fn noop_backend_uses_family_scoped_not_configured_error() {
        let err = NoopVerificationBackend
            .verify(BackendVerificationRequest {
                family: VerificationBackendFamily::Tee,
                task: &mock_task(),
                proof_data: b"TEE:...",
                zk_payload: None,
            })
            .unwrap_err();

        assert_eq!(
            err,
            BackendExecutionError::NotConfigured {
                backend: "tee:noop".into()
            }
        );
    }

    #[test]
    fn parse_zk_proof_payload_accepts_canonical_json_vector() {
        let task = mock_task();
        let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","worker","result_hash"],"values":["4242","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0","circuit_id":"settlement-result-v1"}}"#).unwrap();
        assert_eq!(payload.vk_ref, "vk://trnm/dev/mock-groth16/v1");
        assert_eq!(payload.backend_id.as_deref(), Some("mock-zk"));
        assert_eq!(payload.meta.schema_version, "trnm.zk.payload.v0");
        assert_eq!(payload.decode_proof_bytes().unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn parse_zk_proof_payload_rejects_public_input_mismatch() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","worker","result_hash"],"values":["4242","worker-zk","2222222222222222222222222222222222222222222222222222222222222222"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::InvalidProof { reason, .. } if reason.contains("public_inputs mismatch"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_malformed_json_before_crypto() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"base64","proof":"!!!","public_inputs":{"order":["task_id"]"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
        );
    }
}
