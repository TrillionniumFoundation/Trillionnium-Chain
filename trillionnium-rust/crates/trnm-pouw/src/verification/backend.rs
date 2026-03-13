use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use trnm_types::{ProofType, TaskObject};

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

    pub fn normalized_key(&self) -> String {
        self.key().trim().to_ascii_lowercase()
    }

    pub fn system_hint(&self) -> Option<String> {
        backend_system_hint(self.key())
    }
}

fn normalize_backend_token(raw: &str) -> Option<String> {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>();
    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}

pub fn backend_system_hint(raw: &str) -> Option<String> {
    let normalized = normalize_backend_token(raw)?;
    let parts = normalized.split_whitespace().collect::<Vec<_>>();
    let first = *parts.first()?;

    let (family, mut idx) = match first {
        "tee" | "zk" => (Some(first), 1usize),
        _ => (None, 0usize),
    };

    fn tee_platform<'a>(tokens: &'a [&'a str]) -> Option<&'a str> {
        tokens
            .iter()
            .copied()
            .find(|token| matches!(*token, "sgx" | "tdx" | "snp"))
    }

    let is_tee_attestation_surface = |token: &str| {
        matches!(
            token,
            "intel"
                | "amd"
                | "attestation"
                | "attestations"
                | "remote"
                | "ra"
                | "evidence"
                | "evidences"
                | "receipt"
                | "receipts"
                | "enclave"
                | "enclaves"
                | "quote"
                | "quotes"
                | "report"
                | "reports"
                | "claims"
                | "claim"
                | "cert"
                | "certs"
                | "certificate"
                | "certificates"
                | "dcap"
                | "sev"
        )
    };

    if family == Some("tee") {
        while let Some(token) = parts.get(idx).copied() {
            if is_tee_attestation_surface(token) {
                idx += 1;
                continue;
            }
            break;
        }

        // Prefer the concrete TEE attestation platform when compound backend
        // identifiers include both a vendor/family label and a more specific
        // platform token, e.g. `amd-sev-snp` should resolve to `snp` rather
        // than the broader `sev` family marker.
        if let Some(platform) = tee_platform(&parts[idx..]) {
            return Some(platform.to_string());
        }
    }

    // Some backend ids are already family-scoped by path or config key and omit
    // the explicit `tee` prefix, e.g. `intel-sgx-dcap` / `amd-sev-snp`. Others
    // arrive as attestation-oriented labels like `remote attestation quote sgx`
    // or `attestation evidence snp`. Keep those on the same concrete-platform
    // contract instead of falling back to a generic surface token such as
    // `remote` or `attestation`.
    if family.is_none() && is_tee_attestation_surface(first) {
        let start = if matches!(first, "intel" | "amd") { 1 } else { 0 };
        if let Some(platform) = tee_platform(&parts[start..]) {
            return Some(platform.to_string());
        }
    }

    match parts.get(idx).copied() {
        Some("noop") | None => None,
        Some(system)
            if family == Some("tee")
                && matches!(system, "quote" | "report" | "claims" | "claim") =>
        {
            None
        }
        Some(system) => Some(system.to_string()),
    }
}

pub fn normalize_zk_system(raw: &str) -> Option<String> {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();

    match normalized.as_str() {
        "groth16" | "plonk" | "halo2" | "stark" | "risc0" | "sp1" => Some(normalized),
        _ => None,
    }
}

/// Family-scoped alias so TEE verifiers/config can speak in attestation terms
/// without reusing the older ZK-oriented type name at call sites.
pub type TeeBackendKind = VerificationBackendKind;

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
pub struct ResolvedVkRef {
    pub vk_ref: String,
    pub scope: String,
    pub zk_system: Option<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VkRefResolutionError {
    #[error("invalid zk payload: vk_ref is required")]
    Missing,
    #[error("invalid zk payload: unknown vk_ref '{vk_ref}'")]
    Unknown { vk_ref: String },
}

impl VkRefResolutionError {
    pub fn into_backend_execution_error(self) -> BackendExecutionError {
        match self {
            Self::Missing => BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: vk_ref is required".to_string(),
            },
            Self::Unknown { vk_ref } => BackendExecutionError::InvalidProof {
                backend: "zk:payload".to_string(),
                reason: format!("invalid zk payload: unknown vk_ref '{vk_ref}'"),
            },
        }
    }
}

pub trait VkRefResolver: Send + Sync {
    fn resolve(&self, vk_ref: &str) -> Result<ResolvedVkRef, VkRefResolutionError>;
}

#[derive(Default)]
pub struct VkRefRegistry {
    entries: HashMap<String, ResolvedVkRef>,
}

impl VkRefRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            entries: HashMap::new(),
        };
        registry.register_demo_dev_defaults();
        registry
    }

    pub fn register(&mut self, resolved: ResolvedVkRef) {
        self.entries
            .insert(resolved.vk_ref.trim().to_ascii_lowercase(), resolved);
    }

    fn register_demo_dev_defaults(&mut self) {
        for (vk_ref, zk_system) in [
            ("vk://trnm/dev/mock-groth16/v1", "groth16"),
            ("vk://trnm/dev/mock-groth16/valid", "groth16"),
            ("vk://trnm/dev/mock-groth16/invalid", "groth16"),
            ("vk://trnm/dev/mock-plonk/v1", "plonk"),
            ("vk://trnm/dev/mock-plonk/valid", "plonk"),
            ("vk://trnm/dev/mock-plonk/invalid", "plonk"),
        ] {
            self.register(ResolvedVkRef {
                vk_ref: vk_ref.to_string(),
                scope: "dev".to_string(),
                zk_system: Some(zk_system.to_string()),
            });
        }
    }
}

impl VkRefResolver for VkRefRegistry {
    fn resolve(&self, vk_ref: &str) -> Result<ResolvedVkRef, VkRefResolutionError> {
        let normalized = vk_ref.trim();
        if normalized.is_empty() {
            return Err(VkRefResolutionError::Missing);
        }

        self.entries
            .get(&normalized.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| VkRefResolutionError::Unknown {
                vk_ref: normalized.to_string(),
            })
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
    /// Resolved VK metadata, when the proof family is ZK and the vk_ref was
    /// accepted by the platform registry.
    pub resolved_vk_ref: Option<&'a ResolvedVkRef>,
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

    pub fn backend(&self) -> &str {
        match self {
            Self::NotConfigured { backend }
            | Self::InvalidProof { backend, .. }
            | Self::Unavailable { backend, .. }
            | Self::MalformedProof { backend, .. }
            | Self::Internal { backend, .. } => backend,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::NotConfigured { .. } => None,
            Self::InvalidProof { reason, .. }
            | Self::Unavailable { reason, .. }
            | Self::MalformedProof { reason, .. }
            | Self::Internal { reason, .. } => Some(reason),
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

/// Family-scoped backend shim for TEE call sites and tests. This reuses the
/// same runtime contract as the shared verification backend registry while
/// avoiding ZK-oriented naming at attestation-specific integration points.
pub use VerificationBackend as TeeBackend;

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

/// Family-scoped alias so TEE verifiers/config can speak in attestation terms
/// without reusing the older ZK-oriented registry name at call sites.
pub type TeeBackendRegistry = VerificationBackendRegistry;

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
    if let Some(raw_zk_system) = payload.zk_system.as_deref() {
        if normalize_zk_system(raw_zk_system).is_none() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: unsupported zk_system '{}'",
                    raw_zk_system.trim()
                ),
            });
        }
    }
    if payload.vk_ref.trim().is_empty() {
        return Err(VkRefResolutionError::Missing.into_backend_execution_error());
    }
    if payload.proof.trim().is_empty() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof bytes are required".to_string(),
        });
    }
    let mut expected_public_inputs = vec![task.task_id.to_string(), "zk".to_string()];
    let mut expected_order = vec!["task_id".to_string(), "proof_type".to_string()];
    if let Some(worker) = task.worker.as_ref() {
        expected_public_inputs.push(worker.clone());
        expected_order.push("worker".to_string());
    }
    expected_public_inputs.push(expected_hash.clone());
    expected_order.push("result_hash".to_string());
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

pub fn resolve_zk_vk_ref(
    resolver: &dyn VkRefResolver,
    payload: &ParsedZkProofPayload,
) -> Result<ResolvedVkRef, BackendExecutionError> {
    resolver
        .resolve(&payload.vk_ref)
        .map_err(VkRefResolutionError::into_backend_execution_error)
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
                resolved_vk_ref: None,
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
        let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0","circuit_id":"settlement-result-v1"}}"#).unwrap();
        assert_eq!(payload.vk_ref, "vk://trnm/dev/mock-groth16/v1");
        assert_eq!(payload.backend_id.as_deref(), Some("mock-zk"));
        assert_eq!(payload.meta.schema_version, "trnm.zk.payload.v0");
        assert_eq!(payload.decode_proof_bytes().unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn parse_zk_proof_payload_rejects_public_input_mismatch() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","2222222222222222222222222222222222222222222222222222222222222222"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::InvalidProof { reason, .. } if reason.contains("public_inputs mismatch"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_unsupported_zk_system_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"bulletproofs","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("unsupported zk_system 'bulletproofs'"))
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

    #[test]
    fn resolve_zk_vk_ref_rejects_unknown_vk_ref_fail_closed() {
        let task = mock_task();
        let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/unknown","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap();
        let resolver = VkRefRegistry::new();

        let err = resolve_zk_vk_ref(&resolver, &payload).unwrap_err();

        assert_eq!(
            err,
            BackendExecutionError::InvalidProof {
                backend: "zk:payload".into(),
                reason: "invalid zk payload: unknown vk_ref 'vk://trnm/dev/mock-groth16/unknown'"
                    .into(),
            }
        );
    }

    #[test]
    fn resolve_zk_vk_ref_returns_registered_system_metadata() {
        let task = mock_task();
        let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"plonk","backend_id":"plonk-demo","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"schema_version":"trnm.zk.payload.v0"}}"#).unwrap();
        let resolver = VkRefRegistry::new();

        let resolved = resolve_zk_vk_ref(&resolver, &payload).unwrap();

        assert_eq!(resolved.vk_ref, "vk://trnm/dev/mock-plonk/v1");
        assert_eq!(resolved.scope, "dev");
        assert_eq!(resolved.zk_system.as_deref(), Some("plonk"));
    }

    #[test]
    fn normalize_zk_system_accepts_common_aliases() {
        assert_eq!(normalize_zk_system("groth16"), Some("groth16".into()));
        assert_eq!(normalize_zk_system(" Groth-16 "), Some("groth16".into()));
        assert_eq!(normalize_zk_system("PLONK"), Some("plonk".into()));
        assert_eq!(normalize_zk_system("mock-zk"), None);
    }

    #[test]
    fn backend_system_hint_extracts_family_scoped_tee_and_zk_system_tokens() {
        assert_eq!(backend_system_hint(" tee:sgx-dcap "), Some("sgx".into()));
        assert_eq!(backend_system_hint("TEE report-snp"), Some("snp".into()));
        assert_eq!(
            backend_system_hint("tee:intel-sgx-dcap"),
            Some("sgx".into())
        );
        assert_eq!(backend_system_hint("intel-sgx-dcap"), Some("sgx".into()));
        assert_eq!(backend_system_hint("TEE amd-sev-snp"), Some("snp".into()));
        assert_eq!(backend_system_hint("amd-sev-snp"), Some("snp".into()));
        assert_eq!(backend_system_hint("tee attestation report"), None);
        assert_eq!(backend_system_hint("tee receipt quote"), None);
        assert_eq!(backend_system_hint("tee evidence snp"), Some("snp".into()));
        assert_eq!(backend_system_hint("tee quote tdx"), Some("tdx".into()));
        assert_eq!(backend_system_hint("tee claims sgx"), Some("sgx".into()));
        assert_eq!(backend_system_hint("tee cert snp"), Some("snp".into()));
        assert_eq!(
            backend_system_hint("tee certificate tdx"),
            Some("tdx".into())
        );
        assert_eq!(backend_system_hint("zk:groth16"), Some("groth16".into()));
        assert_eq!(backend_system_hint("plonk"), Some("plonk".into()));
        assert_eq!(backend_system_hint("noop"), None);
    }

    #[test]
    fn backend_system_hint_does_not_treat_tee_attestation_surfaces_as_backend_systems() {
        for raw in [
            "tee quote",
            "tee report",
            "tee claim",
            "tee claims",
            "tee cert",
            "tee certificate",
            "tee attestation receipt report",
            "tee enclave report",
            "tee enclave evidence",
            "tee evidence quote",
            "tee ra quote",
            "tee remote attestation quote",
            "tee dcap quote",
            "tee intel dcap quote",
            "tee amd sev quote",
        ] {
            assert_eq!(backend_system_hint(raw), None, "raw={raw}");
        }
    }

    #[test]
    fn backend_system_hint_requires_concrete_tee_platform_not_broad_sev_family_marker() {
        for raw in [
            "tee sev",
            "TEE amd-sev",
            "tee amd sev attestation",
            "tee remote attestation amd sev",
            "tee evidence amd sev",
        ] {
            assert_eq!(backend_system_hint(raw), None, "raw={raw}");
        }

        assert_eq!(backend_system_hint("tee amd sev snp"), Some("snp".into()));
        assert_eq!(
            backend_system_hint("TEE AMD-SEV-SNP quote"),
            Some("snp".into())
        );
        assert_eq!(backend_system_hint("amd sev snp"), Some("snp".into()));
        assert_eq!(backend_system_hint("intel sgx dcap"), Some("sgx".into()));
    }

    #[test]
    fn backend_system_hint_extracts_concrete_tee_platform_after_mixed_attestation_surface_tokens() {
        for (raw, expected) in [
            ("tee certificate quote sgx", "sgx"),
            ("tee attestation receipt report tdx", "tdx"),
            ("tee evidence cert snp", "snp"),
            ("tee remote attestation receipt sgx", "sgx"),
            ("tee remote attestation evidence sgx", "sgx"),
            ("tee remote attestation quote sgx", "sgx"),
            ("tee remote attestation certificate tdx", "tdx"),
            ("tee intel dcap quote sgx", "sgx"),
            ("tee amd sev quote snp", "snp"),
            ("tee remote attestation amd sev snp", "snp"),
            ("tee remote attestation amd-sev-snp", "snp"),
            ("tee enclave report sgx", "sgx"),
            ("tee enclave evidence tdx", "tdx"),
            ("tee attestations receipts reports sgx", "sgx"),
            ("tee evidences certs quotes tdx", "tdx"),
            ("tee remote attestations certificates snp", "snp"),
            ("remote attestation quote sgx", "sgx"),
            ("remote attestation evidence sgx", "sgx"),
            ("attestation evidence snp", "snp"),
            ("receipt report tdx", "tdx"),
        ] {
            assert_eq!(backend_system_hint(raw), Some(expected.into()), "raw={raw}");
        }
    }

    #[test]
    fn backend_system_hint_handles_separator_heavy_tee_attestation_backend_ids_without_falling_back_to_surface_tokens(
    ) {
        for (raw, expected) in [
            ("TEE::remote／attestation－quote＋SGX", "sgx"),
            ("tee|attestation|receipt|TDX", "tdx"),
            ("tee(remote attestation evidence)snp", "snp"),
            ("amd／sev－snp", "snp"),
        ] {
            assert_eq!(backend_system_hint(raw), Some(expected.into()), "raw={raw}");
        }
    }

    #[test]
    fn verification_backend_kind_system_hint_respects_family_prefixes_without_cross_family_assumptions(
    ) {
        assert_eq!(
            VerificationBackendKind::Custom("tee-tdx".into()).system_hint(),
            Some("tdx".into())
        );
        assert_eq!(
            VerificationBackendKind::Custom("tee-intel-sgx-dcap".into()).system_hint(),
            Some("sgx".into())
        );
        assert_eq!(
            VerificationBackendKind::Custom("TEE AMD-SEV-SNP".into()).system_hint(),
            Some("snp".into())
        );
        assert_eq!(
            VerificationBackendKind::Custom("zk_risc0".into()).system_hint(),
            Some("risc0".into())
        );
        assert_eq!(VerificationBackendKind::Noop.system_hint(), None);
    }
}
