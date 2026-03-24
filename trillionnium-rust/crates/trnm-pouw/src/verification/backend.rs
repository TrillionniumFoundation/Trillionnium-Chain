use std::collections::{HashMap, HashSet};
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

pub fn normalize_backend_token(raw: &str) -> Option<String> {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>();
    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() || collapsed == "noop" {
        None
    } else {
        Some(collapsed)
    }
}

pub fn contains_forbidden_opaque_token_chars(raw: &str) -> bool {
    raw.chars()
        .any(|ch| !ch.is_ascii() || ch.is_whitespace() || ch.is_control())
}

pub fn backend_token_family_hint(raw: &str) -> Option<VerificationBackendFamily> {
    let normalized = normalize_backend_token(raw)?;
    match normalized.split_whitespace().next()? {
        "zk" => Some(VerificationBackendFamily::Zk),
        "tee" => Some(VerificationBackendFamily::Tee),
        _ => None,
    }
}

pub fn backend_system_hint(raw: &str) -> Option<String> {
    let normalized = normalize_backend_token(raw)?;
    let parts = normalized.split_whitespace().collect::<Vec<_>>();

    match parts.as_slice() {
        ["zk", system, ..] | ["tee", system, ..] => normalize_zk_system(system),
        [system, ..] => normalize_zk_system(system),
        _ => None,
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

pub fn backend_token_zk_system_hints(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    normalize_backend_token(raw)
        .into_iter()
        .flat_map(|token| {
            token
                .split_whitespace()
                .filter_map(normalize_zk_system)
                .filter(|system| seen.insert(system.clone()))
                .collect::<Vec<_>>()
        })
        .collect()
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
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ZkPayloadMeta {
    #[serde(default)]
    pub circuit_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub schema_version: String,
    pub vk_ref: String,
    #[serde(default)]
    pub proof_encoding: Option<ProofBytesEncoding>,
    pub proof: String,
    pub public_inputs: ZkPublicInputs,
    #[serde(default)]
    pub meta: ZkPayloadMeta,
}

impl ParsedZkProofPayload {
    pub fn proof_encoding(&self) -> Result<ProofBytesEncoding, BackendExecutionError> {
        self.proof_encoding
            .clone()
            .ok_or_else(|| BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: proof_encoding is required".to_string(),
            })
    }

    pub fn decode_proof_bytes(&self) -> Result<Vec<u8>, BackendExecutionError> {
        match self.proof_encoding()? {
            ProofBytesEncoding::Base64 => {
                decode_base64(&self.proof).map_err(|reason| BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason,
                })
            }
            ProofBytesEncoding::Hex => hex::decode(self.proof.as_str()).map_err(|_| {
                BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: proof is not valid hex".to_string(),
                }
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeEvidenceKind {
    Quote,
    Report,
}

impl TeeEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quote => "quote",
            Self::Report => "report",
        }
    }

    pub fn verifier_kind(self) -> &'static str {
        match self {
            Self::Quote => "quote-verifier",
            Self::Report => "report-verifier",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TeeVerifierMetadata {
    pub collateral: Option<String>,
    pub cert_chain: Option<String>,
    pub issuer: Option<String>,
    pub vcek: Option<String>,
    pub report_signer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTeeProofPayload {
    pub attestation_target: String,
    pub verifier_kind: String,
    pub measurement_field: String,
    pub measurement: String,
    pub report_data_hash: String,
    pub evidence_kind: TeeEvidenceKind,
    pub quote: Option<String>,
    pub report: Option<String>,
    pub verifier_metadata: TeeVerifierMetadata,
}

impl ParsedTeeProofPayload {
    pub fn evidence(&self) -> Option<&str> {
        match self.evidence_kind {
            TeeEvidenceKind::Quote => self.quote.as_deref(),
            TeeEvidenceKind::Report => self.report.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TeeAttestationTargetSpec {
    canonical: &'static str,
    measurement_field: &'static str,
    measurement_prefix: &'static str,
    evidence_kind: TeeEvidenceKind,
}

fn resolve_tee_attestation_target(raw: &str) -> Option<TeeAttestationTargetSpec> {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();

    match normalized.as_str() {
        "sgx" | "sgxdcap" => Some(TeeAttestationTargetSpec {
            canonical: "sgx-dcap",
            measurement_field: "mrenclave",
            measurement_prefix: "mrenclave:",
            evidence_kind: TeeEvidenceKind::Quote,
        }),
        "tdx" | "tdxqgs" => Some(TeeAttestationTargetSpec {
            canonical: "tdx-qgs",
            measurement_field: "mrtd",
            measurement_prefix: "mrtd:",
            evidence_kind: TeeEvidenceKind::Quote,
        }),
        "snp" | "sevsnp" => Some(TeeAttestationTargetSpec {
            canonical: "sev-snp",
            measurement_field: "measurement",
            measurement_prefix: "measurement:",
            evidence_kind: TeeEvidenceKind::Report,
        }),
        _ => None,
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
        self.entries.insert(resolved.vk_ref.clone(), resolved);
    }

    fn register_demo_dev_defaults(&mut self) {
        for (vk_ref, zk_system) in [
            ("vk://trnm/dev/mock-groth16/v1", Some("groth16")),
            ("vk://trnm/dev/mock-groth16/valid", Some("groth16")),
            ("vk://trnm/dev/mock-groth16/invalid", Some("groth16")),
            ("vk://trnm/dev/mock-plonk/v1", Some("plonk")),
            ("vk://trnm/dev/mock-plonk/valid", Some("plonk")),
            ("vk://trnm/dev/mock-plonk/invalid", Some("plonk")),
            ("vk://trnm/dev/mock-halo2/v1", Some("halo2")),
            ("vk://trnm/dev/mock-stark/v1", Some("stark")),
            ("vk://trnm/dev/mock-risc0/v1", Some("risc0")),
            ("vk://trnm/dev/mock-sp1/v1", Some("sp1")),
            ("vk://trnm/dev/mock-no-system/v1", None),
        ] {
            self.register(ResolvedVkRef {
                vk_ref: vk_ref.to_string(),
                scope: "dev".to_string(),
                zk_system: zk_system.map(str::to_string),
            });
        }
    }
}

impl VkRefResolver for VkRefRegistry {
    fn resolve(&self, vk_ref: &str) -> Result<ResolvedVkRef, VkRefResolutionError> {
        if vk_ref.trim().is_empty() {
            return Err(VkRefResolutionError::Missing);
        }

        self.entries
            .get(vk_ref)
            .cloned()
            .ok_or_else(|| VkRefResolutionError::Unknown {
                vk_ref: vk_ref.to_string(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendVerificationRequest<'a> {
    pub family: VerificationBackendFamily,
    pub task: &'a TaskObject,
    pub proof_data: &'a [u8],
    /// Parsed canonical TEE attestation payload, when the verifier/backend pair
    /// opts into the structured quote/report handoff contract.
    pub tee_payload: Option<&'a ParsedTeeProofPayload>,
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
        let raw_key = backend.backend_id().trim().to_ascii_lowercase();
        self.backends.insert(raw_key, Arc::clone(&backend));

        if let Some(normalized_key) = normalize_backend_token(backend.backend_id()) {
            self.backends.entry(normalized_key).or_insert(backend);
        }
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
            .or_else(|| {
                normalize_backend_token(kind.key())
                    .and_then(|normalized_key| self.backends.get(&normalized_key).cloned())
            })
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

fn parse_tee_kv_fields(body: &str) -> Result<HashMap<String, String>, BackendExecutionError> {
    let mut fields = HashMap::new();
    for entry in body.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((raw_key, raw_value)) = trimmed.split_once('=') else {
            return Err(BackendExecutionError::MalformedProof {
                backend: "tee:payload".to_string(),
                reason: format!("invalid tee receipt field '{trimmed}'"),
            });
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        if key.is_empty() || value.is_empty() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "tee:payload".to_string(),
                reason: format!("invalid tee receipt field '{trimmed}'"),
            });
        }
        if fields.insert(key.clone(), value).is_some() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "tee:payload".to_string(),
                reason: format!("duplicate tee receipt field '{key}'"),
            });
        }
    }
    Ok(fields)
}

fn required_tee_field<'a>(
    fields: &'a HashMap<String, String>,
    key: &str,
) -> Result<&'a str, BackendExecutionError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| BackendExecutionError::MalformedProof {
            backend: "tee:payload".to_string(),
            reason: format!("invalid tee receipt: missing {key}"),
        })
}

fn has_visible_tee_metadata(value: Option<&str>) -> bool {
    value.is_some_and(|raw| !raw.trim().is_empty())
}

pub fn parse_tee_attestation_payload(
    proof_data: &[u8],
) -> Result<ParsedTeeProofPayload, BackendExecutionError> {
    let raw =
        std::str::from_utf8(proof_data).map_err(|_| BackendExecutionError::MalformedProof {
            backend: "tee:payload".to_string(),
            reason: "tee receipt must be valid utf-8".to_string(),
        })?;
    let body = raw
        .strip_prefix("TEE:")
        .or_else(|| raw.strip_prefix("tee:"))
        .ok_or_else(|| BackendExecutionError::MalformedProof {
            backend: "tee:payload".to_string(),
            reason: "tee receipt must start with TEE:".to_string(),
        })?;
    let fields = parse_tee_kv_fields(body)?;

    let raw_target = required_tee_field(&fields, "attestation_target")?;
    let target = resolve_tee_attestation_target(raw_target).ok_or_else(|| {
        BackendExecutionError::MalformedProof {
            backend: "tee:payload".to_string(),
            reason: format!(
                "invalid tee receipt: unsupported attestation_target '{}'",
                raw_target.trim()
            ),
        }
    })?;

    let measurement = required_tee_field(&fields, "measurement")?.to_string();
    if !measurement
        .trim()
        .to_ascii_lowercase()
        .starts_with(target.measurement_prefix)
    {
        return Err(BackendExecutionError::MalformedProof {
            backend: "tee:payload".to_string(),
            reason: format!(
                "invalid tee receipt: target '{}' requires measurement prefix '{}'",
                target.canonical, target.measurement_prefix
            ),
        });
    }

    let report_data_hash = required_tee_field(&fields, "report_data_hash")?
        .trim()
        .to_ascii_lowercase();
    let quote = fields.get("quote").cloned();
    let report = fields.get("report").cloned();
    let verifier_metadata = TeeVerifierMetadata {
        collateral: fields.get("collateral").cloned(),
        cert_chain: fields.get("cert_chain").cloned(),
        issuer: fields.get("issuer").cloned(),
        vcek: fields.get("vcek").cloned(),
        report_signer: fields.get("report_signer").cloned(),
    };

    match target.evidence_kind {
        TeeEvidenceKind::Quote if quote.is_none() => {
            return Err(BackendExecutionError::MalformedProof {
                backend: "tee:payload".to_string(),
                reason: format!(
                    "invalid tee receipt: target '{}' requires quote evidence",
                    target.canonical
                ),
            })
        }
        TeeEvidenceKind::Report if report.is_none() => {
            return Err(BackendExecutionError::MalformedProof {
                backend: "tee:payload".to_string(),
                reason: format!(
                    "invalid tee receipt: target '{}' requires report evidence",
                    target.canonical
                ),
            })
        }
        _ => {}
    }

    match target.evidence_kind {
        TeeEvidenceKind::Quote => {
            if !has_visible_tee_metadata(verifier_metadata.collateral.as_deref()) {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires collateral metadata",
                        target.canonical
                    ),
                });
            }
            if !has_visible_tee_metadata(verifier_metadata.cert_chain.as_deref()) {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires cert_chain metadata",
                        target.canonical
                    ),
                });
            }
            if !has_visible_tee_metadata(verifier_metadata.issuer.as_deref()) {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires issuer metadata",
                        target.canonical
                    ),
                });
            }
            if verifier_metadata.vcek.is_some() || verifier_metadata.report_signer.is_some() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' does not accept report verifier metadata",
                        target.canonical
                    ),
                });
            }
        }
        TeeEvidenceKind::Report => {
            if !has_visible_tee_metadata(verifier_metadata.vcek.as_deref()) {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires vcek metadata",
                        target.canonical
                    ),
                });
            }
            if !has_visible_tee_metadata(verifier_metadata.cert_chain.as_deref()) {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires cert_chain metadata",
                        target.canonical
                    ),
                });
            }
            if !has_visible_tee_metadata(verifier_metadata.report_signer.as_deref()) {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' requires report_signer metadata",
                        target.canonical
                    ),
                });
            }
            if verifier_metadata.collateral.is_some() || verifier_metadata.issuer.is_some() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "tee:payload".to_string(),
                    reason: format!(
                        "invalid tee receipt: target '{}' does not accept quote verifier metadata",
                        target.canonical
                    ),
                });
            }
        }
    }

    Ok(ParsedTeeProofPayload {
        attestation_target: target.canonical.to_string(),
        verifier_kind: target.evidence_kind.verifier_kind().to_string(),
        measurement_field: target.measurement_field.to_string(),
        measurement,
        report_data_hash,
        evidence_kind: target.evidence_kind,
        quote,
        report,
        verifier_metadata,
    })
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
        .ok_or_else(|| BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: missing canonical ZK: prefix".to_string(),
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
    if payload.proof_type != "zk" {
        let reason = if payload.proof_type.eq_ignore_ascii_case("zk") {
            "invalid zk payload: proof_type must use canonical lowercase token 'zk'".to_string()
        } else {
            "invalid zk payload: proof_type must be zk".to_string()
        };
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason,
        });
    }
    if payload.result_hash != expected_hash {
        let reason = if payload.result_hash.eq_ignore_ascii_case(&expected_hash) {
            "invalid zk payload: result_hash must use canonical lowercase hex".to_string()
        } else {
            "invalid zk payload: result_hash mismatch".to_string()
        };
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason,
        });
    }
    let raw_zk_system =
        payload
            .zk_system
            .as_deref()
            .ok_or_else(|| BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: zk_system is required".to_string(),
            })?;
    let normalized_zk_system = normalize_zk_system(raw_zk_system).ok_or_else(|| {
        BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: unsupported zk_system '{}'",
                raw_zk_system.trim()
            ),
        }
    })?;
    if raw_zk_system != normalized_zk_system {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: zk_system must use canonical token '{}'",
                normalized_zk_system
            ),
        });
    }
    if payload.schema_version != "trnm.zk.payload.v0" {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: schema_version must be trnm.zk.payload.v0".to_string(),
        });
    }
    if payload.vk_ref.trim().is_empty() {
        return Err(VkRefResolutionError::Missing.into_backend_execution_error());
    }
    if payload.vk_ref != payload.vk_ref.trim() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: vk_ref must not contain surrounding whitespace"
                .to_string(),
        });
    }
    if payload
        .vk_ref
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: vk_ref must be a single opaque token without embedded whitespace or control characters"
                .to_string(),
        });
    }
    if let Some(backend_id) = payload.backend_id.as_deref() {
        if backend_id != backend_id.trim() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_id must not contain surrounding whitespace"
                    .to_string(),
            });
        }
        if backend_id.is_empty() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_id must not be empty when provided"
                    .to_string(),
            });
        }
        if contains_forbidden_opaque_token_chars(backend_id) {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_id must be a single opaque token without embedded whitespace or control characters"
                    .to_string(),
            });
        }
        if backend_id.eq_ignore_ascii_case("noop") {
            if backend_id != "noop" {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: legacy noop backend_id must use canonical lowercase token 'noop'"
                        .to_string(),
                });
            }
            if payload.backend_version.is_some() {
                return Err(BackendExecutionError::MalformedProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: backend_version must not be provided for legacy noop backend_id"
                        .to_string(),
                });
            }
        } else if normalize_backend_token(backend_id).is_none() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: backend_id '{}' must contain at least one visible canonical backend token segment",
                    backend_id
                ),
            });
        }
    }
    if let Some(backend_version) = payload.backend_version.as_deref() {
        if backend_version != backend_version.trim() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason:
                    "invalid zk payload: backend_version must not contain surrounding whitespace"
                        .to_string(),
            });
        }
        if backend_version.is_empty() {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_version must not be empty when provided"
                    .to_string(),
            });
        }
        if contains_forbidden_opaque_token_chars(backend_version) {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_version must be a single opaque token without embedded whitespace or control characters"
                    .to_string(),
            });
        }
        if payload
            .backend_id
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
        {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: backend_version requires backend_id".to_string(),
            });
        }
    }
    if payload.proof.trim().is_empty() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof bytes are required".to_string(),
        });
    }
    if payload.proof != payload.proof.trim() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof must not contain surrounding whitespace".to_string(),
        });
    }
    if payload
        .proof
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: proof must be encoded as a single token without embedded whitespace or control characters".to_string(),
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

    if payload.public_inputs.order.len() != payload.public_inputs.values.len() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: public_inputs order/value length mismatch".to_string(),
        });
    }

    let mut seen_fields = HashSet::with_capacity(payload.public_inputs.order.len());
    for field in &payload.public_inputs.order {
        if !seen_fields.insert(field.as_str()) {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!("invalid zk payload: duplicate public_inputs field '{field}'"),
            });
        }
    }

    if payload.public_inputs.order != expected_order {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: public_inputs order is not canonical".to_string(),
        });
    }

    if payload.public_inputs.values != expected_public_inputs {
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
    let resolved = resolver
        .resolve(&payload.vk_ref)
        .map_err(VkRefResolutionError::into_backend_execution_error)?;

    if let (Some(payload_system), Some(resolved_system)) = (
        payload.zk_system.as_deref().and_then(normalize_zk_system),
        resolved.zk_system.as_deref().and_then(normalize_zk_system),
    ) {
        if payload_system != resolved_system {
            return Err(BackendExecutionError::InvalidProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: zk_system '{payload_system}' does not match vk_ref '{}'",
                    resolved.vk_ref
                ),
            });
        }
    }

    Ok(resolved)
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

    struct MockRegistryBackend {
        backend_id: &'static str,
    }

    impl ZkBackend for MockRegistryBackend {
        fn backend_id(&self) -> &str {
            self.backend_id
        }

        fn verify(
            &self,
            _request: BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            Ok(BackendVerificationSuccess {
                backend_id: self.backend_id.into(),
            })
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
                tee_payload: None,
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
    fn parse_tee_attestation_payload_accepts_quote_verifier_target_matrix() {
        let payload = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel"
        )
        .unwrap();

        assert_eq!(payload.attestation_target, "sgx-dcap");
        assert_eq!(payload.verifier_kind, "quote-verifier");
        assert_eq!(payload.measurement_field, "mrenclave");
        assert_eq!(payload.evidence_kind, TeeEvidenceKind::Quote);
        assert_eq!(payload.evidence(), Some("quote-sgx-dcap-demo-v1"));
        assert_eq!(
            payload.verifier_metadata.collateral.as_deref(),
            Some("intel-dcap-collateral-demo-v1")
        );
        assert_eq!(
            payload.verifier_metadata.cert_chain.as_deref(),
            Some("intel-dcap-cert-chain-demo-v1")
        );
        assert_eq!(payload.verifier_metadata.issuer.as_deref(), Some("intel"));
    }

    #[test]
    fn parse_tee_attestation_payload_accepts_report_verifier_target_matrix() {
        let payload = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=abababababababababababababababababababababababababababababababab,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd"
        )
        .unwrap();

        assert_eq!(payload.attestation_target, "sev-snp");
        assert_eq!(payload.verifier_kind, "report-verifier");
        assert_eq!(payload.measurement_field, "measurement");
        assert_eq!(payload.evidence_kind, TeeEvidenceKind::Report);
        assert_eq!(payload.evidence(), Some("report-sev-snp-demo-v1"));
        assert_eq!(
            payload.verifier_metadata.vcek.as_deref(),
            Some("amd-vcek-demo-v1")
        );
        assert_eq!(
            payload.verifier_metadata.cert_chain.as_deref(),
            Some("amd-cert-chain-demo-v1")
        );
        assert_eq!(
            payload.verifier_metadata.report_signer.as_deref(),
            Some("amd")
        );
    }

    #[test]
    fn parse_tee_attestation_payload_rejects_quote_target_without_quote_fail_closed() {
        let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=tdx-qgs,measurement=mrtd:demo-tdx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,collateral=intel-tdx-qgs-collateral-demo-v1,cert_chain=intel-tdx-qgs-cert-chain-demo-v1,issuer=intel"
        )
        .unwrap_err();

        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("requires quote evidence"))
        );
    }

    #[test]
    fn parse_tee_attestation_payload_rejects_quote_target_without_collateral_metadata_fail_closed()
    {
        let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-sgx-dcap-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel"
        )
        .unwrap_err();

        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("requires collateral metadata"))
        );
    }

    #[test]
    fn parse_tee_attestation_payload_rejects_report_target_with_quote_metadata_fail_closed() {
        let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=abababababababababababababababababababababababababababababababab,report=report-sev-snp-demo-v1,collateral=wrong-shape,cert_chain=amd-cert-chain-demo-v1,issuer=intel,vcek=amd-vcek-demo-v1,report_signer=amd"
        )
        .unwrap_err();

        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("does not accept quote verifier metadata"))
        );
    }

    #[test]
    fn parse_tee_attestation_payload_rejects_measurement_prefix_mismatch_fail_closed() {
        let err = parse_tee_attestation_payload(
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,attestation_target=tdx-qgs,measurement=mrenclave:wrong-slot,report_data_hash=abababababababababababababababababababababababababababababababab,quote=quote-tdx-qgs-demo-v1,collateral=intel-tdx-qgs-collateral-demo-v1,cert_chain=intel-tdx-qgs-cert-chain-demo-v1,issuer=intel"
        )
        .unwrap_err();

        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("requires measurement prefix 'mrtd:'"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_accepts_canonical_json_vector() {
        let task = mock_task();
        let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"circuit_id":"settlement-result-v1"}}"#).unwrap();
        assert_eq!(payload.vk_ref, "vk://trnm/dev/mock-groth16/v1");
        assert_eq!(payload.zk_system.as_deref(), Some("groth16"));
        assert_eq!(payload.backend_id.as_deref(), Some("mock-zk"));
        assert_eq!(payload.schema_version, "trnm.zk.payload.v0");
        assert_eq!(payload.decode_proof_bytes().unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn parse_zk_proof_payload_rejects_non_canonical_zk_system_aliases_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":" Groth-16 ","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();

        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("zk_system must use canonical token 'groth16'"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_zk_system_with_surrounding_unicode_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"\u{2003}groth16\u{2003}\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();

        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("zk_system must use canonical token 'groth16'"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_public_input_mismatch() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","2222222222222222222222222222222222222222222222222222222222222222"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::InvalidProof { reason, .. } if reason.contains("public_inputs mismatch"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_non_canonical_top_level_proof_type_case() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"ZK","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::InvalidProof { reason, .. } if reason.contains("canonical lowercase token 'zk'"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_non_canonical_top_level_result_hash_case() {
        let mut task = mock_task();
        task.result_hash = Some([0xab; 32]);
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","abababababababababababababababababababababababababababababababab"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::InvalidProof { reason, .. } if reason.contains("canonical lowercase hex"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_public_input_length_mismatch_as_malformed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("order/value length mismatch"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_duplicate_public_input_field_as_malformed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","worker"],"values":["4242","zk","worker-zk","worker-zk"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("duplicate public_inputs field 'worker'"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_non_canonical_public_input_order_as_malformed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["worker","task_id","proof_type","result_hash"],"values":["worker-zk","4242","zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("public_inputs order is not canonical"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_unsupported_zk_system_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"bulletproofs","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
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
    fn parse_zk_proof_payload_rejects_lowercase_prefix_as_non_canonical() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"zk:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("missing canonical ZK: prefix"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_unknown_top_level_field_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","unexpected_binding":"worker-zk","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_unknown_meta_field_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"circuit_id":"settlement-result-v1","unexpected":"drift"}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_duplicate_meta_container_field_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"circuit_id":"settlement-result-v1"},"meta":{"circuit_id":"settlement-result-v2"}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_unknown_public_inputs_field_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"],"digest":"deadbeef"}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_unknown_proof_encoding_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"raw-bytes","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_non_canonical_proof_encoding_case_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"HEX","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_duplicate_top_level_binding_field_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","task_id":9999,"public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_duplicate_public_inputs_container_field_fail_closed() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"],"values":["9999","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("canonical JSON object"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_missing_top_level_schema_version() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"mock-zk","backend_version":"v1","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]},"meta":{"circuit_id":"settlement-result-v1"}}"#).unwrap_err();
        assert!(matches!(err, BackendExecutionError::MalformedProof { .. }));
    }

    #[test]
    fn parse_zk_proof_payload_rejects_missing_proof_encoding_per_protocol_v0() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("proof_encoding is required"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_proof_with_surrounding_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":" 01020304 ","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("proof must not contain surrounding whitespace"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_proof_with_embedded_unicode_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"0102\u{2003}0304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("proof must be encoded as a single token without embedded whitespace or control characters"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_vk_ref_with_surrounding_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"  vk://trnm/dev/mock-groth16/v1  ","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("vk_ref must not contain surrounding whitespace"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_vk_ref_with_embedded_whitespace_or_control_chars() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/line\nbreak","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("single opaque token") && reason.contains("embedded whitespace or control characters"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_vk_ref_with_embedded_unicode_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/line\u{2003}break\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("single opaque token") && reason.contains("embedded whitespace or control characters"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_backend_id_with_surrounding_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"  groth16-demo  ","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id must not contain surrounding whitespace"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_backend_id_with_surrounding_unicode_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"backend_id\":\"\u{2003}groth16-demo\u{2003}\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id must not contain surrounding whitespace"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_backend_id_with_embedded_whitespace_or_control_chars() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo\talt","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id must be a single opaque token") && reason.contains("embedded whitespace or control characters"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_backend_id_with_embedded_unicode_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"backend_id\":\"groth16-demo\u{2003}alt\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id must be a single opaque token") && reason.contains("embedded whitespace or control characters"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_backend_version_with_surrounding_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"  v1  ","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version must not contain surrounding whitespace"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_backend_version_with_surrounding_unicode_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"backend_id\":\"groth16-demo\",\"backend_version\":\"\u{2003}v1\u{2003}\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version must not contain surrounding whitespace"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_backend_version_with_embedded_whitespace_or_control_chars() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"v1\nnext","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version must be a single opaque token") && reason.contains("embedded whitespace or control characters"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_backend_version_with_embedded_unicode_whitespace() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, "ZK:{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"groth16\",\"backend_id\":\"groth16-demo\",\"backend_version\":\"v1\u{2003}next\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"vk://trnm/dev/mock-groth16/v1\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}".as_bytes()).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version must be a single opaque token") && reason.contains("embedded whitespace or control characters"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_empty_backend_id_when_provided() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id must not be empty when provided"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_backend_id_without_visible_canonical_token_segments() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"---","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_id '---'") && reason.contains("visible canonical backend token segment"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_still_allows_noop_backend_id_as_explicit_legacy_no_backend_selector()
    {
        let task = mock_task();
        let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"noop","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap();
        assert_eq!(payload.backend_id.as_deref(), Some("noop"));
    }

    #[test]
    fn parse_zk_proof_payload_rejects_empty_backend_version_when_provided() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_id":"groth16-demo","backend_version":"","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version must not be empty when provided"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_backend_version_without_backend_id() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","backend_version":"v1","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("backend_version requires backend_id"))
        );
    }

    #[test]
    fn parse_zk_proof_payload_rejects_missing_zk_system_per_protocol_v0() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap_err();
        assert!(
            matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("zk_system is required"))
        );
    }

    #[test]
    fn resolve_zk_vk_ref_rejects_unknown_vk_ref_fail_closed() {
        let task = mock_task();
        let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-groth16/unknown","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap();
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
    fn resolve_zk_vk_ref_rejects_case_drift_for_opaque_vk_refs() {
        let task = mock_task();
        let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"VK://TRNM/DEV/MOCK-GROTH16/V1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap();
        let resolver = VkRefRegistry::new();

        let err = resolve_zk_vk_ref(&resolver, &payload).unwrap_err();

        assert_eq!(
            err,
            BackendExecutionError::InvalidProof {
                backend: "zk:payload".into(),
                reason: "invalid zk payload: unknown vk_ref 'VK://TRNM/DEV/MOCK-GROTH16/V1'".into(),
            }
        );
    }

    #[test]
    fn vk_ref_registry_rejects_surrounding_whitespace_without_silent_trim() {
        let resolver = VkRefRegistry::new();

        let err = resolver
            .resolve("  vk://trnm/dev/mock-groth16/v1  ")
            .unwrap_err();

        assert_eq!(
            err,
            VkRefResolutionError::Unknown {
                vk_ref: "  vk://trnm/dev/mock-groth16/v1  ".into(),
            }
        );
    }

    #[test]
    fn vk_ref_registry_rejects_surrounding_unicode_whitespace_without_silent_trim() {
        let resolver = VkRefRegistry::new();

        let err = resolver
            .resolve("\u{2003}vk://trnm/dev/mock-groth16/v1\u{2003}")
            .unwrap_err();

        assert_eq!(
            err,
            VkRefResolutionError::Unknown {
                vk_ref: "\u{2003}vk://trnm/dev/mock-groth16/v1\u{2003}".into(),
            }
        );
    }

    #[test]
    fn vk_ref_registry_rejects_embedded_control_whitespace_without_silent_normalization() {
        let resolver = VkRefRegistry::new();

        let err = resolver
            .resolve("vk://trnm/dev/mock-groth16/line\nbreak")
            .unwrap_err();

        assert_eq!(
            err,
            VkRefResolutionError::Unknown {
                vk_ref: "vk://trnm/dev/mock-groth16/line\nbreak".into(),
            }
        );
    }

    #[test]
    fn vk_ref_registry_rejects_embedded_unicode_whitespace_without_silent_normalization() {
        let resolver = VkRefRegistry::new();

        let err = resolver
            .resolve("vk://trnm/dev/mock-groth16/line\u{2003}break")
            .unwrap_err();

        assert_eq!(
            err,
            VkRefResolutionError::Unknown {
                vk_ref: "vk://trnm/dev/mock-groth16/line\u{2003}break".into(),
            }
        );
    }

    #[test]
    fn vk_ref_registry_rejects_embedded_zero_width_format_char_without_silent_normalization() {
        let resolver = VkRefRegistry::new();

        let err = resolver
            .resolve("vk://trnm/dev/mock-groth16/line\u{200b}break")
            .unwrap_err();

        assert_eq!(
            err,
            VkRefResolutionError::Unknown {
                vk_ref: "vk://trnm/dev/mock-groth16/line\u{200b}break".into(),
            }
        );
    }

    #[test]
    fn resolve_zk_vk_ref_rejects_payload_zk_system_mismatch_against_registered_vk_metadata() {
        let task = mock_task();
        let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","zk_system":"groth16","schema_version":"trnm.zk.payload.v0","vk_ref":"vk://trnm/dev/mock-plonk/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","proof_type","worker","result_hash"],"values":["4242","zk","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap();
        let resolver = VkRefRegistry::new();

        let err = resolve_zk_vk_ref(&resolver, &payload).unwrap_err();

        assert_eq!(
            err,
            BackendExecutionError::InvalidProof {
                backend: "zk:payload".into(),
                reason: "invalid zk payload: zk_system 'groth16' does not match vk_ref 'vk://trnm/dev/mock-plonk/v1'".into(),
            }
        );
    }

    #[test]
    fn resolve_zk_vk_ref_returns_registered_system_metadata() {
        let resolver = VkRefRegistry::new();

        for (zk_system, backend_id, vk_ref) in [
            ("plonk", "plonk-demo", "vk://trnm/dev/mock-plonk/v1"),
            ("halo2", "halo2-demo", "vk://trnm/dev/mock-halo2/v1"),
            ("stark", "stark-demo", "vk://trnm/dev/mock-stark/v1"),
            ("risc0", "risc0-demo", "vk://trnm/dev/mock-risc0/v1"),
            ("sp1", "sp1-demo", "vk://trnm/dev/mock-sp1/v1"),
        ] {
            let task = mock_task();
            let payload = parse_zk_proof_payload(
                &task,
                format!(
                    "ZK:{{\"task_id\":4242,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"zk_system\":\"{zk_system}\",\"backend_id\":\"{backend_id}\",\"backend_version\":\"v1\",\"schema_version\":\"trnm.zk.payload.v0\",\"vk_ref\":\"{vk_ref}\",\"proof_encoding\":\"hex\",\"proof\":\"01020304\",\"public_inputs\":{{\"order\":[\"task_id\",\"proof_type\",\"worker\",\"result_hash\"],\"values\":[\"4242\",\"zk\",\"worker-zk\",\"1111111111111111111111111111111111111111111111111111111111111111\"]}}}}"
                )
                .as_bytes(),
            )
            .unwrap();

            let resolved = resolve_zk_vk_ref(&resolver, &payload).unwrap();

            assert_eq!(resolved.vk_ref, vk_ref);
            assert_eq!(resolved.scope, "dev");
            assert_eq!(resolved.zk_system.as_deref(), Some(zk_system));
        }
    }

    #[test]
    fn resolve_zk_vk_ref_accepts_registered_reference_with_custom_metadata() {
        let mut resolver = VkRefRegistry::new();
        resolver.register(ResolvedVkRef {
            vk_ref: "vk://trnm/dev/mock-groth16/mixedcase".into(),
            scope: "dev".into(),
            zk_system: Some("groth16".into()),
        });

        let payload = ParsedZkProofPayload {
            task_id: 4242,
            worker: "worker-zk".into(),
            proof_type: "zk".into(),
            result_hash: "1111111111111111111111111111111111111111111111111111111111111111".into(),
            zk_system: Some("groth16".into()),
            backend_id: Some("mock-zk".into()),
            backend_version: Some("v1".into()),
            schema_version: "trnm.zk.payload.v0".into(),
            vk_ref: "vk://trnm/dev/mock-groth16/mixedcase".into(),
            proof_encoding: Some(ProofBytesEncoding::Hex),
            proof: "01020304".into(),
            public_inputs: ZkPublicInputs {
                order: vec![
                    "task_id".into(),
                    "proof_type".into(),
                    "worker".into(),
                    "result_hash".into(),
                ],
                values: vec![
                    "4242".into(),
                    "zk".into(),
                    "worker-zk".into(),
                    "1111111111111111111111111111111111111111111111111111111111111111".into(),
                ],
            },
            meta: ZkPayloadMeta {
                circuit_id: Some("settlement-result-v1".into()),
            },
        };

        let resolved = resolve_zk_vk_ref(&resolver, &payload).unwrap();

        assert_eq!(resolved.vk_ref, "vk://trnm/dev/mock-groth16/mixedcase");
        assert_eq!(resolved.scope, "dev");
        assert_eq!(resolved.zk_system.as_deref(), Some("groth16"));
    }

    #[test]
    fn normalize_zk_system_accepts_common_aliases() {
        assert_eq!(normalize_zk_system("groth16"), Some("groth16".into()));
        assert_eq!(normalize_zk_system(" Groth-16 "), Some("groth16".into()));
        assert_eq!(normalize_zk_system("PLONK"), Some("plonk".into()));
        assert_eq!(normalize_zk_system("mock-zk"), None);
    }

    #[test]
    fn normalize_zk_system_rejects_reserved_custom_namespace_until_versioned_support_lands() {
        assert_eq!(normalize_zk_system("custom:acme:sumcheck"), None);
        assert_eq!(normalize_zk_system(" custom:acme:sumcheck "), None);
    }

    #[test]
    fn normalize_backend_token_rejects_noop_aliases_as_non_explicit_backend() {
        assert_eq!(normalize_backend_token("noop"), None);
        assert_eq!(normalize_backend_token(" NOOP "), None);
        assert_eq!(normalize_backend_token("noop!!!"), None);
        assert_eq!(
            normalize_backend_token("groth16-demo"),
            Some("groth16 demo".into())
        );
    }

    #[test]
    fn backend_token_zk_system_hints_extracts_all_canonical_system_hints() {
        assert_eq!(
            backend_token_zk_system_hints("groth16-demo"),
            vec!["groth16"]
        );
        assert_eq!(
            backend_token_zk_system_hints("groth16-plonk-demo"),
            vec!["groth16", "plonk"]
        );
        assert_eq!(
            backend_token_zk_system_hints("groth16-groth16-demo"),
            vec!["groth16"]
        );
        assert_eq!(
            backend_token_zk_system_hints("tee-groth16-demo"),
            vec!["groth16"]
        );
        assert!(backend_token_zk_system_hints("mock-zk").is_empty());
    }

    #[test]
    fn backend_token_family_and_system_hints_canonicalize_case_drifted_alias_segments() {
        assert_eq!(
            backend_token_family_hint("ZK-Groth-16-demo"),
            Some(VerificationBackendFamily::Zk)
        );
        assert_eq!(
            backend_token_zk_system_hints("ZK-Groth-16-GROTH16-demo"),
            vec!["groth16"]
        );
        assert_eq!(
            backend_token_zk_system_hints("TEE-PLONK-Plonk-demo"),
            vec!["plonk"]
        );
    }

    #[test]
    fn backend_registry_resolves_canonicalized_backend_aliases_fail_closed_without_guessing() {
        let mut registry = VerificationBackendRegistry::new();
        registry.register(Arc::new(MockRegistryBackend {
            backend_id: "zk groth16 demo",
        }));

        let backend = registry
            .resolve(
                VerificationBackendFamily::Zk,
                &VerificationBackendKind::Custom("zk-groth16-demo".into()),
            )
            .unwrap();
        assert_eq!(backend.backend_id(), "zk groth16 demo");

        let err = match registry.resolve(
            VerificationBackendFamily::Zk,
            &VerificationBackendKind::Custom("zk-groth16-plonk-demo".into()),
        ) {
            Ok(found) => panic!("expected unknown backend, got {}", found.backend_id()),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            BackendSelectionError::UnknownBackend { family, backend }
                if family == VerificationBackendFamily::Zk
                    && backend == "zk-groth16-plonk-demo"
        ));
    }

    #[test]
    fn backend_system_hint_only_returns_canonical_system_tokens() {
        assert_eq!(backend_system_hint("groth16-demo"), Some("groth16".into()));
        assert_eq!(
            backend_system_hint("zk-groth16-demo"),
            Some("groth16".into())
        );
        assert_eq!(backend_system_hint("zk-demo"), None);
        assert_eq!(backend_system_hint("mock-zk"), None);
    }

    #[test]
    fn backend_token_family_hint_detects_explicit_family_prefixes() {
        assert_eq!(
            backend_token_family_hint("zk-groth16-demo"),
            Some(VerificationBackendFamily::Zk)
        );
        assert_eq!(
            backend_token_family_hint(" tee-groth16-demo "),
            Some(VerificationBackendFamily::Tee)
        );
        assert_eq!(backend_token_family_hint("groth16-demo"), None);
        assert_eq!(backend_token_family_hint("noop"), None);
    }

    #[test]
    fn backend_execution_error_classification_matches_v0_taxonomy() {
        let cases = vec![
            (
                BackendExecutionError::NotConfigured {
                    backend: "zk:noop".into(),
                },
                VerificationErrorClass::Unavailable,
            ),
            (
                BackendExecutionError::Unavailable {
                    backend: "zk:groth16-demo".into(),
                    reason: "registry temporarily unavailable".into(),
                },
                VerificationErrorClass::Unavailable,
            ),
            (
                BackendExecutionError::InvalidProof {
                    backend: "zk:groth16-demo".into(),
                    reason: "proof/vk mismatch".into(),
                },
                VerificationErrorClass::Invalid,
            ),
            (
                BackendExecutionError::MalformedProof {
                    backend: "zk:payload".into(),
                    reason: "public_inputs order is not canonical".into(),
                },
                VerificationErrorClass::Malformed,
            ),
            (
                BackendExecutionError::Internal {
                    backend: "zk:groth16-demo".into(),
                    reason: "ffi panic".into(),
                },
                VerificationErrorClass::BackendError,
            ),
        ];

        for (err, expected_class) in cases {
            assert_eq!(err.error_class(), expected_class);
        }
    }
}
