use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use trnm_types::TaskObject;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkBackendKind {
    Noop,
    Custom(String),
}

impl Default for ZkBackendKind {
    fn default() -> Self {
        Self::Noop
    }
}

impl ZkBackendKind {
    pub fn key(&self) -> &str {
        match self {
            Self::Noop => "noop",
            Self::Custom(key) => key.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationBackendConfig {
    pub tee_backend: ZkBackendKind,
    pub zk_backend: ZkBackendKind,
}

impl Default for VerificationBackendConfig {
    fn default() -> Self {
        Self {
            tee_backend: ZkBackendKind::Noop,
            zk_backend: ZkBackendKind::Noop,
        }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedZkProofPayload {
    pub task_id: u64,
    pub worker: String,
    pub proof_type: String,
    pub result_hash: String,
    pub vk_ref: String,
    #[serde(default = "default_proof_bytes_encoding")]
    pub proof_encoding: ProofBytesEncoding,
    pub proof: String,
    pub public_inputs: ZkPublicInputs,
}

impl ParsedZkProofPayload {
    pub fn decode_proof_bytes(&self) -> Result<Vec<u8>, BackendExecutionError> {
        match self.proof_encoding {
            ProofBytesEncoding::Base64 => {
                decode_base64(&self.proof).map_err(|reason| BackendExecutionError::InvalidProof {
                    backend: "zk:payload".to_string(),
                    reason,
                })
            }
            ProofBytesEncoding::Hex => hex::decode(self.proof.trim()).map_err(|_| {
                BackendExecutionError::InvalidProof {
                    backend: "zk:payload".to_string(),
                    reason: "invalid zk payload: proof is not valid hex".to_string(),
                }
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendVerificationRequest<'a> {
    pub backend_family: &'static str,
    pub task: &'a TaskObject,
    pub proof_data: &'a [u8],
    pub zk_payload: Option<&'a ParsedZkProofPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendVerificationSuccess {
    pub backend_id: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendSelectionError {
    #[error("verification backend '{backend}' is not registered for family '{family}'")]
    UnknownBackend { family: &'static str, backend: String },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendExecutionError {
    #[error("cryptographic verification backend not configured: {backend}")]
    NotConfigured { backend: String },
    #[error("verification backend '{backend}' rejected proof: {reason}")]
    InvalidProof { backend: String, reason: String },
    #[error("verification backend '{backend}' failed: {reason}")]
    Internal { backend: String, reason: String },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerificationBackendError {
    #[error(transparent)]
    Selection(#[from] BackendSelectionError),
    #[error(transparent)]
    Execution(#[from] BackendExecutionError),
}

pub trait ZkBackend: Send + Sync {
    fn backend_id(&self) -> &str;
    fn verify(&self, request: BackendVerificationRequest<'_>) -> Result<BackendVerificationSuccess, BackendExecutionError>;
}

#[derive(Default)]
pub struct ZkBackendRegistry {
    backends: HashMap<String, Arc<dyn ZkBackend>>,
}

impl ZkBackendRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            backends: HashMap::new(),
        };
        registry.register(Arc::new(NoopZkBackend));
        registry
    }

    pub fn register(&mut self, backend: Arc<dyn ZkBackend>) {
        self.backends
            .insert(backend.backend_id().trim().to_ascii_lowercase(), backend);
    }

    pub fn resolve(&self, family: &'static str, kind: &ZkBackendKind) -> Result<Arc<dyn ZkBackend>, BackendSelectionError> {
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

pub struct NoopZkBackend;

impl ZkBackend for NoopZkBackend {
    fn backend_id(&self) -> &str {
        "noop"
    }

    fn verify(&self, request: BackendVerificationRequest<'_>) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        Err(BackendExecutionError::NotConfigured {
            backend: format!("{}:{}", request.backend_family, self.backend_id()),
        })
    }
}

pub fn parse_zk_proof_payload(task: &TaskObject, proof_data: &[u8]) -> Result<ParsedZkProofPayload, BackendExecutionError> {
    let raw = std::str::from_utf8(proof_data).map_err(|_| BackendExecutionError::InvalidProof {
        backend: "zk:payload".to_string(),
        reason: "invalid zk payload: proof envelope is not valid utf-8".to_string(),
    })?;
    let body = raw.strip_prefix("ZK:").or_else(|| raw.strip_prefix("zk:")).ok_or_else(|| {
        BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: missing ZK: prefix".to_string(),
        }
    })?;
    let payload: ParsedZkProofPayload = serde_json::from_str(body).map_err(|_| BackendExecutionError::InvalidProof {
        backend: "zk:payload".to_string(),
        reason: "invalid zk payload: body must be canonical JSON object".to_string(),
    })?;

    let expected_hash = hex::encode(task.result_hash.ok_or_else(|| BackendExecutionError::InvalidProof {
        backend: "zk:payload".to_string(),
        reason: "invalid zk payload: missing task result_hash binding context".to_string(),
    })?);

    if payload.task_id != task.task_id {
        return Err(BackendExecutionError::InvalidProof { backend: "zk:payload".to_string(), reason: "invalid zk payload: task_id mismatch".to_string() });
    }
    if payload.worker != task.worker.as_deref().unwrap_or_default() {
        return Err(BackendExecutionError::InvalidProof { backend: "zk:payload".to_string(), reason: "invalid zk payload: worker mismatch".to_string() });
    }
    if !payload.proof_type.eq_ignore_ascii_case("zk") {
        return Err(BackendExecutionError::InvalidProof { backend: "zk:payload".to_string(), reason: "invalid zk payload: proof_type must be zk".to_string() });
    }
    if !payload.result_hash.eq_ignore_ascii_case(&expected_hash) {
        return Err(BackendExecutionError::InvalidProof { backend: "zk:payload".to_string(), reason: "invalid zk payload: result_hash mismatch".to_string() });
    }
    if payload.vk_ref.trim().is_empty() {
        return Err(BackendExecutionError::InvalidProof { backend: "zk:payload".to_string(), reason: "invalid zk payload: vk_ref is required".to_string() });
    }
    if payload.proof.trim().is_empty() {
        return Err(BackendExecutionError::InvalidProof { backend: "zk:payload".to_string(), reason: "invalid zk payload: proof bytes are required".to_string() });
    }
    let expected_public_inputs = vec![
        task.task_id.to_string(),
        task.worker.clone().unwrap_or_default(),
        expected_hash.clone(),
    ];
    let expected_order = vec!["task_id".to_string(), "worker".to_string(), "result_hash".to_string()];
    if payload.public_inputs.order != expected_order || payload.public_inputs.values != expected_public_inputs {
        return Err(BackendExecutionError::InvalidProof { backend: "zk:payload".to_string(), reason: "invalid zk payload: public_inputs mismatch".to_string() });
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
    fn parse_zk_proof_payload_accepts_canonical_json_vector() {
        let task = mock_task();
        let payload = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","worker","result_hash"],"values":["4242","worker-zk","1111111111111111111111111111111111111111111111111111111111111111"]}}"#).unwrap();
        assert_eq!(payload.vk_ref, "vk://trnm/dev/mock-groth16/v1");
        assert_eq!(payload.decode_proof_bytes().unwrap(), vec![1,2,3,4]);
    }

    #[test]
    fn parse_zk_proof_payload_rejects_public_input_mismatch() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"hex","proof":"01020304","public_inputs":{"order":["task_id","worker","result_hash"],"values":["4242","worker-zk","2222222222222222222222222222222222222222222222222222222222222222"]}}"#).unwrap_err();
        assert!(matches!(err, BackendExecutionError::InvalidProof{reason, ..} if reason.contains("public_inputs mismatch")));
    }

    #[test]
    fn parse_zk_proof_payload_rejects_malformed_json_before_crypto() {
        let task = mock_task();
        let err = parse_zk_proof_payload(&task, br#"ZK:{"task_id":4242,"worker":"worker-zk","proof_type":"zk","result_hash":"1111111111111111111111111111111111111111111111111111111111111111","vk_ref":"vk://trnm/dev/mock-groth16/v1","proof_encoding":"base64","proof":"!!!","public_inputs":{"order":["task_id"]"#).unwrap_err();
        assert!(matches!(err, BackendExecutionError::InvalidProof{reason, ..} if reason.contains("canonical JSON object")));
    }
}
