use super::*;

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
                super::payload_parse::decode_base64(&self.proof).map_err(|reason| BackendExecutionError::MalformedProof {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVkRef {
    pub vk_ref: String,
    pub scope: String,
    pub zk_system: Option<String>,
}
