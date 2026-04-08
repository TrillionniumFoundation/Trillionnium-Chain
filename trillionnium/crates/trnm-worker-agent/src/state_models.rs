use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(crate) struct PersistedAckHashes {
    pub(crate) commit_tx_hash: Option<String>,
    pub(crate) reveal_tx_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WorkerState {
    pub(super) last_task_id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SubmissionRecord {
    pub(crate) ts_unix_ms: u128,
    pub(crate) task_id: u64,
    pub(crate) worker: String,
    pub(crate) nonce: Option<u64>,
    pub(crate) commit_hash: String,
    pub(crate) result_hash: String,
    pub(crate) salt_hex: String,
    pub(crate) commit_cmd: String,
    pub(crate) reveal_cmd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MessageIngressRecord {
    pub(crate) request_id: String,
    pub(crate) task_id: u64,
    pub(crate) channel: String,
    pub(crate) user_id: String,
    pub(crate) session_id: String,
    pub(crate) text: String,
    pub(crate) idempotency_key: String,
    pub(crate) status: String,
    pub(crate) created_at_unix_ms: u128,
    #[serde(default)]
    pub(crate) assigned_worker: Option<String>,
    #[serde(default)]
    pub(crate) assigned_at_unix_ms: Option<u128>,
    #[serde(default)]
    pub(crate) model_output: Option<String>,
    #[serde(default)]
    pub(crate) provider_request_id: Option<String>,
    #[serde(default)]
    pub(crate) provenance_schema_version: Option<String>,
    #[serde(default)]
    pub(crate) llm_provenance: Option<LlmProvenanceRecord>,
    #[serde(default)]
    pub(crate) result_hash: Option<String>,
    #[serde(default)]
    pub(crate) verifier_status: Option<String>,
    #[serde(default)]
    pub(crate) resolution_code: Option<String>,
    #[serde(default)]
    pub(crate) commit_tx_hash: Option<String>,
    #[serde(default)]
    pub(crate) reveal_tx_hash: Option<String>,
    #[serde(default)]
    pub(crate) adapter_error: Option<String>,
    #[serde(default)]
    pub(crate) reputation_delta: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LlmProvenanceRecord {
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) adapter: Option<String>,
    #[serde(default)]
    pub(crate) agent_protocol: Option<String>,
    #[serde(default)]
    pub(crate) compliance_profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AckRecord {
    pub(crate) ts_unix_ms: u128,
    pub(crate) task_id: u64,
    pub(crate) status: String,
    pub(crate) commit_tx_hash: Option<String>,
    pub(crate) reveal_tx_hash: Option<String>,
    #[serde(default)]
    pub(crate) reason_code: Option<String>,
    #[serde(default)]
    pub(crate) run_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WorkerEvent {
    pub(crate) ts_unix_ms: u128,
    pub(crate) run_id: String,
    pub(crate) event_type: String,
    pub(crate) task_id: u64,
    pub(crate) status: String,
    pub(crate) reason_code: String,
    pub(crate) commit_rc: i32,
    pub(crate) reveal_rc: i32,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProgressRecord {
    pub(crate) ts_unix_ms: u128,
    pub(crate) run_id: String,
    pub(crate) task_id: u64,
    pub(crate) state: String,
    pub(crate) note: String,
}

#[derive(Debug)]
pub(crate) struct AdapterExecResult {
    pub(crate) ok: bool,
    pub(crate) rc: i32,
    pub(crate) tx_hash: Option<String>,
    pub(crate) terminal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetryPolicy {
    pub(crate) max_retries: u32,
    pub(crate) backoff_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LlmAdapterPolicy {
    pub(crate) retry: RetryPolicy,
    pub(crate) timeout_ms: u64,
}

#[derive(Debug)]
pub(crate) struct TaskExecutionLock {
    pub(super) path: PathBuf,
}

impl Drop for TaskExecutionLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
