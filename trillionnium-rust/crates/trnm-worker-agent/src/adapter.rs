use serde::Deserialize;
use std::path::PathBuf;

pub(crate) use crate::adapter_error::{
    adapter_error_signal, classify_adapter_error, is_deterministic_rejection,
    is_idempotent_duplicate_ok, reputation_delta, AdapterError, AdapterErrorKind, ReputationSignal,
};
use crate::adapter_parse::{
    normalized_agent_protocol, normalized_compliance_profile, normalized_provenance_label,
    normalized_provider_request_id,
};
use crate::state::{
    load_ack_records, AdapterExecResult, LlmProvenanceRecord, MessageIngressRecord,
    PersistedAckHashes,
};

pub(crate) const DEFAULT_TX_ADAPTER_MAX_RETRIES: u32 = 3;
pub(crate) const DEFAULT_TX_ADAPTER_BACKOFF_MS: u64 = 200;
pub(crate) const DEFAULT_LLM_ADAPTER_MAX_RETRIES: u32 = 2;
pub(crate) const DEFAULT_LLM_ADAPTER_BACKOFF_MS: u64 = 200;
pub(crate) const DEFAULT_LLM_ADAPTER_TIMEOUT_MS: u64 = 10_000;

pub(crate) const TX_ADAPTER_MAX_RETRIES_ENV: &str = "TRNM_TX_ADAPTER_MAX_RETRIES";
pub(crate) const TX_ADAPTER_BACKOFF_MS_ENV: &str = "TRNM_TX_ADAPTER_BACKOFF_MS";
pub(crate) const LLM_ADAPTER_MAX_RETRIES_ENV: &str = "TRNM_LLM_ADAPTER_MAX_RETRIES";
pub(crate) const LLM_ADAPTER_BACKOFF_MS_ENV: &str = "TRNM_LLM_ADAPTER_BACKOFF_MS";
pub(crate) const LLM_ADAPTER_TIMEOUT_ENV: &str = "TRNM_LLM_ADAPTER_TIMEOUT_MS";
pub(crate) const PROOF_ADAPTER_ENV: &str = "TRNM_PROOF_ADAPTER";
pub(crate) const WORKER_EVENT_LOG_ENV: &str = "TRNM_WORKER_EVENT_LOG";
pub(crate) const WORKER_PROGRESS_LOG_ENV: &str = "TRNM_WORKER_PROGRESS_LOG";

pub(crate) const RC_OK: i32 = 0;
pub(crate) const RC_DUPLICATE: i32 = 9;
pub(crate) const RC_NONCE_REJECTED: i32 = 10;
pub(crate) const RC_SLO_VIOLATION: i32 = 11;
pub(crate) const RC_SKIPPED: i32 = -1;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LlmAdapterResponse {
    pub(crate) output_text: String,
    #[serde(default)]
    pub(crate) provider_request_id: Option<String>,
    #[serde(default)]
    pub(crate) provider: Option<String>,
    #[serde(default)]
    pub(crate) model: Option<String>,
    #[serde(default)]
    pub(crate) adapter: Option<String>,
    #[serde(default)]
    pub(crate) agent_protocol: Option<String>,
    #[serde(default)]
    pub(crate) compliance_profile: Option<String>,
}

pub(crate) fn should_execute_reveal(commit_res: &AdapterExecResult) -> bool {
    commit_res.ok || is_idempotent_duplicate_ok(commit_res.rc)
}

pub(crate) fn persisted_ack_hashes_for_task(ack_log: &PathBuf, task_id: u64) -> PersistedAckHashes {
    let mut hashes = PersistedAckHashes {
        commit_tx_hash: None,
        reveal_tx_hash: None,
    };

    for ack in load_ack_records(ack_log).into_iter().rev() {
        if ack.task_id != task_id {
            continue;
        }
        if hashes.commit_tx_hash.is_none() {
            hashes.commit_tx_hash = ack.commit_tx_hash;
        }
        if hashes.reveal_tx_hash.is_none() {
            hashes.reveal_tx_hash = ack.reveal_tx_hash;
        }
        if hashes.commit_tx_hash.is_some() && hashes.reveal_tx_hash.is_some() {
            break;
        }
    }

    hashes
}

pub(crate) fn attach_llm_provenance(rec: &mut MessageIngressRecord, llm: &LlmAdapterResponse) {
    rec.provider_request_id = normalized_provider_request_id(llm.provider_request_id.as_deref());

    let provider = normalized_provenance_label(llm.provider.as_deref(), 64);
    let model = normalized_provenance_label(llm.model.as_deref(), 128);
    let adapter = normalized_provenance_label(llm.adapter.as_deref(), 64);
    let agent_protocol = normalized_agent_protocol(llm.agent_protocol.as_deref());
    let compliance_profile = normalized_compliance_profile(llm.compliance_profile.as_deref());

    let has_v1_fields = provider.is_some() || model.is_some() || adapter.is_some();
    let has_v2_fields = agent_protocol.is_some() || compliance_profile.is_some();
    let has_structured_provenance = has_v1_fields || has_v2_fields;

    rec.provenance_schema_version = if has_v2_fields {
        Some("llm.v2".to_string())
    } else if has_v1_fields {
        Some("llm.v1".to_string())
    } else {
        None
    };

    rec.llm_provenance = has_structured_provenance.then(|| LlmProvenanceRecord {
        provider,
        model,
        adapter,
        agent_protocol,
        compliance_profile,
    });
}
