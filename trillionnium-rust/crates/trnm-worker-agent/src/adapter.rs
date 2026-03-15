use serde::Deserialize;
use std::path::PathBuf;

use crate::adapter_parse::{
    context_matches_token, normalized_agent_protocol, normalized_compliance_profile,
    normalized_provenance_label, normalized_provider_request_id,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterErrorKind {
    Retriable,
    NonRetriable,
}

#[derive(Debug, Clone)]
pub(crate) struct AdapterError {
    pub(crate) kind: AdapterErrorKind,
    pub(crate) context: String,
}

pub(crate) fn is_deterministic_rejection(rc: i32) -> bool {
    matches!(rc, RC_DUPLICATE | RC_NONCE_REJECTED | RC_SLO_VIOLATION)
}

pub(crate) fn is_idempotent_duplicate_ok(rc: i32) -> bool {
    rc == RC_DUPLICATE
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

pub(crate) fn classify_adapter_error(err: &AdapterError) -> (&'static str, &'static str) {
    if context_matches_token(&err.context, "proof-missing")
        || context_matches_token(&err.context, "missing-provider-request-id")
    {
        return ("ERR_M2V2_PROOF_MISSING", "proof_missing");
    }
    if context_matches_token(&err.context, "proof-invalid")
        || context_matches_token(&err.context, "missing-adapter-label")
        || context_matches_token(&err.context, "no-json-line")
        || context_matches_token(&err.context, "invalid-json")
    {
        return ("ERR_M2V2_PROOF_INVALID", "proof_invalid");
    }
    if context_matches_token(&err.context, "settlement-degraded") {
        return ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded");
    }
    if context_matches_token(&err.context, "proof-late")
        || context_matches_token(&err.context, "timeout")
    {
        return ("ERR_M2V2_PROOF_LATE", "proof_late");
    }

    match err.kind {
        AdapterErrorKind::Retriable => ("adapter_error", "retry_exhausted"),
        AdapterErrorKind::NonRetriable => ("adapter_error", "non_retriable"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReputationSignal {
    Accepted,
    VerifierRejected,
    AdapterRetryExhausted,
    AdapterNonRetriable,
}

pub(crate) fn reputation_delta(signal: ReputationSignal) -> i32 {
    match signal {
        ReputationSignal::Accepted => 3,
        ReputationSignal::VerifierRejected => -2,
        ReputationSignal::AdapterRetryExhausted => -1,
        ReputationSignal::AdapterNonRetriable => -3,
    }
}

pub(crate) fn adapter_error_signal(kind: AdapterErrorKind) -> ReputationSignal {
    match kind {
        AdapterErrorKind::Retriable => ReputationSignal::AdapterRetryExhausted,
        AdapterErrorKind::NonRetriable => ReputationSignal::AdapterNonRetriable,
    }
}
