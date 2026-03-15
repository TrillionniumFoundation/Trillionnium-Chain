use std::path::PathBuf;

pub(crate) use crate::adapter_error::{
    adapter_error_signal, classify_adapter_error, is_deterministic_rejection,
    is_idempotent_duplicate_ok, reputation_delta, AdapterError, AdapterErrorKind, ReputationSignal,
};
use crate::adapter_model::LlmAdapterResponse;
use crate::adapter_parse::{
    normalized_agent_protocol, normalized_compliance_profile, normalized_provenance_label,
    normalized_provider_request_id,
};
use crate::state::{
    load_ack_records, AdapterExecResult, LlmProvenanceRecord, MessageIngressRecord,
    PersistedAckHashes,
};

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
