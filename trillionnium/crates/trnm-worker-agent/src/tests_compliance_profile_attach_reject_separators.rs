use super::*;

#[test]
fn attach_llm_provenance_rejects_boundary_separators_in_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6c".to_string(),
        task_id: 142,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6c".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6c".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("-cn-pii-restricted_".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_rejects_repeated_separators_in_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6d".to_string(),
        task_id: 143,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6d".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6d".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("cn--pii__restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_rejects_mixed_adjacent_separators_in_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6e".to_string(),
        task_id: 144,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6e".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6e".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("cn-_pii-restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}
