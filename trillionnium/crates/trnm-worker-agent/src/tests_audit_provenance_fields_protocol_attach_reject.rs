use super::*;
#[test]
fn attach_llm_provenance_rejects_non_ascii_or_invisible_agent_protocol_aliases() {
    let mut rec = MessageIngressRecord {
        request_id: "r5aa".to_string(),
        task_id: 1301,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5aa".to_string(),
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
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("MCP🔥".to_string()),
        compliance_profile: None,
    };
    attach_llm_provenance(&mut rec, &llm);
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("a2a\u{200b}".to_string()),
        compliance_profile: None,
    };
    attach_llm_provenance(&mut rec, &llm);
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_drops_unsupported_agent_protocol() {
    let mut rec = MessageIngressRecord {
        request_id: "r5b".to_string(),
        task_id: 131,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5b".to_string(),
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
        provider_request_id: Some("prid-1".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some(" custom-proto ".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}
