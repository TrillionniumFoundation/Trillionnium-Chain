use super::*;
#[test]
fn attach_llm_provenance_normalizes_agent_protocol_casing() {
    let mut rec = MessageIngressRecord {
        request_id: "r5".to_string(),
        task_id: 13,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5".to_string(),
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
        agent_protocol: Some("  MCP  ".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));
}

#[test]
fn attach_llm_provenance_accepts_agent_protocol_aliases() {
    let mut rec = MessageIngressRecord {
        request_id: "r5a".to_string(),
        task_id: 130,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5a".to_string(),
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
        agent_protocol: Some("  Model-Context Protocol  ".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("MCP v2".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("Agent/2/Agent".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("A2A v1".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("agent-to-agent".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: Some("Agent 2 Agent Protocol".to_string()),
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));
}
