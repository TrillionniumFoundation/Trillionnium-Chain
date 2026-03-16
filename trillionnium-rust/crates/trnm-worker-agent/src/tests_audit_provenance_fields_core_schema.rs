use super::*;
#[test]
fn attach_llm_provenance_uses_v2_when_protocol_or_compliance_present() {
    let mut rec = MessageIngressRecord {
        request_id: "r3".to_string(),
        task_id: 11,
        channel: "telegram".to_string(),
        user_id: "u3".to_string(),
        session_id: "s3".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik3".to_string(),
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
        provider_request_id: Some("provider-321".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-pii-restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id.as_deref(), Some("provider-321"));
    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));
    assert_eq!(
        prov.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn attach_llm_provenance_trims_whitespace_and_drops_empty_fields() {
    let mut rec = MessageIngressRecord {
        request_id: "r4".to_string(),
        task_id: 12,
        channel: "telegram".to_string(),
        user_id: "u4".to_string(),
        session_id: "s4".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik4".to_string(),
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
        provider_request_id: Some("  provider-444  ".to_string()),
        provider: Some("  ".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("   ".to_string()),
        compliance_profile: Some("  cn-pii-restricted  ".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id.as_deref(), Some("provider-444"));
    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.provider, None);
    assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(prov.adapter.as_deref(), Some("mcp"));
    assert_eq!(prov.agent_protocol, None);
    assert_eq!(
        prov.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
}
