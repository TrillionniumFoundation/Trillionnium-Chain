use super::*;
#[test]
fn attach_llm_provenance_keeps_v1_when_v2_fields_are_invalid() {
    let mut rec = MessageIngressRecord {
        request_id: "r5c".to_string(),
        task_id: 132,
        channel: "telegram".to_string(),
        user_id: "u5".to_string(),
        session_id: "s5".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik5c".to_string(),
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
        provider_request_id: Some("prid-2".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some(" custom-proto ".to_string()),
        compliance_profile: Some("CN@PII@Restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.provider.as_deref(), Some("openai"));
    assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(prov.adapter.as_deref(), Some("mcp"));
    assert_eq!(prov.agent_protocol, None);
    assert_eq!(prov.compliance_profile, None);
}
