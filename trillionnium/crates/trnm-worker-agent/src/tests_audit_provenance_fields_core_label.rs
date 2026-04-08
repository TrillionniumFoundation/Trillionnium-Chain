use super::*;
#[test]
fn attach_llm_provenance_drops_overlong_and_controlled_v1_labels() {
    let mut rec = MessageIngressRecord {
        request_id: "r4b".to_string(),
        task_id: 120,
        channel: "telegram".to_string(),
        user_id: "u4".to_string(),
        session_id: "s4".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik4b".to_string(),
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
        provider_request_id: Some("provider-4b".to_string()),
        provider: Some("p".repeat(65)),
        model: Some(format!("model-{}", "x".repeat(140))),
        adapter: Some("mcp\nrelay".to_string()),
        agent_protocol: None,
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id.as_deref(), Some("provider-4b"));
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_rejects_invisible_fillers_in_v1_labels() {
    let mut rec = MessageIngressRecord {
        request_id: "r4c".to_string(),
        task_id: 121,
        channel: "telegram".to_string(),
        user_id: "u4".to_string(),
        session_id: "s4".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik4c".to_string(),
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
        provider_request_id: Some("provider-4c".to_string()),
        provider: Some("open\u{200b}ai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: None,
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id.as_deref(), Some("provider-4c"));
    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.provider, None);
    assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(prov.adapter.as_deref(), Some("mcp"));
}
