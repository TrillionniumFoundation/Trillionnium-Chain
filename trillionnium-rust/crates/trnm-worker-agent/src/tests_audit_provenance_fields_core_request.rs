use super::*;
#[test]
fn attach_llm_provenance_persists_provider_request_id() {
    let mut rec = MessageIngressRecord {
        request_id: "r1".to_string(),
        task_id: 9,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik1".to_string(),
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
        provider_request_id: Some("provider-123".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: None,
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id.as_deref(), Some("provider-123"));
    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(prov.provider.as_deref(), Some("openai"));
    assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(prov.adapter.as_deref(), Some("mcp"));
    assert_eq!(prov.agent_protocol, None);
    assert_eq!(prov.compliance_profile, None);
}

#[test]
fn attach_llm_provenance_rejects_non_canonical_provider_request_id() {
    let mut rec = MessageIngressRecord {
        request_id: "r1b".to_string(),
        task_id: 901,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik1".to_string(),
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
        provider_request_id: Some("provider-123\nmal".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: None,
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provider_request_id, None);
    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
    assert!(rec.llm_provenance.is_some());
}

#[test]
fn normalized_provider_request_id_accepts_boundary_and_rejects_overflow() {
    let ok = "a".repeat(128);
    assert_eq!(
        normalized_provider_request_id(Some(&ok)).as_deref(),
        Some(ok.as_str())
    );

    let overflow = "a".repeat(129);
    assert_eq!(normalized_provider_request_id(Some(&overflow)), None);
}

#[test]
fn normalized_provider_request_id_rejects_colon_and_non_alnum_edges() {
    assert_eq!(
        normalized_provider_request_id(Some("req:123")),
        None,
        "colon-delimited ids are ambiguous in downstream audit consumers"
    );
    assert_eq!(normalized_provider_request_id(Some("-req123")), None);
    assert_eq!(normalized_provider_request_id(Some("req123.")), None);
    assert_eq!(
        normalized_provider_request_id(Some("req_123-abc.DEF")).as_deref(),
        Some("req_123-abc.DEF")
    );
}

#[test]
fn attach_llm_provenance_keeps_schema_empty_without_structured_fields() {
    let mut rec = MessageIngressRecord {
        request_id: "r2".to_string(),
        task_id: 10,
        channel: "telegram".to_string(),
        user_id: "u2".to_string(),
        session_id: "s2".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik2".to_string(),
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
        provider_request_id: Some("provider-opaque-id".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: None,
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(
        rec.provider_request_id.as_deref(),
        Some("provider-opaque-id")
    );
    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}
