use super::*;
#[test]
fn attach_llm_provenance_normalizes_compliance_profile_casing() {
    let mut rec = MessageIngressRecord {
        request_id: "r6".to_string(),
        task_id: 14,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6".to_string(),
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
        agent_protocol: None,
        compliance_profile: Some("  CN-PII-Restricted  ".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(
        prov.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn attach_llm_provenance_normalizes_space_separated_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6-space".to_string(),
        task_id: 142,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6-space".to_string(),
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
        agent_protocol: None,
        compliance_profile: Some("CN PII Restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(
        prov.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
}
