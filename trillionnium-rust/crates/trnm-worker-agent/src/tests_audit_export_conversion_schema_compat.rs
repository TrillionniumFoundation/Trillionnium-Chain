use super::*;
#[test]
fn enterprise_audit_export_accepts_separator_aliases_for_v1_schema_version() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v1-alias".to_string(),
        task_id: 70116,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v1-alias".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-70116".to_string()),
        provenance_schema_version: Some("LLM_V1".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    for alias in ["LLM_V1", "llm1", "llm-v1", "llm/v1"] {
        let mut v1_alias = rec.clone();
        v1_alias.provenance_schema_version = Some(alias.to_string());
        let export = to_enterprise_audit_export(&v1_alias);
        assert_eq!(
            export.provenance_schema_version.as_deref(),
            Some("llm.v1"),
            "schema alias should canonicalize: {alias}"
        );
        assert_eq!(export.adapter.as_deref(), Some("mcp"));
        assert_eq!(export.agent_protocol, None);
        assert_eq!(export.compliance_profile, None);
    }
}

#[test]
fn enterprise_audit_export_re_normalizes_legacy_persisted_provenance_fields() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-legacy-provenance".to_string(),
        task_id: 7012,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-legacy-provenance".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-7012".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("  openai  ".to_string()),
            model: Some("  gpt-5.3-codex  ".to_string()),
            adapter: Some("mcp\ninvalid".to_string()),
            agent_protocol: Some(" Agent-to-Agent v2 ".to_string()),
            compliance_profile: Some(" CN_PII/RESTRICTED ".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.provider.as_deref(), Some("openai"));
    assert_eq!(export.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(export.adapter, None);
    assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
    assert_eq!(
        export.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );

    let expected = build_provenance_fingerprint(
        Some("llm.v2"),
        Some("openai"),
        Some("gpt-5.3-codex"),
        None,
        Some("a2a"),
        Some("cn-pii-restricted"),
    );
    assert_eq!(export.provenance_fingerprint, expected);
}

#[test]
fn enterprise_audit_export_drops_v2_only_fields_when_schema_is_not_v2() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v1-with-v2-fields".to_string(),
        task_id: 702,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v1-with-v2-fields".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-702".to_string()),
        provenance_schema_version: Some("llm.v1".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v1"));
    assert_eq!(export.provider.as_deref(), Some("openai"));
    assert_eq!(export.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(export.adapter.as_deref(), Some("mcp"));
    assert_eq!(export.agent_protocol, None);
    assert_eq!(export.compliance_profile, None);
    let expected = build_provenance_fingerprint(
        Some("llm.v1"),
        Some("openai"),
        Some("gpt-5.3-codex"),
        Some("mcp"),
        None,
        None,
    );
    assert_eq!(export.provenance_fingerprint, expected);
}

#[test]
fn enterprise_audit_export_keeps_backward_compat_when_provenance_absent() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-legacy".to_string(),
        task_id: 702,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-legacy".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: None,
        assigned_at_unix_ms: None,
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

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.request_id, "r-audit-legacy");
    assert_eq!(export.provenance_schema_version, None);
    assert_eq!(export.provenance_fingerprint, None);
    assert_eq!(export.agent_protocol, None);
    assert_eq!(export.compliance_profile, None);
    assert_eq!(export.provider, None);
}

#[test]
fn enterprise_audit_export_gates_fingerprint_when_schema_exists_without_labels() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-empty".to_string(),
        task_id: 703,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-empty".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-703".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: None,
            compliance_profile: None,
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.provenance_fingerprint, None);
    assert_eq!(export.provider, None);
    assert_eq!(export.model, None);
    assert_eq!(export.adapter, None);
    assert_eq!(export.agent_protocol, None);
    assert_eq!(export.compliance_profile, None);
}

#[test]
fn enterprise_audit_export_fail_closed_on_noncanonical_schema_tag() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-bad-schema".to_string(),
        task_id: 7031,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-bad-schema".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-7031".to_string()),
        provenance_schema_version: Some("llm.v2-beta".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }),
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.provenance_schema_version, None);
    assert_eq!(export.provenance_fingerprint, None);
    assert_eq!(export.provider.as_deref(), Some("openai"));
    assert_eq!(export.model.as_deref(), Some("gpt-5.3-codex"));
    assert_eq!(export.adapter.as_deref(), Some("mcp"));
    assert_eq!(export.agent_protocol, None);
    assert_eq!(export.compliance_profile, None);
}
