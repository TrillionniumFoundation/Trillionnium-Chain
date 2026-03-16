use super::*;
#[test]
fn enterprise_audit_export_re_normalizes_legacy_provider_request_id() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-provider-request-id".to_string(),
        task_id: 700,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-provider-request-id".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some(" provider\n701 ".to_string()),
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
    assert_eq!(export.provider_request_id, None);
}

#[test]
fn enterprise_audit_export_trims_boundary_bom_from_provider_request_id() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-provider-request-id-bom".to_string(),
        task_id: 7001,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-provider-request-id-bom".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("\u{feff}provider-701\u{200b}".to_string()),
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
    assert_eq!(export.provider_request_id.as_deref(), Some("provider-701"));
}

#[test]
fn enterprise_audit_export_flattens_v2_provenance_for_agent_and_compliance() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2".to_string(),
        task_id: 701,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-701".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
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
    assert_eq!(export.request_id, "r-audit-v2");
    assert_eq!(export.task_id, 701);
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
    assert_eq!(
        export.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
    assert_eq!(export.provider.as_deref(), Some("openai"));
    let expected = build_provenance_fingerprint(
        Some("llm.v2"),
        Some("openai"),
        Some("gpt-5.3-codex"),
        Some("mcp"),
        Some("a2a"),
        Some("cn-pii-restricted"),
    );
    assert_eq!(export.provenance_fingerprint, expected);
}

#[test]
fn enterprise_audit_export_accepts_case_and_whitespace_drift_for_v2_schema() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-drift".to_string(),
        task_id: 7011,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-drift".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-7011".to_string()),
        provenance_schema_version: Some("  LLM.V2  ".to_string()),
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
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
    assert_eq!(
        export.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );

    let expected = build_provenance_fingerprint(
        Some("llm.v2"),
        Some("openai"),
        Some("gpt-5.3-codex"),
        Some("mcp"),
        Some("a2a"),
        Some("cn-pii-restricted"),
    );
    assert_eq!(export.provenance_fingerprint, expected);
}

#[test]
fn enterprise_audit_export_accepts_separator_aliases_for_schema_version() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-alias".to_string(),
        task_id: 70115,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-alias".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-70115".to_string()),
        provenance_schema_version: Some("LLM_V2".to_string()),
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
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
    assert_eq!(
        export.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );

    for alias in ["llm2", "llm-v2", "llm/v2"] {
        let mut compact_alias = rec.clone();
        compact_alias.provenance_schema_version = Some(alias.to_string());
        let compact_export = to_enterprise_audit_export(&compact_alias);
        assert_eq!(
            compact_export.provenance_schema_version.as_deref(),
            Some("llm.v2"),
            "schema alias should canonicalize: {alias}"
        );
        assert_eq!(compact_export.agent_protocol.as_deref(), Some("a2a"));
        assert_eq!(
            compact_export.compliance_profile.as_deref(),
            Some("cn-pii-restricted")
        );
    }
}

#[test]
fn enterprise_audit_export_normalizes_mcp_streamable_http_aliases_for_v2_schema() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-mcp-streamable-http".to_string(),
        task_id: 70117,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-mcp-streamable-http".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-70117".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("MCP/streamable-http v2".to_string()),
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
    assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
    assert_eq!(export.agent_protocol.as_deref(), Some("mcp"));

    for alias in [
        "MCP/streamable-http v2",
        "mcp over streamable-http",
        "model context protocol over streamable-http",
        "OpenAI model context protocol over streamable-http v2",
    ] {
        let mut alias_rec = rec.clone();
        alias_rec
            .llm_provenance
            .as_mut()
            .expect("provenance exists")
            .agent_protocol = Some(alias.to_string());
        let alias_export = to_enterprise_audit_export(&alias_rec);
        assert_eq!(
            alias_export.agent_protocol.as_deref(),
            Some("mcp"),
            "agent protocol alias should canonicalize: {alias}"
        );
    }
}

#[test]
fn enterprise_audit_export_normalizes_mcp_websocket_aliases_for_v2_schema() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-mcp-websocket".to_string(),
        task_id: 70118,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-mcp-websocket".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-70118".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("MCP over WebSocket v2".to_string()),
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

    for alias in [
        "MCP over WebSocket v2",
        "model context protocol websocket",
        "OpenAI MCP websocket v1",
        "OpenAI model context protocol over websocket v2",
        "Anthropic model-context-protocol over websocket",
    ] {
        let mut alias_rec = rec.clone();
        alias_rec
            .llm_provenance
            .as_mut()
            .expect("provenance exists")
            .agent_protocol = Some(alias.to_string());
        let alias_export = to_enterprise_audit_export(&alias_rec);
        assert_eq!(
            alias_export.agent_protocol.as_deref(),
            Some("mcp"),
            "agent protocol websocket alias should canonicalize: {alias}"
        );
    }
}

#[test]
fn enterprise_audit_export_normalizes_mcp_sse_aliases_for_v2_schema() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-v2-mcp-sse".to_string(),
        task_id: 70119,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-v2-mcp-sse".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-70119".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: Some(LlmProvenanceRecord {
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("OpenAI MCP over SSE v2".to_string()),
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

    for alias in [
        "OpenAI MCP over SSE v2",
        "openai model context protocol sse",
        "Anthropic MCP over SSE",
        "Anthropic model-context-protocol over sse v1",
    ] {
        let mut alias_rec = rec.clone();
        alias_rec
            .llm_provenance
            .as_mut()
            .expect("provenance exists")
            .agent_protocol = Some(alias.to_string());
        let alias_export = to_enterprise_audit_export(&alias_rec);
        assert_eq!(
            alias_export.agent_protocol.as_deref(),
            Some("mcp"),
            "agent protocol sse alias should canonicalize: {alias}"
        );
    }
}

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
