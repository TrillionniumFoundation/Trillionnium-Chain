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

#[test]
fn export_audit_detects_markdown_output_extension() {
    assert_eq!(
        detect_audit_export_format(Path::new("audit-export.md")),
        AuditExportFormat::Markdown
    );
    assert_eq!(
        detect_audit_export_format(Path::new("audit-export.markdown")),
        AuditExportFormat::Markdown
    );
    assert_eq!(
        detect_audit_export_format(Path::new("audit-export.jsonl")),
        AuditExportFormat::Jsonl
    );
}

#[test]
fn validate_audit_export_index_accepts_current_version() {
    let index = AuditExportIndex {
        version: 1,
        total_records: 0,
        by_task_id: BTreeMap::new(),
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    validate_audit_export_index(&index, 0).expect("v1 index should be accepted");
}

#[test]
fn validate_audit_export_index_rejects_unknown_version_fail_closed() {
    let index = AuditExportIndex {
        version: 2,
        total_records: 0,
        by_task_id: BTreeMap::new(),
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    let err = validate_audit_export_index(&index, 0)
        .expect_err("unknown audit index version must fail closed");
    assert!(err
        .to_string()
        .contains("unsupported audit index version=2"));
}

#[test]
fn validate_audit_export_index_rejects_total_record_mismatch_fail_closed() {
    let index = AuditExportIndex {
        version: 1,
        total_records: 2,
        by_task_id: BTreeMap::new(),
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    let err = validate_audit_export_index(&index, 1)
        .expect_err("mismatched export length must fail closed");
    assert!(err
        .to_string()
        .contains("audit index total_records mismatch: index=2 exports=1"));
}

#[test]
fn validate_audit_export_index_rejects_out_of_bounds_offsets_fail_closed() {
    let mut by_task_id = BTreeMap::new();
    by_task_id.insert("7001".to_string(), vec![1]);
    let index = AuditExportIndex {
        version: 1,
        total_records: 1,
        by_task_id,
        by_status: BTreeMap::new(),
        by_status_phase: BTreeMap::new(),
        by_provider: BTreeMap::new(),
        by_model: BTreeMap::new(),
        by_agent_protocol: BTreeMap::new(),
        by_compliance_profile: BTreeMap::new(),
        by_provenance_fingerprint: BTreeMap::new(),
    };

    let err = validate_audit_export_index(&index, 1)
        .expect_err("out-of-bounds index offsets must fail closed");
    assert!(err.to_string().contains(
        "audit index offset out of bounds: map=by_task_id key=7001 idx=1 total_records=1"
    ));
}

#[test]
fn export_audit_markdown_contains_provenance_fingerprint_fields() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("req-1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-pii-restricted".to_string()),
    }];

    let md = render_enterprise_audit_markdown(&rows);
    assert!(md.contains("| provenance_schema_version | provenance_fingerprint |"));
    assert!(md.contains("| r1 | 7 | reveal_submitted | req-1 | llm.v2 | deadbeef |"));
}

#[test]
fn export_audit_markdown_normalizes_multiline_cells_to_single_line() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r\n1".to_string(),
        task_id: 8,
        status: "reveal\r\nsubmitted".to_string(),
        provider_request_id: Some("req|2".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("cafebabe".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-pii-restricted".to_string()),
    }];

    let md = render_enterprise_audit_markdown(&rows);
    assert!(md.contains("| r 1 | 8 | reveal  submitted | req\\|2 | llm.v2 | cafebabe |"));
    assert!(!md.contains("r\n1"));
    assert!(!md.contains("reveal\r\nsubmitted"));
}

#[test]
fn export_audit_index_contains_task_status_provider_model_and_fingerprint_keys() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7001,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-abc".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7002,
            status: "rejected".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-abc".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(index.total_records, 2);
    assert_eq!(index.by_task_id.get("7001"), Some(&vec![0]));
    assert_eq!(index.by_task_id.get("7002"), Some(&vec![1]));
    assert_eq!(index.by_status.get("reveal_submitted"), Some(&vec![0]));
    assert_eq!(index.by_status.get("rejected"), Some(&vec![1]));
    assert_eq!(index.by_status_phase.get("active"), Some(&vec![0]));
    assert_eq!(index.by_status_phase.get("terminal"), Some(&vec![1]));
    assert_eq!(index.by_provider.get("openai"), Some(&vec![0, 1]));
    assert_eq!(index.by_model.get("gpt-5.3-codex"), Some(&vec![0, 1]));
    assert_eq!(index.by_agent_protocol.get("a2a"), Some(&vec![0, 1]));
    assert_eq!(
        index.by_compliance_profile.get("cn-moderate"),
        Some(&vec![0, 1])
    );
    assert_eq!(
        index.by_provenance_fingerprint.get("fp-abc"),
        Some(&vec![0, 1])
    );
}

#[test]
fn export_audit_index_trims_and_drops_blank_provider_model_or_fingerprint_values() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7101,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("  fp-xyz  ".to_string()),
            provider: Some("  openai  ".to_string()),
            model: Some("  gpt-5.3-codex  ".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7102,
            status: "rejected".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("   ".to_string()),
            provider: Some("   ".to_string()),
            model: Some("\t".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(index.by_provider.get("openai"), Some(&vec![0]));
    assert_eq!(index.by_model.get("gpt-5.3-codex"), Some(&vec![0]));
    assert_eq!(index.by_agent_protocol.get("a2a"), Some(&vec![0, 1]));
    assert_eq!(
        index.by_compliance_profile.get("cn-moderate"),
        Some(&vec![0, 1])
    );
    assert_eq!(
        index.by_provenance_fingerprint.get("fp-xyz"),
        Some(&vec![0])
    );
    assert!(!index.by_provider.contains_key(""));
    assert!(!index.by_model.contains_key(""));
    assert!(!index.by_agent_protocol.contains_key(""));
    assert!(!index.by_compliance_profile.contains_key(""));
    assert!(!index.by_provenance_fingerprint.contains_key(""));
}

#[test]
fn export_audit_index_normalizes_uppercase_fingerprint_variants() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7201,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("DEADBEEF".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7202,
            status: "rejected".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("deadbeef".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(
        index.by_provenance_fingerprint.get("deadbeef"),
        Some(&vec![0, 1])
    );
    assert!(!index.by_provenance_fingerprint.contains_key("DEADBEEF"));
}

#[test]
fn export_audit_index_normalizes_agent_protocol_aliases_to_canonical_keys() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7251,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-1".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("A2A-JSON-RPC-V2".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7252,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-2".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some(" model-context-protocol / stdio v1 ".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
        EnterpriseAuditExportRecord {
            request_id: "r3".to_string(),
            task_id: 7253,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p3".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-3".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("Google-Agent-to-Agent-Streamable-HTTP-v1".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(index.by_agent_protocol.get("a2a"), Some(&vec![0, 2]));
    assert_eq!(index.by_agent_protocol.get("mcp"), Some(&vec![1]));
    assert!(!index.by_agent_protocol.contains_key("A2A-JSON-RPC-V2"));
    assert!(!index
        .by_agent_protocol
        .contains_key("model-context-protocol / stdio v1"));
    assert!(!index
        .by_agent_protocol
        .contains_key("Google-Agent-to-Agent-Streamable-HTTP-v1"));
}

#[test]
fn export_audit_index_normalizes_compliance_profile_aliases_to_canonical_keys() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7281,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-1".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("CN_PII_RESTRICTED".to_string()),
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7282,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("fp-2".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some(" cn/pii/restricted ".to_string()),
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(
        index.by_compliance_profile.get("cn-pii-restricted"),
        Some(&vec![0, 1])
    );
    assert!(!index
        .by_compliance_profile
        .contains_key("CN_PII_RESTRICTED"));
    assert!(!index
        .by_compliance_profile
        .contains_key("cn/pii/restricted"));
}

#[test]
fn export_audit_index_drops_non_ascii_or_controlled_fingerprints() {
    let rows = vec![
        EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7301,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("p1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("deadbeef".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
        EnterpriseAuditExportRecord {
            request_id: "r2".to_string(),
            task_id: 7302,
            status: "rejected".to_string(),
            provider_request_id: Some("p2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("de\u{200b}adbeef".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
        EnterpriseAuditExportRecord {
            request_id: "r3".to_string(),
            task_id: 7303,
            status: "rejected".to_string(),
            provider_request_id: Some("p3".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("cafébabe".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
    ];

    let index = build_audit_export_index(&rows);
    assert_eq!(
        index.by_provenance_fingerprint.get("deadbeef"),
        Some(&vec![0])
    );
    assert_eq!(index.by_provenance_fingerprint.len(), 1);
}
