use super::*;
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
