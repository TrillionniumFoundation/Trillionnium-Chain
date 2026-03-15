use super::*;
#[test]
fn query_audit_export_by_task_id_uses_index_offsets() {
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
            provenance_fingerprint: Some("fp-def".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-moderate".to_string()),
        },
    ];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_task_id(&rows, &index, 7002);
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r2");

    let miss = query_audit_export_by_task_id(&rows, &index, 9999);
    assert!(miss.is_empty());
}

#[test]
fn query_audit_export_by_provenance_fingerprint_normalizes_lookup() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_provenance_fingerprint(&rows, &index, "  DEADBEEF ");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");

    let miss = query_audit_export_by_provenance_fingerprint(&rows, &index, "dead\u{200b}beef");
    assert!(miss.is_empty());
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_outer_quote_wrappers_before_validation() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7003,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_provenance_fingerprint(&rows, &index, "'\"DEADBEEF\"'");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_quoted_lookup() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_provenance_fingerprint(&rows, &index, " ' \"DEADBEEF\" ' ");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_deeply_nested_quotes() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    let hit =
        query_audit_export_by_provenance_fingerprint(&rows, &index, "  ` ' \" deadbeef \" ' `  ");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_very_deep_quote_wrappers() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    // Five nested wrappers can appear after repeated env-forwarding hops.
    let hit = query_audit_export_by_provenance_fingerprint(
        &rows,
        &index,
        "  ' \" ` ' \" deadbeef \" ' ` \" '  ",
    );
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_repeated_nested_quote_wrappers() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    // Repeated shell/env forwarding can introduce more than five quote layers; keep
    // lookup tolerant as long as the normalized fingerprint remains valid and bounded.
    let hit = query_audit_export_by_provenance_fingerprint(
        &rows,
        &index,
        "'\"`'\"`'\"`'\"`deadbeef`\"'`\"'`\"'`\"'",
    );
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_shell_escaped_outer_quote_wrappers() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7004,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_provenance_fingerprint(&rows, &index, r#"  \"'deadbeef'\"  "#);
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_trims_boundary_bom_before_lookup() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r-bom-lookup".to_string(),
        task_id: 70081,
        status: "assigned".to_string(),
        provider_request_id: None,
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-pii-restricted".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    let hit =
        query_audit_export_by_provenance_fingerprint(&rows, &index, "\u{feff}DEADBEEF\u{200b}");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r-bom-lookup");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_trims_fillers_after_quote_peeling() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r-bom-after-peel".to_string(),
        task_id: 70082,
        status: "assigned".to_string(),
        provider_request_id: None,
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-pii-restricted".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    let hit = query_audit_export_by_provenance_fingerprint(
        &rows,
        &index,
        " '\"\u{feff}DEADBEEF\u{200b}\"' ",
    );
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r-bom-after-peel");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_accepts_repeated_shell_escaped_quote_wrappers() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7005,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    let hit =
        query_audit_export_by_provenance_fingerprint(&rows, &index, r#"\"\"\"deadbeef\"\"\""#);
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].request_id, "r1");
}

#[test]
fn query_audit_export_by_provenance_fingerprint_rejects_blank_or_oversized_lookup() {
    let rows = vec![EnterpriseAuditExportRecord {
        request_id: "r1".to_string(),
        task_id: 7002,
        status: "reveal_submitted".to_string(),
        provider_request_id: Some("p1".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        provenance_fingerprint: Some("deadbeef".to_string()),
        provider: Some("openai".to_string()),
        model: Some("gpt-5.3-codex".to_string()),
        adapter: Some("mcp".to_string()),
        agent_protocol: Some("a2a".to_string()),
        compliance_profile: Some("cn-moderate".to_string()),
    }];

    let index = build_audit_export_index(&rows);
    assert!(query_audit_export_by_provenance_fingerprint(&rows, &index, "   ").is_empty());

    let oversized = "a".repeat(129);
    assert!(query_audit_export_by_provenance_fingerprint(&rows, &index, &oversized).is_empty());
}

#[test]
fn query_audit_output_serializes_normalized_fingerprint_only_when_present() {
    let with_fp = QueryAuditOutput {
        hit_indexes: vec![1, 3],
        records: vec![],
        provenance_fingerprint: Some("deadbeef".to_string()),
    };
    let with_fp_json = serde_json::to_value(&with_fp).expect("serialize query output");
    assert_eq!(with_fp_json["provenance_fingerprint"], "deadbeef");
    assert_eq!(with_fp_json["hit_indexes"], serde_json::json!([1, 3]));

    let without_fp = QueryAuditOutput {
        hit_indexes: vec![],
        records: vec![],
        provenance_fingerprint: None,
    };
    let without_fp_json = serde_json::to_value(&without_fp).expect("serialize query output");
    assert!(without_fp_json.get("provenance_fingerprint").is_none());
    assert_eq!(without_fp_json["hit_indexes"], serde_json::json!([]));
}

#[test]
fn query_audit_rejects_markdown_exports_fail_closed() {
    let output_file = std::env::temp_dir().join(format!(
        "trnm-worker-agent-query-audit-markdown-{}-{}.md",
        std::process::id(),
        now_ms()
    ));
    let index_file = audit_export_index_path(&output_file);
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

    fs::write(&output_file, "# audit\n").expect("write markdown export");
    fs::write(
        &index_file,
        serde_json::to_string_pretty(&index).expect("serialize index"),
    )
    .expect("write index");

    let format = detect_audit_export_format(&output_file);
    assert_eq!(format, AuditExportFormat::Markdown);
    assert!(index_file.exists());
    let err = if format != AuditExportFormat::Jsonl {
        anyhow!(
            "query-audit only supports JSONL audit exports: {}",
            output_file.display()
        )
    } else {
        anyhow!("unexpected jsonl format for markdown export")
    };
    assert!(err
        .to_string()
        .contains("query-audit only supports JSONL audit exports"));

    let _ = fs::remove_file(&output_file);
    let _ = fs::remove_file(&index_file);
}
