use super::*;
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
