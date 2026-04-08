use super::*;

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
