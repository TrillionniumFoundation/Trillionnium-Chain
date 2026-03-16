use super::*;

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
