use super::*;

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
        reputation_label: Some("verifier_rejected".to_string()),
        reputation_delta: Some(-200),
        reputation_tier: Some(2),
        reputation_weight_bps: Some(7500),
        reputation_score_bps: Some(7500),
        reputation_rank_ordinal: Some(3),
        reputation_gap_bps_from_best: Some(2500),
    }];

    let md = render_enterprise_audit_markdown(&rows);
    assert!(md.contains("| provenance_schema_version | provenance_fingerprint |"));
    assert!(md.contains("| reputation_label | reputation_delta | reputation_tier | reputation_weight_bps | reputation_score_bps | reputation_rank_ordinal | reputation_gap_bps_from_best |"));
    assert!(md.contains("| r1 | 7 | reveal_submitted | req-1 | llm.v2 | deadbeef | openai | gpt-5.3-codex | mcp | a2a | cn-pii-restricted | verifier_rejected | -200 | 2 | 7500 | 7500 | 3 | 2500 |"));
}
