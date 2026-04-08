use super::*;

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
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
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
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
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
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
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
        reputation_label: None,
        reputation_delta: None,
        reputation_tier: None,
        reputation_weight_bps: None,
        reputation_score_bps: None,
        reputation_rank_ordinal: None,
        reputation_gap_bps_from_best: None,
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
