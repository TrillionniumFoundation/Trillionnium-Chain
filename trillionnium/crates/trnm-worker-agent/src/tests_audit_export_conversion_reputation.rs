use super::*;

#[test]
fn enterprise_audit_export_projects_canonical_reputation_surface_axes() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-reputation-surface".to_string(),
        task_id: 7401,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-reputation-surface".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-7401".to_string()),
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
        reputation_delta: Some(reputation_delta(ReputationSignal::VerifierRejected)),
    };

    let export = to_enterprise_audit_export(&rec);
    let expected = reputation_surface(ReputationSignal::VerifierRejected);

    assert_eq!(export.reputation_label.as_deref(), Some(expected.label));
    assert_eq!(export.reputation_delta, Some(expected.delta));
    assert_eq!(export.reputation_tier, Some(expected.tier));
    assert_eq!(export.reputation_weight_bps, Some(expected.weight_bps));
    assert_eq!(export.reputation_score_bps, Some(expected.score_bps));
    assert_eq!(export.reputation_rank_ordinal, Some(expected.rank_ordinal));
    assert_eq!(
        export.reputation_gap_bps_from_best,
        Some(reputation_gap_bps_from_best(ReputationSignal::VerifierRejected))
    );
}

#[test]
fn enterprise_audit_export_drops_non_canonical_reputation_delta_fail_closed() {
    let rec = MessageIngressRecord {
        request_id: "r-audit-reputation-invalid".to_string(),
        task_id: 7402,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-audit-reputation-invalid".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: Some("provider-7402".to_string()),
        provenance_schema_version: Some("llm.v2".to_string()),
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: Some(42),
    };

    let export = to_enterprise_audit_export(&rec);
    assert_eq!(export.reputation_label, None);
    assert_eq!(export.reputation_delta, None);
    assert_eq!(export.reputation_tier, None);
    assert_eq!(export.reputation_weight_bps, None);
    assert_eq!(export.reputation_score_bps, None);
    assert_eq!(export.reputation_rank_ordinal, None);
    assert_eq!(export.reputation_gap_bps_from_best, None);
}
