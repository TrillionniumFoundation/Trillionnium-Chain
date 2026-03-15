use super::*;
#[test]
fn attach_llm_provenance_normalizes_compliance_profile_casing() {
    let mut rec = MessageIngressRecord {
        request_id: "r6".to_string(),
        task_id: 14,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
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
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("  CN-PII-Restricted  ".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(
        prov.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn attach_llm_provenance_normalizes_space_separated_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6-space".to_string(),
        task_id: 142,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6-space".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
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
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: None,
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("CN PII Restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
    let prov = rec.llm_provenance.as_ref().expect("provenance attached");
    assert_eq!(
        prov.compliance_profile.as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn attach_llm_provenance_rejects_invalid_compliance_profile_chars() {
    let mut rec = MessageIngressRecord {
        request_id: "r6b".to_string(),
        task_id: 141,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6b".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
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
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6b".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("CN@PII@Restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_rejects_boundary_separators_in_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6c".to_string(),
        task_id: 142,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6c".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
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
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6c".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("-cn-pii-restricted_".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_rejects_repeated_separators_in_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6d".to_string(),
        task_id: 143,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6d".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
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
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6d".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("cn--pii__restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn attach_llm_provenance_rejects_mixed_adjacent_separators_in_compliance_profile() {
    let mut rec = MessageIngressRecord {
        request_id: "r6e".to_string(),
        task_id: 144,
        channel: "telegram".to_string(),
        user_id: "u6".to_string(),
        session_id: "s6".to_string(),
        text: "prompt".to_string(),
        idempotency_key: "ik6e".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
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
    let llm = LlmAdapterResponse {
        output_text: "ok".to_string(),
        provider_request_id: Some("provider-6e".to_string()),
        provider: None,
        model: None,
        adapter: None,
        agent_protocol: None,
        compliance_profile: Some("cn-_pii-restricted".to_string()),
    };

    attach_llm_provenance(&mut rec, &llm);

    assert_eq!(rec.provenance_schema_version, None);
    assert!(rec.llm_provenance.is_none());
}

#[test]
fn normalized_compliance_profile_accepts_64_char_boundary() {
    let profile = format!("{}-{}", "a".repeat(31), "b".repeat(32));
    assert_eq!(profile.len(), 64);
    assert_eq!(
        normalized_compliance_profile(Some(&profile)).as_deref(),
        Some(profile.as_str())
    );
}

#[test]
fn normalized_compliance_profile_rejects_over_64_chars() {
    let profile = "a".repeat(65);
    assert_eq!(normalized_compliance_profile(Some(&profile)), None);
}

#[test]
fn normalized_compliance_profile_rejects_numeric_only_values() {
    assert_eq!(normalized_compliance_profile(Some("202602")), None);
}

#[test]
fn normalized_compliance_profile_rejects_single_token_values() {
    assert_eq!(normalized_compliance_profile(Some("restricted")), None);
}

#[test]
fn normalized_compliance_profile_accepts_alphanumeric_when_contains_alpha() {
    assert_eq!(
        normalized_compliance_profile(Some("cn-202602")).as_deref(),
        Some("cn-202602")
    );
}

#[test]
fn normalized_compliance_profile_accepts_dot_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN.PII.Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_accepts_slash_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN/PII/Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_accepts_backslash_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN\\PII\\Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_accepts_space_separators_and_normalizes_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN PII Restricted")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_compliance_profile_rejects_adjacent_space_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn  pii restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_control_whitespace_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn\tpii restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_newline_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn\npii restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_adjacent_dot_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn..pii.restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_adjacent_mixed_path_separators() {
    assert_eq!(
        normalized_compliance_profile(Some("cn\\/pii-restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_rejects_values_starting_with_digit() {
    assert_eq!(
        normalized_compliance_profile(Some("1cn-pii-restricted")),
        None
    );
}

#[test]
fn normalized_compliance_profile_canonicalizes_underscore_to_hyphen() {
    assert_eq!(
        normalized_compliance_profile(Some("CN_PII_RESTRICTED")).as_deref(),
        Some("cn-pii-restricted")
    );
}

#[test]
fn normalized_provenance_label_accepts_ascii_audit_text() {
    assert_eq!(
        normalized_provenance_label(Some("openai gpt-5.3:preview"), 64).as_deref(),
        Some("openai gpt-5.3:preview")
    );
}

#[test]
fn normalized_provenance_label_rejects_non_ascii_homoglyphs() {
    assert_eq!(
        normalized_provenance_label(Some("оpenai"), 64),
        None,
        "non-ascii provenance labels should be rejected to avoid audit ambiguity"
    );
}

#[test]
fn normalized_provenance_label_rejects_embedded_control_characters() {
    assert_eq!(
        normalized_provenance_label(Some("openai\nmodel"), 64),
        None,
        "embedded control chars should fail-closed for provenance labels"
    );
}
