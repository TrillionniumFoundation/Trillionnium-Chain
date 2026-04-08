use super::*;

#[test]
fn issue_at_did_revocation_boundary_is_fail_closed_and_sequence_safe() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-issue-after-did-revoke".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    reg.revoke_did(
        "org:lane-xi-admin".to_string(),
        "did:trnm:agent-i3-issue-after-did-revoke",
        30,
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let err = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-issue-after-did-revoke".to_string(),
            CapabilityScope::AuditRead,
            30,
            Some(90),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did }
            if did == "did:trnm:agent-i3-issue-after-did-revoke"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert!(reg.capability(1).is_none());
}

#[test]
fn revoke_at_issue_boundary_is_immediately_fail_closed_and_side_effect_free_for_renew() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-issue-revoke-boundary".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-issue-revoke-boundary".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        20,
        Some("same_height_issue_revoke".to_string()),
    )
    .unwrap();

    let token = reg.capability(token_id).expect("token exists");
    assert_eq!(token.revoked_at, Some(20));
    assert!(!token.is_active_at(20));

    let audit_len_before = reg.audit_trail().len();
    let token_before = token.clone();
    let err = reg
        .renew_capability("org:lane-xi-admin".to_string(), token_id, 20, Some(80))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 20,
            revoked_at: Some(20),
            ..
        } if err_token_id == token_id
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
