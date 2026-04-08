use super::*;

#[test]
fn renew_capability_extends_expiry_and_appends_audit() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(30),
        )
        .unwrap();

    reg.renew_capability("org:lane2-admin".to_string(), token_id, 25, Some(45))
        .unwrap();

    let token = reg.capability(token_id).unwrap();
    assert_eq!(token.expires_at, Some(45));

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityRenewed);
    assert_eq!(last.actor, "org:lane2-admin");
    assert_eq!(last.subject, "did:trnm:agent-renew");
    assert_eq!(last.at_height, 25);
    assert_eq!(last.note.as_deref(), Some("token_id=1 expires_at=Some(45)"));
}

#[test]
fn renew_capability_with_same_expiry_is_idempotent_without_new_audit() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-same-expiry".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-same-expiry".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(40),
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    reg.renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(40))
        .unwrap();

    let token = reg.capability(token_id).unwrap();
    assert_eq!(token.expires_at, Some(40));
    assert_eq!(token.revoked_at, None);
    assert_eq!(reg.audit_trail().len(), audit_len_before);

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityIssued);
    assert_eq!(last.at_height, 20);
}

#[test]
fn renew_capability_at_expiry_boundary_keeps_token_active_and_audited() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-boundary".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-boundary".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(30),
        )
        .unwrap();

    reg.renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(40))
        .unwrap();

    let token = reg.capability(token_id).unwrap();
    assert_eq!(token.expires_at, Some(40));
    assert!(token.is_active_at(40));

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityRenewed);
    assert_eq!(last.actor, "org:lane2-admin");
    assert_eq!(last.subject, "did:trnm:agent-renew-boundary");
    assert_eq!(last.at_height, 30);
    assert_eq!(last.note.as_deref(), Some("token_id=1 expires_at=Some(40)"));
}

#[test]
fn renew_capability_rejects_at_revocation_boundary_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-revoke-boundary".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-revoke-boundary".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("manual_boundary_revoke".to_string()),
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(90))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: 1,
            at_height: 30,
            issued_at: 20,
            expires_at: Some(60),
            revoked_at: Some(30),
        }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}

#[test]
fn renew_capability_with_non_expiring_token_is_idempotent_without_new_audit() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-no-expiry".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-no-expiry".to_string(),
            CapabilityScope::AuditRead,
            20,
            None,
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();

    reg.renew_capability("org:lane2-admin".to_string(), token_id, 25, None)
        .unwrap();

    let token = reg.capability(token_id).unwrap();
    assert_eq!(token.expires_at, None);
    assert_eq!(token.revoked_at, None);
    assert_eq!(reg.audit_trail().len(), audit_len_before);

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityIssued);
    assert_eq!(last.actor, "org:lane2-admin");
    assert_eq!(last.subject, "did:trnm:agent-renew-no-expiry");
    assert_eq!(last.at_height, 20);
}
