use super::*;

#[test]
fn revoke_capability_is_idempotent_for_audit_and_timestamp() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3".to_string(),
            CapabilityScope::AuditRead,
            12,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("security_rotate".to_string()),
    )
    .unwrap();
    let first_audit_len = reg.audit_trail().len();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        90,
        Some("late_duplicate".to_string()),
    )
    .unwrap();

    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(30));
    assert_eq!(reg.audit_trail().len(), first_audit_len);
}

#[test]
fn revoke_capability_replay_with_same_height_is_idempotent_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3eq".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3eq".to_string(),
            CapabilityScope::AuditRead,
            12,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("initial_revoke".to_string()),
    )
    .unwrap();
    let audit_len_before = reg.audit_trail().len();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("same_height_replay".to_string()),
    )
    .unwrap();

    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(30));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}

#[test]
fn revoke_capability_makes_token_inactive_at_same_height_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3eq-boundary".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3eq-boundary".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(80),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("boundary_revoke".to_string()),
    )
    .unwrap();

    let err = reg
        .verify_capability("org:lane2-admin", token_id, CapabilityScope::AuditRead, 30)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 30,
            issued_at: 12,
            expires_at: Some(80),
            revoked_at: Some(30),
        } if err_token_id == token_id
    ));
}

#[test]
fn revoke_capability_replay_with_older_height_is_rejected_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3r".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3r".to_string(),
            CapabilityScope::AuditRead,
            12,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("initial_revoke".to_string()),
    )
    .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            29,
            Some("stale_replay".to_string()),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidCapabilityRevocationHeight {
            issued_at: 30,
            revoked_at: 29,
        }
    ));
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(30));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}

#[test]
fn revoke_capability_rejects_height_before_issue_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3b".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3b".to_string(),
            CapabilityScope::AuditRead,
            12,
            None,
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            11,
            Some("time_travel_revoke".to_string()),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidCapabilityRevocationHeight {
            issued_at: 12,
            revoked_at: 11
        }
    ));
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}
