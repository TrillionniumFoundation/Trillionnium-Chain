use super::*;

#[test]
fn renew_capability_rejects_actor_that_is_not_did_controller_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-auth".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-auth".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(50),
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .renew_capability("org:lane2-observer".to_string(), token_id, 25, Some(60))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::UnauthorizedActor {
            actor,
            did,
            controller,
        } if actor == "org:lane2-observer"
            && did == "did:trnm:agent-renew-auth"
            && controller == "org:lane2-admin"
    ));
    let token = reg.capability(token_id).unwrap();
    assert_eq!(token.expires_at, Some(50));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}
#[test]
fn issue_capability_rejects_actor_that_is_not_did_controller_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-8".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .issue_capability(
            "org:lane2-backup".to_string(),
            "did:trnm:agent-8".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::UnauthorizedActor {
            actor,
            did,
            controller,
        } if actor == "org:lane2-backup"
            && did == "did:trnm:agent-8"
            && controller == "org:lane2-admin"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert!(reg.capability(1).is_none());
}
#[test]
fn revoke_capability_rejects_actor_that_is_not_did_controller_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-9".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-9".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability("org:lane2-backup".to_string(), token_id, 30, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::UnauthorizedActor {
            actor,
            did,
            controller,
        } if actor == "org:lane2-backup"
            && did == "did:trnm:agent-9"
            && controller == "org:lane2-admin"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
}
#[test]
fn revoke_capability_keeps_controller_check_even_after_token_is_revoked() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-10".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-10".to_string(),
            CapabilityScope::AuditRead,
            20,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("first_revoke".to_string()),
    )
    .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability("org:lane2-backup".to_string(), token_id, 40, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::UnauthorizedActor {
            actor,
            did,
            controller,
        } if actor == "org:lane2-backup"
            && did == "did:trnm:agent-10"
            && controller == "org:lane2-admin"
    ));
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(30));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}
