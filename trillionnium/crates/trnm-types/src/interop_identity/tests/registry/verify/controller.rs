use super::*;

#[test]
fn verify_capability_rejects_inactive_or_unauthorized_actor() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-3".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-3".to_string(),
            CapabilityScope::BridgeRevert,
            20,
            Some(30),
        )
        .unwrap();

    let err = reg
        .verify_capability(
            "org:lane2-admin",
            token_id,
            CapabilityScope::BridgeRevert,
            31,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: id,
            at_height: 31,
            issued_at: 20,
            expires_at: Some(30),
            revoked_at: None,
        } if id == token_id
    ));

    let token2 = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-3".to_string(),
            CapabilityScope::BridgeRevert,
            40,
            None,
        )
        .unwrap();
    let err = reg
        .verify_capability(
            "org:lane2-backup",
            token2,
            CapabilityScope::BridgeRevert,
            45,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::UnauthorizedActor {
            actor,
            did,
            controller,
        } if actor == "org:lane2-backup"
            && did == "did:trnm:settler-3"
            && controller == "org:lane2-admin"
    ));
}

#[test]
fn verify_capability_unauthorized_actor_does_not_mutate_registry() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-authz-no-side-effect".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-authz-no-side-effect".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(120),
        )
        .unwrap();

    let audit_before = reg.audit_trail().to_vec();
    let token_before = reg.capability(token_id).cloned().unwrap();

    let err = reg
        .verify_capability(
            "org:lane2-unauthorized",
            token_id,
            CapabilityScope::BridgeSettle,
            30,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::UnauthorizedActor {
            actor,
            did,
            controller,
        } if actor == "org:lane2-unauthorized"
            && did == "did:trnm:settler-authz-no-side-effect"
            && controller == "org:lane2-admin"
    ));
    assert_eq!(reg.audit_trail(), audit_before.as_slice());
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
