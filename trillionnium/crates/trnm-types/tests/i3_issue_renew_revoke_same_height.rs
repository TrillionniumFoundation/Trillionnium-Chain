use trnm_types::{AuditAction, CapabilityScope, IdentityRegistry, InteropIdentityError};

#[test]
fn issue_renew_revoke_same_height_is_fail_closed_at_boundary() {
    let mut reg = IdentityRegistry::default();
    let did = "did:trnm:agent-i3-issue-renew-revoke-race".to_string();
    let actor = "org:lane-xi-admin".to_string();

    reg.register_did(did.clone(), actor.clone(), 10).unwrap();

    let token_id = reg
        .issue_capability(
            actor.clone(),
            did,
            CapabilityScope::BridgeSettle,
            20,
            Some(30),
        )
        .unwrap();

    // I3 timing contract: renew and revoke may race at the same height.
    // Regardless of ordering, verification at the boundary must fail-closed.
    reg.renew_capability(actor.clone(), token_id, 30, Some(40))
        .unwrap();
    reg.revoke_capability(
        actor,
        token_id,
        30,
        Some("same_height_race_revoke".to_string()),
    )
    .unwrap();

    let token = reg.capability(token_id).expect("token exists");
    assert_eq!(token.expires_at, Some(40));
    assert_eq!(token.revoked_at, Some(30));

    let err = reg
        .verify_capability(
            "org:lane-xi-admin",
            token_id,
            CapabilityScope::BridgeSettle,
            30,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 30,
            issued_at: 20,
            expires_at: Some(40),
            revoked_at: Some(30),
        } if err_token_id == token_id
    ));

    let actions: Vec<_> = reg.audit_trail().iter().map(|ev| ev.action).collect();
    assert_eq!(
        actions,
        vec![
            AuditAction::DidRegistered,
            AuditAction::CapabilityIssued,
            AuditAction::CapabilityRenewed,
            AuditAction::CapabilityRevoked,
        ]
    );
}
