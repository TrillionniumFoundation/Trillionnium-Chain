use trnm_types::{CapabilityScope, IdentityRegistry, InteropIdentityError};

#[test]
fn revoke_dominates_issue_renew_revoke_competition_at_same_height() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-race".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-race".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(60),
        )
        .unwrap();

    // Competition path: renew and revoke race at the same height. If renew lands first,
    // revoke must still dominate final liveness at that boundary.
    reg.renew_capability("org:lane-xi-admin".to_string(), token_id, 30, Some(90))
        .unwrap();
    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        30,
        Some("race_revoke".to_string()),
    )
    .unwrap();

    let token = reg.capability(token_id).expect("token exists");
    assert_eq!(token.expires_at, Some(90));
    assert_eq!(token.revoked_at, Some(30));
    assert!(!token.is_active_at(30));
    assert!(!token.is_active_at(31));

    // Fail-closed contract: post-revocation renew attempts must be rejected with
    // a stable inactive error carrying the revocation boundary.
    let err = reg
        .renew_capability("org:lane-xi-admin".to_string(), token_id, 31, Some(120))
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 31,
            revoked_at: Some(30),
            ..
        } if err_token_id == token_id
    ));
}

#[test]
fn renew_at_revocation_boundary_is_fail_closed_when_revoke_lands_first() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-revoke-first".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-revoke-first".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        30,
        Some("revoke_first".to_string()),
    )
    .unwrap();

    let err = reg
        .renew_capability("org:lane-xi-admin".to_string(), token_id, 30, Some(90))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 30,
            issued_at: 20,
            expires_at: Some(60),
            revoked_at: Some(30),
        } if err_token_id == token_id
    ));

    let token = reg.capability(token_id).expect("token exists");
    assert_eq!(token.expires_at, Some(60));
    assert_eq!(token.revoked_at, Some(30));
}

#[test]
fn verify_at_revocation_boundary_is_fail_closed_after_same_height_renew_revoke_race() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-verify-race".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-verify-race".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(60),
        )
        .unwrap();

    // Same-height race where renew lands first; verify at that exact boundary must
    // still fail-closed once revoke is observed.
    reg.renew_capability("org:lane-xi-admin".to_string(), token_id, 30, Some(90))
        .unwrap();
    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        30,
        Some("same_height_race".to_string()),
    )
    .unwrap();

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
            expires_at: Some(90),
            revoked_at: Some(30),
        } if err_token_id == token_id
    ));
}
