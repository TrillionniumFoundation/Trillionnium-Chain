use super::*;

#[test]
fn verify_before_revocation_boundary_stays_active_after_same_height_renew_revoke_race() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-verify-pre-boundary".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-verify-pre-boundary".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(60),
        )
        .unwrap();

    // Same-height renew/revoke race: revocation must be fail-closed at boundary,
    // but historical verification just before that boundary remains valid.
    reg.renew_capability("org:lane-xi-admin".to_string(), token_id, 30, Some(90))
        .unwrap();
    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        30,
        Some("same_height_race".to_string()),
    )
    .unwrap();

    reg.verify_capability(
        "org:lane-xi-admin",
        token_id,
        CapabilityScope::BridgeSettle,
        29,
    )
    .unwrap();
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
