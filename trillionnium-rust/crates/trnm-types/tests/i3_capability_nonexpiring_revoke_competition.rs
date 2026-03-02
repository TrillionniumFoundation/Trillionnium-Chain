use trnm_types::{CapabilityScope, IdentityRegistry, InteropIdentityError};

#[test]
fn nonexpiring_token_revoke_then_same_height_renew_is_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-nonexpiring-race".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-nonexpiring-race".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        35,
        Some("nonexpiring_race_revoke".to_string()),
    )
    .unwrap();

    let err = reg
        .renew_capability("org:lane-xi-admin".to_string(), token_id, 35, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 35,
            issued_at: 20,
            expires_at: None,
            revoked_at: Some(35),
        } if err_token_id == token_id
    ));

    let token = reg.capability(token_id).expect("token exists");
    assert_eq!(token.expires_at, None);
    assert_eq!(token.revoked_at, Some(35));
    assert!(!token.is_active_at(35));
    assert!(!token.is_active_at(36));
}
