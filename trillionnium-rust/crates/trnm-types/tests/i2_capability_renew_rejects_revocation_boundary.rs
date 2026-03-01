use trnm_types::{CapabilityScope, IdentityRegistry, InteropIdentityError};

#[test]
fn renew_capability_rejects_height_equal_to_revocation_boundary() {
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
        Some("manual_revoke".to_string()),
    )
    .unwrap();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(80))
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

    let token = reg.capability(token_id).unwrap();
    assert_eq!(token.expires_at, Some(60));
    assert_eq!(token.revoked_at, Some(30));
}
