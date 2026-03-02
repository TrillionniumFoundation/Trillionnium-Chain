use trnm_types::{CapabilityScope, IdentityRegistry, InteropIdentityError};

#[test]
fn revoked_token_with_scope_mismatch_returns_inactive_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(80),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        35,
        Some("precedence_revoke".to_string()),
    )
    .unwrap();

    // I3 fail-closed contract: once token is inactive, verifier should return
    // CapabilityInactive even when requested scope is mismatched.
    let err = reg
        .verify_capability(
            "org:lane-xi-admin",
            token_id,
            CapabilityScope::AuditRead,
            35,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 35,
            issued_at: 20,
            expires_at: Some(80),
            revoked_at: Some(35),
        } if err_token_id == token_id
    ));
}
