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

#[test]
fn revoked_token_with_unauthorized_actor_returns_inactive_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-unauth".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-unauth".to_string(),
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

    // I3 fail-closed contract: inactive state must dominate unauthorized actor
    // checks to avoid leaking authorization details through verifier error shape.
    let err = reg
        .verify_capability("org:intruder", token_id, CapabilityScope::BridgeSettle, 35)
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

#[test]
fn expired_token_with_scope_mismatch_returns_inactive_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-expired".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-expired".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(30),
        )
        .unwrap();

    // I3 fail-closed contract: inactive state from expiry must dominate scope
    // mismatch checks, preserving stable verifier error semantics.
    let err = reg
        .verify_capability("org:lane-xi-admin", token_id, CapabilityScope::AuditRead, 31)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 31,
            issued_at: 20,
            expires_at: Some(30),
            revoked_at: None,
        } if err_token_id == token_id
    ));
}

#[test]
fn expired_token_with_unauthorized_actor_returns_inactive_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-expired-unauth".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-expired-unauth".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(30),
        )
        .unwrap();

    // I3 fail-closed contract: inactive state from expiry must dominate actor
    // authorization checks so verifier error shape does not leak authz details.
    let err = reg
        .verify_capability("org:intruder", token_id, CapabilityScope::BridgeSettle, 31)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 31,
            issued_at: 20,
            expires_at: Some(30),
            revoked_at: None,
        } if err_token_id == token_id
    ));
}

#[test]
fn revoked_and_expired_token_with_unauthorized_actor_returns_inactive_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-revoked-expired".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-revoked-expired".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(28),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        25,
        Some("precedence_revoke".to_string()),
    )
    .unwrap();

    // I3 fail-closed contract: inactive must dominate actor authorization checks,
    // even when both revocation and expiry are true at verification height.
    let err = reg
        .verify_capability("org:intruder", token_id, CapabilityScope::BridgeSettle, 31)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 31,
            issued_at: 20,
            expires_at: Some(28),
            revoked_at: Some(25),
        } if err_token_id == token_id
    ));
}

#[test]
fn revoked_did_with_scope_mismatch_returns_did_revoked_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-did-revoked".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-did-revoked".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(80),
        )
        .unwrap();

    reg.revoke_did(
        "org:lane-xi-admin".to_string(),
        "did:trnm:agent-i3-fail-closed-did-revoked",
        35,
    )
    .unwrap();

    // I3 fail-closed contract: DID revocation must dominate requested scope
    // mismatch checks so verifier error shape does not leak authz semantics.
    let err = reg
        .verify_capability("org:lane-xi-admin", token_id, CapabilityScope::AuditRead, 35)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did } if did == "did:trnm:agent-i3-fail-closed-did-revoked"
    ));
}

#[test]
fn preissued_token_with_unauthorized_actor_returns_inactive_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-preissue".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-preissue".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(80),
        )
        .unwrap();

    // I3 fail-closed contract: pre-issue verification must short-circuit as inactive
    // before actor authorization checks, preventing auth-shape leakage.
    let err = reg
        .verify_capability("org:intruder", token_id, CapabilityScope::BridgeSettle, 19)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 19,
            issued_at: 20,
            expires_at: Some(80),
            revoked_at: None,
        } if err_token_id == token_id
    ));
}

#[test]
fn revoked_did_with_unauthorized_actor_still_returns_did_revoked_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-did-revoked-unauth".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-did-revoked-unauth".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(80),
        )
        .unwrap();

    reg.revoke_did(
        "org:lane-xi-admin".to_string(),
        "did:trnm:agent-i3-fail-closed-did-revoked-unauth",
        35,
    )
    .unwrap();

    // I3 fail-closed contract: DID revocation should dominate actor auth checks
    // so unauthorized callers do not get an ActorUnauthorized-shaped side channel.
    let err = reg
        .verify_capability("org:intruder", token_id, CapabilityScope::BridgeSettle, 35)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did }
            if did == "did:trnm:agent-i3-fail-closed-did-revoked-unauth"
    ));
}

#[test]
fn revoked_did_before_token_issue_still_returns_did_revoked_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-did-revoked-preissue".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-did-revoked-preissue".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(80),
        )
        .unwrap();

    reg.revoke_did(
        "org:lane-xi-admin".to_string(),
        "did:trnm:agent-i3-fail-closed-did-revoked-preissue",
        15,
    )
    .unwrap();

    // I3 fail-closed contract: DID revocation must dominate even when the token
    // is also inactive because verify height is before issued_at.
    let err = reg
        .verify_capability("org:intruder", token_id, CapabilityScope::AuditRead, 19)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did }
            if did == "did:trnm:agent-i3-fail-closed-did-revoked-preissue"
    ));
}
