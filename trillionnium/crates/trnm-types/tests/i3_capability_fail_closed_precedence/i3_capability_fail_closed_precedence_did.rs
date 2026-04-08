use super::*;

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
        .verify_capability(
            "org:lane-xi-admin",
            token_id,
            CapabilityScope::AuditRead,
            35,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did } if did == "did:trnm:agent-i3-fail-closed-did-revoked"
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

#[test]
fn revoked_did_with_expired_token_and_scope_mismatch_still_returns_did_revoked_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-did-revoked-expired".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-did-revoked-expired".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(30),
        )
        .unwrap();

    reg.revoke_did(
        "org:lane-xi-admin".to_string(),
        "did:trnm:agent-i3-fail-closed-did-revoked-expired",
        35,
    )
    .unwrap();

    // I3 fail-closed contract: DID revocation must still dominate verifier error
    // shape even when capability expiry (inactive) and scope mismatch are also true.
    let err = reg
        .verify_capability(
            "org:lane-xi-admin",
            token_id,
            CapabilityScope::AuditRead,
            40,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did }
            if did == "did:trnm:agent-i3-fail-closed-did-revoked-expired"
    ));
}

#[test]
fn revoked_did_with_expired_token_and_unauthorized_actor_still_returns_did_revoked_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-did-revoked-expired-unauth".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-did-revoked-expired-unauth".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(30),
        )
        .unwrap();

    reg.revoke_did(
        "org:lane-xi-admin".to_string(),
        "did:trnm:agent-i3-fail-closed-did-revoked-expired-unauth",
        35,
    )
    .unwrap();

    // I3 fail-closed contract: DID revocation must dominate even when expiry and
    // actor unauthorized conditions are both true at verification height.
    let err = reg
        .verify_capability("org:intruder", token_id, CapabilityScope::BridgeSettle, 40)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did }
            if did == "did:trnm:agent-i3-fail-closed-did-revoked-expired-unauth"
    ));
}

#[test]
fn revoked_did_with_revoked_token_and_scope_mismatch_still_returns_did_revoked_fail_closed() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-did-and-token-revoked".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-did-and-token-revoked".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(80),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane-xi-admin".to_string(),
        token_id,
        30,
        Some("precedence_revoke_token".to_string()),
    )
    .unwrap();

    reg.revoke_did(
        "org:lane-xi-admin".to_string(),
        "did:trnm:agent-i3-fail-closed-did-and-token-revoked",
        35,
    )
    .unwrap();

    // I3 fail-closed contract: once DID is revoked, DidRevoked must dominate
    // even when token-level inactive and scope mismatch are simultaneously true.
    let err = reg
        .verify_capability(
            "org:lane-xi-admin",
            token_id,
            CapabilityScope::AuditRead,
            40,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did }
            if did == "did:trnm:agent-i3-fail-closed-did-and-token-revoked"
    ));
}
