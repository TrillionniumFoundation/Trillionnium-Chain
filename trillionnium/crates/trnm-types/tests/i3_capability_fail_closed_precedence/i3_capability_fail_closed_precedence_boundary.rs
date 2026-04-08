use super::*;

#[test]
fn pre_revocation_height_with_unauthorized_actor_returns_unauthorized_not_did_revoked() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-i3-fail-closed-pre-revoke-actor".to_string(),
        "org:lane-xi-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane-xi-admin".to_string(),
            "did:trnm:agent-i3-fail-closed-pre-revoke-actor".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(80),
        )
        .unwrap();

    reg.revoke_did(
        "org:lane-xi-admin".to_string(),
        "did:trnm:agent-i3-fail-closed-pre-revoke-actor",
        35,
    )
    .unwrap();

    // I3 boundary contract: before the DID revocation boundary, verifier should
    // not over-dominate with DidRevoked; normal actor authorization still applies.
    let err = reg
        .verify_capability("org:intruder", token_id, CapabilityScope::BridgeSettle, 34)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::UnauthorizedActor {
            actor,
            did,
            controller
        } if actor == "org:intruder"
            && did == "did:trnm:agent-i3-fail-closed-pre-revoke-actor"
            && controller == "org:lane-xi-admin"
    ));
}
