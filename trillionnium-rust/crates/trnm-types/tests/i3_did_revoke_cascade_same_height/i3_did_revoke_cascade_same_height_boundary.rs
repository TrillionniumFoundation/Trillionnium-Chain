use super::*;

#[test]
fn did_revoke_cascade_same_height_fail_closed_for_all_subject_tokens() {
    let mut reg = IdentityRegistry::default();
    let did = "did:trnm:agent-i3-did-cascade-race".to_string();
    let actor = "org:lane-xi-admin".to_string();

    reg.register_did(did.clone(), actor.clone(), 10).unwrap();

    let token_a = reg
        .issue_capability(
            actor.clone(),
            did.clone(),
            CapabilityScope::BridgeSettle,
            20,
            Some(80),
        )
        .unwrap();
    let token_b = reg
        .issue_capability(
            actor.clone(),
            did.clone(),
            CapabilityScope::AuditRead,
            30,
            None,
        )
        .unwrap();

    // I3 timing contract: DID-level revoke at height 30 must cascade to every
    // subject token with revoked_at anchored to the revocation boundary.
    reg.revoke_did(actor.clone(), &did, 30).unwrap();

    let token_a_state = reg.capability(token_a).expect("token_a exists");
    let token_b_state = reg.capability(token_b).expect("token_b exists");
    assert_eq!(token_a_state.revoked_at, Some(30));
    assert_eq!(token_b_state.revoked_at, Some(30));

    // Historical pre-boundary verify remains valid.
    reg.verify_capability(
        "org:lane-xi-admin",
        token_a,
        CapabilityScope::BridgeSettle,
        29,
    )
    .unwrap();

    // Boundary verification is fail-closed for both tokens with DID-level
    // precedence (I3): once DID is revoked, verifier returns DidRevoked.
    for (token_id, scope) in [
        (token_a, CapabilityScope::BridgeSettle),
        (token_b, CapabilityScope::AuditRead),
    ] {
        let err = reg
            .verify_capability("org:lane-xi-admin", token_id, scope, 30)
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::DidRevoked { did: ref err_did }
                if err_did == "did:trnm:agent-i3-did-cascade-race"
        ));
    }

    // Audit ordering: DID revoke followed by deterministic cascade revoke events.
    let did_revokes: Vec<_> = reg
        .audit_trail()
        .iter()
        .filter(|ev| ev.action == AuditAction::DidRevoked)
        .collect();
    assert_eq!(did_revokes.len(), 1);
    assert_eq!(did_revokes[0].at_height, 30);

    let cascade_revokes: Vec<_> = reg
        .audit_trail()
        .iter()
        .filter(|ev| {
            ev.action == AuditAction::CapabilityRevoked
                && ev.actor == "system:cascade"
                && ev
                    .note
                    .as_deref()
                    .is_some_and(|note| note.starts_with("cascade_on_did_revoke token_id="))
        })
        .collect();
    assert_eq!(cascade_revokes.len(), 2);
    assert_eq!(
        cascade_revokes
            .iter()
            .map(|ev| ev.at_height)
            .collect::<Vec<_>>(),
        vec![30, 30]
    );
}
