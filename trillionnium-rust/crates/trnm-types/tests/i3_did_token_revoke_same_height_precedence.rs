use trnm_types::{AuditAction, CapabilityScope, IdentityRegistry, InteropIdentityError};

#[test]
fn did_revoke_dominates_token_revoke_at_same_height_for_verifier_shape() {
    let mut reg = IdentityRegistry::default();
    let did = "did:trnm:agent-i3-did-token-precedence".to_string();
    let actor = "org:lane-xi-admin".to_string();

    reg.register_did(did.clone(), actor.clone(), 10).unwrap();

    let token_id = reg
        .issue_capability(
            actor.clone(),
            did.clone(),
            CapabilityScope::BridgeSettle,
            20,
            Some(80),
        )
        .unwrap();

    // I3 contract: at the same boundary, DID-level revoke must dominate verifier
    // error shape over token-level inactive semantics.
    reg.revoke_did(actor.clone(), &did, 35).unwrap();
    reg.revoke_capability(
        actor,
        token_id,
        35,
        Some("same_height_did_token_revoke".to_string()),
    )
    .unwrap();

    let err = reg
        .verify_capability(
            "org:lane-xi-admin",
            token_id,
            CapabilityScope::BridgeSettle,
            35,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did: err_did }
            if err_did == "did:trnm:agent-i3-did-token-precedence"
    ));

    let actions: Vec<_> = reg.audit_trail().iter().map(|ev| ev.action).collect();
    assert_eq!(
        actions,
        vec![
            AuditAction::DidRegistered,
            AuditAction::CapabilityIssued,
            AuditAction::DidRevoked,
            AuditAction::CapabilityRevoked,
        ]
    );
}
