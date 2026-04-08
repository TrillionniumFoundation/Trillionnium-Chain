use super::*;

#[test]
fn verify_capability_accepts_active_controller_and_matching_scope() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-1".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-1".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    reg.verify_capability(
        "org:lane2-admin",
        token_id,
        CapabilityScope::BridgeSettle,
        50,
    )
    .unwrap();
}

#[test]
fn verify_capability_allows_historical_height_before_did_revocation() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-legacy-historical".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-legacy-historical".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    // Legacy/corrupt snapshot: DID was revoked, but token revocation was never cascaded.
    reg.dids
        .get_mut("did:trnm:settler-legacy-historical")
        .unwrap()
        .revoked_at = Some(80);
    reg.capabilities.get_mut(&token_id).unwrap().revoked_at = None;

    let out = reg.verify_capability(
        "org:lane2-admin",
        token_id,
        CapabilityScope::BridgeSettle,
        79,
    );

    assert!(out.is_ok());
}

#[test]
fn verify_capability_accepts_height_equal_to_expiry_boundary() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-expiry-boundary".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-expiry-boundary".to_string(),
            CapabilityScope::BridgeRevert,
            20,
            Some(30),
        )
        .unwrap();

    let baseline_audit = reg.audit_trail().to_vec();
    let baseline_token = reg.capability(token_id).cloned().unwrap();
    reg.verify_capability(
        "org:lane2-admin",
        token_id,
        CapabilityScope::BridgeRevert,
        30,
    )
    .unwrap();

    assert_eq!(reg.audit_trail(), baseline_audit.as_slice());
    assert_eq!(reg.capability(token_id), Some(&baseline_token));
}
