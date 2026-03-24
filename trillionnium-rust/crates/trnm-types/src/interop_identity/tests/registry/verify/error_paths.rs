use super::*;

#[test]
fn verify_capability_rejects_scope_mismatch_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-2".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-2".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(200),
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .verify_capability(
            "org:lane2-admin",
            token_id,
            CapabilityScope::BridgeSettle,
            50,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityScopeMismatch {
            token_id: id,
            expected: CapabilityScope::BridgeSettle,
            actual: CapabilityScope::AuditRead,
        } if id == token_id
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
}

#[test]
fn verify_capability_rejects_revoked_did_even_if_token_looks_active() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-legacy".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-legacy".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    // simulate a legacy/corrupt snapshot: DID revoked but token still not revoked.
    reg.dids
        .get_mut("did:trnm:settler-legacy")
        .unwrap()
        .revoked_at = Some(25);
    reg.capabilities.get_mut(&token_id).unwrap().revoked_at = None;

    let err = reg
        .verify_capability(
            "org:lane2-admin",
            token_id,
            CapabilityScope::BridgeSettle,
            30,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did } if did == "did:trnm:settler-legacy"
    ));
}

#[test]
fn verify_capability_rejects_height_equal_to_did_revocation_boundary() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-legacy-boundary".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-legacy-boundary".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    // Legacy/corrupt snapshot: DID revocation exists but token revoke cascade is absent.
    reg.dids
        .get_mut("did:trnm:settler-legacy-boundary")
        .unwrap()
        .revoked_at = Some(80);
    reg.capabilities.get_mut(&token_id).unwrap().revoked_at = None;

    let err = reg
        .verify_capability(
            "org:lane2-admin",
            token_id,
            CapabilityScope::BridgeSettle,
            80,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did } if did == "did:trnm:settler-legacy-boundary"
    ));
}

#[test]
fn verify_capability_rejects_expired_token_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-expired".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-expired".to_string(),
            CapabilityScope::BridgeRevert,
            20,
            Some(30),
        )
        .unwrap();

    let baseline_audit = reg.audit_trail().to_vec();
    let baseline_token = reg.capability(token_id).cloned().unwrap();
    let err = reg
        .verify_capability(
            "org:lane2-admin",
            token_id,
            CapabilityScope::BridgeRevert,
            31,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: id,
            at_height: 31,
            issued_at: 20,
            expires_at: Some(30),
            revoked_at: None,
        } if id == token_id
    ));
    assert_eq!(reg.audit_trail(), baseline_audit.as_slice());
    assert_eq!(reg.capability(token_id), Some(&baseline_token));
}

#[test]
fn verify_capability_rejects_height_before_issue_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-before-issue".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-before-issue".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();

    let baseline_audit = reg.audit_trail().to_vec();
    let baseline_token = reg.capability(token_id).cloned().unwrap();
    let err = reg
        .verify_capability(
            "org:lane2-admin",
            token_id,
            CapabilityScope::BridgeSettle,
            19,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: id,
            at_height: 19,
            issued_at: 20,
            expires_at: None,
            revoked_at: None,
        } if id == token_id
    ));
    assert_eq!(reg.audit_trail(), baseline_audit.as_slice());
    assert_eq!(reg.capability(token_id), Some(&baseline_token));
}
