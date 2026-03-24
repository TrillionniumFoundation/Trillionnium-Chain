use super::*;

#[test]
fn renew_capability_rejects_unknown_token_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-missing".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let err = reg
        .renew_capability("org:lane2-admin".to_string(), 42, 25, Some(60))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityNotFound { token_id } if token_id == 42
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}
#[test]
fn renew_capability_rejects_missing_subject_did_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-missing-subject".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-missing-subject".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    // Simulate legacy/corrupt snapshot drift: token row exists but DID row is gone.
    let removed = reg.dids.remove("did:trnm:agent-renew-missing-subject");
    assert!(removed.is_some());

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(80))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidNotFound { did }
            if did == "did:trnm:agent-renew-missing-subject"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
#[test]
fn verify_capability_rejects_missing_subject_did_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-missing-subject".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-missing-subject".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(120),
        )
        .unwrap();

    // Simulate legacy/corrupt snapshot drift: capability exists but DID row was lost.
    let removed = reg.dids.remove("did:trnm:settler-missing-subject");
    assert!(removed.is_some());

    let audit_before = reg.audit_trail().to_vec();
    let token_before = reg.capability(token_id).cloned().unwrap();

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
        InteropIdentityError::DidNotFound { did }
            if did == "did:trnm:settler-missing-subject"
    ));
    assert_eq!(reg.audit_trail(), audit_before.as_slice());
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
#[test]
fn verify_capability_rejects_unknown_token_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-missing-token".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let baseline = reg.audit_trail().to_vec();
    let err = reg
        .verify_capability("org:lane2-admin", 42, CapabilityScope::BridgeSettle, 50)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityNotFound { token_id } if token_id == 42
    ));
    assert_eq!(reg.audit_trail(), baseline.as_slice());
}
