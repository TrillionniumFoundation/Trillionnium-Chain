use super::*;

#[test]
fn issue_capability_rejects_expiry_before_issue_height() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-1".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let err = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-1".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(19),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidCapabilityExpiry {
            issued_at: 20,
            expires_at: 19
        }
    ));
}

#[test]
fn issue_capability_failure_does_not_consume_token_sequence() {
    let mut reg = IdentityRegistry::default();

    let err = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:missing".to_string(),
            CapabilityScope::AuditRead,
            11,
            None,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidNotFound { did } if did == "did:trnm:missing"
    ));

    reg.register_did(
        "did:trnm:agent-5".to_string(),
        "org:lane2-admin".to_string(),
        12,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-5".to_string(),
            CapabilityScope::BridgeSettle,
            13,
            Some(200),
        )
        .unwrap();

    assert_eq!(token_id, 1);
}
