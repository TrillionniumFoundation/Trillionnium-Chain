use super::*;

#[test]
fn capability_is_not_active_before_issue_height() {
    let token = CapabilityToken {
        token_id: 1,
        subject_did: "did:trnm:agent-issue-window".to_string(),
        scope: CapabilityScope::BridgeSettle,
        issued_at: 50,
        expires_at: Some(60),
        revoked_at: None,
    };

    assert!(!token.is_active_at(49));
    assert!(token.is_active_at(50));
    assert!(token.is_active_at(60));
    assert!(!token.is_active_at(61));
}

#[test]
fn capability_revocation_respects_historical_heights() {
    let token = CapabilityToken {
        token_id: 2,
        subject_did: "did:trnm:agent-revoke-window".to_string(),
        scope: CapabilityScope::AuditRead,
        issued_at: 10,
        expires_at: None,
        revoked_at: Some(20),
    };

    assert!(token.is_active_at(19));
    assert!(!token.is_active_at(20));
    assert!(!token.is_active_at(21));
}

#[test]
fn capability_expiry_is_inclusive_at_expiry_height() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-11".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-11".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(25),
        )
        .unwrap();

    let token = reg.capability(token_id).unwrap();
    assert!(token.is_active_at(20));
    assert!(token.is_active_at(25));
    assert!(!token.is_active_at(26));
}
