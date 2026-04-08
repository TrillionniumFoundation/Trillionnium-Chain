use trnm_types::{CapabilityScope, CapabilityToken};

#[test]
fn capability_revocation_takes_precedence_over_expiry_window() {
    let token = CapabilityToken {
        token_id: 42,
        subject_did: "did:trnm:agent-i2-expiry-revoke".to_string(),
        scope: CapabilityScope::BridgeSettle,
        issued_at: 100,
        expires_at: Some(180),
        revoked_at: Some(140),
    };

    assert!(token.is_active_at(139));
    assert!(!token.is_active_at(140));
    assert!(!token.is_active_at(150));
    assert!(!token.is_active_at(180));
}
