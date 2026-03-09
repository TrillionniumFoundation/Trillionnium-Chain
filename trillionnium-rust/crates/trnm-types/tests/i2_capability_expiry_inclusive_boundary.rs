use trnm_types::{CapabilityScope, CapabilityToken};

#[test]
fn expiring_capability_is_active_through_expiry_height_only() {
    let token = CapabilityToken {
        token_id: 108,
        subject_did: "did:trnm:agent-i2-expiry-inclusive".to_string(),
        scope: CapabilityScope::MarketExecute,
        issued_at: 300,
        expires_at: Some(360),
        revoked_at: None,
    };

    assert!(!token.is_active_at(299));
    assert!(token.is_active_at(300));
    assert!(token.is_active_at(359));
    assert!(token.is_active_at(360));
    assert!(!token.is_active_at(361));
}
