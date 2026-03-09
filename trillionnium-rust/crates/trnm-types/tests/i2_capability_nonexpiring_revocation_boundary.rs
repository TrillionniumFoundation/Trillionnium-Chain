use trnm_types::{CapabilityScope, CapabilityToken};

#[test]
fn non_expiring_capability_still_honors_revocation_boundary() {
    let token = CapabilityToken {
        token_id: 77,
        subject_did: "did:trnm:agent-i2-nonexpiring-revoke".to_string(),
        scope: CapabilityScope::BridgeRevert,
        issued_at: 200,
        expires_at: None,
        revoked_at: Some(245),
    };

    assert!(!token.is_active_at(199));
    assert!(token.is_active_at(200));
    assert!(token.is_active_at(244));
    assert!(!token.is_active_at(245));
    assert!(!token.is_active_at(280));
}
