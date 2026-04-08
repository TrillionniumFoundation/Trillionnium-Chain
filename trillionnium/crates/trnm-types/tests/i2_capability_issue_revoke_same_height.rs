use trnm_types::{CapabilityScope, CapabilityToken};

#[test]
fn capability_revoked_at_issue_height_is_never_active() {
    let token = CapabilityToken {
        token_id: 9,
        subject_did: "did:trnm:agent-i2-boundary".to_string(),
        scope: CapabilityScope::AuditRead,
        issued_at: 100,
        expires_at: Some(200),
        revoked_at: Some(100),
    };

    assert!(!token.is_active_at(99));
    assert!(!token.is_active_at(100));
    assert!(!token.is_active_at(101));
}
