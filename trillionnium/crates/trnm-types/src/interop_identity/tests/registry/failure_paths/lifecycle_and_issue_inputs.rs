use super::*;

#[test]
fn renew_capability_rejects_revoked_did_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-revoked".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-revoked".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    reg.revoke_did(
        "org:lane2-admin".to_string(),
        "did:trnm:agent-renew-revoked",
        30,
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 35, Some(80))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did } if did == "did:trnm:agent-renew-revoked"
    ));
    let token_after = reg.capability(token_id).unwrap();
    assert_eq!(token_after.expires_at, token_before.expires_at);
    assert_eq!(token_after.revoked_at, token_before.revoked_at);
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}
#[test]
fn renew_capability_rejects_previously_revoked_token_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-token-revoked".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-token-revoked".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("manual_revoke_before_renew".to_string()),
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 35, Some(80))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 35,
            issued_at: 20,
            expires_at: Some(60),
            revoked_at: Some(30),
        } if err_token_id == token_id
    ));

    let token_after = reg.capability(token_id).unwrap();
    assert_eq!(token_after.expires_at, token_before.expires_at);
    assert_eq!(token_after.revoked_at, token_before.revoked_at);
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}
#[test]
fn renew_capability_rejects_when_renew_height_equals_revocation_height() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-revoke-race".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-revoke-race".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("race_revoke".to_string()),
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(90))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 30,
            issued_at: 20,
            expires_at: Some(60),
            revoked_at: Some(30),
        } if err_token_id == token_id
    ));

    let token_after = reg.capability(token_id).unwrap();
    assert_eq!(token_after.expires_at, token_before.expires_at);
    assert_eq!(token_after.revoked_at, token_before.revoked_at);
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}
#[test]
fn renew_capability_rejects_when_renew_height_equals_did_revocation_boundary() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-did-race".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-did-race".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    reg.revoke_did(
        "org:lane2-admin".to_string(),
        "did:trnm:agent-renew-did-race",
        30,
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(90))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked { did } if did == "did:trnm:agent-renew-did-race"
    ));
    let token_after = reg.capability(token_id).unwrap();
    assert_eq!(token_after.expires_at, token_before.expires_at);
    assert_eq!(token_after.revoked_at, token_before.revoked_at);
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}
#[test]
fn issue_capability_rejects_noncanonical_actor_identity_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-6".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .issue_capability(
            " org:lane2-admin".to_string(),
            "did:trnm:agent-6".to_string(),
            CapabilityScope::AuditRead,
            20,
            None,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert!(reg.capability(1).is_none());
}
#[test]
fn issue_capability_rejects_noncanonical_subject_did_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-6b".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            " did:trnm:agent-6b ".to_string(),
            CapabilityScope::AuditRead,
            20,
            None,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue {
            field: "subject_did",
            ..
        }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert!(reg.capability(1).is_none());
}
