use super::*;

#[test]
fn renew_capability_rejects_expiry_before_renew_height_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-invalid-expiry".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-invalid-expiry".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 25, Some(24))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidCapabilityExpiry {
            issued_at: 25,
            expires_at: 24,
        }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}

#[test]
fn renew_capability_rejects_expiry_regression_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 25, Some(45))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityRenewalRegression {
            current_expires_at: 60,
            requested_expires_at: 45,
        }
    ));
    let token = reg.capability(token_id).unwrap();
    assert_eq!(token.expires_at, Some(60));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}

#[test]
fn renew_capability_rejects_clearing_existing_expiry_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-clear-expiry".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-clear-expiry".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 25, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityRenewalCannotClearExpiry {
            current_expires_at: 60,
        }
    ));
    let token = reg.capability(token_id).unwrap();
    assert_eq!(token.expires_at, Some(60));
    assert_eq!(token.revoked_at, None);
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}

#[test]
fn renew_capability_rejects_height_before_issue_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-preissue".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-preissue".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .renew_capability("org:lane2-admin".to_string(), token_id, 19, Some(80))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::CapabilityInactive {
            token_id: err_token_id,
            at_height: 19,
            issued_at: 20,
            expires_at: Some(60),
            revoked_at: None,
        } if err_token_id == token_id
    ));
    let token = reg.capability(token_id).unwrap();
    assert_eq!(token.expires_at, Some(60));
    assert_eq!(token.revoked_at, None);
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}
