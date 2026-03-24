use super::*;

#[test]
fn renew_capability_rejects_noncanonical_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-actorfmt".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-actorfmt".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability(" org:lane2-admin ".to_string(), token_id, 25, Some(80))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
#[test]
fn renew_capability_rejects_blank_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-blank-actor".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-blank-actor".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability("   ".to_string(), token_id, 25, Some(80))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
#[test]
fn renew_capability_rejects_control_character_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-control-actor".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-control-actor".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability("org:lane2-admin\n".to_string(), token_id, 25, Some(80))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
#[test]
fn renew_capability_rejects_zero_width_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-zero-width-actor".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-zero-width-actor".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability(
            "org:lane2-admin\u{200b}".to_string(),
            token_id,
            25,
            Some(80),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
#[test]
fn renew_capability_rejects_zero_width_non_joiner_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-zwnj-actor".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-zwnj-actor".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability(
            "org:lane2-admin\u{200c}".to_string(),
            token_id,
            25,
            Some(80),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
#[test]
fn renew_capability_rejects_word_joiner_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-word-joiner-actor".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-word-joiner-actor".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability(
            "org:lane2-admin\u{2060}".to_string(),
            token_id,
            25,
            Some(80),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
#[test]
fn renew_capability_rejects_arabic_letter_mark_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-alm-actor".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-alm-actor".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability(
            "org:lane2-admin\u{061C}".to_string(),
            token_id,
            25,
            Some(80),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
#[test]
fn renew_capability_rejects_bom_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-renew-bom-actor".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-bom-actor".to_string(),
            CapabilityScope::AuditRead,
            20,
            Some(60),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).unwrap().clone();

    let err = reg
        .renew_capability(
            "org:lane2-admin\u{FEFF}".to_string(),
            token_id,
            25,
            Some(80),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id), Some(&token_before));
}
