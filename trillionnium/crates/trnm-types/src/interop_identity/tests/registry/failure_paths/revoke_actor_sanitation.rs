use super::*;

#[test]
fn revoke_capability_rejects_blank_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-7".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-7".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability("   ".to_string(), token_id, 30, Some("x".to_string()))
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
}
#[test]
fn revoke_capability_rejects_control_character_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-7-control".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-7-control".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability("org:lane2-admin\n".to_string(), token_id, 30, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
}
#[test]
fn revoke_capability_rejects_zero_width_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-7-zero-width".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-7-zero-width".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability("org:lane2\u{200b}-admin".to_string(), token_id, 30, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
}
#[test]
fn revoke_capability_rejects_zero_width_non_joiner_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-7-zwnj".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-7-zwnj".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability("org:lane2\u{200c}-admin".to_string(), token_id, 30, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
}
#[test]
fn revoke_capability_rejects_word_joiner_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-7-word-joiner".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-7-word-joiner".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability("org:lane2\u{2060}-admin".to_string(), token_id, 30, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
}
#[test]
fn revoke_capability_rejects_arabic_letter_mark_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-7-alm".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-7-alm".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability("org:lane2\u{061C}-admin".to_string(), token_id, 30, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
}
#[test]
fn revoke_capability_rejects_bom_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-7-bom".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-7-bom".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            None,
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_capability("org:lane2\u{FEFF}-admin".to_string(), token_id, 30, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
}
