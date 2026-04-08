use super::*;

#[test]
fn verify_capability_rejects_noncanonical_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-actorfmt".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-actorfmt".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).cloned().unwrap();

    let err = reg
        .verify_capability(
            " org:lane2-admin ",
            token_id,
            CapabilityScope::BridgeSettle,
            50,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap(), &token_before);
}
#[test]
fn verify_capability_rejects_blank_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-actor-blank".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-actor-blank".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).cloned().unwrap();

    let err = reg
        .verify_capability("", token_id, CapabilityScope::BridgeSettle, 50)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap(), &token_before);
}
#[test]
fn verify_capability_rejects_control_character_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-actor-control".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-actor-control".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).cloned().unwrap();

    let err = reg
        .verify_capability(
            "org:lane2-admin\n",
            token_id,
            CapabilityScope::BridgeSettle,
            50,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap(), &token_before);
}
#[test]
fn verify_capability_rejects_zero_width_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-actor-zwsp".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-actor-zwsp".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).cloned().unwrap();

    let err = reg
        .verify_capability(
            "org:lane2-admin\u{200B}",
            token_id,
            CapabilityScope::BridgeSettle,
            50,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap(), &token_before);
}
#[test]
fn verify_capability_rejects_zero_width_non_joiner_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-actor-zwnj".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-actor-zwnj".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).cloned().unwrap();

    let err = reg
        .verify_capability(
            "org:lane2-admin\u{200C}",
            token_id,
            CapabilityScope::BridgeSettle,
            50,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap(), &token_before);
}
#[test]
fn verify_capability_rejects_word_joiner_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-actor-word-joiner".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-actor-word-joiner".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).cloned().unwrap();

    let err = reg
        .verify_capability(
            "org:lane2-admin\u{2060}",
            token_id,
            CapabilityScope::BridgeSettle,
            50,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap(), &token_before);
}
#[test]
fn verify_capability_rejects_arabic_letter_mark_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-actor-alm".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-actor-alm".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).cloned().unwrap();

    let err = reg
        .verify_capability(
            "org:lane2-admin\u{061C}",
            token_id,
            CapabilityScope::BridgeSettle,
            50,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap(), &token_before);
}
#[test]
fn verify_capability_rejects_bom_actor_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:settler-actor-bom".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:settler-actor-bom".to_string(),
            CapabilityScope::BridgeSettle,
            20,
            Some(200),
        )
        .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let token_before = reg.capability(token_id).cloned().unwrap();

    let err = reg
        .verify_capability(
            "\u{FEFF}org:lane2-admin",
            token_id,
            CapabilityScope::BridgeSettle,
            50,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert_eq!(reg.capability(token_id).unwrap(), &token_before);
}
