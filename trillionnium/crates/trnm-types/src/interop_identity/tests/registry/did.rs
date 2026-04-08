use super::*;

#[test]
fn issue_capability_rejects_height_before_did_creation_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-1b".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-1b".to_string(),
            CapabilityScope::BridgeSettle,
            9,
            Some(90),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidCapabilityIssueHeight {
            did,
            created_at: 10,
            issued_at: 9,
        } if did == "did:trnm:agent-1b"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert!(reg.capability(1).is_none());
}

#[test]
fn did_capability_revocation_appends_audit_trail() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-1".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-1".to_string(),
            CapabilityScope::BridgeSettle,
            12,
            Some(120),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        20,
        Some("manual_revoke".to_string()),
    )
    .unwrap();
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(20));

    let token2 = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-1".to_string(),
            CapabilityScope::AuditRead,
            30,
            None,
        )
        .unwrap();

    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-1", 40)
        .unwrap();

    assert_eq!(reg.did("did:trnm:agent-1").unwrap().revoked_at, Some(40));
    assert_eq!(reg.capability(token2).unwrap().revoked_at, Some(40));

    let audit = reg.audit_trail();
    assert_eq!(audit.len(), 6);
    assert_eq!(audit[0].action, AuditAction::DidRegistered);
    assert_eq!(audit[1].action, AuditAction::CapabilityIssued);
    assert_eq!(audit[2].action, AuditAction::CapabilityRevoked);
    assert_eq!(audit[3].action, AuditAction::CapabilityIssued);
    assert_eq!(audit[4].action, AuditAction::DidRevoked);
    assert_eq!(audit[5].action, AuditAction::CapabilityRevoked);
    assert_eq!(audit[5].actor, "system:cascade");
    assert!(audit[5]
        .note
        .as_deref()
        .unwrap_or_default()
        .contains("cascade_on_did_revoke"));
}

#[test]
fn revoke_did_replay_repairs_legacy_uncascaded_capability_without_rewriting_did_timestamp() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-2fix".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-2fix".to_string(),
            CapabilityScope::BridgeSettle,
            12,
            Some(100),
        )
        .unwrap();

    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2fix", 40)
        .unwrap();

    // Simulate legacy/corrupt snapshot drift: DID already revoked but cascade revoke was lost.
    reg.capabilities.get_mut(&token_id).unwrap().revoked_at = None;
    let audit_len_before = reg.audit_trail().len();

    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2fix", 99)
        .unwrap();

    assert_eq!(reg.did("did:trnm:agent-2fix").unwrap().revoked_at, Some(40));
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(40));
    assert_eq!(reg.audit_trail().len(), audit_len_before + 1);
    assert_eq!(
        reg.audit_trail().last().map(|ev| ev.action),
        Some(AuditAction::CapabilityRevoked)
    );
    assert_eq!(
        reg.audit_trail().last().map(|ev| ev.actor.as_str()),
        Some("system:cascade")
    );
    assert_eq!(reg.audit_trail().last().map(|ev| ev.at_height), Some(40));
}

#[test]
fn revoke_did_replay_preserves_issue_height_floor_when_repairing_legacy_token() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-2rfloor".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-2rfloor".to_string(),
            CapabilityScope::BridgeSettle,
            60,
            Some(120),
        )
        .unwrap();

    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2rfloor", 40)
        .unwrap();

    // Simulate legacy/corrupt snapshot drift: replay should re-apply the cascade
    // but keep the issue-height floor instead of backdating to DID revoke anchor.
    reg.capabilities.get_mut(&token_id).unwrap().revoked_at = None;
    let audit_len_before = reg.audit_trail().len();

    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2rfloor", 99)
        .unwrap();

    assert_eq!(
        reg.did("did:trnm:agent-2rfloor").unwrap().revoked_at,
        Some(40)
    );
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(60));
    assert_eq!(reg.audit_trail().len(), audit_len_before + 1);
}

#[test]
fn revoke_did_replay_with_older_height_is_rejected_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-2r".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-2r".to_string(),
            CapabilityScope::BridgeSettle,
            12,
            Some(100),
        )
        .unwrap();

    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2r", 40)
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2r", 39)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidDidRevocationHeight {
            created_at: 40,
            revoked_at: 39,
        }
    ));
    assert_eq!(reg.did("did:trnm:agent-2r").unwrap().revoked_at, Some(40));
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(40));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}

#[test]
fn revoke_did_does_not_override_previously_revoked_capability() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-4".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-4".to_string(),
            CapabilityScope::BridgeRevert,
            12,
            Some(88),
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        20,
        Some("manual_revoke_before_did_revoke".to_string()),
    )
    .unwrap();
    let first_revoke_audit_len = reg.audit_trail().len();

    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-4", 40)
        .unwrap();

    assert_eq!(reg.did("did:trnm:agent-4").unwrap().revoked_at, Some(40));
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(20));
    assert_eq!(reg.audit_trail().len(), first_revoke_audit_len + 1);
    assert_eq!(
        reg.audit_trail().last().map(|e| e.action),
        Some(AuditAction::DidRevoked)
    );
}

#[test]
fn revoke_did_cascade_does_not_backdate_capability_before_issue_height() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-4b".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-4b".to_string(),
            CapabilityScope::BridgeSettle,
            60,
            Some(200),
        )
        .unwrap();

    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-4b", 40)
        .unwrap();

    assert_eq!(reg.did("did:trnm:agent-4b").unwrap().revoked_at, Some(40));
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(60));

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityRevoked);
    assert_eq!(last.actor, "system:cascade");
    assert_eq!(last.at_height, 60);
}

#[test]
fn issue_capability_rejects_revoked_did_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-5".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();
    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-5", 20)
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-5".to_string(),
            CapabilityScope::BridgeSettle,
            21,
            Some(100),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidRevoked {
            did
        } if did == "did:trnm:agent-5"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);
    assert!(reg.capability(1).is_none());
}
