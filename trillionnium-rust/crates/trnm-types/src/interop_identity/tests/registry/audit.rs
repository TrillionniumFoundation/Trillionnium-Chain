use super::*;

#[test]
fn revoke_capability_trims_audit_note_for_compliance_provenance() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3a".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3a".to_string(),
            CapabilityScope::AuditRead,
            12,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("  evidence:case-42  ".to_string()),
    )
    .unwrap();

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityRevoked);
    assert_eq!(last.note.as_deref(), Some("evidence:case-42"));
}

#[test]
fn revoke_capability_blank_audit_note_is_normalized_to_none() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3aa".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3aa".to_string(),
            CapabilityScope::AuditRead,
            12,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("   ".to_string()),
    )
    .unwrap();

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityRevoked);
    assert_eq!(last.note, None);
}

#[test]
fn revoke_capability_zero_width_audit_note_is_normalized_to_none() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3ab".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3ab".to_string(),
            CapabilityScope::AuditRead,
            12,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("\u{200B}\u{200C}\u{2060}".to_string()),
    )
    .unwrap();

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityRevoked);
    assert_eq!(last.note, None);
}

#[test]
fn revoke_capability_bidi_controls_only_audit_note_is_normalized_to_none() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3ab-bidi".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3ab-bidi".to_string(),
            CapabilityScope::AuditRead,
            12,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("\u{202E}\u{202C}\u{2067}\u{2069}".to_string()),
    )
    .unwrap();

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityRevoked);
    assert_eq!(last.note, None);
}

#[test]
fn revoke_capability_audit_note_strips_invisibles_and_collapses_whitespace() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3ab-note-sanitize".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3ab-note-sanitize".to_string(),
            CapabilityScope::AuditRead,
            12,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("  proof\u{200B}\n case\u{202E}\t42  ".to_string()),
    )
    .unwrap();

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityRevoked);
    assert_eq!(last.note.as_deref(), Some("proof case 42"));
}

#[test]
fn revoke_capability_audit_note_with_only_controls_after_trim_is_none() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-3ab-note-empty".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-3ab-note-empty".to_string(),
            CapabilityScope::AuditRead,
            12,
            None,
        )
        .unwrap();

    reg.revoke_capability(
        "org:lane2-admin".to_string(),
        token_id,
        30,
        Some("\n\t\u{200B}\u{202E}\r".to_string()),
    )
    .unwrap();

    let last = reg.audit_trail().last().unwrap();
    assert_eq!(last.action, AuditAction::CapabilityRevoked);
    assert_eq!(last.note, None);
}

#[test]
fn content_hash_changes_when_audit_note_differs() {
    let mut reg_a = IdentityRegistry::default();
    reg_a
        .register_did(
            "did:trnm:hash-audit-note".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
    let token_id = reg_a
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:hash-audit-note".to_string(),
            CapabilityScope::AuditRead,
            20,
            None,
        )
        .unwrap();
    reg_a
        .revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("reason:a".to_string()),
        )
        .unwrap();

    let mut reg_b = IdentityRegistry::default();
    reg_b
        .register_did(
            "did:trnm:hash-audit-note".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
    let token_id = reg_b
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:hash-audit-note".to_string(),
            CapabilityScope::AuditRead,
            20,
            None,
        )
        .unwrap();
    reg_b
        .revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("reason:b".to_string()),
        )
        .unwrap();

    assert_ne!(reg_a.content_hash(), reg_b.content_hash());
}
