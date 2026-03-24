use super::*;

#[test]
fn settlement_evidence_path_sanitizes_windows_separators_and_control_whitespace() {
    let rec = SettlementRecord {
        settlement_id: 55,
        route: BridgeRoute {
            route_id: "eth/CON. /log".to_string(),
            source_chain: "bridge\\aux...\\proof".to_string(),
            target_chain: "mainnet/LPT1 .trace".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_232,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_CON.__log/bridge_aux..._proof/mainnet_LPT1_.trace/55/pending@2232"
    );
}

#[test]
fn register_did_rejects_duplicate_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-dup".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let err = reg
        .register_did(
            "did:trnm:agent-dup".to_string(),
            "org:lane2-backup".to_string(),
            20,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::DidAlreadyExists { did } if did == "did:trnm:agent-dup"
    ));
    assert_eq!(reg.audit_trail().len(), audit_len_before);

    let did = reg.did("did:trnm:agent-dup").unwrap();
    assert_eq!(did.controller, "org:lane2-admin");
    assert_eq!(did.created_at, 10);
    assert_eq!(did.revoked_at, None);
}

#[test]
fn register_did_rejects_blank_or_noncanonical_identifiers_without_side_effects() {
    let mut reg = IdentityRegistry::default();

    let err = reg
        .register_did("   ".to_string(), "org:lane2-admin".to_string(), 10)
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "did", .. }
    ));
    assert!(reg.audit_trail().is_empty());

    let err = reg
        .register_did(
            "did:trnm:agent-space ".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "did", .. }
    ));
    assert!(reg.did("did:trnm:agent-space").is_none());

    let err = reg
        .register_did(
            "did:trnm:agent-ok".to_string(),
            " org:lane2-admin".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue {
            field: "controller",
            ..
        }
    ));
    assert!(reg.did("did:trnm:agent-ok").is_none());

    let err = reg
        .register_did(
            "did:trnm:agent-ok".to_string(),
            "org:lane2-admin ".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue {
            field: "controller",
            ..
        }
    ));
    assert!(reg.did("did:trnm:agent-ok").is_none());

    let err = reg
        .register_did("did:trnm:agent-ok".to_string(), "  ".to_string(), 10)
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue {
            field: "controller",
            ..
        }
    ));
    assert!(reg.did("did:trnm:agent-ok").is_none());

    let err = reg
        .register_did(
            "did:trnm:agent\nnewline".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "did", .. }
    ));

    let err = reg
        .register_did(
            "did:trnm:agent-ok".to_string(),
            "org:lane2\nadmin".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue {
            field: "controller",
            ..
        }
    ));

    assert!(reg.audit_trail().is_empty());
}

#[test]
fn register_did_rejects_did_case_and_length_boundary_violations_without_side_effects() {
    let mut reg = IdentityRegistry::default();

    let err = reg
        .register_did(
            "did:Org:lane-xi".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "did", .. }
    ));

    let err = reg
        .register_did(
            "did:org:Lane-Xi".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "did", .. }
    ));

    let max_suffix = "a".repeat(120);
    let ok_boundary = format!("did:org:{max_suffix}");
    assert_eq!(ok_boundary.len(), 128);
    reg.register_did(ok_boundary.clone(), "org:lane2-admin".to_string(), 11)
        .expect("128-char DID boundary should be accepted");
    assert!(reg.did(&ok_boundary).is_some());

    let too_long = format!("did:org:{}", "a".repeat(121));
    assert_eq!(too_long.len(), 129);
    let err = reg
        .register_did(too_long, "org:lane2-admin".to_string(), 12)
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "did", .. }
    ));
}

#[test]
fn register_did_rejects_bidi_or_invisible_format_controls_without_side_effects() {
    let mut reg = IdentityRegistry::default();

    let err = reg
        .register_did(
            "did:trnm:agent\u{202E}spoof".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "did", .. }
    ));

    let err = reg
        .register_did(
            "did:trnm:agent-safe".to_string(),
            "org:lane2\u{2066}admin\u{2069}".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue {
            field: "controller",
            ..
        }
    ));

    let err = reg
        .register_did(
            "did:trnm:agent\u{2060}joiner".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "did", .. }
    ));

    let err = reg
        .register_did(
            "did:trnm:agent-bom-controller".to_string(),
            "org:lane2\u{FEFF}admin".to_string(),
            10,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue {
            field: "controller",
            ..
        }
    ));

    assert!(reg.did("did:trnm:agent-safe").is_none());
    assert!(reg.did("did:trnm:agent-bom-controller").is_none());
    assert!(reg.audit_trail().is_empty());
}

#[test]
fn revoke_did_rejects_height_before_creation_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-2".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let err = reg
        .revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2", 9)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidDidRevocationHeight {
            created_at: 10,
            revoked_at: 9
        }
    ));
    assert_eq!(reg.did("did:trnm:agent-2").unwrap().revoked_at, None);
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}

#[test]
fn revoke_did_rejects_noncanonical_did_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-2x".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let audit_len_before = reg.audit_trail().len();
    let err = reg
        .revoke_did("org:lane2-admin".to_string(), " did:trnm:agent-2x ", 12)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidIdentityValue { field: "did", .. }
    ));
    assert_eq!(reg.did("did:trnm:agent-2x").unwrap().revoked_at, None);
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}

#[test]
fn revoke_did_rejects_actor_that_is_not_did_controller_without_side_effects() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-2u".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-2u".to_string(),
            CapabilityScope::AuditRead,
            12,
            Some(100),
        )
        .unwrap();
    let audit_len_before = reg.audit_trail().len();

    let err = reg
        .revoke_did("org:lane2-backup".to_string(), "did:trnm:agent-2u", 40)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::UnauthorizedActor {
            actor,
            did,
            controller,
        } if actor == "org:lane2-backup"
            && did == "did:trnm:agent-2u"
            && controller == "org:lane2-admin"
    ));
    assert_eq!(reg.did("did:trnm:agent-2u").unwrap().revoked_at, None);
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    assert_eq!(reg.audit_trail().len(), audit_len_before);
}

#[test]
fn revoke_did_is_idempotent_for_audit_and_timestamp() {
    let mut reg = IdentityRegistry::default();
    reg.register_did(
        "did:trnm:agent-2".to_string(),
        "org:lane2-admin".to_string(),
        10,
    )
    .unwrap();

    let token_id = reg
        .issue_capability(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-2".to_string(),
            CapabilityScope::BridgeSettle,
            12,
            Some(100),
        )
        .unwrap();

    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2", 40)
        .unwrap();
    let first_audit_len = reg.audit_trail().len();

    reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2", 99)
        .unwrap();

    assert_eq!(reg.did("did:trnm:agent-2").unwrap().revoked_at, Some(40));
    assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(40));
    assert_eq!(reg.audit_trail().len(), first_audit_len);
}
