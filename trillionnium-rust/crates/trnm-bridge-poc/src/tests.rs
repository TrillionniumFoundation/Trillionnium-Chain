use crate::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementError, SettlementRequest,
};

fn settlement_operator() -> CapabilityToken {
    CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    }
}

#[test]
fn settlement_request_rejects_ogham_space_mark_in_tx_hash() {
    let mut request = SettlementRequest::new(7, "0xabc\u{1680}def".to_string());
    let err = request.revert_authorized(&settlement_operator(), "target relay timeout".to_string());
    assert_eq!(
        err,
        Err(SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        })
    );
}

#[test]
fn settlement_audit_view_exposes_explicit_terminal_fields() {
    let mut finalized = SettlementRequest::new(7, "0xfinal".to_string());
    finalized.status = BridgeStatus::Finalized(88);
    assert_eq!(
        finalized.audit_view(),
        crate::bridge_status::SettlementAuditView {
            chain_id: 7,
            tx_hash: "0xfinal".to_string(),
            status: "finalized",
            finalized_height: Some(88),
            revert_reason: None,
        }
    );

    let mut reverted = SettlementRequest::new(7, "0xrevert".to_string());
    reverted.status = BridgeStatus::Reverted("proof mismatch".to_string());
    assert_eq!(
        reverted.audit_view(),
        crate::bridge_status::SettlementAuditView {
            chain_id: 7,
            tx_hash: "0xrevert".to_string(),
            status: "reverted",
            finalized_height: None,
            revert_reason: Some("proof mismatch".to_string()),
        }
    );
}

#[test]
fn settlement_request_collapses_ogham_space_mark_in_revert_reason() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    request
        .revert_authorized(
            &settlement_operator(),
            "target\u{1680}relay timeout".to_string(),
        )
        .expect("ogham-only spacing should be normalized in revert reason");

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("target relay timeout".to_string())
    );
}

#[test]
fn settlement_request_collapses_bom_spacing_in_revert_reason() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    request
        .revert_authorized(
            &settlement_operator(),
            "target\u{FEFF}relay timeout".to_string(),
        )
        .expect("bom-style hidden spacing should be normalized in revert reason");

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("target relay timeout".to_string())
    );
}

#[test]
fn settlement_request_rejects_non_canonical_subject_with_word_joiner() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement\u{2060}-operator".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let err = request.revert_authorized(&token, "target relay timeout".to_string());
    assert_eq!(
        err,
        Err(SettlementError::MalformedToken {
            reason: "non-canonical subject",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn settlement_request_rejects_hangul_fillers_in_tx_hash_and_subject() {
    let mut request = SettlementRequest::new(7, "0xabc\u{115F}def\u{1160}ghi\u{3164}".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement\u{115F}-operator\u{3164}".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 77);
    assert_eq!(
        finalize_err,
        Err(SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    request.tx_hash = "0xabcdef".to_string();

    let revert_err = request.revert_authorized(&token, "target relay timeout".to_string());
    assert_eq!(
        revert_err,
        Err(SettlementError::MalformedToken {
            reason: "non-canonical subject",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn settlement_request_rejects_plane14_tags_in_tx_hash_and_subject() {
    let mut request = SettlementRequest::new(7, "0xabc\u{E0100}def\u{E0101}".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement\u{E0100}-operator\u{E0101}".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 88);
    assert_eq!(
        finalize_err,
        Err(SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    request.tx_hash = "0xabcdef".to_string();

    let revert_err = request.revert_authorized(&token, "target relay timeout".to_string());
    assert_eq!(
        revert_err,
        Err(SettlementError::MalformedToken {
            reason: "non-canonical subject",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn settlement_request_rejects_braille_blank_in_tx_hash_and_subject() {
    let mut request = SettlementRequest::new(7, "0xabc\u{2800}def".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement\u{2800}-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 89);
    assert_eq!(
        finalize_err,
        Err(SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    request.tx_hash = "0xabcdef".to_string();

    let revert_err = request.revert_authorized(&token, "target relay timeout".to_string());
    assert_eq!(
        revert_err,
        Err(SettlementError::MalformedToken {
            reason: "non-canonical subject",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn settlement_request_rejects_boundary_whitespace_in_tx_hash_and_subject() {
    let mut request = SettlementRequest::new(7, " 0xabcdef ".to_string());
    let token = CapabilityToken {
        subject: " did:trn:settlement-operator ".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 91);
    assert_eq!(
        finalize_err,
        Err(SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    request.tx_hash = "0xabcdef".to_string();

    let revert_err = request.revert_authorized(&token, "target relay timeout".to_string());
    assert_eq!(
        revert_err,
        Err(SettlementError::MalformedToken {
            reason: "non-canonical subject",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn settlement_request_rejects_internal_ascii_whitespace_in_subject() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement operator".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let err = request.revert_authorized(&token, "target relay timeout".to_string());
    assert_eq!(
        err,
        Err(SettlementError::MalformedToken {
            reason: "non-canonical subject",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
