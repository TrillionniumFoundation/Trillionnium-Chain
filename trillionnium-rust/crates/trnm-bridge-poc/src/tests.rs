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
fn settlement_audit_view_exposes_non_terminal_pending_fields() {
    let pending = SettlementRequest::new(7, "0xpending".to_string());

    assert_eq!(
        pending.audit_view(),
        crate::bridge_status::SettlementAuditView {
            chain_id: 7,
            tx_hash: "0xpending".to_string(),
            status: "pending",
            is_terminal: false,
            finalized_height: None,
            revert_reason: None,
        }
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
            is_terminal: true,
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
            is_terminal: true,
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
fn settlement_audit_view_normalizes_reverted_reason_from_legacy_state() {
    let mut reverted = SettlementRequest::new(7, "0xlegacy".to_string());
    reverted.status = BridgeStatus::Reverted("proof\u{1680}mismatch\ntrail".to_string());

    assert_eq!(
        reverted.audit_view(),
        crate::bridge_status::SettlementAuditView {
            chain_id: 7,
            tx_hash: "0xlegacy".to_string(),
            status: "reverted",
            is_terminal: true,
            finalized_height: None,
            revert_reason: Some("proof mismatch trail".to_string()),
        }
    );
}

#[test]
fn settlement_audit_view_omits_legacy_revert_reason_that_sanitizes_empty() {
    let mut reverted = SettlementRequest::new(7, "0xlegacy-empty".to_string());
    reverted.status =
        BridgeStatus::Reverted("\u{200B}\u{2065}\u{202E}\n\t\u{FEFF}".to_string());

    assert_eq!(
        reverted.audit_view(),
        crate::bridge_status::SettlementAuditView {
            chain_id: 7,
            tx_hash: "0xlegacy-empty".to_string(),
            status: "reverted",
            is_terminal: true,
            finalized_height: None,
            revert_reason: None,
        }
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
fn settlement_request_collapses_halfwidth_hangul_filler_in_revert_reason() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    request
        .revert_authorized(
            &settlement_operator(),
            "target\u{FFA0}relay timeout".to_string(),
        )
        .expect("halfwidth hangul filler should be normalized in revert reason");

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("target relay timeout".to_string())
    );
}

#[test]
fn settlement_request_collapses_medium_math_and_ideographic_spacing_in_revert_reason() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    request
        .revert_authorized(
            &settlement_operator(),
            "target\u{205F}relay\u{3000}timeout".to_string(),
        )
        .expect("medium math and ideographic spacing should be normalized in revert reason");

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("target relay timeout".to_string())
    );
}

#[test]
fn settlement_request_rejects_revert_reason_that_becomes_empty_after_sanitize() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    let err = request.revert_authorized(
        &settlement_operator(),
        "\u{200B}\u{2065}\u{202E}\n\t\u{FEFF}".to_string(),
    );

    assert_eq!(err, Err(SettlementError::InvalidRevertReason));
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn settlement_request_collapses_interlinear_annotation_controls_in_revert_reason() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    request
        .revert_authorized(
            &settlement_operator(),
            "proof\u{FFF9}mismatch\u{FFFA}target\u{FFFB}trail".to_string(),
        )
        .expect("interlinear annotation controls should be normalized in revert reason");

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("proof mismatch target trail".to_string())
    );
}

#[test]
fn settlement_request_collapses_plane14_tag_noise_in_revert_reason() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    request
        .revert_authorized(
            &settlement_operator(),
            "proof\u{E0100}mismatch\u{E0101}\u{E0001}trail".to_string(),
        )
        .expect("plane14 tag noise should be normalized in revert reason");

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("proof mismatch trail".to_string())
    );
}

#[test]
fn settlement_audit_view_normalizes_plane14_tag_noise_from_legacy_revert_reason() {
    let mut reverted = SettlementRequest::new(7, "0xlegacy-plane14".to_string());
    reverted.status = BridgeStatus::Reverted(
        "proof\u{E0100}mismatch\u{E0101}\u{E0001}trail".to_string(),
    );

    assert_eq!(
        reverted.audit_view(),
        crate::bridge_status::SettlementAuditView {
            chain_id: 7,
            tx_hash: "0xlegacy-plane14".to_string(),
            status: "reverted",
            is_terminal: true,
            finalized_height: None,
            revert_reason: Some("proof mismatch trail".to_string()),
        }
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
fn settlement_request_rejects_variation_selectors_in_tx_hash_and_subject() {
    let mut request = SettlementRequest::new(7, "0xabc\u{FE0E}def\u{FE0F}".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement\u{FE0E}-operator\u{FE0F}".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 90);
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

#[test]
fn settlement_request_rejects_revert_only_token_from_finalizing() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let err = request.settle_authorized(&token, 42);
    assert_eq!(
        err,
        Err(SettlementError::Unauthorized {
            subject: "did:trn:settlement-operator".to_string(),
            action: "finalize",
        })
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn settlement_request_rejects_finalize_only_token_from_reverting_finalized_request() {
    let mut request = SettlementRequest::new(7, "0xabcdef".to_string());
    let finalize_only = CapabilityToken {
        subject: "did:trn:settlement-finalizer".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    request
        .settle_authorized(&finalize_only, 42)
        .expect("finalize-only token should be able to finalize pending request");

    let err = request.revert_authorized(&finalize_only, "late sponsor rollback".to_string());
    assert_eq!(
        err,
        Err(SettlementError::Unauthorized {
            subject: "did:trn:settlement-finalizer".to_string(),
            action: "revert",
        })
    );
    assert_eq!(request.status, BridgeStatus::Finalized(42));
}
