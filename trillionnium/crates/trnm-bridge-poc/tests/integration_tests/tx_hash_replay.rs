use crate::support::*;

#[test]
fn test_authorized_calls_reject_empty_tx_hash() {
    let mut request = SettlementRequest::new(44, "   ".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-d".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 514).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedRequest {
            reason: "empty tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    let revert_err = request
        .revert_authorized(&token, "bad proof".to_string())
        .unwrap_err();
    assert_eq!(
        revert_err,
        SettlementError::MalformedRequest {
            reason: "empty tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_non_canonical_tx_hash() {
    let mut request = SettlementRequest::new(45, " 0xabc\n".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-e".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let err = request.settle_authorized(&token, 515).unwrap_err();
    assert_eq!(
        err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_tx_hash_with_ascii_internal_whitespace() {
    let mut request = SettlementRequest::new(46, "0xabc def".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-f".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 516).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    let revert_err = request
        .revert_authorized(&token, "bridge timeout".to_string())
        .unwrap_err();
    assert_eq!(
        revert_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_tx_hash_with_invisible_unicode_controls() {
    let mut request = SettlementRequest::new(46, "0xabc\u{200B}\u{2060}def".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-f".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 516).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    let revert_err = request
        .revert_authorized(&token, "bridge timeout".to_string())
        .unwrap_err();
    assert_eq!(
        revert_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_tx_hash_with_alm_and_zwnj_controls() {
    let mut request = SettlementRequest::new(461, "0xabc\u{061C}\u{200C}def".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-f1".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 516).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    let revert_err = request
        .revert_authorized(&token, "bridge timeout".to_string())
        .unwrap_err();
    assert_eq!(
        revert_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_tx_hash_with_unicode_spacing_variants() {
    let mut request = SettlementRequest::new(47, "0xabc\u{00A0}\u{2007}\u{202F}def".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-g".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 517).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    let revert_err = request
        .revert_authorized(&token, "bridge timeout".to_string())
        .unwrap_err();
    assert_eq!(
        revert_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_tx_hash_with_general_punctuation_spacing_variants() {
    let mut request = SettlementRequest::new(
        48,
        "0xabc\u{2000}\u{2003}\u{200A}\u{205F}\u{3000}def".to_string(),
    );
    let token = CapabilityToken {
        subject: "did:trn:worker-h".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 518).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    let revert_err = request
        .revert_authorized(&token, "bridge timeout".to_string())
        .unwrap_err();
    assert_eq!(
        revert_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_tx_hash_with_variation_selectors_and_plane14_tags() {
    let mut request = SettlementRequest::new(
        481,
        "0xabc\u{FE0E}\u{FE0F}def\u{E0100}\u{E0101}".to_string(),
    );
    let token = CapabilityToken {
        subject: "did:trn:worker-hv".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&token, 518).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    let revert_err = request
        .revert_authorized(&token, "bridge timeout".to_string())
        .unwrap_err();
    assert_eq!(
        revert_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_tx_hash_and_subject_with_interlinear_annotation_controls() {
    let mut request =
        SettlementRequest::new(492, "0xabc\u{FFF9}def\u{FFFA}ghi\u{FFFB}".to_string());
    let malformed = CapabilityToken {
        subject: "did:trn:worker\u{FFF9}-i\u{FFFA}bridge\u{FFFB}".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&malformed, 521).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    request.tx_hash = "0xabc124".to_string();

    let revert_err = request
        .revert_authorized(&malformed, "bridge timeout".to_string())
        .unwrap_err();
    assert_eq!(
        revert_err,
        SettlementError::MalformedToken {
            reason: "non-canonical subject",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_legacy_bidi_isolates_in_tx_hash_and_subject() {
    let mut request =
        SettlementRequest::new(493, "0xabc\u{206A}def\u{206B}ghi\u{206C}".to_string());
    let malformed = CapabilityToken {
        subject: "did:trn:worker\u{206D}-legacy\u{206E}bidi\u{206F}".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&malformed, 523).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    request.tx_hash = "0xabc126".to_string();

    let revert_err = request
        .revert_authorized(&malformed, "bridge timeout".to_string())
        .unwrap_err();
    assert_eq!(
        revert_err,
        SettlementError::MalformedToken {
            reason: "non-canonical subject",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
