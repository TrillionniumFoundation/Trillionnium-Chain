use crate::support::*;

#[test]
fn test_authorized_calls_reject_empty_subject_token() {
    let mut request = SettlementRequest::new(42, "0xddd".to_string());
    let malformed = CapabilityToken {
        subject: "   ".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&malformed, 512).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedToken {
            reason: "empty subject",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    let revert_err = request
        .revert_authorized(&malformed, "bad proof".to_string())
        .unwrap_err();
    assert_eq!(
        revert_err,
        SettlementError::MalformedToken {
            reason: "empty subject",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_non_canonical_subject_token() {
    let mut request = SettlementRequest::new(43, "0xeee".to_string());
    let malformed = CapabilityToken {
        subject: " did:trn:worker-c\n".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&malformed, 513).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedToken {
            reason: "non-canonical subject",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

    let revert_err = request
        .revert_authorized(&malformed, "bad proof".to_string())
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
fn test_authorized_calls_reject_non_did_subject_token() {
    let mut request = SettlementRequest::new(431, "0xeee1".to_string());
    let malformed = CapabilityToken {
        subject: "bridge-admin".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    let err = request.settle_authorized(&malformed, 600).unwrap_err();
    assert_eq!(
        err,
        SettlementError::MalformedToken {
            reason: "non-canonical subject",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
#[test]
fn test_authorized_calls_reject_subject_token_with_invisible_unicode_controls() {
    let mut request = SettlementRequest::new(432, "0xeee2".to_string());
    let malformed = CapabilityToken {
        subject: "did:trn:worker\u{200B}\u{2060}-g".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&malformed, 601).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedToken {
            reason: "non-canonical subject",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

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
fn test_authorized_calls_reject_subject_token_with_general_punctuation_spacing_variants() {
    let mut request = SettlementRequest::new(49, "0xabc123".to_string());
    let malformed = CapabilityToken {
        subject: "did:trn:worker\u{2000}\u{2003}\u{200A}\u{205F}\u{3000}-i".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&malformed, 519).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedToken {
            reason: "non-canonical subject",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

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
fn test_authorized_calls_reject_subject_token_with_alm_and_zwnj_controls() {
    let mut request = SettlementRequest::new(4910, "0xabc125".to_string());
    let malformed = CapabilityToken {
        subject: "did:trn:worker\u{061C}\u{200C}-j".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&malformed, 522).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedToken {
            reason: "non-canonical subject",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

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
fn test_authorized_calls_reject_subject_token_with_variation_selectors_and_plane14_tags() {
    let mut request = SettlementRequest::new(491, "0xabc124".to_string());
    let malformed = CapabilityToken {
        subject: "did:trn:worker\u{FE0E}\u{FE0F}-i\u{E0100}\u{E0101}".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let finalize_err = request.settle_authorized(&malformed, 520).unwrap_err();
    assert_eq!(
        finalize_err,
        SettlementError::MalformedToken {
            reason: "non-canonical subject",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);

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
