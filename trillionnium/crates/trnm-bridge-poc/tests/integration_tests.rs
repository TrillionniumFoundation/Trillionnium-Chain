use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementError, SettlementRequest,
};

#[test]
fn test_bridge_settlement_workflow() {
    let mut request = SettlementRequest::new(1, "0xabc".to_string());
    assert_eq!(request.status, BridgeStatus::Pending);

    let finalize = CapabilityToken {
        subject: "did:trn:worker-a".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    // X1: State transition -> Finalized (authorized path only)
    request.settle_authorized(&finalize, 100).unwrap();
    match request.status {
        BridgeStatus::Finalized(h) => assert_eq!(h, 100),
        _ => panic!("Expected Finalized status"),
    }

    // X1: State transition -> Reverted (authorized path only)
    let mut request_failed = SettlementRequest::new(1, "0xdef".to_string());
    let revert = CapabilityToken {
        subject: "did:trn:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };
    request_failed
        .revert_authorized(&revert, "Gas limit exceeded".to_string())
        .unwrap();
    match request_failed.status {
        BridgeStatus::Reverted(reason) => assert_eq!(reason, "Gas limit exceeded"),
        _ => panic!("Expected Reverted status"),
    }
}

#[allow(deprecated)]
#[test]
fn test_legacy_public_settle_cannot_bypass_authorization() {
    let mut request = SettlementRequest::new(7, "0x111".to_string());

    request.settle(777);

    assert_eq!(request.status, BridgeStatus::Pending);
}

#[allow(deprecated)]
#[test]
fn test_legacy_public_revert_cannot_bypass_authorization() {
    let mut request = SettlementRequest::new(8, "0x222".to_string());

    request.revert("manual override".to_string());

    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_finalize_requires_capability() {
    let mut request = SettlementRequest::new(1, "0xaaa".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-a".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    request.settle_authorized(&token, 128).unwrap();
    assert_eq!(request.status, BridgeStatus::Finalized(128));
}

#[test]
fn test_authorized_finalize_rejects_zero_height() {
    let mut request = SettlementRequest::new(1, "0xaa0".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-a".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    let err = request.settle_authorized(&token, 0).unwrap_err();
    assert_eq!(err, SettlementError::InvalidHeight { height: 0 });
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_finalize_rejects_zero_chain_id() {
    let mut request = SettlementRequest::new(0, "0xaa0-chain".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-a".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    let err = request.settle_authorized(&token, 128).unwrap_err();
    assert_eq!(
        err,
        SettlementError::MalformedRequest {
            reason: "invalid chain_id",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_finalize_rejects_tx_hash_with_u2065_for_canonical_replay() {
    let mut request = SettlementRequest::new(1, "0xabc\u{2065}def".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-a".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    let err = request.settle_authorized(&token, 128).unwrap_err();
    assert_eq!(
        err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_finalize_rejects_missing_capability() {
    let mut request = SettlementRequest::new(1, "0xbbb".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let err = request.settle_authorized(&token, 256).unwrap_err();
    assert!(err.is_unauthorized());
    assert_eq!(
        err,
        SettlementError::Unauthorized {
            subject: "did:trn:worker-b".to_string(),
            action: "finalize",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_revert_rejects_empty_reason() {
    let mut request = SettlementRequest::new(1, "0xbbc".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let err = request
        .revert_authorized(&token, "   ".to_string())
        .unwrap_err();
    assert_eq!(err, SettlementError::InvalidRevertReason);
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_revert_normalizes_invisible_reason_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xbbc1".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    request
        .revert_authorized(
            &token,
            "target\u{200B}\nreceipt\t\u{202E}timeout".to_string(),
        )
        .unwrap();

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("target receipt timeout".to_string())
    );
}

#[test]
fn test_authorized_revert_preserves_long_reason_without_second_truncation() {
    let mut request = SettlementRequest::new(1, "0xbbc2".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let raw = format!("timeout{}", "x".repeat(400));
    request.revert_authorized(&token, raw.clone()).unwrap();

    let BridgeStatus::Reverted(reason) = &request.status else {
        panic!("expected reverted status");
    };
    assert_eq!(reason, &raw);
    assert!(!reason.ends_with('…'));
}

#[test]
fn test_authorized_revert_normalizes_hangul_fillers_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xbbc2a".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    request
        .revert_authorized(
            &token,
            "target\u{115F}receipt\u{1160}timeout\u{3164}signal".to_string(),
        )
        .unwrap();

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("target receipt timeout signal".to_string())
    );
}

#[test]
fn test_authorized_revert_normalizes_variation_selectors_and_plane14_tags_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xbbc2b".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    request
        .revert_authorized(
            &token,
            "target\u{FE0F}receipt\u{E0100}timeout\u{E0101}signal".to_string(),
        )
        .unwrap();

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("target receipt timeout signal".to_string())
    );
}

#[test]
fn test_authorized_revert_normalizes_plane14_language_tags_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xbbc2ba".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    request
        .revert_authorized(
            &token,
            "target\u{E0001}receipt\u{E0020}timeout\u{E007F}signal".to_string(),
        )
        .unwrap();

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("target receipt timeout signal".to_string())
    );
}

#[test]
fn test_authorized_revert_normalizes_legacy_bidi_isolates_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xbbc2c".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    request
        .revert_authorized(
            &token,
            "target\u{206A}receipt\u{206B}timeout\u{206C}signal\u{206D}\u{206E}\u{206F}"
                .to_string(),
        )
        .unwrap();

    assert_eq!(
        request.status,
        BridgeStatus::Reverted("target receipt timeout signal".to_string())
    );
}

#[test]
fn test_authorized_revert_rejects_missing_capability() {
    let mut request = SettlementRequest::new(1, "0xbbd".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-c".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    let err = request
        .revert_authorized(&token, "challenge proof mismatch".to_string())
        .unwrap_err();
    assert!(err.is_unauthorized());
    assert_eq!(
        err,
        SettlementError::Unauthorized {
            subject: "did:trn:worker-c".to_string(),
            action: "revert",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_transition_blocks_terminal_rewrite() {
    let mut request = SettlementRequest::new(10, "0xccc".to_string());
    let admin = CapabilityToken {
        subject: "did:trn:bridge-admin".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    request.settle_authorized(&admin, 999).unwrap();
    let err = request
        .revert_authorized(&admin, "late challenge".to_string())
        .unwrap_err();

    assert_eq!(
        err,
        SettlementError::InvalidTransition {
            from: "finalized",
            to: "reverted",
        }
    );
    assert_eq!(request.status, BridgeStatus::Finalized(999));
}

#[test]
fn test_authorized_transition_blocks_reverted_to_finalized_rewrite() {
    let mut request = SettlementRequest::new(11, "0xccd".to_string());
    let admin = CapabilityToken {
        subject: "did:trn:bridge-admin".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    request
        .revert_authorized(&admin, "proof invalidated".to_string())
        .unwrap();
    let err = request.settle_authorized(&admin, 1001).unwrap_err();

    assert_eq!(
        err,
        SettlementError::InvalidTransition {
            from: "reverted",
            to: "finalized",
        }
    );
    assert_eq!(
        request.status,
        BridgeStatus::Reverted("proof invalidated".to_string())
    );
}

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
