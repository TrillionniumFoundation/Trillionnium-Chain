use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementError, SettlementRequest,
};

#[test]
fn test_bridge_settlement_workflow() {
    let mut request = SettlementRequest::new(1, "0xabc".to_string());
    assert_eq!(request.status, BridgeStatus::Pending);

    let finalize = CapabilityToken {
        subject: "agent:worker-a".to_string(),
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
        subject: "agent:worker-b".to_string(),
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

#[test]
fn test_legacy_public_settle_cannot_bypass_authorization() {
    let mut request = SettlementRequest::new(7, "0x111".to_string());

    request.settle(777);

    assert_eq!(request.status, BridgeStatus::Pending);
}

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
        subject: "agent:worker-a".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    request.settle_authorized(&token, 128).unwrap();
    assert_eq!(request.status, BridgeStatus::Finalized(128));
}

#[test]
fn test_authorized_finalize_rejects_zero_height() {
    let mut request = SettlementRequest::new(1, "0xaa0".to_string());
    let token = CapabilityToken {
        subject: "agent:worker-a".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    let err = request.settle_authorized(&token, 0).unwrap_err();
    assert_eq!(err, SettlementError::InvalidHeight { height: 0 });
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_finalize_rejects_missing_capability() {
    let mut request = SettlementRequest::new(1, "0xbbb".to_string());
    let token = CapabilityToken {
        subject: "agent:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let err = request.settle_authorized(&token, 256).unwrap_err();
    assert!(err.is_unauthorized());
    assert_eq!(
        err,
        SettlementError::Unauthorized {
            subject: "agent:worker-b".to_string(),
            action: "finalize",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_revert_rejects_empty_reason() {
    let mut request = SettlementRequest::new(1, "0xbbc".to_string());
    let token = CapabilityToken {
        subject: "agent:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let err = request
        .revert_authorized(&token, "   ".to_string())
        .unwrap_err();
    assert_eq!(err, SettlementError::InvalidRevertReason);
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_revert_rejects_missing_capability() {
    let mut request = SettlementRequest::new(1, "0xbbd".to_string());
    let token = CapabilityToken {
        subject: "agent:worker-c".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    let err = request
        .revert_authorized(&token, "challenge proof mismatch".to_string())
        .unwrap_err();
    assert!(err.is_unauthorized());
    assert_eq!(
        err,
        SettlementError::Unauthorized {
            subject: "agent:worker-c".to_string(),
            action: "revert",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}

#[test]
fn test_authorized_transition_blocks_terminal_rewrite() {
    let mut request = SettlementRequest::new(10, "0xccc".to_string());
    let admin = CapabilityToken {
        subject: "org:bridge-admin".to_string(),
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
        subject: "org:bridge-admin".to_string(),
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
        subject: " agent:worker-c\n".to_string(),
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
fn test_authorized_calls_reject_empty_tx_hash() {
    let mut request = SettlementRequest::new(44, "   ".to_string());
    let token = CapabilityToken {
        subject: "agent:worker-d".to_string(),
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
        subject: "agent:worker-e".to_string(),
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
