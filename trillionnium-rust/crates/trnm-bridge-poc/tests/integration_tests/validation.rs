use super::*;

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
fn test_authorized_calls_reject_braille_blank_tx_hash() {
    let mut request = SettlementRequest::new(46, "0xabc\u{2800}def".to_string());
    let token = CapabilityToken {
        subject: "did:trn:worker-f".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    };

    let err = request.settle_authorized(&token, 516).unwrap_err();
    assert_eq!(
        err,
        SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(request.status, BridgeStatus::Pending);
}
