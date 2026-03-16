use super::*;

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
