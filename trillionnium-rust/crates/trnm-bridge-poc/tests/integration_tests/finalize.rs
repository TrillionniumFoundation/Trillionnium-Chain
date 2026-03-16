use super::*;

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
