use super::*;

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
