use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementError, SettlementRequest,
};

#[test]
fn test_bridge_settlement_workflow() {
    let mut request = SettlementRequest::new(1, "0xabc".to_string());
    assert_eq!(request.status, BridgeStatus::Pending);

    // X1: State transition -> Finalized
    request.settle(100);
    match request.status {
        BridgeStatus::Finalized(h) => assert_eq!(h, 100),
        _ => panic!("Expected Finalized status"),
    }

    // X1: State transition -> Reverted
    let mut request_failed = SettlementRequest::new(1, "0xdef".to_string());
    request_failed.revert("Gas limit exceeded".to_string());
    match request_failed.status {
        BridgeStatus::Reverted(reason) => assert_eq!(reason, "Gas limit exceeded"),
        _ => panic!("Expected Reverted status"),
    }
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
fn test_authorized_finalize_rejects_missing_capability() {
    let mut request = SettlementRequest::new(1, "0xbbb".to_string());
    let token = CapabilityToken {
        subject: "agent:worker-b".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let err = request.settle_authorized(&token, 256).unwrap_err();
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
