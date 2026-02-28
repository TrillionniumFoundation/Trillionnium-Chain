use trnm_bridge_poc::bridge_status::{BridgeStatus, SettlementRequest};

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
