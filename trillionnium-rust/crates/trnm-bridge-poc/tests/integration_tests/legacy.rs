use crate::support::*;

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
