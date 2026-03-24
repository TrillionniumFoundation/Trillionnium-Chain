use crate::support::*;

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
