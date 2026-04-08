use super::super::*;

#[test]
fn settlement_reapply_same_terminal_status_is_idempotent() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };

    let mut finalized = SettlementRecord {
        settlement_id: 8,
        route: route.clone(),
        status: SettlementStatus::Pending,
        at_height: 100,
        settlement_tx: None,
        revert_reason: None,
    };
    finalized
        .apply_status(
            SettlementStatus::Finalized,
            101,
            Some("0xabc".to_string()),
            None,
        )
        .unwrap();
    finalized
        .apply_status(SettlementStatus::Finalized, 102, None, None)
        .unwrap();
    assert_eq!(finalized.status, SettlementStatus::Finalized);
    assert_eq!(finalized.settlement_tx.as_deref(), Some("0xabc"));
    assert_eq!(finalized.revert_reason, None);

    let mut reverted = SettlementRecord {
        settlement_id: 9,
        route,
        status: SettlementStatus::Pending,
        at_height: 200,
        settlement_tx: None,
        revert_reason: None,
    };
    reverted
        .apply_status(
            SettlementStatus::Reverted,
            201,
            None,
            Some("fraud-proof".to_string()),
        )
        .unwrap();
    reverted
        .apply_status(SettlementStatus::Reverted, 202, None, None)
        .unwrap();
    assert_eq!(reverted.status, SettlementStatus::Reverted);
    assert_eq!(reverted.settlement_tx, None);
    assert_eq!(reverted.revert_reason.as_deref(), Some("fraud-proof"));
}

#[test]
fn settlement_terminal_idempotent_reapply_ignores_blank_payload_overrides() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };

    let mut finalized = SettlementRecord {
        settlement_id: 81,
        route: route.clone(),
        status: SettlementStatus::Pending,
        at_height: 1_000,
        settlement_tx: None,
        revert_reason: None,
    };
    finalized
        .apply_status(
            SettlementStatus::Finalized,
            1_001,
            Some("0xpersist".to_string()),
            None,
        )
        .unwrap();
    finalized
        .apply_status(
            SettlementStatus::Finalized,
            1_002,
            Some("   \t".to_string()),
            None,
        )
        .unwrap();
    assert_eq!(finalized.status, SettlementStatus::Finalized);
    assert_eq!(finalized.settlement_tx.as_deref(), Some("0xpersist"));
    assert_eq!(finalized.revert_reason, None);

    let mut reverted = SettlementRecord {
        settlement_id: 82,
        route,
        status: SettlementStatus::Pending,
        at_height: 2_000,
        settlement_tx: None,
        revert_reason: None,
    };
    reverted
        .apply_status(
            SettlementStatus::Reverted,
            2_001,
            None,
            Some("keep-this-reason".to_string()),
        )
        .unwrap();
    reverted
        .apply_status(
            SettlementStatus::Reverted,
            2_002,
            None,
            Some("   \n".to_string()),
        )
        .unwrap();
    assert_eq!(reverted.status, SettlementStatus::Reverted);
    assert_eq!(reverted.settlement_tx, None);
    assert_eq!(reverted.revert_reason.as_deref(), Some("keep-this-reason"));
}
