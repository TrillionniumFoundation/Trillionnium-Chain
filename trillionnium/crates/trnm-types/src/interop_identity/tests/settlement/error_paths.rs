use super::*;

#[test]
fn settlement_finalize_requires_non_empty_settlement_tx() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 11,
        route,
        status: SettlementStatus::Pending,
        at_height: 100,
        settlement_tx: None,
        revert_reason: None,
    };

    let err = rec
        .apply_status(
            SettlementStatus::Finalized,
            101,
            Some("   ".to_string()),
            None,
        )
        .unwrap_err();

    assert!(matches!(err, InteropIdentityError::MissingSettlementTx));
    assert_eq!(rec.status, SettlementStatus::Pending);
}

#[test]
fn settlement_revert_requires_non_empty_reason() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 12,
        route,
        status: SettlementStatus::Pending,
        at_height: 200,
        settlement_tx: None,
        revert_reason: None,
    };

    let err = rec
        .apply_status(
            SettlementStatus::Reverted,
            201,
            None,
            Some("\n\t".to_string()),
        )
        .unwrap_err();

    assert!(matches!(err, InteropIdentityError::MissingRevertReason));
    assert_eq!(rec.status, SettlementStatus::Pending);
}

#[test]
fn settlement_status_update_rejects_height_regression_without_side_effects() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 15,
        route,
        status: SettlementStatus::Pending,
        at_height: 500,
        settlement_tx: None,
        revert_reason: None,
    };

    let err = rec
        .apply_status(
            SettlementStatus::Finalized,
            499,
            Some("0xlate".to_string()),
            None,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidSettlementHeightRegression {
            current_at: 500,
            next_at: 499
        }
    ));
    assert_eq!(rec.status, SettlementStatus::Pending);
    assert_eq!(rec.at_height, 500);
    assert_eq!(rec.settlement_tx, None);
    assert_eq!(rec.revert_reason, None);
}
