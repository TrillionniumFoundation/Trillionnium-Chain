use trnm_types::{BridgeRoute, InteropIdentityError, SettlementRecord, SettlementStatus};

#[test]
fn stale_pending_replay_after_finalize_is_rejected_without_mutation() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };

    let mut rec = SettlementRecord {
        settlement_id: 301,
        route,
        status: SettlementStatus::Pending,
        at_height: 10_000,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Finalized,
        10_005,
        Some("0xsettled301".to_string()),
        None,
    )
    .expect("initial finalize must succeed");

    let snapshot = rec.clone();

    // X3 stale-pending guard: once terminal state is reached, a delayed pending
    // replay (reorder/duplicate path) must fail closed and keep state immutable.
    let err = rec
        .apply_status(
            SettlementStatus::Pending,
            10_006,
            Some("0xignored".to_string()),
            Some("stale_pending_replay".to_string()),
        )
        .expect_err("terminal -> pending replay must be rejected");

    assert!(matches!(
        err,
        InteropIdentityError::InvalidSettlementTransition {
            from: SettlementStatus::Finalized,
            to: SettlementStatus::Pending,
        }
    ));
    assert_eq!(rec, snapshot);
}

#[test]
fn settlement_finalization_rejects_failed_tx_receipt() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };

    let mut rec = SettlementRecord {
        settlement_id: 302,
        route,
        status: SettlementStatus::Pending,
        at_height: 10_010,
        settlement_tx: None,
        revert_reason: None,
    };

    let err = rec
        .apply_status_with_receipt_status(
            SettlementStatus::Finalized,
            10_011,
            Some("0xdead".to_string()),
            Some(0),
            None,
        )
        .expect_err("failed tx receipt status must be rejected");

    assert!(matches!(
        err,
        InteropIdentityError::InvalidSettlementReceiptStatus { expected, got: 0 }
            if expected == 1
    ));
}

#[test]
fn terminal_finalize_replay_with_failed_tx_receipt_is_rejected_without_mutation() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };

    let mut rec = SettlementRecord {
        settlement_id: 303,
        route,
        status: SettlementStatus::Pending,
        at_height: 10_020,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Finalized,
        10_021,
        Some("0xsettled303".to_string()),
        None,
    )
    .expect("initial finalize must succeed");

    let snapshot = rec.clone();

    let err = rec
        .apply_status_with_receipt_status(
            SettlementStatus::Finalized,
            10_022,
            Some("0xignored-replay".to_string()),
            Some(0),
            None,
        )
        .expect_err("terminal finalize replay with failed receipt must be rejected");

    assert!(matches!(
        err,
        InteropIdentityError::InvalidSettlementReceiptStatus {
            expected,
            got: 0,
        } if expected == 1
    ));
    assert_eq!(rec, snapshot);
}
