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
