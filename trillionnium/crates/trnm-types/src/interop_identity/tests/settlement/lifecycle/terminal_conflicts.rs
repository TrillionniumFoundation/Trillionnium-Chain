use super::super::*;

#[test]
fn settlement_terminal_idempotent_reapply_rejects_conflicting_payload_override() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };

    let mut finalized = SettlementRecord {
        settlement_id: 83,
        route: route.clone(),
        status: SettlementStatus::Pending,
        at_height: 3_000,
        settlement_tx: None,
        revert_reason: None,
    };
    finalized
        .apply_status(
            SettlementStatus::Finalized,
            3_001,
            Some("0xfinal-a".to_string()),
            None,
        )
        .unwrap();
    let err = finalized
        .apply_status(
            SettlementStatus::Finalized,
            3_002,
            Some("0xfinal-b".to_string()),
            None,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::SettlementTerminalPayloadConflict {
            status: SettlementStatus::Finalized,
            ..
        }
    ));
    assert_eq!(finalized.settlement_tx.as_deref(), Some("0xfinal-a"));

    let mut reverted = SettlementRecord {
        settlement_id: 84,
        route,
        status: SettlementStatus::Pending,
        at_height: 4_000,
        settlement_tx: None,
        revert_reason: None,
    };
    reverted
        .apply_status(
            SettlementStatus::Reverted,
            4_001,
            None,
            Some("reason-a".to_string()),
        )
        .unwrap();
    let err = reverted
        .apply_status(
            SettlementStatus::Reverted,
            4_002,
            None,
            Some("reason-b".to_string()),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::SettlementTerminalPayloadConflict {
            status: SettlementStatus::Reverted,
            ..
        }
    ));
    assert_eq!(reverted.revert_reason.as_deref(), Some("reason-a"));
}

#[test]
fn settlement_terminal_idempotent_reapply_accepts_whitespace_equivalent_payload() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };

    let mut finalized = SettlementRecord {
        settlement_id: 85,
        route: route.clone(),
        status: SettlementStatus::Pending,
        at_height: 5_000,
        settlement_tx: None,
        revert_reason: None,
    };
    finalized
        .apply_status(
            SettlementStatus::Finalized,
            5_001,
            Some("0xstable".to_string()),
            None,
        )
        .unwrap();
    finalized
        .apply_status(
            SettlementStatus::Finalized,
            5_002,
            Some("  0xstable\n".to_string()),
            None,
        )
        .unwrap();
    assert_eq!(finalized.status, SettlementStatus::Finalized);
    assert_eq!(finalized.settlement_tx.as_deref(), Some("0xstable"));

    let mut reverted = SettlementRecord {
        settlement_id: 86,
        route,
        status: SettlementStatus::Pending,
        at_height: 6_000,
        settlement_tx: None,
        revert_reason: None,
    };
    reverted
        .apply_status(
            SettlementStatus::Reverted,
            6_001,
            None,
            Some("timeout across relayers".to_string()),
        )
        .unwrap();
    reverted
        .apply_status(
            SettlementStatus::Reverted,
            6_002,
            None,
            Some("  timeout across relayers\t".to_string()),
        )
        .unwrap();
    assert_eq!(reverted.status, SettlementStatus::Reverted);
    assert_eq!(
        reverted.revert_reason.as_deref(),
        Some("timeout across relayers")
    );
}

#[test]
fn settlement_terminal_idempotent_reapply_accepts_legacy_revert_reason_alias() {
    let mut reverted = SettlementRecord {
        settlement_id: 860,
        route: BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        },
        status: SettlementStatus::Reverted,
        at_height: 6_100,
        settlement_tx: None,
        revert_reason: Some("tee_attestation".to_string()),
    };

    reverted
        .apply_status(
            SettlementStatus::Reverted,
            6_101,
            None,
            Some("tee-receipt".to_string()),
        )
        .unwrap();

    assert_eq!(reverted.status, SettlementStatus::Reverted);
    assert_eq!(reverted.revert_reason.as_deref(), Some("tee-receipt"));
}

#[test]
fn settlement_terminal_idempotent_reapply_still_rejects_height_regression() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };

    let mut rec = SettlementRecord {
        settlement_id: 10,
        route,
        status: SettlementStatus::Pending,
        at_height: 300,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Finalized,
        305,
        Some("0xdone".to_string()),
        None,
    )
    .unwrap();

    let err = rec
        .apply_status(SettlementStatus::Finalized, 304, None, None)
        .unwrap_err();

    assert!(matches!(
        err,
        InteropIdentityError::InvalidSettlementHeightRegression {
            current_at: 305,
            next_at: 304
        }
    ));
    assert_eq!(rec.status, SettlementStatus::Finalized);
    assert_eq!(rec.at_height, 305);
    assert_eq!(rec.settlement_tx.as_deref(), Some("0xdone"));
    assert_eq!(rec.revert_reason, None);
}
