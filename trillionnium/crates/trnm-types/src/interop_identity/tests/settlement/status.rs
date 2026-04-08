use super::*;

#[test]
fn settlement_state_machine_enforces_receipt_success_for_finalization() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 6,
        route,
        status: SettlementStatus::Pending,
        at_height: 100,
        settlement_tx: None,
        revert_reason: None,
    };

    let err = rec
        .apply_status_with_receipt_status(
            SettlementStatus::Finalized,
            105,
            Some("0xfailed".to_string()),
            Some(0),
            None,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidSettlementReceiptStatus {
            expected: 1,
            got: 0
        }
    ));

    rec.apply_status_with_receipt_status(
        SettlementStatus::Finalized,
        105,
        Some("0xok".to_string()),
        Some(SETTLEMENT_TX_RECEIPT_SUCCESS),
        None,
    )
    .unwrap();
    assert_eq!(rec.settlement_tx.as_deref(), Some("0xok"));
}

#[test]
fn settlement_state_machine_enforces_pending_terminal_model() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 7,
        route,
        status: SettlementStatus::Pending,
        at_height: 100,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Finalized,
        105,
        Some("0xabc".to_string()),
        None,
    )
    .unwrap();
    assert_eq!(rec.status, SettlementStatus::Finalized);
    assert_eq!(rec.settlement_tx.as_deref(), Some("0xabc"));

    let err = rec
        .apply_status(
            SettlementStatus::Reverted,
            106,
            None,
            Some("late fraud proof".to_string()),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        InteropIdentityError::InvalidSettlementTransition {
            from: SettlementStatus::Finalized,
            to: SettlementStatus::Reverted
        }
    ));
}

#[test]
fn settlement_revert_and_finalize_fields_are_mutually_exclusive() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 9,
        route,
        status: SettlementStatus::Pending,
        at_height: 100,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Reverted,
        101,
        Some("0xshould-be-ignored".to_string()),
        Some("executor_sla_timeout".to_string()),
    )
    .unwrap();
    assert_eq!(rec.status, SettlementStatus::Reverted);
    assert_eq!(rec.revert_reason.as_deref(), Some("executor_sla_timeout"));
    assert_eq!(rec.settlement_tx, None);

    let mut rec2 = SettlementRecord {
        settlement_id: 10,
        route: BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 200,
        settlement_tx: Some("0xstale".to_string()),
        revert_reason: Some("stale-reason".to_string()),
    };

    rec2.apply_status(
        SettlementStatus::Finalized,
        201,
        Some("0xfinal".to_string()),
        Some("should-be-cleared".to_string()),
    )
    .unwrap();
    assert_eq!(rec2.status, SettlementStatus::Finalized);
    assert_eq!(rec2.settlement_tx.as_deref(), Some("0xfinal"));
    assert_eq!(rec2.revert_reason, None);
}

#[test]
fn settlement_terminal_payloads_are_trimmed_before_persisting() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };

    let mut finalized = SettlementRecord {
        settlement_id: 13,
        route: route.clone(),
        status: SettlementStatus::Pending,
        at_height: 300,
        settlement_tx: None,
        revert_reason: None,
    };
    finalized
        .apply_status(
            SettlementStatus::Finalized,
            301,
            Some("  0xtrimmed  ".to_string()),
            None,
        )
        .unwrap();
    assert_eq!(finalized.settlement_tx.as_deref(), Some("0xtrimmed"));
    assert_eq!(finalized.revert_reason, None);

    let mut reverted = SettlementRecord {
        settlement_id: 14,
        route,
        status: SettlementStatus::Pending,
        at_height: 400,
        settlement_tx: None,
        revert_reason: None,
    };
    reverted
        .apply_status(
            SettlementStatus::Reverted,
            401,
            None,
            Some("  manual_compensation  ".to_string()),
        )
        .unwrap();
    assert_eq!(reverted.settlement_tx, None);
    assert_eq!(
        reverted.revert_reason.as_deref(),
        Some("manual_compensation")
    );
}

#[test]
fn settlement_revert_reason_normalizes_proof_adapter_aliases() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 140,
        route,
        status: SettlementStatus::Pending,
        at_height: 500,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Reverted,
        501,
        None,
        Some("TEE_ATTESTATION".to_string()),
    )
    .unwrap();
    assert_eq!(rec.revert_reason.as_deref(), Some("tee-receipt"));

    rec.apply_status(
        SettlementStatus::Reverted,
        502,
        None,
        Some("zk_proof".to_string()),
    )
    .unwrap_err();
    assert_eq!(rec.revert_reason.as_deref(), Some("tee-receipt"));
}

#[test]
fn settlement_revert_reason_normalization_keeps_non_proof_reason() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 141,
        route,
        status: SettlementStatus::Pending,
        at_height: 600,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Reverted,
        601,
        None,
        Some("executor_sla_timeout".to_string()),
    )
    .unwrap();
    assert_eq!(rec.revert_reason.as_deref(), Some("executor_sla_timeout"));
}

#[test]
fn settlement_pending_reapply_scrubs_terminal_payload_fields() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 16,
        route,
        status: SettlementStatus::Pending,
        at_height: 600,
        // simulate legacy/corrupt snapshot carrying terminal payloads while pending
        settlement_tx: Some("0xstale".to_string()),
        revert_reason: Some("stale-reason".to_string()),
    };

    rec.apply_status(
        SettlementStatus::Pending,
        601,
        Some("0xignored".to_string()),
        Some("ignored".to_string()),
    )
    .unwrap();

    assert_eq!(rec.status, SettlementStatus::Pending);
    assert_eq!(rec.at_height, 601);
    assert_eq!(rec.settlement_tx, None);
    assert_eq!(rec.revert_reason, None);
}
