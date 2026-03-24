use super::super::*;

#[test]
fn settlement_revert_reason_reapply_accepts_equivalent_canonical_alias() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 142,
        route,
        status: SettlementStatus::Pending,
        at_height: 610,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Reverted,
        611,
        None,
        Some("fraud-proof".to_string()),
    )
    .unwrap();

    // Re-applying same terminal state with an equivalent alias should stay idempotent.
    rec.apply_status(
        SettlementStatus::Reverted,
        612,
        None,
        Some("FRAUD_PROOF".to_string()),
    )
    .unwrap();

    assert_eq!(rec.revert_reason.as_deref(), Some("fraud-proof"));
}

#[test]
fn settlement_revert_reason_reapply_accepts_delimiter_variant_alias() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 143,
        route,
        status: SettlementStatus::Pending,
        at_height: 620,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Reverted,
        621,
        None,
        Some("tee-receipt".to_string()),
    )
    .unwrap();

    rec.apply_status(
        SettlementStatus::Reverted,
        622,
        None,
        Some(" TEE / ATTESTATION ".to_string()),
    )
    .unwrap();

    assert_eq!(rec.revert_reason.as_deref(), Some("tee-receipt"));
}

#[test]
fn settlement_revert_reason_reapply_accepts_compact_legacy_alias() {
    let route = BridgeRoute {
        route_id: "eth->trnm".to_string(),
        source_chain: "ethereum".to_string(),
        target_chain: "trillionnium".to_string(),
    };
    let mut rec = SettlementRecord {
        settlement_id: 144,
        route,
        status: SettlementStatus::Pending,
        at_height: 623,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Reverted,
        624,
        None,
        Some("fraud-proof".to_string()),
    )
    .unwrap();

    rec.apply_status(
        SettlementStatus::Reverted,
        625,
        None,
        Some("FRAUDPROOF".to_string()),
    )
    .unwrap();

    assert_eq!(rec.revert_reason.as_deref(), Some("fraud-proof"));
}
