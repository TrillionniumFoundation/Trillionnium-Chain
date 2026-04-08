use super::*;

#[test]
fn x3_prep_duplicate_confirm_after_finalize_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xdup00f".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(310, 309, 25);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 311 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 311,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(310),
                heartbeat_target_height: Some(309),
                heartbeat_latency_ms: Some(25),
                confirm_height: Some(311),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 312 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "finalized",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));
}

#[test]
fn x3_prep_reorder_confirm_with_older_height_after_finalize_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xreorder-confirm-height".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 701,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(700),
                heartbeat_target_height: Some(699),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(701),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(701));

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 700 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "finalized",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(701));
}

#[test]
fn x3_prep_reorder_failed_confirm_after_finalize_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xreorder".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(512, 510, 31);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 513 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 513,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(512),
                heartbeat_target_height: Some(510),
                heartbeat_latency_ms: Some(31),
                confirm_height: Some(513),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(513));

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "late reordered failure receipt".to_string(),
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "reverted",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(513));
}
