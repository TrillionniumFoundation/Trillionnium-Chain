use super::super::support::*;

#[test]
fn x3_prep_confirm_at_exact_source_plus_one_finality_boundary_succeeds() {
    let mut request = SettlementRequest::new(1, "0xfinality-boundary".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 698, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .expect("exact source+1 finality boundary should remain confirmable");

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: 701,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(700),
                heartbeat_target_height: Some(698),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(701),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(701));
}

#[test]
fn x3_prep_rejects_source_height_confirm_when_target_has_already_reached_source_head() {
    let mut request = SettlementRequest::new(1, "0xoverlay-head-caught-up".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 700, 19);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 700 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 700 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_rejects_confirm_height_below_target_when_overlay_has_already_caught_up() {
    let mut request = SettlementRequest::new(1, "0xoverlay-below-target".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 700, 19);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 699 },
    )
    .expect_err("caught-up overlay must reject confirmations below the observed target head");

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 699 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_accepts_source_plus_one_confirm_when_target_has_already_reached_source_head() {
    let mut request = SettlementRequest::new(1, "0xoverlay-head-plus-one".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 700, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .expect("source+1 overlay boundary should remain confirmable even when target has reached source head");

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: 701,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(700),
                heartbeat_target_height: Some(700),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(701),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(701));
}

#[test]
fn x3_prep_rejects_stale_saturated_confirm_when_target_has_already_reached_u64_max_source_head() {
    let mut request = SettlementRequest::new(1, "0xoverlay-max-stale-boundary".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(u64::MAX, u64::MAX, 19);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed {
            height: u64::MAX - 1,
        },
    )
    .expect_err("stale saturated confirm must fail once target reaches the source head");

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight {
            height: u64::MAX - 1,
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_accepts_saturated_finality_boundary_at_u64_max() {
    let mut request = SettlementRequest::new(1, "0xoverlay-max-boundary".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(u64::MAX, u64::MAX, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: u64::MAX },
    )
    .expect("exact saturated finality boundary should remain confirmable");

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: u64::MAX,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(u64::MAX),
                heartbeat_target_height: Some(u64::MAX),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(u64::MAX),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(u64::MAX));
}

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
