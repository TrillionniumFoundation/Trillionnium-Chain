use super::*;

#[test]
fn x3_prep_duplicate_failed_confirm_after_revert_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xdup-revert".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(640, 639, 24);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(640),
                heartbeat_target_height: Some(639),
                heartbeat_latency_ms: Some(24),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target chain receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "duplicate replay from target".to_string(),
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "reverted",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );
}

#[test]
fn x3_prep_reorder_confirmed_after_revert_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xreorder-confirm-after-revert".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(645, 644, 26);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(645),
                heartbeat_target_height: Some(644),
                heartbeat_latency_ms: Some(26),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target chain receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 646 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "finalized",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );
}

#[test]
fn x3_prep_duplicate_confirmed_after_revert_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xdup-confirm-after-revert".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(646, 645, 26);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(646),
                heartbeat_target_height: Some(645),
                heartbeat_latency_ms: Some(26),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target chain receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 646 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "finalized",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );
}

#[test]
fn x3_prep_stale_confirm_height_after_revert_prefers_replay_guard_over_finality_validation() {
    let mut request = SettlementRequest::new(1, "0xstale-confirm-after-revert".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(646, 645, 26);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(646),
                heartbeat_target_height: Some(645),
                heartbeat_latency_ms: Some(26),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target chain receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 644 },
    )
    .expect_err("reverted replay must short-circuit before stale confirm height validation");

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "finalized",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );
}
