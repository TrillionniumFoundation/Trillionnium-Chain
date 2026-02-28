use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest,
};
use trnm_bridge_poc::relay_heartbeat::{RelayHeartbeatConfig, RelayHeartbeatMonitor};
use trnm_bridge_poc::x2_settlement_loop::{
    current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep,
};

fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "agent:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    }
}

#[test]
fn x2_happy_path_heartbeat_ok_then_confirm_finalize() {
    let mut request = SettlementRequest::new(1, "0xfeedbeef".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(120, 118, 42);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 121 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: 121,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(120),
                heartbeat_target_height: Some(118),
                heartbeat_latency_ms: Some(42),
                confirm_height: Some(121),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(121));
}

#[test]
fn x2_failure_path_confirm_failed_triggers_compensation_revert() {
    let mut request = SettlementRequest::new(1, "0xbadf00d".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(220, 219, 38);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(220),
                heartbeat_target_height: Some(219),
                heartbeat_latency_ms: Some(38),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target chain receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target chain receipt timeout".to_string())
    );
}

#[test]
fn x3_prep_stale_pending_on_degraded_heartbeat_triggers_compensation_revert() {
    let mut request = SettlementRequest::new(1, "0xstale01".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("target relay timeout #1");
    let degraded = monitor.record_failure("target relay timeout #2");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 411 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: target relay timeout #2".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: target relay timeout #2".to_string()),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout #2".to_string())
    );
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
