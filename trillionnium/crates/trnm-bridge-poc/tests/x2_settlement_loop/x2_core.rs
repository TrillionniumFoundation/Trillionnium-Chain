use super::*;

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
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );
}
