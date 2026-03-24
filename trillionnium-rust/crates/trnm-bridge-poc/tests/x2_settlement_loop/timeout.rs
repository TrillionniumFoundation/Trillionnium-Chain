use super::support::*;

#[test]
fn x3_prep_invalid_heartbeat_height_takes_precedence_over_confirm_failure_reason() {
    let mut request = SettlementRequest::new(1, "0xhb-invalid-height-precedence".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let degraded = monitor.record_success(0, 411, 29);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Failed {
            reason: "target confirm timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: invalid heartbeat height".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: invalid heartbeat height".to_string()),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: invalid heartbeat height".to_string())
    );
}
#[test]
fn x3_prep_target_ahead_heartbeat_takes_precedence_over_confirm_failure_reason() {
    let mut request = SettlementRequest::new(1, "0xhb-invalid-progression-precedence".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let degraded = monitor.record_success(411, 412, 29);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Failed {
            reason: "target confirm timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: invalid heartbeat progression".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(
                    "heartbeat degraded: invalid heartbeat progression".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: invalid heartbeat progression".to_string())
    );
}
#[test]
fn x3_prep_degraded_heartbeat_takes_precedence_over_timeout_confirm_failure() {
    let mut request = SettlementRequest::new(1, "0xstale-timeout".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("target relay timeout #1");
    let degraded = monitor.record_failure("target relay timeout #2");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Failed {
            reason: "target confirm timeout".to_string(),
        },
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
fn x3_prep_confirm_failure_blank_reason_falls_back_to_stable_contract_message() {
    let mut request = SettlementRequest::new(1, "0xblankreason".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(601, 600, 22);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "\u{200B}\n\t\u{202E}".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: unknown confirm failure".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(601),
                heartbeat_target_height: Some(600),
                heartbeat_latency_ms: Some(22),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: unknown confirm failure".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: unknown confirm failure".to_string())
    );
}
#[test]
fn x3_prep_confirm_failure_blank_reason_preserves_heartbeat_metrics() {
    let mut request = SettlementRequest::new(1, "0xconfirm-blank-metrics".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(701, 699, 21);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "\u{200B}\n\t\u{202E}".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: unknown confirm failure".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(701),
                heartbeat_target_height: Some(699),
                heartbeat_latency_ms: Some(21),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: unknown confirm failure".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: unknown confirm failure".to_string())
    );
}
#[test]
fn x3_prep_degraded_blank_reason_takes_precedence_over_confirm_failure_reason() {
    let mut request = SettlementRequest::new(1, "0xhbblank-precedence".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("\u{200B}\n\t\u{202E}");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Failed {
            reason: "target confirm timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: unknown heartbeat failure".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: unknown heartbeat failure".to_string(),),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: unknown heartbeat failure".to_string())
    );
}
