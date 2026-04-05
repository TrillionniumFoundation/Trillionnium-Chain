use super::support::*;

#[test]
fn x3_prep_degraded_heartbeat_reason_sanitizes_invisible_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-sanitize".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{200B}\nrelay\t\u{202E}timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 734 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: target relay timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: target relay timeout".to_string()),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout".to_string())
    );
}
#[test]
fn x3_prep_degraded_heartbeat_reason_sanitizes_bom_and_word_joiner_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-sanitize-bom".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{FEFF}relay\u{2060}timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 736 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: target relay timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: target relay timeout".to_string()),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout".to_string())
    );
}
#[test]
fn x3_prep_degraded_heartbeat_reason_strips_directional_marks_and_cgj_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-sanitize-dir-cgj".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{200E}\u{034F}relay\u{200F}timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 736 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: target relay timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: target relay timeout".to_string()),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout".to_string())
    );
}
#[test]
fn x3_prep_degraded_heartbeat_reason_strips_inhibit_symmetric_swapping_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-sanitize-iss".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{2065} relay timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 736 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: target relay timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: target relay timeout".to_string()),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout".to_string())
    );
}
#[test]
fn x3_prep_degraded_heartbeat_reason_strips_variation_selectors_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-sanitize-vs".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{FE0E} relay\u{FE0F} timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 737 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: target relay timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: target relay timeout".to_string()),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout".to_string())
    );
}
#[test]
fn x3_prep_degraded_heartbeat_reason_unicode_over_cap_truncates_once_with_terminal_ellipsis() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-unicode-cap".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure(&format!("target relay timeout{}", "x".repeat(200)));

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 737 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert!(reason.starts_with("heartbeat degraded: target relay timeout"));
    assert!(reason.ends_with('…'));
    assert_eq!(reason.matches('…').count(), 1);
    assert!(reason.chars().count() <= 181);

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.heartbeat_source_height, None);
    assert_eq!(event.heartbeat_target_height, None);
    assert_eq!(event.heartbeat_latency_ms, None);
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason.as_deref(), Some(reason.as_str()));

    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}
