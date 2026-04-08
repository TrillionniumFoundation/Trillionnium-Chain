use super::super::support::*;

#[test]
fn x3_prep_degraded_heartbeat_reason_is_length_capped_for_replayable_compensation() {
    let mut request = SettlementRequest::new(1, "0xreasoncap".to_string());
    let token = operator_token();

    let long_reason = format!("timeout{}", "x".repeat(400));
    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("target relay timeout #1");
    let degraded = monitor.record_failure(&long_reason);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 9001 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, .. } = out else {
        panic!("expected compensated branch");
    };
    assert!(reason.starts_with("heartbeat degraded: timeout"));
    assert!(reason.ends_with('…'));
    assert_eq!(reason.chars().count(), 181);
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_degraded_heartbeat_reason_exact_cap_has_no_ellipsis_and_is_replay_stable() {
    let mut request = SettlementRequest::new(1, "0xhbcapexact".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let exact_reason = "h".repeat(160);
    let degraded = monitor.record_failure(&exact_reason);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 9090 },
    )
    .unwrap();

    let expected = format!("heartbeat degraded: {exact_reason}");
    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: expected.clone(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(expected.clone()),
            },
        }
    );
    assert!(!expected.ends_with('…'));
    assert_eq!(expected.chars().count(), 180);
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(expected));
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
