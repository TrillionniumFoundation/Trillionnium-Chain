use super::super::support::*;

#[test]
fn x3_prep_confirm_failure_reason_exact_cap_has_no_ellipsis_and_is_replay_stable() {
    let mut request = SettlementRequest::new(1, "0xcapexact".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);
    let exact_reason = "r".repeat(160);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: exact_reason.clone(),
        },
    )
    .unwrap();

    let expected = format!("settlement confirm failed: {exact_reason}");
    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: expected.clone(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(700),
                heartbeat_target_height: Some(699),
                heartbeat_latency_ms: Some(19),
                confirm_height: None,
                confirm_reason: Some(expected.clone()),
            },
        }
    );
    assert!(!expected.ends_with('…'));
    assert_eq!(expected.chars().count(), 187);
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(expected));
}

#[test]
fn x3_prep_confirm_failure_reason_unicode_over_cap_truncates_once_with_terminal_ellipsis() {
    let mut request = SettlementRequest::new(1, "0xconfirm-unicode-cap".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(736, 735, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: format!("target chain confirmation timeout{}", "x".repeat(200)),
        },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert!(reason.starts_with("settlement confirm failed: target chain confirmation timeout"));
    assert!(reason.ends_with('…'));
    assert_eq!(reason.matches('…').count(), 1);
    assert!(reason.chars().count() <= 188);

    assert_eq!(event.phase, "settlement_confirm_failed");
    assert_eq!(event.heartbeat_source_height, Some(736));
    assert_eq!(event.heartbeat_target_height, Some(735));
    assert_eq!(event.heartbeat_latency_ms, Some(19));
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason.as_deref(), Some(reason.as_str()));

    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}
