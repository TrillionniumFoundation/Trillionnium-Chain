use super::*;

#[test]
fn x3_prep_degraded_replay_keeps_first_compensation_reason_stable() {
    let mut request = SettlementRequest::new(7, "0xreplay-stale".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("target relay timeout #1");
    let degraded = monitor.record_failure("target relay timeout #2");

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 900 },
    )
    .unwrap();

    assert_eq!(
        first,
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

    let replay = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "stale retry with mutated reason".to_string(),
    };
    let replay_err = drive_minimal_settlement(
        &mut request,
        &token,
        &replay,
        SettlementConfirm::Failed {
            reason: "late confirm timeout".to_string(),
        },
    )
    .unwrap_err();

    assert_eq!(
        replay_err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "reverted",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout #2".to_string())
    );
}

#[test]
fn x3_prep_degraded_blank_reason_replay_keeps_fallback_reason_stable() {
    let mut request = SettlementRequest::new(8, "0xreplay-blank".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "\u{200B}\n\t\u{202E}".to_string(),
    };

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 901 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: unknown heartbeat failure".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: unknown heartbeat failure".to_string()),
            },
        }
    );

    let replay = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target relay timeout #mutated".to_string(),
    };

    let replay_err = drive_minimal_settlement(
        &mut request,
        &token,
        &replay,
        SettlementConfirm::Confirmed { height: 902 },
    )
    .unwrap_err();

    assert_eq!(
        replay_err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "reverted",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: unknown heartbeat failure".to_string())
    );
}

#[test]
fn x3_prep_degraded_over_cap_reason_replay_keeps_truncated_reason_stable() {
    let mut request = SettlementRequest::new(12, "0xreplay-degraded-over-cap".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "x".repeat(220),
    };

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 903 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = first else {
        panic!("expected compensated branch");
    };

    assert!(reason.starts_with("heartbeat degraded: "));
    assert!(reason.ends_with('…'));
    assert_eq!(reason.matches('…').count(), 1);
    assert_eq!(event.confirm_reason, Some(reason.clone()));

    let replay = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "mutated shorter degraded reason".to_string(),
    };

    let replay_err = drive_minimal_settlement(
        &mut request,
        &token,
        &replay,
        SettlementConfirm::Confirmed { height: 904 },
    )
    .unwrap_err();

    assert_eq!(
        replay_err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "reverted",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}
