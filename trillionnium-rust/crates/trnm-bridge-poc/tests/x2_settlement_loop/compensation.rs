use super::support::*;

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
fn x3_prep_degraded_heartbeat_blank_reason_falls_back_to_stable_contract_message() {
    let mut request = SettlementRequest::new(1, "0xhbblankreason".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("\u{200B}\n\t\u{202E}");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 8080 },
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
fn x3_prep_manual_degraded_blank_message_uses_stable_failure_fallback() {
    let mut request = SettlementRequest::new(1, "0xmanual-hbblank".to_string());
    let token = operator_token();

    let degraded = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "\u{200B}\n\t\u{202E}".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 9999 },
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
#[test]
fn x3_prep_manual_degraded_reason_is_length_capped_for_replayable_compensation() {
    let mut request = SettlementRequest::new(1, "0xmanual-hbcap".to_string());
    let token = operator_token();

    let degraded = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: format!("manual{}", "y".repeat(400)),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 10001 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, .. } = out else {
        panic!("expected compensated branch");
    };
    assert!(reason.starts_with("heartbeat degraded: manual"));
    assert!(reason.ends_with('…'));
    assert_eq!(reason.chars().count(), 181);
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}
#[test]
fn x3_prep_manual_degraded_heartbeat_preserves_last_observed_metrics_in_compensation_event() {
    let mut request = SettlementRequest::new(1, "0xmanual-hbmetrics".to_string());
    let token = operator_token();

    let degraded = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 812,
            target_height: 807,
            latency_ms: 91,
        }),
        should_retry: false,
        degraded: true,
        message: "target relay timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 813 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: target relay timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: Some(812),
                heartbeat_target_height: Some(807),
                heartbeat_latency_ms: Some(91),
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
fn x3_prep_manual_degraded_heartbeat_drops_invalid_embedded_metrics_from_compensation_event() {
    let mut request = SettlementRequest::new(1, "0xmanual-hbmetrics-invalid".to_string());
    let token = operator_token();

    let degraded = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 0,
            target_height: 807,
            latency_ms: 91,
        }),
        should_retry: false,
        degraded: true,
        message: "target relay timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 813 },
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
fn x3_prep_manual_degraded_heartbeat_drops_target_ahead_embedded_metrics_from_compensation_event() {
    let mut request = SettlementRequest::new(1, "0xmanual-hbmetrics-target-ahead".to_string());
    let token = operator_token();

    let degraded = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 807,
            target_height: 808,
            latency_ms: 91,
        }),
        should_retry: false,
        degraded: true,
        message: "target relay timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 813 },
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
