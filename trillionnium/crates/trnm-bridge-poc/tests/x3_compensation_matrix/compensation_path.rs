use super::support::*;

#[test]
fn x3_prep_stale_pending_degraded_with_heartbeat_metrics_prefers_compensation_path() {
    let mut request = SettlementRequest::new(5, "0xmatrix-degraded-with-metrics".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: Some(RelayHeartbeat {
            source_height: 88,
            target_height: 77,
            latency_ms: 19,
        }),
        should_retry: false,
        degraded: true,
        message: "target relay timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Failed {
            reason: "should be ignored once degraded".to_string(),
        },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout");
    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.heartbeat_source_height, Some(88));
    assert_eq!(event.heartbeat_target_height, Some(77));
    assert_eq!(event.heartbeat_latency_ms, Some(19));
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_retry_hint_still_fails_closed_to_compensation() {
    let mut request = SettlementRequest::new(6, "0xmatrix-degraded-retry-hint".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: Some(RelayHeartbeat {
            source_height: 188,
            target_height: 177,
            latency_ms: 29,
        }),
        should_retry: true,
        degraded: true,
        message: "target relay timeout with retry hint".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 5252 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(
        reason,
        "heartbeat degraded: target relay timeout with retry hint"
    );
    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.heartbeat_source_height, Some(188));
    assert_eq!(event.heartbeat_target_height, Some(177));
    assert_eq!(event.heartbeat_latency_ms, Some(29));
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}
