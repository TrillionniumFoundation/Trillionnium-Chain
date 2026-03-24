use super::super::support::*;

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
