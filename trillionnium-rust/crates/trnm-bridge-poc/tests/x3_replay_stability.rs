use trnm_bridge_poc::bridge_status::{BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest};
use trnm_bridge_poc::relay_heartbeat::{HeartbeatOutcome, RelayHeartbeatConfig, RelayHeartbeatMonitor};
use trnm_bridge_poc::x2_settlement_loop::{current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep};

fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "agent:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    }
}

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
