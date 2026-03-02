use trnm_bridge_poc::bridge_status::{BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest};
use trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome;
use trnm_bridge_poc::x2_settlement_loop::{current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep};

fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "agent:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    }
}

#[test]
fn x3_prep_stale_pending_degraded_reason_is_sanitized_and_capped_for_replay() {
    let mut request = SettlementRequest::new(1, "0xmatrix-sanitize-cap".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: format!("target\u{200B}\nrelay\t\u{202E}timeout{}", "x".repeat(400)),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 4242 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert!(reason.starts_with("heartbeat degraded: target relay timeout"));
    assert!(reason.ends_with('…'));
    assert!(!reason.contains('\n'));
    assert!(!reason.contains('\t'));
    assert!(!reason.contains('\u{200B}'));
    assert!(!reason.contains('\u{202E}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}
