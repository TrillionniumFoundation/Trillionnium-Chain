use super::common::*;

#[test]
fn x3_prep_confirm_failed_replay_keeps_first_compensation_reason_stable() {
    let mut request = SettlementRequest::new(9, "0xreplay-confirm-failed".to_string());
    let token = operator_token();
    let healthy = healthy_outcome();

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Failed {
            reason: "target relay timeout #1".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target relay timeout #1".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target relay timeout #1".to_string(),
                ),
            },
        }
    );

    let replay_err = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Failed {
            reason: "mutated timeout reason".to_string(),
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
        &BridgeStatus::Reverted("settlement confirm failed: target relay timeout #1".to_string())
    );
}

#[test]
fn x3_prep_confirm_failed_blank_reason_replay_keeps_fallback_reason_stable() {
    let mut request = SettlementRequest::new(10, "0xreplay-confirm-failed-blank".to_string());
    let token = operator_token();
    let healthy = healthy_outcome();

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Failed {
            reason: "\u{200B}\n\t\u{202E}".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: unknown confirm failure".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: unknown confirm failure".to_string(),
                ),
            },
        }
    );

    let replay_err = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Failed {
            reason: "mutated timeout reason".to_string(),
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
        &BridgeStatus::Reverted("settlement confirm failed: unknown confirm failure".to_string())
    );
}

#[test]
fn x3_prep_confirm_failed_over_cap_reason_replay_keeps_truncated_reason_stable() {
    let mut request = SettlementRequest::new(11, "0xreplay-confirm-failed-over-cap".to_string());
    let token = operator_token();
    let healthy = healthy_outcome();

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Failed {
            reason: "x".repeat(220),
        },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = first else {
        panic!("expected compensated branch");
    };

    assert!(reason.starts_with("settlement confirm failed: "));
    assert!(reason.ends_with('…'));
    assert_eq!(reason.matches('…').count(), 1);
    assert_eq!(event.confirm_reason, Some(reason.clone()));

    let replay_err = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Failed {
            reason: "mutated shorter reason".to_string(),
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
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_confirm_failed_unicode_controls_replay_keeps_first_sanitized_reason_stable() {
    let mut request =
        SettlementRequest::new(15, "0xreplay-confirm-failed-unicode-controls".to_string());
    let token = operator_token();
    let healthy = healthy_outcome();

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Failed {
            reason: "target\u{2065}\r\nrelay\u{2028}timeout\u{2029}signal\u{FE0F}\u{E0100}\u{FFF9}\u{FFFA}\u{FFFB}".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target relay timeout signal".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target relay timeout signal".to_string(),
                ),
            },
        }
    );

    let replay_err = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Failed {
            reason: "mutated replay reason should not replace canonical first reason".to_string(),
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
        &BridgeStatus::Reverted(
            "settlement confirm failed: target relay timeout signal".to_string(),
        )
    );
}
