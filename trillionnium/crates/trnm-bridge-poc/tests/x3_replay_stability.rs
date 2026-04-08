use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest,
};
use trnm_bridge_poc::relay_heartbeat::{
    HeartbeatOutcome, RelayHeartbeatConfig, RelayHeartbeatMonitor,
};
use trnm_bridge_poc::x2_settlement_loop::{
    current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep,
};

fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
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
fn x3_prep_confirm_failed_replay_keeps_first_compensation_reason_stable() {
    let mut request = SettlementRequest::new(9, "0xreplay-confirm-failed".to_string());
    let token = operator_token();

    let healthy = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    };

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

    let healthy = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    };

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

    let healthy = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    };

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

#[test]
fn x3_prep_confirm_failed_unicode_controls_replay_keeps_first_sanitized_reason_stable() {
    let mut request =
        SettlementRequest::new(15, "0xreplay-confirm-failed-unicode-controls".to_string());
    let token = operator_token();

    let healthy = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    };

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

#[test]
fn x3_prep_duplicate_or_reordered_degraded_after_finalize_is_rejected_without_state_drift() {
    let mut request = SettlementRequest::new(13, "0xreplay-after-finalize".to_string());
    let token = operator_token();

    let healthy = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 1001,
            target_height: 1000,
            latency_ms: 18,
        }),
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    };

    let finalized = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Confirmed { height: 1001 },
    )
    .unwrap();

    assert_eq!(
        finalized,
        SettlementStep::Finalized {
            height: 1001,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(1001),
                heartbeat_target_height: Some(1000),
                heartbeat_latency_ms: Some(18),
                confirm_height: Some(1001),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(1001));

    let stale_degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "stale degraded timeout after finalize".to_string(),
    };

    let replay_err = drive_minimal_settlement(
        &mut request,
        &token,
        &stale_degraded,
        SettlementConfirm::Confirmed { height: 1002 },
    )
    .unwrap_err();

    assert_eq!(
        replay_err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "reverted",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(1001));
}

#[test]
fn x3_prep_duplicate_or_reordered_failed_confirm_after_finalize_is_rejected_without_state_drift() {
    let mut request = SettlementRequest::new(14, "0xreplay-failed-after-finalize".to_string());
    let token = operator_token();

    let healthy = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 1003,
            target_height: 1002,
            latency_ms: 19,
        }),
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    };

    let finalized = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Confirmed { height: 1003 },
    )
    .unwrap();

    assert_eq!(
        finalized,
        SettlementStep::Finalized {
            height: 1003,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(1003),
                heartbeat_target_height: Some(1002),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(1003),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(1003));

    let replay_err = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
        SettlementConfirm::Failed {
            reason: "late duplicate timeout signal".to_string(),
        },
    )
    .unwrap_err();

    assert_eq!(
        replay_err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "reverted",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(1003));
}
