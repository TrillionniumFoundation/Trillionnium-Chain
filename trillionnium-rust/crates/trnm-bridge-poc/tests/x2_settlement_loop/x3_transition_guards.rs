use super::*;
use trnm_bridge_poc::relay_heartbeat::{HeartbeatOutcome, RelayHeartbeat};

#[test]
fn x3_prep_stale_pending_on_degraded_heartbeat_triggers_compensation_revert() {
    let mut request = SettlementRequest::new(1, "0xstale01".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("target relay timeout #1");
    let degraded = monitor.record_failure("target relay timeout #2");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 411 },
    )
    .unwrap();

    assert_eq!(
        out,
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
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout #2".to_string())
    );
}

#[test]
fn x3_prep_degraded_heartbeat_takes_precedence_over_timeout_confirm_failure() {
    let mut request = SettlementRequest::new(1, "0xstale-timeout".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("target relay timeout #1");
    let degraded = monitor.record_failure("target relay timeout #2");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Failed {
            reason: "target confirm timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
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
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout #2".to_string())
    );
}

#[test]
fn x3_prep_degraded_heartbeat_with_invalid_bounds_fails_closed_before_compensation() {
    let mut request = SettlementRequest::new(1, "0xdegraded-invalid-bounds".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: Some(RelayHeartbeat {
            source_height: 0,
            target_height: 9,
            latency_ms: 42,
        }),
        degraded: true,
        should_retry: false,
        message: "target relay timeout with malformed heights".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Failed {
            reason: "target confirm timeout".to_string(),
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 0 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_degraded_retry_pending_prefers_compensation_revert_over_retry_pending() {
    let mut request = SettlementRequest::new(1, "0xdegraded-retry-pending".to_string());
    let token = operator_token();

    let degraded_retry_pending = HeartbeatOutcome {
        heartbeat: None,
        should_retry: true,
        degraded: true,
        message: "target relay timeout #2".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded_retry_pending,
        SettlementConfirm::Confirmed { height: 411 },
    )
    .unwrap();

    assert_eq!(
        out,
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
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout #2".to_string())
    );
}

#[test]
fn x3_prep_degraded_heartbeat_blank_reason_falls_back_to_stable_contract_message() {
    let mut request = SettlementRequest::new(1, "0xdegraded-blank-reason".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "\u{200B}\n\t\u{202E}".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 411 },
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
                confirm_reason: Some(
                    "heartbeat degraded: unknown heartbeat failure".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: unknown heartbeat failure".to_string())
    );
}

#[test]
fn x3_prep_degraded_invalid_heartbeat_progression_prefix_allows_compensation_revert() {
    let mut request = SettlementRequest::new(1, "0xdegraded-invalid-progression-prefix".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 310,
            target_height: 999,
            latency_ms: 25,
        }),
        should_retry: false,
        degraded: true,
        message: "Invalid heartbeat progression: target height exceeded source sample".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 411 },
    )
    .expect("declared invalid heartbeat progression should fail closed via compensation revert");

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: Invalid heartbeat progression: target height exceeded source sample".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(
                    "heartbeat degraded: Invalid heartbeat progression: target height exceeded source sample"
                        .to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "heartbeat degraded: Invalid heartbeat progression: target height exceeded source sample"
                .to_string(),
        )
    );
}

#[test]
fn x3_prep_degraded_invalid_heartbeat_progression_parenthesized_suffix_allows_compensation_revert() {
    let mut request = SettlementRequest::new(
        1,
        "0xdegraded-invalid-progression-parenthesized-suffix".to_string(),
    );
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 310,
            target_height: 999,
            latency_ms: 25,
        }),
        should_retry: false,
        degraded: true,
        message: "Invalid heartbeat progression (target height exceeded source sample)"
            .to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 411 },
    )
    .expect("parenthesized invalid heartbeat progression should fail closed via compensation revert");

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: Invalid heartbeat progression (target height exceeded source sample)".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(
                    "heartbeat degraded: Invalid heartbeat progression (target height exceeded source sample)"
                        .to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "heartbeat degraded: Invalid heartbeat progression (target height exceeded source sample)"
                .to_string(),
        )
    );
}

#[test]
fn x3_prep_degraded_invalid_heartbeat_metrics_fail_closed_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xdegraded-invalid-metrics".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 310,
            target_height: 999,
            latency_ms: 25,
        }),
        should_retry: false,
        degraded: true,
        message: "target relay timeout after malformed sample".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 411 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 999 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_failed_confirm_blank_reason_falls_back_to_stable_contract_message() {
    let mut request = SettlementRequest::new(1, "0xfailed-confirm-blank-reason".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "\u{200B}\n\t\u{202E}".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
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
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: unknown confirm failure".to_string()
        )
    );
}

#[test]
fn x3_prep_failed_confirm_blank_reason_preserves_heartbeat_metrics_in_audit_event() {
    let mut request = SettlementRequest::new(1, "0xfailed-confirm-blank-reason-metrics".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(310, 309, 25);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "\u{200B}\n\t\u{202E}".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: unknown confirm failure".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(310),
                heartbeat_target_height: Some(309),
                heartbeat_latency_ms: Some(25),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: unknown confirm failure".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: unknown confirm failure".to_string()
        )
    );
}

#[test]
fn x3_prep_stale_invalid_heartbeat_after_finalize_prefers_replay_guard_over_metric_validation() {
    let mut request = SettlementRequest::new(1, "0xstale-invalid-after-finalize".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(310, 309, 25);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 311 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 311,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(310),
                heartbeat_target_height: Some(309),
                heartbeat_latency_ms: Some(25),
                confirm_height: Some(311),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));

    let malformed_replay = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 310,
            target_height: 999,
            latency_ms: 25,
        }),
        should_retry: false,
        degraded: false,
        message: "stale malformed replay".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &malformed_replay,
        SettlementConfirm::Confirmed { height: 312 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "finalized",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));
}

#[test]
fn x3_prep_zero_source_heartbeat_replay_after_finalize_prefers_replay_guard_over_metric_validation() {
    let mut request = SettlementRequest::new(1, "0xzero-source-replay-after-finalize".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(310, 309, 25);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 311 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 311,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(310),
                heartbeat_target_height: Some(309),
                heartbeat_latency_ms: Some(25),
                confirm_height: Some(311),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));

    let malformed_replay = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 0,
            target_height: 309,
            latency_ms: 25,
        }),
        should_retry: false,
        degraded: false,
        message: "stale zero-source replay".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &malformed_replay,
        SettlementConfirm::Confirmed { height: 312 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "finalized",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));
}

#[test]
fn x3_prep_duplicate_confirm_after_finalize_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xdup00f".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(310, 309, 25);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 311 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 311,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(310),
                heartbeat_target_height: Some(309),
                heartbeat_latency_ms: Some(25),
                confirm_height: Some(311),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 311 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "finalized",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));
}

#[test]
fn x3_prep_stale_confirm_height_replay_after_finalize_prefers_replay_guard_over_finality_validation() {
    let mut request = SettlementRequest::new(1, "0xstale-confirm-replay-after-finalize".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(310, 309, 25);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 311 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 311,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(310),
                heartbeat_target_height: Some(309),
                heartbeat_latency_ms: Some(25),
                confirm_height: Some(311),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 308 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "finalized",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));
}

#[test]
fn x3_prep_rejects_stale_source_height_when_target_has_reached_source_head() {
    let mut request = SettlementRequest::new(1, "0xstale-source-height-after-catchup".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 700, 19);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 700 },
    )
    .expect_err("stale source-height confirm must fail once target reaches source head");

    assert_eq!(err, trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 700 });
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_accepts_confirm_height_at_source_plus_one_finality_boundary() {
    let mut request = SettlementRequest::new(1, "0xconfirm-upper-boundary".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: 701,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(700),
                heartbeat_target_height: Some(699),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(701),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(701));
}

#[test]
fn x3_prep_accepts_saturated_confirm_height_when_target_has_caught_up_at_u64_max() {
    let mut request =
        SettlementRequest::new(1, "0xconfirm-saturated-catchup-boundary".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(u64::MAX, u64::MAX, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: u64::MAX },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: u64::MAX,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(u64::MAX),
                heartbeat_target_height: Some(u64::MAX),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(u64::MAX),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(u64::MAX));
}

#[test]
fn x3_prep_accepts_saturated_finality_boundary_when_source_is_u64_max_and_target_lags() {
    let mut request = SettlementRequest::new(1, "0xconfirm-saturated-upper-boundary".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(u64::MAX, u64::MAX - 1, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: u64::MAX },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: u64::MAX,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(u64::MAX),
                heartbeat_target_height: Some(u64::MAX - 1),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(u64::MAX),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(u64::MAX));
}

#[test]
fn x3_prep_rejects_confirm_height_at_heartbeat_target_lower_boundary() {
    let mut request = SettlementRequest::new(1, "0xconfirm-lower-boundary".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 699 },
    )
    .expect_err("target-floor confirm height must fail closed");

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 699 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_rejects_saturated_confirm_height_at_heartbeat_target_lower_boundary() {
    let mut request =
        SettlementRequest::new(1, "0xconfirm-saturated-lower-boundary".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(u64::MAX, u64::MAX - 1, 19);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed {
            height: u64::MAX - 1,
        },
    )
    .expect_err("saturated target-floor confirm height must fail closed");

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight {
            height: u64::MAX - 1,
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_accepts_confirm_height_at_heartbeat_source_boundary() {
    let mut request = SettlementRequest::new(1, "0xconfirm-source-boundary".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 700 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: 700,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(700),
                heartbeat_target_height: Some(699),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(700),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(700));
}

#[test]
fn x3_prep_accepts_source_plus_one_confirm_when_target_has_reached_source_head() {
    let mut request = SettlementRequest::new(1, "0xconfirm-head-plus-one-boundary".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 700,
            target_height: 700,
            latency_ms: 19,
        }),
        should_retry: false,
        degraded: false,
        message: "heartbeat ok".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .expect("source+1 overlay boundary should remain confirmable even when target has reached source head");

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: 701,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(700),
                heartbeat_target_height: Some(700),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(701),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(701));
}

#[test]
fn x3_prep_rejects_confirm_height_behind_heartbeat_target_height() {
    let mut request = SettlementRequest::new(1, "0xstale-confirm-height".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 698 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 698 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_rejects_zero_confirm_height_before_finality_transition() {
    let mut request = SettlementRequest::new(1, "0xzero-confirm-height".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 0 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 0 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_rejects_non_degraded_invalid_heartbeat_progression_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xinvalid-heartbeat-progression".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 700,
            target_height: 701,
            latency_ms: 19,
        }),
        should_retry: false,
        degraded: false,
        message: "heartbeat ok".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 701 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_rejects_degraded_invalid_heartbeat_progression_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xdegraded-invalid-heartbeat-progression".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 700,
            target_height: 701,
            latency_ms: 19,
        }),
        should_retry: false,
        degraded: true,
        message: "relay heartbeat degraded".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 701 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_retry_pending_heartbeat_blocks_settlement_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xretry-pending-settlement".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let retry_pending = monitor.record_failure("target relay timeout #1");

    assert!(retry_pending.should_retry);
    assert!(!retry_pending.degraded);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &retry_pending,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::HeartbeatRetryPending {
            reason: "target relay timeout #1".to_string(),
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_retry_pending_blank_reason_falls_back_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xretry-pending-blank-reason".to_string());
    let token = operator_token();

    let retry_pending = HeartbeatOutcome {
        heartbeat: None,
        should_retry: true,
        degraded: false,
        message: "\u{200B}\n\t\u{202E}".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &retry_pending,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::HeartbeatRetryPending {
            reason: "heartbeat retry pending".to_string(),
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_retry_pending_reason_sanitizes_unicode_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xretry-pending-sanitized-reason".to_string());
    let token = operator_token();

    let retry_pending = HeartbeatOutcome {
        heartbeat: None,
        should_retry: true,
        degraded: false,
        message: "target\u{2060} relay\u{2028}timeout\u{FFF9} signal".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &retry_pending,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::HeartbeatRetryPending {
            reason: "target relay timeout signal".to_string(),
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_retry_pending_heartbeat_does_not_override_confirm_failure_terminal_compensation() {
    let mut request = SettlementRequest::new(1, "0xretry-pending-confirm-failure".to_string());
    let token = operator_token();

    let retry_pending = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 700,
            target_height: 699,
            latency_ms: 19,
        }),
        should_retry: true,
        degraded: false,
        message: "target relay timeout #1".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &retry_pending,
        SettlementConfirm::Failed {
            reason: "target confirm timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target confirm timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(700),
                heartbeat_target_height: Some(699),
                heartbeat_latency_ms: Some(19),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target confirm timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target confirm timeout".to_string())
    );
}

#[test]
fn x3_prep_retry_pending_heartbeat_after_finalize_prefers_replay_guard_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xretry-pending-after-finalize".to_string());
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
        SettlementConfirm::Confirmed { height: 701 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 701,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: Some(701),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(701));

    let retry_pending = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 700,
            target_height: 701,
            latency_ms: 19,
        }),
        should_retry: true,
        degraded: false,
        message: "late retry heartbeat".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &retry_pending,
        SettlementConfirm::Confirmed { height: 702 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "finalized",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(701));
}

#[test]
fn x3_prep_retry_pending_heartbeat_with_malformed_embedded_metrics_stays_retry_bounded() {
    let mut request = SettlementRequest::new(1, "0xretry-pending-malformed-metrics".to_string());
    let token = operator_token();

    let retry_pending = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 700,
            target_height: 701,
            latency_ms: 19,
        }),
        should_retry: true,
        degraded: false,
        message: "target relay timeout #1".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &retry_pending,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::HeartbeatRetryPending {
            reason: "target relay timeout #1".to_string(),
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_retry_pending_zero_source_metrics_stays_retry_bounded() {
    let mut request = SettlementRequest::new(1, "0xretry-pending-zero-source".to_string());
    let token = operator_token();

    let retry_pending = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 0,
            target_height: 0,
            latency_ms: 19,
        }),
        should_retry: true,
        degraded: false,
        message: "target relay timeout #1".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &retry_pending,
        SettlementConfirm::Confirmed { height: 1 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::HeartbeatRetryPending {
            reason: "target relay timeout #1".to_string(),
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_stale_retry_pending_after_finalize_prefers_replay_guard_over_retry_bounded_failure() {
    let mut request = SettlementRequest::new(1, "0xstale-retry-after-finalize".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    };

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 311 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 311,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: Some(311),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));

    let stale_retry_pending = HeartbeatOutcome {
        heartbeat: None,
        should_retry: true,
        degraded: false,
        message: "target relay timeout #1".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &stale_retry_pending,
        SettlementConfirm::Confirmed { height: 312 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "finalized",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(311));
}

#[test]
fn x3_prep_retry_pending_zero_target_metrics_stays_retry_bounded() {
    let mut request = SettlementRequest::new(1, "0xretry-pending-zero-target".to_string());
    let token = operator_token();

    let retry_pending = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 700,
            target_height: 0,
            latency_ms: 19,
        }),
        should_retry: true,
        degraded: false,
        message: "target relay timeout #1".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &retry_pending,
        SettlementConfirm::Confirmed { height: 700 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::HeartbeatRetryPending {
            reason: "target relay timeout #1".to_string(),
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_reorder_confirm_with_older_height_after_finalize_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xreorder-confirm-height".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 701 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 701,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(700),
                heartbeat_target_height: Some(699),
                heartbeat_latency_ms: Some(19),
                confirm_height: Some(701),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(701));

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 700 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "finalized",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(701));
}

#[test]
fn x3_prep_reorder_failed_confirm_after_finalize_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xreorder".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(512, 510, 31);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 513 },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Finalized {
            height: 513,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(512),
                heartbeat_target_height: Some(510),
                heartbeat_latency_ms: Some(31),
                confirm_height: Some(513),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(513));

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "late reordered failure receipt".to_string(),
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "finalized",
            to: "reverted",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(513));
}

#[test]
fn x3_prep_duplicate_failed_confirm_after_revert_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xdup-revert".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(640, 639, 24);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(640),
                heartbeat_target_height: Some(639),
                heartbeat_latency_ms: Some(24),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target chain receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "duplicate replay from target".to_string(),
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "reverted",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );
}

#[test]
fn x3_prep_reorder_confirmed_after_revert_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xreorder-confirm-after-revert".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(645, 644, 26);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(645),
                heartbeat_target_height: Some(644),
                heartbeat_latency_ms: Some(26),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target chain receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 646 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "finalized",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );
}

#[test]
fn x3_prep_duplicate_confirmed_after_revert_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xdup-confirm-after-revert".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(646, 645, 26);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(646),
                heartbeat_target_height: Some(645),
                heartbeat_latency_ms: Some(26),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target chain receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 646 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "finalized",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );
}

#[test]
fn x3_prep_retry_pending_with_malformed_metrics_after_revert_prefers_replay_guard() {
    let mut request = SettlementRequest::new(1, "0xretry-after-revert".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(646, 645, 26);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(646),
                heartbeat_target_height: Some(645),
                heartbeat_latency_ms: Some(26),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target chain receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );

    let replay_retry = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 646,
            target_height: 999,
            latency_ms: 26,
        }),
        should_retry: true,
        degraded: false,
        message: "late retry heartbeat".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &replay_retry,
        SettlementConfirm::Confirmed { height: 647 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "finalized",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );
}

#[test]
fn x3_prep_degraded_heartbeat_after_revert_prefers_replay_guard_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xdegraded-after-revert".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(648, 647, 27);

    let first = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        first,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(648),
                heartbeat_target_height: Some(647),
                heartbeat_latency_ms: Some(27),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target chain receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );

    let degraded_replay = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 648,
            target_height: 647,
            latency_ms: 27,
        }),
        should_retry: false,
        degraded: true,
        message: "late degraded heartbeat replay".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded_replay,
        SettlementConfirm::Confirmed { height: 649 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidTransition {
            from: "reverted",
            to: "reverted",
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target chain receipt timeout".to_string()
        )
    );
}
