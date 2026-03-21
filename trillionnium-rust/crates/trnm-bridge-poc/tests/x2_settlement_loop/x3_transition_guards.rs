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
fn x3_prep_confirm_during_heartbeat_retry_window_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xconfirm-retry-window".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_failure("target relay timeout #1");

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 699 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::RetryPending {
            phase: "relay_heartbeat",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_failed_confirm_during_heartbeat_retry_window_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xfailed-confirm-retry-window".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_failure("target relay timeout #1");

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target confirm timeout".to_string(),
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::RetryPending {
            phase: "relay_heartbeat",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_zero_height_confirm_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xconfirm-zero-height".to_string());
    let token = operator_token();

    let healthy = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: false,
        message: "healthy".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &healthy,
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
fn x3_prep_confirm_equal_to_observed_target_height_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xconfirm-equal-target-height".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 699 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 699 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_confirm_with_non_monotonic_heartbeat_payload_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xconfirm-invalid-heartbeat-bounds".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: Some(RelayHeartbeat {
            source_height: 699,
            target_height: 700,
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
fn x3_prep_confirm_below_observed_target_height_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xconfirm-below-target-height".to_string());
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
fn x3_prep_failed_confirm_with_non_monotonic_heartbeat_payload_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xfailed-confirm-invalid-heartbeat-bounds".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: Some(RelayHeartbeat {
            source_height: 699,
            target_height: 700,
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
        SettlementConfirm::Failed {
            reason: "late target receipt timeout".to_string(),
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 700 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_confirm_equal_to_observed_source_height_finalizes_with_stable_event() {
    let mut request = SettlementRequest::new(1, "0xconfirm-equal-source-height".to_string());
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
fn x3_prep_confirm_above_observed_source_plus_one_is_rejected_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xconfirm-above-source-plus-one".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 702 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 702 }
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
