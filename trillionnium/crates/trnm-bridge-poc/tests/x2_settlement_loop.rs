use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest,
};
use trnm_bridge_poc::relay_heartbeat::{RelayHeartbeatConfig, RelayHeartbeatMonitor};
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
fn x2_happy_path_heartbeat_ok_then_confirm_finalize() {
    let mut request = SettlementRequest::new(1, "0xfeedbeef".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(120, 118, 42);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 121 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: 121,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(120),
                heartbeat_target_height: Some(118),
                heartbeat_latency_ms: Some(42),
                confirm_height: Some(121),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(121));
}

#[test]
fn x2_confirm_rejects_stale_source_height_once_heartbeat_overlay_has_caught_up() {
    let mut request = SettlementRequest::new(1, "0xstronger-finality-boundary".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(640, 640, 17);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 640 },
    )
    .expect_err("caught-up overlay must require the stronger source+1 boundary");

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 640 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x2_confirm_accepts_source_plus_one_height_once_heartbeat_overlay_has_caught_up() {
    let mut request = SettlementRequest::new(1, "0xstronger-finality-boundary-pass".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(640, 640, 17);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 641 },
    )
    .expect("caught-up overlay should still accept the stronger source+1 boundary");

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: 641,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(640),
                heartbeat_target_height: Some(640),
                heartbeat_latency_ms: Some(17),
                confirm_height: Some(641),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(641));
}

#[test]
fn x2_confirm_accepts_saturated_source_height_once_heartbeat_overlay_has_caught_up() {
    let mut request = SettlementRequest::new(1, "0xsaturated-finality-boundary-pass".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(u64::MAX, u64::MAX, 17);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: u64::MAX },
    )
    .expect("caught-up saturated overlay should keep the source+1 boundary pinned at u64::MAX");

    assert_eq!(
        out,
        SettlementStep::Finalized {
            height: u64::MAX,
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: Some(u64::MAX),
                heartbeat_target_height: Some(u64::MAX),
                heartbeat_latency_ms: Some(17),
                confirm_height: Some(u64::MAX),
                confirm_reason: None,
            },
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(u64::MAX));
}

#[test]
fn x2_failure_path_confirm_failed_triggers_compensation_revert() {
    let mut request = SettlementRequest::new(1, "0xbadf00d".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(220, 219, 38);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(220),
                heartbeat_target_height: Some(219),
                heartbeat_latency_ms: Some(38),
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
}

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
fn x3_prep_zero_height_heartbeat_success_fails_closed_to_compensation() {
    let mut request = SettlementRequest::new(1, "0xhb-zero-height".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let degraded = monitor.record_success(0, 411, 29);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 412 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: invalid heartbeat height".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: invalid heartbeat height".to_string()),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: invalid heartbeat height".to_string())
    );
}

#[test]
fn x3_prep_zero_target_height_heartbeat_success_fails_closed_to_compensation() {
    let mut request = SettlementRequest::new(1, "0xhb-zero-target-height".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let degraded = monitor.record_success(411, 0, 29);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 412 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: invalid heartbeat height".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: invalid heartbeat height".to_string()),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: invalid heartbeat height".to_string())
    );
}

#[test]
fn x3_prep_invalid_heartbeat_height_takes_precedence_over_confirm_failure_reason() {
    let mut request = SettlementRequest::new(1, "0xhb-invalid-height-precedence".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let degraded = monitor.record_success(0, 411, 29);

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
            reason: "heartbeat degraded: invalid heartbeat height".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some("heartbeat degraded: invalid heartbeat height".to_string()),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: invalid heartbeat height".to_string())
    );
}

#[test]
fn x3_prep_target_ahead_heartbeat_takes_precedence_over_confirm_failure_reason() {
    let mut request = SettlementRequest::new(1, "0xhb-invalid-progression-precedence".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let degraded = monitor.record_success(411, 412, 29);

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
            reason: "heartbeat degraded: invalid heartbeat progression".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(
                    "heartbeat degraded: invalid heartbeat progression".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: invalid heartbeat progression".to_string())
    );
}

#[test]
fn x3_prep_invalid_heartbeat_height_prefix_allows_compensation_revert_with_embedded_zero_metrics() {
    let mut request = SettlementRequest::new(1, "0xhb-invalid-height-prefix".to_string());
    let token = operator_token();

    let degraded = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 0,
            target_height: 411,
            latency_ms: 29,
        }),
        should_retry: false,
        degraded: true,
        message: "invalid heartbeat height: sampled target relay payload malformed".to_string(),
    };

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
            reason: "heartbeat degraded: invalid heartbeat height: sampled target relay payload malformed".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(
                    "heartbeat degraded: invalid heartbeat height: sampled target relay payload malformed".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "heartbeat degraded: invalid heartbeat height: sampled target relay payload malformed"
                .to_string()
        )
    );
}

#[test]
fn x3_prep_invalid_heartbeat_height_parenthesized_suffix_allows_compensation_revert() {
    let mut request =
        SettlementRequest::new(1, "0xhb-invalid-height-parenthesized-suffix".to_string());
    let token = operator_token();

    let degraded = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 0,
            target_height: 411,
            latency_ms: 29,
        }),
        should_retry: false,
        degraded: true,
        message: "invalid heartbeat height (sampled target relay payload malformed)".to_string(),
    };

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
            reason: "heartbeat degraded: invalid heartbeat height (sampled target relay payload malformed)".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(
                    "heartbeat degraded: invalid heartbeat height (sampled target relay payload malformed)".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "heartbeat degraded: invalid heartbeat height (sampled target relay payload malformed)"
                .to_string()
        )
    );
}

#[test]
fn x3_prep_invalid_heartbeat_progression_exclamation_suffix_allows_compensation_revert() {
    let mut request =
        SettlementRequest::new(1, "0xhb-invalid-progression-exclamation-suffix".to_string());
    let token = operator_token();

    let degraded = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: 411,
            target_height: 412,
            latency_ms: 29,
        }),
        should_retry: false,
        degraded: true,
        message: "invalid heartbeat progression! sampled target relay payload ahead of source"
            .to_string(),
    };

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
            reason: "heartbeat degraded: invalid heartbeat progression! sampled target relay payload ahead of source".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "relay_heartbeat_degraded",
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
                confirm_height: None,
                confirm_reason: Some(
                    "heartbeat degraded: invalid heartbeat progression! sampled target relay payload ahead of source".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "heartbeat degraded: invalid heartbeat progression! sampled target relay payload ahead of source".to_string()
        )
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
fn x3_prep_degraded_heartbeat_without_revert_capability_fails_closed_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xdegraded-unauthorized".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
    };

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("target relay timeout #1");
    let degraded = monitor.record_failure("target relay timeout #2");

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 412 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::Unauthorized {
            subject: "did:trn:settlement-operator".to_string(),
            action: "revert",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_degraded_heartbeat_with_non_canonical_tx_hash_fails_closed_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xabc\u{200B}def".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("target relay timeout #1");
    let degraded = monitor.record_failure("target relay timeout #2");

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 413 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_confirm_failure_with_non_canonical_operator_subject_fails_closed_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xconfirm-malformed-subject".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement\u{200B}-operator".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(414, 413, 17);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target chain receipt timeout".to_string(),
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::MalformedToken {
            reason: "non-canonical subject",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_degraded_heartbeat_with_non_canonical_operator_subject_fails_closed_without_state_change(
) {
    let mut request = SettlementRequest::new(1, "0xdegraded-malformed-subject".to_string());
    let token = CapabilityToken {
        subject: "did:trn:settlement\u{200B}-operator".to_string(),
        capabilities: vec![SettlementCapability::Revert],
    };

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("target relay timeout #1");
    let degraded = monitor.record_failure("target relay timeout #2");

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 414 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::MalformedToken {
            reason: "non-canonical subject",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
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
fn x3_prep_confirm_with_zero_height_fails_closed_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xzero-height".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);

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
fn x3_prep_confirm_with_zero_chain_id_fails_closed_without_state_change() {
    let mut request = SettlementRequest::new(0, "0xzero-chain".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(702, 701, 20);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 703 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::MalformedRequest {
            reason: "invalid chain_id",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_confirm_with_non_canonical_tx_hash_fails_closed_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xabc\u{200B}def".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(701, 700, 20);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 702 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_confirm_with_plane14_tagged_tx_hash_fails_closed_without_state_change() {
    let mut request = SettlementRequest::new(1, "0xabc\u{E0100}def".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(702, 701, 20);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 703 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::MalformedRequest {
            reason: "non-canonical tx_hash",
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
    assert_eq!(reason.chars().count(), 180);
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_confirm_failure_blank_reason_falls_back_to_stable_contract_message() {
    let mut request = SettlementRequest::new(1, "0xblankreason".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(601, 600, 22);

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
                heartbeat_source_height: Some(601),
                heartbeat_target_height: Some(600),
                heartbeat_latency_ms: Some(22),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: unknown confirm failure".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: unknown confirm failure".to_string())
    );
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
fn x3_prep_confirm_failure_blank_reason_preserves_heartbeat_metrics() {
    let mut request = SettlementRequest::new(1, "0xconfirm-blank-metrics".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(701, 699, 21);

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
                heartbeat_source_height: Some(701),
                heartbeat_target_height: Some(699),
                heartbeat_latency_ms: Some(21),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: unknown confirm failure".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: unknown confirm failure".to_string())
    );
}

#[test]
fn x3_prep_confirm_failure_reason_exact_cap_has_no_ellipsis_and_is_replay_stable() {
    let mut request = SettlementRequest::new(1, "0xcapexact".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(700, 699, 19);
    let exact_reason = "r".repeat(160);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: exact_reason.clone(),
        },
    )
    .unwrap();

    let expected = format!("settlement confirm failed: {exact_reason}");
    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: expected.clone(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(700),
                heartbeat_target_height: Some(699),
                heartbeat_latency_ms: Some(19),
                confirm_height: None,
                confirm_reason: Some(expected.clone()),
            },
        }
    );
    assert!(!expected.ends_with('…'));
    assert_eq!(expected.chars().count(), 187);
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(expected));
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
fn x3_prep_degraded_heartbeat_reason_strips_soft_hyphen_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xhb-soft-hyphen".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{00AD} relay timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 8081 },
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
                confirm_reason: Some("heartbeat degraded: target relay timeout".to_string(),),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: target relay timeout".to_string())
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
fn x3_prep_confirm_failure_reason_strips_alm_and_zwnj_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-alm-zwnj".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(734, 733, 17);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{061C} receipt\u{200C} timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(734),
                heartbeat_target_height: Some(733),
                heartbeat_latency_ms: Some(17),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target receipt timeout".to_string())
    );
}

#[test]
fn x3_prep_confirm_failure_reason_collapses_nbsp_family_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-nbsp-family".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(735, 734, 17);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{00A0}relay\u{2007}timeout\u{202F}signal".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target relay timeout signal".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(735),
                heartbeat_target_height: Some(734),
                heartbeat_latency_ms: Some(17),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target relay timeout signal".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target relay timeout signal".to_string()
        )
    );
}

#[test]
fn x3_prep_confirm_failure_reason_collapses_ogham_space_mark_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-ogham-space".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(736, 735, 17);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{1680}relay timeout signal".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target relay timeout signal".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(736),
                heartbeat_target_height: Some(735),
                heartbeat_latency_ms: Some(17),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target relay timeout signal".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target relay timeout signal".to_string()
        )
    );
}

#[test]
fn x3_prep_confirm_failure_reason_collapses_medium_math_and_ideographic_spaces_for_replay_stability(
) {
    let mut request = SettlementRequest::new(736, "0xconfirm-unicode-wide-space".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(737, 736, 17);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{205F}relay\u{3000}timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target relay timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(737),
                heartbeat_target_height: Some(736),
                heartbeat_latency_ms: Some(17),
                confirm_height: None,
                confirm_reason: Some("settlement confirm failed: target relay timeout".to_string(),),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target relay timeout".to_string())
    );
}

#[test]
fn x3_prep_confirm_failure_reason_strips_mvs_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-mvs".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(738, 737, 17);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{180E}receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(738),
                heartbeat_target_height: Some(737),
                heartbeat_latency_ms: Some(17),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target receipt timeout".to_string())
    );
}

#[test]
fn x3_prep_confirm_failure_reason_collapses_general_punctuation_spaces_for_replay_stability() {
    let mut request = SettlementRequest::new(
        1,
        "0xconfirm-sanitize-general-punctuation-space".to_string(),
    );
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(736, 735, 17);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{2000}relay\u{2001}timeout\u{2002}signal".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target relay timeout signal".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(736),
                heartbeat_target_height: Some(735),
                heartbeat_latency_ms: Some(17),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target relay timeout signal".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target relay timeout signal".to_string()
        )
    );
}

#[test]
fn x3_prep_degraded_blank_reason_takes_precedence_over_confirm_failure_reason() {
    let mut request = SettlementRequest::new(1, "0xhbblank-precedence".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("\u{200B}\n\t\u{202E}");

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
fn x3_confirm_without_embedded_heartbeat_metrics_fails_closed() {
    let mut request = SettlementRequest::new(1, "0xmanual-sparse-overlay".to_string());
    let token = operator_token();

    let heartbeat = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: false,
        message: "healthy overlay".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 9999 },
    )
    .expect_err("confirm without heartbeat evidence must fail closed");

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 9999 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
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
    assert_eq!(reason.chars().count(), 180);
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
fn x3_prep_manual_degraded_heartbeat_invalid_embedded_metrics_fail_closed_without_state_drift() {
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

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 813 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 807 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_manual_degraded_heartbeat_target_ahead_embedded_metrics_fail_closed_without_state_drift()
{
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

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 813 },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 808 }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_manual_degraded_heartbeat_saturated_source_surfaces_max_invalid_height_without_state_drift(
) {
    let mut request = SettlementRequest::new(1, "0xmanual-hbmetrics-saturated-source".to_string());
    let token = operator_token();

    let degraded = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: u64::MAX,
            target_height: 0,
            latency_ms: 91,
        }),
        should_retry: false,
        degraded: true,
        message: "target relay timeout".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: u64::MAX },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: u64::MAX }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x3_prep_confirm_failure_reason_sanitizes_invisible_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(733, 732, 18);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{200B}\nreceipt\t\u{202E}timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(733),
                heartbeat_target_height: Some(732),
                heartbeat_latency_ms: Some(18),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target receipt timeout".to_string())
    );
}

#[test]
fn x3_prep_degraded_heartbeat_reason_sanitizes_invisible_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-sanitize".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{200B}\nrelay\t\u{202E}timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 734 },
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
fn x3_prep_confirm_failure_reason_collapses_crlf_and_unicode_separators_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-crlf".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(734, 733, 18);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\r\nrelay\u{2028}timeout\u{2029}signal".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target relay timeout signal".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(734),
                heartbeat_target_height: Some(733),
                heartbeat_latency_ms: Some(18),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target relay timeout signal".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target relay timeout signal".to_string()
        )
    );
}

#[test]
fn x3_prep_confirm_failure_reason_sanitizes_bom_and_word_joiner_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-bom".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(735, 734, 18);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{FEFF}receipt\u{2060}timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(735),
                heartbeat_target_height: Some(734),
                heartbeat_latency_ms: Some(18),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target receipt timeout".to_string())
    );
}

#[test]
fn x3_prep_confirm_failure_reason_sanitizes_braille_blank_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-braille-blank".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(735, 734, 18);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{2800}receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(735),
                heartbeat_target_height: Some(734),
                heartbeat_latency_ms: Some(18),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target receipt timeout".to_string())
    );
}

#[test]
fn x3_prep_confirm_failure_reason_strips_u2065_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-u2065".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(735, 734, 18);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{2065}receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(735),
                heartbeat_target_height: Some(734),
                heartbeat_latency_ms: Some(18),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target receipt timeout".to_string())
    );
}

#[test]
fn x3_prep_confirm_failure_reason_strips_inhibit_symmetric_swapping_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-iss".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(735, 734, 18);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{2065} receipt timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(735),
                heartbeat_target_height: Some(734),
                heartbeat_latency_ms: Some(18),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target receipt timeout".to_string())
    );
}

#[test]
fn x3_prep_degraded_heartbeat_reason_sanitizes_bom_and_word_joiner_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-sanitize-bom".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{FEFF}relay\u{2060}timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 736 },
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
fn x3_prep_degraded_heartbeat_reason_strips_directional_marks_and_cgj_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-sanitize-dir-cgj".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{200E}\u{034F}relay\u{200F}timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 736 },
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
fn x3_prep_degraded_heartbeat_reason_strips_inhibit_symmetric_swapping_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-sanitize-iss".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{2065} relay timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 736 },
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
fn x3_prep_confirm_failure_reason_strips_interlinear_annotation_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-interlinear".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(736, 735, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{FFF9}receipt\u{FFFA}timeout\u{FFFB}signal".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout signal".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(736),
                heartbeat_target_height: Some(735),
                heartbeat_latency_ms: Some(19),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target receipt timeout signal".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target receipt timeout signal".to_string()
        )
    );
}

#[test]
fn x3_prep_confirm_failure_reason_unicode_over_cap_truncates_once_with_terminal_ellipsis() {
    let mut request = SettlementRequest::new(1, "0xconfirm-unicode-cap".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(736, 735, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: format!("target chain confirmation timeout{}", "x".repeat(200)),
        },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert!(reason.starts_with("settlement confirm failed: target chain confirmation timeout"));
    assert!(reason.ends_with('…'));
    assert_eq!(reason.matches('…').count(), 1);
    assert!(reason.chars().count() <= 188);

    assert_eq!(event.phase, "settlement_confirm_failed");
    assert_eq!(event.heartbeat_source_height, Some(736));
    assert_eq!(event.heartbeat_target_height, Some(735));
    assert_eq!(event.heartbeat_latency_ms, Some(19));
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason.as_deref(), Some(reason.as_str()));

    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_confirm_failure_reason_strips_variation_selectors_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-vs".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(736, 735, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{FE0E} receipt\u{FE0F} timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(736),
                heartbeat_target_height: Some(735),
                heartbeat_latency_ms: Some(19),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target receipt timeout".to_string())
    );
}

#[test]
fn x3_prep_degraded_heartbeat_reason_strips_variation_selectors_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-sanitize-vs".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure("target\u{FE0E} relay\u{FE0F} timeout");

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 737 },
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
fn x3_prep_confirm_failure_reason_strips_plane14_tags_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-plane14".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(737, 736, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{E0100} receipt\u{E0101} timeout".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(737),
                heartbeat_target_height: Some(736),
                heartbeat_latency_ms: Some(19),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target receipt timeout".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: target receipt timeout".to_string())
    );
}

#[test]
fn x3_prep_degraded_heartbeat_reason_unicode_over_cap_truncates_once_with_terminal_ellipsis() {
    let mut request = SettlementRequest::new(1, "0xheartbeat-unicode-cap".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let _ = monitor.record_failure("first failure");
    let degraded = monitor.record_failure(&format!("target relay timeout{}", "x".repeat(200)));

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 737 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert!(reason.starts_with("heartbeat degraded: target relay timeout"));
    assert!(reason.ends_with('…'));
    assert_eq!(reason.matches('…').count(), 1);
    assert!(reason.chars().count() <= 181);

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.heartbeat_source_height, None);
    assert_eq!(event.heartbeat_target_height, None);
    assert_eq!(event.heartbeat_latency_ms, None);
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason.as_deref(), Some(reason.as_str()));

    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_retry_pending_heartbeat_does_not_override_confirm_failure_terminal_compensation() {
    let mut request = SettlementRequest::new(1, "0xretry-pending-confirm-failure".to_string());
    let token = operator_token();

    let retry_pending = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
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
    .expect("terminal confirm failure should compensate even if heartbeat is retry-pending");

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
fn x3_prep_failed_confirm_reason_sanitizes_unicode_controls_and_preserves_heartbeat_metrics() {
    let mut request = SettlementRequest::new(1, "0xfailed-confirm-sanitized-reason".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(310, 309, 25);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{2060} confirm\u{2028}timeout\u{FFF9} signal".to_string(),
        },
    )
    .expect("confirm failure reason should sanitize before recording audit evidence");

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target confirm timeout signal".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(310),
                heartbeat_target_height: Some(309),
                heartbeat_latency_ms: Some(25),
                confirm_height: None,
                confirm_reason: Some(
                    "settlement confirm failed: target confirm timeout signal".to_string(),
                ),
            },
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted(
            "settlement confirm failed: target confirm timeout signal".to_string()
        )
    );
}
