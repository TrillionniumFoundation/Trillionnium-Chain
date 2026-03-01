use trnm_bridge_poc::bridge_status::{
    BridgeStatus, CapabilityToken, SettlementCapability, SettlementRequest,
};
use trnm_bridge_poc::relay_heartbeat::{RelayHeartbeatConfig, RelayHeartbeatMonitor};
use trnm_bridge_poc::x2_settlement_loop::{
    current_status, drive_minimal_settlement, SettlementConfirm, SettlementStep,
};

fn operator_token() -> CapabilityToken {
    CapabilityToken {
        subject: "agent:settlement-operator".to_string(),
        capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
    }
}

fn finalize_only_token() -> CapabilityToken {
    CapabilityToken {
        subject: "agent:settlement-finalizer".to_string(),
        capabilities: vec![SettlementCapability::Finalize],
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

    assert_eq!(out, SettlementStep::Finalized { height: 121 });
    assert_eq!(current_status(&request), &BridgeStatus::Finalized(121));
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
fn x2_degraded_heartbeat_short_circuits_confirm_and_reverts() {
    let mut request = SettlementRequest::new(1, "0xdeadbeef".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    monitor.record_success(300, 296, 41);
    monitor.record_failure("lag above threshold");
    let heartbeat = monitor.record_failure("lag above threshold");

    assert!(heartbeat.degraded);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 307 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: lag above threshold".to_string(),
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: lag above threshold".to_string())
    );
}

#[test]
fn x2_failure_path_confirm_reason_is_canonicalized_before_compensation() {
    let mut request = SettlementRequest::new(1, "0x0bada55".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(330, 329, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "  target\u{200B} chain\n\treceipt\u{FEFF} timeout  ".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target chain receipt timeout".to_string(),
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
fn x2_failure_path_blank_confirm_reason_falls_back_to_stable_unknown() {
    let mut request = SettlementRequest::new(1, "0x00c0ffee".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(340, 339, 17);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "   \t\n  ".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: unknown confirm failure".to_string(),
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: unknown confirm failure".to_string())
    );
}

#[test]
fn x2_degraded_heartbeat_blank_reason_falls_back_to_stable_unknown() {
    let mut request = SettlementRequest::new(2, "0x0ddcafe".to_string());
    let token = operator_token();

    let heartbeat = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "   \n\t ".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 401 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: unknown heartbeat degradation".to_string(),
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: unknown heartbeat degradation".to_string())
    );
}

#[test]
fn x2_degraded_heartbeat_control_only_reason_falls_back_to_stable_unknown() {
    let mut request = SettlementRequest::new(2, "0x0ddcafe0".to_string());
    let token = operator_token();

    let heartbeat = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "\u{2060}\u{202E}\u{202C}\u{2069}".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 401 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: unknown heartbeat degradation".to_string(),
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: unknown heartbeat degradation".to_string())
    );
}

#[test]
fn x2_failure_path_bidi_controls_are_sanitized_before_compensation() {
    let mut request = SettlementRequest::new(2, "0x0ddcafee".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(355, 354, 15);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "settlement\u{2060} \u{202E}confirm\u{202C}   \u{2067}failed\u{2069}"
                .to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: settlement confirm failed".to_string(),
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: settlement confirm failed".to_string())
    );
}

#[test]
fn x2_failure_path_control_only_confirm_reason_falls_back_to_stable_unknown() {
    let mut request = SettlementRequest::new(2, "0x0ddcafef".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(360, 359, 14);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "\u{200B}\u{200D}\u{FEFF}\u{0007}".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: unknown confirm failure".to_string(),
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("settlement confirm failed: unknown confirm failure".to_string())
    );
}

#[test]
fn x2_degraded_heartbeat_control_chars_are_sanitized_before_compensation() {
    let mut request = SettlementRequest::new(2, "0x0ddcafe1".to_string());
    let token = operator_token();

    let heartbeat = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "\u{200B}relay\u{200D}\n\tquorum\u{FEFF} lost\u{0007}".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 402 },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "heartbeat degraded: relay quorum lost".to_string(),
        }
    );
    assert_eq!(
        current_status(&request),
        &BridgeStatus::Reverted("heartbeat degraded: relay quorum lost".to_string())
    );
}

#[test]
fn x2_degraded_heartbeat_requires_revert_capability_and_preserves_pending_on_reject() {
    let mut request = SettlementRequest::new(9, "0xdecafbad".to_string());
    let token = finalize_only_token();

    let heartbeat = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "relay quorum lost".to_string(),
    };

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 812 },
    )
    .expect_err("degraded compensation must require revert capability");

    assert!(err.is_unauthorized());
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x2_confirm_with_zero_height_rejected_and_preserves_pending() {
    let mut request = SettlementRequest::new(10, "0xabcddcba".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(500, 499, 12);

    let err = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 0 },
    )
    .expect_err("zero height must be rejected before finalization");

    assert!(matches!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight { height: 0 }
    ));
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}

#[test]
fn x2_failure_path_long_confirm_reason_is_capped_for_log_safety() {
    let mut request = SettlementRequest::new(11, "0xfacefeed".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(510, 509, 11);
    let long_reason = "r".repeat(220);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: long_reason,
        },
    )
    .unwrap();

    let compensated_reason = match out {
        SettlementStep::Compensated { reason } => reason,
        other => panic!("expected compensated step, got {other:?}"),
    };

    assert_eq!(compensated_reason.chars().count(), 188);
    assert!(compensated_reason.ends_with('…'));
    assert!(compensated_reason.starts_with("settlement confirm failed: "));
}

#[test]
fn x2_failure_path_reason_at_limit_is_not_ellipsized() {
    let mut request = SettlementRequest::new(13, "0xfeedf00d".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(520, 519, 10);
    let exact_limit_reason = "r".repeat(160);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: exact_limit_reason,
        },
    )
    .unwrap();

    let compensated_reason = match out {
        SettlementStep::Compensated { reason } => reason,
        other => panic!("expected compensated step, got {other:?}"),
    };

    assert_eq!(compensated_reason.chars().count(), 187);
    assert!(!compensated_reason.ends_with('…'));
    assert!(compensated_reason.starts_with("settlement confirm failed: "));
}

#[test]
fn x2_degraded_heartbeat_reason_at_limit_is_not_ellipsized() {
    let mut request = SettlementRequest::new(12, "0xfacebead".to_string());
    let token = operator_token();

    let exact_limit_reason = "h".repeat(160);
    let heartbeat = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: exact_limit_reason,
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 600 },
    )
    .unwrap();

    let compensated_reason = match out {
        SettlementStep::Compensated { reason } => reason,
        other => panic!("expected compensated step, got {other:?}"),
    };

    assert_eq!(compensated_reason.chars().count(), 180);
    assert!(!compensated_reason.ends_with('…'));
    assert!(compensated_reason.starts_with("heartbeat degraded: "));
}

#[test]
fn x2_degraded_heartbeat_long_reason_is_capped_for_log_safety() {
    let mut request = SettlementRequest::new(12, "0xfacebead".to_string());
    let token = operator_token();

    let long_reason = "h".repeat(220);
    let heartbeat = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: long_reason,
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 601 },
    )
    .unwrap();

    let compensated_reason = match out {
        SettlementStep::Compensated { reason } => reason,
        other => panic!("expected compensated step, got {other:?}"),
    };

    assert_eq!(compensated_reason.chars().count(), 181);
    assert!(compensated_reason.ends_with('…'));
    assert!(compensated_reason.starts_with("heartbeat degraded: "));
}

#[test]
fn x2_failure_path_reason_just_above_limit_is_ellipsized_once() {
    let mut request = SettlementRequest::new(14, "0xfeedabba".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(530, 529, 9);
    let above_limit_reason = "r".repeat(161);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: above_limit_reason,
        },
    )
    .unwrap();

    let compensated_reason = match out {
        SettlementStep::Compensated { reason } => reason,
        other => panic!("expected compensated step, got {other:?}"),
    };

    assert_eq!(compensated_reason.chars().count(), 188);
    assert!(compensated_reason.ends_with('…'));
    assert!(compensated_reason.starts_with("settlement confirm failed: "));
}

#[test]
fn x2_degraded_heartbeat_reason_just_above_limit_is_ellipsized_once() {
    let mut request = SettlementRequest::new(15, "0xfaceabba".to_string());
    let token = operator_token();

    let above_limit_reason = "h".repeat(161);
    let heartbeat = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: above_limit_reason,
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 602 },
    )
    .unwrap();

    let compensated_reason = match out {
        SettlementStep::Compensated { reason } => reason,
        other => panic!("expected compensated step, got {other:?}"),
    };

    assert_eq!(compensated_reason.chars().count(), 181);
    assert!(compensated_reason.ends_with('…'));
    assert!(compensated_reason.starts_with("heartbeat degraded: "));
}

#[test]
fn x2_degraded_heartbeat_reason_sanitizes_arabic_letter_mark_control() {
    let mut request = SettlementRequest::new(16, "0xfeedbead".to_string());
    let token = operator_token();

    let heartbeat = trnm_bridge_poc::relay_heartbeat::HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "relay\u{061C}quorum\u{061C}lost".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: 603 },
    )
    .unwrap();

    let compensated_reason = match out {
        SettlementStep::Compensated { reason } => reason,
        other => panic!("expected compensated step, got {other:?}"),
    };

    assert_eq!(compensated_reason, "heartbeat degraded: relay quorum lost");
    assert!(!compensated_reason.contains('\u{061C}'));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(compensated_reason));
}
