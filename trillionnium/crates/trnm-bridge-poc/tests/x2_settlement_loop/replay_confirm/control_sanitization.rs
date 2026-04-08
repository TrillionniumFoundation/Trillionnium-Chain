use super::super::support::*;

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
