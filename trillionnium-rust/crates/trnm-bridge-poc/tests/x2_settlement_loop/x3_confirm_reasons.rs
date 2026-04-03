use super::*;

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
fn x3_prep_confirm_failure_reason_strips_plane14_tag_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-plane14-tags".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(735, 734, 18);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{E0001}receipt\u{E0020}timeout\u{E007F}signal".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout signal".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(735),
                heartbeat_target_height: Some(734),
                heartbeat_latency_ms: Some(18),
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
fn x3_prep_confirm_failure_reason_strips_hangul_fillers_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-hangul-fillers".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(736, 735, 18);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{115F}receipt\u{1160}timeout\u{3164}signal".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout signal".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(735),
                heartbeat_target_height: Some(734),
                heartbeat_latency_ms: Some(18),
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
fn x3_prep_confirm_failure_reason_strips_zwj_and_mongolian_fvs_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-zwj-mongolian-fvs".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(737, 736, 18);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{200D}receipt\u{180F}timeout".to_string(),
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
    let heartbeat = monitor.record_success(735, 734, 18);

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
                heartbeat_source_height: Some(735),
                heartbeat_target_height: Some(734),
                heartbeat_latency_ms: Some(18),
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
fn x3_prep_confirm_failure_reason_collapses_braille_blank_for_replay_stability() {
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
            reason: format!("目标链确认超时{}", "测".repeat(200)),
        },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert!(reason.starts_with("settlement confirm failed: 目标链确认超时"));
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
fn x3_prep_confirm_failure_reason_strips_plane1_musical_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-plane1-musical".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(737, 736, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{1D173}receipt\u{1D174}timeout\u{1D17A}signal".to_string(),
        },
    )
    .unwrap();

    assert_eq!(
        out,
        SettlementStep::Compensated {
            reason: "settlement confirm failed: target receipt timeout signal".to_string(),
            event: trnm_bridge_poc::x2_settlement_loop::SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: Some(737),
                heartbeat_target_height: Some(736),
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
fn x3_prep_confirm_failure_reason_collapses_braille_blank_near_target_boundary_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-braille".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(742, 741, 21);

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
                heartbeat_source_height: Some(742),
                heartbeat_target_height: Some(741),
                heartbeat_latency_ms: Some(21),
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
