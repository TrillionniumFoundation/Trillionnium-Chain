use super::super::support::*;

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
            reason: "target\u{FE00} receipt\u{FE0E}\u{FE0F} timeout".to_string(),
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
fn x3_prep_confirm_failure_reason_strips_unicode_tag_controls_for_replay_stability() {
    let mut request = SettlementRequest::new(1, "0xconfirm-sanitize-tag-controls".to_string());
    let token = operator_token();

    let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));
    let heartbeat = monitor.record_success(738, 737, 19);

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Failed {
            reason: "target\u{E0001} receipt\u{E0020} timeout\u{E007F}".to_string(),
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
