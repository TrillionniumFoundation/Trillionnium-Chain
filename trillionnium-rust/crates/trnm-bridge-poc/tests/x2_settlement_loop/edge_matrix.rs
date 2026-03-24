use super::support::*;

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
