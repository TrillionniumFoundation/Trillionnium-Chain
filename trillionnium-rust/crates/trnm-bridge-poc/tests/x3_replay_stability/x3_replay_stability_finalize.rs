use super::*;

#[test]
fn x3_prep_duplicate_or_reordered_degraded_after_finalize_is_rejected_without_state_drift() {
    let mut request = SettlementRequest::new(13, "0xreplay-after-finalize".to_string());
    let token = operator_token();

    let healthy = HeartbeatOutcome {
        heartbeat: None,
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
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
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
        heartbeat: None,
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
                heartbeat_source_height: None,
                heartbeat_target_height: None,
                heartbeat_latency_ms: None,
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

#[test]
fn x3_prep_accepts_confirm_height_at_u64_max_source_finality_boundary() {
    let mut request = SettlementRequest::new(15, "0xconfirm-u64-max-boundary".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: u64::MAX,
            target_height: u64::MAX - 1,
            latency_ms: 19,
        }),
        should_retry: false,
        degraded: false,
        message: "heartbeat ok".to_string(),
    };

    let finalized = drive_minimal_settlement(
        &mut request,
        &token,
        &heartbeat,
        SettlementConfirm::Confirmed { height: u64::MAX },
    )
    .unwrap();

    assert_eq!(
        finalized,
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
fn x3_prep_rejects_confirm_height_below_u64_max_target_boundary() {
    let mut request = SettlementRequest::new(16, "0xconfirm-u64-max-lower-boundary".to_string());
    let token = operator_token();

    let heartbeat = HeartbeatOutcome {
        heartbeat: Some(trnm_bridge_poc::relay_heartbeat::RelayHeartbeat {
            source_height: u64::MAX,
            target_height: u64::MAX - 1,
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
        SettlementConfirm::Confirmed {
            height: u64::MAX - 2,
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        trnm_bridge_poc::bridge_status::SettlementError::InvalidHeight {
            height: u64::MAX - 2,
        }
    );
    assert_eq!(current_status(&request), &BridgeStatus::Pending);
}
