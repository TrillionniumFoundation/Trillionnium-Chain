use super::support::*;

#[test]
fn x3_prep_stale_pending_degraded_reason_strips_invisible_math_operators_for_replay_stability() {
    let mut request = SettlementRequest::new(16, "0xmatrix-sanitize-invisible-math".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{2061} relay\u{2062} timeout\u{2063} signal\u{2064}".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6269 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout signal");
    assert!(!reason.contains('\u{2061}'));
    assert!(!reason.contains('\u{2062}'));
    assert!(!reason.contains('\u{2063}'));
    assert!(!reason.contains('\u{2064}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_collapses_non_breaking_spaces_for_replay_stability() {
    let mut request = SettlementRequest::new(17, "0xmatrix-sanitize-nbsp".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{00A0}relay\u{00A0}timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6270 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout");
    assert!(!reason.contains('\u{00A0}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_strips_variation_selectors_for_replay_stability() {
    let mut request =
        SettlementRequest::new(20, "0xmatrix-sanitize-variation-selectors".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{FE0E} relay\u{FE0F} timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6273 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout");
    assert!(!reason.contains('\u{FE0E}'));
    assert!(!reason.contains('\u{FE0F}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_strips_plane14_tags_for_replay_stability() {
    let mut request = SettlementRequest::new(21, "0xmatrix-sanitize-plane14-tags".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{E0100} relay\u{E0101} timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6274 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout");
    assert!(!reason.contains('\u{E0100}'));
    assert!(!reason.contains('\u{E0101}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_collapses_figure_and_narrow_nbsp_for_replay_stability() {
    let mut request = SettlementRequest::new(22, "0xmatrix-sanitize-figure-nnbsp".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{2007}relay\u{202F}timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6274 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout");
    assert!(!reason.contains('\u{2007}'));
    assert!(!reason.contains('\u{202F}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_collapses_thin_space_family_for_replay_stability() {
    let mut request = SettlementRequest::new(22, "0xmatrix-sanitize-thin-space-family".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{2008}relay\u{2009}timeout\u{200A}signal".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6275 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout signal");
    assert!(!reason.contains('\u{2008}'));
    assert!(!reason.contains('\u{2009}'));
    assert!(!reason.contains('\u{200A}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}
