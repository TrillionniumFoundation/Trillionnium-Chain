use super::super::support::*;

#[test]
fn x3_prep_stale_pending_degraded_reason_strips_directional_marks_for_replay_stability() {
    let mut request = SettlementRequest::new(8, "0xmatrix-sanitize-directional-marks".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{200E} relay\u{200F} timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6263 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout");
    assert!(!reason.contains('\u{200E}'));
    assert!(!reason.contains('\u{200F}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_strips_bidi_embeddings_for_replay_stability() {
    let mut request = SettlementRequest::new(10, "0xmatrix-sanitize-bidi-embeddings".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{202A} relay\u{202B} timeout\u{202C} signal\u{202D}".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6264 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout signal");
    assert!(!reason.contains('\u{202A}'));
    assert!(!reason.contains('\u{202B}'));
    assert!(!reason.contains('\u{202C}'));
    assert!(!reason.contains('\u{202D}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_strips_bidi_isolates_for_replay_stability() {
    let mut request = SettlementRequest::new(12, "0xmatrix-sanitize-bidi-isolates".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{2066} relay\u{2067} timeout\u{2068} signal\u{2069}".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6265 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout signal");
    assert!(!reason.contains('\u{2066}'));
    assert!(!reason.contains('\u{2067}'));
    assert!(!reason.contains('\u{2068}'));
    assert!(!reason.contains('\u{2069}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_strips_bom_and_word_joiner_for_replay_stability() {
    let mut request = SettlementRequest::new(13, "0xmatrix-sanitize-bom-word-joiner".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{FEFF} relay\u{2060} timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6266 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout");
    assert!(!reason.contains('\u{FEFF}'));
    assert!(!reason.contains('\u{2060}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}
