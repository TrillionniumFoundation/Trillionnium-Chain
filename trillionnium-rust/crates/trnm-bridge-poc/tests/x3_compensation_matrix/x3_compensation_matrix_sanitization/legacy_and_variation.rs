use super::super::support::*;

#[test]
fn x3_prep_stale_pending_degraded_reason_strips_legacy_bidi_isolates_for_replay_stability() {
    let mut request = SettlementRequest::new(18, "0xmatrix-sanitize-legacy-bidi-isolates".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{206A} relay\u{206B} timeout\u{206C} signal\u{206D}\u{206E}\u{206F}"
            .to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6271 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout signal");
    assert!(!reason.contains('\u{206A}'));
    assert!(!reason.contains('\u{206B}'));
    assert!(!reason.contains('\u{206C}'));
    assert!(!reason.contains('\u{206D}'));
    assert!(!reason.contains('\u{206E}'));
    assert!(!reason.contains('\u{206F}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_strips_mongolian_vowel_separator_for_replay_stability() {
    let mut request = SettlementRequest::new(19, "0xmatrix-sanitize-mvs".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\u{180E} relay timeout".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 6272 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: target relay timeout");
    assert!(!reason.contains('\u{180E}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_strips_variation_selectors_for_replay_stability() {
    let mut request = SettlementRequest::new(20, "0xmatrix-sanitize-variation-selectors".to_string());
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
