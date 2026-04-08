use super::support::*;

#[test]
fn x3_prep_stale_pending_degraded_reason_collapses_crlf_and_unicode_separators_for_replay_stability(
) {
    let mut request = SettlementRequest::new(9, "0xmatrix-sanitize-crlf-separators".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "target\r\nrelay\u{2028}timeout\u{2029}signal\n".to_string(),
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

    assert_eq!(reason, "heartbeat degraded: target relay timeout signal");
    assert!(!reason.contains('\n'));
    assert!(!reason.contains('\r'));
    assert!(!reason.contains('\u{2028}'));
    assert!(!reason.contains('\u{2029}'));

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
fn x3_prep_stale_pending_degraded_reason_strips_legacy_bidi_isolates_for_replay_stability() {
    let mut request =
        SettlementRequest::new(18, "0xmatrix-sanitize-legacy-bidi-isolates".to_string());
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
