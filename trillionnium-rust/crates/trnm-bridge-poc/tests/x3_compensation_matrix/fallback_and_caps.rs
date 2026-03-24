use super::support::*;

#[test]
fn x3_prep_stale_pending_degraded_reason_is_sanitized_and_capped_for_replay() {
    let mut request = SettlementRequest::new(1, "0xmatrix-sanitize-cap".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: format!("target\u{200B}\nrelay\t\u{202E}timeout{}", "x".repeat(400)),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 4242 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert!(reason.starts_with("heartbeat degraded: target relay timeout"));
    assert!(reason.ends_with('…'));
    assert!(!reason.contains('\n'));
    assert!(!reason.contains('\t'));
    assert!(!reason.contains('\u{200B}'));
    assert!(!reason.contains('\u{202E}'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_at_cap_does_not_append_ellipsis() {
    let mut request = SettlementRequest::new(2, "0xmatrix-cap-boundary".to_string());
    let token = operator_token();

    let exact = "a".repeat(160);
    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: exact.clone(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 4243 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    let expected = format!("heartbeat degraded: {exact}");
    assert_eq!(reason, expected);
    assert!(!reason.ends_with('…'));

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_reason_above_cap_appends_single_ellipsis() {
    let mut request = SettlementRequest::new(4, "0xmatrix-cap-overflow".to_string());
    let token = operator_token();

    let over = "b".repeat(161);
    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: over,
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 4245 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    let suffix = reason
        .strip_prefix("heartbeat degraded: ")
        .expect("reason prefix");
    assert_eq!(suffix.chars().count(), 161);
    assert!(suffix.ends_with('…'));
    assert_eq!(suffix.matches('…').count(), 1);

    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}

#[test]
fn x3_prep_stale_pending_degraded_empty_reason_uses_stable_fallback() {
    let mut request = SettlementRequest::new(3, "0xmatrix-empty-fallback".to_string());
    let token = operator_token();

    let degraded = HeartbeatOutcome {
        heartbeat: None,
        should_retry: false,
        degraded: true,
        message: "\u{200B}\u{202E}\n\t\u{2066}".to_string(),
    };

    let out = drive_minimal_settlement(
        &mut request,
        &token,
        &degraded,
        SettlementConfirm::Confirmed { height: 4244 },
    )
    .unwrap();

    let SettlementStep::Compensated { reason, event } = out else {
        panic!("expected compensated branch");
    };

    assert_eq!(reason, "heartbeat degraded: unknown heartbeat failure");
    assert_eq!(event.phase, "relay_heartbeat_degraded");
    assert_eq!(event.confirm_height, None);
    assert_eq!(event.confirm_reason, Some(reason.clone()));
    assert_eq!(current_status(&request), &BridgeStatus::Reverted(reason));
}
