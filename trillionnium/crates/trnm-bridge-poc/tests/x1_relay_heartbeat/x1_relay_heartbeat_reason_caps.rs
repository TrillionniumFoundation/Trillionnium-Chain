use super::*;

#[test]
fn relay_heartbeat_failure_reason_is_capped_for_log_safety() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));
    let long_reason = "x".repeat(220);

    let out = hb.record_failure(&long_reason);
    assert_eq!(out.message.chars().count(), 161);
    assert!(out.message.ends_with('…'));
}

#[test]
fn relay_heartbeat_failure_reason_at_limit_does_not_append_ellipsis() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));
    let exact_limit_reason = "x".repeat(160);

    let out = hb.record_failure(&exact_limit_reason);
    assert_eq!(out.message.chars().count(), 160);
    assert!(!out.message.ends_with('…'));
    assert_eq!(out.message, exact_limit_reason);
}

#[test]
fn relay_heartbeat_failure_reason_collapses_braille_blank_for_log_consensus() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));

    let out = hb.record_failure("target\u{2800}relay timeout");
    assert_eq!(out.message, "target relay timeout");
}
