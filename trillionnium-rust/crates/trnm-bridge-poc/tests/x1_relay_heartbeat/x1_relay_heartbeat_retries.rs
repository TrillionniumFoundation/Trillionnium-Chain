use super::*;

#[test]
fn relay_heartbeat_retries_then_degrades() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));

    let first = hb.record_failure("rpc timeout");
    assert!(first.should_retry);
    assert!(!first.degraded);
    assert_eq!(hb.consecutive_failures(), 1);

    let second = hb.record_failure("rpc timeout");
    assert!(!second.should_retry);
    assert!(second.degraded);
    assert_eq!(hb.consecutive_failures(), 2);

    let recovered = hb.record_success(200, 198, 8);
    assert!(!recovered.degraded);
    assert_eq!(hb.consecutive_failures(), 0);
}

#[test]
fn relay_heartbeat_flap_after_recovery_restarts_retry_budget() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));

    let first = hb.record_failure("transient rpc timeout");
    assert!(first.should_retry);
    assert!(!first.degraded);

    let recovered = hb.record_success(210, 209, 6);
    assert!(!recovered.degraded);
    assert!(!recovered.should_retry);

    let next = hb.record_failure("transient rpc timeout");
    assert!(next.should_retry);
    assert!(!next.degraded);
}

#[test]
fn relay_heartbeat_degraded_failures_stay_bounded_at_retry_cap() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));

    let _ = hb.record_failure("rpc timeout #1");
    let degraded = hb.record_failure("rpc timeout #2");
    assert!(degraded.degraded);
    assert_eq!(hb.consecutive_failures(), 2);

    let repeated = hb.record_failure("rpc timeout #3");
    assert!(repeated.degraded);
    assert!(!repeated.should_retry);
    assert_eq!(hb.consecutive_failures(), 2);
}
