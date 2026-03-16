use super::*;

#[test]
fn relay_heartbeat_config_clamps_zero_to_safe_minimums() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(0, 0));
    assert_eq!(hb.interval_secs(), 1);

    let first = hb.record_failure("rpc timeout");
    assert!(!first.should_retry);
    assert!(first.degraded);

    let second = hb.record_failure("rpc timeout");
    assert!(!second.should_retry);
    assert!(second.degraded);
}

#[test]
fn relay_heartbeat_failure_counter_saturates_without_overflow() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, u8::MAX));

    for _ in 0..u16::from(u8::MAX) {
        hb.record_failure("persistent rpc timeout");
    }
    assert_eq!(hb.consecutive_failures(), u8::MAX);

    let extra = hb.record_failure("persistent rpc timeout");
    assert_eq!(hb.consecutive_failures(), u8::MAX);
    assert!(!extra.should_retry);
    assert!(extra.degraded);
}
