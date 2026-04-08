use super::*;

#[test]
fn relay_heartbeat_smoke_reports_heights_and_latency() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(3, 2));
    assert_eq!(hb.interval_secs(), 3);

    let out = hb.record_success(101, 95, 42);
    assert!(!out.degraded);
    assert!(!out.should_retry);
    let beat = out.heartbeat.expect("heartbeat present");
    assert_eq!(beat.source_height, 101);
    assert_eq!(beat.target_height, 95);
    assert_eq!(beat.latency_ms, 42);
}
