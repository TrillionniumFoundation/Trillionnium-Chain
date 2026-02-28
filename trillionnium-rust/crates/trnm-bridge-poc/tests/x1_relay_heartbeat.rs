use trnm_bridge_poc::relay_heartbeat::{RelayHeartbeatConfig, RelayHeartbeatMonitor};

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

#[test]
fn relay_heartbeat_retries_then_degrades() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));

    let first = hb.record_failure("rpc timeout");
    assert!(first.should_retry);
    assert!(!first.degraded);

    let second = hb.record_failure("rpc timeout");
    assert!(!second.should_retry);
    assert!(second.degraded);

    let recovered = hb.record_success(200, 198, 8);
    assert!(!recovered.degraded);
}
