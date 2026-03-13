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

#[test]
fn relay_heartbeat_failure_reason_is_trimmed_and_never_blank() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 2));

    let trimmed = hb.record_failure("  rpc timeout  ");
    assert_eq!(trimmed.message, "rpc timeout");

    let blank = hb.record_failure("   \n\t");
    assert_eq!(blank.message, "unknown heartbeat failure");
}

#[test]
fn relay_heartbeat_failure_reason_collapses_internal_whitespace() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));

    let out = hb.record_failure("rpc\n timeout\t on   bridge-a");
    assert_eq!(out.message, "rpc timeout on bridge-a");
}

#[test]
fn relay_heartbeat_failure_reason_strips_control_and_zero_width_chars() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));

    let out = hb.record_failure("\u{200B}rpc\u{200D} timeout\u{FEFF}\u{0007}");
    assert_eq!(out.message, "rpc timeout");

    let control_only = hb.record_failure("\u{200B}\u{200D}\u{FEFF}\u{0007}");
    assert_eq!(control_only.message, "unknown heartbeat failure");
}

#[test]
fn relay_heartbeat_failure_reason_strips_zero_width_non_joiner() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));

    let out = hb.record_failure("rpc\u{200C} timeout");
    assert_eq!(out.message, "rpc timeout");
}

#[test]
fn relay_heartbeat_failure_reason_strips_bidi_and_word_joiner_controls() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));

    let out = hb.record_failure("rpc\u{202E} timeout\u{2060} bridge");
    assert_eq!(out.message, "rpc timeout bridge");
}

#[test]
fn relay_heartbeat_failure_reason_strips_soft_hyphen_and_mongolian_vowel_separator() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));

    let out = hb.record_failure("rpc\u{00AD}\u{180E} timeout");
    assert_eq!(out.message, "rpc timeout");
}

#[test]
fn relay_heartbeat_failure_reason_strips_invisible_math_and_legacy_bidi_controls() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));

    let out = hb.record_failure(
        "rpc\u{2061} timeout\u{2062} bridge\u{2063} degraded\u{2064} \u{206A}\u{206B}\u{206C}\u{206D}\u{206E}\u{206F}",
    );
    assert_eq!(out.message, "rpc timeout bridge degraded");
}

#[test]
fn relay_heartbeat_failure_reason_strips_variation_selectors_and_plane14_tags() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));

    let out = hb.record_failure("rpc\u{FE0E} timeout\u{FE0F} bridge\u{E0100}\u{E0101}");
    assert_eq!(out.message, "rpc timeout bridge");
}

#[test]
fn relay_heartbeat_failure_reason_collapses_unicode_line_separators() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));

    let out = hb.record_failure("rpc\u{2028} timeout\u{2029} bridge");
    assert_eq!(out.message, "rpc timeout bridge");
}

#[test]
fn relay_heartbeat_failure_reason_collapses_general_punctuation_spaces() {
    let mut hb = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(5, 3));

    let out = hb.record_failure("rpc\u{2000} timeout\u{2001} bridge\u{2002} degraded");
    assert_eq!(out.message, "rpc timeout bridge degraded");
}

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
