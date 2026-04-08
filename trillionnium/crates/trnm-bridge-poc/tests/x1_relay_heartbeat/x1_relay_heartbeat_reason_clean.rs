use super::*;

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
