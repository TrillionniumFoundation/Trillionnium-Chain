use super::*;

#[test]
fn parse_event_log_kv_preserves_quoted_values_with_spaces() {
    let line = "[event] event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority tx_id=9 block_height=12 state_root=abc ts_unix_ms=1000 resolution_code=\"timeout reached\" bond_disposition='forfeit all'";
    let kv = parse_event_log_kv(line);

    assert_eq!(kv.get("event_type").map(String::as_str), Some("resolve"));
    assert_eq!(
        kv.get("resolution_code").map(String::as_str),
        Some("timeout reached")
    );
    assert_eq!(
        kv.get("bond_disposition").map(String::as_str),
        Some("forfeit all")
    );
}

#[test]
fn parse_event_log_kv_supports_prefixed_runtime_noise() {
    let line = "2026-03-03T20:10:11Z INFO node [event] event_type=commit task_id=7 from_status=Accepted to_status=Committed actor=did:trnm:worker tx_id=9 block_height=12 state_root=abc ts_unix_ms=1000";
    let event_line = &line[line.find("[event]").expect("event marker")..];
    let kv = parse_event_log_kv(event_line);
    assert_eq!(kv.get("event_type").map(String::as_str), Some("commit"));
    assert_eq!(kv.get("task_id").map(String::as_str), Some("7"));
}
