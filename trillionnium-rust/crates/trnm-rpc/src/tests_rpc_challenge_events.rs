use super::*;

#[test]
fn query_events_response_applies_same_trust_and_transition_filters() {
    let events = vec![
        NodeEventRecord {
            event_type: "accept".into(),
            task_id: 9,
            from_status: "Open".into(),
            to_status: "Assigned".into(),
            actor: "worker-a".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "s1".into(),
            ts_unix_ms: 1,
            signer: Some("worker-a".into()),
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
        },
        NodeEventRecord {
            event_type: "commit".into(),
            task_id: 9,
            from_status: "Open".into(),
            to_status: "Committed".into(),
            actor: "worker-a".into(),
            tx_id: 2,
            block_height: 2,
            state_root: "s2".into(),
            ts_unix_ms: 2,
            signer: Some("worker-a".into()),
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
        },
        NodeEventRecord {
            event_type: "reveal".into(),
            task_id: 9,
            from_status: "Committed".into(),
            to_status: "Revealed".into(),
            actor: "worker-a".into(),
            tx_id: 3,
            block_height: 3,
            state_root: "s3".into(),
            ts_unix_ms: 3,
            signer: Some("worker-b".into()),
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
        },
    ];

    let out = query_events_response(9, 20, &events, &[]).expect("events expected");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].event_type, "accept");
}

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
fn load_node_events_recent_tail_marks_truncation_but_authoritative_keeps_history() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");

    let old_event = "2026-03-03T20:10:11Z INFO node [event] event_type=challenge task_id=7 from_status=Revealed to_status=Challenged actor=challenger-a tx_id=1 block_height=1 state_root=s1 ts_unix_ms=1000 challenger=challenger-a challenger_delta=-5 bond_disposition=posted\n";
    let filler = "x".repeat(600);
    let new_event = "2026-03-03T20:10:12Z INFO node [event] event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 signer=authority resolution_code=completed challenger=challenger-a challenger_delta=0 bond_disposition=forfeited\n";
    fs::write(
        run.join("node1.log"),
        format!("{old_event}{filler}\n{new_event}"),
    )
    .expect("write log");

    std::env::set_var("TRNM_RPC_NODE_EVENT_LOG_TAIL_BYTES", "400");
    let recent = load_node_events_from_root(root.path(), NodeEventScanMode::RecentTail);
    std::env::remove_var("TRNM_RPC_NODE_EVENT_LOG_TAIL_BYTES");

    assert!(recent.truncated);
    assert_eq!(recent.mode, NodeEventScanMode::RecentTail);
    assert_eq!(recent.events.len(), 1);
    assert_eq!(recent.events[0].event_type, "resolve");

    let authoritative = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert!(!authoritative.truncated);
    assert_eq!(authoritative.mode, NodeEventScanMode::Authoritative);
    assert_eq!(authoritative.events.len(), 2);
    assert_eq!(authoritative.events[0].event_type, "challenge");
    assert_eq!(authoritative.events[1].event_type, "resolve");
}

#[test]
fn parse_event_log_kv_supports_prefixed_runtime_noise() {
    let line = "2026-03-03T20:10:11Z INFO node [event] event_type=commit task_id=7 from_status=Accepted to_status=Committed actor=did:trnm:worker tx_id=9 block_height=12 state_root=abc ts_unix_ms=1000";
    let event_line = &line[line.find("[event]").expect("event marker")..];
    let kv = parse_event_log_kv(event_line);
    assert_eq!(kv.get("event_type").map(String::as_str), Some("commit"));
    assert_eq!(kv.get("task_id").map(String::as_str), Some("7"));
}
