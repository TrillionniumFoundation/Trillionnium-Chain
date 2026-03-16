use super::*;

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
