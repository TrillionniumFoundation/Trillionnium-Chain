use super::*;

#[test]
fn summarize_challenge_treasury_limit_keeps_recent() {
    let events = vec![
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 1,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c1".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "a".into(),
            ts_unix_ms: 1,
            signer: None,
            challenger: Some("c1".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-3),
            bond_disposition: Some("posted".into()),
        },
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 2,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c2".into(),
            tx_id: 2,
            block_height: 2,
            state_root: "b".into(),
            ts_unix_ms: 2,
            signer: None,
            challenger: Some("c2".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-4),
            bond_disposition: Some("posted".into()),
        },
    ];

    let out =
        summarize_challenge_treasury(&events, 1, None, NodeEventScanMode::Authoritative, false);
    assert_eq!(out.events_total, 2);
    assert_eq!(out.events.len(), 1);
    assert_eq!(out.events[0].task_id, 2);
    assert_eq!(out.current_escrow_balance, 7);
    assert!(out.daily_summary.is_none());
    assert!(out.window.is_none());
}
