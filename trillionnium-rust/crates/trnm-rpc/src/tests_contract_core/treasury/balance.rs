use super::*;

#[test]
fn summarize_challenge_treasury_tracks_balances_and_forfeits() {
    let events = vec![
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 1001,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "challenger-a".into(),
            tx_id: 1,
            block_height: 10,
            state_root: "s1".into(),
            ts_unix_ms: 100,
            signer: Some("challenger-a".into()),
            challenger: Some("challenger-a".into()),
            tx_hash: Some("0x01".into()),
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-10),
            bond_disposition: Some("posted".into()),
            metering: None,
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 1001,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "validator".into(),
            tx_id: 2,
            block_height: 11,
            state_root: "s2".into(),
            ts_unix_ms: 120,
            signer: Some("validator".into()),
            challenger: Some("challenger-a".into()),
            tx_hash: Some("0x02".into()),
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("forfeited".into()),
            metering: None,
        },
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 1002,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "challenger-b".into(),
            tx_id: 3,
            block_height: 12,
            state_root: "s3".into(),
            ts_unix_ms: 140,
            signer: Some("challenger-b".into()),
            challenger: Some("challenger-b".into()),
            tx_hash: Some("0x03".into()),
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-7),
            bond_disposition: Some("posted".into()),
            metering: None,
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 1002,
            from_status: "Challenged".into(),
            to_status: "Slashed".into(),
            actor: "validator".into(),
            tx_id: 4,
            block_height: 13,
            state_root: "s4".into(),
            ts_unix_ms: 160,
            signer: Some("validator".into()),
            challenger: Some("challenger-b".into()),
            tx_hash: Some("0x04".into()),
            resolution_code: Some("slashed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(7),
            bond_disposition: Some("refunded".into()),
            metering: None,
        },
    ];

    let out =
        summarize_challenge_treasury(&events, 10, None, NodeEventScanMode::Authoritative, false);
    assert_eq!(out.current_escrow_balance, 0);
    assert_eq!(out.current_forfeits_balance, 10);
    assert_eq!(out.cumulative_forfeited, 10);
    assert_eq!(out.events_total, 4);
    assert_eq!(out.events.len(), 4);
    assert_eq!(out.events[1].forfeits_delta, 10);
    assert_eq!(out.events[3].forfeits_delta, 0);
}

#[test]
fn summarize_challenge_treasury_timeout_refund_is_non_forfeit() {
    let events = vec![
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 2001,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "challenger-a".into(),
            tx_id: 1,
            block_height: 10,
            state_root: "s1".into(),
            ts_unix_ms: 100,
            signer: Some("challenger-a".into()),
            challenger: Some("challenger-a".into()),
            tx_hash: Some("0x01".into()),
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-10),
            bond_disposition: Some("posted".into()),
            metering: None,
        },
        NodeEventRecord {
            event_type: "timeout".into(),
            task_id: 2001,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "system".into(),
            tx_id: 2,
            block_height: 11,
            state_root: "s2".into(),
            ts_unix_ms: 120,
            signer: Some("system".into()),
            challenger: Some("challenger-a".into()),
            tx_hash: Some("0x02".into()),
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(10),
            bond_disposition: Some("refunded".into()),
            metering: None,
        },
    ];

    let out = summarize_challenge_treasury(
        &events,
        10,
        Some((50, 200, "custom".into())),
        NodeEventScanMode::Authoritative,
        false,
    );
    assert_eq!(out.current_escrow_balance, 0);
    assert_eq!(out.current_forfeits_balance, 0);
    assert_eq!(out.cumulative_forfeited, 0);
    assert_eq!(out.events_total, 2);
    assert_eq!(out.events[1].forfeits_delta, 0);
    let summary = out.daily_summary.expect("summary expected");
    assert_eq!(summary.posted, 1);
    assert_eq!(summary.refunded, 1);
    assert_eq!(summary.forfeited, 0);
    assert_eq!(summary.unresolved, 0);
}

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
            metering: None,
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
            metering: None,
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
