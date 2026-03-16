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

#[test]
fn summarize_challenge_treasury_window_daily_summary_counts() {
    let events = vec![
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 11,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c11".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "a".into(),
            ts_unix_ms: 1_000,
            signer: None,
            challenger: Some("c11".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-5),
            bond_disposition: Some("posted".into()),
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 11,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "v".into(),
            tx_id: 2,
            block_height: 2,
            state_root: "b".into(),
            ts_unix_ms: 2_000,
            signer: None,
            challenger: Some("c11".into()),
            tx_hash: None,
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("refunded".into()),
        },
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 12,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c12".into(),
            tx_id: 3,
            block_height: 3,
            state_root: "c".into(),
            ts_unix_ms: 3_000,
            signer: None,
            challenger: Some("c12".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-8),
            bond_disposition: Some("posted".into()),
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 99,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "v".into(),
            tx_id: 4,
            block_height: 4,
            state_root: "d".into(),
            ts_unix_ms: 4_000,
            signer: None,
            challenger: Some("c99".into()),
            tx_hash: None,
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("forfeited".into()),
        },
    ];

    let out = summarize_challenge_treasury(
        &events,
        10,
        Some((500, 3_500, "custom".to_string())),
        NodeEventScanMode::Authoritative,
        false,
    );

    let summary = out.daily_summary.expect("summary expected");
    assert_eq!(summary.posted, 2);
    assert_eq!(summary.refunded, 1);
    assert_eq!(summary.forfeited, 0);
    assert_eq!(summary.unresolved, 1);
    assert_eq!(out.window.expect("window expected").mode, "custom");
}

#[test]
fn summarize_challenge_treasury_ignores_invalid_challenge_delta_sign() {
    let events = vec![NodeEventRecord {
        event_type: "challenge".into(),
        task_id: 77,
        from_status: "Revealed".into(),
        to_status: "Challenged".into(),
        actor: "c77".into(),
        tx_id: 1,
        block_height: 1,
        state_root: "a".into(),
        ts_unix_ms: 1_000,
        signer: None,
        challenger: Some("c77".into()),
        tx_hash: None,
        resolution_code: None,
        treasury_delta: Some(0),
        challenger_delta: Some(10),
        bond_disposition: Some("posted".into()),
    }];

    let out = summarize_challenge_treasury(
        &events,
        10,
        Some((500, 1_500, "custom".into())),
        NodeEventScanMode::Authoritative,
        false,
    );
    assert_eq!(out.current_escrow_balance, 0);
    assert_eq!(out.current_forfeits_balance, 0);
    assert_eq!(out.cumulative_forfeited, 0);
    assert_eq!(out.events[0].bond_amount, 0);
    assert_eq!(out.events[0].escrow_delta, 0);
    let summary = out.daily_summary.expect("summary expected");
    assert_eq!(summary.posted, 0);
    assert_eq!(summary.unresolved, 0);
    assert_eq!(out.anomaly_count, 1);
    assert_eq!(out.anomalies[0].code, "invalid_challenge_delta_sign");
}

#[test]
fn summarize_challenge_treasury_does_not_count_or_move_missing_posted_bond() {
    let events = vec![NodeEventRecord {
        event_type: "resolve".into(),
        task_id: 88,
        from_status: "Challenged".into(),
        to_status: "Completed".into(),
        actor: "v".into(),
        tx_id: 2,
        block_height: 2,
        state_root: "b".into(),
        ts_unix_ms: 2_000,
        signer: None,
        challenger: Some("c88".into()),
        tx_hash: None,
        resolution_code: Some("completed".into()),
        treasury_delta: Some(0),
        challenger_delta: Some(0),
        bond_disposition: Some("forfeited".into()),
    }];

    let out = summarize_challenge_treasury(
        &events,
        10,
        Some((500, 3_000, "custom".into())),
        NodeEventScanMode::Authoritative,
        false,
    );
    assert_eq!(out.current_escrow_balance, 0);
    assert_eq!(out.current_forfeits_balance, 0);
    assert_eq!(out.cumulative_forfeited, 0);
    assert_eq!(out.events[0].bond_amount, 0);
    assert_eq!(out.events[0].escrow_delta, 0);
    assert_eq!(out.events[0].forfeits_delta, 0);
    let summary = out.daily_summary.expect("summary expected");
    assert_eq!(summary.forfeited, 0);
    assert_eq!(summary.refunded, 0);
    assert_eq!(out.anomaly_count, 1);
    assert_eq!(out.anomalies[0].code, "resolve_without_posted_bond");
}

#[test]
fn summarize_challenge_treasury_ignores_duplicate_open_challenge_for_same_task() {
    let events = vec![
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 55,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c55".into(),
            tx_id: 1,
            block_height: 10,
            state_root: "a".into(),
            ts_unix_ms: 1_000,
            signer: None,
            challenger: Some("c55".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-9),
            bond_disposition: Some("posted".into()),
        },
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 55,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c55".into(),
            tx_id: 2,
            block_height: 11,
            state_root: "b".into(),
            ts_unix_ms: 2_000,
            signer: None,
            challenger: Some("c55".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-4),
            bond_disposition: Some("posted".into()),
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 55,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "validator".into(),
            tx_id: 3,
            block_height: 12,
            state_root: "c".into(),
            ts_unix_ms: 3_000,
            signer: None,
            challenger: Some("c55".into()),
            tx_hash: None,
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("forfeited".into()),
        },
    ];

    let out = summarize_challenge_treasury(
        &events,
        10,
        Some((500, 3_500, "custom".into())),
        NodeEventScanMode::Authoritative,
        false,
    );
    assert_eq!(out.current_escrow_balance, 0);
    assert_eq!(out.current_forfeits_balance, 9);
    assert_eq!(out.cumulative_forfeited, 9);
    assert_eq!(out.events[0].bond_amount, 9);
    assert_eq!(out.events[1].bond_amount, 0);
    let summary = out.daily_summary.expect("summary expected");
    assert_eq!(summary.posted, 1);
    assert_eq!(summary.forfeited, 1);
    assert_eq!(summary.unresolved, 0);
    assert_eq!(out.anomaly_count, 1);
    assert_eq!(out.anomalies[0].code, "duplicate_open_challenge");
}

#[test]
fn summarize_challenge_treasury_duplicate_resolve_replay_marks_replay_anomaly() {
    let events = vec![
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 66,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c66".into(),
            tx_id: 1,
            block_height: 10,
            state_root: "a".into(),
            ts_unix_ms: 1_000,
            signer: None,
            challenger: Some("c66".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-6),
            bond_disposition: Some("posted".into()),
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 66,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "validator".into(),
            tx_id: 2,
            block_height: 11,
            state_root: "b".into(),
            ts_unix_ms: 2_000,
            signer: None,
            challenger: Some("c66".into()),
            tx_hash: None,
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("forfeited".into()),
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 66,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "validator".into(),
            tx_id: 2,
            block_height: 12,
            state_root: "c".into(),
            ts_unix_ms: 2_100,
            signer: None,
            challenger: Some("c66".into()),
            tx_hash: None,
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("forfeited".into()),
        },
    ];

    let out = summarize_challenge_treasury(
        &events,
        10,
        Some((500, 3_000, "custom".into())),
        NodeEventScanMode::Authoritative,
        false,
    );
    assert_eq!(out.current_escrow_balance, 0);
    assert_eq!(out.current_forfeits_balance, 6);
    assert_eq!(out.cumulative_forfeited, 6);
    let summary = out.daily_summary.expect("summary expected");
    assert_eq!(summary.posted, 1);
    assert_eq!(summary.forfeited, 1);
    assert_eq!(summary.unresolved, 0);
    assert_eq!(out.anomaly_count, 1);
    assert_eq!(out.anomalies[0].code, "duplicate_event_replay");
}

#[test]
fn summarize_challenge_treasury_ignores_non_terminal_disposition_without_clearing_posted_bond() {
    let events = vec![
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 77,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c77".into(),
            tx_id: 1,
            block_height: 10,
            state_root: "a".into(),
            ts_unix_ms: 1_000,
            signer: None,
            challenger: Some("c77".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-8),
            bond_disposition: Some("posted".into()),
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 77,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "validator".into(),
            tx_id: 2,
            block_height: 11,
            state_root: "b".into(),
            ts_unix_ms: 2_000,
            signer: None,
            challenger: Some("c77".into()),
            tx_hash: None,
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("posted".into()),
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 77,
            from_status: "Challenged".into(),
            to_status: "Slashed".into(),
            actor: "validator".into(),
            tx_id: 3,
            block_height: 12,
            state_root: "c".into(),
            ts_unix_ms: 3_000,
            signer: None,
            challenger: Some("c77".into()),
            tx_hash: None,
            resolution_code: Some("slashed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("forfeited".into()),
        },
    ];

    let out = summarize_challenge_treasury(
        &events,
        10,
        Some((500, 3_500, "custom".into())),
        NodeEventScanMode::Authoritative,
        false,
    );
    assert_eq!(out.current_escrow_balance, 0);
    assert_eq!(out.current_forfeits_balance, 8);
    assert_eq!(out.cumulative_forfeited, 8);
    assert_eq!(out.events.len(), 2);
    assert_eq!(out.events[1].bond_amount, 8);
    assert_eq!(out.events[1].escrow_delta, -8);
    assert_eq!(out.events[1].forfeits_delta, 8);
    let summary = out.daily_summary.expect("summary expected");
    assert_eq!(summary.posted, 1);
    assert_eq!(summary.forfeited, 1);
    assert_eq!(summary.unresolved, 0);
    assert_eq!(out.anomaly_count, 0);
}
