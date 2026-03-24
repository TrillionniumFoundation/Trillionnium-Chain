use super::*;

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
        metering: None,
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
        metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
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
