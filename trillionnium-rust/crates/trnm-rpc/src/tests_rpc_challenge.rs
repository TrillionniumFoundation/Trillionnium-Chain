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

#[test]
fn resolve_ops_window_custom_validation() {
    assert!(resolve_ops_window(Some(OpsWindowArg::Custom), None, Some(1), 10).is_err());
    assert!(resolve_ops_window(Some(OpsWindowArg::Custom), Some(2), Some(1), 10).is_err());
    assert!(resolve_ops_window(
        Some(OpsWindowArg::Custom),
        Some(0),
        Some(OPS_WINDOW_CUSTOM_MAX_MS + 1),
        10
    )
    .is_err());

    let got = resolve_ops_window(Some(OpsWindowArg::H24), None, None, 1_000).unwrap();
    let (from, to, mode) = got.expect("window expected");
    assert_eq!(to, 1_000);
    assert_eq!(mode, "24h");
    assert!(from <= to);
}

#[test]
fn make_request_id_is_deterministic_and_separator_sensitive() {
    let a = make_request_id("telegram", "u1", "s1", "idem-1", 123);
    let b = make_request_id("telegram", "u1", "s1", "idem-1", 123);
    let c = make_request_id("telegram|u1", "s1", "idem-1", "", 123);

    assert_eq!(a, b, "same tuple must hash to a stable request id");
    assert_ne!(a, c, "field separators must keep scopes unambiguous");
    assert!(a.starts_with("req_"));
    assert_eq!(a.len(), 20, "req_ + 16 hex chars");
}

#[test]
fn submit_message_idempotency_scope_requires_channel_user_session_and_key_match() {
    let rec = MessageIngressRecord {
        request_id: "req_1".into(),
        task_id: 42,
        channel: "telegram".into(),
        user_id: "u1".into(),
        session_id: "s1".into(),
        text: "hi".into(),
        idempotency_key: "idem-1".into(),
        status: RequestStatus::Open.as_str().into(),
        created_at_unix_ms: 1,
        assigned_worker: None,
        assigned_at_unix_ms: None,
        model_output: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
    };

    assert!(is_same_submit_message_idempotency_scope(
        &rec, "telegram", "u1", "s1", "idem-1"
    ));
    assert!(!is_same_submit_message_idempotency_scope(
        &rec, "discord", "u1", "s1", "idem-1"
    ));
    assert!(!is_same_submit_message_idempotency_scope(
        &rec, "telegram", "u2", "s1", "idem-1"
    ));
    assert!(!is_same_submit_message_idempotency_scope(
        &rec, "telegram", "u1", "s2", "idem-1"
    ));
    assert!(!is_same_submit_message_idempotency_scope(
        &rec, "telegram", "u1", "s1", "idem-2"
    ));
}

#[test]
fn transition_request_status_accepts_benign_formatting_variants() {
    let next = transition_request_status("  open ", RequestStatus::Assigned)
        .expect("OPEN -> ASSIGNED should parse with whitespace/case drift");
    assert_eq!(next, RequestStatus::Assigned.as_str());

    let next = transition_request_status("aSsIgNeD", RequestStatus::CommitQueued)
        .expect("ASSIGNED -> COMMIT_QUEUED should parse case-insensitively");
    assert_eq!(next, RequestStatus::CommitQueued.as_str());
}

#[test]
fn transition_request_status_rejects_malformed_state_with_stable_diagnostic() {
    let err = transition_request_status(" pending-ish ", RequestStatus::Assigned)
        .expect_err("unknown states must be rejected");
    assert!(
        err.to_string().contains("unknown request state"),
        "unexpected error text: {}",
        err
    );
}

#[test]
fn query_task_from_node_events_uses_latest_status_and_worker() {
    let events = vec![
        NodeEventRecord {
            event_type: "accept".into(),
            task_id: 42,
            from_status: "Open".into(),
            to_status: "Assigned".into(),
            actor: "worker-a".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "s1".into(),
            ts_unix_ms: 1,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
        },
        NodeEventRecord {
            event_type: "commit".into(),
            task_id: 42,
            from_status: "Assigned".into(),
            to_status: "Committed".into(),
            actor: "worker-b".into(),
            tx_id: 2,
            block_height: 2,
            state_root: "s2".into(),
            ts_unix_ms: 2,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
        },
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 42,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "challenger".into(),
            tx_id: 3,
            block_height: 3,
            state_root: "s3".into(),
            ts_unix_ms: 3,
            signer: None,
            challenger: Some("challenger".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
        },
    ];

    let out = query_task_from_node_events(42, &events).expect("task expected");
    assert_eq!(out.version, 3);
    assert_eq!(out.status, TaskStatus::Challenged);
    assert_eq!(out.worker.as_deref(), Some("worker-b"));
}

#[test]
fn query_task_from_node_events_none_for_missing_task() {
    let events = vec![NodeEventRecord {
        event_type: "accept".into(),
        task_id: 10,
        from_status: "Open".into(),
        to_status: "Assigned".into(),
        actor: "worker-a".into(),
        tx_id: 1,
        block_height: 1,
        state_root: "s1".into(),
        ts_unix_ms: 1,
        signer: None,
        challenger: None,
        tx_hash: None,
        resolution_code: None,
        treasury_delta: None,
        challenger_delta: None,
        bond_disposition: None,
    }];

    assert!(query_task_from_node_events(999, &events).is_none());
}

#[test]
fn query_task_from_node_events_ignores_unknown_status_transition() {
    let events = vec![
        NodeEventRecord {
            event_type: "accept".into(),
            task_id: 7,
            from_status: "Open".into(),
            to_status: "Assigned".into(),
            actor: "worker-a".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "s1".into(),
            ts_unix_ms: 1,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
        },
        NodeEventRecord {
            event_type: "mystery".into(),
            task_id: 7,
            from_status: "Assigned".into(),
            to_status: "UNRECOGNIZED".into(),
            actor: "system".into(),
            tx_id: 2,
            block_height: 2,
            state_root: "s2".into(),
            ts_unix_ms: 2,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
        },
    ];

    let out = query_task_from_node_events(7, &events).expect("task expected");
    assert_eq!(out.status, TaskStatus::Assigned);
    assert_eq!(out.version, 1);
}

#[test]
fn query_task_from_node_events_filters_invalid_signer_mismatch() {
    let events = vec![
        NodeEventRecord {
            event_type: "accept".into(),
            task_id: 8,
            from_status: "Open".into(),
            to_status: "Assigned".into(),
            actor: "worker-a".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "s1".into(),
            ts_unix_ms: 1,
            signer: Some("worker-b".into()),
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
        },
        NodeEventRecord {
            event_type: "commit".into(),
            task_id: 8,
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
    ];

    assert!(query_task_from_node_events(8, &events).is_none());
}

#[test]
fn query_task_from_node_events_rejects_system_resolve_actor() {
    let events = vec![
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 10,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "challenger-a".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "s1".into(),
            ts_unix_ms: 1,
            signer: Some("challenger-a".into()),
            challenger: Some("challenger-a".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-5),
            bond_disposition: Some("posted".into()),
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 10,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "system".into(),
            tx_id: 2,
            block_height: 2,
            state_root: "s2".into(),
            ts_unix_ms: 2,
            signer: Some("system".into()),
            challenger: Some("challenger-a".into()),
            tx_hash: None,
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("forfeited".into()),
        },
    ];

    let out = query_task_from_node_events(10, &events).expect("task expected");
    assert_eq!(out.status, TaskStatus::Challenged);
    assert_eq!(out.version, 1);
}

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
