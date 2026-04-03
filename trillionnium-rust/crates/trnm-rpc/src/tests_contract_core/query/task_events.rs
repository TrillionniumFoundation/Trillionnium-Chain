use super::*;

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
            metering: None,
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
            metering: None,
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
            metering: None,
        },
    ];

    let out = query_task_from_node_events(42, &events).expect("task expected");
    assert_eq!(out.version, 3);
    assert_eq!(out.status, TaskStatus::Challenged);
    assert_eq!(out.worker.as_deref(), Some("worker-b"));
}

#[test]
fn query_task_from_node_events_sorts_historical_replay_before_deriving_status() {
    let events = vec![
        NodeEventRecord {
            event_type: "reveal".into(),
            task_id: 43,
            from_status: "Committed".into(),
            to_status: "Revealed".into(),
            actor: "worker-z".into(),
            tx_id: 3,
            block_height: 3,
            state_root: "s3".into(),
            ts_unix_ms: 30,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
            metering: None,
        },
        NodeEventRecord {
            event_type: "accept".into(),
            task_id: 43,
            from_status: "Open".into(),
            to_status: "Assigned".into(),
            actor: "worker-a".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "s1".into(),
            ts_unix_ms: 10,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
            metering: None,
        },
        NodeEventRecord {
            event_type: "commit".into(),
            task_id: 43,
            from_status: "Assigned".into(),
            to_status: "Committed".into(),
            actor: "worker-z".into(),
            tx_id: 2,
            block_height: 2,
            state_root: "s2".into(),
            ts_unix_ms: 20,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
            metering: None,
        },
    ];

    let out = query_task_from_node_events(43, &events).expect("task expected");
    assert_eq!(out.version, 3);
    assert_eq!(out.status, TaskStatus::Revealed);
    assert_eq!(out.worker.as_deref(), Some("worker-z"));
}

#[test]
fn query_task_response_fallback_normalizes_adapter_worker_for_read_model_consistency() {
    with_market_path_env(&[(TASK_STATE_FILE_ENV, None)], || {
        let recs = vec![AdapterRecord {
            ts: 10,
            kind: "commit".into(),
            task_id: 88,
            worker: Some(" \u{200B}Worker\u{2060} A\t".into()),
            result_hash: None,
            status: "accepted".into(),
            tx_hash: Some("0xabc".into()),
        }];

        let out = query_task_response(88, &[], &recs).expect("task expected");
        assert_eq!(out.worker.as_deref(), Some("worker a"));
        assert_eq!(out.status, TaskStatus::Committed);
    });
}

#[test]
fn query_task_response_fallback_rejects_reveal_without_persisted_commit() {
    with_market_path_env(&[(TASK_STATE_FILE_ENV, None)], || {
        let recs = vec![AdapterRecord {
            ts: 20,
            kind: "reveal".into(),
            task_id: 89,
            worker: Some("worker-z".into()),
            result_hash: Some("0x89".into()),
            status: "accepted".into(),
            tx_hash: Some("0xddd".into()),
        }];

        let err = query_task_response(89, &[], &recs)
            .expect_err("reveal-only fallback must not synthesize a historical task state");
        assert!(err
            .to_string()
            .contains("requires persisted commit history"));
    });
}

#[test]
fn query_task_response_fallback_dedupes_canonical_replay_rows_from_persistence() {
    with_market_path_env(&[(TASK_STATE_FILE_ENV, None)], || {
        let recs = vec![
            AdapterRecord {
                ts: 10,
                kind: "commit".into(),
                task_id: 90,
                worker: Some(" worker-z\u{200b}".into()),
                result_hash: None,
                status: "accepted".into(),
                tx_hash: Some(" tx_hash=0xabc ".into()),
            },
            AdapterRecord {
                ts: 10,
                kind: "commit".into(),
                task_id: 90,
                worker: Some("worker-z".into()),
                result_hash: None,
                status: "accepted".into(),
                tx_hash: Some("0XABC".into()),
            },
            AdapterRecord {
                ts: 20,
                kind: "reveal".into(),
                task_id: 90,
                worker: Some("worker-z".into()),
                result_hash: Some("0xdef".into()),
                status: "accepted".into(),
                tx_hash: Some("0xdef".into()),
            },
            AdapterRecord {
                ts: 21,
                kind: "reveal".into(),
                task_id: 90,
                worker: Some(" worker-z ".into()),
                result_hash: Some("0xdef".into()),
                status: "accepted".into(),
                tx_hash: Some("0XDEF".into()),
            },
        ];

        let out = query_task_response(90, &[], &recs).expect("task expected");
        assert_eq!(out.status, TaskStatus::Revealed);
        assert_eq!(out.worker.as_deref(), Some("worker-z"));
        assert_eq!(out.result_hash_hex.as_deref(), Some("0xdef"));
        assert_eq!(
            out.version, 2,
            "duplicate replay rows must not inflate durable task history"
        );
    });
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
        metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
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
            metering: None,
        },
    ];

    let out = query_task_from_node_events(10, &events).expect("task expected");
    assert_eq!(out.status, TaskStatus::Challenged);
    assert_eq!(out.version, 1);
}
