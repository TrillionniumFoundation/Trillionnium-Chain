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
            metering: None,
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
            metering: None,
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
            metering: None,
        },
    ];

    let out = query_events_response(9, 20, &events, &[]).expect("events expected");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].event_type, "accept");
}

#[test]
fn query_events_response_sorts_historical_node_events_before_returning_read_model_chain() {
    let events = vec![
        NodeEventRecord {
            event_type: "reveal".into(),
            task_id: 44,
            from_status: "Committed".into(),
            to_status: "Revealed".into(),
            actor: "worker-z".into(),
            tx_id: 3,
            block_height: 3,
            state_root: "s3".into(),
            ts_unix_ms: 30,
            signer: Some("worker-z".into()),
            challenger: None,
            tx_hash: Some("0xccc".into()),
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
            metering: None,
        },
        NodeEventRecord {
            event_type: "accept".into(),
            task_id: 44,
            from_status: "Open".into(),
            to_status: "Assigned".into(),
            actor: "worker-z".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "s1".into(),
            ts_unix_ms: 10,
            signer: Some("worker-z".into()),
            challenger: None,
            tx_hash: Some("0xaaa".into()),
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
            metering: None,
        },
        NodeEventRecord {
            event_type: "commit".into(),
            task_id: 44,
            from_status: "Assigned".into(),
            to_status: "Committed".into(),
            actor: "worker-z".into(),
            tx_id: 2,
            block_height: 2,
            state_root: "s2".into(),
            ts_unix_ms: 20,
            signer: Some("worker-z".into()),
            challenger: None,
            tx_hash: Some("0xbbb".into()),
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
            metering: None,
        },
    ];

    let out = query_events_response(44, 20, &events, &[]).expect("events expected");
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].event_type, "accept");
    assert_eq!(out[1].event_type, "commit");
    assert_eq!(out[2].event_type, "reveal");
    assert_eq!(out[0].tx_hash.as_deref(), Some("0xaaa"));
    assert_eq!(out[1].tx_hash.as_deref(), Some("0xbbb"));
    assert_eq!(out[2].tx_hash.as_deref(), Some("0xccc"));
}

#[test]
fn query_events_response_fallback_sorts_adapter_records_stably() {
    let recs = vec![
        AdapterRecord {
            ts: 20,
            kind: "reveal".into(),
            task_id: 44,
            worker: Some("worker-z".into()),
            result_hash: Some("0x44".into()),
            status: "accepted".into(),
            tx_hash: Some("0xbbb".into()),
        },
        AdapterRecord {
            ts: 10,
            kind: "commit".into(),
            task_id: 44,
            worker: Some("worker-z".into()),
            result_hash: None,
            status: "accepted".into(),
            tx_hash: Some("0xaaa".into()),
        },
    ];

    let out = query_events_response(44, 20, &[], &recs).expect("events expected");
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].event_type, "commit");
    assert_eq!(out[0].from_status, "Assigned");
    assert_eq!(out[0].to_status, "Committed");
    assert_eq!(out[1].event_type, "reveal");
    assert_eq!(out[1].from_status, "Committed");
    assert_eq!(out[1].to_status, "Revealed");
}

#[test]
fn query_events_response_fallback_rejects_reveal_without_persisted_commit() {
    let recs = vec![AdapterRecord {
        ts: 20,
        kind: "reveal".into(),
        task_id: 45,
        worker: Some("worker-z".into()),
        result_hash: Some("0x45".into()),
        status: "accepted".into(),
        tx_hash: Some("0xccc".into()),
    }];

    let err = query_events_response(45, 20, &[], &recs)
        .expect_err("reveal-only fallback must not synthesize a historical event chain");
    assert!(err.to_string().contains("events not found for task_id=45"));
}

#[test]
fn query_events_response_fallback_sorts_same_timestamp_records_by_normalized_identity() {
    let recs = vec![
        AdapterRecord {
            ts: 10,
            kind: "commit".into(),
            task_id: 46,
            worker: Some(" worker-z\u{200b}".into()),
            result_hash: None,
            status: "accepted".into(),
            tx_hash: Some("0XBBB".into()),
        },
        AdapterRecord {
            ts: 10,
            kind: "commit".into(),
            task_id: 46,
            worker: Some("worker-z".into()),
            result_hash: None,
            status: "accepted".into(),
            tx_hash: Some(" tx_hash=0xaaa ".into()),
        },
    ];

    let out = query_events_response(46, 20, &[], &recs).expect("events expected");
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].actor, "worker-z");
    assert_eq!(out[0].tx_hash.as_deref(), Some("0xaaa"));
    assert_eq!(out[1].actor, "worker-z");
    assert_eq!(out[1].tx_hash.as_deref(), Some("0xbbb"));
}

#[test]
fn query_events_response_fallback_dedupes_canonical_replay_rows_from_persistence() {
    let recs = vec![
        AdapterRecord {
            ts: 10,
            kind: "commit".into(),
            task_id: 47,
            worker: Some(" worker-z\u{200b}".into()),
            result_hash: None,
            status: "accepted".into(),
            tx_hash: Some(" tx_hash=0xabc ".into()),
        },
        AdapterRecord {
            ts: 10,
            kind: "commit".into(),
            task_id: 47,
            worker: Some("worker-z".into()),
            result_hash: None,
            status: "accepted".into(),
            tx_hash: Some("0XABC".into()),
        },
        AdapterRecord {
            ts: 20,
            kind: "reveal".into(),
            task_id: 47,
            worker: Some("worker-z".into()),
            result_hash: Some("0xdef".into()),
            status: "accepted".into(),
            tx_hash: Some("0xdef".into()),
        },
        AdapterRecord {
            ts: 21,
            kind: "reveal".into(),
            task_id: 47,
            worker: Some(" worker-z ".into()),
            result_hash: Some("0xdef".into()),
            status: "accepted".into(),
            tx_hash: Some("0XDEF".into()),
        },
    ];

    let out = query_events_response(47, 20, &[], &recs).expect("events expected");
    assert_eq!(out.len(), 2, "duplicate replay rows must not duplicate historical events");
    assert_eq!(out[0].event_type, "commit");
    assert_eq!(out[0].tx_hash.as_deref(), Some("0xabc"));
    assert_eq!(out[1].event_type, "reveal");
    assert_eq!(out[1].tx_hash.as_deref(), Some("0xdef"));
}

#[test]
fn query_events_response_fallback_dedupes_hex_result_hash_replay_aliases() {
    let recs = vec![
        AdapterRecord {
            ts: 10,
            kind: "commit".into(),
            task_id: 48,
            worker: Some("worker-z".into()),
            result_hash: None,
            status: "accepted".into(),
            tx_hash: Some("0xabc".into()),
        },
        AdapterRecord {
            ts: 20,
            kind: "reveal".into(),
            task_id: 48,
            worker: Some(" worker-z ".into()),
            result_hash: Some(" 0XDEF ".into()),
            status: "accepted".into(),
            tx_hash: Some("0xdef".into()),
        },
        AdapterRecord {
            ts: 21,
            kind: "reveal".into(),
            task_id: 48,
            worker: Some("worker-z\u{200b}".into()),
            result_hash: Some("0xdef".into()),
            status: "accepted".into(),
            tx_hash: Some("0XDEF".into()),
        },
    ];

    let out = query_events_response(48, 20, &[], &recs).expect("events expected");
    assert_eq!(out.len(), 2, "hex result-hash aliases must not duplicate historical replay rows");
    assert_eq!(out[1].event_type, "reveal");
    assert_eq!(out[1].tx_hash.as_deref(), Some("0xdef"));
}
