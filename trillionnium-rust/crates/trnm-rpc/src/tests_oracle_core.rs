pub(crate) use super::*;

#[test]
fn parse_query_normalized_audit_events_query_from_path_defaults_and_filters() {
    let out = parse_query_normalized_audit_events_query_from_path("/query-normalized-audit-events")
        .expect("default should parse");
    assert_eq!(out.limit, QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT);
    assert!(out.source.is_none());
    assert!(out.event_type.is_none());
    assert!(out.cursor.is_none());

    let out = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?source=trnm.task&eventType=trnm.task.commit&limit=3&cursor=2"
    )
    .expect("explicit query should parse");
    assert_eq!(out.source.as_deref(), Some("trnm.task"));
    assert_eq!(out.event_type.as_deref(), Some("trnm.task.commit"));
    assert_eq!(out.limit, 3);
    assert_eq!(out.cursor, Some(2));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_unrelated_query_keys() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?source=trnm.task&foo=bar",
    )
    .expect_err("unexpected keys should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid query"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_suffixed_paths() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events-extra?source=trnm.task",
    )
    .expect_err("suffixed route variants must fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid query"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_invalid_cursor() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?cursor=bad",
    )
    .expect_err("invalid cursor should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid cursor"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_duplicate_limit() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?limit=3&limit=4",
    )
    .expect_err("duplicate limit should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("duplicate limit"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_duplicate_event_type() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?eventType=trnm.task.accept&eventType=trnm.task.commit",
    )
    .expect_err("duplicate eventType should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("duplicate eventType"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_duplicate_source() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?source=trnm.task&source=trnm.adapter",
    )
    .expect_err("duplicate source should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("duplicate source"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_duplicate_cursor() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?cursor=1&cursor=2",
    )
    .expect_err("duplicate cursor should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("duplicate cursor"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_empty_source_value() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?source=",
    )
    .expect_err("empty source should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid source"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_empty_event_type_value() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?eventType=",
    )
    .expect_err("empty eventType should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid eventType"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_unknown_source_and_mixed_prefix_event_types() {
    for path in [
        "/query-normalized-audit-events?source=trnm.oracle",
        "/query-normalized-audit-events?eventType=trnm.oracle.accept",
        "/query-normalized-audit-events?source=trnm.task&eventType=trnm.adapter.accept",
        "/query-normalized-audit-events?source=trnm.adapter&eventType=trnm.task.commit",
    ] {
        let err = parse_query_normalized_audit_events_query_from_path(path)
            .expect_err("unknown or mixed-prefix filters should fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(
            err.contains("invalid source") || err.contains("invalid eventType"),
            "path={path} err={err}"
        );
    }
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_empty_cursor_value() {
    let err = parse_query_normalized_audit_events_query_from_path(
        "/query-normalized-audit-events?cursor=",
    )
    .expect_err("empty cursor should fail closed");
    assert!(err.contains("400 Bad Request"));
    assert!(err.contains("invalid cursor"));
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_malformed_percent_encoding() {
    for path in [
        "/query-normalized-audit-events%",
        "/query-normalized-audit-events%2?source=trnm.task",
        "/query-normalized-audit-events%zz?source=trnm.task",
        "/query-normalized-audit-events?source=trnm.task%",
        "/query-normalized-audit-events?eventType=trnm.task.commit%2",
        "/query-normalized-audit-events?limit=3%zz",
    ] {
        let err = parse_query_normalized_audit_events_query_from_path(path)
            .expect_err("malformed percent encoding should fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid query"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_percent_encoded_c0_controls_and_del() {
    for path in [
        "/query-normalized-audit-events?source=trnm.task%00shadow",
        "/query-normalized-audit-events?source=trnm.task%01shadow",
        "/query-normalized-audit-events?eventType=trnm.task.commit%1ftrail",
        "/query-normalized-audit-events?eventType=trnm.task.commit%7ftrail",
        "/query-normalized-audit-events%00shadow?source=trnm.task",
        "/query-normalized-audit-events%01shadow?source=trnm.task",
        "/query-normalized-audit-events%1fshadow?source=trnm.task",
        "/query-normalized-audit-events%7fshadow?source=trnm.task",
    ] {
        let err = parse_query_normalized_audit_events_query_from_path(path)
            .expect_err("encoded controls should fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid query"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_percent_encoded_query_delimiters() {
    for path in [
        "/query-normalized-audit-events?source=trnm.task%26eventType=trnm.task.commit",
        "/query-normalized-audit-events?eventType%3dtrnm.task.commit",
        "/query-normalized-audit-events?limit=3%23tail",
        "/query-normalized-audit-events?cursor=1%3Flimit=2",
        "/query-normalized-audit-events?source=trnm.task%26limit=2",
        "/query-normalized-audit-events?eventType%3Dtrnm.task.commit",
    ] {
        let err = parse_query_normalized_audit_events_query_from_path(path)
            .expect_err("encoded query delimiters should fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid query"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_percent_encoded_spaces() {
    for path in [
        "/query-normalized-audit-events?source=trnm.task%20shadow",
        "/query-normalized-audit-events?eventType=trnm.task.commit%20tail",
        "/query-normalized-audit-events?cursor=1%20",
        "/query-normalized-audit-events?limit=3%20",
        "/query-normalized-audit-events%20shadow?source=trnm.task",
    ] {
        let err = parse_query_normalized_audit_events_query_from_path(path)
            .expect_err("percent-encoded spaces should fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid query"), "path={path} err={err}");
    }
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_raw_whitespace() {
    for path in [
        "/query-normalized-audit-events ?source=trnm.task",
        "/query-normalized-audit-events?source=trnm.task ",
        "/query-normalized-audit-events?eventType=trnm.task.commit\t",
        "/query-normalized-audit-events?limit=3\n",
    ] {
        let err = parse_query_normalized_audit_events_query_from_path(path)
            .expect_err("raw whitespace should fail closed");
        assert!(err.contains("400 Bad Request"), "path={path:?} err={err}");
        assert!(err.contains("invalid query"), "path={path:?} err={err}");
    }
}

#[test]
fn parse_query_normalized_audit_events_query_from_path_rejects_prefix_shadow_paths() {
    for path in [
        "/query-normalized-audit-events-shadow",
        "/query-normalized-audit-events-shadow?source=trnm.task",
        "/query-normalized-audit-events/extra",
        "/query-normalized-audit-events/extra?limit=2",
    ] {
        let err = parse_query_normalized_audit_events_query_from_path(path)
            .expect_err("prefix-shadow paths should fail closed");
        assert!(err.contains("400 Bad Request"), "path={path} err={err}");
        assert!(err.contains("invalid query"), "path={path} err={err}");
    }
}

#[test]
fn query_normalized_audit_events_supports_pagination_and_event_filters() {
    let events = vec![
        NodeEventRecord {
            event_type: "accept".into(),
            task_id: 1,
            from_status: "Open".into(),
            to_status: "Assigned".into(),
            actor: "worker-a".into(),
            tx_id: 1,
            block_height: 10,
            state_root: "s1".into(),
            ts_unix_ms: 100,
            signer: Some("worker-a".into()),
            challenger: None,
            tx_hash: None,
            resolution_code: Some("accepted".into()),
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
            metering: None,
        },
        NodeEventRecord {
            event_type: "commit".into(),
            task_id: 1,
            from_status: "Assigned".into(),
            to_status: "Committed".into(),
            actor: "worker-a".into(),
            tx_id: 2,
            block_height: 20,
            state_root: "s2".into(),
            ts_unix_ms: 200,
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

    let first = query_normalized_audit_events(
        &events,
        &[],
        &QueryNormalizedAuditEventsQuery {
            source: Some("trnm.task".into()),
            event_type: None,
            cursor: None,
            limit: 1,
        },
    );
    assert_eq!(first.total, Some(2));
    assert_eq!(first.events.len(), 1);
    assert_eq!(first.events[0].event_type, "trnm.task.commit");
    assert_eq!(first.has_more, Some(true));
    assert_eq!(first.next_cursor.as_deref(), Some("1"));

    let second = query_normalized_audit_events(
        &events,
        &[],
        &QueryNormalizedAuditEventsQuery {
            source: Some("trnm.task".into()),
            event_type: Some("trnm.task.accept".into()),
            cursor: Some(0),
            limit: 10,
        },
    );
    assert_eq!(second.total, Some(1));
    assert_eq!(second.events.len(), 1);
    assert_eq!(second.events[0].event_type, "trnm.task.accept");
    assert_eq!(second.has_more, Some(false));
}

#[test]
fn query_normalized_audit_events_supports_adapter_source_filter() {
    let recs = vec![AdapterRecord {
        ts: 300,
        kind: "accept".into(),
        task_id: 7,
        worker: Some("worker-a".into()),
        result_hash: Some("rh-1".into()),
        status: "accepted".into(),
        tx_hash: Some("0xabc123".into()),
    }];

    let out = query_normalized_audit_events(
        &[],
        &recs,
        &QueryNormalizedAuditEventsQuery {
            source: Some("trnm.adapter".into()),
            event_type: Some("trnm.adapter.accept".into()),
            cursor: None,
            limit: 10,
        },
    );
    assert_eq!(out.total, Some(1));
    assert_eq!(out.events.len(), 1);
    assert_eq!(out.events[0].source, "trnm.adapter");
    assert_eq!(out.events[0].event_type, "trnm.adapter.accept");
    assert_eq!(out.events[0].actor.as_deref(), Some("worker-a"));
    assert_eq!(out.events[0].object_id.as_deref(), Some("task:7"));
    assert_eq!(out.events[0].note.as_deref(), Some("0xabc123"));
    assert_eq!(out.has_more, Some(false));
}

#[test]
fn query_normalized_audit_events_bounds_node_reason_and_note_fields() {
    let long_status = "A".repeat(120);
    let long_resolution = "r".repeat(220);
    let events = vec![NodeEventRecord {
        event_type: "accept".into(),
        task_id: 9,
        from_status: long_status.clone(),
        to_status: long_status,
        actor: "worker-a".into(),
        tx_id: 1,
        block_height: 10,
        state_root: "s1".into(),
        ts_unix_ms: 100,
        signer: Some("worker-a".into()),
        challenger: None,
        tx_hash: None,
        resolution_code: Some(long_resolution),
        treasury_delta: None,
        challenger_delta: None,
        bond_disposition: None,
        metering: None,
    }];

    let out = query_normalized_audit_events(
        &events,
        &[],
        &QueryNormalizedAuditEventsQuery {
            source: Some("trnm.task".into()),
            event_type: Some("trnm.task.accept".into()),
            cursor: None,
            limit: 10,
        },
    );
    assert_eq!(out.total, Some(1));
    assert_eq!(out.events.len(), 1);
    let event = &out.events[0];
    assert_eq!(event.reason.as_ref().unwrap().chars().count(), 160);
    assert!(event.reason.as_ref().unwrap().ends_with('…'));
    assert_eq!(event.note.as_ref().unwrap().chars().count(), 160);
    assert!(event.note.as_ref().unwrap().ends_with('…'));
}

#[test]
fn query_normalized_audit_events_bounds_adapter_note_field() {
    let recs = vec![AdapterRecord {
        ts: 300,
        kind: "accept".into(),
        task_id: 7,
        worker: Some("worker-a".into()),
        result_hash: Some("h".repeat(220)),
        status: "accepted".into(),
        tx_hash: None,
    }];

    let out = query_normalized_audit_events(
        &[],
        &recs,
        &QueryNormalizedAuditEventsQuery {
            source: Some("trnm.adapter".into()),
            event_type: Some("trnm.adapter.accept".into()),
            cursor: None,
            limit: 10,
        },
    );
    assert_eq!(out.total, Some(1));
    assert_eq!(out.events.len(), 1);
    let event = &out.events[0];
    assert_eq!(event.reason.as_deref(), Some("adapter-event"));
    assert_eq!(event.note.as_ref().unwrap().chars().count(), 160);
    assert!(event.note.as_ref().unwrap().ends_with('…'));
}
