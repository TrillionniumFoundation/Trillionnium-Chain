use super::*;

#[test]
fn sqlite_cleanup_expired_prunes_pending_and_drops_empty_session() {
    if ReliabilityStoreMode::from_env() == ReliabilityStoreMode::Memory {
        eprintln!("[skip] RELIABILITY_STORE=memory, skip sqlite smoke");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("reliability-cleanup.db");
    let mut store = SqliteReliabilityStore::open(&db_path).expect("open sqlite store");

    let msg = ReliableMessage {
        from: "user-ttl".to_string(),
        chain_id: "trnm-mainnet".to_string(),
        session_id: "sess-cleanup".to_string(),
        seq: Some(8),
        nonce: None,
        msg_type: "INPUT_CHUNK".to_string(),
        payload: "expire me".to_string(),
    };
    let ack_id = format!("ack_{}_{}", msg.from, msg.seq.expect("seq"));
    let mut pending = std::collections::BTreeMap::new();
    pending.insert(
        ack_id.clone(),
        trnm_rpc::reliability::PendingItem {
            ack_id,
            message: msg,
            attempts: 0,
            next_retry_at_unix_ms: 1_050,
            created_at_unix_ms: 1_000,
        },
    );
    store.upsert_session(trnm_rpc::reliability::SessionState {
        session_id: "sess-cleanup".to_string(),
        pending,
    });

    store.cleanup_expired(
        1_500,
        &RetentionConfig {
            dedup_ttl_ms: 10_000,
            pending_ttl_ms: 200,
            cleanup_interval_ms: 1,
        },
    );

    assert!(
        store.get_session("sess-cleanup").is_none(),
        "expired pending items should not leave an empty sqlite session behind"
    );
}

#[test]
fn sqlite_cleanup_expired_reclaims_empty_session_after_ack_timestamp() {
    if ReliabilityStoreMode::from_env() == ReliabilityStoreMode::Memory {
        eprintln!("[skip] RELIABILITY_STORE=memory, skip sqlite smoke");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("reliability-empty-session.db");
    let mut engine = ReliabilityEngine::new_with_retention(
        SqliteReliabilityStore::open(&db_path).expect("open sqlite store"),
        RetryConfig::default(),
        RetentionConfig {
            dedup_ttl_ms: 10_000,
            pending_ttl_ms: 200,
            cleanup_interval_ms: 1,
        },
    );

    let msg = ReliableMessage {
        from: "user-empty".to_string(),
        chain_id: "trnm-mainnet".to_string(),
        session_id: "sess-empty".to_string(),
        seq: Some(9),
        nonce: None,
        msg_type: "INPUT_CHUNK".to_string(),
        payload: "ack then expire".to_string(),
    };

    let ack = engine.receive(msg, 1_000);
    assert_eq!(ack.code, AckCode::Accepted);
    assert!(engine.mark_acked("sess-empty", &ack.ack_id));

    let due = engine.collect_due_retries(1_250);
    assert!(due.is_empty());

    let store = engine.into_store();
    assert!(
        store.get_session("sess-empty").is_none(),
        "sqlite cleanup should reclaim empty sessions once their preserved timestamp ages past pending ttl"
    );
}

#[test]
fn sqlite_cleanup_reclaims_pending_capacity_after_ttl_expiry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("reliability-pending-cleanup.db");
    let store = SqliteReliabilityStore::open_with_config(
        &db_path,
        InMemoryReliabilityStoreConfig {
            max_sessions: Some(8),
            max_pending_total: Some(1),
            max_pending_per_session: Some(1),
            max_dedup_entries: Some(8),
            ..InMemoryReliabilityStoreConfig::default()
        },
    )
    .expect("open sqlite store");
    let mut engine = ReliabilityEngine::new_with_retention(
        store,
        RetryConfig::default(),
        RetentionConfig {
            dedup_ttl_ms: 1,
            pending_ttl_ms: 10,
            cleanup_interval_ms: 10,
        },
    );

    let first = ReliableMessage {
        from: "alice".to_string(),
        chain_id: "trnm-mainnet".to_string(),
        session_id: "s1".to_string(),
        seq: Some(1),
        nonce: None,
        msg_type: "INPUT_CHUNK".to_string(),
        payload: "one".to_string(),
    };
    assert_eq!(engine.receive(first, 1).code, AckCode::Accepted);

    let blocked = ReliableMessage {
        from: "bob".to_string(),
        chain_id: "trnm-mainnet".to_string(),
        session_id: "s2".to_string(),
        seq: Some(1),
        nonce: None,
        msg_type: "INPUT_CHUNK".to_string(),
        payload: "two".to_string(),
    };
    let blocked_ack = engine.receive(blocked.clone(), 2);
    assert_eq!(blocked_ack.code, AckCode::BadRequest);
    assert!(blocked_ack
        .detail
        .contains("pending total limit reached (1)"));

    let recovered = engine.receive(blocked, 20);
    assert_eq!(recovered.code, AckCode::Accepted);
}
