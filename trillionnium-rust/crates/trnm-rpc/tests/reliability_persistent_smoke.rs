use trnm_rpc::reliability::{
    AckCode, ReliabilityEngine, ReliabilityStore, ReliabilityStoreMode, ReliableMessage,
    RetentionConfig, RetryConfig, SqliteReliabilityStore,
};

#[test]
fn reliability_persistent_store_smoke() {
    if ReliabilityStoreMode::from_env() == ReliabilityStoreMode::Memory {
        eprintln!("[skip] RELIABILITY_STORE=memory, skip sqlite smoke");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("reliability-smoke.db");

    // First engine instance writes accepted record.
    let mut engine = ReliabilityEngine::new(
        SqliteReliabilityStore::open(&db_path).expect("open sqlite store"),
        RetryConfig::default(),
    );

    let msg = ReliableMessage {
        from: "user-42".to_string(),
        chain_id: "trnm-mainnet".to_string(),
        session_id: "sess-persist".to_string(),
        seq: Some(7),
        nonce: None,
        msg_type: "INPUT_CHUNK".to_string(),
        payload: "persist me".to_string(),
    };

    let ack = engine.receive(msg.clone(), 1_000);
    assert_eq!(ack.code, AckCode::Accepted);
    drop(engine);

    // Simulate restart: second instance should dedup from persisted store.
    let mut restarted = ReliabilityEngine::new(
        SqliteReliabilityStore::open(&db_path).expect("reopen sqlite store"),
        RetryConfig::default(),
    );

    let dup = restarted.receive(msg, 1_100);
    assert_eq!(dup.code, AckCode::Duplicate);
}

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
