use super::*;

#[test]
fn dedup_quota_limit_rejects_fresh_ingress_without_breaking_duplicate_ack_path() {
    let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
        max_dedup_entries: Some(1),
        ..InMemoryReliabilityStoreConfig::default()
    });
    let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

    let first = engine.receive(mk_msg("alice", "s1", 1), 1_000);
    assert_eq!(first.code, AckCode::Accepted);

    // New dedup domains should be backpressured once quota is full.
    let blocked = engine.receive(mk_msg("bob", "s2", 9), 1_001);
    assert_eq!(blocked.code, AckCode::BadRequest);
    assert!(blocked.detail.contains("dedup limit reached (1)"));

    // Existing dedup domains must still resolve to Duplicate rather than
    // quota errors so callers keep idempotent semantics under pressure.
    let duplicate = engine.receive(mk_msg("alice", "s1", 1), 1_002);
    assert_eq!(duplicate.code, AckCode::Duplicate);
    assert_eq!(duplicate.ack_id, first.ack_id);
}

#[test]
fn dedup_ttl_expiry_does_not_reset_existing_pending_retry_state() {
    let store = InMemoryReliabilityStore::default();
    let mut engine = ReliabilityEngine::new_with_retention(
        store,
        RetryConfig {
            base_backoff_ms: 10,
            max_backoff_ms: 10,
            ..RetryConfig::default()
        },
        RetentionConfig {
            dedup_ttl_ms: 1,
            pending_ttl_ms: 10_000,
            cleanup_interval_ms: 1,
        },
    );

    let first = engine.receive(mk_msg("alice", "s1", 7), 1_000);
    assert_eq!(first.code, AckCode::Accepted);

    // Dedup memory expires, but retry state is still pending in-session.
    engine.maybe_cleanup(1_010);
    let replay = engine.receive(mk_msg("alice", "s1", 7), 1_011);
    assert_eq!(replay.code, AckCode::Duplicate);
    assert_eq!(replay.detail, "already pending");

    let store = engine.into_store();
    let session = store.get_session("s1").expect("session should exist");
    assert_eq!(
        session.pending.len(),
        1,
        "replay must not overwrite pending state"
    );

    let item = session
        .pending
        .get(&first.ack_id)
        .expect("pending item should keep original ack_id");
    assert_eq!(item.created_at_unix_ms, 1_000);
    assert_eq!(item.attempts, 0);
}

#[test]
fn dedup_quota_allows_refreshing_existing_key_timestamp_at_capacity() {
    let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
        max_dedup_entries: Some(1),
        ..InMemoryReliabilityStoreConfig::default()
    });

    let key = DedupKey {
        from: "alice".to_string(),
        seq_or_nonce: 7,
    };

    assert!(store
        .try_remember_dedup_key_with_ts(key.clone(), 1_000)
        .is_ok());
    assert!(store
        .try_remember_dedup_key_with_ts(key.clone(), 2_000)
        .is_ok());

    let blocked = store.try_remember_dedup_key_with_ts(
        DedupKey {
            from: "bob".to_string(),
            seq_or_nonce: 8,
        },
        2_001,
    );
    assert!(matches!(
        blocked,
        Err(ReliabilityStoreError::CapacityExceeded { .. })
    ));

    assert_eq!(store.dedup.get(&key), Some(&2_000));
}

#[test]
fn empty_session_retained_until_cleanup_ttl() {
    let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
        empty_session_cleanup: EmptySessionCleanupPolicy::RetainForMs(200),
        ..InMemoryReliabilityStoreConfig::default()
    });
    let mut engine = ReliabilityEngine::new_with_retention(
        store,
        RetryConfig::default(),
        RetentionConfig {
            dedup_ttl_ms: 10_000,
            pending_ttl_ms: 10_000,
            cleanup_interval_ms: 1,
        },
    );

    let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);
    assert!(engine.mark_acked("s1", &ack.ack_id));

    // Empty session should still exist before its empty-session ttl elapses.
    let due = engine.collect_due_retries(1_100);
    assert!(due.is_empty());

    let store = engine.into_store();
    assert!(store.get_session("s1").is_some());
}

#[test]
fn empty_session_cleanup_ttl_eventually_reclaims_idle_session() {
    let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
        empty_session_cleanup: EmptySessionCleanupPolicy::RetainForMs(200),
        ..InMemoryReliabilityStoreConfig::default()
    });
    let mut engine = ReliabilityEngine::new_with_retention(
        store,
        RetryConfig::default(),
        RetentionConfig {
            dedup_ttl_ms: 10_000,
            pending_ttl_ms: 10_000,
            cleanup_interval_ms: 1,
        },
    );

    let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);
    assert!(engine.mark_acked("s1", &ack.ack_id));

    // Trigger cleanup at/after TTL so retained empty sessions do not linger
    // and consume quota under prolonged idle periods.
    let due = engine.collect_due_retries(1_201);
    assert!(due.is_empty());

    let store = engine.into_store();
    assert!(store.get_session("s1").is_none());
}

#[test]
fn in_memory_store_lists_sessions_in_stable_sorted_order() {
    let mut store = InMemoryReliabilityStore::default();
    store.upsert_session(SessionState {
        session_id: "s-b".to_string(),
        pending: BTreeMap::new(),
    });
    store.upsert_session(SessionState {
        session_id: "s-a".to_string(),
        pending: BTreeMap::new(),
    });
    store.upsert_session(SessionState {
        session_id: "s-c".to_string(),
        pending: BTreeMap::new(),
    });

    assert_eq!(
        store.list_session_ids(),
        vec!["s-a".to_string(), "s-b".to_string(), "s-c".to_string()]
    );
}

#[test]
fn sqlite_store_open_applies_resilience_pragmas() {
    let unique = format!(
        "trnm-reliability-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix epoch")
            .as_nanos()
    );
    let db_path = std::env::temp_dir().join(unique);

    let store = SqliteReliabilityStore::open(&db_path).expect("open sqlite store");

    let mode: String = store
        .conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .expect("query journal_mode");
    assert_eq!(mode.to_ascii_lowercase(), "wal");

    let busy_timeout_ms: i64 = store
        .conn
        .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
        .expect("query busy_timeout");
    assert_eq!(busy_timeout_ms, 5_000);

    drop(store);
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(db_path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(db_path.with_extension("sqlite-shm"));
}
