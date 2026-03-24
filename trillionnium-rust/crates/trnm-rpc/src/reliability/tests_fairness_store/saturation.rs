use super::*;
use std::sync::atomic::Ordering;

#[test]
fn store_config_clamps_zero_dedup_quota_to_keep_one_idempotency_slot_live() {
    let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
        max_dedup_entries: Some(0),
        ..InMemoryReliabilityStoreConfig::default()
    });

    let key1 = DedupKey {
        from: "alice".to_string(),
        seq_or_nonce: 1,
    };
    let key2 = DedupKey {
        from: "bob".to_string(),
        seq_or_nonce: 1,
    };

    assert!(store.try_remember_dedup_key_with_ts(key1, 1).is_ok());
    let err = store
        .try_remember_dedup_key_with_ts(key2, 2)
        .expect_err("second unique key should hit clamped quota");
    assert!(matches!(
        err,
        ReliabilityStoreError::CapacityExceeded { .. }
    ));
}

#[test]
fn store_config_clamps_zero_session_limit_to_preserve_forward_progress() {
    let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
        max_sessions: Some(0),
        ..InMemoryReliabilityStoreConfig::default()
    });

    let session = SessionState {
        session_id: "s1".to_string(),
        pending: BTreeMap::new(),
    };

    assert!(store.try_upsert_session_with_ts(session, 1).is_ok());
    assert_eq!(store.list_session_ids(), vec!["s1".to_string()]);
}

#[test]
fn store_config_clamps_per_session_pending_quota_to_global_total_cap() {
    let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
        max_pending_per_session: Some(5),
        max_pending_total: Some(2),
        ..InMemoryReliabilityStoreConfig::default()
    });

    let mk_pending = |ack_id: &str| PendingItem {
        ack_id: ack_id.to_string(),
        message: ReliableMessage {
            from: "alice".to_string(),
            chain_id: "trnm-testnet".to_string(),
            session_id: "s1".to_string(),
            seq: Some(1),
            nonce: None,
            msg_type: "INPUT_CHUNK".to_string(),
            payload: "x".to_string(),
        },
        attempts: 0,
        created_at_unix_ms: 1,
        next_retry_at_unix_ms: 1,
    };

    let mut two_pending = BTreeMap::new();
    two_pending.insert("ack-1".to_string(), mk_pending("ack-1"));
    two_pending.insert("ack-2".to_string(), mk_pending("ack-2"));
    let two = SessionState {
        session_id: "s1".to_string(),
        pending: two_pending,
    };
    assert!(store.try_upsert_session_with_ts(two, 1).is_ok());

    let mut three_pending = BTreeMap::new();
    three_pending.insert("ack-1".to_string(), mk_pending("ack-1"));
    three_pending.insert("ack-2".to_string(), mk_pending("ack-2"));
    three_pending.insert("ack-3".to_string(), mk_pending("ack-3"));
    let three = SessionState {
        session_id: "s1".to_string(),
        pending: three_pending,
    };

    let err = store
        .try_upsert_session_with_ts(three, 2)
        .expect_err("per-session quota should be clamped to global total cap");
    assert!(matches!(
        err,
        ReliabilityStoreError::CapacityExceeded { .. }
    ));
}

#[test]
fn store_config_clamps_zero_pending_quotas_to_keep_ingress_live() {
    let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
        max_pending_per_session: Some(0),
        max_pending_total: Some(0),
        ..InMemoryReliabilityStoreConfig::default()
    });

    let mk_pending = |ack_id: &str| PendingItem {
        ack_id: ack_id.to_string(),
        message: ReliableMessage {
            from: "alice".to_string(),
            chain_id: "trnm-testnet".to_string(),
            session_id: "s1".to_string(),
            seq: Some(1),
            nonce: None,
            msg_type: "INPUT_CHUNK".to_string(),
            payload: "x".to_string(),
        },
        attempts: 0,
        created_at_unix_ms: 1,
        next_retry_at_unix_ms: 1,
    };

    let mut first_pending = BTreeMap::new();
    first_pending.insert("ack-1".to_string(), mk_pending("ack-1"));
    let first = SessionState {
        session_id: "s1".to_string(),
        pending: first_pending,
    };
    assert!(store.try_upsert_session_with_ts(first, 1).is_ok());

    let mut second_pending = BTreeMap::new();
    second_pending.insert("ack-2".to_string(), mk_pending("ack-2"));
    let second = SessionState {
        session_id: "s2".to_string(),
        pending: second_pending,
    };
    let err = store
        .try_upsert_session_with_ts(second, 2)
        .expect_err("second pending item should hit clamped global quota");
    assert!(matches!(
        err,
        ReliabilityStoreError::CapacityExceeded { .. }
    ));
}

#[test]
fn pending_total_quota_does_not_block_empty_session_touch_at_capacity() {
    let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
        max_pending_total: Some(1),
        ..InMemoryReliabilityStoreConfig::default()
    });

    let mut pending = BTreeMap::new();
    pending.insert(
        "ack-1".to_string(),
        PendingItem {
            ack_id: "ack-1".to_string(),
            message: ReliableMessage {
                from: "alice".to_string(),
                chain_id: "trnm-testnet".to_string(),
                session_id: "s1".to_string(),
                seq: Some(1),
                nonce: None,
                msg_type: "INPUT_CHUNK".to_string(),
                payload: "x".to_string(),
            },
            attempts: 0,
            created_at_unix_ms: 1,
            next_retry_at_unix_ms: 1,
        },
    );

    assert!(store
        .try_upsert_session_with_ts(
            SessionState {
                session_id: "s1".to_string(),
                pending,
            },
            1,
        )
        .is_ok());

    assert!(store
        .try_upsert_session_with_ts(
            SessionState {
                session_id: "s2".to_string(),
                pending: BTreeMap::new(),
            },
            2,
        )
        .is_ok());
}

#[test]
fn store_config_clamps_zero_empty_session_retention_window() {
    let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
        empty_session_cleanup: EmptySessionCleanupPolicy::RetainForMs(0),
        ..InMemoryReliabilityStoreConfig::default()
    });

    assert!(matches!(
        store.config.empty_session_cleanup,
        EmptySessionCleanupPolicy::RetainForMs(1)
    ));
}

#[test]
fn collect_retry_cursor_wraps_safely_from_usize_max() {
    let store = InMemoryReliabilityStore::default();
    let mut engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 1,
            max_backoff_ms: 1,
            ..RetryConfig::default()
        },
    );

    engine.collect_rr_cursor = usize::MAX;
    let start = engine.advance_collect_rr_cursor(5);

    assert_eq!(start, usize::MAX % 5);
    assert_eq!(engine.collect_rr_cursor, 0);
}

#[test]
fn retry_exhausted_total_increment_saturates_at_u64_max() {
    let store = InMemoryReliabilityStore::default();
    let engine = ReliabilityEngine::new(store, RetryConfig::default());

    engine
        .retry_exhausted_total
        .store(u64::MAX, Ordering::Relaxed);
    engine.increment_retry_exhausted_total();

    assert_eq!(engine.retry_exhausted_total(), u64::MAX);
}

#[test]
fn circuit_counters_increment_saturates_at_u64_max() {
    let store = InMemoryReliabilityStore::default();
    let engine = ReliabilityEngine::new(store, RetryConfig::default());

    engine.circuit_open_total.store(u64::MAX, Ordering::Relaxed);
    ReliabilityEngine::<InMemoryReliabilityStore>::increment_atomic_saturating(
        &engine.circuit_open_total,
    );
    assert_eq!(engine.circuit_open_total(), u64::MAX);

    engine
        .circuit_recovered_total
        .store(u64::MAX, Ordering::Relaxed);
    ReliabilityEngine::<InMemoryReliabilityStore>::increment_atomic_saturating(
        &engine.circuit_recovered_total,
    );
    assert_eq!(engine.circuit_recovered_total(), u64::MAX);
}
