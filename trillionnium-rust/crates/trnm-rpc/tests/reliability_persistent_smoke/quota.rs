use super::*;

#[test]
fn sqlite_store_quota_rejects_new_sessions_once_session_limit_is_hit() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("reliability-session-limit.db");
    let store = SqliteReliabilityStore::open_with_config(
        &db_path,
        InMemoryReliabilityStoreConfig {
            max_sessions: Some(1),
            max_pending_total: Some(8),
            max_pending_per_session: Some(8),
            max_dedup_entries: Some(8),
            ..InMemoryReliabilityStoreConfig::default()
        },
    )
    .expect("open sqlite store");
    let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

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

    let second = ReliableMessage {
        from: "bob".to_string(),
        chain_id: "trnm-mainnet".to_string(),
        session_id: "s2".to_string(),
        seq: Some(1),
        nonce: None,
        msg_type: "INPUT_CHUNK".to_string(),
        payload: "two".to_string(),
    };
    let ack = engine.receive(second, 2);
    assert_eq!(ack.code, AckCode::BadRequest);
    assert!(ack.detail.contains("session limit reached (1)"));
}

#[test]
fn sqlite_store_quota_rejects_new_dedup_domains_at_capacity_but_keeps_duplicate_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("reliability-dedup-limit.db");
    let store = SqliteReliabilityStore::open_with_config(
        &db_path,
        InMemoryReliabilityStoreConfig {
            max_sessions: Some(8),
            max_pending_total: Some(8),
            max_pending_per_session: Some(8),
            max_dedup_entries: Some(1),
            ..InMemoryReliabilityStoreConfig::default()
        },
    )
    .expect("open sqlite store");
    let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

    let msg = ReliableMessage {
        from: "alice".to_string(),
        chain_id: "trnm-mainnet".to_string(),
        session_id: "s1".to_string(),
        seq: Some(1),
        nonce: None,
        msg_type: "INPUT_CHUNK".to_string(),
        payload: "one".to_string(),
    };
    assert_eq!(engine.receive(msg.clone(), 1).code, AckCode::Accepted);

    let blocked = ReliableMessage {
        from: "bob".to_string(),
        chain_id: "trnm-mainnet".to_string(),
        session_id: "s2".to_string(),
        seq: Some(1),
        nonce: None,
        msg_type: "INPUT_CHUNK".to_string(),
        payload: "two".to_string(),
    };
    let blocked_ack = engine.receive(blocked, 2);
    assert_eq!(blocked_ack.code, AckCode::BadRequest);
    assert!(blocked_ack.detail.contains("dedup limit reached (1)"));

    let dup = engine.receive(msg, 3);
    assert_eq!(dup.code, AckCode::Duplicate);
}
