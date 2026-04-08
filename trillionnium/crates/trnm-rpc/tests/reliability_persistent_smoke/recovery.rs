use super::*;

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
