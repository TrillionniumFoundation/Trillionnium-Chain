use trnm_rpc::reliability::{
    AckCode, ReliabilityEngine, ReliabilityStoreMode, ReliableMessage, RetryConfig,
    SqliteReliabilityStore,
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
