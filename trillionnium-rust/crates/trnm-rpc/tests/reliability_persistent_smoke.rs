use std::env;
use std::path::PathBuf;

use trnm_rpc::reliability::{
    AckCode, ReliabilityEngine, ReliableMessage, RetryConfig, SqliteReliabilityStore,
};

#[test]
fn reliability_persistent_store_smoke() {
    let store_kind = env::var("RELIABILITY_STORE").unwrap_or_else(|_| "memory".to_string());
    if store_kind != "sqlite" {
        eprintln!("[skip] RELIABILITY_STORE={store_kind}, skip sqlite smoke");
        return;
    }

    let db_path = env::var("RELIABILITY_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/trnm-reliability-phasea-smoke.sqlite"));

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).expect("create db parent");
    }
    if db_path.exists() {
        std::fs::remove_file(&db_path).expect("remove stale db");
    }

    // First engine instance writes accepted record.
    let mut engine = ReliabilityEngine::new(
        SqliteReliabilityStore::open(&db_path).expect("open sqlite store"),
        RetryConfig::default(),
    );

    let msg = ReliableMessage {
        from: "user-42".to_string(),
        session_id: "sess-persist".to_string(),
        seq: Some(7),
        nonce: None,
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
