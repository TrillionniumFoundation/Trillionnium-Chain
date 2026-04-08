use trnm_rpc::reliability::{
    AckCode, InMemoryReliabilityStore, ReliabilityEngine, ReliableMessage, RetryConfig,
};

#[test]
fn phase_a_flow_ack_retry_and_idempotency() {
    let mut engine = ReliabilityEngine::new(
        InMemoryReliabilityStore::default(),
        RetryConfig {
            base_backoff_ms: 50,
            max_backoff_ms: 1_000,
            ..RetryConfig::default()
        },
    );

    let msg = ReliableMessage {
        from: "user-42".to_string(),
        chain_id: "trnm-mainnet".to_string(),
        session_id: "sess-a".to_string(),
        seq: Some(1),
        nonce: None,
        msg_type: "INPUT_CHUNK".to_string(),
        payload: "ping".to_string(),
    };

    let ack = engine.receive(msg.clone(), 1_000);
    assert_eq!(ack.code, AckCode::Accepted);

    let dup = engine.receive(msg, 1_010);
    assert_eq!(dup.code, AckCode::Duplicate);

    let retries = engine.collect_due_retries(1_050);
    assert_eq!(retries.len(), 1);
    assert_eq!(retries[0].attempts, 1);

    assert!(engine.mark_acked("sess-a", &ack.ack_id));
    assert!(engine.collect_due_retries(9_999).is_empty());
}
