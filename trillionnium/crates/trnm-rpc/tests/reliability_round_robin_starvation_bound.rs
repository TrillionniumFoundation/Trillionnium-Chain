use trnm_rpc::reliability::{
    AckCode, InMemoryReliabilityStore, ReliabilityEngine, ReliableMessage, RetryConfig,
};

fn mk_msg(from: &str, session_id: &str, seq: u64) -> ReliableMessage {
    ReliableMessage {
        from: from.to_string(),
        chain_id: "trnm-mainnet".to_string(),
        session_id: session_id.to_string(),
        seq: Some(seq),
        nonce: None,
        msg_type: "INPUT_CHUNK".to_string(),
        payload: "hello".to_string(),
    }
}

#[test]
fn global_retry_cap_rotates_start_session_and_prevents_long_tail_starvation() {
    let store = InMemoryReliabilityStore::default();
    let mut engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 1,
            max_backoff_ms: 1,
            ..RetryConfig::default()
        },
    );

    // 5 sessions * 80 pending each = 400 due items.
    // One collect cycle is globally capped at 256 and per-session capped at 64,
    // so the first cycle cannot include all sessions.
    let sessions = ["s-a", "s-b", "s-c", "s-d", "s-e"];
    for (sid_idx, sid) in sessions.iter().enumerate() {
        for seq in 1..=80u64 {
            let ack = engine.receive(
                mk_msg(&format!("sender-{sid_idx}"), sid, seq),
                1_000 + sid_idx as u128 * 10_000 + seq as u128,
            );
            assert_eq!(ack.code, AckCode::Accepted);
        }
    }

    let first = engine.collect_due_retries(100_000);
    let first_sessions: std::collections::HashSet<_> = first
        .iter()
        .map(|i| i.message.session_id.as_str())
        .collect();
    assert_eq!(first.len(), 256);
    assert!(
        !first_sessions.contains("s-e"),
        "last session should miss the first globally-capped cycle"
    );

    // Cursor rotation should bring the previously starved tail session into the
    // very next cycle instead of keeping a fixed-start bias.
    let second = engine.collect_due_retries(100_001);
    let second_sessions: std::collections::HashSet<_> = second
        .iter()
        .map(|i| i.message.session_id.as_str())
        .collect();
    assert!(
        second_sessions.contains("s-e"),
        "rotated start must let previously skipped tail session make progress"
    );
}
