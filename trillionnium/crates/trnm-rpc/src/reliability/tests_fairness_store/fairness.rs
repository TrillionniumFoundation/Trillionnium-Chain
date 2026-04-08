use super::*;

#[test]
fn collect_due_retries_caps_per_session_to_reduce_hot_session_starvation() {
    let store = InMemoryReliabilityStore::default();
    let mut engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 1,
            max_backoff_ms: 1,
            ..RetryConfig::default()
        },
    );

    for seq in 1..=80 {
        let ack = engine.receive(mk_msg("alice", "hot", seq), 1_000 + seq as u128);
        assert_eq!(ack.code, AckCode::Accepted);
    }
    for seq in 1..=2 {
        let ack = engine.receive(mk_msg("bob", "cold", seq), 2_000 + seq as u128);
        assert_eq!(ack.code, AckCode::Accepted);
    }

    let first_round = engine.collect_due_retries(10_000);
    let hot_count = first_round
        .iter()
        .filter(|i| i.message.session_id == "hot")
        .count();
    let cold_count = first_round
        .iter()
        .filter(|i| i.message.session_id == "cold")
        .count();

    assert_eq!(hot_count, MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT);
    assert_eq!(cold_count, 2, "cold session should still make progress");

    let second_round = engine.collect_due_retries(10_002);
    let hot_count_second = second_round
        .iter()
        .filter(|i| i.message.session_id == "hot")
        .count();
    assert_eq!(
        hot_count_second, MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT,
        "hot session should stay bounded per collect cycle"
    );
}

#[test]
fn collect_due_retries_applies_global_cap_and_rotates_start_session() {
    let store = InMemoryReliabilityStore::default();
    let mut engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 1,
            max_backoff_ms: 1,
            ..RetryConfig::default()
        },
    );

    // Keep each session small enough to avoid hitting per-session caps; this
    // isolates global-cap and round-robin behavior.
    for seq in 1..=100 {
        let ack = engine.receive(mk_msg("alice", "s-a", seq), 1_000 + seq as u128);
        assert_eq!(ack.code, AckCode::Accepted);
    }
    for seq in 1..=100 {
        let ack = engine.receive(mk_msg("bob", "s-b", seq), 2_000 + seq as u128);
        assert_eq!(ack.code, AckCode::Accepted);
    }
    for seq in 1..=100 {
        let ack = engine.receive(mk_msg("carol", "s-c", seq), 3_000 + seq as u128);
        assert_eq!(ack.code, AckCode::Accepted);
    }
    for seq in 1..=100 {
        let ack = engine.receive(mk_msg("dave", "s-d", seq), 4_000 + seq as u128);
        assert_eq!(ack.code, AckCode::Accepted);
    }
    for seq in 1..=100 {
        let ack = engine.receive(mk_msg("erin", "s-e", seq), 5_000 + seq as u128);
        assert_eq!(ack.code, AckCode::Accepted);
    }

    let first = engine.collect_due_retries(10_000);
    assert_eq!(
        first.len(),
        MAX_DUE_RETRIES_PER_COLLECT,
        "global cap should bound one collect cycle"
    );

    let first_front = first.first().expect("first batch not empty");
    assert_eq!(first_front.message.session_id, "s-a");

    let second = engine.collect_due_retries(10_001);
    assert_eq!(
        second.len(),
        MAX_DUE_RETRIES_PER_COLLECT,
        "global cap should remain stable across rounds"
    );

    let second_front = second.first().expect("second batch not empty");
    assert_eq!(
        second_front.message.session_id, "s-b",
        "round-robin session rotation should avoid fixed first-session bias"
    );
}

#[test]
fn collect_due_retries_cursor_handles_session_churn_without_stalling_other_sessions() {
    let store = InMemoryReliabilityStore::default();
    let mut engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 1,
            max_backoff_ms: 1,
            ..RetryConfig::default()
        },
    );

    let hot_ack = engine.receive(mk_msg("alice", "s-a", 1), 1_000);
    assert_eq!(hot_ack.code, AckCode::Accepted);
    let cold_ack = engine.receive(mk_msg("bob", "s-b", 1), 1_001);
    assert_eq!(cold_ack.code, AckCode::Accepted);

    let first = engine.collect_due_retries(2_000);
    assert_eq!(
        first.first().map(|i| i.message.session_id.as_str()),
        Some("s-a")
    );

    // Simulate session churn: one lane drains/acks fully while another lane remains hot.
    assert!(engine.mark_acked("s-a", &hot_ack.ack_id));

    let second = engine.collect_due_retries(2_001);
    assert_eq!(
        second.first().map(|i| i.message.session_id.as_str()),
        Some("s-b"),
        "round-robin cursor should rebase on the active session set"
    );
}

#[test]
fn global_cap_round_robin_still_grants_new_cold_session_a_turn_next_cycle() {
    let store = InMemoryReliabilityStore::default();
    let mut engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 1,
            max_backoff_ms: 1,
            ..RetryConfig::default()
        },
    );

    // Start with one hot session so cursor is pinned to zero in the single-session path.
    for seq in 1..=(MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT as u64 + 8) {
        let ack = engine.receive(mk_msg("alice", "s-hot", seq), 1_000 + seq as u128);
        assert_eq!(ack.code, AckCode::Accepted);
    }
    let first = engine.collect_due_retries(2_000);
    assert_eq!(first.len(), MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT);
    assert!(first.iter().all(|item| item.message.session_id == "s-hot"));

    // A new cold session should not be starved indefinitely by the global cap:
    // after one capped cycle, round-robin rotation must give it front-of-batch priority.
    let cold = engine.receive(mk_msg("bob", "s-cold", 1), 2_001);
    assert_eq!(cold.code, AckCode::Accepted);

    let second = engine.collect_due_retries(2_002);
    assert_eq!(
        second.first().map(|item| item.message.session_id.as_str()),
        Some("s-cold"),
        "new cold session should get first dispatch on the next collect cycle"
    );
}

#[test]
fn collect_due_retries_single_session_keeps_cursor_stable_at_zero() {
    let store = InMemoryReliabilityStore::default();
    let mut engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 1,
            max_backoff_ms: 1,
            ..RetryConfig::default()
        },
    );

    let ack = engine.receive(mk_msg("alice", "s-a", 1), 1_000);
    assert_eq!(ack.code, AckCode::Accepted);

    engine.collect_rr_cursor = usize::MAX;
    let first = engine.collect_due_retries(2_000);
    assert_eq!(first.len(), 1);
    assert_eq!(engine.collect_rr_cursor, 0);

    let second = engine.collect_due_retries(2_001);
    assert_eq!(second.len(), 1);
    assert_eq!(engine.collect_rr_cursor, 0);
}

#[test]
fn collect_due_retries_cursor_wraps_without_overflow_panic() {
    let store = InMemoryReliabilityStore::default();
    let mut engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 1,
            max_backoff_ms: 1,
            ..RetryConfig::default()
        },
    );

    let ack_a = engine.receive(mk_msg("alice", "s-a", 1), 1_000);
    let ack_b = engine.receive(mk_msg("bob", "s-b", 1), 1_001);
    assert_eq!(ack_a.code, AckCode::Accepted);
    assert_eq!(ack_b.code, AckCode::Accepted);

    engine.collect_rr_cursor = usize::MAX;

    let due = engine.collect_due_retries(2_000);
    assert_eq!(
        due.first().map(|i| i.message.session_id.as_str()),
        Some("s-b"),
        "wrapped cursor should still produce deterministic modulo rotation"
    );

    assert_eq!(engine.collect_rr_cursor, 0);
}

#[test]
fn collect_due_retries_resets_cursor_after_idle_full_drain() {
    let store = InMemoryReliabilityStore::default();
    let mut engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 1,
            max_backoff_ms: 1,
            ..RetryConfig::default()
        },
    );

    let ack = engine.receive(mk_msg("alice", "s-a", 1), 1_000);
    assert_eq!(ack.code, AckCode::Accepted);

    engine.collect_rr_cursor = usize::MAX;
    assert!(engine.mark_acked("s-a", &ack.ack_id));

    let idle = engine.collect_due_retries(2_000);
    assert!(idle.is_empty());
    assert_eq!(
        engine.collect_rr_cursor, 0,
        "idle collect should reset stale cursor state"
    );

    let cold = engine.receive(mk_msg("bob", "s-b", 1), 2_001);
    assert_eq!(cold.code, AckCode::Accepted);
    let due = engine.collect_due_retries(2_002);
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].message.session_id, "s-b");
}

#[test]
fn collect_due_retries_drops_session_when_retry_state_persist_fails() {
    let mut store = FailingUpsertStore::default();
    store.fail_upsert = true;
    let mut engine = ReliabilityEngine::new(
        store,
        RetryConfig {
            base_backoff_ms: 1,
            max_backoff_ms: 1,
            ..RetryConfig::default()
        },
    );

    // Seed one pending item while upsert failures are disabled.
    engine.store.fail_upsert = false;
    let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);
    assert_eq!(ack.code, AckCode::Accepted);

    // Inject persistence failure for the collect/update pass.
    engine.store.fail_upsert = true;
    let due = engine.collect_due_retries(2_000);
    assert_eq!(due.len(), 1, "first due retry still dispatches once");

    let store = engine.into_store();
    assert!(
        store.get_session("s1").is_none(),
        "failed retry-state persist should drop session to avoid retry storms"
    );
}
