    #[test]
    fn retry_uses_exponential_backoff() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 100,
                max_backoff_ms: 800,
                ..RetryConfig::default()
            },
        );

        let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        let first = engine.collect_due_retries(1_100);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].attempts, 1);
        assert_eq!(first[0].ack_id, ack.ack_id);

        let second = engine.collect_due_retries(1_200);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].attempts, 2);

        let third = engine.collect_due_retries(1_400);
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].attempts, 3);
    }

    #[test]
    fn exp_backoff_saturates_without_overflow_for_large_bases() {
        // Regression guard for free-ingress throughput gates: malformed retry config
        // must not overflow into tiny delays that can trigger retry storms.
        let capped = exp_backoff_ms(u64::MAX - 7, u64::MAX - 3, 32);
        assert_eq!(capped, u64::MAX - 3);

        let exact_first_attempt = exp_backoff_ms(u64::MAX - 7, u64::MAX, 1);
        assert_eq!(exact_first_attempt, u64::MAX - 7);
    }

    #[test]
    fn max_attempts_stops_retrying_and_drops_pending() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 100,
                max_backoff_ms: 800,
                max_attempts: 2,
                ..RetryConfig::default()
            },
        );

        let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);

        let first = engine.collect_due_retries(1_100);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].attempts, 1);

        let second = engine.collect_due_retries(1_200);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].attempts, 2);

        let third = engine.collect_due_retries(1_400);
        assert!(third.is_empty(), "must stop retrying after max_attempts");
        assert_eq!(engine.retry_exhausted_total(), 1);

        let store = engine.into_store();
        let session = store.get_session("s1");
        assert!(
            session.is_none(),
            "pending item should be dropped after max attempts"
        );

        assert_eq!(ack.ack_id, "ack_alice_1");
    }

    #[test]
    fn circuit_breaker_opens_and_recovers_after_window() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 100,
                max_backoff_ms: 800,
                max_attempts: 1,
                circuit_breaker_threshold: 1,
                circuit_open_ms: 300,
            },
        );

        engine.receive(mk_msg("alice", "s1", 1), 1_000);

        let first = engine.collect_due_retries(1_100);
        assert_eq!(first.len(), 1);
        assert_eq!(engine.circuit_state(), CircuitState::Closed);

        let exhausted_round = engine.collect_due_retries(1_200);
        assert!(exhausted_round.is_empty());
        assert_eq!(engine.retry_exhausted_total(), 1);
        assert_eq!(engine.circuit_open_total(), 1);
        assert_eq!(
            engine.circuit_state(),
            CircuitState::Open {
                until_unix_ms: 1_500
            }
        );

        engine.receive(mk_msg("bob", "s2", 1), 1_250);
        let blocked = engine.collect_due_retries(1_350);
        assert!(blocked.is_empty());

        let recovered = engine.collect_due_retries(1_550);
        assert_eq!(engine.circuit_state(), CircuitState::Closed);
        assert_eq!(engine.circuit_recovered_total(), 1);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].ack_id, "ack_bob_1");
    }

    #[test]
    fn mark_acked_removes_pending() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());
        let ack = engine.receive(mk_msg("alice", "sess", 3), 1_000);

        assert!(engine.mark_acked("sess", &ack.ack_id));

        let retries = engine.collect_due_retries(10_000);
        assert!(retries.is_empty());
    }

    #[test]
    fn cleanup_expires_dedup_and_accepts_again_after_ttl() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new_with_retention(
            store,
            RetryConfig::default(),
            RetentionConfig {
                dedup_ttl_ms: 100,
                pending_ttl_ms: 10_000,
                cleanup_interval_ms: 1,
            },
        );

        let first = engine.receive(mk_msg("alice", "s1", 9), 1_000);
        assert_eq!(first.code, AckCode::Accepted);

        let dup = engine.receive(mk_msg("alice", "s1", 9), 1_050);
        assert_eq!(dup.code, AckCode::Duplicate);

        // This test isolates dedup-TTL expiry after the original delivery has been
        // fully acknowledged. Pending retry state is covered separately below and
        // must still reject replays even after dedup memory ages out.
        assert!(engine.mark_acked("s1", &first.ack_id));

        let after_ttl = engine.receive(mk_msg("alice", "s1", 9), 1_101);
        assert_eq!(after_ttl.code, AckCode::Accepted);
    }

    #[test]
    fn cleanup_preserves_legacy_dedup_entries_without_timestamp() {
        let mut store = InMemoryReliabilityStore::default();
        let key = DedupKey {
            from: "legacy".to_string(),
            seq_or_nonce: 77,
        };
        store.remember_dedup_key(key.clone()); // seen_at=0 legacy path

        store.cleanup_expired(
            10_000,
            &RetentionConfig {
                dedup_ttl_ms: 100,
                pending_ttl_ms: 10_000,
                cleanup_interval_ms: 1,
            },
        );

        assert!(
            store.contains_dedup_key(&key),
            "legacy seen_at=0 dedup entry should remain until rewritten with a timestamp"
        );
    }

    #[test]
    fn cleanup_drops_only_expired_pending_items() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new_with_retention(
            store,
            RetryConfig {
                base_backoff_ms: 100,
                max_backoff_ms: 1_000,
                ..RetryConfig::default()
            },
            RetentionConfig {
                dedup_ttl_ms: 10_000,
                pending_ttl_ms: 500,
                cleanup_interval_ms: 1,
            },
        );

        let old = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        let fresh = engine.receive(mk_msg("alice", "s1", 2), 1_300);

        let due = engine.collect_due_retries(1_499);
        assert_eq!(due.len(), 2, "before ttl cutoff both should stay");

        let due_after_cleanup = engine.collect_due_retries(1_600);
        assert_eq!(
            due_after_cleanup.len(),
            1,
            "expired pending must be removed"
        );
        assert_eq!(
            due_after_cleanup[0].ack_id, fresh.ack_id,
            "fresh item must remain"
        );
        assert_ne!(due_after_cleanup[0].ack_id, old.ack_id);
    }

    #[test]
    fn capacity_limit_returns_bad_request_with_detail() {
        let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            max_sessions: Some(1),
            ..InMemoryReliabilityStoreConfig::default()
        });
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let ok = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        assert_eq!(ok.code, AckCode::Accepted);

        let blocked = engine.receive(mk_msg("bob", "s2", 1), 1_001);
        assert_eq!(blocked.code, AckCode::BadRequest);
        assert!(blocked.detail.contains("capacity_exceeded"));
    }

