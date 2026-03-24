    #[test]
    fn dedup_by_from_and_seq() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let a1 = engine.receive(mk_msg("alice", "s1", 7), 1_000);
        assert_eq!(a1.code, AckCode::Accepted);

        let a2 = engine.receive(mk_msg("alice", "s1", 7), 1_010);
        assert_eq!(a2.code, AckCode::Duplicate);

        let a3 = engine.receive(mk_msg("bob", "s1", 7), 1_020);
        assert_eq!(
            a3.code,
            AckCode::Accepted,
            "different from should not dedup"
        );
    }

    #[test]
    fn reject_missing_chain_id_or_seq_for_critical_message() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let mut missing_chain = mk_msg("alice", "s1", 1);
        missing_chain.chain_id.clear();
        let ack = engine.receive(missing_chain, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("missing chain_id"));

        let mut missing_from = mk_msg("alice", "s1", 1);
        missing_from.from = "   ".to_string();
        let ack = engine.receive(missing_from, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("missing from"));

        let mut missing_seq = mk_msg("alice", "s1", 1);
        missing_seq.seq = None;
        missing_seq.nonce = Some(99);
        let ack = engine.receive(missing_seq, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("missing seq"));
    }

    #[test]
    fn rejects_non_canonical_whitespace_wrapped_msg_type() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "alice".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: None,
            nonce: Some(77),
            msg_type: "  ACK  ".to_string(),
            payload: "ok".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical msg_type"));
    }

    #[test]
    fn rejects_non_canonical_msg_type_case_variant_to_prevent_strict_field_bypass() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "alice".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: None,
            nonce: Some(77),
            msg_type: "ack".to_string(),
            payload: "ok".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical msg_type"));
    }

    #[test]
    fn rejects_non_canonical_identifier_whitespace_to_prevent_replay_namespace_bypass() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: " alice ".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: Some(1),
            nonce: None,
            msg_type: "INPUT_CHUNK".to_string(),
            payload: "hello".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical identifier"));
    }

    #[test]
    fn rejects_non_canonical_identifier_with_control_chars() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "alice\n".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: Some(1),
            nonce: None,
            msg_type: "INPUT_CHUNK".to_string(),
            payload: "hello".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical identifier"));
    }

    #[test]
    fn rejects_non_canonical_msg_type_with_control_chars() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "alice".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: None,
            nonce: Some(7),
            msg_type: "ACK\n".to_string(),
            payload: "ok".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical msg_type"));
    }

    #[test]
    fn legacy_message_without_msg_type_allows_nonce_path() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "legacy-sender".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "legacy-session".to_string(),
            seq: None,
            nonce: Some(7),
            msg_type: String::new(),
            payload: "legacy".to_string(),
        };
        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::Accepted);
    }

    #[test]
    fn rejects_ambiguous_dual_seq_and_nonce_to_harden_replay_migration() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "legacy-sender".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "legacy-session".to_string(),
            seq: Some(7),
            nonce: Some(7),
            msg_type: String::new(),
            payload: "legacy".to_string(),
        };
        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("ambiguous seq/nonce"));
    }

    #[test]
    fn rejects_zero_seq_or_nonce_to_harden_replay_namespace() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let mut msg = mk_msg("alice", "s1", 0);
        let ack = engine.receive(msg.clone(), 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("invalid zero seq/nonce"));

        msg.seq = None;
        msg.nonce = Some(0);
        msg.msg_type = String::new();
        let ack = engine.receive(msg, 1_001);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("invalid zero seq/nonce"));
    }

