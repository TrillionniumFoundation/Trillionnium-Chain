use super::*;

#[test]
fn source_quota_rejection_rolls_back_session_counter_to_avoid_false_backpressure() {
    let mut state = RiskQuotaState::default();
    let cfg = RiskQuotaConfig {
        window_ms: 1_000,
        per_session_limit: 3,
        per_source_limit: 1,
    };

    state
        .consume(1_000, RiskDomain::Relay, "rb-session", "src-a", &cfg)
        .expect("seed consume");

    let err = state
        .consume(1_000, RiskDomain::Relay, "rb-session", "src-a", &cfg)
        .expect_err("second consume should hit per-source quota");
    assert!(err.to_string().contains("too_many_requests/quota_exceeded"));

    state
        .consume(1_000, RiskDomain::Relay, "rb-session", "src-b", &cfg)
        .expect("source-b should pass after rollback");
    state
        .consume(1_000, RiskDomain::Relay, "rb-session", "src-c", &cfg)
        .expect("source-c should pass after rollback");
}

#[test]
fn quota_keyspace_has_domain_cap_with_expired_bucket_pruning() {
    let mut state = RiskQuotaState::default();
    let cfg = RiskQuotaConfig {
        window_ms: 50,
        per_session_limit: u32::MAX,
        per_source_limit: u32::MAX,
    };

    for i in 0..MAX_RISK_BUCKET_KEYS_PER_DOMAIN {
        state
            .consume(
                1_000,
                RiskDomain::Relay,
                "ks-session",
                &format!("src-{i}"),
                &cfg,
            )
            .unwrap();
    }

    let err = state
        .consume(1_000, RiskDomain::Relay, "ks-session", "src-over-cap", &cfg)
        .unwrap_err();
    assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
    assert!(err.to_string().contains("keyspace_exhausted"));

    state
        .consume(
            1_100,
            RiskDomain::Relay,
            "ks-session",
            "src-after-window",
            &cfg,
        )
        .unwrap();
}

#[test]
fn source_attribution_is_canonicalized_for_quota_boundaries() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::with_risk_quota_config(
        router,
        RiskQuotaConfig {
            window_ms: 1_000,
            per_session_limit: 5,
            per_source_limit: 2,
        },
    );
    relay
        .open(RelayOpenRequest {
            session_id: "mv-src-s1".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "mv-src-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"a".to_vec(),
            source: Some("mv-src".into()),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "mv-src-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"b".to_vec(),
            source: Some("  mv-src  ".into()),
        })
        .unwrap();
    let trimmed_alias_err = relay
        .send(RelaySendRequest {
            session_id: "mv-src-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"c".to_vec(),
            source: Some("mv-src".into()),
        })
        .unwrap_err();
    assert!(trimmed_alias_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));

    relay
        .send(RelaySendRequest {
            session_id: "mv-src-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"d".to_vec(),
            source: None,
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "mv-src-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"e".to_vec(),
            source: Some("   \t\n".into()),
        })
        .unwrap();
    let anon_alias_err = relay
        .send(RelaySendRequest {
            session_id: "mv-src-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"f".to_vec(),
            source: Some("".into()),
        })
        .unwrap_err();
    assert!(anon_alias_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));

    relay
        .open(RelayOpenRequest {
            session_id: "mv-src-s2".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "mv-src-s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"ws-a".to_vec(),
            source: Some("worker   lane".into()),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "mv-src-s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"ws-b".to_vec(),
            source: Some("worker lane".into()),
        })
        .unwrap();
    let ws_alias_err = relay
        .send(RelaySendRequest {
            session_id: "mv-src-s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"ws-c".to_vec(),
            source: Some("worker\t\nlane".into()),
        })
        .unwrap_err();
    assert!(ws_alias_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));

    relay
        .open(RelayOpenRequest {
            session_id: "mv-src-s3".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "mv-src-s3".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"g".to_vec(),
            source: Some("CaseMixSrc".into()),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "mv-src-s3".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"h".to_vec(),
            source: Some("casemixsrc".into()),
        })
        .unwrap();
    let case_alias_err = relay
        .send(RelaySendRequest {
            session_id: "mv-src-s3".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"i".to_vec(),
            source: Some("CASEMIXSRC".into()),
        })
        .unwrap_err();
    assert!(case_alias_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));
}

#[test]
fn source_attribution_overlong_values_share_truncated_quota_bucket() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::with_risk_quota_config(
        router,
        RiskQuotaConfig {
            window_ms: 1_000,
            per_session_limit: 5,
            per_source_limit: 2,
        },
    );
    relay
        .open(RelayOpenRequest {
            session_id: "mv-src-s3".into(),
        })
        .unwrap();

    let prefix = "X".repeat(RISK_SOURCE_MAX_CHARS);
    let src_a = format!("{}-A", prefix);
    let src_b = format!("{}-B", prefix);

    relay
        .send(RelaySendRequest {
            session_id: "mv-src-s3".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"a".to_vec(),
            source: Some(src_a),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "mv-src-s3".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"b".to_vec(),
            source: Some(src_b),
        })
        .unwrap();

    let err = relay
        .send(RelaySendRequest {
            session_id: "mv-src-s3".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"c".to_vec(),
            source: Some(format!("{}-C", prefix)),
        })
        .unwrap_err();
    assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
}
