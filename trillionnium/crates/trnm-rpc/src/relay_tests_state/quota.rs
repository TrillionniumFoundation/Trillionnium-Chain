use super::*;

#[test]
fn relay_quota_lock_poisoning_recovers_and_still_enforces_limits() {
    let relay = super::tiny_quota_relay();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = relay.risk_quota.lock().expect("quota lock");
        panic!("intentional poison for resilience test");
    }));

    relay
        .send(RelaySendRequest {
            session_id: "rq-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("src-poison".into()),
        })
        .expect("first post-poison request should recover");
    relay
        .send(RelaySendRequest {
            session_id: "rq-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("src-poison".into()),
        })
        .expect("second post-poison request should recover");

    let err = relay
        .send(RelaySendRequest {
            session_id: "rq-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("src-poison".into()),
        })
        .unwrap_err();
    assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
}

#[test]
fn relay_quota_exceeded_returns_unified_error_code() {
    let relay = super::tiny_quota_relay();
    for _ in 0..2 {
        relay
            .send(RelaySendRequest {
                session_id: "rq-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-a".into()),
            })
            .unwrap();
    }
    let err = relay
        .send(RelaySendRequest {
            session_id: "rq-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("src-a".into()),
        })
        .unwrap_err();
    assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
}

#[test]
fn relay_quota_resets_after_window() {
    let relay = super::tiny_quota_relay();
    for _ in 0..2 {
        relay
            .send(RelaySendRequest {
                session_id: "rq-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-b".into()),
            })
            .unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(60));
    relay
        .send(RelaySendRequest {
            session_id: "rq-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("src-b".into()),
        })
        .unwrap();
}

#[test]
fn zero_window_quota_config_is_clamped_to_preserve_enforcement() {
    let mut state = RiskQuotaState::default();
    let cfg = RiskQuotaConfig {
        window_ms: 0,
        per_session_limit: 2,
        per_source_limit: 2,
    };

    state
        .consume(1_000, RiskDomain::Relay, "zw-session", "zw-src", &cfg)
        .unwrap();
    state
        .consume(1_000, RiskDomain::Relay, "zw-session", "zw-src", &cfg)
        .unwrap();

    let err = state
        .consume(1_000, RiskDomain::Relay, "zw-session", "zw-src", &cfg)
        .unwrap_err();
    assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
}

#[test]
fn zero_limits_are_clamped_to_preserve_forward_progress() {
    let mut state = RiskQuotaState::default();
    let cfg = RiskQuotaConfig {
        window_ms: 1_000,
        per_session_limit: 0,
        per_source_limit: 0,
    };

    state
        .consume(1_000, RiskDomain::Relay, "zl-session", "zl-source", &cfg)
        .expect("first request should pass because zero limits are clamped to one slot");

    let err = state
        .consume(1_000, RiskDomain::Relay, "zl-session", "zl-source", &cfg)
        .expect_err("second request in same window should hit clamped quota");
    assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
}

#[test]
fn relay_quota_isolated_across_sessions() {
    let relay = super::tiny_quota_relay();
    for _ in 0..2 {
        relay
            .send(RelaySendRequest {
                session_id: "rq-s1".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: Some("src-c".into()),
            })
            .unwrap();
    }
    relay
        .send(RelaySendRequest {
            session_id: "rq-s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("src-d".into()),
        })
        .unwrap();
}

#[test]
fn relay_quota_isolated_across_sources() {
    let relay = super::tiny_quota_relay();
    relay
        .send(RelaySendRequest {
            session_id: "rq-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("src-e1".into()),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "rq-s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("src-e2".into()),
        })
        .unwrap();
}
