use super::*;

#[test]
fn relay_proof_query_rejects_message_gap_in_requested_range() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-gap".into(),
        })
        .unwrap();

    for payload in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
        relay
            .send(RelaySendRequest {
                session_id: "sp-gap".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: payload.to_vec(),
                source: None,
            })
            .unwrap();
    }

    {
        let mut sessions = relay.sessions.lock().expect("relay lock");
        let state = sessions.get_mut("sp-gap").expect("session exists");
        state.queue.retain(|env| env.sequence != 2);
    }

    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "sp-gap".into(),
            from_seq: 1,
            to_seq: 3,
            source: None,
        })
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("session message gap in requested range: expected=3 actual=2"),
        "unexpected err: {err}"
    );
}

#[test]
fn proof_quota_exceeded_has_same_error_code() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::with_risk_quota_config(
        router,
        RiskQuotaConfig {
            window_ms: 1_000,
            per_session_limit: 2,
            per_source_limit: 2,
        },
    );
    relay
        .open(RelayOpenRequest {
            session_id: "proof-s1".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "proof-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("proof-src".into()),
        })
        .unwrap();

    for _ in 0..2 {
        relay
            .query_session_proof(RelaySessionProofQuery {
                task_id: 1,
                session_id: "proof-s1".into(),
                from_seq: 1,
                to_seq: 1,
                source: Some("proof-src".into()),
            })
            .unwrap();
    }
    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("proof-src".into()),
        })
        .unwrap_err();
    assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
}

#[test]
fn challenge_quota_uses_same_limiter_and_error_code() {
    let relay = RelayService::with_risk_quota_config(
        RelayRouter::new(),
        RiskQuotaConfig {
            window_ms: 1_000,
            per_session_limit: 1,
            per_source_limit: 1,
        },
    );
    relay
        .check_challenge_quota("c-s1", Some("challenger-a"))
        .unwrap();
    let err = relay
        .check_challenge_quota("c-s1", Some("challenger-a"))
        .unwrap_err();
    assert!(err.to_string().contains("too_many_requests/quota_exceeded"));
}
