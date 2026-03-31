use super::*;

#[test]
fn proof_quota_source_attribution_aliases_share_boundary() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::with_risk_quota_config(
        router,
        RiskQuotaConfig {
            window_ms: 1_000,
            per_session_limit: 9,
            per_source_limit: 2,
        },
    );
    relay
        .open(RelayOpenRequest {
            session_id: "proof-src-s1".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "proof-src-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("seed".into()),
        })
        .unwrap();

    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("proof-src".into()),
        })
        .unwrap();
    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("  `\"proof-src\"`  ".into()),
        })
        .unwrap();
    let trimmed_alias_err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("proof-src".into()),
        })
        .unwrap_err();
    assert!(trimmed_alias_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));

    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("«proof-src»".into()),
        })
        .unwrap();
    let unicode_wrapped_alias_err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("proof-src".into()),
        })
        .unwrap_err();
    assert!(unicode_wrapped_alias_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));

    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("proof\u{200B}src".into()),
        })
        .unwrap();
    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("PROOF\u{2060}SRC".into()),
        })
        .unwrap();
    let invisible_alias_err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("proof src".into()),
        })
        .unwrap_err();
    assert!(invisible_alias_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));

    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: None,
        })
        .unwrap();
    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("\t \n".into()),
        })
        .unwrap();
    let anon_alias_err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-src-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("".into()),
        })
        .unwrap_err();
    assert!(anon_alias_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));
}

#[test]
fn proof_quota_source_attribution_tag_noise_aliases_share_boundary() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::with_risk_quota_config(
        router,
        RiskQuotaConfig {
            window_ms: 1_000,
            per_session_limit: 6,
            per_source_limit: 2,
        },
    );
    relay
        .open(RelayOpenRequest {
            session_id: "proof-tag-noise-s1".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "proof-tag-noise-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: Some("seed".into()),
        })
        .unwrap();

    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-tag-noise-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("proof source".into()),
        })
        .unwrap();
    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-tag-noise-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("proof\u{FEFF}\u{E0020}\u{FE0F}source".into()),
        })
        .unwrap();
    let alias_err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "proof-tag-noise-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("proof source".into()),
        })
        .unwrap_err();
    assert!(alias_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));
}

#[test]
fn relay_and_proof_quota_are_isolated_by_domain() {
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
            session_id: "mv-s1".into(),
        })
        .unwrap();

    relay
        .send(RelaySendRequest {
            session_id: "mv-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"lane-mv-a".to_vec(),
            source: Some("mv-src".into()),
        })
        .unwrap();
    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 7,
            session_id: "mv-s1".into(),
            from_seq: 1,
            to_seq: 1,
            source: Some("mv-src".into()),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "mv-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"lane-mv-b".to_vec(),
            source: Some("mv-src".into()),
        })
        .unwrap();
    relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 7,
            session_id: "mv-s1".into(),
            from_seq: 1,
            to_seq: 2,
            source: Some("mv-src".into()),
        })
        .unwrap();

    let proof_err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 7,
            session_id: "mv-s1".into(),
            from_seq: 1,
            to_seq: 2,
            source: Some("mv-src".into()),
        })
        .unwrap_err();
    assert!(proof_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));

    let relay_err = relay
        .send(RelaySendRequest {
            session_id: "mv-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"lane-mv-c".to_vec(),
            source: Some("mv-src".into()),
        })
        .unwrap_err();
    assert!(relay_err
        .to_string()
        .contains("too_many_requests/quota_exceeded"));
}
