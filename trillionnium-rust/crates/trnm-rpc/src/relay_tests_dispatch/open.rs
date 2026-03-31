use super::*;

#[test]
fn relay_proof_query_rejects_empty_session() {
    let relay = RelayService::new(RelayRouter::new());
    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "".into(),
            from_seq: 1,
            to_seq: 1,
            source: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/empty_session"));
}

#[test]
fn relay_proof_query_rejects_unknown_session_with_explicit_not_found_code() {
    let relay = RelayService::new(RelayRouter::new());
    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "sp-missing".into(),
            from_seq: 1,
            to_seq: 1,
            source: None,
        })
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("not_found/session_not_found"));
}

#[test]
fn relay_proof_query_rejects_noncanonical_session() {
    let relay = RelayService::new(RelayRouter::new());
    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "  sp-canonical\n".into(),
            from_seq: 1,
            to_seq: 1,
            source: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/invalid_session"));
}

#[test]
fn relay_proof_query_rejects_session_with_unicode_control() {
    let relay = RelayService::new(RelayRouter::new());
    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "sp\u{202E}canonical".into(),
            from_seq: 1,
            to_seq: 1,
            source: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/invalid_session"));
}

#[test]
fn relay_proof_query_rejects_session_with_zero_width_space() {
    let relay = RelayService::new(RelayRouter::new());
    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "sp\u{200B}canonical".into(),
            from_seq: 1,
            to_seq: 1,
            source: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/invalid_session"));
}

#[test]
fn relay_proof_query_rejects_zero_from_seq() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-zero-from".into(),
        })
        .unwrap();

    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "sp-zero-from".into(),
            from_seq: 0,
            to_seq: 1,
            source: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/invalid_range"));
}

#[test]
fn relay_proof_query_rejects_reversed_range() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-range".into(),
        })
        .unwrap();

    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "sp-range".into(),
            from_seq: 4,
            to_seq: 2,
            source: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/invalid_range"));
}

#[test]
fn relay_proof_query_rejects_span_overflow() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-span".into(),
        })
        .unwrap();

    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "sp-span".into(),
            from_seq: 1,
            to_seq: MAX_PROOF_QUERY_SPAN + 1,
            source: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/range_out_of_bounds"));
    assert_eq!(relay.proof_query_rejected_range_out_of_bounds_total(), 1);
}

#[test]
fn relay_proof_query_rejects_to_seq_out_of_bounds() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-oob".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp-oob".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: None,
        })
        .unwrap();

    let err = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 1,
            session_id: "sp-oob".into(),
            from_seq: 1,
            to_seq: 9,
            source: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/range_out_of_bounds"));
    assert_eq!(relay.proof_query_rejected_range_out_of_bounds_total(), 1);
}
