use super::*;

#[test]
fn relay_ack_upto_seq_batch_and_boundaries() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "s2".into(),
        })
        .unwrap();

    relay
        .send(RelaySendRequest {
            session_id: "s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
            source: None,
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m2".to_vec(),
            source: None,
        })
        .unwrap();

    let all = relay
        .poll(RelayPollRequest {
            session_id: "s2".into(),
            limit: 10,
        })
        .unwrap();
    assert_eq!(all.envelopes.len(), 4);

    let empty_range = relay
        .ack(RelayAckRequest {
            session_id: "s2".into(),
            envelope_ids: vec![],
            upto_seq: Some(0),
        })
        .unwrap();
    assert_eq!(empty_range.acked, 0);

    let first_batch = relay
        .ack(RelayAckRequest {
            session_id: "s2".into(),
            envelope_ids: vec![],
            upto_seq: Some(2),
        })
        .unwrap();
    assert_eq!(first_batch.acked, 2);

    let repeat = relay
        .ack(RelayAckRequest {
            session_id: "s2".into(),
            envelope_ids: vec![],
            upto_seq: Some(2),
        })
        .unwrap();
    assert_eq!(repeat.acked, 0);

    let overflow = relay
        .ack(RelayAckRequest {
            session_id: "s2".into(),
            envelope_ids: vec![],
            upto_seq: Some(u64::MAX),
        })
        .unwrap();
    assert_eq!(overflow.acked, 2);

    let none_left = relay
        .poll(RelayPollRequest {
            session_id: "s2".into(),
            limit: 10,
        })
        .unwrap();
    assert!(none_left.envelopes.is_empty());
}

#[test]
fn relay_ack_advances_poll_start_index_for_contiguous_acked_prefix() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "s2-cursor".into(),
        })
        .unwrap();

    relay
        .send(RelaySendRequest {
            session_id: "s2-cursor".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
            source: None,
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "s2-cursor".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m2".to_vec(),
            source: None,
        })
        .unwrap();

    let batch = relay
        .ack(RelayAckRequest {
            session_id: "s2-cursor".into(),
            envelope_ids: vec![],
            upto_seq: Some(2),
        })
        .unwrap();
    assert_eq!(batch.acked, 2);

    {
        let g = relay.sessions.lock().unwrap();
        let state = g.get("s2-cursor").unwrap();
        assert_eq!(state.poll_start_idx, 2);
    }

    let pending = relay
        .poll(RelayPollRequest {
            session_id: "s2-cursor".into(),
            limit: 10,
        })
        .unwrap();
    assert_eq!(pending.envelopes.len(), 2);
    assert!(pending.envelopes.iter().all(|e| e.sequence > 2));
}

#[test]
fn relay_poll_clamps_limit() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-limit".into(),
        })
        .unwrap();
    for _ in 0..3 {
        relay
            .send(RelaySendRequest {
                session_id: "sp-limit".into(),
                route: "relay.echo".into(),
                from: "alice".into(),
                to: Some("bob".into()),
                payload: b"x".to_vec(),
                source: None,
            })
            .unwrap();
    }

    let out = relay
        .poll(RelayPollRequest {
            session_id: "sp-limit".into(),
            limit: usize::MAX,
        })
        .unwrap();
    assert_eq!(out.envelopes.len(), 6);
    assert_eq!(relay.relay_poll_total(), 1);
}
