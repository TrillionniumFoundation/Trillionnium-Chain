use trnm_rpc::{
    EchoHandler, RelayAckRequest, RelayOpenRequest, RelayPollRequest, RelayRouter,
    RelaySendRequest, RelayService,
};

#[test]
fn relay_ack_backward_compatible_single_id_and_unknown_id_ignored() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);

    relay
        .open(RelayOpenRequest {
            session_id: "it-s1".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "it-s1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"hello".to_vec(),
            source: None,
        })
        .unwrap();

    let polled = relay
        .poll(RelayPollRequest {
            session_id: "it-s1".into(),
            limit: 10,
        })
        .unwrap();
    assert_eq!(polled.envelopes.len(), 2);

    let acked = relay
        .ack(RelayAckRequest {
            session_id: "it-s1".into(),
            envelope_ids: vec![polled.envelopes[0].envelope_id, 9_999_999],
            upto_seq: None,
        })
        .unwrap();
    assert_eq!(acked.acked, 1);
}

#[test]
fn relay_ack_upto_seq_then_id_ack_mixed() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);

    relay
        .open(RelayOpenRequest {
            session_id: "it-s2".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "it-s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
            source: None,
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "it-s2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m2".to_vec(),
            source: None,
        })
        .unwrap();

    let polled = relay
        .poll(RelayPollRequest {
            session_id: "it-s2".into(),
            limit: 10,
        })
        .unwrap();
    assert_eq!(polled.envelopes.len(), 4);

    let ack1 = relay
        .ack(RelayAckRequest {
            session_id: "it-s2".into(),
            envelope_ids: vec![],
            upto_seq: Some(3),
        })
        .unwrap();
    assert_eq!(ack1.acked, 3);

    let last_id = polled.envelopes[3].envelope_id;
    let ack2 = relay
        .ack(RelayAckRequest {
            session_id: "it-s2".into(),
            envelope_ids: vec![last_id],
            upto_seq: Some(3),
        })
        .unwrap();
    assert_eq!(ack2.acked, 1);

    let left = relay
        .poll(RelayPollRequest {
            session_id: "it-s2".into(),
            limit: 10,
        })
        .unwrap();
    assert!(left.envelopes.is_empty());
}

#[test]
fn relay_ack_does_not_cross_session_boundary_by_envelope_id() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);

    relay
        .open(RelayOpenRequest {
            session_id: "it-s3-a".into(),
        })
        .unwrap();
    relay
        .open(RelayOpenRequest {
            session_id: "it-s3-b".into(),
        })
        .unwrap();

    relay
        .send(RelaySendRequest {
            session_id: "it-s3-a".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"a1".to_vec(),
            source: None,
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "it-s3-b".into(),
            route: "relay.echo".into(),
            from: "carol".into(),
            to: Some("dave".into()),
            payload: b"b1".to_vec(),
            source: None,
        })
        .unwrap();

    let polled_b = relay
        .poll(RelayPollRequest {
            session_id: "it-s3-b".into(),
            limit: 10,
        })
        .unwrap();
    assert_eq!(polled_b.envelopes.len(), 2);
    let foreign_id = polled_b.envelopes[0].envelope_id;

    let ack_on_a = relay
        .ack(RelayAckRequest {
            session_id: "it-s3-a".into(),
            envelope_ids: vec![foreign_id],
            upto_seq: None,
        })
        .unwrap();
    assert_eq!(ack_on_a.acked, 0);

    let still_visible_a = relay
        .poll(RelayPollRequest {
            session_id: "it-s3-a".into(),
            limit: 10,
        })
        .unwrap();
    assert_eq!(still_visible_a.envelopes.len(), 2);
}

#[test]
fn relay_ack_deduplicates_overlapping_envelope_ids_and_upto_seq() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);

    relay
        .open(RelayOpenRequest {
            session_id: "it-s4".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "it-s4".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
            source: None,
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "it-s4".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m2".to_vec(),
            source: None,
        })
        .unwrap();

    let polled = relay
        .poll(RelayPollRequest {
            session_id: "it-s4".into(),
            limit: 10,
        })
        .unwrap();
    assert_eq!(polled.envelopes.len(), 4);

    let second_id = polled.envelopes[1].envelope_id;
    let acked = relay
        .ack(RelayAckRequest {
            session_id: "it-s4".into(),
            envelope_ids: vec![second_id, second_id],
            upto_seq: Some(2),
        })
        .unwrap();
    assert_eq!(acked.acked, 2);

    let left = relay
        .poll(RelayPollRequest {
            session_id: "it-s4".into(),
            limit: 10,
        })
        .unwrap();
    assert_eq!(left.envelopes.len(), 2);
    assert_eq!(left.envelopes[0].sequence, 3);
    assert_eq!(left.envelopes[1].sequence, 4);
}
