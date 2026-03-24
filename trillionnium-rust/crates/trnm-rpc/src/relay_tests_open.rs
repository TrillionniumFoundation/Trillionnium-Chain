use super::*;

#[test]
fn relay_open_send_poll_ack_close_happy_path() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);

    let opened = relay
        .open(RelayOpenRequest {
            session_id: "s1".to_string(),
        })
        .expect("open");
    assert_eq!(opened.session.status, RelaySessionStatus::Open);
    assert_eq!(relay.relay_open_total(), 1);

    let sent = relay
        .send(RelaySendRequest {
            session_id: "s1".to_string(),
            route: "relay.echo".to_string(),
            from: "alice".to_string(),
            to: Some("bob".to_string()),
            payload: b"ping".to_vec(),
            source: None,
        })
        .expect("send");
    assert_eq!(sent.envelope.sequence, 1);

    let polled = relay
        .poll(RelayPollRequest {
            session_id: "s1".to_string(),
            limit: 10,
        })
        .expect("poll");
    assert_eq!(polled.envelopes.len(), 2);
    assert_eq!(relay.relay_poll_total(), 1);

    let acked = relay
        .ack(RelayAckRequest {
            session_id: "s1".to_string(),
            envelope_ids: polled.envelopes.iter().map(|e| e.envelope_id).collect(),
            upto_seq: None,
        })
        .expect("ack");
    assert_eq!(acked.acked, 2);

    let polled2 = relay
        .poll(RelayPollRequest {
            session_id: "s1".to_string(),
            limit: 10,
        })
        .expect("poll after ack");
    assert!(polled2.envelopes.is_empty());
    assert_eq!(relay.relay_poll_total(), 2);

    let closed = relay
        .close(RelayCloseRequest {
            session_id: "s1".to_string(),
        })
        .expect("close");
    assert_eq!(closed.session.status, RelaySessionStatus::Closed);
}

#[test]
fn relay_reopen_closed_session_clears_closed_at_and_accepts_send() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);

    relay
        .open(RelayOpenRequest {
            session_id: "s1-reopen".to_string(),
        })
        .expect("open");

    let closed = relay
        .close(RelayCloseRequest {
            session_id: "s1-reopen".to_string(),
        })
        .expect("close");
    assert_eq!(closed.session.status, RelaySessionStatus::Closed);
    assert!(closed.session.closed_at_unix_ms.is_some());

    let reopened = relay
        .open(RelayOpenRequest {
            session_id: "s1-reopen".to_string(),
        })
        .expect("reopen");
    assert_eq!(reopened.session.status, RelaySessionStatus::Open);
    assert!(reopened.session.closed_at_unix_ms.is_none());

    let sent = relay
        .send(RelaySendRequest {
            session_id: "s1-reopen".to_string(),
            route: "relay.echo".to_string(),
            from: "alice".to_string(),
            to: Some("bob".to_string()),
            payload: b"ping-reopen".to_vec(),
            source: None,
        })
        .expect("send after reopen");
    assert_eq!(sent.envelope.sequence, 1);
}

#[test]
fn relay_open_rejects_empty_session() {
    let relay = RelayService::new(RelayRouter::new());
    let err = relay
        .open(RelayOpenRequest {
            session_id: "   ".into(),
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/empty_session"));
}
