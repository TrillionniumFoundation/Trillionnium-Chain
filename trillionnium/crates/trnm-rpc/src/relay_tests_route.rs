use super::*;

#[test]
fn relay_send_rejects_invalid_route_type() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "s-route".into(),
        })
        .unwrap();

    let err = relay
        .send(RelaySendRequest {
            session_id: "s-route".into(),
            route: "foo/bar".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/invalid_route_type"));
}

#[test]
fn relay_send_rejects_unregistered_route_and_counts_metric() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "s-route-missing".into(),
        })
        .unwrap();

    let err = relay
        .send(RelaySendRequest {
            session_id: "s-route-missing".into(),
            route: "relay.unknown".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"x".to_vec(),
            source: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("bad_request/invalid_route"));
    assert_eq!(relay.relay_send_rejected_route_not_registered_total(), 1);
}
