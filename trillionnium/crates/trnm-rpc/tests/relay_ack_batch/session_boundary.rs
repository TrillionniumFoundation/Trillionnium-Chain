use super::*;

#[test]
fn relay_ack_does_not_cross_session_boundary_by_envelope_id() {
    let relay = relay_fixture();

    open_session(&relay, "it-s3-a");
    open_session(&relay, "it-s3-b");

    send_echo(&relay, "it-s3-a", "alice", "bob", b"a1");
    send_echo(&relay, "it-s3-b", "carol", "dave", b"b1");

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
