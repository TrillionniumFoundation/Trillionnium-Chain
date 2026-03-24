use super::*;

#[test]
fn relay_ack_backward_compatible_single_id_and_unknown_id_ignored() {
    let relay = relay_fixture();

    open_session(&relay, "it-s1");
    send_echo(&relay, "it-s1", "alice", "bob", b"hello");

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
