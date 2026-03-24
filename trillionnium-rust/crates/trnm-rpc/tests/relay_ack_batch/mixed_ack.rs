use super::*;

#[test]
fn relay_ack_upto_seq_then_id_ack_mixed() {
    let relay = relay_fixture();

    open_session(&relay, "it-s2");
    send_echo(&relay, "it-s2", "alice", "bob", b"m1");
    send_echo(&relay, "it-s2", "alice", "bob", b"m2");

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
