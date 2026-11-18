use super::*;

#[test]
fn ineligible_body_never_blocks_new_body_or_history_fifo_and_keeps_original_expiry() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let now = Instant::now();
    let eligible = now + rejection_backpressure::COOLDOWN;
    let mut connections = BTreeMap::new();
    let mut peers = Vec::new();
    for id in 0..3 {
        peers.push(TcpStream::connect(address).unwrap());
        let (socket, peer) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        let op = if id == 2 { 3 } else { 1 };
        connections.insert(
            id,
            Connection {
                _connection_permit: None,
                intake_lease: None,
                observation: None,
                id,
                socket,
                peer,
                deadline: now + Duration::from_millis(PREFIX_MS),
                total_deadline: now + Duration::from_millis(OVERALL_MS),
                stage: Stage::WaitChallenge {
                    hello: Hello {
                        op,
                        len: 1,
                        caller: [id as u8; 32],
                        digest: [id as u8; 32],
                        client_nonce: [0; 32],
                    },
                    pending: PendingOrder {
                        sequence: id + 1,
                        entered_at: now,
                        eligible_at: if id == 0 { eligible } else { now },
                    },
                },
                permit: None,
                lane_permit: None,
                cancelled: Arc::new(AtomicBool::new(false)),
            },
        );
    }
    for before in [now, eligible - Duration::from_nanos(1)] {
        let heads = PendingHeads::collect(&connections, before);
        assert!(heads.is_head(PendingKind::Challenge, 1, 1));
        assert!(heads.is_head(PendingKind::Challenge, 3, 2));
        assert!(!heads.is_head(PendingKind::Challenge, 1, 0));
    }
    let after = PendingHeads::collect(&connections, eligible);
    assert!(after.is_head(PendingKind::Challenge, 1, 0));
    assert!(after.is_head(PendingKind::Challenge, 3, 2));
    let original_deadline = now + Duration::from_millis(100);
    connections.get_mut(&0).unwrap().deadline = original_deadline;
    let expired = PendingHeads::collect(&connections, eligible);
    assert!(expired.is_head(PendingKind::Challenge, 1, 1));
    let waiting = &connections[&0];
    assert!(waiting.permit.is_none() && waiting.lane_permit.is_none());
    assert_eq!(waiting.deadline, original_deadline);
    assert_eq!(waiting.stage.phase(), "hello");
}
