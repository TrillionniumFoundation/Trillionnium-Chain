use super::*;

#[test]
fn concurrent_receive_preserves_dedup() {
    let engine = Arc::new(Mutex::new(ReliabilityEngine::new(
        InMemoryReliabilityStore::default(),
        RetryConfig::default(),
    )));

    let mut handles = Vec::new();
    for _ in 0..16 {
        let e = Arc::clone(&engine);
        handles.push(thread::spawn(move || {
            let mut g = e.lock().expect("lock");
            g.receive(mk_msg("alice", "sess", 42), 1_000).code
        }));
    }

    let mut accepted = 0;
    let mut duplicate = 0;
    for h in handles {
        match h.join().expect("thread join") {
            AckCode::Accepted => accepted += 1,
            AckCode::Duplicate => duplicate += 1,
            other => panic!("unexpected ack: {other:?}"),
        }
    }

    assert_eq!(accepted, 1);
    assert_eq!(duplicate, 15);
}
