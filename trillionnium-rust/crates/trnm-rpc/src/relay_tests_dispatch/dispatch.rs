use super::*;

#[test]
fn relay_query_session_proof_returns_messages_root_and_proofs() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp1".into(),
        })
        .unwrap();

    relay
        .send(RelaySendRequest {
            session_id: "sp1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"p1".to_vec(),
            source: None,
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp1".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"p2".to_vec(),
            source: None,
        })
        .unwrap();

    let out = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 42,
            session_id: "sp1".into(),
            from_seq: 2,
            to_seq: 4,
            source: None,
        })
        .unwrap();

    assert_eq!(out.task_id, 42);
    assert_eq!(out.session_id, "sp1");
    assert_eq!(out.messages.len(), 3);
    assert_eq!(out.proofs.len(), 3);
    assert_eq!(out.messages[0].sequence, 2);
    assert_eq!(out.messages[2].sequence, 4);

    let mut leaves = Vec::new();
    for m in &out.messages {
        leaves.push(hash_envelope(m).unwrap());
    }
    let (expect_root, _) = merkle_root_and_proofs(&leaves);
    assert_eq!(out.segment_root_hex, hex::encode(expect_root));

    for (i, p) in out.proofs.iter().enumerate() {
        assert_eq!(p.envelope.sequence, out.messages[i].sequence);
        assert_eq!(p.leaf_index, i);
        assert!(!p.leaf_hash_hex.is_empty());
    }
}

#[test]
fn relay_session_proof_smoke_and_tamper_matrix() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp2".into(),
        })
        .unwrap();

    relay
        .send(RelaySendRequest {
            session_id: "sp2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
            source: None,
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp2".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m2".to_vec(),
            source: None,
        })
        .unwrap();

    let proof = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 7,
            session_id: "sp2".into(),
            from_seq: 1,
            to_seq: 4,
            source: None,
        })
        .unwrap();

    verify_session_proof(&proof).unwrap();

    let mut missing_segment = proof.clone();
    missing_segment.messages.remove(1);
    missing_segment.proofs.remove(1);
    assert!(verify_session_proof(&missing_segment).is_err());

    let mut out_of_order = proof.clone();
    out_of_order.messages.swap(1, 2);
    out_of_order.proofs.swap(1, 2);
    assert!(verify_session_proof(&out_of_order).is_err());

    let mut content_tampered = proof.clone();
    content_tampered.messages[0].payload = b"tampered".to_vec();
    content_tampered.proofs[0].envelope.payload = b"tampered".to_vec();
    assert!(verify_session_proof(&content_tampered).is_err());

    let mut leaf_hash_tampered = proof.clone();
    leaf_hash_tampered.proofs[0].leaf_hash_hex = "ff".repeat(32);
    assert!(verify_session_proof(&leaf_hash_tampered).is_err());

    let mut root_mismatch = proof.clone();
    root_mismatch.segment_root_hex = "00".repeat(32);
    assert!(verify_session_proof(&root_mismatch).is_err());

    let mut session_mismatch = proof.clone();
    session_mismatch.session_id = "sp2-other".to_string();
    assert!(verify_session_proof(&session_mismatch).is_err());
}

#[test]
fn relay_session_proof_accepts_uppercase_leaf_hash_hex() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp3".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp3".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
            source: None,
        })
        .unwrap();

    let mut proof = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 7,
            session_id: "sp3".into(),
            from_seq: 1,
            to_seq: 2,
            source: None,
        })
        .unwrap();

    for entry in proof.proofs.iter_mut() {
        entry.leaf_hash_hex = entry.leaf_hash_hex.to_uppercase();
    }

    verify_session_proof(&proof).unwrap();
}

#[test]
fn relay_session_proof_accepts_0x_prefixed_hash_hex() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp3-prefixed".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp3-prefixed".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
            source: None,
        })
        .unwrap();

    let mut proof = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 7,
            session_id: "sp3-prefixed".into(),
            from_seq: 1,
            to_seq: 2,
            source: None,
        })
        .unwrap();

    proof.segment_root_hex = format!("0x{}", proof.segment_root_hex);
    for entry in proof.proofs.iter_mut() {
        entry.leaf_hash_hex = format!("0X{}", entry.leaf_hash_hex);
        for step in entry.proof.iter_mut() {
            step.sibling_hash_hex = format!("0x{}", step.sibling_hash_hex);
        }
    }

    verify_session_proof(&proof).unwrap();
}
