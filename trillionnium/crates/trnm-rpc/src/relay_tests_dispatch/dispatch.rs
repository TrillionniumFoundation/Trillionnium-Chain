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
    assert_eq!(out.range_len, 3);
    assert_eq!(out.message_count, 3);
    assert_eq!(out.proof_count, 3);
    assert_eq!(out.total_proof_steps, 6);
    assert_eq!(out.max_proof_depth, 2);
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
        assert_eq!(p.leaf_sequence, out.messages[i].sequence);
        assert_eq!(p.leaf_index, i);
        assert!(!p.leaf_hash_hex.is_empty());
    }
}

#[test]
fn relay_session_proof_remains_queryable_after_close_for_audit_replay() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-closed-audit".into(),
        })
        .unwrap();

    relay
        .send(RelaySendRequest {
            session_id: "sp-closed-audit".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"audit-me".to_vec(),
            source: None,
        })
        .unwrap();

    let closed = relay
        .close(RelayCloseRequest {
            session_id: "sp-closed-audit".into(),
        })
        .unwrap();
    assert_eq!(closed.session.status, RelaySessionStatus::Closed);
    assert!(closed.session.closed_at_unix_ms.is_some());

    let proof = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 99,
            session_id: "sp-closed-audit".into(),
            from_seq: 1,
            to_seq: 2,
            source: None,
        })
        .unwrap();

    assert_eq!(proof.session_id, "sp-closed-audit");
    assert_eq!(proof.range_len, 2);
    assert_eq!(proof.message_count, 2);
    assert_eq!(proof.proof_count, 2);
    assert_eq!(proof.messages.len(), 2);
    assert_eq!(proof.proofs.len(), 2);
    assert_eq!(proof.messages[0].sequence, 1);
    assert_eq!(proof.messages[1].sequence, 2);
    verify_session_proof(&proof).unwrap();
}

#[test]
fn relay_session_proof_json_contract_keeps_explicit_audit_fields() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-contract".into(),
        })
        .unwrap();

    relay
        .send(RelaySendRequest {
            session_id: "sp-contract".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
            source: None,
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp-contract".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m2".to_vec(),
            source: None,
        })
        .unwrap();

    let proof = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 88,
            session_id: "sp-contract".into(),
            from_seq: 1,
            to_seq: 4,
            source: None,
        })
        .unwrap();

    let json = serde_json::to_value(&proof).unwrap();
    assert_eq!(json["task_id"], 88);
    assert_eq!(json["session_id"], "sp-contract");
    assert_eq!(json["from_seq"], 1);
    assert_eq!(json["to_seq"], 4);
    assert_eq!(json["range_len"], 4);
    assert_eq!(json["message_count"], 4);
    assert_eq!(json["proof_count"], 4);
    assert_eq!(json["total_proof_steps"], 8);
    assert_eq!(json["max_proof_depth"], 2);
    assert_eq!(json["messages"].as_array().unwrap().len(), 4);
    assert_eq!(json["proofs"].as_array().unwrap().len(), 4);
    assert_eq!(json["proofs"][0]["leaf_sequence"], 1);
    assert_eq!(json["proofs"][3]["leaf_sequence"], 4);
    assert_eq!(json["proofs"][0]["leaf_index"], 0);
    assert_eq!(json["proofs"][3]["leaf_index"], 3);
    assert_eq!(json["proofs"][0]["envelope"]["session_id"], "sp-contract");
    assert_eq!(json["proofs"][0]["envelope"]["sequence"], 1);
    assert_eq!(json["proofs"][3]["envelope"]["sequence"], 4);
    assert_eq!(json["proofs"][0]["proof"].as_array().unwrap().len(), 2);
    assert_eq!(json["proofs"][3]["proof"].as_array().unwrap().len(), 2);
    assert!(json["segment_root_hex"].as_str().unwrap().len() == 64);
    assert!(json["proofs"][0]["leaf_hash_hex"].as_str().unwrap().len() == 64);
}

#[test]
fn relay_session_proof_rejects_leaf_sequence_drift() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-leaf-seq".into(),
        })
        .unwrap();

    relay
        .send(RelaySendRequest {
            session_id: "sp-leaf-seq".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
            source: None,
        })
        .unwrap();

    let mut proof = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 77,
            session_id: "sp-leaf-seq".into(),
            from_seq: 1,
            to_seq: 2,
            source: None,
        })
        .unwrap();
    verify_session_proof(&proof).unwrap();

    proof.proofs[0].leaf_sequence += 1;
    assert!(verify_session_proof(&proof).is_err());
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
fn relay_session_proof_single_message_range_has_empty_merkle_path_and_verifies() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp-single".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp-single".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"solo".to_vec(),
            source: None,
        })
        .unwrap();

    let proof = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 9,
            session_id: "sp-single".into(),
            from_seq: 1,
            to_seq: 1,
            source: None,
        })
        .unwrap();

    assert_eq!(proof.range_len, 1);
    assert_eq!(proof.message_count, 1);
    assert_eq!(proof.proof_count, 1);
    assert_eq!(proof.total_proof_steps, 0);
    assert_eq!(proof.max_proof_depth, 0);
    assert_eq!(proof.messages.len(), 1);
    assert_eq!(proof.proofs.len(), 1);
    assert_eq!(proof.messages[0].sequence, 1);
    assert_eq!(proof.proofs[0].leaf_index, 0);
    assert!(proof.proofs[0].proof.is_empty());
    assert_eq!(proof.proofs[0].envelope, proof.messages[0]);
    assert_eq!(
        proof.segment_root_hex,
        hex::encode(hash_envelope(&proof.messages[0]).unwrap())
    );

    verify_session_proof(&proof).unwrap();
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

#[test]
fn relay_session_proof_accepts_whitespace_wrapped_hash_hex() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp3-whitespace".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp3-whitespace".into(),
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
            session_id: "sp3-whitespace".into(),
            from_seq: 1,
            to_seq: 2,
            source: None,
        })
        .unwrap();

    proof.segment_root_hex = format!("  \n{}\t  ", proof.segment_root_hex);
    for entry in proof.proofs.iter_mut() {
        entry.leaf_hash_hex = format!("  {}  ", entry.leaf_hash_hex);
        for step in entry.proof.iter_mut() {
            step.sibling_hash_hex = format!("\n{}\r", step.sibling_hash_hex);
        }
    }

    verify_session_proof(&proof).unwrap();
}

#[test]
fn relay_session_proof_accepts_invisible_wrapper_noise_around_hash_hex() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp3-invisible-wrapper-noise".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp3-invisible-wrapper-noise".into(),
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
            session_id: "sp3-invisible-wrapper-noise".into(),
            from_seq: 1,
            to_seq: 2,
            source: None,
        })
        .unwrap();

    proof.segment_root_hex = format!("\u{{FEFF}}0x{}\u{{2060}}", proof.segment_root_hex);
    for entry in proof.proofs.iter_mut() {
        entry.leaf_hash_hex = format!("\u{{200B}}0X{}\u{{202E}}", entry.leaf_hash_hex);
        for step in entry.proof.iter_mut() {
            step.sibling_hash_hex = format!("\u{{2066}}{}\u{{2069}}", step.sibling_hash_hex);
        }
    }

    verify_session_proof(&proof).unwrap();
}

#[test]
fn relay_session_proof_accepts_uppercase_segment_root_hex() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp3-root-uppercase".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp3-root-uppercase".into(),
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
            session_id: "sp3-root-uppercase".into(),
            from_seq: 1,
            to_seq: 2,
            source: None,
        })
        .unwrap();

    proof.segment_root_hex = proof.segment_root_hex.to_uppercase();

    verify_session_proof(&proof).unwrap();
}

#[test]
fn relay_session_proof_accepts_0x_uppercase_prefixed_hash_hex() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp3-prefixed-uppercase".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp3-prefixed-uppercase".into(),
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
            session_id: "sp3-prefixed-uppercase".into(),
            from_seq: 1,
            to_seq: 2,
            source: None,
        })
        .unwrap();

    proof.segment_root_hex = format!("0X{}", proof.segment_root_hex.to_uppercase());
    for entry in proof.proofs.iter_mut() {
        entry.leaf_hash_hex = format!("0X{}", entry.leaf_hash_hex.to_uppercase());
        for step in entry.proof.iter_mut() {
            step.sibling_hash_hex = format!("0X{}", step.sibling_hash_hex.to_uppercase());
        }
    }

    verify_session_proof(&proof).unwrap();
}

#[test]
fn relay_session_proof_accepts_whitespace_wrapped_0x_uppercase_hash_hex() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp3-prefixed-uppercase-whitespace".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp3-prefixed-uppercase-whitespace".into(),
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
            session_id: "sp3-prefixed-uppercase-whitespace".into(),
            from_seq: 1,
            to_seq: 2,
            source: None,
        })
        .unwrap();

    proof.segment_root_hex = format!("  \n0X{}\t  ", proof.segment_root_hex.to_uppercase());
    for entry in proof.proofs.iter_mut() {
        entry.leaf_hash_hex = format!("\t0X{}\n", entry.leaf_hash_hex.to_uppercase());
        for step in entry.proof.iter_mut() {
            step.sibling_hash_hex = format!("\r  0X{}  \n", step.sibling_hash_hex.to_uppercase());
        }
    }

    verify_session_proof(&proof).unwrap();
}

#[test]
fn relay_session_proof_rejects_tampered_explicit_count_fields() {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::new(router);
    relay
        .open(RelayOpenRequest {
            session_id: "sp3-counts".into(),
        })
        .unwrap();
    relay
        .send(RelaySendRequest {
            session_id: "sp3-counts".into(),
            route: "relay.echo".into(),
            from: "alice".into(),
            to: Some("bob".into()),
            payload: b"m1".to_vec(),
            source: None,
        })
        .unwrap();

    let proof = relay
        .query_session_proof(RelaySessionProofQuery {
            task_id: 8,
            session_id: "sp3-counts".into(),
            from_seq: 1,
            to_seq: 2,
            source: None,
        })
        .unwrap();

    let mut wrong_range_len = proof.clone();
    wrong_range_len.range_len += 1;
    assert!(verify_session_proof(&wrong_range_len).is_err());

    let mut wrong_message_count = proof.clone();
    wrong_message_count.message_count += 1;
    assert!(verify_session_proof(&wrong_message_count).is_err());

    let mut wrong_proof_count = proof.clone();
    wrong_proof_count.proof_count += 1;
    assert!(verify_session_proof(&wrong_proof_count).is_err());

    let mut wrong_total_proof_steps = proof.clone();
    wrong_total_proof_steps.total_proof_steps += 1;
    assert!(verify_session_proof(&wrong_total_proof_steps).is_err());

    let mut wrong_max_proof_depth = proof;
    wrong_max_proof_depth.max_proof_depth += 1;
    assert!(verify_session_proof(&wrong_max_proof_depth).is_err());
}
