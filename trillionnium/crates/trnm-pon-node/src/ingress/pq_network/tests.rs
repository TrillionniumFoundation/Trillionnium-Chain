use super::*;
use openssl::pkey::{KeyType, PKey};
use std::{io::Write, thread};

mod post_intent_cancellation {
    include!("post_intent_cancel_tests.rs");
}

fn signer(seed: u8) -> PqNativeSigningKey {
    // Disposable published test seeds, never a key-custody or entropy claim.
    let key = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap();
    let id = ml_dsa_65_key_id_from_spki(&key.public_key_to_der().unwrap()).unwrap();
    PqNativeSigningKey::from_owned_key(key, id).unwrap()
}
fn settings() -> Settings {
    Settings::development(Some(super::super::now().unwrap() - 100)).unwrap()
}
fn policy(settings: &Settings, generation: u64) -> Arc<PqNetworkPolicy> {
    Arc::new(
        PqNetworkPolicy::new(
            settings,
            signer(71).public_spki(),
            generation,
            [
                signer(72).public_spki().to_vec(),
                signer(73).public_spki().to_vec(),
            ],
        )
        .unwrap(),
    )
}
fn raw_request(address: SocketAddr, wire: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    super::super::write_frame_deadline(&mut stream, wire, deadline)?;
    super::super::read_frame_deadline(&mut stream, deadline)
}

#[test]
fn signed_pq_client_refuses_nonloopback_destination_before_network_io() {
    // Real ML-DSA request and independently pinned keys; rejection is an
    // outbound transport boundary, not a synthetic bad-signature refusal.
    let settings = settings();
    let policy = policy(&settings, 1);
    let client = PqClient::new(policy, signer(72)).unwrap();
    let expires = super::super::now().unwrap() + 30;
    let prepared = client.prepare(1, expires, Request::Head).unwrap();
    for raw in [
        "0.0.0.0:1",
        "192.0.2.42:443",
        "[::]:1",
        "[2001:db8::42]:443",
        "[::ffff:192.0.2.42]:443",
    ] {
        let address: SocketAddr = raw.parse().unwrap();
        assert!(!address.ip().is_loopback(), "{raw}");
        assert_eq!(
            client
                .send(address, &prepared, Duration::from_secs(1))
                .unwrap_err()
                .to_string(),
            "PQ_NETWORK_LOOPBACK_ONLY",
            "{raw}"
        );
    }
    // Existing real_tcp_node_submit... exercises the retained successful
    // loopback request/response/ledger path with the same send method.
}

#[test]
fn real_tcp_node_submit_lost_ack_signature_randomness_and_cold_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let policy = policy(&settings, 1);
    let node = Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    let packet = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let packet_id = packet.id().unwrap();
    let mut bad = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(1).unwrap(),
            settings.genesis_time() + 11,
            4096,
        )
        .unwrap();
    assert_ne!(packet_id, bad.id().unwrap());
    bad.proof[4 + 2 * 64 * 64 * 4] ^= 1; // wrong C on a distinct, unadmitted candidate
    let client = PqClient::new(policy.clone(), signer(72)).unwrap();
    let expiry = super::super::now().unwrap() + 60;
    let first = client.prepare(1, expiry, Request::Head).unwrap();
    let second_signature = client.prepare(1, expiry, Request::Head).unwrap();
    assert_eq!(first.operation_id(), second_signature.operation_id());
    assert_ne!(
        first.wire(),
        second_signature.wire(),
        "real provider should randomize these signatures"
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server = PqServer::new(policy.clone(), signer(71)).unwrap();
    let server_stop = stop.clone();
    let handle = thread::spawn(move || {
        serve_pq_authenticated(listener, node, Duration::from_secs(45), server_stop, server)
            .unwrap()
    });
    let response1 = raw_request(address, first.wire()).unwrap();
    let response2 = raw_request(address, second_signature.wire()).unwrap();
    assert_eq!(
        response1, response2,
        "cached signed bytes survive randomized request signatures"
    );
    assert_eq!(
        policy
            .verify_response(&response1, &first.verified, super::super::now().unwrap())
            .unwrap()
            .value["height"],
        0
    );

    let submitted = client
        .prepare(
            2,
            expiry,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
        )
        .unwrap();
    let mut invalid_signature = submitted.wire().to_vec();
    invalid_signature[8 + 178] ^= 1;
    assert!(raw_request(address, &invalid_signature).is_err());
    assert!(raw_request(address, br#"{"op":"head"}"#).is_err());
    // Deliberately lose the ACK after sending the actual valid block.
    let mut lost_ack = TcpStream::connect(address).unwrap();
    lost_ack
        .write_all(&(submitted.wire().len() as u32).to_be_bytes())
        .unwrap();
    lost_ack.write_all(submitted.wire()).unwrap();
    drop(lost_ack);
    let accepted = client
        .send(address, &submitted, Duration::from_secs(5))
        .unwrap();
    assert!(accepted.ok);
    assert_eq!(accepted.value["block"], hex::encode(packet_id));
    let wrong_work = client
        .prepare(
            3,
            expiry,
            Request::Submit {
                packet: hex::encode(bad.encode().unwrap()),
            },
        )
        .unwrap();
    let refused = client
        .send(address, &wrong_work, Duration::from_secs(5))
        .unwrap();
    assert!(
        !refused.ok,
        "PQ signature cannot satisfy the original W1 relation"
    );
    let observed = client.prepare(4, expiry, Request::Head).unwrap();
    let head = client
        .send(address, &observed, Duration::from_secs(5))
        .unwrap();
    assert_eq!(head.value["height"], 1);
    assert_eq!(head.value["stored_blocks"], 2);
    stop.store(true, Ordering::Release);
    let metrics = handle.join().unwrap();
    assert!(metrics.refused >= 2);

    let reopened =
        Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    assert_eq!(reopened.active().unwrap().0, packet_id);
    assert_eq!(reopened.pq_network_status(&policy).unwrap()["records"], 4);
    let owner = Mutex::new(reopened);
    let server = PqServer::new(policy.clone(), signer(71)).unwrap();
    assert_eq!(
        server
            .handle(
                &owner,
                first.wire(),
                Instant::now() + Duration::from_secs(5)
            )
            .unwrap(),
        response1
    );
    println!(
        "{}",
        json!({"case":"real_tcp_pq_node","records":4,"blocks_including_genesis":2,
        "different_signature_same_operation":true,"lost_ack_recovered":true,"cold_reopen_cached_bytes":true,
        "request_bytes":first.wire().len(),"response_bytes":response1.len(),"metrics":metrics,
        "public_service_qualification":false,"whole_chain_pq":false})
    );
}

#[test]
fn pins_context_canonical_wire_sequence_and_classical_downgrade_refuse() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let policy = policy(&settings, 7);
    let node = Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    let client = PqClient::new(policy.clone(), signer(72)).unwrap();
    let server = PqServer::new(policy.clone(), signer(71)).unwrap();
    let expiry = super::super::now().unwrap() + 60;
    let request = client.prepare(1, expiry, Request::Head).unwrap();
    assert_eq!(request.wire()[8 + 6], 6, "TPQ1 peer purpose is preserved");
    let owner = Mutex::new(node);
    for offset in [
        0, 4, 8, 12, 13, 14, 15, 16, 48, 80, 112, 120, 128, 136, 184, 186,
    ] {
        let mut bad = request.wire().to_vec();
        bad[offset] ^= 1;
        assert!(
            server
                .handle(&owner, &bad, Instant::now() + Duration::from_secs(2))
                .is_err(),
            "offset {offset}"
        );
    }
    for length in [0, 1, 100, 3494] {
        assert!(server
            .handle(
                &owner,
                &request.wire()[..length],
                Instant::now() + Duration::from_secs(2)
            )
            .is_err());
    }
    let mut trailing = request.wire().to_vec();
    trailing.push(0);
    assert!(server
        .handle(&owner, &trailing, Instant::now() + Duration::from_secs(2))
        .is_err());
    assert_eq!(
        owner.lock().unwrap().pq_network_status(&policy).unwrap()["records"],
        0
    );
    // These frames carry valid real signatures, so byte-tamper negatives alone
    // cannot account for their rejection. Peer authentication grants no action
    // outside the original Request/Node owner and no alternate TPQ1 purpose.
    for payload in [
        br#"{ "op":"head" }"#.as_slice(),
        br#"{"op":"head","authorize":"spend"}"#.as_slice(),
        br#"{"op":"install","cell":"arbitrary"}"#.as_slice(),
    ] {
        let expected = policy.expectation(
            signer(72).public_key_id(),
            Direction::Request,
            1,
            expiry,
            super::super::now().unwrap(),
            payload,
        );
        let frame = signer(72)
            .sign_statement(&statement(&expected).unwrap(), &expected)
            .unwrap();
        let wire = encode_wire(REQUEST_MAGIC, &frame, payload).unwrap();
        assert!(server
            .handle(&owner, &wire, Instant::now() + Duration::from_secs(2))
            .is_err());
    }
    let other_generation = self::policy(&settings, 8);
    let other_request = PqClient::new(other_generation, signer(72))
        .unwrap()
        .prepare(1, expiry, Request::Head)
        .unwrap();
    assert_ne!(request.operation_id(), other_request.operation_id());
    assert!(server
        .handle(
            &owner,
            other_request.wire(),
            Instant::now() + Duration::from_secs(2)
        )
        .is_err());
    let payload = serde_json::to_vec(&Request::Head).unwrap();
    let mut wrong_purpose = policy.expectation(
        signer(72).public_key_id(),
        Direction::Request,
        1,
        expiry,
        super::super::now().unwrap(),
        &payload,
    );
    wrong_purpose.purpose = 1;
    let frame = signer(72)
        .sign_statement(&statement(&wrong_purpose).unwrap(), &wrong_purpose)
        .unwrap();
    assert!(server
        .handle(
            &owner,
            &encode_wire(REQUEST_MAGIC, &frame, &payload).unwrap(),
            Instant::now() + Duration::from_secs(2)
        )
        .is_err());
    assert_eq!(
        owner.lock().unwrap().pq_network_status(&policy).unwrap()["records"],
        0
    );
    let gap = client.prepare(2, expiry, Request::Head).unwrap();
    assert_eq!(
        server
            .handle(&owner, gap.wire(), Instant::now() + Duration::from_secs(2))
            .unwrap_err()
            .to_string(),
        "PQ_NETWORK_SEQUENCE_GAP"
    );
    server
        .handle(
            &owner,
            request.wire(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    let changed_lifetime = client.prepare(1, expiry - 1, Request::Head).unwrap();
    assert_ne!(request.operation_id(), changed_lifetime.operation_id());
    assert_eq!(
        server
            .handle(
                &owner,
                changed_lifetime.wire(),
                Instant::now() + Duration::from_secs(2)
            )
            .unwrap_err()
            .to_string(),
        "PQ_NETWORK_CONFLICTING_REPLAY"
    );
    let response = server
        .handle(
            &owner,
            request.wire(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    let mut forged_response = response;
    forged_response[8 + 178] ^= 1;
    assert!(policy
        .verify_response(
            &forged_response,
            &request.verified,
            super::super::now().unwrap()
        )
        .is_err());
    assert!(PqServer::new(policy.clone(), signer(72)).is_err());
    assert!(PqClient::new(policy.clone(), signer(74)).is_err());
    drop(owner);
    assert!(Node::open(directory.path(), settings.clone(), 1).is_err());
    assert!(Node::open_with_authenticated_state(directory.path(), settings.clone(), 1).is_err());
    let changed_policy = self::policy(&settings, 8);
    assert!(
        Node::open_with_pq_network(directory.path(), settings.clone(), 1, &changed_policy).is_err()
    );

    // All existing listener families must reject the new backend before accept.
    for family in 0..6 {
        let node =
            Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let identity =
            super::super::DevelopmentIdentity::from_secret_hex(&hex::encode([17; 32])).unwrap();
        let result = match family {
            0 => super::super::serve(listener, node, Duration::from_millis(10), stop).map(|_| ()),
            1 => super::super::serve_authenticated(
                listener,
                node,
                Duration::from_millis(10),
                stop,
                super::super::AuthenticatedServer::new(
                    identity,
                    [crate::development_public(1).map(hex::encode).unwrap()],
                    1,
                )
                .unwrap(),
            )
            .map(|_| ()),
            2 => super::super::public_v2::serve_public_protected_v2(
                listener,
                node,
                Duration::from_millis(10),
                stop,
                super::super::public_v2::PublicServer::new(
                    identity,
                    super::super::public_v2::PublicPolicy::development(),
                )
                .unwrap(),
            )
            .map(|_| ()),
            3 => super::super::public_v3::serve_public_protected_v3(
                listener,
                Arc::new(Mutex::new(node)),
                Duration::from_millis(10),
                stop,
                super::super::public_v3::PublicServer::new(
                    identity,
                    super::super::public_v3::PublicPolicy::development(),
                )
                .unwrap(),
            )
            .map(|_| ()),
            4 => super::super::serve_protected(
                listener,
                node,
                Duration::from_millis(10),
                stop,
                super::super::AdmissionPolicy::development(),
            )
            .map(|_| ()),
            _ => super::super::serve_authenticated_protected(
                listener,
                node,
                Duration::from_millis(10),
                stop,
                super::super::AuthenticatedServer::new(
                    identity,
                    [crate::development_public(1).map(hex::encode).unwrap()],
                    1,
                )
                .unwrap(),
                super::super::AdmissionPolicy::development(),
            )
            .map(|_| ()),
        };
        assert_eq!(result.unwrap_err().to_string(), "PQ_NETWORK_REQUIRED");
    }
}

#[test]
fn interrupted_owner_revocation_and_retained_ledger_corruption_fail_closed() {
    let settings = settings();
    let policy = policy(&settings, 1);
    let client = PqClient::new(policy.clone(), signer(72)).unwrap();
    let server = PqServer::new(policy.clone(), signer(71)).unwrap();
    let expiry = super::super::now().unwrap() + 60;
    let request = client.prepare(1, expiry, Request::Head).unwrap();
    {
        let directory = tempfile::tempdir().unwrap();
        let mut node =
            Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
        let (epoch, previous) = match node
            .begin_pq_network_request(&policy, &request.verified)
            .unwrap()
        {
            crate::store::pq_network::PqReplay::Execute(epoch, previous) => (epoch, previous),
            _ => panic!("new operation must reserve its original sequence"),
        };
        node.revoke_pq_network_peer(&policy, signer(72).public_key_id())
            .unwrap();
        assert_ne!(epoch.load(Ordering::Acquire), previous);
        let response = server
            .response(&request.verified, Ok(json!({"uncommitted":true})))
            .unwrap();
        assert_eq!(
            node.finish_pq_network_request(&policy, &request.verified, &response, previous)
                .unwrap_err()
                .to_string(),
            "PQ_NETWORK_REVOKED"
        );
        let before = node.pq_network_status(&policy).unwrap();
        drop(node);
        let node =
            Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
        assert_eq!(node.pq_network_status(&policy).unwrap(), before);
        assert_eq!(
            server
                .handle(
                    &Mutex::new(node),
                    request.wire(),
                    Instant::now() + Duration::from_secs(2)
                )
                .unwrap_err()
                .to_string(),
            "PQ_NETWORK_REVOKED"
        );
    }
    for mutation in [
        "UPDATE pq_network_request_v2 SET operation=zeroblob(32)",
        "UPDATE pq_network_request_v2 SET wire=zeroblob(length(wire))",
        "UPDATE pq_network_request_v2 SET response=zeroblob(length(response))",
        "UPDATE pq_network_request_v2 SET response_digest=zeroblob(32)",
        "UPDATE pq_network_peer_v2 SET highest_sequence=0",
        "DELETE FROM pq_network_request_v2",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let node =
            Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
        let owner = Mutex::new(node);
        server
            .handle(
                &owner,
                request.wire(),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        drop(owner);
        let db = rusqlite::Connection::open(directory.path().join("native.sqlite")).unwrap();
        db.execute(mutation, []).unwrap();
        drop(db);
        assert!(
            Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).is_err(),
            "retained ledger corruption: {mutation}"
        );
    }
}

#[test]
fn revocation_survives_actual_branch_reorg_and_cold_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let policy = policy(&settings, 1);
    let mut node =
        Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    let parent = settings.genesis();
    let a = node
        .make(
            parent,
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let b = node
        .make(
            parent,
            vec![],
            crate::development_public(1).unwrap(),
            settings.genesis_time() + 11,
            4096,
        )
        .unwrap();
    let a_id = node.admit(&a, super::super::now().unwrap()).unwrap();
    let b_id = node.admit(&b, super::super::now().unwrap()).unwrap();
    let b_child = node
        .make(
            b_id,
            vec![],
            crate::development_public(1).unwrap(),
            settings.genesis_time() + 21,
            4096,
        )
        .unwrap();
    let b_child_id = node.admit(&b_child, super::super::now().unwrap()).unwrap();
    node.activate(a_id).unwrap();
    assert_eq!(node.active().unwrap().0, a_id);
    let owner = Mutex::new(node);
    let server = PqServer::new(policy.clone(), signer(71)).unwrap();
    let client = PqClient::new(policy.clone(), signer(72)).unwrap();
    let request = client
        .prepare(1, super::super::now().unwrap() + 60, Request::Head)
        .unwrap();
    server
        .handle(
            &owner,
            request.wire(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let key_id = signer(72).public_key_id();
    let (before, after) = {
        let mut node = owner.lock().unwrap();
        node.revoke_pq_network_peer(&policy, key_id).unwrap();
        let before = node.pq_network_status(&policy).unwrap();
        node.activate(b_child_id).unwrap();
        assert_eq!(node.active().unwrap().0, b_child_id);
        (before, node.pq_network_status(&policy).unwrap())
    };
    assert_eq!(before, after);
    assert_eq!(
        server
            .handle(
                &owner,
                request.wire(),
                Instant::now() + Duration::from_secs(2)
            )
            .unwrap_err()
            .to_string(),
        "PQ_NETWORK_REVOKED"
    );
    // Revocation is not refunded by reorg, and rejecting this signed request
    // still consumes the real inbound verification attempt before authorization.
    let mut after_rejection = before.clone();
    after_rejection["inbound_signature_attempts"] =
        json!(before["inbound_signature_attempts"].as_u64().unwrap() + 1);
    assert_eq!(
        owner.lock().unwrap().pq_network_status(&policy).unwrap(),
        after_rejection
    );
    drop(owner);
    let reopened = Node::open_with_pq_network(directory.path(), settings, 1, &policy).unwrap();
    assert_eq!(reopened.active().unwrap().0, b_child_id);
    assert_eq!(
        reopened.pq_network_status(&policy).unwrap(),
        after_rejection
    );
    let reopened = Mutex::new(reopened);
    assert_eq!(
        server
            .handle(
                &reopened,
                request.wire(),
                Instant::now() + Duration::from_secs(2)
            )
            .unwrap_err()
            .to_string(),
        "PQ_NETWORK_REVOKED"
    );
    after_rejection["inbound_signature_attempts"] =
        json!(before["inbound_signature_attempts"].as_u64().unwrap() + 2);
    assert_eq!(
        reopened.lock().unwrap().pq_network_status(&policy).unwrap(),
        after_rejection
    );
}

#[test]
fn expired_pending_operation_retires_without_refreshing_sequence_or_authorization() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let policy = policy(&settings, 1);
    let mut node =
        Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    let client = PqClient::new(policy.clone(), signer(72)).unwrap();
    let expiry = super::super::now().unwrap() + 1;
    let request = client.prepare(1, expiry, Request::Head).unwrap();
    let old_epoch = match node
        .begin_pq_network_request(&policy, &request.verified)
        .unwrap()
    {
        crate::store::pq_network::PqReplay::Execute(epoch, value) => (epoch, value),
        _ => panic!("first request must be pending"),
    };
    let before = node.pq_network_status(&policy).unwrap();
    drop(node);
    while super::super::now().unwrap() <= expiry {
        thread::sleep(Duration::from_millis(10));
    }
    let node = Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    assert_eq!(node.pq_network_status(&policy).unwrap(), before);
    let owner = Mutex::new(node);
    let server = PqServer::new(policy.clone(), signer(71)).unwrap();
    assert!(server
        .handle(
            &owner,
            request.wire(),
            Instant::now() + Duration::from_secs(2)
        )
        .is_err());
    let next = client
        .prepare(2, super::super::now().unwrap() + 60, Request::Head)
        .unwrap();
    server
        .handle(&owner, next.wire(), Instant::now() + Duration::from_secs(3))
        .unwrap();
    assert_eq!(
        owner.lock().unwrap().pq_network_status(&policy).unwrap()["records"],
        2
    );
    // The old process's handle was not refreshed by reopening this owner.
    assert_eq!(old_epoch.0.load(Ordering::Acquire), old_epoch.1);
    drop(owner);
    let reopened = Node::open_with_pq_network(directory.path(), settings, 1, &policy).unwrap();
    assert_eq!(reopened.pq_network_status(&policy).unwrap()["records"], 2);
}

#[test]
fn actual_large_signed_invalid_requests_exhaust_durable_ledger_budget_without_restart_credit() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let policy = policy(&settings, 1);
    let node = Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    let owner = Mutex::new(node);
    let server = PqServer::new(policy.clone(), signer(71)).unwrap();
    let client = PqClient::new(policy.clone(), signer(72)).unwrap();
    let expiry = super::super::now().unwrap() + 60;
    let mut accepted = 0u64;
    let mut rejected = None;
    for sequence in 1..=20 {
        let request = client
            .prepare(
                sequence,
                expiry,
                Request::Submit {
                    packet: "0".repeat(1024 * 1024),
                },
            )
            .unwrap();
        match server.handle(
            &owner,
            request.wire(),
            Instant::now() + Duration::from_secs(5),
        ) {
            Ok(response) => {
                assert!(
                    !policy
                        .verify_response(&response, &request.verified, super::super::now().unwrap())
                        .unwrap()
                        .ok
                );
                accepted += 1;
            }
            Err(error) => {
                assert_eq!(error.to_string(), "PQ_NETWORK_LEDGER_BUDGET");
                rejected = Some(request);
                break;
            }
        }
    }
    let rejected = rejected.expect("original 16 MiB cap must actually exhaust");
    assert!(accepted > 0 && accepted < 20);
    let before = owner.lock().unwrap().pq_network_status(&policy).unwrap();
    drop(owner);
    let reopened = Node::open_with_pq_network(directory.path(), settings, 1, &policy).unwrap();
    assert_eq!(reopened.pq_network_status(&policy).unwrap(), before);
    assert_eq!(
        server
            .handle(
                &Mutex::new(reopened),
                rejected.wire(),
                Instant::now() + Duration::from_secs(5)
            )
            .unwrap_err()
            .to_string(),
        "PQ_NETWORK_LEDGER_BUDGET"
    );
    println!(
        "{}",
        json!({"case":"pq_native_durable_ledger_exhaustion","accepted_native_errors":accepted,"next_request_refused":true,"cold_reopen_no_credit":true,"status":before,"cpu_exhaustion_claim":false})
    );
}
