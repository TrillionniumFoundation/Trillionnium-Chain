// Native ML-DSA controls for exact cold request restoration and signed evidence.
// Disposable fixture keys do not qualify deployment custody or rollback defense.
fn expired_fixture(policy: &PqNetworkPolicy, sequence: u64) -> VerifiedRequest {
    let expiry = crate::ingress::now().unwrap().checked_sub(1).unwrap();
    let peer = signer(72);
    let payload = serde_json::to_vec(&Request::Head).unwrap();
    let expected = policy.expectation(
        peer.public_key_id(), Direction::Request, sequence, expiry, expiry, &payload,
    );
    let signature = peer
        .sign_statement(&statement(&expected).unwrap(), &expected)
        .unwrap();
    let wire = encode_wire(policy.request_magic(), &signature, &payload).unwrap();
    // A fixture explicitly verified at its historical instant. The product
    // restoration API below must independently refuse it at current time.
    policy.verify_request(&wire, expiry).unwrap()
}

#[test]
fn cold_request_restore_preserves_original_signature_sequence_expiry_and_body() {
    let settings = settings();
    let policy = policy(&settings, 1);
    let client = PqClient::new(policy.clone(), signer(72)).unwrap();
    let expiry = crate::ingress::now().unwrap() + 30;
    let request = client.prepare(7, expiry, Request::Head).unwrap();
    let wire = request.wire().to_vec();
    let operation = request.operation_id();
    drop(request);
    drop(client);
    let reopened = PqClient::new(policy, signer(72)).unwrap();
    let restored = reopened.restore_prepared(&wire).unwrap();
    assert_eq!(restored.wire(), wire);
    assert_eq!(restored.operation_id(), operation);
    assert_eq!(restored.sequence(), 7);
    assert_eq!(restored.expires_at(), expiry);
    assert_eq!(
        serde_json::to_vec(restored.request()).unwrap(),
        serde_json::to_vec(&Request::Head).unwrap()
    );
}

#[test]
fn cold_request_restore_refuses_other_peer_policy_genesis_expiry_and_bad_bytes() {
    let settings = settings();
    let selected = policy(&settings, 1);
    let client = PqClient::new(selected.clone(), signer(72)).unwrap();
    let prepared = client
        .prepare(1, crate::ingress::now().unwrap() + 30, Request::Head)
        .unwrap();
    assert!(PqClient::new(selected.clone(), signer(73)).unwrap()
        .restore_prepared(prepared.wire()).is_err());
    assert!(PqClient::new(policy(&settings, 2), signer(72)).unwrap()
        .restore_prepared(prepared.wire()).is_err());
    let other = Settings::development(Some(settings.genesis_time() - 1)).unwrap();
    assert!(PqClient::new(policy(&other, 1), signer(72)).unwrap()
        .restore_prepared(prepared.wire()).is_err());
    let expired = expired_fixture(&selected, 2);
    assert!(client.restore_prepared(&expired.wire).is_err());
    let mut tampered = prepared.wire().to_vec();
    tampered[8 + 178] ^= 1;
    assert!(client.restore_prepared(&tampered).is_err());
    assert!(client.restore_prepared(b"{}").is_err());
}

#[test]
fn retained_signed_reply_audit_cannot_restore_expired_or_cross_request_authority() {
    let settings = settings();
    let policy = policy(&settings, 1);
    let client = PqClient::new(policy.clone(), signer(72)).unwrap();
    let server = PqServer::new(policy.clone(), signer(71)).unwrap();
    let old = expired_fixture(&policy, 1);
    let signed_reply = server.response(&old, Ok(json!({"fixture": true}))).unwrap();
    client.audit_retained_reply(&old.wire, &signed_reply).unwrap();
    assert!(client.restore_prepared(&old.wire).is_err());
    assert!(client.restore_prepared(&signed_reply).is_err());
    let other = expired_fixture(&policy, 2);
    assert!(client.audit_retained_reply(&other.wire, &signed_reply).is_err());
    assert!(PqClient::new(policy, signer(73)).unwrap()
        .audit_retained_reply(&old.wire, &signed_reply).is_err());
    let mut tampered = signed_reply;
    tampered[8 + 178] ^= 1;
    assert!(client.audit_retained_reply(&old.wire, &tampered).is_err());
}

#[test]
fn actual_tcp_signed_evidence_survives_client_and_node_cold_reopen_without_reexecution() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let policy = policy(&settings, 1);
    let node = Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    let client = PqClient::new(policy.clone(), signer(72)).unwrap();
    let prepared = client
        .prepare(1, crate::ingress::now().unwrap() + 30, Request::Head)
        .unwrap();
    let request_wire = prepared.wire().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = PqServer::new(policy.clone(), signer(71)).unwrap();
    let handle = thread::spawn(move || {
        serve_pq_authenticated(listener, node, Duration::from_secs(20), server_stop, server)
    });
    let first = client.send_with_evidence(address, &prepared, Duration::from_secs(5));
    let repeated = match first.as_ref() {
        Ok(_) => raw_request(address, &request_wire),
        Err(_) => Err("FIRST_EXCHANGE_REFUSED".into()),
    };
    stop.store(true, Ordering::Release);
    let terminal = handle.join().unwrap();
    let evidence = first.unwrap();
    let repeated = repeated.unwrap();
    assert_eq!(terminal.unwrap().accepted, 2);
    assert!(evidence.response().ok);
    assert_eq!(evidence.wire(), repeated);
    assert_eq!(evidence.response().value["height"], 0);
    drop(client);
    let reopened = PqClient::new(policy.clone(), signer(72)).unwrap();
    reopened.audit_retained_reply(&request_wire, evidence.wire()).unwrap();
    let restored = reopened.restore_prepared(&request_wire).unwrap();
    assert_eq!(restored.wire(), request_wire);
    let node = Node::open_with_pq_network(directory.path(), settings, 1, &policy).unwrap();
    assert_eq!(node.pq_network_status(&policy).unwrap()["records"], 1);
    let owner = Mutex::new(node);
    let server = PqServer::new(policy, signer(71)).unwrap();
    let after_restart = server.handle(
        &owner, restored.wire(), Instant::now() + Duration::from_secs(5),
    ).unwrap();
    assert_eq!(after_restart, evidence.wire());
    assert_eq!(evidence.into_response().value["height"], 0);
}
