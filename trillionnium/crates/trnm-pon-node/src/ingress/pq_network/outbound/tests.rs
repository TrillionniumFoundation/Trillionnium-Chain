use super::*;
use crate::ingress::pq_network::{
    canonical_tests::key, tls::serve_pq_tls13, tls_fixtures, PqServer,
};
use crate::{Node, Settings};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::{
    net::{TcpListener, TcpStream},
    os::unix::fs::{symlink, PermissionsExt},
    sync::{Arc, Mutex},
    thread,
};

fn setup() -> (Settings, Arc<PqNetworkPolicy>) {
    let settings = Settings::development(Some(crate::ingress::now().unwrap() - 100)).unwrap();
    let policy = Arc::new(
        PqNetworkPolicy::new(
            &settings,
            key(71).public_spki(),
            1,
            [
                key(72).public_spki().to_vec(),
                key(73).public_spki().to_vec(),
            ],
        )
        .unwrap(),
    );
    (settings, policy)
}
fn client(policy: &Arc<PqNetworkPolicy>) -> PqClient {
    PqClient::new(policy.clone(), key(72)).unwrap()
}
fn expiry() -> u64 {
    crate::ingress::now().unwrap() + 60
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn error<T>(result: Result<T>) -> String {
    result.err().expect("expected refusal").to_string()
}
fn readonly(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}
fn remote_sequence(path: &Path) -> u64 {
    readonly(&path.join("native.sqlite"))
        .query_row(
            "SELECT highest_sequence FROM pq_network_peer_v2 WHERE peer=?",
            [key(72).public_key_id().as_slice()],
            |r| r.get(0),
        )
        .unwrap()
}
fn accept(listener: &TcpListener, end: Instant) -> Result<TcpStream> {
    listener.set_nonblocking(true)?;
    loop {
        ensure(Instant::now() < end, "OUTBOUND_TEST_ACCEPT_DEADLINE")?;
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e.into()),
        }
    }
}
struct Exchange {
    request: Vec<u8>,
    response: Vec<u8>,
}
fn serve_one(
    listener: &TcpListener,
    node: Arc<Mutex<Node>>,
    policy: Arc<PqNetworkPolicy>,
    journal: PathBuf,
    lose_ack: bool,
    cancel_after_commit: Option<Arc<AtomicBool>>,
) -> thread::JoinHandle<Result<Exchange>> {
    let listener = listener.try_clone().unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = accept(&listener, deadline)?;
        let server = PqServer::new(policy.clone(), key(71))?;
        let request = server.read_request(&node, &mut stream, deadline)?;
        // Read the actual committed journal through a separate connection at
        // the receiving socket. A memory-only reservation cannot satisfy this.
        let (wire, attempts): (Vec<u8>, u64) = readonly(&journal).query_row(
            "SELECT wire,attempts FROM pq_outbound_request_v1 WHERE response IS NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure(
            wire == request && attempts > 0,
            "OUTBOUND_TEST_PRE_SEND_DURABILITY",
        )?;
        let response = server.handle(&node, &request, deadline)?;
        if let Some(cancel) = cancel_after_commit {
            cancel.store(true, Ordering::Release);
        }
        if !lose_ack {
            crate::ingress::write_frame_deadline(&mut stream, &response, deadline)?;
        }
        Ok(Exchange { request, response })
    })
}

#[test]
fn real_node_lost_ack_cold_reopen_replays_exact_signed_request_and_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, policy) = setup();
    let node_path = directory.path().join("node");
    let journal = directory.path().join("client.sqlite");
    let node = Node::open_with_pq_network(&node_path, settings.clone(), 1, &policy).unwrap();
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
    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut outbound =
        DurablePqOutbound::create_plaintext(&journal, address, client(&policy)).unwrap();
    outbound
        .prepare(
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            expiry(),
            MAX_OPERATION_LIFETIME,
        )
        .unwrap();
    let before = outbound.checked().unwrap();
    let original = before.pending().unwrap();
    let original_wire = original.wire.clone();
    let original_deadline = original.deadline_ns;
    let serving = serve_one(
        &listener,
        owner.clone(),
        policy.clone(),
        journal.clone(),
        true,
        None,
    );
    assert!(outbound
        .send_pending(until(), &AtomicBool::new(false))
        .is_err());
    let first = serving.join().unwrap().unwrap();
    assert_eq!(first.request, original_wire);
    assert_eq!(outbound.status().unwrap().completed_sequence, 0);
    assert_eq!(outbound.status().unwrap().pending.unwrap().attempts, 1);
    assert_eq!(
        remote_sequence(&node_path),
        1,
        "remote terminal committed despite lost ACK"
    );
    assert_eq!(owner.lock().unwrap().active().unwrap().0, packet_id);
    drop(outbound);
    drop(owner);

    let node = Node::open_with_pq_network(&node_path, settings.clone(), 1, &policy).unwrap();
    let owner = Arc::new(Mutex::new(node));
    let mut outbound =
        DurablePqOutbound::open_plaintext(&journal, address, client(&policy)).unwrap();
    let reopened = outbound.checked().unwrap();
    assert_eq!(reopened.pending().unwrap().wire, original_wire);
    assert_eq!(reopened.pending().unwrap().deadline_ns, original_deadline);
    let serving = serve_one(
        &listener,
        owner.clone(),
        policy.clone(),
        journal.clone(),
        false,
        None,
    );
    let reply = outbound
        .send_pending(until(), &AtomicBool::new(false))
        .unwrap();
    let second = serving.join().unwrap().unwrap();
    assert_eq!(
        second.request, first.request,
        "not a newly randomized ML-DSA signature"
    );
    assert_eq!(
        second.response, first.response,
        "actual retained signed server receipt"
    );
    assert_eq!(reply.wire(), first.response);
    assert!(reply.response().ok);
    assert_eq!(reply.response().value["block"], hex::encode(packet_id));
    outbound.record_verified_reply(&reply).unwrap();
    assert_eq!(outbound.status().unwrap().completed_sequence, 1);
    assert!(outbound.status().unwrap().pending.is_none());
    assert_eq!(
        outbound
            .prepare(Request::Head, expiry(), MAX_OPERATION_LIFETIME)
            .unwrap()
            .sequence,
        2
    );
    let serving = serve_one(
        &listener,
        owner,
        policy.clone(),
        journal.clone(),
        false,
        None,
    );
    let head = outbound
        .send_pending(until(), &AtomicBool::new(false))
        .unwrap();
    serving.join().unwrap().unwrap();
    assert_eq!(head.response().value["height"], 1);
    assert_eq!(head.response().value["stored_blocks"], 2);
    assert_eq!(remote_sequence(&node_path), 2);
    drop(outbound);
    let reopened = DurablePqOutbound::open_plaintext(&journal, address, client(&policy)).unwrap();
    assert_eq!(
        reopened.retained_response(1).unwrap().unwrap(),
        reply.into_response()
    );
}

#[test]
fn real_tls_unknown_parent_is_committed_terminal_then_explicit_new_sequences_work() {
    let fixture = tls_fixtures::Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let node_path = directory.path().join("node");
    let journal = directory.path().join("client.sqlite");
    let mut producer = Node::open(
        &directory.path().join("producer"),
        fixture.settings.clone(),
        1,
    )
    .unwrap();
    let parent = producer
        .make(
            fixture.settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            fixture.settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    producer
        .admit(&parent, crate::ingress::now().unwrap())
        .unwrap();
    let child = producer
        .make(
            parent.id().unwrap(),
            vec![],
            crate::development_public(0).unwrap(),
            fixture.settings.genesis_time() + 20,
            4096,
        )
        .unwrap();
    let child_bytes = hex::encode(child.encode().unwrap());
    let target =
        Node::open_with_pq_network(&node_path, fixture.settings.clone(), 1, &fixture.policy)
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let server = fixture.server();
    let thread = thread::spawn(move || {
        serve_pq_tls13(listener, target, Duration::from_secs(30), stopping, server).unwrap()
    });
    let mut outbound = DurablePqOutbound::create_tls(&journal, address, fixture.client()).unwrap();
    outbound
        .prepare(
            Request::Submit {
                packet: child_bytes.clone(),
            },
            expiry(),
            MAX_OPERATION_LIFETIME,
        )
        .unwrap();
    let refused = outbound
        .send_pending(until(), &AtomicBool::new(false))
        .unwrap();
    assert!(!refused.response().ok);
    assert_eq!(refused.response().value["error"], "UNKNOWN_PARENT");
    assert_eq!(
        remote_sequence(&node_path),
        1,
        "a real dispatch refusal spends the remote sequence"
    );
    assert_eq!(outbound.status().unwrap().completed_sequence, 1);
    drop(outbound);
    let mut outbound = DurablePqOutbound::open_tls(&journal, address, fixture.client()).unwrap();
    assert_eq!(
        outbound.retained_response(1).unwrap().unwrap(),
        *refused.response()
    );
    // Deliberately explicit submissions, not an automatic parent recovery API.
    assert_eq!(
        outbound
            .prepare(
                Request::Submit {
                    packet: hex::encode(parent.encode().unwrap())
                },
                expiry(),
                MAX_OPERATION_LIFETIME
            )
            .unwrap()
            .sequence,
        2
    );
    assert!(
        outbound
            .send_pending(until(), &AtomicBool::new(false))
            .unwrap()
            .response()
            .ok
    );
    assert_eq!(
        outbound
            .prepare(
                Request::Submit {
                    packet: child_bytes
                },
                expiry(),
                MAX_OPERATION_LIFETIME
            )
            .unwrap()
            .sequence,
        3
    );
    assert!(
        outbound
            .send_pending(until(), &AtomicBool::new(false))
            .unwrap()
            .response()
            .ok
    );
    assert_eq!(remote_sequence(&node_path), 3);
    stop.store(true, Ordering::Release);
    assert_eq!(thread.join().unwrap().accepted, 3);
    let reopened =
        Node::open_with_pq_network(&node_path, fixture.settings, 1, &fixture.policy).unwrap();
    assert_eq!(reopened.active().unwrap().0, child.id().unwrap());
    assert_eq!(
        reopened.pq_network_status(&fixture.policy).unwrap()["records"],
        3
    );
}

#[test]
fn admission_resource_refusal_has_no_terminal_seal_and_cannot_advance_client_sequence() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, policy) = setup();
    let node_path = directory.path().join("node");
    let mut node = Node::open_with_pq_network(&node_path, settings, 1, &policy).unwrap();
    for _ in 0..64 {
        node.charge_pq_ingress(&policy, true, 0, false).unwrap();
    }
    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let journal = directory.path().join("client.sqlite");
    let mut outbound =
        DurablePqOutbound::create_plaintext(&journal, address, client(&policy)).unwrap();
    outbound
        .prepare(Request::Head, expiry(), MAX_OPERATION_LIFETIME)
        .unwrap();
    let serving = serve_one(
        &listener,
        owner,
        policy.clone(),
        journal.clone(),
        false,
        None,
    );
    assert!(outbound
        .send_pending(until(), &AtomicBool::new(false))
        .is_err());
    assert_eq!(error(serving.join().unwrap()), "PQ_NETWORK_INGRESS_BUDGET");
    assert_eq!(remote_sequence(&node_path), 0);
    assert_eq!(outbound.status().unwrap().completed_sequence, 0);
    assert_eq!(outbound.status().unwrap().pending.unwrap().attempts, 1);
    assert_eq!(
        error(outbound.prepare(Request::Head, expiry(), MAX_OPERATION_LIFETIME)),
        "PQ_OUTBOUND_UNRESOLVED"
    );
    drop(outbound);
    let reopened = DurablePqOutbound::open_plaintext(&journal, address, client(&policy)).unwrap();
    assert_eq!(reopened.status().unwrap().pending.unwrap().sequence, 1);
}

#[test]
fn sealed_reply_rejects_other_policy_peer_and_randomized_wire_even_for_same_operation() {
    use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
    use trnm_protocol::pq_frame::TPQ1_UNSIGNED_BYTES;

    let directory = tempfile::tempdir().unwrap();
    let (settings, policy) = setup();
    let node_path = directory.path().join("node");
    let owner = Arc::new(Mutex::new(
        Node::open_with_pq_network(&node_path, settings.clone(), 1, &policy).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let journal = directory.path().join("client.sqlite");
    let mut outbound =
        DurablePqOutbound::create_plaintext(&journal, address, client(&policy)).unwrap();
    let expiry = expiry();
    outbound
        .prepare(Request::Head, expiry, MAX_OPERATION_LIFETIME)
        .unwrap();
    let serving = serve_one(
        &listener,
        owner.clone(),
        policy.clone(),
        journal.clone(),
        true,
        None,
    );
    assert!(outbound
        .send_pending(until(), &AtomicBool::new(false))
        .is_err());
    let retained = serving.join().unwrap().unwrap();
    // The canonical seed owner signs deterministically. Exercise signature-only
    // variation with the existing OpenSSL owner for the same pinned public key.
    let repeated = client(&policy).prepare(1, expiry, Request::Head).unwrap();
    assert_eq!(repeated.wire(), retained.request);
    let signer =
        PqNativeSigningKey::from_owned_key(tls_fixtures::key(72), key(72).public_key_id()).unwrap();
    assert_eq!(signer.public_spki(), key(72).public_spki());
    let another = PqClient::new(policy.clone(), signer).unwrap();
    let randomized = another.prepare(1, expiry, Request::Head).unwrap();
    assert_ne!(randomized.wire(), retained.request);
    let signature_start = 8 + TPQ1_UNSIGNED_BYTES + 2;
    assert_eq!(
        &randomized.wire()[..signature_start],
        &retained.request[..signature_start]
    );
    assert_eq!(
        &randomized.wire()[8 + TPQ1_SIGNED_BYTES..],
        &retained.request[8 + TPQ1_SIGNED_BYTES..]
    );
    let randomized = PreparedPqRequest {
        verified: policy
            .verify_request(randomized.wire(), crate::ingress::now().unwrap())
            .unwrap(),
    };
    assert_eq!(
        randomized.operation_id(),
        outbound.status().unwrap().pending.unwrap().operation
    );
    let same_operation_reply = another
        .finish_response(&retained.response, &randomized, until())
        .unwrap();
    assert_eq!(
        error(outbound.record_verified_reply(&same_operation_reply)),
        "PQ_OUTBOUND_REPLY_CONTEXT"
    );

    for (peer, generation) in [(73, 1), (72, 2)] {
        let changed_policy = Arc::new(
            PqNetworkPolicy::new(
                &settings,
                key(71).public_spki(),
                generation,
                [
                    key(72).public_spki().to_vec(),
                    key(73).public_spki().to_vec(),
                ],
            )
            .unwrap(),
        );
        let changed_client = PqClient::new(changed_policy.clone(), key(peer)).unwrap();
        let prepared = changed_client.prepare(1, expiry, Request::Head).unwrap();
        // Real pinned signatures under a *different* owner context; these are
        // verification controls, not an assertion of remote execution.
        let server = PqServer::new(changed_policy, key(71)).unwrap();
        let wire = server
            .response(&prepared.verified, Ok(serde_json::json!({"test":true})))
            .unwrap();
        let reply = changed_client
            .finish_response(&wire, &prepared, until())
            .unwrap();
        assert_eq!(
            error(outbound.record_verified_reply(&reply)),
            "PQ_OUTBOUND_REPLY_CONTEXT"
        );
    }
    let exact = PreparedPqRequest {
        verified: policy
            .verify_request(&retained.request, crate::ingress::now().unwrap())
            .unwrap(),
    };
    let mut damaged = retained.response.clone();
    damaged[8 + TPQ1_SIGNED_BYTES - 1] ^= 1;
    assert!(another.finish_response(&damaged, &exact, until()).is_err());
    assert_eq!(outbound.status().unwrap().completed_sequence, 0);
    let mut late_client = client(&policy);
    late_client.before_response_completion = Some(Box::new(|end| {
        while Instant::now() < end {
            thread::sleep(end.saturating_duration_since(Instant::now()));
        }
    }));
    assert_eq!(
        error(late_client.finish_response(
            &retained.response,
            &exact,
            Instant::now() + Duration::from_millis(50),
        )),
        "PQ_NETWORK_DEADLINE"
    );
    assert_eq!(outbound.status().unwrap().completed_sequence, 0);
    let valid = another
        .finish_response(&retained.response, &exact, until())
        .unwrap();
    outbound.record_verified_reply(&valid).unwrap();
    outbound.record_verified_reply(&valid).unwrap();
    assert_eq!(outbound.status().unwrap().completed_sequence, 1);
}

#[test]
fn cancellation_is_durable_and_late_received_terminal_is_retained_without_timely_success() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, policy) = setup();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let journal = directory.path().join("cancel-before.sqlite");
    let mut outbound =
        DurablePqOutbound::create_plaintext(&journal, address, client(&policy)).unwrap();
    outbound
        .prepare(Request::Head, expiry(), MAX_OPERATION_LIFETIME)
        .unwrap();
    let cancel = AtomicBool::new(true);
    assert_eq!(
        error(outbound.send_pending(until(), &cancel)),
        "PQ_OUTBOUND_CANCELLED"
    );
    cancel.store(false, Ordering::Release);
    drop(outbound);
    let mut reopened =
        DurablePqOutbound::open_plaintext(&journal, address, client(&policy)).unwrap();
    assert_eq!(
        error(reopened.send_pending(until(), &cancel)),
        "PQ_OUTBOUND_CANCELLED"
    );
    assert_eq!(reopened.status().unwrap().pending.unwrap().attempts, 0);
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );

    let journal = directory.path().join("cancel-after.sqlite");
    let node_path = directory.path().join("node");
    let owner = Arc::new(Mutex::new(
        Node::open_with_pq_network(&node_path, settings, 1, &policy).unwrap(),
    ));
    let mut outbound =
        DurablePqOutbound::create_plaintext(&journal, address, client(&policy)).unwrap();
    outbound
        .prepare(Request::Head, expiry(), MAX_OPERATION_LIFETIME)
        .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let serving = serve_one(
        &listener,
        owner,
        policy.clone(),
        journal.clone(),
        false,
        Some(cancel.clone()),
    );
    assert_eq!(
        error(outbound.send_pending(until(), &cancel)),
        "PQ_OUTBOUND_CANCELLED"
    );
    serving.join().unwrap().unwrap();
    assert_eq!(remote_sequence(&node_path), 1);
    assert_eq!(outbound.status().unwrap().completed_sequence, 1);
    assert!(outbound.checked().unwrap().records[0].cancelled);
    drop(outbound);
    let reopened = DurablePqOutbound::open_plaintext(&journal, address, client(&policy)).unwrap();
    assert!(reopened.retained_response(1).unwrap().unwrap().ok);
    assert!(reopened.status().unwrap().pending.is_none());
}

#[test]
fn expired_pending_stays_unknown_while_expired_terminal_cold_audit_is_historical_only() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, policy) = setup();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let expires = crate::ingress::now().unwrap() + 2;
    let pending_path = directory.path().join("pending.sqlite");
    let complete_path = directory.path().join("complete.sqlite");
    let mut pending =
        DurablePqOutbound::create_plaintext(&pending_path, address, client(&policy)).unwrap();
    pending
        .prepare(Request::Head, expires, MAX_OPERATION_LIFETIME)
        .unwrap();
    let original = pending.checked().unwrap().pending().unwrap().wire.clone();
    drop(pending);
    let owner = Arc::new(Mutex::new(
        Node::open_with_pq_network(&directory.path().join("node"), settings, 1, &policy).unwrap(),
    ));
    let mut complete =
        DurablePqOutbound::create_plaintext(&complete_path, address, client(&policy)).unwrap();
    complete
        .prepare(Request::Head, expires, MAX_OPERATION_LIFETIME)
        .unwrap();
    let serving = serve_one(
        &listener,
        owner,
        policy.clone(),
        complete_path.clone(),
        false,
        None,
    );
    complete
        .send_pending(until(), &AtomicBool::new(false))
        .unwrap();
    serving.join().unwrap().unwrap();
    drop(complete);
    while crate::ingress::now().unwrap() <= expires {
        thread::sleep(Duration::from_millis(20));
    }
    let mut pending =
        DurablePqOutbound::open_plaintext(&pending_path, address, client(&policy)).unwrap();
    assert_eq!(
        error(pending.send_pending(until(), &AtomicBool::new(false))),
        "PQ_NETWORK_EXPIRED_UNCONFIRMED"
    );
    assert_eq!(
        error(pending.prepare(Request::Head, expiry(), MAX_OPERATION_LIFETIME)),
        "PQ_OUTBOUND_UNRESOLVED"
    );
    assert_eq!(pending.checked().unwrap().pending().unwrap().wire, original);
    assert_eq!(pending.status().unwrap().completed_sequence, 0);
    assert_eq!(pending.status().unwrap().pending.unwrap().attempts, 0);
    let complete =
        DurablePqOutbound::open_plaintext(&complete_path, address, client(&policy)).unwrap();
    assert!(complete.retained_response(1).unwrap().unwrap().ok);
    assert_eq!(complete.status().unwrap().completed_sequence, 1);
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn original_boot_deadline_attempt_limit_and_boot_change_cannot_be_renewed_by_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let (_, policy) = setup();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener); // Connect refusal is a genuine ambiguous transport outcome.
    let path = directory.path().join("attempts.sqlite");
    let mut outbound =
        DurablePqOutbound::create_plaintext(&path, address, client(&policy)).unwrap();
    outbound
        .prepare(Request::Head, expiry(), MAX_OPERATION_LIFETIME)
        .unwrap();
    let original = outbound.checked().unwrap().pending().unwrap().wire.clone();
    for attempt in 1..=MAX_OUTBOUND_ATTEMPTS {
        assert!(outbound
            .send_pending(until(), &AtomicBool::new(false))
            .is_err());
        assert_eq!(
            outbound.status().unwrap().pending.unwrap().attempts,
            attempt
        );
        drop(outbound);
        outbound = DurablePqOutbound::open_plaintext(&path, address, client(&policy)).unwrap();
    }
    assert_eq!(
        error(outbound.send_pending(until(), &AtomicBool::new(false))),
        "PQ_OUTBOUND_ATTEMPT_LIMIT"
    );
    assert_eq!(
        outbound.checked().unwrap().pending().unwrap().wire,
        original
    );
    let short = directory.path().join("deadline.sqlite");
    let mut short_owner =
        DurablePqOutbound::create_plaintext(&short, address, client(&policy)).unwrap();
    short_owner
        .prepare(Request::Head, expiry(), Duration::from_secs(1))
        .unwrap();
    let original_deadline = short_owner
        .checked()
        .unwrap()
        .pending()
        .unwrap()
        .deadline_ns;
    drop(short_owner);
    while boot_clock().unwrap().1 < original_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let mut short_owner =
        DurablePqOutbound::open_plaintext(&short, address, client(&policy)).unwrap();
    assert_eq!(
        error(short_owner.send_pending(until(), &AtomicBool::new(false))),
        "PQ_OUTBOUND_DEADLINE_UNCONFIRMED"
    );
    assert_eq!(short_owner.status().unwrap().pending.unwrap().attempts, 0);
    drop(short_owner);
    readonly(&short).close().unwrap();
    // Model a different kernel boot in the local clock record, without
    // forging/changing a request signature or manufacturing an ACK.
    let db = Connection::open(&short).unwrap();
    db.execute("UPDATE pq_outbound_request_v1 SET boot_id=zeroblob(16)", [])
        .unwrap();
    drop(db);
    let mut different_boot =
        DurablePqOutbound::open_plaintext(&short, address, client(&policy)).unwrap();
    assert_eq!(
        error(different_boot.send_pending(until(), &AtomicBool::new(false))),
        "PQ_OUTBOUND_BOOT_CHANGED_UNCONFIRMED"
    );
    assert_eq!(different_boot.status().unwrap().completed_sequence, 0);
}

#[test]
fn failed_durable_attempt_latches_before_socket_and_reopen_recovers_actual_state() {
    let directory = tempfile::tempdir().unwrap();
    let (_, policy) = setup();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let path = directory.path().join("client.sqlite");
    let mut outbound =
        DurablePqOutbound::create_plaintext(&path, address, client(&policy)).unwrap();
    outbound
        .prepare(Request::Head, expiry(), MAX_OPERATION_LIFETIME)
        .unwrap();
    // Deny the actual SQLite UPDATE after BEGIN, not a successful mock store.
    outbound
        .db
        .authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update {
                table_name: "pq_outbound_request_v1",
                ..
            } => Authorization::Deny,
            _ => Authorization::Allow,
        }))
        .unwrap();
    assert!(outbound
        .send_pending(until(), &AtomicBool::new(false))
        .is_err());
    assert_eq!(error(outbound.status()), "PQ_OUTBOUND_COMMIT_UNCERTAIN");
    assert_eq!(
        error(outbound.send_pending(until(), &AtomicBool::new(false))),
        "PQ_OUTBOUND_COMMIT_UNCERTAIN"
    );
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(outbound);
    let reopened = DurablePqOutbound::open_plaintext(&path, address, client(&policy)).unwrap();
    assert_eq!(reopened.status().unwrap().pending.unwrap().attempts, 0);
    assert_eq!(reopened.status().unwrap().completed_sequence, 0);
}

#[test]
fn create_open_context_single_writer_schema_and_storage_identity_are_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, policy) = setup();
    let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let path = directory.path().join("client.sqlite");
    assert!(DurablePqOutbound::open_plaintext(&path, address, client(&policy)).is_err());
    assert!(!path.exists());
    let foreign = directory.path().join("other-owner.sqlite");
    let db = Connection::open(&foreign).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE other_owner(value INTEGER); INSERT INTO other_owner VALUES(7);").unwrap();
    drop(db);
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        error(DurablePqOutbound::open_plaintext(
            &foreign,
            address,
            client(&policy)
        )),
        "PQ_OUTBOUND_SCHEMA"
    );
    let db = readonly(&foreign);
    assert_eq!(
        db.pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    assert_eq!(
        db.query_row("SELECT value FROM other_owner", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        7
    );
    drop(db);
    let mut outbound =
        DurablePqOutbound::create_plaintext(&path, address, client(&policy)).unwrap();
    assert_eq!(
        error(DurablePqOutbound::open_plaintext(
            &path,
            address,
            client(&policy)
        )),
        "PQ_OUTBOUND_BUSY"
    );
    assert!(DurablePqOutbound::create_plaintext(&path, address, client(&policy)).is_err());
    outbound
        .prepare(Request::Head, expiry(), MAX_OPERATION_LIFETIME)
        .unwrap();
    drop(outbound);
    let changed = Arc::new(
        PqNetworkPolicy::new(
            &settings,
            key(71).public_spki(),
            2,
            [
                key(72).public_spki().to_vec(),
                key(73).public_spki().to_vec(),
            ],
        )
        .unwrap(),
    );
    for (selected, peer, destination) in [
        (policy.clone(), 72, "127.0.0.1:2".parse().unwrap()),
        (policy.clone(), 73, address),
        (changed, 72, address),
    ] {
        let caller = PqClient::new(selected, key(peer)).unwrap();
        assert_eq!(
            error(DurablePqOutbound::open_plaintext(
                &path,
                destination,
                caller
            )),
            "PQ_OUTBOUND_BINDING"
        );
    }
    let link = directory.path().join("link.sqlite");
    symlink(&path, &link).unwrap();
    assert!(DurablePqOutbound::open_plaintext(&link, address, client(&policy)).is_err());
    fs::remove_file(&link).unwrap();
    fs::hard_link(&path, &link).unwrap();
    assert_eq!(
        error(DurablePqOutbound::open_plaintext(
            &path,
            address,
            client(&policy)
        )),
        "PQ_OUTBOUND_STORAGE_IDENTITY"
    );
    fs::remove_file(&link).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        error(DurablePqOutbound::open_plaintext(
            &path,
            address,
            client(&policy)
        )),
        "PQ_OUTBOUND_STORAGE_IDENTITY"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let baseline = fs::read(&path).unwrap();
    for sql in [
        "CREATE TABLE unexpected(value BLOB)",
        "UPDATE pq_outbound_meta_v1 SET highest_sequence=1",
        "UPDATE pq_outbound_request_v1 SET sequence=2",
        "UPDATE pq_outbound_request_v1 SET attempts='invalid'",
        "UPDATE pq_outbound_request_v1 SET wire=zeroblob(2097153)",
        "UPDATE pq_outbound_request_v1 SET response=zeroblob(4000),attempts=1; UPDATE pq_outbound_meta_v1 SET highest_sequence=1",
    ] {
        fs::write(&path, &baseline).unwrap();
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA ignore_check_constraints=ON").unwrap();
        db.execute_batch(sql).unwrap();
        drop(db);
        assert!(DurablePqOutbound::open_plaintext(&path, address, client(&policy)).is_err(), "{sql}");
    }
    // Legal row widths do not make a restored aggregate fit the reservation.
    // These malformed stores must fail before signature CPU or blob allocation.
    fs::write(&path, &baseline).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("DELETE FROM pq_outbound_request_v1; WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5) INSERT INTO pq_outbound_request_v1 SELECT x,zeroblob(32),zeroblob(2097152),zeroblob(16),0,1,1,0,zeroblob(2097152) FROM n; UPDATE pq_outbound_meta_v1 SET highest_sequence=5;").unwrap();
    drop(db);
    assert_eq!(
        error(DurablePqOutbound::open_plaintext(
            &path,
            address,
            client(&policy)
        )),
        "PQ_OUTBOUND_BYTE_LIMIT"
    );
    fs::write(&path, &baseline).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("DELETE FROM pq_outbound_request_v1; WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<65) INSERT INTO pq_outbound_request_v1 SELECT x,zeroblob(32),zeroblob(4000),zeroblob(16),0,1,1,0,CASE WHEN x=65 THEN NULL ELSE zeroblob(4000) END FROM n; UPDATE pq_outbound_meta_v1 SET highest_sequence=64;").unwrap();
    drop(db);
    assert_eq!(
        error(DurablePqOutbound::open_plaintext(
            &path,
            address,
            client(&policy)
        )),
        "PQ_OUTBOUND_STATE"
    );
    fs::write(&path, &baseline).unwrap();
    let outbound = DurablePqOutbound::open_plaintext(&path, address, client(&policy)).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE pq_outbound_request_v1 SET attempts=1", [])
        .unwrap();
    drop(db);
    assert_eq!(error(outbound.status()), "PQ_OUTBOUND_STORAGE_CHANGED");
}
