use super::*;
use std::{
    io::{Read, Write},
    thread,
};
#[path = "fixtures.rs"]
mod fixtures;
use fixtures::Fixture;

fn start(
    node: Node,
    fixture: &Fixture,
) -> (
    SocketAddr,
    Arc<AtomicBool>,
    thread::JoinHandle<PqNetworkMetrics>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let server = fixture.server();
    let handle = thread::spawn(move || {
        serve_pq_tls13(listener, node, Duration::from_secs(45), stopping, server).unwrap()
    });
    (address, stop, handle)
}
fn finish(stop: Arc<AtomicBool>, handle: thread::JoinHandle<PqNetworkMetrics>) -> PqNetworkMetrics {
    stop.store(true, Ordering::Release);
    handle.join().unwrap()
}

#[test]
fn real_tls_node_submit_lost_ack_exact_receipt_and_cold_reopen() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let packet = node
        .make(
            fixture.settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            fixture.settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let packet_id = packet.id().unwrap();
    let client = fixture.client();
    let expiry = crate::ingress::now().unwrap() + 60;
    let head = client.prepare(1, expiry, Request::Head).unwrap();
    let alternate = client.prepare(1, expiry, Request::Head).unwrap();
    assert_eq!(head.operation_id(), alternate.operation_id());
    assert_ne!(head.wire(), alternate.wire());
    let submit = client
        .prepare(
            2,
            expiry,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
        )
        .unwrap();
    let (address, stop, handle) = start(node, &fixture);
    let original = client
        .exchange(
            address,
            head.wire(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(
        client
            .exchange(
                address,
                alternate.wire(),
                Instant::now() + Duration::from_secs(5)
            )
            .unwrap(),
        original
    );
    assert_eq!(
        fixture
            .policy
            .verify_response(&original, &head.verified, crate::ingress::now().unwrap())
            .unwrap()
            .value["height"],
        0
    );

    // The real TLS peer sends a complete signed block then loses the receipt.
    // The next connection enters the same durable Node operation, not another
    // effect. A handshake-specific exporter is intentionally NOT the operation ID.
    let deadline = Instant::now() + Duration::from_secs(5);
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    let mut lost_ack = io::Channel::connect(stream, deadline, &client.context).unwrap();
    lost_ack.write_frame(submit.wire()).unwrap();
    drop(lost_ack);
    let receipt = client
        .exchange(
            address,
            submit.wire(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let accepted = fixture
        .policy
        .verify_response(&receipt, &submit.verified, crate::ingress::now().unwrap())
        .unwrap();
    assert!(accepted.ok);
    assert_eq!(accepted.value["block"], hex::encode(packet_id));
    assert_eq!(
        client
            .send(address, &submit, Duration::from_secs(5))
            .unwrap(),
        accepted
    );
    let current = client.prepare(3, expiry, Request::Head).unwrap();
    let current = client
        .send(address, &current, Duration::from_secs(5))
        .unwrap();
    assert_eq!(current.value["height"], 1);
    assert_eq!(current.value["stored_blocks"], 2);
    let metrics = finish(stop, handle);
    assert!(metrics.accepted >= 5);

    let reopened = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    assert_eq!(reopened.active().unwrap().0, packet_id);
    assert_eq!(
        reopened.pq_network_status(&fixture.policy).unwrap()["records"],
        3
    );
    let (address, stop, handle) = start(reopened, &fixture);
    assert_eq!(
        client
            .exchange(
                address,
                head.wire(),
                Instant::now() + Duration::from_secs(5)
            )
            .unwrap(),
        original
    );
    assert_eq!(
        client
            .exchange(
                address,
                submit.wire(),
                Instant::now() + Duration::from_secs(5)
            )
            .unwrap(),
        receipt
    );
    finish(stop, handle);
    let reopened = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    assert_eq!(reopened.active().unwrap().0, packet_id);
    assert_eq!(
        reopened.pq_network_status(&fixture.policy).unwrap()["records"],
        3
    );
}

#[test]
fn tls_required_policy_refuses_plaintext_before_io_and_old_ledger_reopen() {
    let fixture = Fixture::new();
    let plaintext = Arc::new(
        PqNetworkPolicy::new(
            &fixture.settings,
            &fixture.server.key.public_key_to_der().unwrap(),
            1,
            [
                fixture.peer.key.public_key_to_der().unwrap(),
                fixture.other.key.public_key_to_der().unwrap(),
            ],
        )
        .unwrap(),
    );
    assert_ne!(plaintext.id(), fixture.policy.id());
    assert!(!String::from_utf8(plaintext.canonical().to_vec())
        .unwrap()
        .contains("\"tls\""));
    let old_directory = tempfile::tempdir().unwrap();
    drop(
        Node::open_with_pq_network(
            old_directory.path(),
            fixture.settings.clone(),
            1,
            &plaintext,
        )
        .unwrap(),
    );
    assert!(Node::open_with_pq_network(
        old_directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy
    )
    .is_err());
    assert_eq!(
        Node::open_with_pq_network(
            old_directory.path(),
            fixture.settings.clone(),
            1,
            &plaintext
        )
        .unwrap()
        .pq_network_status(&plaintext)
        .unwrap()["records"],
        0
    );
    assert!(PqTlsClient::new(
        plaintext,
        fixture.peer.signer(),
        fixture.peer.tls(&fixture.ca)
    )
    .is_err());

    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let client = PqClient::new(fixture.policy.clone(), fixture.peer.signer()).unwrap();
    let prepared = client
        .prepare(1, crate::ingress::now().unwrap() + 60, Request::Head)
        .unwrap();
    assert!(client
        .send(address, &prepared, Duration::from_secs(5))
        .unwrap_err()
        .to_string()
        .contains("PQ_TLS_REQUIRED"));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let owner = Mutex::new(node);
    let server = PqServer::new(fixture.policy.clone(), fixture.server.signer()).unwrap();
    assert!(server
        .handle(
            &owner,
            prepared.wire(),
            Instant::now() + Duration::from_secs(5)
        )
        .is_err());
    assert_eq!(
        owner
            .lock()
            .unwrap()
            .pq_network_status(&fixture.policy)
            .unwrap()["inbound_signature_attempts"],
        0
    );
    assert!(serve_pq_authenticated(
        listener,
        owner.into_inner().unwrap(),
        Duration::from_secs(1),
        Arc::new(AtomicBool::new(false)),
        server
    )
    .unwrap_err()
    .to_string()
    .contains("PQ_TLS_REQUIRED"));
}

