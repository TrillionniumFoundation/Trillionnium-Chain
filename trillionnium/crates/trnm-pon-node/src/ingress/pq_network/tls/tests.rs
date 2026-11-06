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

#[test]
fn tls_peer_cannot_relay_another_rostered_signers_request_into_node() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let client = fixture.client();
    let other = PqClient::new(fixture.policy.clone(), fixture.other.signer()).unwrap();
    let prepared = other
        .prepare(1, crate::ingress::now().unwrap() + 60, Request::Head)
        .unwrap();
    let (address, stop, handle) = start(node, &fixture);
    assert!(client
        .exchange(
            address,
            prepared.wire(),
            Instant::now() + Duration::from_secs(5)
        )
        .is_err());
    assert_eq!(finish(stop, handle).refused, 1);
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let status = node.pq_network_status(&fixture.policy).unwrap();
    assert_eq!(status["records"], 0);
    assert_eq!(status["inbound_signature_attempts"], 1);
    assert_eq!(status["tls_handshake_attempts"], 1);
    assert!(status["ingress_bytes"].as_u64().unwrap() > prepared.wire().len() as u64);
}

#[test]
fn tls_ca_hostname_and_local_identity_pins_refuse() {
    use openssl::pkey::PKey;
    let fixture = Fixture::new();
    let wrong_ca_key = fixtures::key(62);
    let wrong_ca = fixtures::certificate(
        &wrong_ca_key,
        &wrong_ca_key,
        "other CA",
        "other CA",
        true,
        2,
    );
    assert!(PqTlsIdentity::new(
        fixture.peer.certificate.clone(),
        fixture.peer.key.clone(),
        wrong_ca
    )
    .is_err());
    assert!(PqTlsClient::new(
        fixture.policy.clone(),
        fixture.peer.signer(),
        fixture.other.tls(&fixture.ca)
    )
    .is_err());
    let classical = PKey::generate_ed25519().unwrap();
    let root_key = fixtures::key(61);
    let classical_cert = fixtures::certificate(
        &classical,
        &root_key,
        "classical",
        "TRNM TLS fixture CA",
        false,
        9,
    );
    assert!(PqTlsIdentity::new(classical_cert, classical, fixture.ca.clone()).is_err());

    let wrong_hostname = Arc::new(
        PqNetworkPolicy::new_tls13(
            &fixture.settings,
            &fixture.server.key.public_key_to_der().unwrap(),
            1,
            [fixture.peer.key.public_key_to_der().unwrap()],
            PqTlsPins::new(
                fixture.policy.tls_pins().unwrap().ca_certificate_sha256(),
                "wrong.localhost".into(),
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let client = PqTlsClient::new(
        wrong_hostname,
        fixture.peer.signer(),
        fixture.peer.tls(&fixture.ca),
    )
    .unwrap();
    let prepared = client
        .prepare(1, crate::ingress::now().unwrap() + 60, Request::Head)
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let (address, stop, handle) = start(node, &fixture);
    assert!(client
        .send(address, &prepared, Duration::from_secs(5))
        .is_err());
    assert_eq!(finish(stop, handle).refused, 1);
    assert_eq!(
        Node::open_with_pq_network(
            directory.path(),
            fixture.settings.clone(),
            1,
            &fixture.policy
        )
        .unwrap()
        .pq_network_status(&fixture.policy)
        .unwrap()["records"],
        0
    );
}

fn raw_handshake(
    address: SocketAddr,
    fixture: &Fixture,
    group: &str,
    version: openssl::ssl::SslVersion,
    certificate: bool,
    wire: &[u8],
) -> (bool, bool) {
    use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream, SslVerifyMode};
    let mut context = SslContext::builder(SslMethod::tls()).unwrap();
    context.set_min_proto_version(Some(version)).unwrap();
    context.set_max_proto_version(Some(version)).unwrap();
    context.set_groups_list(group).unwrap();
    context.set_verify(SslVerifyMode::PEER);
    context
        .cert_store_mut()
        .add_cert(fixture.ca.clone())
        .unwrap();
    context.set_alpn_protos(b"\x0etrnm-pq-node/1").unwrap();
    if certificate {
        context.set_certificate(&fixture.peer.certificate).unwrap();
        context.set_private_key(&fixture.peer.key).unwrap();
    }
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut ssl = Ssl::new(&context.build()).unwrap();
    ssl.param_mut().set_host("localhost").unwrap();
    let mut stream = SslStream::new(ssl, tcp).unwrap();
    if stream.connect().is_err() {
        return (false, false);
    }
    // TLS 1.3's server rejection of a missing client certificate can arrive
    // after the client's handshake method returns. It must never accept data.
    let _ = stream.write_all(&(wire.len() as u32).to_be_bytes());
    let _ = stream.write_all(wire);
    let mut byte = [0];
    (true, stream.read(&mut byte).is_ok_and(|read| read != 0))
}

#[test]
fn actual_tls_node_refuses_classical_group_tls12_missing_certificate_and_plaintext() {
    use openssl::ssl::SslVersion;
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let (address, stop, handle) = start(node, &fixture);
    let client = fixture.client();
    let prepared = client
        .prepare(1, crate::ingress::now().unwrap() + 60, Request::Head)
        .unwrap();
    assert!(
        !raw_handshake(
            address,
            &fixture,
            "X25519",
            SslVersion::TLS1_3,
            true,
            prepared.wire()
        )
        .0
    );
    assert!(
        !raw_handshake(
            address,
            &fixture,
            "X25519",
            SslVersion::TLS1_2,
            true,
            prepared.wire()
        )
        .0
    );
    assert!(
        !raw_handshake(
            address,
            &fixture,
            "X25519MLKEM768",
            SslVersion::TLS1_3,
            false,
            prepared.wire()
        )
        .1
    );
    let mut raw = TcpStream::connect(address).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    raw.write_all(&(prepared.wire().len() as u32).to_be_bytes())
        .unwrap();
    let _ = raw.write_all(prepared.wire());
    let mut byte = [0];
    // TLS may return an alert; it cannot return a signed native receipt.
    let _ = raw.read(&mut byte);
    drop(raw);
    assert_eq!(finish(stop, handle).refused, 4);
    let reopened = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let status = reopened.pq_network_status(&fixture.policy).unwrap();
    assert_eq!(status["records"], 0);
    assert_eq!(status["ingress_connections"], 4);
    assert_eq!(status["inbound_signature_attempts"], 0);
    assert_eq!(status["tls_handshake_attempts"], 4);
}

#[test]
fn tls_handshake_does_not_reset_the_original_client_deadline() {
    let fixture = Fixture::new();
    let client = fixture.client();
    let prepared = client
        .prepare(1, crate::ingress::now().unwrap() + 60, Request::Head)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (release, wait) = std::sync::mpsc::channel();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let _ = wait.recv_timeout(Duration::from_secs(2));
        drop(stream);
    });
    let start = Instant::now();
    let result = client.send(address, &prepared, Duration::from_millis(120));
    let elapsed = start.elapsed();
    release.send(()).unwrap();
    handle.join().unwrap();
    assert!(result.is_err());
    assert!(elapsed < Duration::from_secs(1));
}

