use super::{fixtures::Fixture, *};
use std::{
    io::{Read, Write},
    thread,
};

#[cfg(target_os = "linux")]
#[path = "shared_tests.rs"]
mod shared_tests;

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
fn tls_local_identity_requires_complete_key_pin_for_both_roles() {
    let fixture = Fixture::new();
    for server in [false, true] {
        let mut policy = fixture.policy_for_server_name("localhost");
        let identity = if server {
            &fixture.server
        } else {
            &fixture.peer
        };
        let local_id = identity.signer().public_key_id();
        let substitute = fixture.other.signer();
        let verifier = PqNativeVerifier::from_pinned_spki(
            substitute.public_spki(),
            substitute.public_key_id(),
        )
        .unwrap();
        // Deliberately model an identity-index alias without claiming to have
        // found a hash collision or changing any certificate/signature bytes.
        let owner = Arc::get_mut(&mut policy).unwrap();
        if server {
            owner.server = verifier;
        } else {
            owner.peers.insert(local_id, verifier);
        }
        let result = context::TlsContext::new(policy, local_id, identity.tls(&fixture.ca), server);
        let error = match result {
            Ok(_) => panic!("TLS local key admission used only the identity index"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "PQ_TLS_LOCAL_PIN");
    }
}

#[test]
fn actual_tls_peer_identity_alias_refuses_before_application_dispatch_in_both_directions() {
    for client_checks_server in [false, true] {
        let fixture = Fixture::new();
        let mut selected = fixture.policy_for_server_name("localhost");
        let substitute = fixture.other.signer();
        let verifier = PqNativeVerifier::from_pinned_spki(
            substitute.public_spki(),
            substitute.public_key_id(),
        )
        .unwrap();
        // The real TLS exchange below uses valid ML-DSA certificates, mutual
        // authentication and the pinned CA. This private mutation supplies the
        // conditional identity alias; it is not an observed SHA-256 collision.
        let owner = Arc::get_mut(&mut selected).unwrap();
        if client_checks_server {
            owner.server = verifier;
        } else {
            owner
                .peers
                .insert(fixture.peer.signer().public_key_id(), verifier);
        }
        let (client, server) = if client_checks_server {
            (
                PqTlsClient::new(
                    selected,
                    fixture.peer.signer(),
                    fixture.peer.tls(&fixture.ca),
                )
                .unwrap(),
                fixture.server(),
            )
        } else {
            (
                fixture.client(),
                PqTlsServer::new(
                    selected,
                    fixture.server.signer(),
                    fixture.server.tls(&fixture.ca),
                )
                .unwrap(),
            )
        };
        let directory = tempfile::tempdir().unwrap();
        let node = Node::open_with_pq_network(
            directory.path(),
            fixture.settings.clone(),
            1,
            &fixture.policy,
        )
        .unwrap();
        let prepared = client
            .prepare(1, crate::ingress::now().unwrap() + 30, Request::Head)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let worker = thread::spawn(move || {
            let owner = Mutex::new(node);
            // A client that expires before connecting must not leave join()
            // waiting on an unbounded accept. Accept and handshake consume
            // the same original interval, including every WouldBlock retry.
            let stream = (|| -> Result<TcpStream> {
                loop {
                    check_live_request(deadline, None)?;
                    match listener.accept() {
                        Ok((stream, _)) => return Ok(stream),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            })();
            let result = stream.and_then(|stream| server.connection(stream, &owner, deadline));
            (result, owner.into_inner().unwrap())
        });
        let client_result = client.exchange(address, prepared.wire(), deadline);
        let (server_result, node) = worker.join().unwrap();
        let error = if client_checks_server {
            client_result.expect_err("TLS client must reject an aliased server key")
        } else {
            server_result.expect_err("TLS server must reject an aliased client key")
        };
        assert_eq!(error.to_string(), "PQ_TLS_PEER_PIN");
        let status = node.pq_network_status(&fixture.policy).unwrap();
        assert_eq!(status["records"], 0);
        assert_eq!(status["inbound_signature_attempts"], 0);
    }
}

#[test]
fn real_tls_frame_split_boundary_preserves_exact_bytes_in_both_directions() {
    const LENGTHS: [usize; 3] = [16_379, 16_380, 16_381];
    fn payload(length: usize, salt: u8) -> Vec<u8> {
        (0..length)
            .map(|offset| (offset as u8).wrapping_mul(37).wrapping_add(salt))
            .collect()
    }

    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let owner = Mutex::new(node);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = fixture.server();
    let client = fixture.client();
    server.inner.policy.check_tls_listener(address).unwrap();
    // One original deadline covers the handshake and every frame, without
    // renewing the connection budget at the 16 KiB plaintext split.
    let deadline = Instant::now() + Duration::from_secs(5);
    thread::scope(|scope| {
        let sending = scope.spawn(move || {
            let remaining = deadline.checked_duration_since(Instant::now()).unwrap();
            let tcp = TcpStream::connect_timeout(&address, remaining).unwrap();
            let mut channel = io::Channel::connect(tcp, deadline, &client.context).unwrap();
            for length in LENGTHS {
                channel.write_frame(&payload(length, 0x35)).unwrap();
                let response = channel.read_frame().unwrap();
                assert_eq!(response.len(), length);
                assert!(
                    response == payload(length, 0xc7),
                    "exact server-to-client bytes at length {length}"
                );
            }
        });
        let tcp = loop {
            check_live_request(deadline, None).unwrap();
            match listener.accept() {
                Ok((tcp, _)) => break tcp,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("bounded TLS accept: {error}"),
            }
        };
        server
            .inner
            .policy
            .check_tls_client_ip(tcp.peer_addr().unwrap())
            .unwrap();
        server.inner.charge_connection(&owner, deadline).unwrap();
        let mut channel =
            io::Channel::accept(tcp, deadline, &server.context, &owner, &fixture.policy).unwrap();
        for length in LENGTHS {
            let request = channel.read_frame().unwrap();
            assert_eq!(request.len(), length);
            assert!(
                request == payload(length, 0x35),
                "exact client-to-server bytes at length {length}"
            );
            channel.write_frame(&payload(length, 0xc7)).unwrap();
        }
        sending.join().unwrap();
    });
    let status = owner
        .lock()
        .unwrap()
        .pq_network_status(&fixture.policy)
        .unwrap();
    let framed_bytes: usize = LENGTHS.iter().map(|length| length + 4).sum();
    assert!(status["ingress_bytes"].as_u64().unwrap() > framed_bytes as u64);
    assert_eq!(status["tls_handshake_attempts"], 1);
    // These are transport frames, not an admitted PNQ operation.
    assert_eq!(status["inbound_signature_attempts"], 0);
    assert_eq!(status["records"], 0);
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

#[test]
fn tls_local_server_certificate_constraints_refuse_before_serving() {
    let fixture = Fixture::new();
    let issuer = fixtures::key(61);
    for (label, name, profile) in fixtures::local_server_refusal_cases() {
        let certificate = fixtures::certificate_with_profile(
            &fixture.server.key,
            &issuer,
            name,
            "TRNM TLS fixture CA",
            false,
            91,
            &profile,
        );
        // Signature and key checks succeed, isolating the missing local
        // certificate constraints from a bad CA, wrong key or altered pin.
        let identity =
            PqTlsIdentity::new(certificate, fixture.server.key.clone(), fixture.ca.clone())
                .unwrap();
        let error = PqTlsServer::new(
            fixture.policy_for_server_name(name),
            fixture.server.signer(),
            identity,
        )
        .err()
        .unwrap_or_else(|| panic!("accepted {label}"));
        assert_eq!(
            error.to_string(),
            "PQ_TLS_LOCAL_CERTIFICATE_PROFILE",
            "{label}"
        );
    }
}

#[test]
fn tls_local_client_certificate_time_purpose_and_root_leaf_refuse() {
    use fixtures::CertificateProfile;
    let fixture = Fixture::new();
    let issuer = fixtures::key(61);
    for (label, profile) in [
        (
            "expired",
            CertificateProfile {
                not_before: b"230101000000Z",
                not_after: b"240101000000Z",
                ..CertificateProfile::default()
            },
        ),
        (
            "not yet valid",
            CertificateProfile {
                not_before: b"21200101000000Z",
                ..CertificateProfile::default()
            },
        ),
        (
            "server-only purpose",
            CertificateProfile {
                extended_key_usage: &[1],
                ..CertificateProfile::default()
            },
        ),
    ] {
        let certificate = fixtures::certificate_with_profile(
            &fixture.peer.key,
            &issuer,
            "peer",
            "TRNM TLS fixture CA",
            false,
            92,
            &profile,
        );
        let identity =
            PqTlsIdentity::new(certificate, fixture.peer.key.clone(), fixture.ca.clone()).unwrap();
        let error = PqTlsClient::new(fixture.policy.clone(), fixture.peer.signer(), identity)
            .err()
            .unwrap_or_else(|| panic!("accepted {label}"));
        assert_eq!(
            error.to_string(),
            "PQ_TLS_LOCAL_CERTIFICATE_PROFILE",
            "{label}"
        );
    }
    // A trusted root is not a leaf: peer admission requires the same exact
    // two-certificate chain even if its key was explicitly rostered.
    let policy = Arc::new(
        PqNetworkPolicy::new_tls13(
            &fixture.settings,
            &fixture.server.key.public_key_to_der().unwrap(),
            1,
            [issuer.public_key_to_der().unwrap()],
            fixture.policy.tls_pins().unwrap().clone(),
        )
        .unwrap(),
    );
    let root = fixtures::Identity {
        key: issuer,
        certificate: fixture.ca.clone(),
    };
    let error = PqTlsClient::new(policy, root.signer(), root.tls(&fixture.ca))
        .err()
        .expect("root certificate cannot stand in for a client leaf");
    assert_eq!(error.to_string(), "PQ_TLS_LOCAL_CERTIFICATE_PROFILE");
}

#[test]
fn tls_local_role_specific_certificates_accept_without_client_hostname() {
    use fixtures::CertificateProfile;
    let fixture = Fixture::new();
    let issuer = fixtures::key(61);
    let server = fixtures::certificate_with_profile(
        &fixture.server.key,
        &issuer,
        "server",
        "TRNM TLS fixture CA",
        false,
        93,
        &CertificateProfile {
            extended_key_usage: &[1],
            ..CertificateProfile::default()
        },
    );
    assert!(PqTlsServer::new(
        fixture.policy.clone(),
        fixture.server.signer(),
        PqTlsIdentity::new(server, fixture.server.key.clone(), fixture.ca.clone()).unwrap(),
    )
    .is_ok());
    let client = fixtures::certificate_with_profile(
        &fixture.peer.key,
        &issuer,
        "peer",
        "TRNM TLS fixture CA",
        false,
        94,
        &CertificateProfile {
            dns_name: None,
            extended_key_usage: &[2],
            ..CertificateProfile::default()
        },
    );
    assert!(PqTlsClient::new(
        fixture.policy.clone(),
        fixture.peer.signer(),
        PqTlsIdentity::new(client, fixture.peer.key.clone(), fixture.ca.clone()).unwrap(),
    )
    .is_ok());
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

fn send_untrusted_chain(
    address: SocketAddr,
    fixture: &Fixture,
    leaf: openssl::x509::X509,
    extra: Vec<openssl::x509::X509>,
    wire: &[u8],
) -> bool {
    use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream, SslVerifyMode, SslVersion};
    let mut context = SslContext::builder(SslMethod::tls()).unwrap();
    context
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    context
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    context.set_groups_list("X25519MLKEM768").unwrap();
    context.set_sigalgs_list("mldsa65").unwrap();
    context.set_verify(SslVerifyMode::PEER);
    context
        .cert_store_mut()
        .add_cert(fixture.ca.clone())
        .unwrap();
    context.set_alpn_protos(b"\x0etrnm-pq-node/1").unwrap();
    context.set_certificate(&leaf).unwrap();
    context.set_private_key(&fixture.peer.key).unwrap();
    for certificate in extra {
        context.add_extra_chain_cert(certificate).unwrap();
    }
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut ssl = Ssl::new(&context.build()).unwrap();
    ssl.param_mut().set_host("localhost").unwrap();
    let mut stream = SslStream::new(ssl, tcp).unwrap();
    if stream.connect().is_err() {
        return false;
    }
    let _ = stream.write_all(&(wire.len() as u32).to_be_bytes());
    let _ = stream.write_all(wire);
    let mut byte = [0];
    stream.read(&mut byte).is_ok_and(|count| count != 0)
}

#[test]
fn tls_invalid_intermediate_same_subject_chain_and_signature_spend_handshake_only() {
    let fixture = Fixture::new();
    let prepared = fixture
        .client()
        .prepare(1, crate::ingress::now().unwrap() + 60, Request::Head)
        .unwrap();
    let root = fixtures::key(61);
    let intermediate = fixtures::key(82);
    let intermediate_cert = fixtures::certificate(
        &intermediate,
        &root,
        "TRNM TLS fixture CA",
        "TRNM TLS fixture CA",
        true,
        82,
    );
    let leaf = fixtures::certificate(
        &fixture.peer.key,
        &intermediate,
        "peer",
        "TRNM TLS fixture CA",
        false,
        83,
    );
    let wrong_key = fixtures::key(84);
    let invalid_signature = fixtures::certificate(
        &fixture.peer.key,
        &wrong_key,
        "peer",
        "TRNM TLS fixture CA",
        false,
        84,
    );
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let (address, stop, handle) = start(node, &fixture);
    assert!(!send_untrusted_chain(
        address,
        &fixture,
        leaf.clone(),
        vec![intermediate_cert.clone()],
        prepared.wire()
    ));
    // Genuine same-subject candidates whose constructed DER exceeds 64 KiB.
    // The peer may reject early or omit duplicates, so this proves invalid-chain
    // refusal, NOT bytes observed on the wire or a certificate CPU bound.
    let candidates = vec![intermediate_cert; 16];
    assert!(
        candidates
            .iter()
            .map(|cert| cert.to_der().unwrap().len())
            .sum::<usize>()
            > 65_536
    );
    assert!(!send_untrusted_chain(
        address,
        &fixture,
        leaf,
        candidates,
        prepared.wire()
    ));
    assert!(!send_untrusted_chain(
        address,
        &fixture,
        invalid_signature,
        vec![],
        prepared.wire()
    ));
    assert_eq!(finish(stop, handle).refused, 3);
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let status = node.pq_network_status(&fixture.policy).unwrap();
    assert_eq!(status["records"], 0);
    assert_eq!(status["tls_handshake_attempts"], 3);
    assert_eq!(status["inbound_signature_attempts"], 0);
    assert!(status["ingress_bytes"].as_u64().unwrap() <= 3 * 65_536);
    assert_eq!(status["tls_certificate_verification_cpu_qualified"], false);
}

#[test]
fn tls_handshake_attempt_cap_is_durable_and_refuses_before_handshake_after_reopen() {
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
    for _ in 0..TLS_HANDSHAKE_LIMIT {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(b"PLAIN").unwrap();
        let mut byte = [0];
        let _ = stream.read(&mut byte);
    }
    assert_eq!(finish(stop, handle).refused, TLS_HANDSHAKE_LIMIT);
    let reopened = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let before = reopened.pq_network_status(&fixture.policy).unwrap();
    assert_eq!(before["tls_handshake_attempts"], TLS_HANDSHAKE_LIMIT);
    assert_eq!(before["inbound_signature_attempts"], 0);
    let (address, stop, handle) = start(reopened, &fixture);
    let client = fixture.client();
    let prepared = client
        .prepare(1, crate::ingress::now().unwrap() + 60, Request::Head)
        .unwrap();
    assert!(client
        .send(address, &prepared, Duration::from_secs(5))
        .is_err());
    assert_eq!(finish(stop, handle).refused, 1);
    let reopened = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    assert_eq!(reopened.pq_network_status(&fixture.policy).unwrap(), before);
}

#[test]
fn tls_authentication_does_not_replace_native_work_or_pnq_signature_checks() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let mut packet = node
        .make(
            fixture.settings.genesis(),
            vec![],
            crate::development_public(1).unwrap(),
            fixture.settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    packet.proof[4 + 2 * 64 * 64 * 4] ^= 1; // Original W1 relation's C, not an envelope failure.
    let client = fixture.client();
    let expiry = crate::ingress::now().unwrap() + 60;
    let bad_work = client
        .prepare(
            1,
            expiry,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
        )
        .unwrap();
    let head = client.prepare(2, expiry, Request::Head).unwrap();
    let mut bad_signature = head.wire().to_vec();
    bad_signature[8 + 178] ^= 1;
    let (address, stop, handle) = start(node, &fixture);
    assert!(
        !client
            .send(address, &bad_work, Duration::from_secs(5))
            .unwrap()
            .ok
    );
    assert!(client
        .exchange(
            address,
            &bad_signature,
            Instant::now() + Duration::from_secs(5)
        )
        .is_err());
    let head = client.send(address, &head, Duration::from_secs(5)).unwrap();
    assert_eq!(head.value["height"], 0);
    assert_eq!(head.value["stored_blocks"], 1);
    let metrics = finish(stop, handle);
    assert_eq!(metrics.accepted, 2); // Signed failure receipt + successful Head.
    assert_eq!(metrics.refused, 1);
    let reopened = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let status = reopened.pq_network_status(&fixture.policy).unwrap();
    assert_eq!(status["records"], 2);
    assert_eq!(status["inbound_signature_attempts"], 3);
}

#[test]
fn actual_tcp_bio_refuses_byte_65537_before_openssl_and_preserves_durable_debit() {
    // This exercises the receive direction, not a combined bidirectional cap.
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let owner = Mutex::new(node);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let sender = thread::spawn(move || {
        let mut tcp = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.write_all(&vec![0x5a; 65_537]).unwrap();
    });
    let (tcp, _) = listener.accept().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    fixture
        .server()
        .inner
        .charge_connection(&owner, deadline)
        .unwrap();
    let mut bio = io::DeadlineStream::new(tcp, deadline, Some((&owner, &fixture.policy))).unwrap();
    let mut actual = vec![0; 65_536];
    bio.read_exact(&mut actual).unwrap();
    assert_eq!(actual, vec![0x5a; 65_536]);
    let error = bio.read(&mut [0]).unwrap_err();
    assert!(error.to_string().contains("PQ_TLS_CIPHERTEXT_LIMIT"));
    sender.join().unwrap();
    drop(bio);
    let before = owner
        .lock()
        .unwrap()
        .pq_network_status(&fixture.policy)
        .unwrap();
    assert_eq!(before["ingress_bytes"], 65_536);
    assert_eq!(before["tls_handshake_attempts"], 1);
    assert_eq!(before["inbound_signature_attempts"], 0);
    assert_eq!(before["records"], 0);
    drop(owner);
    let reopened = Node::open_with_pq_network(
        directory.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    assert_eq!(reopened.pq_network_status(&fixture.policy).unwrap(), before);
}
