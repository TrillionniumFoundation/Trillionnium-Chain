use super::{fixtures::Fixture, *};
use crate::pq_rollback_witness::{
    initial_network_checkpoint, DurableWitness, WitnessBinding, WitnessClient, WitnessTransport,
};
use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    sync::atomic::AtomicUsize,
    thread,
};

fn endpoint(fixture: &Fixture, address: SocketAddr, ips: Vec<IpAddr>) -> Arc<PqNetworkPolicy> {
    Arc::new(
        PqNetworkPolicy::new_tls13_endpoint(
            &fixture.settings,
            &fixture.server.key.public_key_to_der().unwrap(),
            1,
            [
                fixture.peer.key.public_key_to_der().unwrap(),
                fixture.other.key.public_key_to_der().unwrap(),
            ],
            fixture.policy.tls_pins().unwrap().clone(),
            PqTlsEndpointPins::new(address, ips).unwrap(),
        )
        .unwrap(),
    )
}

fn local_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn tls_client(fixture: &Fixture, policy: Arc<PqNetworkPolicy>) -> PqTlsClient {
    PqTlsClient::new(policy, fixture.peer.signer(), fixture.peer.tls(&fixture.ca)).unwrap()
}

fn tls_server(fixture: &Fixture, policy: Arc<PqNetworkPolicy>) -> PqTlsServer {
    PqTlsServer::new(
        policy,
        fixture.server.signer(),
        fixture.server.tls(&fixture.ca),
    )
    .unwrap()
}

// Real signed witness requests and durable SQLite transitions. Only the test
// transport is in-process; independent daemon/custody evidence is not inferred.
struct Transport {
    owner: Arc<Mutex<DurableWitness>>,
    calls: Arc<AtomicUsize>,
}
impl WitnessTransport for Transport {
    fn exchange(&mut self, request: &[u8], until: Instant) -> Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.owner.lock().unwrap().handle(request, until)
    }
}

struct Witness {
    owner: Arc<Mutex<DurableWitness>>,
    calls: Arc<AtomicUsize>,
}
impl Witness {
    fn binding(policy: &PqNetworkPolicy) -> WitnessBinding {
        let witness = fixtures::key(92);
        let writer = fixtures::key(91);
        WitnessBinding::new(
            policy,
            1,
            &witness.public_key_to_der().unwrap(),
            &writer.public_key_to_der().unwrap(),
        )
        .unwrap()
    }
    fn signer(seed: u8) -> PqNativeSigningKey {
        let key = fixtures::key(seed);
        let id = ml_dsa_65_key_id_from_spki(&key.public_key_to_der().unwrap()).unwrap();
        PqNativeSigningKey::from_owned_key(key, id).unwrap()
    }
    fn new(policy: &PqNetworkPolicy, directory: &Path) -> Self {
        let binding = Self::binding(policy);
        let initial = initial_network_checkpoint(policy, &binding).unwrap();
        Self {
            owner: Arc::new(Mutex::new(
                DurableWitness::register_new(
                    &directory.join("witness.sqlite"),
                    binding,
                    initial,
                    Self::signer(92),
                )
                .unwrap(),
            )),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn client(&self, policy: &PqNetworkPolicy) -> WitnessClient {
        WitnessClient::new(
            Self::binding(policy),
            Self::signer(91),
            Box::new(Transport {
                owner: self.owner.clone(),
                calls: self.calls.clone(),
            }),
        )
        .unwrap()
    }
}

fn start(
    listener: TcpListener,
    node: Node,
    server: PqTlsServer,
) -> (Arc<AtomicBool>, thread::JoinHandle<PqNetworkMetrics>) {
    let stop = Arc::new(AtomicBool::new(false));
    let halted = stop.clone();
    let worker = thread::spawn(move || {
        serve_pq_tls13(listener, node, Duration::from_secs(10), halted, server).unwrap()
    });
    (stop, worker)
}

#[test]
fn endpoint_policy_keeps_legacy_bytes_and_separates_signed_domains() {
    let fixture = Fixture::new();
    // Independently spell the original field order and shape: the new optional
    // endpoint field must not add even a null to the old canonical TLS policy.
    let old = &fixture.policy.record;
    let legacy =
        format!(
            concat!("{{\"schema\":\"{}\",\"network\":\"{}\",\"parameters\":\"{}\",",
        "\"genesis\":\"{}\",\"server_spki\":\"{}\",\"generation\":{},\"peers\":{},",
        "\"ledger_byte_limit\":{},\"ledger_record_limit\":{},\"ingress_connection_limit\":{},",
        "\"ingress_byte_limit\":{},\"inbound_verification_limit\":{},",
        "\"transport_confidentiality\":\"{}\",\"tls\":{}}}"),
            TLS_PROFILE,
            old.network,
            old.parameters,
            old.genesis,
            old.server_spki,
            old.generation,
            serde_json::to_string(&old.peers).unwrap(),
            MAX_LEDGER_BYTES,
            MAX_RECORDS,
            TLS_HANDSHAKE_LIMIT,
            MAX_INGRESS_BYTES,
            MAX_INBOUND_VERIFICATIONS,
            TLS_TRANSPORT_MODE,
            serde_json::to_string(fixture.policy.tls_pins().unwrap()).unwrap(),
        );
    assert_eq!(fixture.policy.canonical(), legacy.as_bytes());
    assert_eq!(
        fixture.policy.id(),
        hash(b"native-pq-network-tls13-policy-v1", &[legacy.as_bytes()])
    );
    let policy = endpoint(
        &fixture,
        "127.0.0.1:31001".parse().unwrap(),
        vec![local_ip()],
    );
    let other = endpoint(
        &fixture,
        "127.0.0.1:31002".parse().unwrap(),
        vec![local_ip()],
    );
    assert_ne!(policy.id(), fixture.policy.id());
    assert_ne!(policy.id(), other.id());
    assert_ne!(
        Witness::binding(&policy).id(),
        Witness::binding(&fixture.policy).id()
    );
    let expiry = super::super::super::now().unwrap() + 55;
    let fresh = tls_client(&fixture, policy.clone())
        .prepare(1, expiry, Request::Head)
        .unwrap();
    let old = fixture.client().prepare(1, expiry, Request::Head).unwrap();
    assert_ne!(fresh.operation_id(), old.operation_id());
    assert_ne!(
        policy.response_digest(b"receipt"),
        fixture.policy.response_digest(b"receipt")
    );
    let now = super::super::super::now().unwrap();
    assert!(policy.verify_request(old.wire(), now).is_err());
    assert!(fixture.policy.verify_request(fresh.wire(), now).is_err());
    // Replacing only framing magic cannot turn either signed context into the other.
    let mut relabeled = fresh.wire().to_vec();
    relabeled[..4].copy_from_slice(fixture.policy.request_magic());
    assert!(fixture.policy.verify_request(&relabeled, now).is_err());
    assert!(other.verify_request(fresh.wire(), now).is_err());
}

#[test]
fn endpoint_policy_rejects_malformed_recovery_and_address_pins() {
    for address in [
        "0.0.0.0:20",
        "127.0.0.1:0",
        "224.0.0.1:20",
        "255.255.255.255:20",
        "[::1]:20",
        "[::ffff:127.0.0.1]:20",
    ] {
        assert_eq!(
            PqTlsEndpointPins::new(address.parse().unwrap(), vec![local_ip()])
                .unwrap_err()
                .to_string(),
            "PQ_TLS_ENDPOINT_ADDRESS",
        );
    }
    let address = "127.0.0.1:31001".parse().unwrap();
    for ips in [
        vec![],
        vec![local_ip(), local_ip()],
        vec!["0.0.0.0".parse().unwrap()],
        vec!["::1".parse().unwrap()],
        vec![local_ip(); MAX_PEERS + 1],
    ] {
        assert_eq!(
            PqTlsEndpointPins::new(address, ips)
                .unwrap_err()
                .to_string(),
            "PQ_TLS_ENDPOINT_CLIENTS",
        );
    }
    let fixture = Fixture::new();
    let policy = endpoint(
        &fixture,
        address,
        vec!["127.0.0.2".parse().unwrap(), local_ip()],
    );
    assert_eq!(
        policy.tls_endpoint_pins().unwrap().allowed_client_ips()[0],
        local_ip()
    );
    assert!(peer_ids_from_policy_record(policy.canonical()).is_ok());
    let valid: serde_json::Value = serde_json::from_slice(policy.canonical()).unwrap();
    let mut invalid = Vec::new();
    let mut record = valid.clone();
    record["schema"] = TLS_PROFILE.into();
    invalid.push((record, "PQ_NETWORK_POLICY_RECORD"));
    let mut record = valid.clone();
    record["transport_confidentiality"] = TLS_TRANSPORT_MODE.into();
    invalid.push((record, "PQ_NETWORK_POLICY_RECORD"));
    let mut record = valid.clone();
    record.as_object_mut().unwrap().remove("endpoint");
    invalid.push((record, "PQ_NETWORK_POLICY_RECORD"));
    let mut record = valid.clone();
    record["endpoint"] = serde_json::Value::Null;
    invalid.push((record, "PQ_NETWORK_POLICY_RECORD"));
    let mut record = valid.clone();
    record.as_object_mut().unwrap().remove("tls");
    invalid.push((record, "PQ_NETWORK_POLICY_RECORD"));
    let mut record = valid.clone();
    record["endpoint"]["allowed_client_ips"] = serde_json::json!(["127.0.0.2", "127.0.0.1"]);
    invalid.push((record, "PQ_TLS_ENDPOINT_CLIENTS"));
    let mut record = valid.clone();
    record["endpoint"]["allowed_client_ips"] = serde_json::json!(["127.0.0.1", "127.0.0.1"]);
    invalid.push((record, "PQ_TLS_ENDPOINT_CLIENTS"));
    let mut record = valid;
    record["endpoint"]["server_address"] = "127.0.0.1:0".into();
    invalid.push((record, "PQ_TLS_ENDPOINT_ADDRESS"));
    for (record, expected_error) in invalid {
        // Preserve struct field order so each malformed schema/endpoint reaches
        // transport validation, rather than failing only JSON map ordering.
        let parsed: PolicyRecord = serde_json::from_value(record).unwrap();
        let canonical = serde_json::to_vec(&parsed).unwrap();
        let roundtrip: PolicyRecord = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(serde_json::to_vec(&roundtrip).unwrap(), canonical);
        assert_eq!(
            parsed.validate_transport().unwrap_err().to_string(),
            expected_error
        );
        assert_eq!(
            peer_ids_from_policy_record(&canonical)
                .unwrap_err()
                .to_string(),
            expected_error,
        );
    }
}

#[test]
fn endpoint_client_and_listener_refuse_mismatched_targets_before_io() {
    let fixture = Fixture::new();
    let correct = TcpListener::bind("127.0.0.1:0").unwrap();
    let incorrect = TcpListener::bind("127.0.0.1:0").unwrap();
    incorrect.set_nonblocking(true).unwrap();
    let policy = endpoint(&fixture, correct.local_addr().unwrap(), vec![local_ip()]);
    let client = tls_client(&fixture, policy.clone());
    let prepared = client
        .prepare(1, super::super::super::now().unwrap() + 55, Request::Head)
        .unwrap();
    let error = client
        .send(
            incorrect.local_addr().unwrap(),
            &prepared,
            Duration::from_secs(1),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "PQ_TLS_ENDPOINT_TARGET");
    assert_eq!(
        incorrect.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let path = tempfile::tempdir().unwrap();
    let node =
        Node::open_with_pq_network(path.path(), fixture.settings.clone(), 1, &fixture.policy)
            .unwrap();
    let before = node.pq_network_status(&fixture.policy).unwrap();
    let error = serve_pq_tls13(
        incorrect,
        node,
        Duration::from_secs(1),
        Arc::new(AtomicBool::new(false)),
        tls_server(&fixture, policy),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "PQ_TLS_ENDPOINT_TARGET");
    let reopened =
        Node::open_with_pq_network(path.path(), fixture.settings.clone(), 1, &fixture.policy)
            .unwrap();
    assert_eq!(reopened.pq_network_status(&fixture.policy).unwrap(), before);
}

#[test]
fn endpoint_profile_requires_witness_at_constructor_and_live_owner() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let policy = endpoint(&fixture, address, vec![local_ip()]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("absent-node");
    let error = Node::open_with_pq_network(&path, fixture.settings.clone(), 1, &policy)
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "PQ_TLS_ENDPOINT_WITNESS_REQUIRED");
    assert!(!path.exists());
    let node =
        Node::open_with_pq_network(&path, fixture.settings.clone(), 1, &fixture.policy).unwrap();
    let error = serve_pq_tls13(
        listener,
        node,
        Duration::from_secs(1),
        Arc::new(AtomicBool::new(false)),
        tls_server(&fixture, policy.clone()),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "PQ_TLS_ENDPOINT_WITNESS_REQUIRED");
    // Even a correctly pinned endpoint cannot route through the plaintext API.
    let client = PqClient::new(policy, fixture.peer.signer()).unwrap();
    let prepared = client
        .prepare(1, super::super::super::now().unwrap() + 55, Request::Head)
        .unwrap();
    assert_eq!(
        client
            .send(address, &prepared, Duration::from_secs(1))
            .unwrap_err()
            .to_string(),
        "PQ_TLS_REQUIRED"
    );
}

#[test]
fn endpoint_disallowed_source_spends_no_owner_budget_and_stops_at_accept_cap() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let policy = endpoint(&fixture, address, vec!["127.0.0.2".parse().unwrap()]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("node");
    let witness = Witness::new(&policy, directory.path());
    let node = Node::create_with_pq_witness(
        &path,
        fixture.settings.clone(),
        1,
        &policy,
        witness.client(&policy),
    )
    .unwrap();
    let before = node.pq_network_status(&policy).unwrap();
    let calls = witness.calls.load(Ordering::SeqCst);
    let (_, worker) = start(listener, node, tls_server(&fixture, policy.clone()));
    for _ in 0..TLS_ENDPOINT_ACCEPT_LIMIT {
        let mut tcp = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut byte = [0];
        match tcp.read(&mut byte) {
            Ok(0) => (),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => (),
            result => panic!("unrostered source must close before TLS: {result:?}"),
        }
    }
    let metrics = worker.join().unwrap();
    assert_eq!(metrics.accepted, 0);
    assert_eq!(metrics.refused, TLS_ENDPOINT_ACCEPT_LIMIT);
    assert_eq!(witness.calls.load(Ordering::SeqCst), calls);
    let reopened = Node::open_with_pq_witness(
        &path,
        fixture.settings.clone(),
        1,
        &policy,
        witness.client(&policy),
    )
    .unwrap();
    assert_eq!(reopened.pq_network_status(&policy).unwrap(), before);
}

#[test]
fn endpoint_tls_witness_dispatch_replay_reopen_and_legacy_alpn_refusal() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let retained_listener = listener.try_clone().unwrap();
    let policy = endpoint(&fixture, address, vec![local_ip()]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("node");
    let witness = Witness::new(&policy, directory.path());
    let node = Node::create_with_pq_witness(
        &path,
        fixture.settings.clone(),
        1,
        &policy,
        witness.client(&policy),
    )
    .unwrap();
    let (stop, worker) = start(listener, node, tls_server(&fixture, policy.clone()));
    let expiry = super::super::super::now().unwrap() + 55;
    let legacy = fixture.client();
    // Stop at the actual TLS handshake: no PNQ frame is sent, so an application
    // magic mismatch cannot falsely stand in for early ALPN refusal.
    assert!(io::Channel::connect(
        TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap(),
        Instant::now() + Duration::from_secs(5),
        &legacy.context,
    )
    .is_err());
    let client = tls_client(&fixture, policy.clone());
    let prepared = client.prepare(1, expiry, Request::Head).unwrap();
    let first = client
        .send(address, &prepared, Duration::from_secs(5))
        .unwrap();
    assert_eq!(first.value["height"], 0);
    assert_eq!(
        client
            .send(address, &prepared, Duration::from_secs(5))
            .unwrap(),
        first
    );
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    assert_eq!((metrics.accepted, metrics.refused), (2, 1));
    assert!(Node::open_with_pq_witness(
        &path,
        fixture.settings.clone(),
        1,
        &fixture.policy,
        witness.client(&fixture.policy)
    )
    .is_err());
    let reopened = Node::open_with_pq_witness(
        &path,
        fixture.settings.clone(),
        1,
        &policy,
        witness.client(&policy),
    )
    .unwrap();
    let status = reopened.pq_network_status(&policy).unwrap();
    assert_eq!(status["records"], 1);
    assert_eq!(status["tls_handshake_attempts"], 3);
    let (stop, worker) = start(retained_listener, reopened, tls_server(&fixture, policy));
    assert_eq!(
        client
            .send(address, &prepared, Duration::from_secs(5))
            .unwrap(),
        first
    );
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    assert_eq!((metrics.accepted, metrics.refused), (1, 0));

    // The inverse direction must also refuse during handshake with the same
    // valid CA/keys/certificates. Only the independently selected ALPN differs.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let old_path = directory.path().join("legacy-node");
    let old_node =
        Node::open_with_pq_network(&old_path, fixture.settings.clone(), 1, &fixture.policy)
            .unwrap();
    let new_client = tls_client(&fixture, endpoint(&fixture, address, vec![local_ip()]));
    let (stop, worker) = start(listener, old_node, fixture.server());
    assert!(io::Channel::connect(
        TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap(),
        Instant::now() + Duration::from_secs(5),
        &new_client.context,
    )
    .is_err());
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    assert_eq!((metrics.accepted, metrics.refused), (0, 1));
    let old_node =
        Node::open_with_pq_network(&old_path, fixture.settings.clone(), 1, &fixture.policy)
            .unwrap();
    let status = old_node.pq_network_status(&fixture.policy).unwrap();
    assert_eq!(status["records"], 0);
    assert_eq!(status["inbound_signature_attempts"], 0);
    assert_eq!(status["tls_handshake_attempts"], 1);
}
