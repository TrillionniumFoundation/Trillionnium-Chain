//! Real socket transport-admission checks. No public fairness or PoN-hardness claim.
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_pon_node::{
    development_public,
    ingress::{
        self, AdmissionChallenge, AdmissionPolicy, AdmissionSolution, AuthenticatedClient,
        AuthenticatedServer, DevelopmentIdentity, Request,
    },
    Node, Packet, Settings,
};
use trnm_protocol::pon_wire::hash;

fn send(stream: &mut TcpStream, bytes: &[u8]) {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
}
fn read(stream: &mut TcpStream) -> Vec<u8> {
    try_read(stream).unwrap()
}
fn try_read(stream: &mut TcpStream) -> std::result::Result<Vec<u8>, String> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).map_err(|e| e.to_string())?;
    let length = u32::from_be_bytes(prefix) as usize;
    assert!(length <= 2 * 1024 * 1024);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
fn connect(address: SocketAddr, request: &Request) -> (TcpStream, Vec<u8>, AdmissionChallenge) {
    try_connect(address, request).unwrap()
}
fn try_connect(
    address: SocketAddr,
    request: &Request,
) -> std::result::Result<(TcpStream, Vec<u8>, AdmissionChallenge), String> {
    let wire = serde_json::to_vec(request).unwrap();
    let mut stream = TcpStream::connect(address).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    ingress::write_protected_request(&mut stream, request, &wire).map_err(|e| e.to_string())?;
    let challenge = serde_json::from_slice(&try_read(&mut stream)?).map_err(|e| e.to_string())?;
    Ok((stream, wire, challenge))
}
fn request(packet: &Packet) -> Request {
    Request::Submit {
        packet: hex::encode(packet.encode().unwrap()),
    }
}
fn fixture() -> (tempfile::TempDir, Settings, Node, Packet) {
    fixture_at_age(100)
}
fn fixture_at_age(age_seconds: u64) -> (tempfile::TempDir, Settings, Node, Packet) {
    let directory = tempfile::tempdir().unwrap();
    let clock = ingress::now().unwrap();
    let settings = Settings::development(Some(clock - age_seconds)).unwrap();
    let node = Node::open(directory.path(), settings.clone(), 2).unwrap();
    let packet = node
        .make(
            settings.genesis(),
            vec![],
            development_public(0).unwrap(),
            clock - age_seconds + 10,
            4096,
        )
        .unwrap();
    (directory, settings, node, packet)
}
fn fake_trace(packet: &Packet) -> (Packet, u64) {
    let mut forged = packet.clone();
    for nonce in 0..4096_u64 {
        let fake = hash(b"protected-socket-fake-trace", &[&nonce.to_le_bytes()]);
        let start = forged.proof.len() - 32;
        if hash(b"ticket", &[&forged.header.challenge(), &fake]) <= forged.header.target
            && fake != forged.proof[start..]
        {
            forged.proof[start..].copy_from_slice(&fake);
            return (forged, nonce + 1);
        }
    }
    panic!("fixture forgery hash budget");
}

#[test]
fn socket_admission_binds_exact_challenge_and_keeps_fake_work_invalid() {
    let (directory, settings, node, packet) = fixture();
    let (forged, forgery_trials) = fake_trace(&packet);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || {
        ingress::serve_protected(
            listener,
            node,
            Duration::from_secs(15),
            server_stop,
            AdmissionPolicy::development(),
        )
        .unwrap()
    });

    let submitted = request(&forged);
    let (mut first, wire, challenge) = connect(address, &submitted);
    let started = Instant::now();
    let (solution, hash_trials) =
        ingress::solve_admission_challenge(&challenge, &wire, &settings).unwrap();
    let solve_ns = started.elapsed().as_nanos();
    let mut wrong = solution.clone();
    wrong.challenge_digest = hex::encode([0; 32]);
    send(&mut first, &serde_json::to_vec(&wrong).unwrap());
    let refusal: Value = serde_json::from_slice(&read(&mut first)).unwrap();
    assert_eq!(refusal["error"], "ADMISSION_REPLAY_OR_CONTEXT");

    let (mut second, _, fresh) = connect(address, &submitted);
    assert_ne!(fresh.nonce, challenge.nonce);
    send(&mut second, &serde_json::to_vec(&solution).unwrap());
    let refusal: Value = serde_json::from_slice(&read(&mut second)).unwrap();
    assert_eq!(refusal["error"], "ADMISSION_REPLAY_OR_CONTEXT");

    let (mut target_failure, wire, challenge) = connect(address, &submitted);
    let (mut wrong_target, _) =
        ingress::solve_admission_challenge(&challenge, &wire, &settings).unwrap();
    let statement = trnm_pon_node::digest(&wrong_target.challenge_digest).unwrap();
    wrong_target.nonce = (0..1024_u64)
        .find(|nonce| {
            let digest = hash(
                b"native-transport-admission-solution-v1",
                &[&statement, &nonce.to_le_bytes()],
            );
            u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]).leading_zeros()
                < u32::from(challenge.bits)
        })
        .unwrap();
    send(
        &mut target_failure,
        &serde_json::to_vec(&wrong_target).unwrap(),
    );
    let refusal: Value = serde_json::from_slice(&read(&mut target_failure)).unwrap();
    assert_eq!(refusal["error"], "ADMISSION_TARGET");

    let (mut third, wire, challenge) = connect(address, &submitted);
    let (solution, _) = ingress::solve_admission_challenge(&challenge, &wire, &settings).unwrap();
    send(&mut third, &serde_json::to_vec(&solution).unwrap());
    let refusal: Value = serde_json::from_slice(&read(&mut third)).unwrap();
    assert_eq!(refusal["error"], "WORK:Transcript");
    let accepted = ingress::call_protected(address, &request(&packet), &settings).unwrap();
    assert_eq!(accepted["block"], hex::encode(packet.id().unwrap()));
    stop.store(true, Ordering::Release);
    let metrics = server.join().unwrap();
    assert_eq!(metrics.admission_rejected_before_work, 3);
    assert_eq!(metrics.admission_accepted, 2);
    assert_eq!(metrics.work_verifications, 2);
    assert_eq!(
        Node::open(directory.path(), settings, 1)
            .unwrap()
            .stats()
            .unwrap()["height"],
        1
    );
    println!(
        "{}",
        json!({"schema":"transport-admission-socket-cost-v1","bits":16,"ttl_ms":2000,"forged_pon_ticket_hash_trials":forgery_trials,"admission_hash_trials":hash_trials,"client_solve_ns":solve_ns,"metrics":metrics,"scope":"controlled loopback, not public fairness or work hardness"})
    );
}

#[test]
fn socket_admission_absolute_expiry_and_client_caps_prevent_work() {
    let (_directory, settings, node, packet) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || {
        ingress::serve_protected(
            listener,
            node,
            Duration::from_secs(5),
            server_stop,
            AdmissionPolicy::new(8, Duration::from_millis(100)).unwrap(),
        )
        .unwrap()
    });
    let (mut stream, wire, challenge) = connect(address, &request(&packet));
    let mut altered = challenge.clone();
    altered.genesis = hex::encode([0; 32]);
    assert_eq!(
        ingress::solve_admission_challenge(&altered, &wire, &settings)
            .unwrap_err()
            .to_string(),
        "ADMISSION_CONTEXT"
    );
    altered = challenge.clone();
    altered.bits = 21;
    assert_eq!(
        ingress::solve_admission_challenge(&altered, &wire, &settings)
            .unwrap_err()
            .to_string(),
        "ADMISSION_POLICY"
    );
    assert_eq!(
        ingress::solve_admission_challenge(&challenge, b"other request", &settings)
            .unwrap_err()
            .to_string(),
        "ADMISSION_REQUEST"
    );
    thread::sleep(Duration::from_millis(150));
    let refusal: Value = serde_json::from_slice(&read(&mut stream)).unwrap();
    assert!(
        refusal["error"].as_str().unwrap().contains("deadline")
            || refusal["error"].as_str().unwrap().starts_with("IO:")
            || refusal["error"] == "ADMISSION_EXPIRED"
    );
    stop.store(true, Ordering::Release);
    let metrics = server.join().unwrap();
    assert_eq!(metrics.admission_rejected_before_work, 1);
    assert_eq!(metrics.work_verifications, 0);
}

#[test]
fn authenticated_protected_retry_preserves_durable_wire_and_verifies_server() {
    let (_directory, settings, node, packet) = fixture();
    let server_identity = DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap();
    let client_identity = DevelopmentIdentity::from_secret_hex(&hex::encode([72; 32])).unwrap();
    let authentication = AuthenticatedServer::new(
        server_identity.clone(),
        [client_identity.public_key().to_owned()],
        1,
    )
    .unwrap();
    let client =
        AuthenticatedClient::new(client_identity, server_identity.public_key().to_owned(), 1)
            .unwrap();
    let caller_directory = tempfile::tempdir().unwrap();
    let mut caller = Node::open(caller_directory.path(), settings.clone(), 1).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || {
        ingress::serve_authenticated_protected(
            listener,
            node,
            Duration::from_secs(10),
            server_stop,
            authentication,
            AdmissionPolicy::new(12, Duration::from_secs(2)).unwrap(),
        )
        .unwrap()
    });
    let submitted = request(&packet);
    let wire =
        ingress::authenticated_request_bytes(&settings, &client, 1, submitted.clone()).unwrap();
    let mut untrusted = TcpStream::connect(address).unwrap();
    untrusted
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    ingress::write_protected_request(&mut untrusted, &submitted, &wire).unwrap();
    let mut challenge: AdmissionChallenge = serde_json::from_slice(&read(&mut untrusted)).unwrap();
    assert_eq!(challenge.server, server_identity.public_key());
    challenge.signature = "00".repeat(64);
    assert!(
        ingress::solve_admission_challenge(&challenge, &wire, &settings)
            .unwrap_err()
            .to_string()
            .starts_with("ADMISSION_SIGNATURE:")
    );
    drop(untrusted);
    let accepted =
        ingress::call_authenticated_durable_protected(&mut caller, address, &submitted, &client)
            .unwrap();
    assert_eq!(accepted["block"], hex::encode(packet.id().unwrap()));
    assert_eq!(caller.stats().unwrap()["authenticated_outbox_pending"], 0);
    let mut nonce = 1;
    let replay =
        ingress::call_authenticated_protected(address, &submitted, &settings, &client, &mut nonce)
            .unwrap();
    assert_eq!(replay, accepted);
    assert_eq!(nonce, 2);
    stop.store(true, Ordering::Release);
    let metrics = server.join().unwrap();
    assert_eq!(metrics.admission_accepted, 2);
    assert_eq!(metrics.work_verifications, 1);
    assert_eq!(metrics.replayed_responses, 1);
}

#[test]
fn protected_mixed_socket_load_preserves_honest_ingress_and_measures_actual_rejections() {
    let (_directory, settings, node, first) = fixture();
    let (forged, _) = fake_trace(&first);
    let producer_directory = tempfile::tempdir().unwrap();
    let mut producer = Node::open(producer_directory.path(), settings.clone(), 1).unwrap();
    let clock = ingress::now().unwrap();
    let packets = (1..=8)
        .map(|height| {
            producer
                .mine(vec![], settings.genesis_time() + height * 10, clock)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || {
        ingress::serve_protected(
            listener,
            node,
            Duration::from_secs(20),
            server_stop,
            AdmissionPolicy::new(12, Duration::from_secs(2)).unwrap(),
        )
        .unwrap()
    });
    let attackers = (0..2)
        .map(|_| {
            let submitted = request(&forged);
            thread::spawn(move || {
                for _ in 0..32 {
                    let (mut stream, _, _) = connect(address, &submitted);
                    let wrong = AdmissionSolution {
                        schema: "trnm-pon-admission-solution-v1".into(),
                        challenge_digest: hex::encode([0; 32]),
                        nonce: 0,
                    };
                    send(&mut stream, &serde_json::to_vec(&wrong).unwrap());
                    let reply: Value = serde_json::from_slice(&read(&mut stream)).unwrap();
                    assert_eq!(reply["error"], "ADMISSION_REPLAY_OR_CONTEXT");
                }
            })
        })
        .collect::<Vec<_>>();
    let mut honest_ns = Vec::new();
    for packet in &packets {
        let started = Instant::now();
        let value = ingress::call_protected(address, &request(packet), &settings).unwrap();
        assert_eq!(value["block"], hex::encode(packet.id().unwrap()));
        assert_eq!(
            ingress::call(address, &Request::Head).unwrap()["height"],
            packet.header.height
        );
        honest_ns.push(started.elapsed().as_nanos());
    }
    for attacker in attackers {
        attacker.join().unwrap();
    }
    stop.store(true, Ordering::Release);
    let metrics = server.join().unwrap();
    assert_eq!(metrics.admission_rejected_before_work, 64);
    assert_eq!(metrics.admission_accepted, 8);
    assert_eq!(metrics.work_verifications, 8);
    println!(
        "{}",
        json!({"schema":"transport-admission-mixed-load-v1","bits":12,"ttl_ms":2000,"attack_connections":64,"honest_valid_blocks":8,"honest_request_ns":honest_ns,"metrics":metrics,"scope":"bounded two-client loopback attack, not sustained public Sybil fairness"})
    );
}

#[test]
fn strict_negotiation_refuses_legacy_before_mutation_and_blocks_unnegotiated_submit() {
    let (directory, settings, node, packet) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || {
        ingress::serve(listener, node, Duration::from_secs(5), server_stop).unwrap()
    });
    assert_eq!(
        ingress::call_protected(address, &request(&packet), &settings)
            .unwrap_err()
            .to_string(),
        "ADMISSION_REQUIRED"
    );
    assert_eq!(ingress::call(address, &Request::Head).unwrap()["height"], 0);
    stop.store(true, Ordering::Release);
    assert_eq!(server.join().unwrap().work_verifications, 0);

    let node = Node::open(directory.path(), settings, 1).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || {
        ingress::serve_protected(
            listener,
            node,
            Duration::from_secs(5),
            server_stop,
            AdmissionPolicy::development(),
        )
        .unwrap()
    });
    assert!(ingress::call(address, &request(&packet))
        .unwrap_err()
        .to_string()
        .contains("ADMISSION_REQUIRED"));
    assert_eq!(ingress::call(address, &Request::Head).unwrap()["height"], 0);
    stop.store(true, Ordering::Release);
    let metrics = server.join().unwrap();
    assert_eq!(metrics.admission_unnegotiated_requests, 1);
    assert_eq!(metrics.work_verifications, 0);
}

#[test]
fn client_binds_ready_profile_before_searching_challenge() {
    let (_directory, settings, _node, packet) = fixture();
    let expected_wire = serde_json::to_vec(&request(&packet)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server_settings = settings.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let hello: Value = serde_json::from_slice(&read(&mut stream)).unwrap();
        let ready = json!({
            "schema":"trnm-pon-admission-ready-v1", "profile":hex::encode([0;32]),
            "request_digest":hello["request_digest"],
        });
        // Struct serialization order is part of this transport's closed wire.
        let ready_wire = format!(
            "{{\"schema\":\"trnm-pon-admission-ready-v1\",\"profile\":\"{}\",\"request_digest\":\"{}\"}}",
            ready["profile"].as_str().unwrap(),
            ready["request_digest"].as_str().unwrap(),
        );
        send(&mut stream, ready_wire.as_bytes());
        let wire = read(&mut stream);
        assert_eq!(wire, expected_wire);
        let challenge = AdmissionChallenge {
            schema: "trnm-pon-admission-challenge-v1".into(),
            profile: hex::encode([1; 32]),
            network: hex::encode(server_settings.network()),
            parameters: hex::encode(server_settings.parameters()),
            genesis: hex::encode(server_settings.genesis()),
            nonce: hex::encode([2; 32]),
            request_digest: hello["request_digest"].as_str().unwrap().into(),
            bits: 16,
            lifetime_ms: 2000,
            expires_unix_ms: (ingress::now().unwrap() + 2) * 1000,
            server: String::new(),
            signature: String::new(),
        };
        send(&mut stream, &serde_json::to_vec(&challenge).unwrap());
        let mut byte = [0u8];
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
    });
    assert_eq!(
        ingress::call_protected(address, &request(&packet), &settings)
            .unwrap_err()
            .to_string(),
        "ADMISSION_NEGOTIATION_CONTEXT"
    );
    server.join().unwrap();
}

#[test]
fn slow_hello_bodies_cannot_take_the_reserved_read_only_worker() {
    let (_directory, _settings, node, packet) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || {
        ingress::serve_protected(
            listener,
            node,
            Duration::from_secs(5),
            server_stop,
            AdmissionPolicy::development(),
        )
        .unwrap()
    });
    let wire = serde_json::to_vec(&request(&packet)).unwrap();
    let hello = format!(
        "{{\"schema\":\"trnm-pon-admission-hello-v1\",\"request_digest\":\"{}\"}}",
        hex::encode(hash(b"native-transport-admission-wire-v1", &[&wire])),
    );
    let mut held = Vec::new();
    while held.len() < 2 {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(75)))
            .unwrap();
        send(&mut stream, hello.as_bytes());
        let reply: Value = serde_json::from_slice(&read(&mut stream)).unwrap();
        if reply["schema"] == "trnm-pon-admission-ready-v1" {
            held.push(stream);
        } else {
            assert_eq!(reply["error"], "ADMISSION_BUSY_READ_ONLY_RESERVED");
        }
    }
    // Both proof workers are waiting for request bodies. Head must finish before
    // the original 100 ms preface deadline releases either of them.
    let mut head = TcpStream::connect(address).unwrap();
    head.set_nodelay(true).unwrap();
    head.set_read_timeout(Some(Duration::from_millis(75)))
        .unwrap();
    send(&mut head, &serde_json::to_vec(&Request::Head).unwrap());
    let reply: Value = serde_json::from_slice(&read(&mut head)).unwrap();
    assert_eq!(reply["height"], 0);
    drop(held);
    stop.store(true, Ordering::Release);
    let metrics = server.join().unwrap();
    assert_eq!(metrics.work_verifications, 0);
    assert_eq!(metrics.completed_requests, 1);
    assert_eq!(metrics.protected_preface_refusals, 2);
}

#[test]
fn protected_untrusted_large_errors_have_bounded_real_socket_responses() {
    for authenticated in [false, true] {
        let (_directory, settings, node, _packet) = fixture();
        let server_identity = DevelopmentIdentity::from_secret_hex(&hex::encode([81; 32])).unwrap();
        let client_identity = DevelopmentIdentity::from_secret_hex(&hex::encode([82; 32])).unwrap();
        let client = AuthenticatedClient::new(
            client_identity.clone(),
            server_identity.public_key().to_owned(),
            1,
        )
        .unwrap();
        let authentication = AuthenticatedServer::new(
            server_identity,
            [client_identity.public_key().to_owned()],
            1,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let server = thread::spawn(move || {
            if authenticated {
                ingress::serve_authenticated_protected(
                    listener,
                    node,
                    Duration::from_secs(5),
                    server_stop,
                    authentication,
                    AdmissionPolicy::development(),
                )
                .unwrap()
            } else {
                ingress::serve_protected(
                    listener,
                    node,
                    Duration::from_secs(5),
                    server_stop,
                    AdmissionPolicy::development(),
                )
                .unwrap()
            }
        });
        let hostile_op = "x".repeat(65_536);
        let hostile = if authenticated {
            let mut envelope: Value = serde_json::from_slice(
                &ingress::authenticated_request_bytes(&settings, &client, 1, Request::Head)
                    .unwrap(),
            )
            .unwrap();
            envelope["request"]["op"] = hostile_op.into();
            envelope
        } else {
            json!({"op":hostile_op})
        };
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        send(&mut stream, &serde_json::to_vec(&hostile).unwrap());
        let wire = read(&mut stream);
        assert!(wire.len() <= 1024);
        let refusal: Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(refusal["error"].as_str().unwrap().chars().count(), 128);
        if authenticated {
            let mut nonce = 1;
            assert_eq!(
                ingress::call_authenticated_protected(
                    address,
                    &Request::Head,
                    &settings,
                    &client,
                    &mut nonce,
                )
                .unwrap()["height"],
                0
            );
        } else {
            assert_eq!(ingress::call(address, &Request::Head).unwrap()["height"], 0);
        }
        stop.store(true, Ordering::Release);
        let metrics = server.join().unwrap();
        assert_eq!(metrics.malformed_requests, 1);
        assert_eq!(metrics.work_verifications, 0);
        assert_eq!(metrics.completed_requests, 1);
    }
}

#[derive(Default)]
struct AttackObservations {
    connections: u64,
    forgery_hash_trials: u64,
    admission_hash_trials: u64,
    admission_solve_ns: u128,
    full_work_rejections: u64,
    cheap_rejections: u64,
    busy_rejections: u64,
    slow_connections: u64,
    slow_partial_hello_connections: u64,
    slow_body_hello_connections: u64,
    transport_errors: Vec<String>,
    elapsed_ns: u128,
}

/// Explicit release measurement, separate from fast deterministic contract tests.
/// Two sequential attacker streams do not establish fairness under identity rotation.
#[test]
#[ignore = "release-only sustained socket cost measurement; run explicitly with --ignored"]
fn sustained_protected_socket_cost_campaign() {
    for phase in [
        "baseline",
        "unpaid_false_transcript",
        "paid_false_transcript",
        "slow_hello_occupancy",
    ] {
        let (_directory, settings, node, first) = fixture_at_age(2000);
        let producer_directory = tempfile::tempdir().unwrap();
        let mut producer = Node::open(producer_directory.path(), settings.clone(), 1).unwrap();
        let clock = ingress::now().unwrap();
        let packets = (1..=128)
            .map(|height| {
                producer
                    .mine(vec![], settings.genesis_time() + height * 10, clock)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let server = thread::spawn(move || {
            ingress::serve_protected(
                listener,
                node,
                Duration::from_secs(25),
                server_stop,
                AdmissionPolicy::development(),
            )
            .unwrap()
        });
        let started = Instant::now();
        let end = started + Duration::from_secs(10);
        let attacker_streams = match phase {
            "baseline" => 0,
            "slow_hello_occupancy" => 3,
            _ => 2,
        };
        let attackers = (0..attacker_streams)
            .map(|attacker| {
                let template = first.clone();
                let settings = settings.clone();
                thread::spawn(move || {
                    let attacker_start = Instant::now();
                    let mut observations = AttackObservations::default();
                    while Instant::now() < end {
                        if phase == "slow_hello_occupancy" {
                            let wire = serde_json::to_vec(&request(&template)).unwrap();
                            let mut stream = TcpStream::connect(address).unwrap();
                            stream.set_nodelay(true).unwrap();
                            let hello = format!(
                                "{{\"schema\":\"trnm-pon-admission-hello-v1\",\"request_digest\":\"{}\"}}",
                                hex::encode(hash(b"native-transport-admission-wire-v1", &[&wire])),
                            );
                            if observations.connections.is_multiple_of(2) {
                                stream.write_all(&(hello.len() as u32).to_be_bytes()).unwrap();
                                stream.write_all(&hello.as_bytes()[..hello.len() / 2]).unwrap();
                                observations.slow_partial_hello_connections += 1;
                            } else {
                                send(&mut stream, hello.as_bytes());
                                observations.slow_body_hello_connections += 1;
                            }
                            // Partial initial hellos can occupy all three workers.
                            // Complete hellos with withheld bodies test the proof lane.
                            thread::sleep(Duration::from_millis(150));
                            drop(stream);
                            observations.connections += 1;
                            observations.slow_connections += 1;
                            continue;
                        }
                        // A fresh false digest avoids deduplication presenting a lower
                        // verifier cost than the actual stale, easy-parent attack.
                        let mut forged = template.clone();
                        for nonce in 0..4096_u64 {
                            observations.forgery_hash_trials += 1;
                            let false_trace = hash(
                                b"transport-duration-false-trace-v1",
                                &[
                                    &u64::try_from(attacker).unwrap().to_le_bytes(),
                                    &observations.connections.to_le_bytes(),
                                    &nonce.to_le_bytes(),
                                ],
                            );
                            if hash(b"ticket", &[&forged.header.challenge(), &false_trace])
                                <= forged.header.target
                            {
                                let start = forged.proof.len() - 32;
                                forged.proof[start..].copy_from_slice(&false_trace);
                                break;
                            }
                        }
                        let (mut stream, wire, challenge) =
                            match try_connect(address, &request(&forged)) {
                                Ok(connected) => connected,
                                Err(error) => {
                                    observations.connections += 1;
                                    observations.transport_errors.push(error);
                                    continue;
                                }
                            };
                        let solution = if phase == "paid_false_transcript" {
                            let solve_started = Instant::now();
                            let (solution, trials) =
                                ingress::solve_admission_challenge(&challenge, &wire, &settings)
                                    .unwrap();
                            observations.admission_hash_trials += trials;
                            observations.admission_solve_ns += solve_started.elapsed().as_nanos();
                            solution
                        } else {
                            AdmissionSolution {
                                schema: "trnm-pon-admission-solution-v1".into(),
                                challenge_digest: hex::encode([0; 32]),
                                nonce: 0,
                            }
                        };
                        send(&mut stream, &serde_json::to_vec(&solution).unwrap());
                        let reply: Value = serde_json::from_slice(&read(&mut stream)).unwrap();
                        match reply["error"].as_str().unwrap() {
                            "WORK:Transcript" => observations.full_work_rejections += 1,
                            "ADMISSION_REPLAY_OR_CONTEXT" => observations.cheap_rejections += 1,
                            error if error.starts_with("BUSY:") => {
                                observations.busy_rejections += 1
                            }
                            error => panic!("unexpected campaign refusal: {error}"),
                        }
                        observations.connections += 1;
                    }
                    observations.elapsed_ns = attacker_start.elapsed().as_nanos();
                    observations
                })
            })
            .collect::<Vec<_>>();
        let mut honest_ns = Vec::new();
        let mut head_ns = Vec::new();
        let mut honest_attempts = 0_u64;
        let mut honest_errors = Vec::new();
        let mut head_attempts = 0_u64;
        let mut head_errors = Vec::new();
        let mut packet_index = 0;
        while Instant::now() < end && packet_index < packets.len() {
            let packet = &packets[packet_index];
            honest_attempts += 1;
            let request_started = Instant::now();
            match ingress::call_protected(address, &request(packet), &settings) {
                Ok(accepted) => {
                    assert_eq!(accepted["block"], hex::encode(packet.id().unwrap()));
                    honest_ns.push(request_started.elapsed().as_nanos());
                    packet_index += 1;
                }
                Err(error) => honest_errors.push(json!({
                    "elapsed_ns":request_started.elapsed().as_nanos(),
                    "error":error.to_string(), "block_height":packet.header.height,
                })),
            }
            head_attempts += 1;
            let head_started = Instant::now();
            match ingress::call(address, &Request::Head) {
                Ok(head) => {
                    assert_eq!(head["height"], packet_index);
                    head_ns.push(head_started.elapsed().as_nanos());
                }
                Err(error) => head_errors.push(json!({
                    "elapsed_ns":head_started.elapsed().as_nanos(), "error":error.to_string(),
                })),
            }
            thread::sleep(Duration::from_millis(80));
        }
        let observations = attackers
            .into_iter()
            .map(|attacker| attacker.join().unwrap())
            .collect::<Vec<_>>();
        let wall_ns = started.elapsed().as_nanos();
        stop.store(true, Ordering::Release);
        let metrics = server.join().unwrap();
        let connections: u64 = observations.iter().map(|o| o.connections).sum();
        let paid: u64 = observations.iter().map(|o| o.full_work_rejections).sum();
        let cheap: u64 = observations.iter().map(|o| o.cheap_rejections).sum();
        let busy: u64 = observations.iter().map(|o| o.busy_rejections).sum();
        let slow: u64 = observations.iter().map(|o| o.slow_connections).sum();
        let transport_errors = observations
            .iter()
            .flat_map(|o| o.transport_errors.iter())
            .collect::<Vec<_>>();
        assert!(honest_attempts > 0);
        assert!(metrics.work_verifications >= paid + honest_ns.len() as u64);
        assert!(metrics.work_verifications <= paid + honest_attempts);
        assert_eq!(metrics.admission_rejected_before_work, cheap);
        assert!(metrics.admission_accepted >= paid + busy + honest_ns.len() as u64);
        if phase == "unpaid_false_transcript" {
            assert!(connections > 0);
            assert_eq!(paid, 0);
        } else if phase == "paid_false_transcript" {
            assert!(paid > 0);
        } else if phase == "slow_hello_occupancy" {
            assert!(slow > 0);
            assert!(metrics.protected_preface_refusals > 0);
        }
        println!(
            "{}",
            json!({
                "schema":"transport-admission-sustained-cost-v1", "phase":phase,
                "bits":16, "ttl_ms":2000, "requested_attack_duration_ns":10_000_000_000_u64,
                "observed_wall_ns":wall_ns, "attacker_streams":observations.len(),
                "attacker_observed_ns":observations.iter().map(|o| o.elapsed_ns).collect::<Vec<_>>(),
                "attack_connections":connections, "paid_full_work_rejections":paid,
                "cheap_rejections":cheap, "busy_rejections":busy,
                "slow_preface_connections":slow,
                "slow_partial_hello_connections":observations.iter().map(|o| o.slow_partial_hello_connections).sum::<u64>(),
                "slow_body_hello_connections":observations.iter().map(|o| o.slow_body_hello_connections).sum::<u64>(),
                "submitted_wire_bytes":serde_json::to_vec(&request(&first)).unwrap().len(),
                "attack_transport_error_count":transport_errors.len(),
                "attack_transport_errors":transport_errors,
                "forged_ticket_hash_trials":observations.iter().map(|o| o.forgery_hash_trials).sum::<u64>(),
                "admission_hash_trials":observations.iter().map(|o| o.admission_hash_trials).sum::<u64>(),
                "attacker_admission_solve_ns":observations.iter().map(|o| o.admission_solve_ns).sum::<u128>(),
                "honest_submit_attempts":honest_attempts, "honest_valid_blocks":honest_ns.len(),
                "honest_submit_ns":honest_ns, "honest_submit_errors":honest_errors,
                "honest_head_attempts":head_attempts, "honest_head_ns":head_ns,
                "honest_head_errors":head_errors, "metrics":metrics,
                "scope":"release controlled loopback, two false-transcript streams or three rotating slow-Hello streams, stale easy genesis parent, elapsed scheduling-inclusive costs; no global identity-rotation fairness, hardware-hardness, or public deployment claim"
            })
        );
    }
}
