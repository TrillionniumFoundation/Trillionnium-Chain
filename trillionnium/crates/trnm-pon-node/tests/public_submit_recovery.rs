//! Ordinary local Native packets and authenticated loopback responses. No remote load.
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::{
    development_public, ingress,
    ingress::public_v3::{self, PublicMetrics, PublicPolicy, PublicServer, Request},
    public_submit::{submit_with_verified_parent_recovery, PinnedPublicClient, SubmitRecoveryPlan},
    Node, Packet, PoolLimits, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope};

fn identity(byte: u8) -> ingress::DevelopmentIdentity {
    ingress::DevelopmentIdentity::from_secret_hex(&hex::encode([byte; 32])).unwrap()
}
fn policy() -> PublicPolicy {
    PublicPolicy::new(8, Duration::from_secs(2)).unwrap()
}
fn transfer(settings: &Settings, account_sequence: u64) -> Vec<u8> {
    let mut payload = development_public(4).unwrap().to_vec();
    payload.extend(1u64.to_le_bytes());
    let mut envelope = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: account_sequence,
        expiry: 1000,
        fee_limit: 1000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    envelope.encode().unwrap()
}
fn producer(path: &Path, count: usize) -> (Node, Vec<Packet>, Settings) {
    let settings = Settings::development(Some(ingress::now().unwrap() - 200)).unwrap();
    let mut node = Node::open(path, settings.clone(), 1).unwrap();
    let mut packets = Vec::new();
    for height in 1..=count {
        let packet = node
            .mine(
                vec![transfer(&settings, height as u64)],
                settings.genesis_time() + height as u64 + 1,
                ingress::now().unwrap(),
            )
            .unwrap();
        packets.push(packet);
    }
    (node, packets, settings)
}
struct Server {
    address: SocketAddr,
    node: Arc<Mutex<Node>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<trnm_pon_node::Result<PublicMetrics>>>,
    public: String,
}
impl Server {
    fn start(path: &Path, settings: &Settings) -> Self {
        let mut node = Node::open(path, settings.clone(), 1).unwrap();
        node.enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 32,
            preview_miner: development_public(0).unwrap(),
        })
        .unwrap();
        let node = Arc::new(Mutex::new(node));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let public = identity(101).public_key().to_owned();
        let service_node = node.clone();
        let service_stop = stop.clone();
        let join = thread::spawn(move || {
            public_v3::serve_public_protected_v3(
                listener,
                service_node,
                Duration::from_secs(30),
                service_stop,
                PublicServer::new(identity(101), policy()).unwrap(),
            )
        });
        Self {
            address,
            node,
            stop,
            join: Some(join),
            public,
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            join.join().unwrap().unwrap();
        }
    }
}

fn client<'a>(
    address: SocketAddr,
    server: &'a Server,
    guest: &'a ingress::DevelopmentIdentity,
) -> PinnedPublicClient<'a> {
    PinnedPublicClient {
        address,
        server_public: &server.public,
        identity: guest,
        policy: policy(),
    }
}
fn plan() -> SubmitRecoveryPlan {
    SubmitRecoveryPlan::new(Duration::from_secs(10)).unwrap()
}

fn frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let length = u32::from_be_bytes(prefix) as usize;
    assert!((1..=2_100_000).contains(&length));
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).unwrap();
    let mut full = prefix.to_vec();
    full.extend(bytes);
    full
}
enum Interruption {
    BeforeHelloAdmission,
    BeforeEverySubmit,
    AfterNativeAck,
    HoldNativeAckUntilDeadline,
    AfterNativeAckFork(Vec<Packet>, Arc<Mutex<Node>>),
}
struct Proxy {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}
impl Proxy {
    fn start(upstream: SocketAddr, interruption: Interruption) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let service_stop = stop.clone();
        let join = thread::spawn(move || {
            let mut intervention = Some(interruption);
            while !service_stop.load(Ordering::Acquire) {
                let (mut caller, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("loopback proxy: {error}"),
                };
                caller
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                caller
                    .set_write_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                let mut hello = [0; 108];
                caller.read_exact(&mut hello).unwrap();
                if matches!(intervention, Some(Interruption::BeforeHelloAdmission)) {
                    intervention.take();
                    continue;
                }
                if matches!(intervention, Some(Interruption::BeforeEverySubmit)) && hello[4] == 1 {
                    continue;
                }
                let mut server = TcpStream::connect(upstream).unwrap();
                server
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                server
                    .set_write_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                server.write_all(&hello).unwrap();
                let cookie = frame(&mut server);
                let parsed: Value = serde_json::from_slice(&cookie[4..]).unwrap();
                caller.write_all(&cookie).unwrap();
                let mut solution = [0; 108];
                caller.read_exact(&mut solution).unwrap();
                server.write_all(&solution).unwrap();
                caller.write_all(&frame(&mut server)).unwrap();
                let mut body = vec![0; parsed["body_len"].as_u64().unwrap() as usize];
                caller.read_exact(&mut body).unwrap();
                server.write_all(&body).unwrap();
                let reply = frame(&mut server);
                let parsed_reply: Value = serde_json::from_slice(&reply[4..]).unwrap();
                if parsed["op"] == 1 && parsed_reply["ok"] == true {
                    match intervention.take() {
                        Some(Interruption::AfterNativeAck) => continue,
                        Some(Interruption::HoldNativeAckUntilDeadline) => {
                            // A real Native ACK has already been generated by
                            // the receiver. This exceeds only this control's
                            // shorter absolute client epoch, not server caps.
                            thread::sleep(Duration::from_millis(500));
                            continue;
                        }
                        Some(Interruption::AfterNativeAckFork(packets, owner)) => {
                            let mut node = owner.lock().unwrap();
                            for packet in packets {
                                let id = node.admit(&packet, ingress::now().unwrap()).unwrap();
                                node.activate_observed(id, ingress::now().unwrap()).unwrap();
                            }
                        }
                        Some(Interruption::BeforeHelloAdmission) => unreachable!(),
                        Some(Interruption::BeforeEverySubmit) => unreachable!(),
                        None => {}
                    }
                }
                caller.write_all(&reply).unwrap();
            }
        });
        Self {
            address,
            stop,
            join: Some(join),
        }
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.join.take().unwrap().join().unwrap();
    }
}

#[test]
fn actual_missing_parent_is_restored_before_child_and_reopens_byte_exact() {
    let dir = tempfile::tempdir().unwrap();
    let (node, packets, settings) = producer(&dir.path().join("producer"), 2);
    let receiver = dir.path().join("receiver");
    let server = Server::start(&receiver, &settings);
    let guest = identity(102);
    let outcome = submit_with_verified_parent_recovery(
        &node,
        client(server.address, &server, &guest),
        &packets[1],
        plan(),
    );
    assert!(outcome.ok, "{outcome:?}");
    assert_eq!(
        outcome.restored_parent_memberships,
        vec![hex::encode(packets[0].id().unwrap())]
    );
    assert_eq!(
        outcome
            .attempts
            .iter()
            .filter(|r| r.operation == "submit")
            .count(),
        3
    );
    assert_eq!(
        outcome.attempts[0].authenticated_reply.as_ref().unwrap()["value"]["error"],
        "UNKNOWN_PARENT"
    );
    assert!(outcome.membership_observed && outcome.may_advance_dependency);
    assert_eq!(outcome.formal_confirmation_observed, None);
    assert!(!outcome.remote_persistence_proved && !outcome.resource_fairness_qualified);
    drop(server);
    let reopened = Node::open(&receiver, settings, 1).unwrap();
    assert_eq!(
        reopened.read_active().unwrap().2,
        node.read_active().unwrap().2
    );
    for packet in packets {
        assert_eq!(
            reopened
                .packet(packet.id().unwrap())
                .unwrap()
                .encode()
                .unwrap(),
            packet.encode().unwrap()
        );
    }
}

#[test]
fn actual_eof_before_admission_keeps_same_packet_and_all_failed_attempts() {
    let dir = tempfile::tempdir().unwrap();
    let (node, packets, settings) = producer(&dir.path().join("producer"), 1);
    let server = Server::start(&dir.path().join("receiver"), &settings);
    let proxy = Proxy::start(server.address, Interruption::BeforeHelloAdmission);
    let guest = identity(103);
    let outcome = submit_with_verified_parent_recovery(
        &node,
        client(proxy.address, &server, &guest),
        &packets[0],
        plan(),
    );
    assert!(outcome.ok, "{outcome:?}");
    let submits: Vec<_> = outcome
        .attempts
        .iter()
        .filter(|r| r.operation == "submit")
        .collect();
    assert_eq!(submits.len(), 2);
    assert_eq!(submits[0].client_error.as_deref(), Some("FRAME_EOF"));
    assert_eq!(submits[0].metrics.failed_stage, Some("challenge"));
    assert_eq!(
        submits[0].request_body_digest,
        submits[1].request_body_digest
    );
    assert!(outcome.submission_outcome_uncertain);
    assert_eq!(
        server.node.lock().unwrap().active().unwrap().0,
        packets[0].id().unwrap()
    );
}

#[test]
fn actual_repeated_exact_eof_stops_after_three_identical_submits() {
    let dir = tempfile::tempdir().unwrap();
    let (node, packets, settings) = producer(&dir.path().join("producer"), 1);
    let server = Server::start(&dir.path().join("receiver"), &settings);
    let proxy = Proxy::start(server.address, Interruption::BeforeEverySubmit);
    let guest = identity(112);
    let outcome = submit_with_verified_parent_recovery(
        &node,
        client(proxy.address, &server, &guest),
        &packets[0],
        plan(),
    );
    assert_eq!(
        outcome.failure.as_deref(),
        Some("SUBMIT_RECOVERY_ATTEMPT_LIMIT")
    );
    let submits: Vec<_> = outcome
        .attempts
        .iter()
        .filter(|r| r.operation == "submit")
        .collect();
    assert_eq!(submits.len(), 3);
    assert!(submits
        .iter()
        .all(|r| r.client_error.as_deref() == Some("FRAME_EOF")
            && r.metrics.failed_stage == Some("challenge")
            && r.request_body_digest == submits[0].request_body_digest));
    assert_eq!(outcome.attempts.len(), 6);
    assert!(outcome.submission_outcome_uncertain && !outcome.may_advance_dependency);
    assert_eq!(
        server.node.lock().unwrap().active().unwrap().0,
        settings.genesis()
    );
}

#[test]
fn actual_lost_native_ack_is_resolved_by_full_membership_without_fabricated_ack() {
    let dir = tempfile::tempdir().unwrap();
    let (node, packets, settings) = producer(&dir.path().join("producer"), 1);
    let server = Server::start(&dir.path().join("receiver"), &settings);
    let proxy = Proxy::start(server.address, Interruption::AfterNativeAck);
    let guest = identity(104);
    let outcome = submit_with_verified_parent_recovery(
        &node,
        client(proxy.address, &server, &guest),
        &packets[0],
        plan(),
    );
    assert!(outcome.ok, "{outcome:?}");
    assert!(outcome.acknowledged_packets.is_empty());
    assert!(outcome.submission_outcome_uncertain);
    assert_eq!(
        outcome.attempts[0].client_error.as_deref(),
        Some("FRAME_EOF")
    );
    assert_eq!(
        outcome.attempts[0].metrics.failed_stage,
        Some("solution-body-response")
    );
    assert_eq!(
        outcome
            .attempts
            .iter()
            .filter(|r| r.operation == "submit")
            .count(),
        1
    );
    assert_eq!(
        server.node.lock().unwrap().read_active().unwrap().2,
        node.read_active().unwrap().2
    );
}

#[test]
fn actual_native_admission_without_response_at_deadline_is_uncertain_and_not_retried() {
    let dir = tempfile::tempdir().unwrap();
    let (node, packets, settings) = producer(&dir.path().join("producer"), 1);
    let receiver = dir.path().join("receiver");
    let server = Server::start(&receiver, &settings);
    let proxy = Proxy::start(server.address, Interruption::HoldNativeAckUntilDeadline);
    let guest = identity(113);
    let budget = Duration::from_millis(250);
    let outcome = submit_with_verified_parent_recovery(
        &node,
        client(proxy.address, &server, &guest),
        &packets[0],
        SubmitRecoveryPlan::new(budget).unwrap(),
    );
    assert!(
        !outcome.ok && !outcome.may_advance_dependency,
        "{outcome:?}"
    );
    assert_eq!(outcome.failure.as_deref(), Some("SUBMIT_RECOVERY_DEADLINE"));
    assert!(outcome.submission_outcome_uncertain);
    assert!(outcome.acknowledged_packets.is_empty());
    assert!(!outcome.membership_observed);
    assert_eq!(outcome.attempts.len(), 1);
    let attempt = &outcome.attempts[0];
    assert_eq!(attempt.operation, "submit");
    assert_eq!(attempt.metrics.failed_stage, Some("solution-body-response"));
    assert!(attempt.client_error.is_some());
    assert!(!attempt.retryable_transport_eof);
    assert!(attempt.authenticated_reply.is_none());
    assert!(outcome.total_elapsed_ns >= budget.as_nanos() as u64);
    assert_eq!(
        server.node.lock().unwrap().active().unwrap().0,
        packets[0].id().unwrap()
    );
    drop(proxy);
    drop(server);
    let reopened = Node::open(&receiver, settings, 1).unwrap();
    assert_eq!(
        reopened.read_active().unwrap().2,
        node.read_active().unwrap().2
    );
    assert_eq!(
        reopened
            .packet(packets[0].id().unwrap())
            .unwrap()
            .encode()
            .unwrap(),
        packets[0].encode().unwrap()
    );
}

#[test]
fn actual_equal_work_duplicate_ack_and_heavier_fork_do_not_advance_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, packets, settings) = producer(&dir.path().join("producer"), 1);
    let first = node
        .make(
            settings.genesis(),
            vec![],
            development_public(1).unwrap(),
            settings.genesis_time() + 11,
            4096,
        )
        .unwrap();
    let id = node.admit(&first, ingress::now().unwrap()).unwrap();
    node.activate_observed(id, ingress::now().unwrap()).unwrap();
    assert_eq!(node.active().unwrap().0, packets[0].id().unwrap());
    let second = node
        .make(
            id,
            vec![],
            development_public(1).unwrap(),
            settings.genesis_time() + 12,
            4096,
        )
        .unwrap();
    let second_id = node.admit(&second, ingress::now().unwrap()).unwrap();
    node.activate_observed(second_id, ingress::now().unwrap())
        .unwrap();
    let server = Server::start(&dir.path().join("receiver"), &settings);
    {
        let mut owner = server.node.lock().unwrap();
        let old_id = owner.admit(&packets[0], ingress::now().unwrap()).unwrap();
        owner
            .activate_observed(old_id, ingress::now().unwrap())
            .unwrap();
    }
    let guest = identity(105);
    let equal = submit_with_verified_parent_recovery(
        &node,
        client(server.address, &server, &guest),
        &first,
        plan(),
    );
    assert!(!equal.ok && !equal.may_advance_dependency, "{equal:?}");
    assert_eq!(
        equal.failure.as_deref(),
        Some("SUBMIT_RECOVERY_STALE_BRANCH")
    );
    assert_eq!(equal.acknowledged_packets, vec![hex::encode(id)]);
    let proxy = Proxy::start(
        server.address,
        Interruption::AfterNativeAckFork(vec![first, second], server.node.clone()),
    );
    let switched = submit_with_verified_parent_recovery(
        &node,
        client(proxy.address, &server, &guest),
        &packets[0],
        plan(),
    );
    assert!(
        !switched.ok && !switched.may_advance_dependency,
        "{switched:?}"
    );
    assert_eq!(
        switched.failure.as_deref(),
        Some("SUBMIT_RECOVERY_STALE_BRANCH")
    );
    assert_eq!(
        switched.acknowledged_packets,
        vec![hex::encode(packets[0].id().unwrap())]
    );
    assert_eq!(server.node.lock().unwrap().active().unwrap().0, second_id);
}

#[test]
fn actual_caps_context_and_mutated_same_id_refuse_without_relabeling_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let (node, packets, settings) = producer(&dir.path().join("producer"), 2);
    let server = Server::start(&dir.path().join("receiver"), &settings);
    let guest = identity(106);
    let mut limits = plan();
    limits.max_parent_packets = 0;
    let refused = submit_with_verified_parent_recovery(
        &node,
        client(server.address, &server, &guest),
        &packets[1],
        limits,
    );
    assert_eq!(
        refused.failure.as_deref(),
        Some("SUBMIT_RECOVERY_PARENT_LIMIT")
    );
    assert!(!refused.membership_observed);
    let wrong_public = identity(107).public_key().to_owned();
    let context = submit_with_verified_parent_recovery(
        &node,
        PinnedPublicClient {
            address: server.address,
            server_public: &wrong_public,
            identity: &guest,
            policy: policy(),
        },
        &packets[0],
        plan(),
    );
    assert_eq!(context.failure.as_deref(), Some("PUBLIC_CHALLENGE_CONTEXT"));
    assert_eq!(context.attempts.len(), 1);
    let other_settings = Settings::development(Some(settings.genesis_time() - 1)).unwrap();
    let mut other_node =
        Node::open(&dir.path().join("other-context"), other_settings.clone(), 1).unwrap();
    let other_packet = other_node
        .mine(
            vec![transfer(&other_settings, 1)],
            other_settings.genesis_time() + 2,
            ingress::now().unwrap(),
        )
        .unwrap();
    let context = submit_with_verified_parent_recovery(
        &other_node,
        client(server.address, &server, &guest),
        &other_packet,
        plan(),
    );
    assert_eq!(context.failure.as_deref(), Some("PUBLIC_CHALLENGE_CONTEXT"));
    assert_eq!(context.attempts.len(), 1);
    let normal = public_v3::call_public_protected_v3(
        server.address,
        &Request::Submit {
            packet: hex::encode(packets[0].encode().unwrap()),
        },
        &settings,
        &server.public,
        &guest,
        policy(),
    )
    .unwrap();
    assert!(normal.ok);
    let mut mutated = packets[0].clone();
    mutated.proof[100] ^= 1;
    assert_eq!(mutated.id().unwrap(), packets[0].id().unwrap());
    let duplicate = public_v3::call_public_protected_v3(
        server.address,
        &Request::Submit {
            packet: hex::encode(mutated.encode().unwrap()),
        },
        &settings,
        &server.public,
        &guest,
        policy(),
    )
    .unwrap();
    assert!(!duplicate.ok);
    assert_eq!(duplicate.value["error"], "DUPLICATE_CONTENT");
    let local = submit_with_verified_parent_recovery(
        &node,
        client(server.address, &server, &guest),
        &mutated,
        plan(),
    );
    assert_eq!(
        local.failure.as_deref(),
        Some("SUBMIT_RECOVERY_LOCAL_BYTES")
    );
    assert!(local.attempts.is_empty());
}

#[test]
fn actual_absolute_epoch_call_cap_and_current_clock_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, packets, settings) = producer(&dir.path().join("producer"), 1);
    let server = Server::start(&dir.path().join("receiver"), &settings);
    let guest = identity(108);
    let mut expired = plan();
    expired.started = std::time::Instant::now() - Duration::from_secs(2);
    expired.deadline = std::time::Instant::now() - Duration::from_secs(1);
    let result = submit_with_verified_parent_recovery(
        &node,
        client(server.address, &server, &guest),
        &packets[0],
        expired,
    );
    assert_eq!(result.failure.as_deref(), Some("SUBMIT_RECOVERY_DEADLINE"));
    assert!(result.attempts.is_empty());
    let mut future_epoch = plan();
    future_epoch.started = std::time::Instant::now() + Duration::from_secs(3600);
    future_epoch.deadline = future_epoch.started + Duration::from_secs(10);
    let result = submit_with_verified_parent_recovery(
        &node,
        client(server.address, &server, &guest),
        &packets[0],
        future_epoch,
    );
    assert_eq!(result.failure.as_deref(), Some("SUBMIT_RECOVERY_LIMITS"));
    assert!(result.attempts.is_empty());
    let proxy = Proxy::start(server.address, Interruption::BeforeHelloAdmission);
    let mut limited = plan();
    limited.max_calls = 1;
    let result = submit_with_verified_parent_recovery(
        &node,
        client(proxy.address, &server, &guest),
        &packets[0],
        limited,
    );
    assert_eq!(
        result.failure.as_deref(),
        Some("SUBMIT_RECOVERY_CALL_LIMIT")
    );
    assert_eq!(result.attempts.len(), 1);
    assert!(result.submission_outcome_uncertain && !result.may_advance_dependency);
    drop(proxy);
    // Explicit logical fixture admission; observation still uses fresh local wall clock.
    let future = ingress::now().unwrap() + 10000;
    let packet = node
        .make(
            node.active().unwrap().0,
            vec![],
            development_public(0).unwrap(),
            future,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, future).unwrap();
    node.activate_observed(id, future).unwrap();
    let result = submit_with_verified_parent_recovery(
        &node,
        client(server.address, &server, &guest),
        &packet,
        plan(),
    );
    assert_eq!(result.failure.as_deref(), Some("TIME_DEFERRED"));
    assert!(result.attempts.is_empty());
}

fn cli(genesis: u64, store: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    command
        .args([
            "push",
            "--development",
            "--genesis-time",
            &genesis.to_string(),
        ])
        .arg("--store")
        .arg(store);
    command
}
#[test]
fn actual_cli_default_reply_is_unchanged_and_opt_in_reports_duplicate_membership() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("producer");
    let (node, packets, settings) = producer(&store, 1);
    let expected = node.read_active().unwrap().2;
    drop(node);
    let file = dir.path().join("packet.pnw1");
    fs::write(&file, packets[0].encode().unwrap()).unwrap();
    let key = dir.path().join("guest.key");
    fs::write(&key, hex::encode([109; 32])).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let receiver = dir.path().join("receiver");
    let server = Server::start(&receiver, &settings);
    let run = |reliable: bool| {
        let mut command = cli(settings.genesis_time(), &store);
        command
            .args([
                "--peer",
                &server.address.to_string(),
                "--admission-profile",
                public_v3::PROFILE,
                "--admission-bits",
                "8",
                "--server-public",
                &server.public,
            ])
            .arg("--auth-secret")
            .arg(&key)
            .arg("--packet")
            .arg(&file);
        if reliable {
            command.arg("--reliable-submit");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "stderr={} stdout={}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let default = run(false);
    assert_eq!(default["ok"], true);
    assert!(default.get("schema").is_none() && default.get("attempts").is_none());
    let recovered = run(true);
    assert_eq!(recovered["schema"], "public-v3-local-submit-recovery-v1");
    assert_eq!(recovered["ok"], true);
    assert_eq!(recovered["attempts"].as_array().unwrap().len(), 4);
    assert_eq!(recovered["formal_confirmation_observed"], Value::Null);
    drop(server);
    let reopened = Node::open(&receiver, settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap().2, expected);
    assert_eq!(reopened.stats().unwrap()["stored_blocks"], 2);
}

#[test]
fn actual_membership_readiness_does_not_replace_installed_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let (node, packets, settings) = producer(&dir.path().join("producer"), 7);
    let server = Server::start(&dir.path().join("receiver"), &settings);
    let guest = identity(110);
    let outcome = submit_with_verified_parent_recovery(
        &node,
        client(server.address, &server, &guest),
        &packets[0],
        plan(),
    );
    assert!(outcome.ok && outcome.membership_observed);
    assert_eq!(outcome.formal_confirmation_observed, None);
    let transaction = Envelope::decode(&packets[0].transactions[0])
        .unwrap()
        .id()
        .unwrap();
    let included = packets[0].id().unwrap();
    let first = server
        .node
        .lock()
        .unwrap()
        .confirmation(transaction, included, ingress::now().unwrap())
        .unwrap();
    assert!(!first.confirmed);
    for packet in &packets[1..] {
        let reply = public_v3::call_public_protected_v3(
            server.address,
            &Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &settings,
            &server.public,
            &guest,
            policy(),
        )
        .unwrap();
        assert!(reply.ok);
    }
    let final_observation = server
        .node
        .lock()
        .unwrap()
        .confirmation(transaction, included, ingress::now().unwrap())
        .unwrap();
    assert!(final_observation.confirmed, "{final_observation:?}");
}

#[test]
fn actual_nonpreemptive_local_full_root_late_return_is_not_reported_on_time() {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(ingress::now().unwrap() - 200)).unwrap();
    let mut node = Node::open(&dir.path().join("producer"), settings.clone(), 1).unwrap();
    let mut transactions = Vec::new();
    for account_sequence in 1..=256 {
        let mut tx = Envelope::decode(&transfer(&settings, account_sequence)).unwrap();
        let mut payload = hash(
            b"public-submit-late-root-test-recipient",
            &[&account_sequence.to_le_bytes()],
        )
        .to_vec();
        payload.extend(1u64.to_le_bytes());
        tx.payload = payload;
        let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()])))
            .unwrap();
        tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
            .unwrap()
            .try_into()
            .unwrap();
        transactions.push(tx.encode().unwrap());
    }
    let packet = node
        .mine(
            transactions,
            settings.genesis_time() + 2,
            ingress::now().unwrap(),
        )
        .unwrap();
    let server = Server::start(&dir.path().join("receiver"), &settings);
    let guest = identity(111);
    let short = SubmitRecoveryPlan::new(Duration::from_millis(1)).unwrap();
    let result = submit_with_verified_parent_recovery(
        &node,
        client(server.address, &server, &guest),
        &packet,
        short,
    );
    assert_eq!(result.failure.as_deref(), Some("SUBMIT_RECOVERY_DEADLINE"));
    assert!(!result.ok && !result.may_advance_dependency);
    assert!(result.total_elapsed_ns >= 1_000_000);
    assert!(
        result.attempts.is_empty(),
        "local full-root stage returned too late before any RPC: {result:?}"
    );
    assert_eq!(
        server.node.lock().unwrap().active().unwrap().0,
        settings.genesis()
    );
}

#[test]
fn actual_cli_bad_combinations_and_limits_precede_store_creation() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("must-not-exist");
    for options in [
        vec!["--submit-attempts", "3"],
        vec![
            "--reliable-submit",
            "--admission-profile",
            public_v3::PROFILE,
            "--submit-deadline-ms",
            "0",
        ],
        vec![
            "--reliable-submit",
            "--admission-profile",
            public_v3::PROFILE,
            "--submit-attempts",
            "0",
        ],
        vec![
            "--reliable-submit",
            "--admission-profile",
            public_v3::PROFILE,
            "--submit-call-cap",
            "0",
        ],
        vec![
            "--reliable-submit",
            "--admission-profile",
            public_v3::PROFILE,
            "--submit-deadline-ms",
            "60001",
        ],
        vec![
            "--reliable-submit",
            "--admission-profile",
            public_v3::PROFILE,
            "--submit-attempts",
            "4",
        ],
        vec![
            "--reliable-submit",
            "--admission-profile",
            public_v3::PROFILE,
            "--submit-call-cap",
            "65",
        ],
        vec![
            "--reliable-submit",
            "--admission-profile",
            public_v3::PROFILE,
            "--submit-parent-depth",
            "17",
        ],
        vec![
            "--reliable-submit",
            "--admission-profile",
            ingress::public_v2::PROFILE,
        ],
    ] {
        let out = cli(1, &store).args(options).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(!store.exists());
    }
    for command in ["submit", "status", "serve"] {
        let out = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
            .args([command, "--development", "--reliable-submit"])
            .arg("--store")
            .arg(&store)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(!store.exists());
    }
}
