//! Actual TCP authentication boundaries. Cookies spend local ingress capacity;
//! account spending still requires the independently verified native transaction.
use super::*;

fn identity(key: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([key; 32])).unwrap()
}

struct TestServer {
    address: SocketAddr,
    settings: Settings,
    policy: PublicPolicy,
    owner: Arc<Mutex<Node>>,
    metrics: Arc<Mutex<PublicMetrics>>,
    observer: PublicRequestObserver,
}

struct Stop(Arc<AtomicBool>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn with_server(
    node: Node,
    test: impl FnOnce(&TestServer),
) -> (PublicMetrics, PublicRequestObservationSnapshot) {
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    with_server_instance(node, PublicServer::new(identity(71), policy).unwrap(), test)
}

fn with_server_instance(
    node: Node,
    server: PublicServer,
    test: impl FnOnce(&TestServer),
) -> (PublicMetrics, PublicRequestObservationSnapshot) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = TestServer {
        address: listener.local_addr().unwrap(),
        settings: node.settings().clone(),
        policy: server.policy,
        owner: super::tests::shared(node),
        metrics: Arc::new(Mutex::new(PublicMetrics::default())),
        observer: PublicRequestObserver::new(8).unwrap(),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let (owner, metrics, observer, stopping) = (
        fixture.owner.clone(),
        fixture.metrics.clone(),
        fixture.observer.clone(),
        stop.clone(),
    );
    let metrics = thread::scope(|scope| {
        let worker = scope.spawn(move || {
            serve_public_protected_v3_with_request_observer(
                listener,
                owner,
                Duration::from_secs(8),
                stopping,
                server,
                metrics,
                observer,
            )
        });
        // A failed assertion still stops and joins the real service.
        let _stop = Stop(stop.clone());
        test(&fixture);
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap()
    });
    (metrics, fixture.observer.snapshot())
}

struct Challenge {
    socket: TcpStream,
    cookie: Cookie,
    raw: Vec<u8>,
    solution_deadline: Instant,
    total_deadline: Instant,
}

impl TestServer {
    fn challenge(&self, request: &Request, claimed_caller: &DevelopmentIdentity) -> Challenge {
        let raw = serde_json::to_vec(request).unwrap();
        let hello = Hello {
            op: request_op(request).unwrap(),
            len: raw.len(),
            caller: digest(claimed_caller.public_key()).unwrap(),
            digest: hash(b"public-request-body-v3", &[&raw]),
            client_nonce: [9; 32],
        };
        let start = Instant::now();
        let solution_deadline = start + Duration::from_millis(PREFIX_MS);
        let total_deadline = start + Duration::from_millis(OVERALL_MS);
        let mut socket = TcpStream::connect(self.address).unwrap();
        socket.set_nodelay(true).unwrap();
        client_write(&mut socket, &hello.encode(), solution_deadline).unwrap();
        let bytes = client_frame(&mut socket, 2048, solution_deadline).unwrap();
        let cookie: Cookie = serde_json::from_slice(&bytes).unwrap();
        validate_challenge_context(
            &bytes,
            &cookie,
            &hello,
            &self.settings,
            identity(71).public_key(),
            self.policy,
            self.policy.id(),
        )
        .unwrap();
        Challenge {
            socket,
            cookie,
            raw,
            solution_deadline,
            total_deadline,
        }
    }

    fn closed_record(&self, index: usize, deadline: Instant) -> PublicRequestObservation {
        loop {
            let snapshot = self.observer.snapshot();
            if let Some(record) = snapshot.records.get(index).filter(|row| row.complete) {
                assert!(!record.observation_failed);
                return record.clone();
            }
            assert!(
                Instant::now() < deadline,
                "actual connection did not close within the original test interval"
            );
            // The predicate, not a fixed delay, synchronizes actual disposal.
            thread::sleep(Duration::from_millis(1));
        }
    }
}

fn solution(cookie: &Cookie, signer: &DevelopmentIdentity) -> Vec<u8> {
    let id = cookie.id().unwrap();
    let nonce = (0..1_048_576u64)
        .find(|n| winner(id, *n, cookie.bits))
        .expect("original bounded ticket search");
    let message = pq_identity::caller_message(cookie, nonce, false).unwrap();
    let signature = signer.sign(&message).unwrap();
    verify_hex_strict(signer.public_key(), &message, &signature).unwrap();
    let mut bytes = b"PPS3".to_vec();
    bytes.extend(id);
    bytes.extend(nonce.to_le_bytes());
    bytes.extend(hex::decode(signature).unwrap());
    assert_eq!(bytes.len(), SOLUTION_BYTES);
    bytes
}

fn expect_closed_before_ready(socket: &mut TcpStream, deadline: Instant) {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .expect("refusal must not be inferred from a timeout");
        socket.set_read_timeout(Some(remaining)).unwrap();
        match socket.read(&mut [0; 1]) {
            Ok(0) => return,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => panic!("untrusted solution did not close before body-ready: {result:?}"),
        }
    }
}

fn assert_unpaid_solution_refusal(record: &PublicRequestObservation, error: &str) {
    assert_eq!(record.terminal_phase, Some("solution"));
    // This is an exact diagnostic assertion, not parsing text into authority.
    let diagnostic = serde_json::to_value(record.error_diagnostics.terminal).unwrap();
    assert_eq!(diagnostic["message_prefix"], error);
    assert_eq!(diagnostic["message_truncated"], false);
    assert!(!record.task_created);
    assert!(!record.dispatch_started);
    assert!(!record.full_work_started);
    assert_eq!(record.frames[2].bytes_read, SOLUTION_BYTES as u64);
    assert_eq!(record.frames[3].bytes_written, 0);
    assert_eq!(record.frames[4].bytes_read, 0);
}

fn complete_original(mut pending: Challenge, signed_solution: &[u8]) -> Response {
    let id = pending.cookie.id().unwrap();
    client_write(
        &mut pending.socket,
        signed_solution,
        pending.solution_deadline,
    )
    .unwrap();
    let ready: Value = serde_json::from_slice(
        &client_frame(&mut pending.socket, 256, pending.solution_deadline).unwrap(),
    )
    .unwrap();
    assert_eq!(ready["schema"], "public-body-ready-v3");
    assert_eq!(ready["cookie_digest"], hex::encode(id));
    client_write(
        &mut pending.socket,
        &pending.raw,
        pending
            .total_deadline
            .min(Instant::now() + Duration::from_millis(BODY_MS)),
    )
    .unwrap();
    let bytes = client_frame(
        &mut pending.socket,
        response_maximum(pending.cookie.op),
        pending
            .total_deadline
            .min(Instant::now() + Duration::from_millis(WORK_MS + OUTPUT_MS)),
    )
    .unwrap();
    let response: Response = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&response).unwrap(), bytes);
    assert_eq!(response.cookie_digest, hex::encode(id));
    assert_eq!(response.request_digest, pending.cookie.body_digest);
    verify_hex_strict(
        identity(71).public_key(),
        &response.message().unwrap(),
        &response.signature,
    )
    .unwrap();
    response
}

#[test]
fn forged_caller_cannot_spend_cookie_or_dispatch_victims_signed_native_packet() {
    let directory = tempfile::tempdir().unwrap();
    let now = super::super::now().unwrap();
    let settings = Settings::development(Some(now - 100)).unwrap();
    let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let before = node.read_active().unwrap();
    let victim = DevelopmentIdentity::from_secret_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&0u64.to_le_bytes()],
    )))
    .unwrap();
    assert_eq!(
        digest(victim.public_key()).unwrap(),
        crate::development_public(0).unwrap()
    );
    let packet = node
        .make(
            before.0,
            super::tests::accounting_transactions(&settings, 1, 1),
            crate::development_public(0).unwrap(),
            now - 50,
            4096,
        )
        .unwrap();
    let request = Request::Submit {
        packet: hex::encode(packet.encode().unwrap()),
    };
    let (metrics, records) = with_server(node, |server| {
        let mut forged = server.challenge(&request, &victim);
        let attacker_solution = solution(&forged.cookie, &identity(73));
        client_write(
            &mut forged.socket,
            &attacker_solution,
            forged.solution_deadline,
        )
        .unwrap();
        expect_closed_before_ready(&mut forged.socket, forged.solution_deadline);
        let refused = server.closed_record(0, forged.solution_deadline);
        assert_unpaid_solution_refusal(&refused, "PUBLIC_CALLER_SIGNATURE");
        {
            let counters = server.metrics.lock().unwrap();
            assert_eq!(counters.ticket_refusals, 0);
            assert_eq!(counters.signature_refusals, 1);
            assert_eq!(counters.spent_reservations, 0);
            assert_eq!(counters.pending_grant_entered, 0);
            assert_eq!(counters.tasks_enqueued, 0);
            assert_eq!(counters.body_bytes_received, 0);
            assert_eq!(counters.work_started, 0);
            assert_eq!(counters.completed_submit, 0);
            assert_eq!(counters.peak_paid_body_bytes, 0);
        }
        // This fixture's full native State, including the signed sender's nonce
        // and funds, remains unchanged before any authenticated dispatch.
        assert_eq!(server.owner.lock().unwrap().read_active().unwrap(), before);
        let reply = call_public_protected_v3(
            server.address,
            &request,
            &settings,
            identity(71).public_key(),
            &victim,
            server.policy,
        )
        .unwrap();
        assert!(reply.ok, "{}", reply.value);
        let owner = server.owner.lock().unwrap();
        let active = owner.read_active().unwrap();
        assert_eq!(active.0, packet.id().unwrap());
        assert!(active.1 > before.1);
        assert_eq!(owner.stats().unwrap()["height"], 1);
        assert_ne!(active.2, before.2);
    });
    assert_eq!(metrics.accepted_connections, 2);
    assert_eq!(metrics.signature_refusals, 1);
    assert_eq!(metrics.spent_reservations, 1);
    assert_eq!(metrics.work_started, 1);
    assert_eq!(metrics.work_finished, 1);
    assert_eq!(metrics.work_failed, 0);
    assert_eq!(metrics.completed_submit, 1);
    assert_eq!(metrics.paid_body_reserved_bytes_after_shutdown, 0);
    assert_eq!(metrics.mutating_grants_after_shutdown, 0);
    assert_eq!(records.records.len(), 2);
    assert!(records.records.iter().all(|record| record.complete));
}

#[test]
fn foreign_operation_or_body_cookie_cannot_burn_the_original_signed_solution() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
    let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let before = node.read_active().unwrap();
    let genesis = hex::encode(settings.genesis());
    let pairs = [
        (Request::Head, Request::PoolStatus),
        (
            Request::History {
                tip: genesis.clone(),
                after: genesis.clone(),
            },
            Request::History {
                tip: genesis,
                after: hex::encode([93; 32]),
            },
        ),
    ];
    let victim = identity(72);
    let (metrics, records) = with_server(node, |server| {
        for (index, (original_request, foreign_request)) in pairs.iter().enumerate() {
            let original = server.challenge(original_request, &victim);
            let mut foreign = server.challenge(foreign_request, &victim);
            assert_eq!(original.cookie.caller, foreign.cookie.caller);
            assert_ne!(original.cookie.body_digest, foreign.cookie.body_digest);
            if index == 0 {
                assert_ne!(original.cookie.op, foreign.cookie.op);
            } else {
                assert_eq!(original.cookie.op, foreign.cookie.op);
                assert_eq!(original.cookie.body_len, foreign.cookie.body_len);
            }
            let original_solution = solution(&original.cookie, &victim);
            let deadline = original.solution_deadline.min(foreign.solution_deadline);
            // Present the exact valid caller signature and ticket on another
            // connection. A claimed foreign cookie ID must never reach spent.
            client_write(&mut foreign.socket, &original_solution, deadline).unwrap();
            expect_closed_before_ready(&mut foreign.socket, deadline);
            let refused = server.closed_record(2 * index + 1, deadline);
            assert_unpaid_solution_refusal(&refused, "PUBLIC_SOLUTION");
            {
                let counters = server.metrics.lock().unwrap();
                assert_eq!(counters.signature_refusals, 0);
                assert_eq!(counters.spent_reservations, index as u64);
                assert_eq!(counters.tasks_enqueued, index as u64);
                assert_eq!(counters.work_started, 0);
            }
            // The exact same original solution is still usable, without a new
            // cookie, nonce, signature, deadline or one-shot authorization.
            let reply = complete_original(original, &original_solution);
            assert!(reply.ok, "{}", reply.value);
        }
        assert_eq!(server.owner.lock().unwrap().read_active().unwrap(), before);
    });
    assert_eq!(metrics.accepted_connections, 4);
    assert_eq!(metrics.spent_reservations, 2);
    assert_eq!(metrics.replay_refusals, 0);
    assert_eq!(metrics.signature_refusals, 0);
    assert_eq!(metrics.completed_read, 2);
    assert_eq!(metrics.work_started, 0);
    assert_eq!(metrics.paid_body_reserved_bytes_after_shutdown, 0);
    assert_eq!(metrics.read_grants_after_shutdown, 0);
    assert_eq!(records.records.len(), 4);
    assert!(records.records.iter().all(|record| record.complete));
}

#[test]
fn actual_cold_zero_authentication_credit_serves_one_head_without_client_retry() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
    let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let before = node.read_active().unwrap();
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let server = PublicServer::new_process_cold(identity(71), policy).unwrap();
    let intake = server.listener_intake().unwrap();
    let cold = intake.classical_authentication.observation().unwrap();
    assert_eq!(cold.stored_credit_ns, 0);
    assert_eq!(cold.attempts, 0);
    assert_eq!(cold.in_flight, 0);
    let (metrics, records) = with_server_instance(node, server, |server| {
        // Exactly one ordinary client call. The reactor retains its existing
        // Hello/Solution state while original wall-clock refill earns the
        // authentication reservation; the client never reconnects or retries.
        let (result, client) = call_public_protected_v3_with_metrics(
            server.address,
            &Request::Head,
            &settings,
            identity(71).public_key(),
            &identity(72),
            policy,
        );
        let reply = result.unwrap();
        assert!(reply.ok, "{}", reply.value);
        assert_eq!(client.failed_stage, None);
        assert!(client.solution_found);
        assert!(client.challenge_ns <= PREFIX_MS * 1_000_000);
        assert_eq!(
            reply.body_bytes_sent,
            serde_json::to_vec(&Request::Head).unwrap().len()
        );
        assert_eq!(server.owner.lock().unwrap().read_active().unwrap(), before);
    });
    assert_eq!(metrics.accepted_connections, 1);
    assert_eq!(metrics.issued_challenges, 1);
    assert_eq!(metrics.spent_reservations, 1);
    assert_eq!(metrics.signature_refusals, 0);
    assert_eq!(metrics.ticket_refusals, 0);
    assert_eq!(metrics.completed_read, 1);
    assert_eq!(metrics.work_started, 0);
    let authentication = metrics.classical_authentication_cpu.unwrap();
    assert_eq!(authentication.attempts, 3);
    assert_eq!(authentication.known_intervals, 3);
    assert_eq!(authentication.unknown_intervals, 0);
    assert_eq!(authentication.in_flight, 0);
    assert!(authentication.known_thread_cpu_ns > 0);
    assert!(!authentication.unavailable);
    assert_eq!(records.records.len(), 1);
    assert!(records.records[0].complete);
    assert!(records.records[0].response_frame_complete);
}
