use super::*;

struct Running {
    directory: tempfile::TempDir,
    settings: Settings,
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<Result<Metrics>>>,
    client: AuthenticatedClient,
    other: AuthenticatedClient,
    target: Packet,
    honest: Packet,
    wire: Vec<u8>,
}
impl Running {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
        let (mut authentication, client) = authentication_fixture(&settings);
        let other =
            AuthenticatedClient::new(test_identity(3), authentication.public_key().to_owned(), 1)
                .unwrap();
        authentication.peers.insert(other.public_key().to_owned());
        let mut node = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let base = settings.genesis_time();
        let left = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                base + 10,
                4096,
            )
            .unwrap();
        let left_id = node.admit(&left, now().unwrap()).unwrap();
        node.activate_observed(left_id, now().unwrap()).unwrap();
        let right = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(1).unwrap(),
                base + 11,
                4096,
            )
            .unwrap();
        let right_id = node.admit(&right, now().unwrap()).unwrap();
        let target = node
            .make(
                right_id,
                vec![],
                crate::development_public(1).unwrap(),
                base + 21,
                4096,
            )
            .unwrap();
        let honest = node
            .make(
                left_id,
                vec![],
                crate::development_public(2).unwrap(),
                base + 22,
                4096,
            )
            .unwrap();
        // Both candidates have real native W1; the original request creates a
        // heavier competing branch and reaches the actual durable reorg intent.
        WorkCheckedPacket::verify(target.clone()).unwrap();
        WorkCheckedPacket::verify(honest.clone()).unwrap();
        assert!(node.public_service_cpu_domain().is_err());
        node.cancel_next_activation_intent_for_test();
        let wire = authenticated_request_bytes(
            &settings,
            &client,
            1,
            Request::Submit {
                packet: hex::encode(target.encode().unwrap()),
            },
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let server = thread::spawn(move || {
            serve_authenticated(
                listener,
                node,
                Duration::from_secs(20),
                worker_stop,
                authentication,
            )
        });
        Self {
            directory,
            settings,
            address,
            stop,
            server: Some(server),
            client,
            other,
            target,
            honest,
            wire,
        }
    }
    fn raw(&self, bytes: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write_frame(&mut stream, bytes).unwrap();
        // The service's original request deadline is ten seconds. This is
        // only the observing client's socket limit; it grants no service time.
        read_frame_budget(&mut stream, Duration::from_secs(15)).unwrap()
    }
    fn signed(&self, bytes: &[u8]) -> (Vec<u8>, bool, bool, Value) {
        let response = self.raw(bytes);
        let request: AuthenticatedRequest = serde_json::from_slice(bytes).unwrap();
        let digest =
            request_authority_digest(&request.session, request.replay_nonce, &request.request)
                .unwrap();
        let (terminal, ok, value) = verify_authenticated_response(
            &response,
            &request.session,
            request.replay_nonce,
            digest,
        )
        .unwrap();
        (response, terminal, ok, value)
    }
    fn durable(&self) -> Value {
        let db = rusqlite::Connection::open_with_flags(
            self.directory.path().join("native.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (done, target): (u64, Vec<u8>) = db
            .query_row(
                "SELECT done,new_tip FROM reorg WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let active: Vec<u8> = db
            .query_row("SELECT tip FROM active WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let (ack, pending): (u64, Option<u64>) = db
            .query_row(
                "SELECT highest_ack,pending_nonce FROM peer_replay",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let audit: u64 = db
            .query_row("SELECT COUNT(*) FROM peer_request_audit", [], |row| {
                row.get(0)
            })
            .unwrap();
        json!({"reorg_done":done,"target":hex::encode(target),"active":hex::encode(active),"highest_ack":ack,"pending_nonce":pending,"audit_rows":audit})
    }
    fn interrupted(&self) {
        let started = Instant::now();
        let (_, terminal, ok, value) = self.signed(&self.wire);
        assert!(!terminal && !ok);
        assert_eq!(value["error"], "REQUEST_DEADLINE");
        assert!(started.elapsed() >= Duration::from_secs(9));
        println!(
            "{}",
            json!({"schema":"native-actual-legacy-request-deadline-v1","request_deadline_not_renewed":true,"actual_original_request_timeout_seconds":10,"observed_wall_ns":started.elapsed().as_nanos(),"terminal":terminal,"ok":ok,"value":value,"typed_error_was_not_injected":true})
        );
        let durable = self.durable();
        assert_eq!(durable["reorg_done"], 0);
        assert_eq!(durable["target"], hex::encode(self.target.id().unwrap()));
        assert_eq!(durable["highest_ack"], 0);
        assert_eq!(durable["pending_nonce"], 1);
        assert_eq!(durable["audit_rows"], 1);
    }
    fn finish(&mut self) -> Metrics {
        self.stop.store(true, Ordering::Release);
        self.server.take().unwrap().join().unwrap().unwrap()
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

#[test]
fn signed_socket_exact_pending_frame_resumes_only_its_original_committed_intent() {
    let mut running = Running::new();
    running.interrupted();
    let before = running.durable();
    let mut changed_payload = running.target.clone();
    // Keep the original packet ID and legal packet framing while changing
    // the signed payload bytes. Its changed proof must never be replayed.
    changed_payload.proof[0] ^= 1;
    assert_eq!(changed_payload.id().unwrap(), running.target.id().unwrap());
    for (nonce, request) in [
        (
            1,
            Request::Submit {
                packet: hex::encode(changed_payload.encode().unwrap()),
            },
        ),
        (
            1,
            Request::Submit {
                packet: hex::encode(running.honest.encode().unwrap()),
            },
        ),
        (
            2,
            Request::Submit {
                packet: hex::encode(running.target.encode().unwrap()),
            },
        ),
        (1, Request::Head),
    ] {
        let bytes = authenticated_request_bytes(&running.settings, &running.client, nonce, request)
            .unwrap();
        let (_, terminal, ok, _) = running.signed(&bytes);
        assert!(!terminal && !ok);
        assert_eq!(running.durable(), before);
    }
    let mut wrong_context: AuthenticatedRequest = serde_json::from_slice(&running.wire).unwrap();
    wrong_context.session.parameters = hex::encode([0x99; 32]);
    let response = running.raw(&serde_json::to_vec(&wrong_context).unwrap());
    assert_eq!(
        serde_json::from_slice::<Value>(&response).unwrap()["error"],
        "AUTH_SESSION_CONTEXT"
    );
    assert_eq!(running.durable(), before);
    // This NEW signed socket attempt has its own original request deadline.
    // It does not extend the cancelled attempt or reserve a different nonce.
    let (completed, terminal, ok, value) = running.signed(&running.wire);
    assert!(terminal && ok);
    assert_eq!(value["block"], hex::encode(running.target.id().unwrap()));
    assert_eq!(value["active"], value["block"]);
    let after = running.durable();
    assert_eq!(after["reorg_done"], 1);
    assert_eq!(after["highest_ack"], 1);
    assert!(after["pending_nonce"].is_null());
    assert_eq!(after["audit_rows"], 1);
    let (cached, terminal, ok, _) = running.signed(&running.wire);
    assert!(terminal && ok);
    assert_eq!(completed, cached);
    let metrics = running.finish();
    assert_eq!(metrics.work_verifications, 1);
    assert_eq!(metrics.replayed_responses, 1);
    let reopened = Node::open(running.directory.path(), running.settings.clone(), 2).unwrap();
    assert_eq!(
        reopened.read_active().unwrap().0,
        running.target.id().unwrap()
    );
    println!(
        "{}",
        json!({"schema":"native-authenticated-exact-intent-recovery-v1","before":before,"after":after,"work_verifications":metrics.work_verifications,"cached_response_equal":true,"same_pending_nonce_acknowledged_once":true,"independent_reconciler_proved":false,"legacy_loopback_functional_test":true,"scalar_paid_host_qualified":false})
    );
}

#[test]
#[ignore = "BLOCKED liveness counterexample: original caller withholds replay; no original budgeted autonomous intent reconciler"]
fn withheld_original_frame_must_not_stall_a_different_honest_signed_mutation() {
    let mut running = Running::new();
    running.interrupted();
    let before = running.durable();
    let bytes = authenticated_request_bytes(
        &running.settings,
        &running.other,
        1,
        Request::Submit {
            packet: hex::encode(running.honest.encode().unwrap()),
        },
    )
    .unwrap();
    let started = Instant::now();
    let (_, terminal, ok, value) = running.signed(&bytes);
    let after = running.durable();
    let metrics = running.finish();
    println!(
        "{}",
        json!({"schema":"native-withheld-frame-liveness-counterexample-v1","original_requester_replayed":false,"different_honest_clients":1,"honest_mutation_attempts":1,"honest_mutations_succeeded":u64::from(terminal && ok),"honest_result":value,"elapsed_ns":started.elapsed().as_nanos(),"before":before,"after":after,"work_verifications":metrics.work_verifications,"registered_scalar_cpu_domain":false,"new_cpu_domains_created_for_recovery":0,"all_honest_service_target_met":terminal && ok,"production_activation":false,"scope":"actual legacy authenticated loopback sockets, exact original partial-intent cut; no new CPU account or relaxed readiness; intentionally failing isolated prototype gate"})
    );
    // Retain the real failure. A refused honest request is not a production PASS.
    assert!(
        terminal && ok,
        "BLOCKED: withheld original frame leaves honest mutation behind REORG_IN_PROGRESS"
    );
}
