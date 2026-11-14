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
        let started = Instant::now();
        let identity = hex::encode(hash(b"native-reorg-socket-evidence-v1", &[bytes]));
        println!("{}",json!({"schema":"native-reorg-socket-request-v1","request_identity":identity,"raw_frame_hex":hex::encode(bytes),"request_scheduled":true}));
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
        let response = read_frame_budget(&mut stream, Duration::from_secs(15)).unwrap();
        println!("{}",json!({"schema":"native-reorg-socket-response-v1","request_identity":identity,"raw_frame_hex":hex::encode(&response),"scheduled_to_observed_ns":started.elapsed().as_nanos()}));
        response
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
                "SELECT highest_ack,pending_nonce FROM peer_replay WHERE session_id=?",
                [digest(&serde_json::from_slice::<AuthenticatedRequest>(&self.wire).unwrap().session.session).unwrap().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let audit: u64 = db
            .query_row("SELECT COUNT(*) FROM peer_request_audit", [], |row| {
                row.get(0)
            })
            .unwrap();
        let lifecycle: Vec<(i64,u64,Option<u64>,String)> = db.prepare(
            "SELECT operation,outcome,cancelled_cursor,reason FROM reorg_lifecycle_v1 ORDER BY operation"
        ).unwrap().query_map([], |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))
            .unwrap().collect::<std::result::Result<_,_>>().unwrap();
        json!({"reorg_done":done,"target":hex::encode(target),"active":hex::encode(active),"highest_ack":ack,"pending_nonce":pending,"audit_rows":audit,"lifecycle":lifecycle})
    }
    fn active_snapshot(&self) -> Value {
        let db = rusqlite::Connection::open_with_flags(
            self.directory.path().join("native.sqlite"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).unwrap();
        let (tip,generation,slot):(Vec<u8>,u64,u64)=db.query_row(
            "SELECT tip,generation,state_slot FROM active WHERE singleton=1",[],
            |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).unwrap();
        let values:Vec<(String,Vec<u8>)>=db.prepare("SELECT key,value FROM kv WHERE slot=? ORDER BY key")
            .unwrap().query_map([slot],|row|Ok((row.get(0)?,row.get(1)?))).unwrap()
            .collect::<std::result::Result<_,_>>().unwrap();
        json!({"tip":hex::encode(tip),"generation":generation,"slot":slot,
            "active_bytes_digest":hex::encode(hash(b"reorg-cancellation-test-state-v1",&[&serde_json::to_vec(&values).unwrap()]))})
    }
    fn interrupted(&self) {
        let active_before = self.active_snapshot();
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
        assert_eq!(durable["reorg_done"], 2);
        assert_eq!(durable["target"], hex::encode(self.target.id().unwrap()));
        assert_eq!(durable["highest_ack"], 0);
        assert_eq!(durable["pending_nonce"], 1);
        assert_eq!(durable["audit_rows"], 1);
        assert_eq!(durable["lifecycle"][0][1], 2);
        assert_eq!(durable["lifecycle"][0][3], "REQUEST_DEADLINE");
        assert_eq!(self.active_snapshot(), active_before);
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
fn authenticated_dispatch_retry_is_confined_to_local_queue_and_cancellation() {
    for code in [
        ErrorCode::LegacyRequestCancelled,
        ErrorCode::LegacyRequestDeadline,
        ErrorCode::PublicRequestCancelled,
        ErrorCode::PublicRequestDeadline,
        ErrorCode::PublicQueueBusy,
    ] {
        assert!(authenticated_dispatch_needs_retry(&Error::new(code)));
    }
    for error in [
        Error::new(ErrorCode::StateCapacity),
        Error::new(ErrorCode::GrowthCapacity),
        Error::new(ErrorCode::PublicExecutionSnapshotCapacity),
        Error::new(ErrorCode::PublicMutationCpuUnavailable),
        Error::new(ErrorCode::PublicQueueBusy).local_integrity(),
        Error::remote("PUBLIC_QUEUE_BUSY"),
        Error::from("WORK:Transcript"),
        Error::from("WORK:Product"),
    ] {
        assert!(!authenticated_dispatch_needs_retry(&error), "{error}");
    }
}

#[test]
fn signed_socket_local_queue_busy_keeps_exact_nonce_for_retry_and_invalid_work_terminal() {
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
    let (authentication, client) = authentication_fixture(&settings);
    let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let packet = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let id = packet.id().unwrap();
    let mut invalid = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(1).unwrap(),
            settings.genesis_time() + 11,
            4096,
        )
        .unwrap();
    // Keep a real target-hitting transcript; change only one bounded product
    // word so the invalid control reaches the original full W1 Product check.
    let offset = 4 + 2 * trnm_crypto_primitives::pon_work::CELLS * 4;
    let word = u32::from_le_bytes(invalid.proof[offset..offset + 4].try_into().unwrap());
    let changed = ((u128::from(word) + 1) % trnm_crypto_primitives::pon_work::Q) as u32;
    invalid.proof[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
    let wire = authenticated_request_bytes(
        &settings,
        &client,
        1,
        Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        },
    )
    .unwrap();
    let envelope: AuthenticatedRequest = serde_json::from_slice(&wire).unwrap();
    let session = digest(&envelope.session.session).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    // This is the real shared execution-capacity slot. Keep it owned until
    // the actual signed request exhausts the original two-second queue wait;
    // no error injection, shortened budget or fake verifier is involved.
    let held = node.reserve_detached_execution().unwrap();
    let call = |bytes: &[u8]| {
        let envelope: AuthenticatedRequest = serde_json::from_slice(bytes).unwrap();
        let digest =
            request_authority_digest(&envelope.session, envelope.replay_nonce, &envelope.request)
                .unwrap();
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write_frame(&mut stream, bytes).unwrap();
        // Only the observer waits this long. The server keeps its original
        // request deadline and the original two-second shared queue limit.
        let reply = read_frame_budget(&mut stream, Duration::from_secs(15)).unwrap();
        let (terminal, ok, value) =
            verify_authenticated_response(&reply, &envelope.session, envelope.replay_nonce, digest)
                .unwrap();
        (reply, terminal, ok, value)
    };
    let durable = |nonce: u64| {
        let db = rusqlite::Connection::open_with_flags(
            directory.path().join("native.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (ack, pending): (u64, Option<u64>) = db
            .query_row(
                "SELECT highest_ack,pending_nonce FROM peer_replay WHERE session_id=?",
                [session.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let (status, payload, response): (u64, Option<Vec<u8>>, Option<Vec<u8>>) = db
            .query_row(
                "SELECT status,payload,response FROM peer_request_audit WHERE session_id=? AND nonce=?",
                rusqlite::params![session.as_slice(), nonce],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let blocks: u64 = db
            .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))
            .unwrap();
        let tip: Vec<u8> = db
            .query_row("SELECT tip FROM active WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        json!({"highest_ack":ack,"pending_nonce":pending,"audit_status":status,
            "payload":payload.map(hex::encode),"response":response.map(hex::encode),
            "stored_blocks":blocks,"active":hex::encode(tip)})
    };
    thread::scope(|scope| {
        let worker_stop = stop.clone();
        let worker = scope.spawn(move || {
            serve_authenticated(
                listener,
                node,
                Duration::from_secs(20),
                worker_stop,
                authentication,
            )
        });
        // This guard also stops the scoped service if a regression panics.
        let _shutdown = StopOnDrop(stop.clone());
        let started = Instant::now();
        let (_, terminal, ok, value) = call(&wire);
        assert!(
            !terminal && !ok,
            "local Busy cannot finish this operation: {value}"
        );
        assert_eq!(value["error"], "PUBLIC_QUEUE_BUSY");
        assert!(started.elapsed() >= Duration::from_secs(2));
        let pending = durable(1);
        assert_eq!(pending["highest_ack"], 0);
        assert_eq!(pending["pending_nonce"], 1);
        assert_eq!(pending["audit_status"], 0);
        assert!(pending["payload"].is_string() && pending["response"].is_null());
        assert_eq!(pending["stored_blocks"], 1);
        assert_eq!(pending["active"], hex::encode(settings.genesis()));

        let changed = authenticated_request_bytes(&settings, &client, 1, Request::Head).unwrap();
        let (_, terminal, ok, value) = call(&changed);
        assert!(!terminal && !ok);
        assert!(value["error"]
            .as_str()
            .unwrap()
            .contains("changed its payload"));
        assert_eq!(durable(1), pending);
        drop(held);

        let (completed, terminal, ok, value) = call(&wire);
        assert!(
            terminal && ok,
            "exact retry after releasing the slot: {value}"
        );
        assert_eq!(value["block"], hex::encode(id));
        assert_eq!(value["active"], value["block"]);
        let finished = durable(1);
        assert_eq!(finished["highest_ack"], 1);
        assert!(finished["pending_nonce"].is_null() && finished["payload"].is_null());
        assert_eq!(finished["audit_status"], 1);
        assert_eq!(finished["stored_blocks"], 2);
        let (cached, terminal, ok, _) = call(&wire);
        assert!(terminal && ok);
        assert_eq!(cached, completed);
        assert_eq!(durable(1), finished);

        let invalid_wire = authenticated_request_bytes(
            &settings,
            &client,
            2,
            Request::Submit {
                packet: hex::encode(invalid.encode().unwrap()),
            },
        )
        .unwrap();
        let (invalid_reply, terminal, ok, value) = call(&invalid_wire);
        assert!(terminal && !ok);
        assert_eq!(value["error"], "WORK:Product");
        let invalid_finished = durable(2);
        assert_eq!(invalid_finished["highest_ack"], 2);
        assert!(invalid_finished["pending_nonce"].is_null());
        assert_eq!(invalid_finished["audit_status"], 1);
        assert_eq!(invalid_finished["stored_blocks"], 2);
        let (cached, terminal, ok, _) = call(&invalid_wire);
        assert!(terminal && !ok);
        assert_eq!(cached, invalid_reply);
        assert_eq!(durable(2), invalid_finished);

        stop.store(true, Ordering::Release);
        let metrics = worker.join().unwrap().unwrap();
        assert_eq!(metrics.work_verifications, 3);
        assert_eq!(metrics.replayed_responses, 2);
        println!("AUTH_LOCAL_QUEUE_RETRY actual_capacity_refusal=true same_signed_bytes=true same_session_nonce=true changed_payload_refused=true complete_invalid_work_terminal=true work_verifications=3 cached_responses=2 original_queue_seconds=2 budget_changed=false");
    });
    let reopened = Node::open(directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap().0, id);
    assert_eq!(reopened.stats().unwrap()["authenticated_pending"], 0);
    assert_eq!(reopened.stats().unwrap()["authenticated_audit_rows"], 2);
    assert_eq!(durable(2)["highest_ack"], 2);
}

#[test]
fn authenticated_context_retry_requires_exact_local_identity_and_kind() {
    for code in [
        ErrorCode::UnknownParent,
        ErrorCode::TimeDeferred,
        ErrorCode::AdmissionHeaderEpochChanged,
    ] {
        assert!(authenticated_dispatch_needs_retry(&Error::new(code)));
        assert!(!authenticated_dispatch_needs_retry(
            &Error::new(code).local_integrity()
        ));
        assert!(!authenticated_dispatch_needs_retry(&Error::remote(
            code.as_str()
        )));
        assert!(!authenticated_dispatch_needs_retry(
            &Error::authenticated_remote(true, code.as_str())
        ));
        assert!(!authenticated_dispatch_needs_retry(
            &Error::authenticated_remote(false, code.as_str())
        ));
        assert!(!authenticated_dispatch_needs_retry(&Error::from(format!(
            "{}:unclassified context",
            code.as_str()
        ))));
    }
    for code in [
        ErrorCode::Cursor,
        ErrorCode::AuthReplayContext,
        ErrorCode::AuthReplayRetired,
        ErrorCode::PublicCookieExpired,
        ErrorCode::StateCapacity,
        ErrorCode::PublicMutationCpuUnavailable,
    ] {
        assert!(!authenticated_dispatch_needs_retry(&Error::new(code)));
    }
}

#[test]
fn signed_socket_missing_parent_preserves_exact_nonce_until_parent_arrives() {
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let producer_directory = tempfile::tempdir().unwrap();
    let receiver_directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(now().unwrap() - 100)).unwrap();
    let mut producer = Node::open(producer_directory.path(), settings.clone(), 1).unwrap();
    let parent = producer
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let parent_id = producer.admit(&parent, now().unwrap()).unwrap();
    producer
        .activate_observed(parent_id, now().unwrap())
        .unwrap();
    let child = producer
        .make(
            parent_id,
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 20,
            4096,
        )
        .unwrap();
    let child_id = child.id().unwrap();
    let mut invalid = producer
        .make(
            parent_id,
            vec![],
            crate::development_public(1).unwrap(),
            settings.genesis_time() + 21,
            4096,
        )
        .unwrap();
    // This separate real target-hitting packet reaches full verification,
    // where one incorrect product claim is a terminal mathematical error.
    let offset = 4 + 2 * trnm_crypto_primitives::pon_work::CELLS * 4;
    let word = u32::from_le_bytes(invalid.proof[offset..offset + 4].try_into().unwrap());
    let changed = ((u128::from(word) + 1) % trnm_crypto_primitives::pon_work::Q) as u32;
    invalid.proof[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
    drop(producer);

    let (mut authentication, child_client) = authentication_fixture(&settings);
    let parent_client =
        AuthenticatedClient::new(test_identity(3), authentication.public_key().to_owned(), 1)
            .unwrap();
    authentication
        .peers
        .insert(parent_client.public_key().to_owned());
    let child_wire = authenticated_request_bytes(
        &settings,
        &child_client,
        1,
        Request::Submit {
            packet: hex::encode(child.encode().unwrap()),
        },
    )
    .unwrap();
    let envelope: AuthenticatedRequest = serde_json::from_slice(&child_wire).unwrap();
    let session = digest(&envelope.session.session).unwrap();
    let node = Node::open(receiver_directory.path(), settings.clone(), 1).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let call = |bytes: &[u8]| {
        let envelope: AuthenticatedRequest = serde_json::from_slice(bytes).unwrap();
        let digest =
            request_authority_digest(&envelope.session, envelope.replay_nonce, &envelope.request)
                .unwrap();
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write_frame(&mut stream, bytes).unwrap();
        let reply = read_frame_budget(&mut stream, Duration::from_secs(15)).unwrap();
        let (terminal, ok, value) =
            verify_authenticated_response(&reply, &envelope.session, envelope.replay_nonce, digest)
                .unwrap();
        (reply, terminal, ok, value)
    };
    let durable = |nonce: u64| {
        let db = rusqlite::Connection::open_with_flags(
            receiver_directory.path().join("native.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (ack, pending): (u64, Option<u64>) = db
            .query_row(
                "SELECT highest_ack,pending_nonce FROM peer_replay WHERE session_id=?",
                [session.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let (status, payload, response): (u64, Option<Vec<u8>>, Option<Vec<u8>>) = db
            .query_row(
                "SELECT status,payload,response FROM peer_request_audit WHERE session_id=? AND nonce=?",
                rusqlite::params![session.as_slice(), nonce],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let blocks: u64 = db
            .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))
            .unwrap();
        let tip: Vec<u8> = db
            .query_row("SELECT tip FROM active WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        json!({"highest_ack":ack,"pending_nonce":pending,"audit_status":status,
            "payload":payload.map(hex::encode),"response":response.map(hex::encode),
            "stored_blocks":blocks,"active":hex::encode(tip)})
    };
    thread::scope(|scope| {
        let worker_stop = stop.clone();
        let worker = scope.spawn(move || {
            serve_authenticated(
                listener,
                node,
                Duration::from_secs(30),
                worker_stop,
                authentication,
            )
        });
        let _shutdown = StopOnDrop(stop.clone());
        // The receiver has only genesis. This is a real missing-parent
        // admission refusal, before full Work, not an injected error or clock.
        let (_, terminal, ok, value) = call(&child_wire);
        assert!(
            !terminal && !ok,
            "missing parent ended exact retry: {value}"
        );
        assert_eq!(value["error"], "UNKNOWN_PARENT");
        let pending = durable(1);
        assert_eq!(pending["highest_ack"], 0);
        assert_eq!(pending["pending_nonce"], 1);
        assert_eq!(pending["audit_status"], 0);
        assert!(pending["payload"].is_string() && pending["response"].is_null());
        assert_eq!(pending["stored_blocks"], 1);
        assert_eq!(pending["active"], hex::encode(settings.genesis()));

        let changed =
            authenticated_request_bytes(&settings, &child_client, 1, Request::Head).unwrap();
        let (_, terminal, ok, value) = call(&changed);
        assert!(!terminal && !ok);
        assert!(value["error"]
            .as_str()
            .unwrap()
            .contains("changed its payload"));
        assert_eq!(durable(1), pending);

        // A distinct authenticated session supplies the missing parent while
        // the original child operation keeps its exact signed bytes and nonce.
        let parent_wire = authenticated_request_bytes(
            &settings,
            &parent_client,
            1,
            Request::Submit {
                packet: hex::encode(parent.encode().unwrap()),
            },
        )
        .unwrap();
        let (_, terminal, ok, value) = call(&parent_wire);
        assert!(
            terminal && ok,
            "independent parent delivery failed: {value}"
        );
        assert_eq!(value["block"], hex::encode(parent_id));
        let after_parent = durable(1);
        assert_eq!(after_parent["highest_ack"], 0);
        assert_eq!(after_parent["pending_nonce"], 1);
        assert_eq!(after_parent["payload"], pending["payload"]);
        assert!(after_parent["response"].is_null());
        assert_eq!(after_parent["stored_blocks"], 2);

        let (completed, terminal, ok, value) = call(&child_wire);
        assert!(terminal && ok, "exact child retry failed: {value}");
        assert_eq!(value["block"], hex::encode(child_id));
        assert_eq!(value["active"], value["block"]);
        let finished = durable(1);
        assert_eq!(finished["highest_ack"], 1);
        assert!(finished["pending_nonce"].is_null() && finished["payload"].is_null());
        assert_eq!(finished["audit_status"], 1);
        assert_eq!(finished["stored_blocks"], 3);
        let (cached, terminal, ok, _) = call(&child_wire);
        assert!(terminal && ok);
        assert_eq!(cached, completed);
        assert_eq!(durable(1), finished);

        let invalid_wire = authenticated_request_bytes(
            &settings,
            &child_client,
            2,
            Request::Submit {
                packet: hex::encode(invalid.encode().unwrap()),
            },
        )
        .unwrap();
        let (invalid_reply, terminal, ok, value) = call(&invalid_wire);
        assert!(terminal && !ok);
        assert_eq!(value["error"], "WORK:Product");
        let invalid_finished = durable(2);
        assert_eq!(invalid_finished["highest_ack"], 2);
        assert!(invalid_finished["pending_nonce"].is_null());
        assert_eq!(invalid_finished["audit_status"], 1);
        assert_eq!(invalid_finished["stored_blocks"], 3);
        let (cached, terminal, ok, _) = call(&invalid_wire);
        assert!(terminal && !ok);
        assert_eq!(cached, invalid_reply);
        assert_eq!(durable(2), invalid_finished);

        stop.store(true, Ordering::Release);
        let metrics = worker.join().unwrap().unwrap();
        assert_eq!(metrics.work_verifications, 3);
        assert_eq!(metrics.replayed_responses, 2);
        println!("AUTH_MISSING_PARENT_RETRY actual_unknown_parent=true separate_parent_session=true same_signed_bytes=true same_session_nonce=true changed_payload_refused=true complete_invalid_work_terminal=true work_verifications=3 cached_responses=2 budget_changed=false");
    });
    let reopened = Node::open(receiver_directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap().0, child_id);
    assert_eq!(reopened.stats().unwrap()["authenticated_pending"], 0);
    assert_eq!(reopened.stats().unwrap()["authenticated_audit_rows"], 3);
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
    assert_eq!(after["lifecycle"][0], before["lifecycle"][0]);
    assert_eq!(after["lifecycle"].as_array().unwrap().len(), 2);
    assert_eq!(after["lifecycle"][1][1], 1);
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
#[ignore = "actual original ten-second deadline and signed-socket honest-service gate; run explicitly"]
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
        json!({"schema":"native-withheld-frame-liveness-termination-v2","original_requester_replayed":false,"different_honest_clients":1,"honest_mutation_attempts":1,"honest_mutations_succeeded":u64::from(terminal && ok),"honest_result":value,"elapsed_ns":started.elapsed().as_nanos(),"before":before,"after":after,"work_verifications":metrics.work_verifications,"registered_scalar_cpu_domain":false,"new_cpu_domains_created_for_recovery":0,"all_honest_service_target_met":terminal && ok,"production_activation":false,"scope":"same actual legacy authenticated sockets, original ten-second deadline and exact original intent cut; same-owner metadata-only termination, unchanged active State, separate paid-resource gate still required"})
    );
    // The original success assertion and original different caller are retained.
    assert!(
        terminal && ok,
        "withheld original frame leaves honest mutation behind REORG_IN_PROGRESS"
    );
    assert_eq!(after["highest_ack"], 0);
    assert_eq!(after["pending_nonce"], 1);
    assert_eq!(after["lifecycle"][0], before["lifecycle"][0]);
}
