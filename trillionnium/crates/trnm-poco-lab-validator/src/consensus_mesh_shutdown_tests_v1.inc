// Real transport data; queue/lifecycle observations remain process-local tests,
// not consensus receipts or a claim that the full mesh terminal consumer ran.
fn shutdown_tcp_pair_v1() -> (
    AuthenticatedConnection<DeadlineIo>,
    MeshAuthenticatedConnectionV1<DeadlineIo>,
) {
    let (client, server) = authenticated_identity_fixture_v0();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut expected = BTreeMap::new();
    expected.insert(client.local, "127.0.0.1:1".parse().unwrap());
    let accepting = thread::spawn(move || {
        let (stream, source) = listener.accept().unwrap();
        authenticate_incoming(
            stream,
            source,
            &expected,
            &server,
            Instant::now() + Duration::from_secs(3),
            Duration::from_secs(2),
        )
        .unwrap()
    });
    let stream = TcpStream::connect(address).unwrap();
    let io = DeadlineIo::new(stream, Instant::now() + Duration::from_secs(3)).unwrap();
    let connection = AuthenticatedConnection::connect(
        io,
        &client.run_id,
        client.local,
        server_thread_remote_v0(&client.validator_set, client.local),
        match &client.p2p_identity_signer {
            MeshIdentitySignerV1::Local(key) => key,
            MeshIdentitySignerV1::External(_) => unreachable!("local fixture"),
        },
        &client.validator_set,
        &client.key_roles,
        client.transport_context,
    )
    .unwrap();
    (connection, accepting.join().unwrap())
}

#[test]
fn shutdown_preserves_real_tcp_owned_event_or_records_bounded_failure_v1() {
    // 0 available queue; 1 full queue; 2 disconnected; 3 superseded edge.
    for mode in 0..4 {
        let (mut sender_connection, mut receiver_connection) = shutdown_tcp_pair_v1();
        sender_connection
            .send(FrameKind::Vote, vec![0x51, 0x52])
            .unwrap();
        let frame = receiver_connection.receive().unwrap();
        let facts = PeerSessionFactsV0 {
            remote: receiver_connection.remote(),
            direction: PeerDirectionV0::Inbound,
            session_id: receiver_connection.session_id(),
            generation: 1,
        };
        assert_eq!(frame.sender, facts.remote);
        assert_eq!(frame.session, facts.session_id);
        let bytes = frame.payload.len() + QUEUED_FRAME_OVERHEAD_BYTES;
        let peer = Arc::new(MeshQueueByteBudgetV0::new(bytes));
        let global = Arc::new(MeshQueueByteBudgetV0::new(bytes));
        let reservation = InboundQueueReservationV0::try_new(&peer, &global, bytes).unwrap();
        let event = MeshIngressEventV0::Frame(MeshInboundFrameV0 {
            remote: facts.remote,
            direction: facts.direction,
            session_id: facts.session_id,
            session_generation: facts.generation,
            frame,
            _reservation: reservation,
        });
        let (tx, rx) = mpsc::sync_channel(1);
        if mode == 1 {
            tx.try_send(MeshIngressEventV0::SessionUnavailable(facts))
                .unwrap();
        }
        let rx = if mode == 2 {
            drop(rx);
            None
        } else {
            Some(rx)
        };
        let stop = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(Mutex::new(None));
        let cancel = Arc::new(AtomicBool::new(false));
        let (go_tx, go_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn({
            let stop = Arc::clone(&stop);
            let terminal = Arc::clone(&terminal);
            let cancel = Arc::clone(&cancel);
            move || {
                go_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                done_tx
                    .send(emit_event(
                        &tx,
                        event,
                        &terminal,
                        &stop,
                        facts,
                        Some(&cancel),
                    ))
                    .unwrap();
            }
        });
        // The worker already owns original authenticated frame + reservation.
        // Control its exact handoff so this tests a real stop race, not timing.
        stop.store(true, Ordering::Release);
        if mode == 3 {
            cancel.store(true, Ordering::Release);
        }
        go_tx.send(()).unwrap();
        let result = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
        if mode == 0 {
            result.expect("owned frame must survive stop for residual validation");
            assert!(terminal.lock().unwrap().is_none());
            assert_eq!(global.used_bytes.load(Ordering::Acquire), bytes);
            let event = rx.unwrap().recv_timeout(Duration::from_secs(1)).unwrap();
            let MeshIngressEventV0::Frame(inbound) = event else {
                panic!("original frame missing");
            };
            assert_eq!(inbound.remote(), facts.remote);
            assert_eq!(inbound.session_id(), facts.session_id);
            assert_eq!(inbound.session_generation(), 1);
            assert_eq!(inbound.frame().kind, FrameKind::Vote);
            assert_eq!(inbound.frame().payload, [0x51, 0x52]);
            drop(inbound);
        } else {
            assert!(result.is_err());
            if mode == 3 {
                assert!(
                    terminal.lock().unwrap().is_none(),
                    "edge cancellation stays distinct"
                );
                assert!(matches!(
                    rx.unwrap().try_recv(),
                    Err(TryRecvError::Empty | TryRecvError::Disconnected)
                ));
            } else {
                let failure = terminal.lock().unwrap();
                let failure = failure
                    .as_ref()
                    .expect("shutdown must retain dropped-work failure");
                assert_eq!(failure.remote, facts.remote);
                assert_eq!(failure.direction, facts.direction);
                assert!(failure
                    .reason
                    .contains(if mode == 1 { "full" } else { "disappeared" }));
            }
        }
        assert_eq!(global.used_bytes.load(Ordering::Acquire), 0);
        assert_eq!(peer.used_bytes.load(Ordering::Acquire), 0);
    }
}

#[test]
fn shutdown_decoded_tcp_frame_cannot_evade_original_byte_capacity_v1() {
    for superseded in [false, true] {
        let (mut sender, mut receiver) = shutdown_tcp_pair_v1();
        sender.send(FrameKind::Vote, vec![1]).unwrap();
        sender.send(FrameKind::Vote, vec![2]).unwrap();
        let first = receiver.receive().unwrap();
        let second = receiver.receive().unwrap();
        assert_eq!((first.sequence, second.sequence), (0, 1));
        let facts = PeerSessionFactsV0 {
            remote: receiver.remote(),
            direction: PeerDirectionV0::Inbound,
            session_id: receiver.session_id(),
            generation: 1,
        };
        let bytes = first.payload.len() + QUEUED_FRAME_OVERHEAD_BYTES;
        let peer = Arc::new(MeshQueueByteBudgetV0::new(bytes));
        let global = Arc::new(MeshQueueByteBudgetV0::new(bytes));
        let held = MeshInboundFrameV0 {
            remote: facts.remote,
            direction: facts.direction,
            session_id: facts.session_id,
            session_generation: facts.generation,
            frame: first,
            _reservation: InboundQueueReservationV0::try_new(&peer, &global, bytes).unwrap(),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(Mutex::new(None));
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn({
            let peer = Arc::clone(&peer);
            let global = Arc::clone(&global);
            let stop = Arc::clone(&stop);
            let cancel = Arc::clone(&cancel);
            let terminal = Arc::clone(&terminal);
            move || {
                started_tx.send(()).unwrap();
                let reservation = reserve_decoded_inbound_frame_v1(
                    &peer,
                    &global,
                    second.payload.len() + QUEUED_FRAME_OVERHEAD_BYTES,
                    &stop,
                    &cancel,
                    &terminal,
                    facts,
                );
                assert_eq!(second.sequence, 1);
                done_tx.send(reservation.is_some()).unwrap();
            }
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            done_rx.recv_timeout(WORKER_POLL + WORKER_POLL),
            Err(RecvTimeoutError::Timeout)
        ));
        assert_eq!(peer.used_bytes.load(Ordering::Acquire), bytes);
        if superseded {
            cancel.store(true, Ordering::Release);
        }
        stop.store(true, Ordering::Release);
        assert!(!done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        worker.join().unwrap();
        assert_eq!(peer.used_bytes.load(Ordering::Acquire), bytes);
        assert_eq!(global.used_bytes.load(Ordering::Acquire), bytes);
        if superseded {
            assert!(terminal.lock().unwrap().is_none());
        } else {
            let failure = terminal.lock().unwrap();
            let failure = failure.as_ref().unwrap();
            assert_eq!(failure.remote, facts.remote);
            assert!(failure.reason.contains("decoded frame byte reservation"));
        }
        drop(held);
        assert_eq!(peer.used_bytes.load(Ordering::Acquire), 0);
        assert_eq!(global.used_bytes.load(Ordering::Acquire), 0);
    }
}

#[test]
fn shutdown_cannot_hide_real_tcp_nontransient_receive_error_v1() {
    // Authentic handshake, followed by a genuinely invalid signature. Pause
    // after receive returns to reproduce stop racing the worker's error arm.
    for superseded in [false, true] {
        let (mut sender, mut receiver) = shutdown_tcp_pair_v1();
        let (identity, _) = authenticated_identity_fixture_v0();
        let MeshIdentitySignerV1::Local(key) = identity.p2p_identity_signer else {
            unreachable!()
        };
        let frame = AuthenticatedFrame {
            sender: identity.local,
            session: sender.session_id(),
            sequence: 0,
            kind: FrameKind::Vote,
            payload: vec![0x91],
        };
        let mut body = frame.encode(TEST_RUN_ID, &key).unwrap();
        *body.last_mut().unwrap() ^= 1;
        sender
            .io_mut()
            .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
            .unwrap();
        sender.io_mut().write_all(&body).unwrap();
        let error = receiver.receive().unwrap_err();
        assert!(matches!(error, FrameError::InvalidSignature));
        let facts = PeerSessionFactsV0 {
            remote: receiver.remote(),
            direction: PeerDirectionV0::Inbound,
            session_id: receiver.session_id(),
            generation: 1,
        };
        let stop = AtomicBool::new(true);
        let cancel = AtomicBool::new(superseded);
        let terminal = Mutex::new(None);
        retain_nontransient_inbound_failure_v1(
            &terminal,
            &stop,
            &cancel,
            facts,
            "non-recoverable frame error",
            &error,
        );
        if superseded {
            assert!(terminal.lock().unwrap().is_none());
            continue;
        }
        let original = terminal.lock().unwrap().as_ref().unwrap().reason.clone();
        assert!(original.contains("signature"));
        retain_nontransient_inbound_failure_v1(
            &terminal,
            &stop,
            &cancel,
            facts,
            "inbound readiness probe failed",
            &FrameError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local probe failure",
            )),
        );
        assert_eq!(
            terminal.lock().unwrap().as_ref().unwrap().reason,
            original,
            "first failure cannot be replaced"
        );
    }
    let (sender, mut receiver) = shutdown_tcp_pair_v1();
    drop(sender);
    let error = receiver.receive().unwrap_err();
    assert!(transient_frame_error(&error));
    let facts = PeerSessionFactsV0 {
        remote: receiver.remote(),
        direction: PeerDirectionV0::Inbound,
        session_id: receiver.session_id(),
        generation: 1,
    };
    let terminal = Mutex::new(None);
    retain_nontransient_inbound_failure_v1(
        &terminal,
        &AtomicBool::new(true),
        &AtomicBool::new(false),
        facts,
        "read during shutdown",
        &error,
    );
    assert!(
        terminal.lock().unwrap().is_none(),
        "explicit TCP shutdown remains transient"
    );
}

#[test]
fn shutdown_child_join_preserves_owned_tcp_event_and_real_panic_v1() {
    for panic_child in [false, true] {
        let (mut sender, mut receiver) = shutdown_tcp_pair_v1();
        sender.send(FrameKind::Vote, vec![0x81]).unwrap();
        let frame = receiver.receive().unwrap();
        let facts = PeerSessionFactsV0 {
            remote: receiver.remote(),
            direction: PeerDirectionV0::Inbound,
            session_id: receiver.session_id(),
            generation: 1,
        };
        let bytes = frame.payload.len() + QUEUED_FRAME_OVERHEAD_BYTES;
        let peer = Arc::new(MeshQueueByteBudgetV0::new(bytes));
        let global = Arc::new(MeshQueueByteBudgetV0::new(bytes));
        let event = MeshIngressEventV0::Frame(MeshInboundFrameV0 {
            remote: facts.remote,
            direction: facts.direction,
            session_id: facts.session_id,
            session_generation: facts.generation,
            frame,
            _reservation: InboundQueueReservationV0::try_new(&peer, &global, bytes).unwrap(),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(Mutex::new(None));
        let (tx, rx) = mpsc::sync_channel(1);
        let child = thread::spawn({
            let stop = Arc::clone(&stop);
            let cancel = Arc::clone(&cancel);
            let terminal = Arc::clone(&terminal);
            move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                while !stop.load(Ordering::Acquire) && !cancel.load(Ordering::Acquire) {
                    assert!(Instant::now() < deadline, "join did not stop worker");
                    thread::sleep(Duration::from_millis(1));
                }
                assert!(!panic_child, "real worker panic racing global stop");
                emit_event(&tx, event, &terminal, &stop, facts, Some(&cancel)).unwrap();
            }
        });
        let mut children = BTreeMap::new();
        children.insert(
            facts.remote,
            InboundWorkerV0 {
                facts,
                cancel: Arc::clone(&cancel),
                handle: child,
            },
        );
        let controls = Arc::new(Mutex::new(BTreeMap::new()));
        join_children(children, &controls, &terminal, &stop);
        assert!(stop.load(Ordering::Acquire));
        assert!(
            !cancel.load(Ordering::Acquire),
            "global join must not impersonate supersession"
        );
        if panic_child {
            let failure = terminal.lock().unwrap();
            let failure = failure.as_ref().unwrap();
            assert_eq!(failure.remote, facts.remote);
            assert!(failure.reason.contains("worker panicked"));
        } else {
            assert!(terminal.lock().unwrap().is_none());
            let MeshIngressEventV0::Frame(inbound) =
                rx.recv_timeout(Duration::from_secs(1)).unwrap()
            else {
                panic!("missing owned frame");
            };
            assert_eq!(inbound.frame().payload, [0x81]);
            assert_eq!(inbound.session_id(), facts.session_id);
            drop(inbound);
        }
        assert_eq!(peer.used_bytes.load(Ordering::Acquire), 0);
        assert_eq!(global.used_bytes.load(Ordering::Acquire), 0);
    }
}

#[test]
fn shutdown_inbound_join_preserves_live_outbound_lease_until_its_worker_joins_v1() {
    // Authentic TCP session + actual external lease. The channel fixes the
    // observed LAN interleaving, without relying on a timer race or sleeping.
    let (sender, _receiver) = shutdown_tcp_pair_v1();
    let (identity, _) = authenticated_identity_fixture_v0();
    let remote = sender.remote();
    let context = PeerAdmissionContextV1::from_validator_set(&identity.validator_set);
    let fences = MeshFenceRegistryV1::new(
        Arc::new(TestExternalPeerLeaseAuthorityV1::new(context)),
        identity.local,
        context,
        MESH_EXTERNAL_FENCE_TTL_V1,
    )
    .unwrap();
    let original = fences
        .acquire(PeerDirectionV0::Outbound, remote, sender.session_id(), 1)
        .unwrap();
    let (go_tx, go_rx) = mpsc::channel();
    let worker = thread::spawn({
        let fences = fences.clone();
        move || {
            let _actual_session_owner = sender;
            go_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            // Identical validation to outgoing_loop's recv_timeout branch.
            fences.renew_if_due(PeerDirectionV0::Outbound, remote)
        }
    });
    let controls = Arc::new(Mutex::new(BTreeMap::new()));
    let terminal = Mutex::new(None);
    let stop = AtomicBool::new(false);
    join_children(BTreeMap::new(), &controls, &terminal, &stop);
    assert!(stop.load(Ordering::Acquire));
    go_tx.send(()).unwrap();
    let checked = worker.join().unwrap();
    checked.expect("inbound subtree must not release a live outbound lease");
    assert!(terminal.lock().unwrap().is_none());
    assert_eq!(
        fences.tokens.lock().unwrap()[&(PeerDirectionV0::Outbound, remote)]
            .token
            .scope(),
        original.scope(),
    );
    // This is the all-workers-joined boundary owned by close/failed setup.
    fences.release_all().unwrap();
    assert_eq!(fences.active_count().unwrap(), 0);
}

#[test]
fn shutdown_missing_outbound_lease_remains_internal_after_stop_v1() {
    let (sender, _receiver) = shutdown_tcp_pair_v1();
    let (identity, _) = authenticated_identity_fixture_v0();
    let remote = sender.remote();
    let context = PeerAdmissionContextV1::from_validator_set(&identity.validator_set);
    let fences = MeshFenceRegistryV1::new(
        Arc::new(TestExternalPeerLeaseAuthorityV1::new(context)),
        identity.local,
        context,
        MESH_EXTERNAL_FENCE_TTL_V1,
    )
    .unwrap();
    fences
        .acquire(PeerDirectionV0::Outbound, remote, sender.session_id(), 1)
        .unwrap();
    fences.release(PeerDirectionV0::Outbound, remote).unwrap();
    let stop = AtomicBool::new(true);
    let terminal = Mutex::new(None);
    let error = fences
        .renew_if_due(PeerDirectionV0::Outbound, remote)
        .expect_err("actual missing lease is never a successful stop");
    set_terminal(
        &terminal,
        &stop,
        MeshTerminalFailureV0 {
            remote,
            direction: PeerDirectionV0::Outbound,
            reason: format!("idle external fence revalidation failed: {error}"),
        },
    );
    let failure = terminal.lock().unwrap();
    let failure = failure.as_ref().unwrap();
    assert_eq!(failure.remote, remote);
    assert!(failure.reason.contains("no admitted external lease"));
}
