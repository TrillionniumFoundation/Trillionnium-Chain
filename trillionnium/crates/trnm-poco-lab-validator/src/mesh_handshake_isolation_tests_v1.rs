// Included inside consensus_mesh::tests: actual TCP accept loop and signed
// transport, with a deliberately test-only external lease authority.
struct HandshakeReceiverV1 {
    address: SocketAddr,
    client: MeshIdentityV0,
    server: MeshIdentityV0,
    setup: Receiver<SetupEventV0>,
    ingress: Receiver<MeshIngressEventV0>,
    stop: Arc<AtomicBool>,
    terminal: Arc<Mutex<Option<MeshTerminalFailureV0>>>,
    controls: ActiveControlsV0,
    fences: MeshFenceRegistryV1,
    worker: Option<JoinHandle<()>>,
}
impl HandshakeReceiverV1 {
    fn start() -> Self {
        let (client, server) = authenticated_identity_fixture_v0();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let expected = BTreeMap::from([(client.local, "127.0.0.1:1".parse().unwrap())]);
        let context = PeerAdmissionContextV1::from_validator_set(&server.validator_set);
        let fences = MeshFenceRegistryV1::new(
            Arc::new(TestExternalPeerLeaseAuthorityV1::new(context)),
            server.local,
            context,
            Duration::from_secs(30),
        )
        .unwrap();
        let (setup_tx, setup) = mpsc::channel();
        let (ingress_tx, ingress) = mpsc::sync_channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(Mutex::new(None));
        let controls = Arc::new(Mutex::new(BTreeMap::new()));
        let worker = thread::spawn({
            let identity = server.clone();
            let stop = Arc::clone(&stop);
            let terminal = Arc::clone(&terminal);
            let controls = Arc::clone(&controls);
            let fences = fences.clone();
            let budgets =
                BTreeMap::from([(client.local, Arc::new(MeshQueueByteBudgetV0::new(4096)))]);
            move || {
                accept_loop(
                    listener,
                    expected,
                    identity,
                    Instant::now() + Duration::from_secs(8),
                    Duration::from_millis(500),
                    setup_tx,
                    ingress_tx,
                    stop,
                    terminal,
                    controls,
                    fences,
                    budgets,
                    Arc::new(MeshQueueByteBudgetV0::new(4096)),
                )
            }
        });
        Self {
            address,
            client,
            server,
            setup,
            ingress,
            stop,
            terminal,
            controls,
            fences,
            worker: Some(worker),
        }
    }
    fn rejected_bytes(&self, bytes: &[u8]) {
        let mut socket = TcpStream::connect(self.address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut length = [0; 2];
        socket.read_exact(&mut length).unwrap();
        let length = usize::from(u16::from_be_bytes(length));
        assert!((1..=512).contains(&length));
        let mut challenge = vec![0; length];
        socket.read_exact(&mut challenge).unwrap();
        socket.write_all(bytes).unwrap();
        let mut result = [0; 1];
        match socket.read(&mut result) {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("rejected connection must close, not time out or respond: {other:?}"),
        }
    }
    fn connect_valid(&self) -> AuthenticatedConnection<DeadlineIo> {
        let socket = TcpStream::connect(self.address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let io = DeadlineIo::new(socket, deadline).unwrap();
        let key = match &self.client.p2p_identity_signer {
            MeshIdentitySignerV1::Local(key) => key,
            _ => unreachable!(),
        };
        AuthenticatedConnection::connect(
            io,
            &self.client.run_id,
            self.client.local,
            self.server.local,
            key,
            &self.client.validator_set,
            &self.client.key_roles,
            self.client.transport_context,
        )
        .unwrap()
    }
    fn assert_healthy(&self) {
        assert!(
            !self.stop.load(Ordering::Acquire),
            "rejected peer input stopped the entire mesh"
        );
        assert!(self.terminal.lock().unwrap().is_none());
    }
    fn ready(&self) -> PeerSessionFactsV0 {
        match self.setup.recv_timeout(Duration::from_secs(3)).unwrap() {
            SetupEventV0::Ready(facts) => facts,
            SetupEventV0::Failed(reason) => panic!("unexpected setup failure: {reason}"),
        }
    }
    fn next_frame(&self) -> MeshInboundFrameV0 {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match self
                .ingress
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap()
            {
                MeshIngressEventV0::Frame(frame) => return frame,
                MeshIngressEventV0::SessionReestablished(_) => {}
                other => panic!("unexpected session event: {other:?}"),
            }
        }
    }
}
impl Drop for HandshakeReceiverV1 {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        shutdown_all(&self.controls);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn malformed_handshake_cannot_stop_receiver_or_mint_a_lease() {
    let receiver = HandshakeReceiverV1::start();
    for bytes in [&[0, 0][..], &[2, 1][..], &[0, 1, 0][..]] {
        receiver.rejected_bytes(bytes);
        receiver.assert_healthy();
        assert!(receiver.fences.tokens.lock().unwrap().is_empty());
        assert!(receiver.controls.lock().unwrap().is_empty());
        assert!(matches!(
            receiver.ingress.try_recv(),
            Err(TryRecvError::Empty)
        ));
        assert!(matches!(
            receiver.setup.try_recv(),
            Err(TryRecvError::Empty)
        ));
    }
    let mut connection = receiver.connect_valid();
    let ready = receiver.ready();
    assert_eq!(
        ready.generation(),
        1,
        "bad handshakes consumed an authenticated generation"
    );
    connection
        .send(FrameKind::Vote, b"first signed payload".to_vec())
        .unwrap();
    let frame = receiver.next_frame();
    assert_eq!(frame.frame.sequence, 0);
    assert_eq!(frame.frame.payload, b"first signed payload");
    receiver.assert_healthy();
}

#[test]
fn malformed_new_connection_preserves_existing_authenticated_stream() {
    let receiver = HandshakeReceiverV1::start();
    let mut connection = receiver.connect_valid();
    let ready = receiver.ready();
    connection.send(FrameKind::Vote, vec![1]).unwrap();
    let first = receiver.next_frame();
    let session = first.session_id;
    drop(first);
    for _ in 0..4 {
        receiver.rejected_bytes(&[0, 1, 0]);
    }
    receiver.assert_healthy();
    connection.send(FrameKind::TimeoutVote, vec![2]).unwrap();
    let second = receiver.next_frame();
    assert_eq!(second.session_id, session);
    assert_eq!(second.session_generation, ready.generation());
    assert_eq!(second.frame.sequence, 1);
    assert_eq!(second.frame.payload, vec![2]);
    assert_eq!(receiver.fences.tokens.lock().unwrap().len(), 1);
    receiver.assert_healthy();
}

#[test]
fn handshake_error_provenance_does_not_hide_local_failures() {
    use crate::transport::InboundHandshakeFailureV1;
    for error in [
        FrameError::Malformed("local entropy/configuration"),
        FrameError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "local custody timeout",
        )),
        FrameError::Io(io::Error::new(
            io::ErrorKind::WouldBlock,
            "local entropy unavailable",
        )),
        FrameError::UnknownSender,
        FrameError::InvalidSignature,
        FrameError::Replay,
        FrameError::Poisoned,
        FrameError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local policy",
        )),
    ] {
        assert!(matches!(
            classify_incoming_auth_failure_v0(InboundHandshakeFailureV1::Local(error)),
            IncomingAuthFailureV0::Terminal(_)
        ));
    }
    for error in [
        FrameError::Malformed("received bytes"),
        FrameError::TooLarge,
        FrameError::WrongRun,
        FrameError::UnknownSender,
        FrameError::InvalidSignature,
        FrameError::Replay,
    ] {
        assert!(matches!(
            classify_incoming_auth_failure_v0(InboundHandshakeFailureV1::Peer(error)),
            IncomingAuthFailureV0::PeerRejected
        ));
    }
    // An unknown disposition is not a permissive connection rejection.
    assert!(matches!(
        classify_incoming_auth_failure_v0(InboundHandshakeFailureV1::Peer(FrameError::Poisoned)),
        IncomingAuthFailureV0::Terminal(_)
    ));
}

#[test]
fn invalid_local_handshake_key_is_terminal_not_a_peer_rejection() {
    let (_client, server) = authenticated_identity_fixture_v0();
    // A wrong commissioned local key fails before any read or accepted peer.
    let error = AuthenticatedConnection::accept_scoped_v1(
        std::io::Cursor::new(Vec::<u8>::new()),
        &server.run_id,
        server.local,
        &SigningKey::from_bytes(&[0x7a; 32]),
        &server.validator_set,
        &server.key_roles,
        server.transport_context,
    )
    .err()
    .expect("wrong local key");
    assert!(matches!(
        classify_incoming_auth_failure_v0(error),
        IncomingAuthFailureV0::Terminal(_)
    ));
}

#[test]
fn real_signed_tcp_stream_yields_to_timer_without_discarding_queue() {
    use crate::{
        consensus_runtime::{drain_ingress_turn_v1, MAX_INGRESS_EVENTS_PER_TURN_V1},
        pacemaker::GenerationAwarePacemakerV0,
    };
    use trnm_consensus_types::View;
    let receiver = HandshakeReceiverV1::start();
    let mut connection = receiver.connect_valid();
    receiver.ready();
    // Payloads are transport probes, not consensus validity or business TPS.
    let writer = thread::spawn(move || {
        for i in 0..MAX_INGRESS_EVENTS_PER_TURN_V1 + 4 {
            connection
                .send(FrameKind::Vote, (i as u64).to_be_bytes().to_vec())
                .unwrap();
        }
        connection
    });
    let now = Instant::now();
    let mut timer =
        GenerationAwarePacemakerV0::new(Duration::from_millis(100), Duration::from_secs(30))
            .unwrap();
    timer.arm(Epoch::new(0), View::new(1), now).unwrap();
    let mut calls = 0;
    let mut sequence = 0;
    drain_ingress_turn_v1(|| {
        calls += 1;
        let event = receiver
            .ingress
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        match event {
            MeshIngressEventV0::Frame(frame) => {
                assert_eq!(frame.frame.sequence, sequence);
                assert_eq!(frame.frame.payload, sequence.to_be_bytes());
                sequence += 1;
            }
            MeshIngressEventV0::SessionReestablished(_) => {}
            other => panic!("unexpected event: {other:?}"),
        }
        Ok(Some(true))
    })
    .unwrap();
    assert_eq!(calls, MAX_INGRESS_EVENTS_PER_TURN_V1);
    assert!(timer.poll(now + Duration::from_millis(100)).is_some());
    let _connection = writer.join().unwrap();
    let retained = receiver.next_frame();
    assert_eq!(retained.frame.sequence, sequence);
    receiver.assert_healthy();
}
