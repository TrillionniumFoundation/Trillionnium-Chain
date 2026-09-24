const CLASSIFIED_RUN_V1: &str = "poco-g3-7-20260813T000000Z-1234abcd";

fn classified_three_peer_fixture_v1() -> (
    Vec<SigningKey>,
    Vec<ValidatorId>,
    ValidatorSet,
    ValidatorKeyRoleRegistryV1,
) {
    let keys = (0x61..=0x63)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    let consensus = (0x31..=0x33)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    let operators = (0x41..=0x43)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    let ids = (0x71..=0x73)
        .map(|n| ValidatorId::new([n; 32]))
        .collect::<Vec<_>>();
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let set = ValidatorSet::new(
        GenesisHash::new([0x75; 32]),
        ChainId::new("trnm-poco-g3-transport-test").unwrap(),
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        ids.iter()
            .enumerate()
            .map(|(i, id)| {
                Validator::new(
                    *id,
                    ConsensusPublicKey::new(consensus[i].verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    let roles = ValidatorKeyRoleRegistryV1::new(
        &set,
        ids.iter()
            .enumerate()
            .map(|(i, id)| {
                ValidatorKeyRoleBindingV1::new(
                    *id,
                    consensus[i].verifying_key().to_bytes(),
                    keys[i].verifying_key().to_bytes(),
                    operators[i].verifying_key().to_bytes(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    (keys, ids, set, roles)
}

fn classified_tcp_deadline_v1(stream: &TcpStream) {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
}

#[derive(Clone, Copy, Debug)]
enum ClassifiedTcpAttackV1 {
    Signature,
    Session,
    Sequence,
    Replay,
    Sender,
    Run,
    Unknown,
    Malformed,
    TooLarge,
    Eof,
}

fn classified_tcp_attack_class_v1(attack: ClassifiedTcpAttackV1) -> EstablishedReceiveClassV1 {
    use EstablishedPeerInputRejectionV1 as Reason;
    EstablishedReceiveClassV1::PeerInput(match attack {
        ClassifiedTcpAttackV1::Signature => Reason::InvalidSignature,
        ClassifiedTcpAttackV1::Session
        | ClassifiedTcpAttackV1::Sequence
        | ClassifiedTcpAttackV1::Replay
        | ClassifiedTcpAttackV1::Sender => Reason::SessionSequenceMismatch,
        ClassifiedTcpAttackV1::Run => Reason::WrongRun,
        ClassifiedTcpAttackV1::Unknown => Reason::UnknownSender,
        ClassifiedTcpAttackV1::Malformed => Reason::Malformed,
        ClassifiedTcpAttackV1::TooLarge => Reason::TooLarge,
        ClassifiedTcpAttackV1::Eof => return EstablishedReceiveClassV1::TransportIo,
    })
}

#[test]
fn established_receive_classified_real_tcp_bad_peer_leaves_independent_peer_usable_v1() {
    // Transport-only proof: three genuine identities and two independent
    // handshakes/connections. This does not assert mesh quarantine is wired.
    for attack in [
        ClassifiedTcpAttackV1::Signature,
        ClassifiedTcpAttackV1::Session,
        ClassifiedTcpAttackV1::Sequence,
        ClassifiedTcpAttackV1::Replay,
        ClassifiedTcpAttackV1::Sender,
        ClassifiedTcpAttackV1::Run,
        ClassifiedTcpAttackV1::Unknown,
        ClassifiedTcpAttackV1::Malformed,
        ClassifiedTcpAttackV1::TooLarge,
        ClassifiedTcpAttackV1::Eof,
    ] {
        let (keys, ids, set, roles) = classified_three_peer_fixture_v1();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_keys = keys.clone();
        let server_ids = ids.clone();
        let server_set = set.clone();
        let server_roles = roles.clone();
        let server = thread::spawn(move || {
            let mut accepted = Vec::new();
            for expected in [server_ids[0], server_ids[2]] {
                let (stream, _) = listener.accept().unwrap();
                classified_tcp_deadline_v1(&stream);
                let connection = AuthenticatedConnection::accept(
                    stream,
                    CLASSIFIED_RUN_V1,
                    server_ids[1],
                    &server_keys[1],
                    &server_set,
                    &server_roles,
                    TEST_TRANSPORT_CONTEXT,
                )
                .unwrap();
                assert_eq!(connection.remote(), expected);
                accepted.push(connection);
            }
            let expected_session = accepted[0].session;
            let expected_sequence = if matches!(attack, ClassifiedTcpAttackV1::Replay) {
                assert_eq!(accepted[0].receive_classified_v1().unwrap().sequence, 0);
                1
            } else {
                0
            };
            let error = accepted[0].receive_classified_v1().unwrap_err();
            assert_eq!(
                error.class_v1(),
                classified_tcp_attack_class_v1(attack),
                "{attack:?}"
            );
            assert_eq!(
                error.session_v1(),
                expected_session,
                "use authenticated owner identity, never claimed sender"
            );
            assert_eq!(accepted[0].next_receive, expected_sequence);
            assert!(accepted[0].is_poisoned());
            if matches!(attack, ClassifiedTcpAttackV1::Eof) {
                assert!(
                    matches!(error.frame_error_v1(), FrameError::Io(e) if e.kind()==io::ErrorKind::UnexpectedEof)
                );
            }
            let original_text = error.frame_error_v1().to_string();
            assert_eq!(error.into_frame_error_v1().to_string(), original_text);
            let retry = accepted[0].receive_classified_v1().unwrap_err();
            assert_eq!(retry.class_v1(), EstablishedReceiveClassV1::Internal);
            assert!(matches!(retry.into_frame_error_v1(), FrameError::Poisoned));
            assert!(matches!(accepted[0].receive(), Err(FrameError::Poisoned)));
            let healthy = accepted[1].receive_classified_v1().unwrap();
            assert_eq!(healthy.sender, server_ids[2]);
            assert_eq!(healthy.payload, b"independent-valid-frame");
            assert_eq!(accepted[1].next_receive, 1);
            assert!(!accepted[1].is_poisoned());
            accepted[1]
                .send(FrameKind::Health, b"ack-of-frame-only".to_vec())
                .unwrap();
        });
        let stream = TcpStream::connect(address).unwrap();
        classified_tcp_deadline_v1(&stream);
        let mut bad = AuthenticatedConnection::connect(
            stream,crate::transport::ConnectionPeerV1 { run_id: CLASSIFIED_RUN_V1, local: ids[0], expected_remote: ids[1] },
            &keys[0],
            &set,
            &roles,
            TEST_TRANSPORT_CONTEXT,
        )
        .unwrap();
        let stream = TcpStream::connect(address).unwrap();
        classified_tcp_deadline_v1(&stream);
        let mut good = AuthenticatedConnection::connect(
            stream,crate::transport::ConnectionPeerV1 { run_id: CLASSIFIED_RUN_V1, local: ids[2], expected_remote: ids[1] },
            &keys[2],
            &set,
            &roles,
            TEST_TRANSPORT_CONTEXT,
        )
        .unwrap();
        let mut frame = AuthenticatedFrame {
            sender: ids[0],
            session: bad.session_id(),
            sequence: 0,
            kind: FrameKind::Health,
            payload: b"untrusted-frame".to_vec(),
        };
        match attack {
            ClassifiedTcpAttackV1::Session => frame.session = [0xa1; 32],
            ClassifiedTcpAttackV1::Sequence => frame.sequence = 1,
            ClassifiedTcpAttackV1::Sender => frame.sender = ids[2],
            ClassifiedTcpAttackV1::Unknown => frame.sender = ValidatorId::new([0xf1; 32]),
            _ => {}
        }
        let key = if matches!(attack, ClassifiedTcpAttackV1::Sender) {
            &keys[2]
        } else {
            &keys[0]
        };
        let run = if matches!(attack, ClassifiedTcpAttackV1::Run) {
            "poco-g3-7-20260813T000000Z-5678abcd"
        } else {
            CLASSIFIED_RUN_V1
        };
        let mut bytes = frame.encode(run, key).unwrap();
        match attack {
            ClassifiedTcpAttackV1::Signature => {
                *bytes.last_mut().unwrap() ^= 1;
            }
            ClassifiedTcpAttackV1::Malformed => bytes[0] ^= 1,
            _ => {}
        }
        let mut send = Vec::new();
        match attack {
            ClassifiedTcpAttackV1::TooLarge => send.extend_from_slice(
                &u32::try_from(crate::frame::MAX_FRAME_BODY_BYTES + 1)
                    .unwrap()
                    .to_be_bytes(),
            ),
            ClassifiedTcpAttackV1::Eof => {
                send.extend_from_slice(&100_u32.to_be_bytes());
                send.extend_from_slice(&[1, 2]);
            }
            _ => {
                send.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
                send.extend_from_slice(&bytes);
            }
        }
        bad.io_mut().write_all(&send).unwrap();
        if matches!(attack, ClassifiedTcpAttackV1::Replay) {
            bad.io_mut().write_all(&send).unwrap();
        }
        if matches!(attack, ClassifiedTcpAttackV1::Eof) {
            bad.io_mut().shutdown(std::net::Shutdown::Write).unwrap();
        }
        good.send(FrameKind::Health, b"independent-valid-frame".to_vec())
            .unwrap();
        // Join first so a server assertion preserves its original diagnostic.
        server.join().unwrap();
        assert_eq!(
            good.receive_classified_v1().unwrap().payload,
            b"ack-of-frame-only"
        );
    }
}

#[test]
fn established_receive_classified_local_exhaustion_is_not_peer_replay_v1() {
    let (key, _, _, local, remote, _set, roles) = fixture();
    let mut connection =
        direct_connection(Cursor::new(vec![0, 0, 0, 0]), local, remote, key, roles);
    connection.next_receive = u64::MAX;
    let error = connection.receive_classified_v1().unwrap_err();
    assert_eq!(error.class_v1(), EstablishedReceiveClassV1::Internal);
    assert!(matches!(error.into_frame_error_v1(), FrameError::Replay));
    assert_eq!(
        connection.io.position(),
        0,
        "local exhaustion precedes all I/O"
    );
    assert_eq!(connection.next_receive, u64::MAX);
    assert!(connection.is_poisoned());
    assert_eq!(
        connection.receive_classified_v1().unwrap_err().class_v1(),
        EstablishedReceiveClassV1::Internal
    );
}

struct ClassifiedTrackedTcpV1 {
    stream: TcpStream,
    reads: Arc<std::sync::atomic::AtomicUsize>,
}
impl Read for ClassifiedTrackedTcpV1 {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.stream.read(out)
    }
}
impl Write for ClassifiedTrackedTcpV1 {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[test]
fn established_receive_classified_external_identity_separates_host_and_peer_failures_v1() {
    for mode in 0..3 {
        let (client_key, server_key, _, client, server, set, roles) = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_set = set.clone();
        let server_roles = roles.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_server = Arc::clone(&requests);
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            classified_tcp_deadline_v1(&stream);
            let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut connection = ExternallySignedAuthenticatedConnectionV1::accept(
                ClassifiedTrackedTcpV1 {
                    stream,
                    reads: Arc::clone(&reads),
                },
                CLASSIFIED_RUN_V1,
                server,
                Box::new(RecordingExternalIdentityProducerV1::new(
                    server_key,
                    Arc::clone(&requests_for_server),
                )),
                &server_set,
                &server_roles,
                TEST_TRANSPORT_CONTEXT,
            )
            .unwrap();
            if mode != 0 {
                let admission = host_admission(
                    server,
                    client,
                    ExternalPeerDirectionV1::Inbound,
                    server_roles.p2p_identity_public_key(server).unwrap(),
                    &server_set,
                    &server_roles,crate::transport::HostSessionFixtureV1 { run_id: CLASSIFIED_RUN_V1, context: TEST_TRANSPORT_CONTEXT, session_id: connection.session_id(), generation: 1, });
                connection
                    .mark_host_attestation_admitted(admission, ExternalPeerDirectionV1::Inbound, 1)
                    .unwrap();
            }
            if mode == 1 {
                connection.next_receive = u64::MAX;
            }
            let io_before = reads.load(std::sync::atomic::Ordering::SeqCst);
            let signatures_before = requests_for_server.lock().unwrap().len();
            let error = connection.receive_classified_v1().unwrap_err();
            assert_eq!(error.session_v1(), connection.session);
            match mode {
                0 => {
                    assert_eq!(error.class_v1(), EstablishedReceiveClassV1::Internal);
                    assert!(matches!(
                        error.frame_error_v1(),
                        FrameError::ExternalIdentity(_)
                    ));
                }
                1 => {
                    assert_eq!(error.class_v1(), EstablishedReceiveClassV1::Internal);
                    assert!(matches!(error.frame_error_v1(), FrameError::Replay));
                }
                2 => {
                    assert_eq!(
                        error.class_v1(),
                        EstablishedReceiveClassV1::PeerInput(
                            EstablishedPeerInputRejectionV1::InvalidSignature
                        )
                    );
                }
                _ => unreachable!(),
            }
            if mode < 2 {
                assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), io_before);
            }
            assert_eq!(
                requests_for_server.lock().unwrap().len(),
                signatures_before,
                "receive cannot call external signing"
            );
            assert!(connection.is_poisoned());
            let after_io = reads.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                connection.receive_classified_v1().unwrap_err().class_v1(),
                EstablishedReceiveClassV1::Internal
            );
            assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), after_io);
        });
        let stream = TcpStream::connect(address).unwrap();
        classified_tcp_deadline_v1(&stream);
        let mut connection = AuthenticatedConnection::connect(
            stream,crate::transport::ConnectionPeerV1 { run_id: CLASSIFIED_RUN_V1, local: client, expected_remote: server },
            &client_key,
            &set,
            &roles,
            TEST_TRANSPORT_CONTEXT,
        )
        .unwrap();
        if mode == 2 {
            let frame = AuthenticatedFrame {
                sender: client,
                session: connection.session_id(),
                sequence: 0,
                kind: FrameKind::Health,
                payload: vec![1],
            };
            let mut body = frame.encode(CLASSIFIED_RUN_V1, &client_key).unwrap();
            *body.last_mut().unwrap() ^= 1;
            connection
                .io_mut()
                .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
                .unwrap();
            connection.io_mut().write_all(&body).unwrap();
        }
        server_thread.join().unwrap();
    }
}
