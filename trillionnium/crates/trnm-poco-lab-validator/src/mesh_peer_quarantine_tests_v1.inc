// Three real P2P identities, four established TCP directions and the production
// mesh worker/lease paths. Test authority is explicitly process-local.
fn quarantine_identities_v1() -> Vec<MeshIdentityV0> {
    let keys = (0..3)
        .map(|i| SigningKey::from_bytes(&[0x61 + i; 32]))
        .collect::<Vec<_>>();
    let consensus = (0..3)
        .map(|i| SigningKey::from_bytes(&[0x31 + i; 32]))
        .collect::<Vec<_>>();
    let operators = (0..3)
        .map(|i| SigningKey::from_bytes(&[0x41 + i; 32]))
        .collect::<Vec<_>>();
    let ids = (0..3)
        .map(|i| ValidatorId::new([0x71 + i; 32]))
        .collect::<Vec<_>>();
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let set = ValidatorSet::new(
        GenesisHash::new([0x73; 32]),
        ChainId::new("trnm-poco-g3-quarantine-test").unwrap(),
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
                crate::key_roles::ValidatorKeyRoleBindingV1::new(
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
    ids.into_iter()
        .enumerate()
        .map(|(i, id)| MeshIdentityV0 {
            run_id: TEST_RUN_ID.to_owned(),
            local: id,
            p2p_identity_signer: MeshIdentitySignerV1::Local(keys[i].clone()),
            validator_set: set.clone(),
            key_roles: roles.clone(),
            transport_context: RunTransportContext::new(
                [0x74; 32], [0x75; 32], [0x76; 32], [0x77; 32],
            ),
            host_attestation: None,
        })
        .collect()
}

fn quarantine_connect_v1(
    identity: &MeshIdentityV0,
    remote: ValidatorId,
    address: SocketAddr,
) -> AuthenticatedConnection<DeadlineIo> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let stream = loop {
        match TcpStream::connect_timeout(&address, Duration::from_secs(1)) {
            Ok(stream) => break stream,
            Err(error)
                if error.kind() == io::ErrorKind::ConnectionRefused
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2))
            }
            Err(error) => panic!("connect fixture peer: {error}"),
        }
    };
    let MeshIdentitySignerV1::Local(key) = &identity.p2p_identity_signer else {
        unreachable!()
    };
    AuthenticatedConnection::connect(
        DeadlineIo::new(stream, deadline).unwrap(),
        &identity.run_id,
        identity.local,
        remote,
        key,
        &identity.validator_set,
        &identity.key_roles,
        identity.transport_context,
    )
    .unwrap()
}

struct QuarantineTcpFixtureV1 {
    mesh: PersistentAuthenticatedPeerMeshV0,
    remotes: Vec<(
        AuthenticatedConnection<DeadlineIo>,
        MeshAuthenticatedConnectionV1<DeadlineIo>,
    )>,
    identities: Vec<MeshIdentityV0>,
    address: SocketAddr,
}

fn quarantine_mesh_fixture_v1(release_fault: u8) -> QuarantineTcpFixtureV1 {
    let mut identities = quarantine_identities_v1();
    if release_fault == 2 {
        identities[0].host_attestation = Some(MeshHostAttestationConfigV1 {
            authority: Arc::new(FailOnceHostReleaseAuthorityV1::new()),
            material: HostAttestationMaterialV1::from_bytes(vec![0x91, 0x92]).unwrap(),
        });
    }
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserve.local_addr().unwrap();
    drop(reserve);
    let listeners = (0..2)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let plan = identities[1..]
        .iter()
        .zip(&listeners)
        .map(|(id, listener)| (id.local, listener.local_addr().unwrap()))
        .collect::<BTreeMap<_, _>>();
    let workers = listeners
        .into_iter()
        .enumerate()
        .map(|(i, listener)| {
            let remote = identities[i + 1].clone();
            let local = identities[0].local;
            thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                let (stream, source) = loop {
                    match listener.accept() {
                        Ok(pair) => break pair,
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("fixture accept deadline/error: {error}"),
                    }
                };
                let incoming = authenticate_incoming(
                    stream,
                    source,
                    &BTreeMap::from([(local, address)]),
                    &remote,
                    Instant::now() + Duration::from_secs(5),
                    Duration::from_secs(2),
                )
                .unwrap();
                let outgoing = quarantine_connect_v1(&remote, local, address);
                (outgoing, incoming)
            })
        })
        .collect::<Vec<_>>();
    let context = PeerAdmissionContextV1::from_validator_set(&identities[0].validator_set);
    let backing = Arc::new(TestExternalPeerLeaseAuthorityV1::new(context));
    let authority: Arc<dyn ExternalPeerLeaseAuthorityV1> = if release_fault == 1 {
        Arc::new(FailOnceReleaseAuthorityV1::new(backing))
    } else {
        backing
    };
    let mesh = PersistentAuthenticatedPeerMeshV0::establish_identity_with_fence_ttl_v1(
        identities[0].clone(),
        address,
        plan.clone(),
        plan,
        Duration::from_secs(5),
        Duration::from_secs(2),
        64,
        MESH_EXTERNAL_FENCE_TTL_V1,
        authority,
    )
    .unwrap();
    let remotes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(mesh.fences.active_count().unwrap(), 4);
    QuarantineTcpFixtureV1 {
        mesh,
        remotes,
        identities,
        address,
    }
}

fn quarantine_attack_v1(fixture: &mut QuarantineTcpFixtureV1, foreign_sender: bool, sequence: u64) {
    let sender = &mut fixture.remotes[0].0;
    let identity = &fixture.identities[if foreign_sender { 2 } else { 1 }];
    let frame = AuthenticatedFrame {
        sender: identity.local,
        session: sender.session_id(),
        sequence,
        kind: FrameKind::Vote,
        payload: vec![0xa1],
    };
    let MeshIdentitySignerV1::Local(key) = &identity.p2p_identity_signer else {
        unreachable!()
    };
    let mut bytes = frame.encode(&identity.run_id, key).unwrap();
    if !foreign_sender {
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
    }
    sender
        .io_mut()
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    sender.io_mut().write_all(&bytes).unwrap();
    sender.io_mut().flush().unwrap();
}

fn await_quarantine_v1(
    mesh: &PersistentAuthenticatedPeerMeshV0,
    remote: ValidatorId,
    cleaned: bool,
) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if mesh
            .fences
            .quarantine
            .lock()
            .unwrap()
            .records
            .get(&remote)
            .is_some_and(|record| !cleaned || record.cleaned)
        {
            return;
        }
        mesh.ensure_healthy().unwrap();
        assert!(Instant::now() < deadline, "quarantine did not finish");
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn quarantine_real_tcp_bad_b_preserves_bidirectional_c_and_refuses_reconnect_v1() {
    for foreign_sender in [false, true] {
        let mut fixture = quarantine_mesh_fixture_v1(0);
        let bad = fixture.identities[1].local;
        let good = fixture.identities[2].local;
        let local = &fixture.identities[0];
        let namespace = PayloadReplayNamespaceV1::new(
            local.local.as_bytes().try_into().unwrap(),
            local.validator_set.epoch().get(),
            local.validator_set.id().into_bytes(),
            payload_replay_run_id_hash_v1(&local.run_id),
            network_context_digest_v1(
                &local.validator_set,
                &local.key_roles,
                local.transport_context,
            ),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let replay = Mutex::new(
            PayloadReplayStoreV1::open(directory.path().join("frames.wal"), namespace).unwrap(),
        );
        let source = fixture
            .mesh
            .initial_sessions
            .iter()
            .find(|facts| facts.remote == bad && facts.direction == PeerDirectionV0::Inbound)
            .copied()
            .unwrap();
        fixture.remotes[0]
            .0
            .send(FrameKind::Vote, vec![0xa0])
            .unwrap();
        quarantine_attack_v1(&mut fixture, foreign_sender, 1);
        await_quarantine_v1(&fixture.mesh, bad, true);
        fixture.mesh.ensure_healthy().unwrap();
        // The valid B frame precedes the bad frame in the original TCP stream,
        // so the receive worker necessarily queued it before quarantine.
        assert!(fixture
            .mesh
            .receive_timeout_with_payload_replay_v1(Duration::from_millis(20), &replay, TEST_RUN_ID)
            .unwrap()
            .is_none());
        {
            let state = fixture.mesh.fences.quarantine.lock().unwrap();
            assert_eq!(state.records[&bad].canceled_ingress_frames, 1);
            assert_eq!(state.records[&bad].canceled_ingress_bytes, 1);
        }
        assert_eq!(replay.lock().unwrap().accepted_frame_count(), 0);
        assert!(!fixture.mesh.stop.load(Ordering::Acquire));
        assert_eq!(fixture.mesh.fences.active_count().unwrap(), 2);
        let original = fixture.mesh.fences.quarantine.lock().unwrap().records[&bad].clone();
        assert_eq!(original.source, source);
        assert_eq!(
            original.reason,
            if foreign_sender {
                crate::transport::EstablishedPeerInputRejectionV1::SessionSequenceMismatch
            } else {
                crate::transport::EstablishedPeerInputRejectionV1::InvalidSignature
            }
        );
        assert!(!fixture.mesh.fences.peer_quarantined_v1(good).unwrap());
        assert_eq!(
            fixture.mesh.send_to(bad, FrameKind::Vote, vec![1]).unwrap(),
            MeshSendDispositionV0::Quarantined
        );
        for marker in [0xb1, 0xb2] {
            fixture.remotes[1]
                .0
                .send(FrameKind::Vote, vec![marker])
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                assert!(Instant::now() < deadline, "healthy C ingress stopped");
                match fixture
                    .mesh
                    .receive_timeout_with_payload_replay_v1(
                        Duration::from_millis(20),
                        &replay,
                        TEST_RUN_ID,
                    )
                    .unwrap()
                {
                    Some(MeshIngressEventV0::Frame(frame)) => {
                        assert_eq!(frame.remote(), good);
                        assert_eq!(frame.frame().payload, [marker]);
                        break;
                    }
                    _ => continue,
                }
            }
            assert_eq!(
                fixture
                    .mesh
                    .send_to(good, FrameKind::Vote, vec![marker])
                    .unwrap(),
                MeshSendDispositionV0::Queued
            );
            assert_eq!(fixture.remotes[1].1.receive().unwrap().payload, [marker]);
        }
        assert_eq!(replay.lock().unwrap().accepted_frame_count(), 2);
        assert!(fixture.mesh.fences.admission_lock.try_lock().is_ok());
        // Authentication completes, but this incarnation rejects the identity
        // before a generation, external lease or new receive worker is minted.
        let _reconnect = quarantine_connect_v1(
            &fixture.identities[1],
            fixture.identities[0].local,
            fixture.address,
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let state = fixture.mesh.fences.quarantine.lock().unwrap();
            let record = &state.records[&bad];
            assert_eq!(record.source, original.source);
            assert_eq!(record.pinned, original.pinned);
            if record.refused_reconnects > 0 {
                break;
            }
            drop(state);
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(fixture.mesh.fences.active_count().unwrap(), 2);
        assert_eq!(fixture.mesh.pending_outbound_bytes_v1().unwrap(), 0);
        // Even an over-permissive residual policy cannot turn quarantine into
        // CleanStop (including an earlier accepted terminal Park).
        let error = fixture
            .mesh
            .close_with_terminal_ingress_v1(|_| Ok(()))
            .unwrap_err();
        assert!(
            error.to_string().contains("quarantined peer forbids"),
            "{error}"
        );
    }
}

#[test]
fn quarantine_external_and_host_cleanup_failure_remain_global_fatal_v1() {
    for release_fault in [1, 2] {
        let mut fixture = quarantine_mesh_fixture_v1(release_fault);
        quarantine_attack_v1(&mut fixture, false, 0);
        let deadline = Instant::now() + Duration::from_secs(3);
        let error = loop {
            if let Err(error) = fixture.mesh.ensure_healthy() {
                break error;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        };
        assert!(
            error.to_string().contains(if release_fault == 2 {
                "host attestation release"
            } else {
                "release"
            }),
            "{error}"
        );
        assert!(fixture.mesh.stop.load(Ordering::Acquire));
        let fences = fixture.mesh.fences.clone();
        let close_error = fixture.mesh.close().unwrap_err();
        assert!(close_error.to_string().contains("release"), "{close_error}");
        assert_eq!(
            fences.active_count().unwrap(),
            0,
            "cleanup still attempted before returning first fault"
        );
    }
}

#[test]
fn quarantine_actual_ingress_and_cleanup_reject_foreign_generations_and_counter_overflow_v1() {
    let mut fixture = quarantine_mesh_fixture_v1(0);
    let bad = fixture.identities[1].local;
    fixture.remotes[0]
        .0
        .send(FrameKind::Vote, vec![0xa0])
        .unwrap();
    quarantine_attack_v1(&mut fixture, false, 1);
    await_quarantine_v1(&fixture.mesh, bad, true);
    let mut event = fixture
        .mesh
        .ingress
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    let original = fixture.mesh.fences.quarantine.lock().unwrap().records[&bad].clone();
    let MeshIngressEventV0::Frame(ref mut frame) = event else {
        panic!("original real TCP frame missing")
    };
    frame.session_generation = original.source.generation + 1;
    assert!(fixture
        .mesh
        .fences
        .cancel_quarantined_ingress_v1(&event)
        .is_err());
    let MeshIngressEventV0::Frame(ref mut frame) = event else {
        unreachable!()
    };
    frame.session_generation = original.source.generation;
    frame.session_id[0] ^= 1;
    assert!(fixture
        .mesh
        .fences
        .cancel_quarantined_ingress_v1(&event)
        .is_err());
    let MeshIngressEventV0::Frame(ref mut frame) = event else {
        unreachable!()
    };
    frame.session_id = original.source.session_id;
    for bytes_overflow in [false, true] {
        {
            let mut state = fixture.mesh.fences.quarantine.lock().unwrap();
            let record = state.records.get_mut(&bad).unwrap();
            record.canceled_ingress_frames = if bytes_overflow { 0 } else { u64::MAX };
            record.canceled_ingress_bytes = if bytes_overflow { u64::MAX } else { 0 };
        }
        assert!(fixture
            .mesh
            .fences
            .cancel_quarantined_ingress_v1(&event)
            .is_err());
        let mut state = fixture.mesh.fences.quarantine.lock().unwrap();
        let record = state.records.get_mut(&bad).unwrap();
        assert_eq!(
            record.canceled_ingress_frames,
            if bytes_overflow { 0 } else { u64::MAX }
        );
        assert_eq!(
            record.canceled_ingress_bytes,
            if bytes_overflow { u64::MAX } else { 0 }
        );
        record.canceled_ingress_frames = 0;
        record.canceled_ingress_bytes = 0;
    }
    assert!(fixture
        .mesh
        .fences
        .cancel_quarantined_ingress_v1(&event)
        .unwrap());
    drop(event);
    fixture
        .mesh
        .fences
        .quarantine
        .lock()
        .unwrap()
        .records
        .get_mut(&bad)
        .unwrap()
        .refused_reconnects = u64::MAX;
    assert!(fixture
        .mesh
        .fences
        .refuse_quarantined_reconnect_v1(bad)
        .is_err());
    assert_eq!(
        fixture.mesh.fences.quarantine.lock().unwrap().records[&bad].refused_reconnects,
        u64::MAX
    );
    let mut foreign = original.source;
    foreign.generation += 1;
    let (sender, _receiver) = mpsc::sync_channel(4);
    assert!(fixture
        .mesh
        .fences
        .retire_quarantined_peer_v1(
            foreign,
            &mut BTreeMap::new(),
            &fixture.mesh.controls,
            &sender,
            &fixture.mesh.terminal,
            &fixture.mesh.stop
        )
        .is_err());
    assert_eq!(fixture.mesh.fences.active_count().unwrap(), 2);
    assert_eq!(
        fixture.mesh.fences.quarantine.lock().unwrap().records[&bad].source,
        original.source
    );
    assert!(fixture.mesh.close_if_ingress_empty_v1().is_err());
}

#[test]
fn quarantine_worker_panic_and_poison_join_all_owned_workers_and_stay_fatal_v1() {
    for poison_registry in [false, true] {
        let identities = quarantine_identities_v1();
        let local = identities[0].local;
        let bad = identities[1].local;
        let good = identities[2].local;
        let context = PeerAdmissionContextV1::from_validator_set(&identities[0].validator_set);
        let fences = MeshFenceRegistryV1::new(
            Arc::new(TestExternalPeerLeaseAuthorityV1::new(context)),
            local,
            context,
            MESH_EXTERNAL_FENCE_TTL_V1,
        )
        .unwrap();
        fences
            .configure_peer_quarantine_v1(BTreeSet::from([bad, good]), BTreeSet::from([bad, good]))
            .unwrap();
        let (go_tx, go_rx) = mpsc::channel();
        let state = Arc::clone(&fences.quarantine);
        let mut bad_worker = Some(thread::spawn(move || {
            go_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            if poison_registry {
                let _guard = state.lock().unwrap();
                panic!("actual poisoned registry worker");
            }
            panic!("actual outbound worker panic");
        }));
        fences
            .register_outgoing_worker_v1(bad, &mut bad_worker)
            .unwrap();
        assert!(bad_worker.is_none());
        let completed = Arc::new(AtomicBool::new(false));
        let finished = Arc::clone(&completed);
        let mut good_worker = Some(thread::spawn(move || {
            finished.store(true, Ordering::Release);
        }));
        fences
            .register_outgoing_worker_v1(good, &mut good_worker)
            .unwrap();
        go_tx.send(()).unwrap();
        if poison_registry {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !fences.quarantine.is_poisoned() {
                assert!(Instant::now() < deadline);
                thread::yield_now();
            }
        }
        assert!(fences.join_outgoing_workers_v1().is_err());
        assert!(completed.load(Ordering::Acquire));
        let owned = match fences.quarantine.lock() {
            Ok(state) => state,
            Err(error) => error.into_inner(),
        };
        assert!(
            owned.outgoing_workers.is_empty(),
            "no detached unjoined survivor"
        );
    }
}

#[test]
fn quarantine_completed_tcp_rejection_survives_supersession_cancel_v1() {
    for mode in 0..4 {
        let global_stop = mode == 1;
        let (mut sender, mut receiver) = shutdown_tcp_pair_v1();
        let (client, server) = authenticated_identity_fixture_v0();
        let frame = AuthenticatedFrame {
            sender: client.local,
            session: sender.session_id(),
            sequence: 0,
            kind: FrameKind::Vote,
            payload: vec![0x31],
        };
        let MeshIdentitySignerV1::Local(key) = &client.p2p_identity_signer else {
            unreachable!()
        };
        let mut bytes = frame.encode(TEST_RUN_ID, key).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        sender
            .io_mut()
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        sender.io_mut().write_all(&bytes).unwrap();
        sender.io_mut().flush().unwrap();
        let error = receiver.receive_classified_v1().unwrap_err();
        assert_eq!(
            error.class_v1(),
            crate::transport::EstablishedReceiveClassV1::PeerInput(
                crate::transport::EstablishedPeerInputRejectionV1::InvalidSignature
            )
        );
        let facts = PeerSessionFactsV0 {
            remote: client.local,
            direction: PeerDirectionV0::Inbound,
            session_id: receiver.session_id(),
            generation: 1,
        };
        let context = PeerAdmissionContextV1::from_validator_set(&server.validator_set);
        let fences = MeshFenceRegistryV1::new(
            Arc::new(TestExternalPeerLeaseAuthorityV1::new(context)),
            server.local,
            context,
            MESH_EXTERNAL_FENCE_TTL_V1,
        )
        .unwrap();
        fences
            .configure_peer_quarantine_v1(BTreeSet::from([client.local]), BTreeSet::new())
            .unwrap();
        fences
            .acquire(PeerDirectionV0::Inbound, client.local, facts.session_id, 1)
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(Mutex::new(None));
        let (go_tx, go_rx) = mpsc::channel();
        let (lifecycle_tx, lifecycle_rx) = mpsc::sync_channel(2);
        if mode == 2 {
            lifecycle_tx
                .try_send(InboundLifecycleV0::TransientLoss(facts))
                .unwrap();
            lifecycle_tx
                .try_send(InboundLifecycleV0::TransientLoss(facts))
                .unwrap();
        }
        let lifecycle_rx = if mode == 3 {
            drop(lifecycle_rx);
            None
        } else {
            Some(lifecycle_rx)
        };
        let worker = thread::spawn({
            let fences = fences.clone();
            let stop = Arc::clone(&stop);
            let cancel = Arc::clone(&cancel);
            let terminal = Arc::clone(&terminal);
            move || {
                let _original_receive_owner = receiver;
                go_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(
                    cancel.load(Ordering::Acquire),
                    "supersession must already be requested"
                );
                handle_completed_peer_rejection_v1(
                    &fences,
                    facts,
                    &error,
                    &lifecycle_tx,
                    &terminal,
                    &stop,
                );
            }
        });
        // Classification is already complete; only now does a new handshake
        // ask to supersede the old receive worker, before any old lease release.
        cancel.store(true, Ordering::Release);
        stop.store(global_stop, Ordering::Release);
        go_tx.send(()).unwrap();
        worker.join().unwrap();
        if mode != 0 {
            let failure = terminal.lock().unwrap();
            let failure = failure.as_ref().unwrap();
            assert!(failure.reason.contains(if global_stop {
                "completed peer input rejection"
            } else {
                "quarantine lifecycle"
            }));
            assert_eq!(failure.remote, client.local);
            assert_eq!(
                fences.quarantine.lock().unwrap().records.is_empty(),
                global_stop
            );
            fences.release_all().unwrap();
        } else {
            assert!(terminal.lock().unwrap().is_none());
            assert!(
                matches!(lifecycle_rx.unwrap().recv_timeout(Duration::from_secs(1)).unwrap(),
                InboundLifecycleV0::PeerRejected(observed) if observed==facts)
            );
            let (ingress, _events) = mpsc::sync_channel(2);
            fences
                .finish_joined_quarantine_v1(
                    facts,
                    &Arc::new(Mutex::new(BTreeMap::new())),
                    &ingress,
                    &terminal,
                    &stop,
                )
                .unwrap();
            assert!(fences
                .acquire_or_quarantined_v1(PeerDirectionV0::Inbound, client.local, [0x99; 32], 2)
                .unwrap()
                .is_none());
            assert_eq!(fences.active_count().unwrap(), 0);
            let state = fences.quarantine.lock().unwrap();
            assert_eq!(state.records[&client.local].source, facts);
            assert!(state.records[&client.local].cleaned);
        }
    }
}

#[test]
fn quarantine_completed_internal_classification_cannot_be_erased_by_cancel_v1() {
    let (mut sender, mut receiver) = shutdown_tcp_pair_v1();
    sender.io_mut().write_all(&0u32.to_be_bytes()).unwrap();
    sender.io_mut().flush().unwrap();
    assert!(matches!(
        receiver.receive_classified_v1().unwrap_err().class_v1(),
        crate::transport::EstablishedReceiveClassV1::PeerInput(_)
    ));
    // The actual poisoned receive owner refuses another operation before I/O.
    let error = receiver.receive_classified_v1().unwrap_err();
    assert_eq!(
        error.class_v1(),
        crate::transport::EstablishedReceiveClassV1::Internal
    );
    assert!(matches!(error.frame_error_v1(), FrameError::Poisoned));
    let source = PeerSessionFactsV0 {
        remote: receiver.remote(),
        direction: PeerDirectionV0::Inbound,
        session_id: receiver.session_id(),
        generation: 1,
    };
    let terminal = Mutex::new(None);
    let stop = AtomicBool::new(true);
    let cancel = AtomicBool::new(true);
    retain_classified_inbound_failure_v1(&terminal, &stop, &cancel, source, &error);
    let first = terminal.lock().unwrap().as_ref().unwrap().clone();
    assert_eq!(first.remote, source.remote);
    assert_eq!(first.direction, source.direction);
    assert!(first
        .reason
        .contains("internal established receive failure"));
    assert!(first.reason.contains(&error.frame_error_v1().to_string()));
    retain_classified_inbound_failure_v1(&terminal, &stop, &cancel, source, &error);
    assert_eq!(
        terminal.lock().unwrap().as_ref().unwrap().reason,
        first.reason
    );
}
