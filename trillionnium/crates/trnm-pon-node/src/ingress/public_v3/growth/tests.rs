//! Actual signed TCP exchanges and real PGH2/PNP2 Native state transitions.
use super::*;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

fn settings(namespace: &str) -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap()
    .with_permanent_account_growth_v2(namespace)
    .unwrap()
}
fn identity(seed: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([seed; 32])).unwrap()
}
fn transfer(settings: &Settings) -> Vec<u8> {
    transfer_nonce(settings, 1)
}
fn transfer_nonce(settings: &Settings, nonce: u64) -> Vec<u8> {
    let mut payload = crate::development_public(91).unwrap().to_vec();
    payload.extend(1000u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: crate::development_public(0).unwrap(),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn make(node: &Node, parent: Hash, height: u64, txs: Vec<Vec<u8>>) -> GrowthPacket {
    node.make_growth_consensus_maintenance(
        parent,
        txs,
        crate::development_public(3).unwrap(),
        1 + height * 10,
        4096,
    )
    .unwrap()
}

#[test]
fn growth_paid_dispatch_charges_joined_preparation_workers_and_fences_unknown_cpu() {
    for workers in [2, 4, 8] {
        for missing_worker_clock in [false, true] {
            let settings = settings("growth-paid-parallel-preparation");
            let directory = tempfile::tempdir().unwrap();
            let node = Node::open_with_permanent_account_growth_v2_and_workers(
                directory.path(),
                settings.clone(),
                workers,
            )
            .unwrap();
            let transactions = (1..=8)
                .map(|nonce| transfer_nonce(&settings, nonce))
                .collect();
            let packet = make(&node, settings.genesis(), 1, transactions);
            let before = node.growth_current_working().unwrap();
            let node = Mutex::new(node);
            let server = PublicServer::new(
                identity(97),
                PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
            )
            .unwrap()
            .with_native_growth()
            .unwrap();
            let metrics = Mutex::new(PublicMetrics::default());
            let permit = PaidMutationCpuPermit::acquire(&server, &metrics).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let stop = Arc::new(AtomicBool::new(false));
            let cancelled = Arc::new(AtomicBool::new(false));
            permit
                .live
                .bind_public_request(deadline, stop.clone(), cancelled.clone())
                .unwrap();
            let measurement = MutationCpuMeasurement::for_permit(Some(&permit));
            measurement
                .workers
                .fail_next_finish
                .store(missing_worker_clock, Ordering::Release);
            let result = dispatch(
                &node,
                Request::GrowthSubmitV1 {
                    packet: hex::encode(packet.encode().unwrap()),
                },
                deadline,
                &stop,
                &cancelled,
                &metrics,
                None,
                Some(&measurement),
            );
            assert_eq!(
                measurement.workers.spawned.load(Ordering::Acquire),
                workers as u64
            );
            assert_eq!(
                measurement.workers.started.load(Ordering::Acquire),
                workers as u64
            );
            assert_eq!(
                measurement.workers.finished.load(Ordering::Acquire),
                workers as u64
            );
            if missing_worker_clock {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "PUBLIC_MUTATION_CPU_UNAVAILABLE"
                );
                assert!(measurement.workers.complete().is_none());
                let owner = node.lock().unwrap();
                assert_eq!(owner.active().unwrap(), (before.block, before.generation));
                assert_eq!(owner.growth_working(before.block).unwrap(), before.working);
            } else {
                assert_eq!(result.unwrap()["block"], hex::encode(packet.id().unwrap()));
                assert!(measurement.workers.complete().unwrap() > 0);
                assert_eq!(
                    node.lock().unwrap().active().unwrap().0,
                    packet.id().unwrap()
                );
            }
            let children = measurement.workers.complete();
            let outer = permit.finish(&measurement, &server, &metrics);
            let budget = server.mutation_cpu.lock().unwrap();
            assert_eq!(budget.in_flight, 0);
            assert_eq!(budget.unavailable, missing_worker_clock);
            if !missing_worker_clock {
                let observed = metrics.lock().unwrap();
                assert_eq!(
                    observed.mutation_cpu_charged_ns,
                    outer.unwrap() + children.unwrap()
                );
                assert_eq!(observed.mutation_cpu_clock_failures, 0);
            }
        }
    }
}

struct Running {
    directory: tempfile::TempDir,
    owner: Option<Arc<Mutex<Node>>>,
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    key: String,
    policy: PublicPolicy,
    settings: Settings,
    metrics: Arc<Mutex<PublicMetrics>>,
    output_pool: Arc<Mutex<usize>>,
    worker: Option<thread::JoinHandle<Result<PublicMetrics>>>,
}
impl Running {
    fn new(settings: Settings) -> Self {
        Self::with_workers(settings, 1, false)
    }
    fn with_workers(settings: Settings, workers: usize, missing_worker_clock: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let node = Node::open_with_permanent_account_growth_v2_and_workers(
            directory.path(),
            settings.clone(),
            workers,
        )
        .unwrap();
        let owner = Arc::new(Mutex::new(node));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let server = PublicServer::new(identity(92), policy)
            .unwrap()
            .with_native_growth()
            .unwrap();
        server
            .fail_next_worker_cpu_finish
            .store(missing_worker_clock, Ordering::Release);
        Self::start(directory, owner, settings, server)
    }
    fn start(
        directory: tempfile::TempDir,
        owner: Arc<Mutex<Node>>,
        settings: Settings,
        server: PublicServer,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let policy = server.policy;
        let key = server.identity.public_key().to_owned();
        let output_pool = server.listener_intake().unwrap().output_pool.clone();
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let worker = {
            let owner = owner.clone();
            let stop = stop.clone();
            let metrics = metrics.clone();
            thread::spawn(move || {
                serve_public_protected_v3_with_metrics(
                    listener,
                    owner,
                    Duration::from_secs(30),
                    stop,
                    server,
                    metrics,
                )
            })
        };
        Self {
            directory,
            owner: Some(owner),
            address,
            stop,
            key,
            policy,
            settings,
            metrics,
            output_pool,
            worker: Some(worker),
        }
    }
    fn call(&self, request: &Request) -> PublicReply {
        call_public_protected_growth_v1(
            self.address,
            request,
            &self.settings,
            &self.key,
            &identity(93),
            self.policy,
            Some(Instant::now() + Duration::from_secs(15)),
        )
        .0
        .unwrap()
    }
    fn exact(&self, packet: &GrowthPacket) -> Value {
        let reply = self.call(&Request::GrowthPacketStatusV1 {
            packet: hex::encode(packet.encode().unwrap()),
        });
        assert!(reply.ok, "{}", reply.value);
        reply.value
    }
    fn submit(&self, packet: &GrowthPacket) -> Value {
        let reply = self.call(&Request::GrowthSubmitV1 {
            packet: hex::encode(packet.encode().unwrap()),
        });
        assert!(reply.ok, "{}", reply.value);
        reply.value
    }
    fn finish(&mut self) -> PublicMetrics {
        self.stop.store(true, Ordering::Release);
        let metrics = self.worker.take().unwrap().join().unwrap().unwrap();
        self.owner.take();
        metrics
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

// Sends a real paid/signed request but never reads its ACK. The caller waits
// only for independent original-owner observation of the durable active block.
fn send_and_lose_ack(run: &Running, packet: &GrowthPacket) {
    let request = Request::GrowthSubmitV1 {
        packet: hex::encode(packet.encode().unwrap()),
    };
    let raw = serde_json::to_vec(&request).unwrap();
    let caller = identity(94);
    let hello = Hello {
        op: 6,
        len: raw.len(),
        caller: digest(caller.public_key()).unwrap(),
        digest: hash(b"public-request-body-v3", &[&raw]),
        client_nonce: [95; 32],
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut socket = TcpStream::connect(run.address).unwrap();
    client_write(&mut socket, &hello.encode(), deadline).unwrap();
    let bytes = client_frame(&mut socket, 2048, deadline).unwrap();
    let cookie: Cookie = serde_json::from_slice(&bytes).unwrap();
    validate_challenge_context(
        &bytes,
        &cookie,
        &hello,
        &run.settings,
        &run.key,
        run.policy,
        run.policy.growth_id(),
    )
    .unwrap();
    let id = cookie.id().unwrap();
    let nonce = (0..1_048_576)
        .find(|nonce| winner(id, *nonce, run.policy.bits))
        .unwrap();
    let mut solution = b"PPS3".to_vec();
    solution.extend(id);
    solution.extend(nonce.to_le_bytes());
    solution.extend(
        hex::decode(
            caller
                .sign(&hash(
                    b"public-caller-sign-v3",
                    &[&id, &nonce.to_le_bytes()],
                ))
                .unwrap(),
        )
        .unwrap(),
    );
    client_write(&mut socket, &solution, deadline).unwrap();
    let ready: Value =
        serde_json::from_slice(&client_frame(&mut socket, 256, deadline).unwrap()).unwrap();
    assert_eq!(ready["cookie_digest"], hex::encode(id));
    client_write(&mut socket, &raw, deadline).unwrap();
    let block = packet.id().unwrap();
    loop {
        if run
            .owner
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .active()
            .unwrap()
            .0
            == block
        {
            break;
        }
        assert!(Instant::now() < deadline, "durable admission deadline");
        thread::sleep(Duration::from_millis(2));
    }
    drop(socket); // Actual signed ACK intentionally unavailable to this caller.
}

#[test]
fn public_growth_v1_real_listener_lost_ack_exact_query_reorg_and_cold_reopen() {
    let settings = settings("public-growth-real-listener-v1");
    let producer_dir = tempfile::tempdir().unwrap();
    let mut producer =
        Node::open_with_permanent_account_growth_v2(producer_dir.path(), settings.clone()).unwrap();
    let packet = make(&producer, settings.genesis(), 1, vec![transfer(&settings)]);
    let id = producer.admit_growth(&packet, 100_000).unwrap();
    producer.activate(id).unwrap();
    let mut run = Running::new(settings.clone());
    let head = run.call(&Request::GrowthHeadV1);
    assert!(head.ok);
    assert_eq!(head.value["height"], 0);
    assert_eq!(run.metrics.lock().unwrap().mutation_cpu_reservations, 0);
    let absent = run.exact(&packet);
    assert_eq!(absent["stored_exact"], false);
    assert_eq!(absent["generation"], 0);
    assert_eq!(run.metrics.lock().unwrap().mutation_cpu_reservations, 1);
    let mut false_work = packet.clone();
    let position = 4 + 2 * trnm_crypto_primitives::pon_work::CELLS * 4;
    let claimed = u32::from_le_bytes(false_work.proof[position..position + 4].try_into().unwrap());
    false_work.proof[position..position + 4].copy_from_slice(
        &((claimed + 1) % (trnm_crypto_primitives::pon_work::Q as u32)).to_le_bytes(),
    );
    assert_eq!(false_work.id().unwrap(), id);
    let invalid = run.call(&Request::GrowthSubmitV1 {
        packet: hex::encode(false_work.encode().unwrap()),
    });
    assert!(!invalid.ok);
    assert!(invalid.value.to_string().contains("WORK:Product"));
    assert_eq!(run.metrics.lock().unwrap().work_failed, 1);
    assert_eq!(run.exact(&packet)["stored_exact"], false);
    send_and_lose_ack(&run, &packet);
    let charged_before = run.metrics.lock().unwrap().mutation_cpu_charged_ns;
    let observed = run.exact(&packet);
    assert_eq!(
        observed["schema"],
        "pon-native-exact-growth-packet-observation-v1"
    );
    assert_eq!(observed["active_chain_member"], true);
    assert_eq!(observed["active_depth"], 0);
    assert_eq!(observed["active_membership_sql_lookups"], 1);
    assert!(observed["accepted_task"].is_null());
    assert!(run.metrics.lock().unwrap().mutation_cpu_charged_ns > charged_before);
    let generation = observed["generation"].clone();
    let read_credit = run.metrics.lock().unwrap().mutation_cpu_reservations;
    let head = run.call(&Request::GrowthHeadV1);
    assert!(head.ok);
    assert_eq!(head.value["generation"], generation);
    assert_eq!(
        run.metrics.lock().unwrap().mutation_cpu_reservations,
        read_credit
    );
    assert_eq!(
        Node::open_growth_packet_observer(run.directory.path(), settings.clone())
            .err()
            .unwrap()
            .to_string(),
        "WRITER_BUSY"
    );
    let mut changed = packet.clone();
    let value = u32::from_le_bytes(changed.proof[4..8].try_into().unwrap());
    changed.proof[4..8].copy_from_slice(
        &((value + 1) % (trnm_crypto_primitives::pon_work::Q as u32)).to_le_bytes(),
    );
    assert_eq!(changed.id().unwrap(), id);
    let rejected = run.call(&Request::GrowthPacketStatusV1 {
        packet: hex::encode(changed.encode().unwrap()),
    });
    assert!(!rejected.ok);
    assert!(rejected.value.to_string().contains("DUPLICATE_CONTENT"));
    assert_eq!(run.exact(&packet)["generation"], generation);
    let work_before = run.metrics.lock().unwrap().work_started;
    assert_eq!(run.submit(&packet)["active"], hex::encode(id));
    assert_eq!(
        run.metrics.lock().unwrap().work_started,
        work_before,
        "stored duplicate cannot mint W1 priority"
    );
    let mut parent = settings.genesis();
    for height in 1..=3 {
        let fork = make(&producer, parent, height, vec![]);
        parent = producer.admit_growth(&fork, 100_000).unwrap();
        run.submit(&fork);
    }
    let orphan = run.exact(&packet);
    assert_eq!(orphan["stored_exact"], true);
    assert_eq!(orphan["active_chain_member"], false);
    assert!(orphan["active_depth"].is_null());
    assert!(orphan["accepted_task"].is_null());
    let metrics = run.finish();
    assert!(metrics.completed_submit >= 5);
    assert!(metrics.mutation_cpu_charged_ns > 0);
    assert_eq!(metrics.mutation_cpu_in_flight_after_shutdown, 0);
    assert_eq!(metrics.paid_body_reserved_bytes_after_shutdown, 0);
    assert_eq!(metrics.output_reserved_bytes_after_shutdown, 0);
    let reopened = Node::open_growth_packet_observer(run.directory.path(), settings).unwrap();
    assert_eq!(reopened.active().unwrap().0, parent);
    assert_eq!(
        reopened.growth_exact_packet_observation(&packet).unwrap(),
        orphan
    );
}

#[test]
fn public_growth_v1_rechecks_future_ancestry_before_new_and_duplicate_activation() {
    for already_stored in [false, true] {
        let settings = settings("public-growth-current-activation-clock");
        let directory = tempfile::tempdir().unwrap();
        let mut node =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        let mut parent = settings.genesis();
        // The normal prefix makes a later low timestamp valid under the
        // original median-time rule, even after one future-dated ancestor.
        for height in 1..=4 {
            let packet = make(&node, parent, height, vec![]);
            parent = node.admit_growth(&packet, 100_000).unwrap();
            node.activate_observed(parent, 100_000).unwrap();
        }
        let before = node.active().unwrap();
        let clock = crate::ingress::now().unwrap();
        let future = clock + settings.limit("future_skew_seconds").unwrap() + 3_600;
        let future_packet = node
            .make_growth_consensus_maintenance(
                parent,
                vec![],
                crate::development_public(3).unwrap(),
                future,
                4096,
            )
            .unwrap();
        let future_id = node.admit_growth(&future_packet, future).unwrap();
        let packet = make(&node, future_id, 6, vec![]);
        let id = packet.id().unwrap();
        if already_stored {
            assert_eq!(node.admit_growth(&packet, clock).unwrap(), id);
        }
        // Admission checks the new header against the original current clock
        // and MTP. It cannot stand in for the complete activation-time walk.
        assert_eq!(
            node.precheck_growth_admission_with_progress(&packet, clock, &|_| Ok(()))
                .unwrap(),
            already_stored.then_some(id)
        );
        // Exercise the original postcommit activation helper independently
        // of the new pre-W1 public ancestry refusal. Local admission retains
        // its historical-validity contract and has already durably completed.
        if !already_stored {
            assert_eq!(node.admit_growth(&packet, clock).unwrap(), id);
        }
        for _ in 0..2 {
            let error = submit_result(&mut node, id).unwrap_err().to_string();
            assert!(error.contains("TIME_DEFERRED"), "{error}");
            assert_eq!(node.active().unwrap(), before);
            assert_eq!(
                node.growth_packet(id).unwrap().encode().unwrap(),
                packet.encode().unwrap()
            );
        }
    }
}

#[test]
fn public_growth_v1_wire_profile_namespace_and_free_lane_cannot_be_confused() {
    let settings = settings("public-growth-wire-v1");
    let mut run = Running::new(settings.clone());
    assert_ne!(run.policy.id(), run.policy.growth_id());
    assert_ne!(run.policy.arithmetic_facts_id(), run.policy.growth_id());
    for request in [
        Request::Head,
        Request::History {
            tip: hex::encode(settings.genesis()),
            after: hex::encode(settings.genesis()),
        },
        Request::PoolStatus,
    ] {
        // Real legacy client sends its original op. Growth listener refuses it
        // before cookie issuance, while keeping the listener alive.
        assert!(call_public_protected_v3(
            run.address,
            &request,
            &settings,
            &run.key,
            &identity(96),
            run.policy
        )
        .is_err());
    }
    let wrong_context = self::settings("public-growth-wire-other-v1");
    let wrong = call_public_protected_growth_v1(
        run.address,
        &Request::GrowthHeadV1,
        &wrong_context,
        &run.key,
        &identity(96),
        run.policy,
        None,
    )
    .0
    .unwrap_err();
    assert_eq!(wrong.to_string(), "PUBLIC_CHALLENGE_CONTEXT");
    assert!(call_public_protected_v3(
        run.address,
        &Request::GrowthHeadV1,
        &settings,
        &run.key,
        &identity(96),
        run.policy
    )
    .is_err());
    for op in [6, 7] {
        assert!(mutating_operation(op));
        let hello = Hello {
            op,
            len: MAX_BODY + 1,
            caller: [0; 32],
            digest: [0; 32],
            client_nonce: [0; 32],
        };
        assert!(Hello::parse(&hello.encode()).is_err());
    }
    assert!(!mutating_operation(8));
    let head = run.call(&Request::GrowthHeadV1);
    assert!(head.ok);
    assert_eq!(head.value["height"], 0);
    assert_eq!(head.value["network"], hex::encode(settings.network()));
    assert_eq!(head.value["production_activation"], false);
    let metrics = run.finish();
    assert_eq!(metrics.completed_submit, 0);
    assert_eq!(metrics.mutation_cpu_reservations, 0);
    assert_eq!(metrics.unknown_caller_durable_rows, 0);
}

#[test]
fn public_growth_v1_control_output_reserve_serves_head_but_not_paid_operations() {
    let settings = settings("public-growth-control-output-v1");
    let mut run = Running::new(settings.clone());
    let packet = make(
        &run.owner.as_ref().unwrap().lock().unwrap(),
        settings.genesis(),
        1,
        vec![],
    );
    let encoded = hex::encode(packet.encode().unwrap());
    // A real shared-intake reservation controls this fixture. This is not a
    // claim that a single listener's bounded sockets can fill this whole pool.
    let bulk = BufferPermit::acquire(
        run.output_pool.clone(),
        MAX_OUTPUT_BYTES - CONTROL_OUTPUT_RESERVE,
        MAX_OUTPUT_BYTES - CONTROL_OUTPUT_RESERVE,
    )
    .unwrap();
    let head = run.call(&Request::GrowthHeadV1);
    assert!(head.ok, "{}", head.value);
    assert_eq!(head.value["height"], 0);
    for request in [
        Request::GrowthSubmitV1 {
            packet: encoded.clone(),
        },
        Request::GrowthPacketStatusV1 { packet: encoded },
    ] {
        let reply = run.call(&request);
        assert!(!reply.ok);
        assert!(
            reply.value.to_string().contains("PUBLIC_BUFFER_CAPACITY"),
            "{}",
            reply.value
        );
    }
    assert_eq!(run.metrics.lock().unwrap().mutation_cpu_reservations, 0);
    assert_eq!(
        run.owner
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .active()
            .unwrap()
            .0,
        settings.genesis()
    );
    assert!(
        run.metrics.lock().unwrap().peak_output_reserved_bytes
            > MAX_OUTPUT_BYTES - CONTROL_OUTPUT_RESERVE
    );
    drop(bulk);
    assert_eq!(run.exact(&packet)["stored_exact"], false);
    let metrics = run.finish();
    assert_eq!(metrics.mutation_cpu_reservations, 1);
    assert_eq!(metrics.output_reserved_bytes_after_shutdown, 0);
}

#[test]
fn public_growth_v1_raw_new_ops_are_refused_by_legacy_and_arithmetic_listeners() {
    for arithmetic in [false, true] {
        let settings = Settings::development(Some(1)).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        let owner = super::super::tests::shared(node);
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let server = PublicServer::new(identity(97), policy).unwrap();
        let server = if arithmetic {
            server.with_arithmetic_facts().unwrap()
        } else {
            server
        };
        let mut run = Running::start(directory, owner, settings.clone(), server);
        for (op, request) in [
            (
                6,
                Request::GrowthSubmitV1 {
                    packet: "00".into(),
                },
            ),
            (
                7,
                Request::GrowthPacketStatusV1 {
                    packet: "00".into(),
                },
            ),
            (8, Request::GrowthHeadV1),
        ] {
            let raw = serde_json::to_vec(&request).unwrap();
            let hello = Hello {
                op,
                len: raw.len(),
                caller: digest(identity(98).public_key()).unwrap(),
                digest: hash(b"public-request-body-v3", &[&raw]),
                client_nonce: [op; 32],
            };
            // Bypass all client profile validation and actually put the new op
            // on the old listener's wire. It must refuse before any cookie.
            Hello::parse(&hello.encode()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = TcpStream::connect(run.address).unwrap();
            client_write(&mut socket, &hello.encode(), deadline).unwrap();
            assert!(
                client_frame(&mut socket, 2048, deadline).is_err(),
                "old listener issued a growth cookie: arithmetic={arithmetic}, op={op}"
            );
        }
        assert_eq!(run.metrics.lock().unwrap().issued_challenges, 0);
        assert_eq!(run.metrics.lock().unwrap().tasks_enqueued, 0);
        let response = if arithmetic {
            call_public_protected_v3_with_arithmetic_facts(
                run.address,
                &Request::Head,
                &settings,
                &run.key,
                &identity(99),
                policy,
                None,
            )
            .0
            .unwrap()
        } else {
            call_public_protected_v3(
                run.address,
                &Request::Head,
                &settings,
                &run.key,
                &identity(99),
                policy,
            )
            .unwrap()
        };
        assert!(response.ok, "{}", response.value);
        let metrics = run.finish();
        assert_eq!(metrics.preface_refusals, 3);
        assert_eq!(metrics.issued_challenges, 1);
        assert_eq!(metrics.mutation_cpu_reservations, 0);
        assert_eq!(metrics.output_reserved_bytes_after_shutdown, 0);
    }
}

#[test]
fn growth_signed_tcp_uses_paid_parallel_preparation_and_rejects_unknown_child_cpu() {
    for workers in [2, 4, 8] {
        for missing_worker_clock in [false, true] {
            let settings = settings("growth-tcp-parallel-preparation");
            let mut run = Running::with_workers(settings.clone(), workers, missing_worker_clock);
            let packet = {
                let owner = run.owner.as_ref().unwrap().lock().unwrap();
                make(
                    &owner,
                    settings.genesis(),
                    1,
                    (1..=8)
                        .map(|nonce| transfer_nonce(&settings, nonce))
                        .collect(),
                )
            };
            let reply = run.call(&Request::GrowthSubmitV1 {
                packet: hex::encode(packet.encode().unwrap()),
            });
            if missing_worker_clock {
                assert!(!reply.ok);
                assert!(
                    reply
                        .value
                        .to_string()
                        .contains("PUBLIC_MUTATION_CPU_UNAVAILABLE"),
                    "{}",
                    reply.value
                );
                assert_eq!(
                    run.owner
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .active()
                        .unwrap(),
                    (settings.genesis(), 0)
                );
            } else {
                assert!(reply.ok, "{}", reply.value);
                assert_eq!(reply.value["block"], hex::encode(packet.id().unwrap()));
                let owner = run.owner.as_ref().unwrap().lock().unwrap();
                assert_eq!(owner.active().unwrap().0, packet.id().unwrap());
                assert_eq!(
                    owner
                        .growth_account(packet.id().unwrap(), crate::development_public(0).unwrap())
                        .unwrap()
                        .unwrap()
                        .nonce,
                    8
                );
            }
            let metrics = run.finish();
            assert_eq!(metrics.mutation_cpu_in_flight_after_shutdown, 0);
            assert_eq!(
                metrics.mutation_cpu_unavailable_after_shutdown,
                missing_worker_clock
            );
            assert_eq!(metrics.output_reserved_bytes_after_shutdown, 0);
            if !missing_worker_clock {
                assert!(metrics.mutation_cpu_charged_ns > 0);
                assert_eq!(metrics.mutation_cpu_clock_failures, 0);
            }
        }
    }
}


#[test]
fn public_growth_v1_future_ancestor_defers_fresh_and_duplicate_before_work() {
    for existing in [false, true] {
        let settings = settings("public-growth-future-ancestor");
        let directory = tempfile::tempdir().unwrap();
        let mut node =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        let future =
            crate::ingress::now().unwrap() + settings.limit("future_skew_seconds").unwrap() + 3600;
        let mut parent = settings.genesis();
        for timestamp in [11, 21, future, 22, 23] {
            let packet = node
                .make_growth_consensus_maintenance(
                    parent,
                    vec![],
                    crate::development_public(3).unwrap(),
                    timestamp,
                    4096,
                )
                .unwrap();
            parent = node.admit_growth(&packet, future).unwrap();
        }
        let packet = node
            .make_growth_consensus_maintenance(
                parent,
                vec![],
                crate::development_public(3).unwrap(),
                24,
                4096,
            )
            .unwrap();
        let id = packet.id().unwrap();
        if existing {
            assert_eq!(node.admit_growth(&packet, future).unwrap(), id);
        }
        let active = node.active().unwrap();
        let owner = Arc::new(Mutex::new(node));
        let server = PublicServer::new(
            identity(92),
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        )
        .unwrap()
        .with_native_growth()
        .unwrap();
        let mut run = Running::start(directory, owner, settings.clone(), server);
        let work_before = run.metrics.lock().unwrap().work_started;
        let reply = run.call(&Request::GrowthSubmitV1 {
            packet: hex::encode(packet.encode().unwrap()),
        });
        assert!(!reply.ok, "future ancestor reached public activation: existing={existing}, future={future}, expected_block={}, reply={}", hex::encode(id), reply.value);
        assert!(
            reply.value.to_string().contains("TIME_DEFERRED"),
            "{}",
            reply.value
        );
        assert_eq!(run.metrics.lock().unwrap().work_started, work_before);
        {
            let owner = run.owner.as_ref().unwrap().lock().unwrap();
            assert_eq!(owner.active().unwrap(), active);
            if existing {
                assert_eq!(
                    owner.growth_packet(id).unwrap().encode().unwrap(),
                    packet.encode().unwrap()
                );
            } else {
                assert!(owner.parent_height(id).is_err());
            }
        }
        // A separate eligible branch still uses the real listener successfully.
        let honest = {
            let owner = run.owner.as_ref().unwrap().lock().unwrap();
            owner
                .make_growth_consensus_maintenance(
                    settings.genesis(),
                    vec![],
                    crate::development_public(4).unwrap(),
                    12,
                    4096,
                )
                .unwrap()
        };
        assert_eq!(
            run.submit(&honest)["active"],
            hex::encode(honest.id().unwrap())
        );
        let metrics = run.finish();
        assert_eq!(metrics.mutation_cpu_in_flight_after_shutdown, 0);
        assert!(!metrics.mutation_cpu_unavailable_after_shutdown);
    }
}
