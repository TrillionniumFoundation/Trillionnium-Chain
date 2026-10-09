//! Actual optional measurements preserve full native acceptance/rejection and shutdown.
use std::{
    io::Write,
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{
            self, PublicMetrics, PublicPolicy, PublicRequestObserver, PublicServer, Request,
        },
        DevelopmentIdentity,
    },
    Node, PoolLimits, Settings,
};

fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn enable(node: &mut Node) {
    node.enable_local_mempool(PoolLimits {
        max_records: 8,
        max_bytes: 32768,
        max_group_members: 4,
        critical_reserve: 0,
        max_removals: 16,
        preview_miner: development_public(3).unwrap(),
    })
    .unwrap();
}
type RunningService = (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    Arc<Mutex<PublicMetrics>>,
    thread::JoinHandle<PublicMetrics>,
);
fn service(node: Arc<Mutex<Node>>, observer: PublicRequestObserver) -> RunningService {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
    let signal = stop.clone();
    let counters = metrics.clone();
    let worker = thread::spawn(move || {
        public_v3::serve_public_protected_v3_with_request_observer(
            listener,
            node,
            Duration::from_secs(15),
            signal,
            PublicServer::new(
                identity(71),
                PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
            )
            .unwrap(),
            counters,
            observer,
        )
        .unwrap()
    });
    (address, stop, metrics, worker)
}

#[test]
fn actual_paid_native_work_rejection_read_frames_and_partial_eof_are_attributed() {
    let now = ingress::now().unwrap();
    let settings = Settings::development(Some(now - 100)).unwrap();
    let oracle_dir = tempfile::tempdir().unwrap();
    let mut oracle = Node::open(oracle_dir.path(), settings.clone(), 1).unwrap();
    let packet = oracle
        .make(
            settings.genesis(),
            vec![],
            development_public(3).unwrap(),
            now - 90,
            4096,
        )
        .unwrap();
    let mut bad = packet.clone();
    let offset = 4 + 8 * pon_work::CELLS;
    let value = u32::from_le_bytes(bad.proof[offset..offset + 4].try_into().unwrap());
    bad.proof[offset..offset + 4]
        .copy_from_slice(&((u128::from(value) + 1) % pon_work::Q).to_le_bytes()[..4]);
    assert_eq!(
        pon_work::verify(
            bad.header.challenge(),
            bad.header.work_task,
            bad.header.target,
            &bad.proof
        )
        .unwrap_err(),
        pon_work::WorkError::Product
    );
    let native_dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(native_dir.path(), settings.clone(), 1).unwrap();
    enable(&mut node);
    let node = Arc::new(Mutex::new(node));
    let observer = PublicRequestObserver::new(5).unwrap();
    let (address, stop, metrics, worker) = service(node.clone(), observer.clone());
    let mut partial = TcpStream::connect(address).unwrap();
    partial.write_all(b"PPI3\x01").unwrap();
    partial.shutdown(Shutdown::Write).unwrap();
    drop(partial);
    let end = Instant::now() + Duration::from_secs(2);
    while metrics.lock().unwrap().preface_refusals == 0 {
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(2));
    }
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let requests = [
        Request::Submit {
            packet: hex::encode(bad.encode().unwrap()),
        },
        Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        },
        Request::Head,
        Request::History {
            tip: hex::encode(packet.id().unwrap()),
            after: hex::encode(settings.genesis()),
        },
    ];
    let mut expected_body = Vec::new();
    for (i, request) in requests.iter().enumerate() {
        let (result, cost) = public_v3::call_public_protected_v3_with_metrics(
            address,
            request,
            &settings,
            identity(71).public_key(),
            &identity(80 + i as u8),
            policy,
        );
        let reply = result.unwrap();
        assert_eq!(reply.ok, i != 0, "{}", reply.value);
        if i == 0 {
            assert!(reply.value.to_string().contains("Product"));
        }
        assert!(cost.solution_found);
        expected_body.push(reply.body_bytes_sent);
    }
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    let snapshot = observer.snapshot();
    assert_eq!(snapshot.accepted_connections_seen, 5);
    assert_eq!(snapshot.records.len(), 5);
    assert_eq!(snapshot.records_not_retained, 0);
    assert_eq!(snapshot.measurement_failures, 0);
    assert!(!snapshot.counter_overflow);
    assert_eq!(metrics.work_started, 2);
    assert_eq!(metrics.work_finished, 2);
    assert_eq!(metrics.work_failed, 1);
    let partial = &snapshot.records[0];
    assert!(partial.complete && partial.connection_closed && !partial.task_created);
    assert_eq!(partial.application_bytes_read, Some(5));
    assert_eq!(partial.application_bytes_written, Some(0));
    assert!(!partial.frames[0].complete);
    assert_eq!(partial.dispatch_thread_cpu_ns, None);
    assert_eq!(partial.full_work_thread_cpu_ns, None);
    for (i, row) in snapshot.records[1..].iter().enumerate() {
        assert!(row.complete && row.task_created && row.task_closed && row.response_frame_complete);
        assert!(row.frames.iter().all(|f| f.complete));
        assert_eq!(row.frames[0].bytes_read, 108);
        assert_eq!(row.frames[2].bytes_read, 108);
        assert_eq!(row.frames[4].bytes_read, expected_body[i] as u64);
        assert_eq!(
            row.application_bytes_read,
            Some(216 + expected_body[i] as u64)
        );
        assert_eq!(
            row.application_bytes_written,
            Some(row.frames.iter().map(|f| f.bytes_written).sum())
        );
        assert!(
            row.frames[1].bytes_written > 4
                && row.frames[3].bytes_written > 4
                && row.frames[5].bytes_written > 4
        );
        assert_eq!(row.physical_network_bytes, None);
        assert!(row.dispatch_started);
        assert_eq!(row.dispatch_accepted, Some(i != 0));
        assert_eq!(row.full_work_started, i < 2);
        if i < 2 {
            assert_eq!(row.full_work_accepted, Some(i == 1));
            if cfg!(target_os = "linux") {
                assert!(
                    row.dispatch_thread_cpu_ns.unwrap() >= row.full_work_thread_cpu_ns.unwrap()
                );
                assert!(row.full_work_thread_cpu_ns.unwrap() > 0);
            }
        } else {
            assert_eq!(row.full_work_thread_cpu_ns, None);
            assert_eq!(row.full_work_accepted, None);
        }
    }
    let id = oracle.admit(&packet, now).unwrap();
    oracle.activate_observed(id, now).unwrap();
    assert_eq!(
        node.lock().unwrap().read_active().unwrap(),
        oracle.read_active().unwrap()
    );
    assert_eq!(
        node.lock().unwrap().packet(id).unwrap().encode().unwrap(),
        packet.encode().unwrap()
    );
    assert_eq!(metrics.unknown_caller_durable_rows, 0);
    assert_eq!(metrics.paid_body_reserved_bytes_after_shutdown, 0);
    assert_eq!(metrics.output_reserved_bytes_after_shutdown, 0);
    println!("{}", serde_json::to_string(&snapshot).unwrap());
}

#[test]
fn real_observer_capacity_overflow_does_not_refuse_concurrent_honest_reads() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(ingress::now().unwrap() - 100)).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    enable(&mut node);
    let before = node.read_active().unwrap();
    let node = Arc::new(Mutex::new(node));
    let observer = PublicRequestObserver::new(1).unwrap();
    let (address, stop, _, worker) = service(node.clone(), observer.clone());
    thread::scope(|scope| {
        let mut clients = Vec::new();
        for i in 0..4 {
            let settings = &settings;
            clients.push(scope.spawn(move || {
                public_v3::call_public_protected_v3(
                    address,
                    &Request::Head,
                    settings,
                    identity(71).public_key(),
                    &identity(80 + i),
                    PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
                )
                .unwrap()
            }));
        }
        for client in clients {
            assert!(client.join().unwrap().ok);
        }
    });
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    let snapshot = observer.snapshot();
    assert_eq!(metrics.completed_read, 4);
    assert_eq!(snapshot.accepted_connections_seen, 4);
    assert_eq!(snapshot.records_not_retained, 3);
    assert_eq!(snapshot.records.len(), 1);
    assert!(snapshot.records[0].complete);
    assert_eq!(snapshot.records[0].full_work_thread_cpu_ns, None);
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
}

#[cfg(target_os = "linux")]
mod actual_depletion {
    //! Trusted local W1 replay drives the existing request CPU domain to refusal.
    //! This is depletion/recovery, not remotely induced public saturation.
    use serde_json::{json, Value};
    use std::{
        fs,
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        thread::{self, JoinHandle},
        time::{Duration, Instant},
    };
    use trnm_crypto_primitives::pon_work;
    use trnm_pon_node::{
        development_public,
        ingress::{
            self,
            public_v3::{self, PublicPolicy, PublicServer, Request, ServiceMutationCpuDomain},
            DevelopmentIdentity,
        },
        maintenance, sequence_root, Node, Packet, PoolLimits, Settings,
    };
    use trnm_protocol::pon_wire::{hash, Header};

    const ROUNDS: usize = 3;
    const SEARCH_LIMIT: u64 = 4096;
    const REPLAY_LIMIT: usize = 100_000;
    const CALL_LIMIT: Duration = Duration::from_secs(2);

    fn identity(n: u8) -> DevelopmentIdentity {
        DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
    }
    fn policy() -> PublicPolicy {
        PublicPolicy::new(8, CALL_LIMIT).unwrap()
    }
    fn elapsed_ns(epoch: Instant) -> u64 {
        epoch.elapsed().as_nanos().try_into().unwrap()
    }

    struct RunningService {
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<Value>>,
    }
    impl RunningService {
        fn finish(mut self) -> Value {
            self.stop.store(true, Ordering::Release);
            self.worker.take().unwrap().join().unwrap()
        }
    }
    impl Drop for RunningService {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn false_packet(node: &Node) -> Packet {
        let settings = node.settings();
        let (a, b) = maintenance();
        let header = Header {
            network: settings.network(),
            parameters: settings.parameters(),
            parent: settings.genesis(),
            height: 1,
            timestamp: settings.genesis_time() + 1,
            target: node.expected_target(settings.genesis()).unwrap(),
            miner: development_public(0).unwrap(),
            transactions: sequence_root("transactions", &[]),
            state: [0; 32],
            receipts: [0; 32],
            work_task: pon_work::task_id(&a, &b).unwrap(),
            nonce: 91_000,
        };
        let challenge = header.challenge();
        let trace = (0..SEARCH_LIMIT)
            .map(|nonce| {
                hash(
                    b"local-cpu-depletion-fixture-v1",
                    &[&challenge, &nonce.to_le_bytes()],
                )
            })
            .find(|trace| hash(b"ticket", &[&challenge, trace]) <= header.target)
            .expect("fixed bounded public fixture must produce a ticket hit");
        let mut proof = Vec::with_capacity(pon_work::PROOF_BYTES);
        proof.extend_from_slice(b"PNW1");
        for matrix in [&a, &b] {
            for value in matrix {
                proof.extend_from_slice(&value.to_le_bytes());
            }
        }
        proof.resize(pon_work::PROOF_BYTES, 0);
        proof[pon_work::PROOF_BYTES - 32..].copy_from_slice(&trace);
        Packet {
            header,
            transactions: vec![],
            proof,
        }
    }

    fn deplete(domain: &ServiceMutationCpuDomain, packet: &Packet, deadline: Instant) -> Value {
        let before = domain.observe().unwrap();
        let started = Instant::now();
        // Actual clock samples only. A cap without live refusal fails the test.
        let operation = loop {
            match domain.begin() {
                Ok(operation) => break operation,
                Err(error) => {
                    if !domain.accounting_available() || Instant::now() >= deadline {
                        return json!({"depletion_observed": false, "begin_error": error.to_string(),
                            "meter_before": before, "meter_after": domain.observe().unwrap()});
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        };
        let mut replays = 0;
        let mut refusal = None;
        while replays < REPLAY_LIMIT && Instant::now() < deadline {
            assert_eq!(
                pon_work::verify_reference(
                    packet.header.challenge(),
                    packet.header.work_task,
                    packet.header.target,
                    &packet.proof,
                )
                .unwrap_err(),
                pon_work::WorkError::Transcript,
            );
            replays += 1;
            if let Err(error) = operation.checkpoint() {
                refusal = Some(error.to_string());
                break;
            }
        }
        let at_refusal = domain.observe().unwrap();
        let settlement = operation.finish();
        let after = domain.observe().unwrap();
        let observed = refusal.as_deref() == Some("PUBLIC_MUTATION_CPU_BUDGET")
            && settlement.live_refused
            && !settlement.accounting_unavailable
            && settlement.total_cpu_ns.is_some_and(|cpu| cpu > 0)
            && at_refusal.stored_credit_ns < i128::from(at_refusal.start_reserve_ns)
            && !after.accounting_unavailable
            && after.in_flight == 0;
        json!({"depletion_observed": observed, "meter_before": before,
            "meter_at_refusal": at_refusal, "meter_after": after,
            "replays": replays, "replay_limit": REPLAY_LIMIT,
            "cap_reached": replays == REPLAY_LIMIT, "refusal": refusal,
            "settlement": settlement, "wall_ns": elapsed_ns(started),
            "scope": "actual owner-thread full W1 replay and checkpoints; trusted local load"})
    }

    #[test]
    fn actual_replay_depletion_public_recovery_and_same_epoch_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let output = std::env::var_os("TRNM_PUBLIC_V3_DEPLETION_DIR")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("TRNM_CI_RECEIPT_DIR")
                    .map(|root| std::path::PathBuf::from(root).join("actual-cpu-depletion"))
            });
        let path = if let Some(path) = output {
            fs::create_dir(&path).unwrap();
            path
        } else {
            temporary.path().to_path_buf()
        };
        let settings = Settings::development(Some(1_750_000_000)).unwrap();
        let receiver_path = path.join("receiver");
        let mut node = Node::open(&receiver_path, settings.clone(), 1).unwrap();
        node.enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 4,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: development_public(0).unwrap(),
        })
        .unwrap();
        let false_work = false_packet(&node);
        let mut producer = Node::open(&path.join("producer"), settings.clone(), 1).unwrap();
        let honest_packets: Vec<_> = (0..ROUNDS)
            .map(|index| {
                producer
                    .mine(
                        vec![],
                        settings.genesis_time() + 10 * (index as u64 + 1),
                        ingress::now().unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        let expected = producer.read_active().unwrap();
        let server = PublicServer::new(identity(71), policy()).unwrap();
        let domain = server.mutation_cpu_domain();
        let initial = domain.observe().unwrap();
        assert_eq!(
            (
                initial.burst_ns,
                initial.refill_ns_per_second,
                initial.start_reserve_ns,
                initial.worker_limit,
            ),
            (2_000_000_000, 250_000_000, 100_000_000, 2)
        );
        let owner = Arc::new(Mutex::new(node));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (shared, signal) = (owner.clone(), stop.clone());
        let service = RunningService {
            stop,
            worker: Some(thread::spawn(
                move || match public_v3::serve_public_protected_v3(
                    listener,
                    shared,
                    Duration::from_secs(90),
                    signal,
                    server,
                ) {
                    Ok(metrics) => json!({"metrics": metrics, "error": null}),
                    Err(error) => json!({"metrics": null, "error": error.to_string()}),
                },
            )),
        };
        let epoch = Instant::now();
        let deadline = epoch + Duration::from_secs(60);
        let mut rounds = Vec::new();
        for (index, packet) in honest_packets.iter().enumerate() {
            let pressure = deplete(&domain, &false_work, deadline);
            let started = Instant::now();
            let (reply, transport) = public_v3::call_public_protected_v3_with_deadline(
                address,
                &Request::Submit {
                    packet: hex::encode(packet.encode().unwrap()),
                },
                &settings,
                identity(71).public_key(),
                &identity(73),
                policy(),
                Some((started + CALL_LIMIT).min(deadline)),
            );
            let elapsed = started.elapsed();
            let (acknowledged, response, error) = match reply {
                Ok(reply) => (reply.ok, Some(serde_json::to_value(reply).unwrap()), None),
                Err(error) => (false, None, Some(error.to_string())),
            };
            let read_started = Instant::now();
            let (read, read_transport) = public_v3::call_public_protected_v3_with_deadline(
                address,
                &Request::Head,
                &settings,
                identity(71).public_key(),
                &identity(72),
                policy(),
                Some((read_started + CALL_LIMIT).min(deadline)),
            );
            let read_on_time =
                read.as_ref().is_ok_and(|reply| reply.ok) && read_started.elapsed() <= CALL_LIMIT;
            let active_id = owner.lock().unwrap().read_active().unwrap().0;
            let expected_id = packet.id().unwrap();
            rounds.push(json!({"round": index + 1, "local_pressure": pressure,
                "honest_acknowledged": acknowledged, "submit_on_time": elapsed <= CALL_LIMIT,
                "submit_wall_ns": elapsed.as_nanos(), "submit_response": response,
                "submit_error": error, "transport": transport,
                "head_on_time": read_on_time, "head_transport": read_transport,
                "active_id": hex::encode(active_id), "expected_id": hex::encode(expected_id),
                "active_packet_equal": active_id == expected_id}));
        }
        let service_outcome = service.finish();
        let node = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
        let before = node.read_active().unwrap();
        let full_state_equal = before.0 == expected.0 && before.2 == expected.2;
        let before_meter = domain.observe().unwrap();
        drop(node);
        let reopened = Node::open(&receiver_path, settings.clone(), 1).unwrap();
        let reopened_equal = before == reopened.read_active().unwrap();
        let resumed =
            PublicServer::with_continuous_domain(identity(71), policy(), &domain).unwrap();
        let same_epoch = domain.shares_domain_with(&resumed.mutation_cpu_domain())
            && before_meter == resumed.mutation_cpu_domain().observe().unwrap();
        let passed = rounds.len() == ROUNDS
            && rounds.iter().all(|round| {
                round["local_pressure"]["depletion_observed"] == true
                    && round["local_pressure"]["cap_reached"] == false
                    && round["honest_acknowledged"] == true
                    && round["submit_on_time"] == true
                    && round["head_on_time"] == true
                    && round["active_packet_equal"] == true
            })
            && full_state_equal
            && reopened_equal
            && same_epoch
            && service_outcome["error"].is_null()
            && before_meter.in_flight == 0
            && !before_meter.accounting_unavailable;
        let report = json!({"schema": "public-v3-actual-local-replay-depletion-v1",
            "network": hex::encode(settings.network()), "parameters": hex::encode(settings.parameters()),
            "policy_id": hex::encode(policy().id()), "initial_meter": initial, "rounds": rounds,
            "false_work_packet": hex::encode(false_work.encode().unwrap()),
            "full_native_state_equal": full_state_equal, "reopen_state_equal": reopened_equal,
            "same_cpu_epoch_across_reopen": same_epoch, "final_meter": before_meter,
            "service": service_outcome, "wall_ns": elapsed_ns(epoch), "passed": passed,
            "scope": "trusted local W1 replay depletion, then real public submit/head recovery; no live remote attack",
            "public_hostile_saturation_qualified": false, "work_profile_qualified": false,
            "resource_fairness_qualified": false, "independent_accepted": false,
            "physical_power_loss": false, "production_activation": false});
        fs::write(
            path.join("report.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        println!("{}", json!({"schema": report["schema"], "passed": passed}));
        assert!(
            passed,
            "retain actual-cpu-depletion/report.json; no inferred or synthetic depletion"
        );
    }

    #[test]
    fn depleted_domain_serves_honest_block_during_rotating_public_false_work() {
        // The local precondition is actual depletion, not a reduced policy or
        // a remote-cost claim. False public traffic continues during honest use.
        const WORKERS: usize = 16;
        const ATTEMPT_LIMIT: usize = 1024;
        const WINDOW: Duration = Duration::from_secs(4);
        let temporary = tempfile::tempdir().unwrap();
        let path = match std::env::var_os("TRNM_CI_RECEIPT_DIR") {
            Some(root) => {
                let path = std::path::PathBuf::from(root).join("depleted-public-overlap");
                fs::create_dir(&path).unwrap();
                path
            }
            None => temporary.path().to_path_buf(),
        };
        let settings = Settings::development(Some(1_750_000_000)).unwrap();
        let receiver = path.join("receiver");
        let mut node = Node::open(&receiver, settings.clone(), 1).unwrap();
        node.enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 4,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: development_public(0).unwrap(),
        })
        .unwrap();
        let false_work = false_packet(&node);
        let false_wire = hex::encode(false_work.encode().unwrap());
        let mut producer = Node::open(&path.join("producer"), settings.clone(), 1).unwrap();
        let honest = producer
            .mine(vec![], settings.genesis_time() + 10, ingress::now().unwrap())
            .unwrap();
        let expected = producer.read_active().unwrap();
        let server = PublicServer::new(identity(71), policy()).unwrap();
        let domain = server.mutation_cpu_domain();
        let initial_meter = domain.observe().unwrap();
        let depletion = deplete(
            &domain,
            &false_work,
            Instant::now() + Duration::from_secs(60),
        );
        let owner = Arc::new(Mutex::new(node));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let observer = public_v3::PublicRequestObserver::new(16_384).unwrap();
        let counters = Arc::new(Mutex::new(public_v3::PublicMetrics::default()));
        let (shared, signal, capture) = (owner.clone(), stop.clone(), observer.clone());
        let service = RunningService {
            stop,
            worker: Some(thread::spawn(
                move || match public_v3::serve_public_protected_v3_with_request_observer(
                    listener,
                    shared,
                    Duration::from_secs(30),
                    signal,
                    server,
                    counters,
                    capture,
                ) {
                    Ok(metrics) => json!({"metrics": metrics, "error": null}),
                    Err(error) => json!({"metrics": null, "error": error.to_string()}),
                },
            )),
        };
        let epoch = Instant::now();
        let end = epoch + WINDOW;
        let barrier = std::sync::Barrier::new(WORKERS + 1);
        let completed = std::sync::atomic::AtomicU64::new(0);
        let (attacks, honest_use) = thread::scope(|scope| {
            let mut workers = Vec::new();
            for worker in 0..WORKERS {
                let (barrier, completed, settings, wire) =
                    (&barrier, &completed, &settings, &false_wire);
                workers.push(scope.spawn(move || {
                    barrier.wait();
                    let mut calls = Vec::new();
                    for attempt in 0..ATTEMPT_LIMIT {
                        if Instant::now() >= end {
                            break;
                        }
                        let started = Instant::now();
                        let started_ns = elapsed_ns(epoch);
                        let caller = 80 + ((worker * 37 + attempt) % 150) as u8;
                        let (result, transport) =
                            public_v3::call_public_protected_v3_with_deadline(
                                address,
                                &Request::Submit {
                                    packet: wire.clone(),
                                },
                                settings,
                                identity(71).public_key(),
                                &identity(caller),
                                policy(),
                                Some(started + CALL_LIMIT),
                            );
                        let (accepted, response, error) = match result {
                            Ok(reply) => (
                                reply.ok,
                                Some(serde_json::to_value(reply).unwrap()),
                                None,
                            ),
                            Err(error) => (false, None, Some(error.to_string())),
                        };
                        calls.push(json!({"caller_fixture": caller,
                            "started_ns": started_ns, "ended_ns": elapsed_ns(epoch),
                            "accepted": accepted, "response": response,
                            "error": error, "transport": transport}));
                        completed.fetch_add(1, Ordering::Release);
                    }
                    json!({"worker": worker, "cap_reached": calls.len() == ATTEMPT_LIMIT,
                        "calls": calls})
                }));
            }
            barrier.wait();
            // A completed false call must precede the honest attempt. A worker
            // merely being spawned is not evidence that public traffic ran.
            while completed.load(Ordering::Acquire) == 0 && Instant::now() < end {
                thread::sleep(Duration::from_millis(1));
            }
            let false_calls_before = completed.load(Ordering::Acquire);
            let started = Instant::now();
            let started_ns = elapsed_ns(epoch);
            let (submit, submit_transport) = public_v3::call_public_protected_v3_with_deadline(
                address,
                &Request::Submit {
                    packet: hex::encode(honest.encode().unwrap()),
                },
                &settings,
                identity(71).public_key(),
                &identity(73),
                policy(),
                Some((started + CALL_LIMIT).min(end)),
            );
            let submit_on_time = started.elapsed() <= CALL_LIMIT && Instant::now() < end;
            let submit_ended_ns = elapsed_ns(epoch);
            let submit_ok = submit.as_ref().is_ok_and(|reply| reply.ok);
            let read_started = Instant::now();
            let (head, head_transport) = public_v3::call_public_protected_v3_with_deadline(
                address,
                &Request::Head,
                &settings,
                identity(71).public_key(),
                &identity(72),
                policy(),
                Some((read_started + CALL_LIMIT).min(end)),
            );
            let head_ok = head.as_ref().is_ok_and(|reply| reply.ok);
            let head_on_time = read_started.elapsed() <= CALL_LIMIT && Instant::now() < end;
            let use_record = json!({"false_calls_completed_before": false_calls_before,
                "started_ns": started_ns, "submit_ended_ns": submit_ended_ns,
                "ended_ns": elapsed_ns(epoch), "submit_ok": submit_ok,
                "submit_on_time": submit_on_time, "head_ok": head_ok,
                "head_on_time": head_on_time, "submit_transport": submit_transport,
                "head_transport": head_transport,
                "submit_error": submit.err().map(|error| error.to_string()),
                "head_error": head.err().map(|error| error.to_string())});
            let rows: Vec<_> = workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect();
            (rows, use_record)
        });
        let service_outcome = service.finish();
        let captured = observer.snapshot();
        let node = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
        let before = node.read_active().unwrap();
        let full_state_equal = before == expected;
        let final_meter = domain.observe().unwrap();
        drop(node);
        let reopened = Node::open(&receiver, settings.clone(), 1).unwrap();
        let reopen_equal = before == reopened.read_active().unwrap();
        let resumed =
            PublicServer::with_continuous_domain(identity(71), policy(), &domain).unwrap();
        let same_epoch = domain.shares_domain_with(&resumed.mutation_cpu_domain())
            && final_meter == resumed.mutation_cpu_domain().observe().unwrap();
        let calls: Vec<_> = attacks
            .iter()
            .flat_map(|worker| worker["calls"].as_array().unwrap())
            .collect();
        let honest_start = honest_use["started_ns"].as_u64().unwrap();
        let honest_end = honest_use["ended_ns"].as_u64().unwrap();
        let overlapping_calls = calls
            .iter()
            .filter(|call| {
                call["started_ns"].as_u64().unwrap() < honest_end
                    && call["ended_ns"].as_u64().unwrap() > honest_start
            })
            .count();
        let metrics = &service_outcome["metrics"];
        let captured_complete = captured.records_not_retained == 0
            && captured.measurement_failures == 0
            && !captured.counter_overflow
            && captured.records.iter().all(|record| record.complete);
        let passed = depletion["depletion_observed"] == true
            && depletion["cap_reached"] == false
            && honest_use["false_calls_completed_before"].as_u64().unwrap() > 0
            && overlapping_calls > 0
            && honest_use["submit_ok"] == true
            && honest_use["submit_on_time"] == true
            && honest_use["head_ok"] == true
            && honest_use["head_on_time"] == true
            && attacks.iter().all(|worker| worker["cap_reached"] == false)
            && calls.iter().all(|call| call["accepted"] == false)
            && metrics["work_failed"].as_u64().is_some_and(|failed| failed > 0)
            && metrics["work_started"] == metrics["work_finished"]
            && metrics["mutation_cpu_clock_failures"] == 0
            && service_outcome["error"].is_null()
            && captured_complete
            && full_state_equal
            && reopen_equal
            && same_epoch
            && final_meter.in_flight == 0
            && !final_meter.accounting_unavailable;
        let report = json!({"schema": "public-v3-depleted-cooffered-observation-v1",
            "network": hex::encode(settings.network()), "parameters": hex::encode(settings.parameters()),
            "initial_meter": initial_meter, "local_depletion": depletion,
            "window_ns": WINDOW.as_nanos(), "workers": WORKERS, "attempt_limit": ATTEMPT_LIMIT,
            "false_packet": false_wire, "attacks": attacks, "honest_use": honest_use,
            "overlapping_false_calls": overlapping_calls, "observations": captured,
            "full_native_state_equal": full_state_equal, "reopen_state_equal": reopen_equal,
            "same_cpu_epoch_across_reopen": same_epoch, "final_meter": final_meter,
            "service": service_outcome, "passed": passed,
            "scope": "actual local depletion then bounded rotating loopback false-work traffic cooffered with honest use; shared controller and repeated false proof",
            "remote_induced_depletion_qualified": false, "work_profile_qualified": false,
            "public_hostile_saturation_qualified": false, "resource_fairness_qualified": false,
            "independent_accepted": false, "physical_power_loss": false,
            "attacker_aggregate_cpu_ns": null, "wan_tps": null, "production_activation": false});
        fs::write(
            path.join("report.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        println!("{}", json!({"schema": report["schema"], "passed": passed}));
        assert!(passed, "retain depleted-public-overlap/report.json");
    }
}
