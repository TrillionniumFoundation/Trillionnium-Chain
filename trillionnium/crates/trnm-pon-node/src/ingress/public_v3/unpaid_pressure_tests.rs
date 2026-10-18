//! Actual bounded loopback pressure, with one administrator and development keys.
//! A finite silent input cohort is not arbitrary anonymous flood fairness.
use super::*;

fn identity(key: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([key; 32])).unwrap()
}
fn until(predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(Instant::now() < deadline, "original reactor did not expose bounded progress");
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn real_shared64_unpaid_pressure_releases_slots_protects_paid_body_and_confirms_one_business() {
    let directory = tempfile::tempdir().unwrap();
    let clock = super::super::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let mut producer = Node::open(&directory.path().join("producer"), settings.clone(), 1).unwrap();
    let transaction = super::tests::accounting_transactions(&settings, 1, 1).remove(0);
    let transaction_id = hash(b"tx-id", &[&transaction]);
    let mut packets = Vec::new();
    for index in 0..=settings.limit("confirmation_depth").unwrap() {
        let parent = producer.active().unwrap().0;
        let packet = producer.make(
            parent,
            if index == 0 { vec![transaction.clone()] } else { vec![] },
            crate::development_public(0).unwrap(), clock - 50 + index, 4096,
        ).unwrap();
        assert_eq!(packet.header.parent, parent);
        assert_eq!(packet.header.height, index + 1);
        let admitted = producer.admit(&packet, clock).unwrap();
        // Admission retains a valid block without selecting the active chain.
        // Advance through the real fork-choice owner so every next packet is a
        // descendant of the business block, rather than another genesis child.
        assert_eq!(producer.activate_observed(admitted, clock).unwrap(), admitted);
        packets.push(packet);
    }
    let receiver = Node::open(&directory.path().join("receiver"), settings.clone(), 1).unwrap();
    let owner = super::tests::shared(receiver);
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let first = PublicServer::with_continuous_domain(identity(71), policy, &domain).unwrap();
    let intake = first.listener_intake().unwrap();
    let second = PublicServer::with_continuous_domain(identity(72), policy, &domain).unwrap();
    let listeners = [TcpListener::bind("127.0.0.1:0").unwrap(), TcpListener::bind("127.0.0.1:0").unwrap()];
    let addresses = listeners.each_ref().map(|l| l.local_addr().unwrap());
    let metrics = [Arc::new(Mutex::new(PublicMetrics::default())), Arc::new(Mutex::new(PublicMetrics::default()))];
    let stop = Arc::new(AtomicBool::new(false));
    struct Stop(Arc<AtomicBool>);
    impl Drop for Stop {
        fn drop(&mut self) { self.0.store(true, Ordering::Release); }
    }
    let mut evidence = Value::Null;
    thread::scope(|scope| {
        let workers: Vec<_> = listeners.into_iter().zip([first, second]).enumerate().map(|(i, (listener, service))| {
            let (node, stopping, counters) = (owner.clone(), stop.clone(), metrics[i].clone());
            scope.spawn(move || serve_public_protected_v3_with_metrics(
                listener, node, Duration::from_secs(30), stopping, service, counters,
            ))
        }).collect();
        let guard = Stop(stop.clone());
        until(|| *intake.listeners.lock().unwrap() == 2);
        let honest_calls = RefCell::new(Vec::new());
        let call = |purpose: &str, index: usize, request: &Request| {
            let (result, client_metrics) = call_public_protected_v3_with_metrics(
                addresses[index], request, &settings, identity(71 + index as u8).public_key(), &identity(80), policy,
            );
            honest_calls.borrow_mut().push(json!({
                "purpose": purpose, "operation": request_op(request).unwrap(), "listener": index,
                "offered": true, "completed": result.as_ref().is_ok_and(|reply| reply.ok),
                "error": result.as_ref().err().map(ToString::to_string),
                "response": result.as_ref().ok(), "client_metrics": client_metrics,
            }));
            result
        };
        let started = Instant::now();
        let silent: Vec<_> = (0..MAX_CONNECTIONS).map(|i| TcpStream::connect(addresses[i % 2]).unwrap()).collect();
        until(|| *intake.connections.lock().unwrap() == MAX_CONNECTIONS);
        thread::sleep(Duration::from_millis(intake::UNPAID_PRESSURE_IDLE_MS + 30));
        assert!(call("phase1-capacity-probe", 1, &Request::Head).is_err(), "pressure request itself cannot reuse an undropped socket slot");
        until(|| metrics.iter().map(|m| m.lock().unwrap().unpaid_pressure_connections_closed).sum::<u64>() >= 1);
        let released_ns = elapsed_ns(started);
        assert!(released_ns < PREFIX_MS * 1_000_000, "pressure release must precede original Hello timeout");
        assert!(call("phase1-after-actual-release", 1, &Request::Head).unwrap().ok);
        let pressure_only_work = metrics.iter().map(|m| m.lock().unwrap().work_started).sum::<u64>();
        assert_eq!(pressure_only_work, 0);
        drop(silent);
        until(|| *intake.connections.lock().unwrap() == 0);

        // The original paid body remains live while a second listener is full
        // of incomplete unpaid Hellos. No fake verifier or budget injection.
        let raw = serde_json::to_vec(&Request::Submit { packet: hex::encode(packets[0].encode().unwrap()) }).unwrap();
        let hello = Hello { op: 1, len: raw.len(), caller: digest(identity(80).public_key()).unwrap(),
            digest: hash(b"public-request-body-v3", &[&raw]), client_nonce: [11; 32] };
        let (mut paid, cookie, _, deadline) = super::tests::paid_solution_only(addresses[0], hello, &identity(80), policy).unwrap();
        let ready: Value = serde_json::from_slice(&client_frame(&mut paid, 256, deadline).unwrap()).unwrap();
        assert_eq!(ready["cookie_digest"], hex::encode(cookie.id().unwrap()));
        until(|| *intake.mutating_grants.lock().unwrap() == 1);
        let silent: Vec<_> = (0..MAX_CONNECTIONS - 1).map(|_| TcpStream::connect(addresses[1]).unwrap()).collect();
        until(|| *intake.connections.lock().unwrap() == MAX_CONNECTIONS);
        let before_closed = metrics.iter().map(|m| m.lock().unwrap().unpaid_pressure_connections_closed).sum::<u64>();
        thread::sleep(Duration::from_millis(intake::UNPAID_PRESSURE_IDLE_MS + 30));
        assert!(call("phase2-capacity-probe", 0, &Request::Head).is_err());
        until(|| metrics.iter().map(|m| m.lock().unwrap().unpaid_pressure_connections_closed).sum::<u64>() > before_closed);
        assert_eq!(*intake.mutating_grants.lock().unwrap(), 1, "pressure must not remove paid Body");
        client_write(&mut paid, &raw, Instant::now() + Duration::from_secs(2)).unwrap();
        let bytes = client_frame(&mut paid, response_maximum(1), Instant::now() + Duration::from_secs(10)).unwrap();
        let response: Response = serde_json::from_slice(&bytes).unwrap();
        assert!(response.ok, "{}", response.value);
        assert_eq!(response.cookie_digest, hex::encode(cookie.id().unwrap()));
        assert_eq!(response.request_digest, hex::encode(hello.digest));
        verify_hex_strict(identity(71).public_key(), &response.message().unwrap(), &response.signature).unwrap();
        assert_eq!(response.value["block"], hex::encode(packets[0].id().unwrap()));
        drop(paid);
        for packet in &packets[1..] {
            assert!(call("confirmation-descendant-submit", 1, &Request::Submit { packet: hex::encode(packet.encode().unwrap()) }).unwrap().ok);
        }
        // Retain the finite unpaid sockets through signed submissions/history;
        // their original two-second deadlines are allowed to expire unchanged.
        let mut verifier = Node::open(&directory.path().join("validating-client"), settings.clone(), 1).unwrap();
        let tip = packets.last().unwrap().id().unwrap();
        let mut after = settings.genesis();
        let mut history_calls = 0;
        while after != tip {
            let reply = call("confirmation-history", 1, &Request::History { tip: hex::encode(tip), after: hex::encode(after) }).unwrap();
            assert!(reply.ok);
            let page: super::super::Page = serde_json::from_value(reply.value).unwrap();
            after = super::super::receive_page(&mut verifier, page, tip, after, clock).unwrap();
            history_calls += 1;
            assert!(history_calls <= packets.len());
        }
        assert_eq!(verifier.active().unwrap().0, tip);
        assert_eq!(
            verifier.packet(packets[0].id().unwrap()).unwrap().encode().unwrap(),
            packets[0].encode().unwrap(),
        );
        let confirmation = verifier.confirmation(transaction_id, packets[0].id().unwrap(), clock).unwrap();
        assert!(confirmation.confirmed);
        assert!(!confirmation.finalized && !confirmation.execution_authority);
        assert_eq!(owner.lock().unwrap().active().unwrap().0, tip);
        drop(silent);
        until(|| *intake.connections.lock().unwrap() == 0);
        let calls = honest_calls.into_inner();
        let ordinary_completed = calls.iter().filter(|row| row["completed"] == true).count();
        evidence = json!({
            "schema": "public-v3-unpaid-pressure-observation-v1",
            "controlled_administrator_count": 1, "independent_operators": false,
            "listeners": 2, "same_original_connection_cap": MAX_CONNECTIONS,
            "phase1_actual_unpaid_sockets": MAX_CONNECTIONS,
            "phase1_release_ns": released_ns, "original_hello_deadline_ms": PREFIX_MS,
            "phase2_paid_body_protected": true, "phase2_actual_unpaid_sockets": MAX_CONNECTIONS - 1,
            "honest_calls_offered": calls.len() + 1, "honest_calls_completed": ordinary_completed + 1,
            "honest_calls_failed": calls.len() - ordinary_completed,
            "ordinary_honest_call_observations": calls,
            "paid_body_business_call": {"offered": true, "completed": true, "server_signature_verified": true},
            "offered_cohort": "includes both intentionally full-capacity Head probes, the pre-paid business submission, all descendant submissions and all History requests",
            "unpaid_sockets_offered": MAX_CONNECTIONS * 2 - 1,
            "unique_signed_business_transactions": 1, "submitted_distinct_blocks": packets.len(),
            "history_calls": history_calls, "validated_confirmation": confirmation,
            "elapsed_wall_ns": elapsed_ns(started), "arbitrary_anonymous_flood_fairness": false,
            "scope": "finite loopback silent-input pressure; no WAN or host-wide resource isolation claim",
        });
        drop(guard);
        for worker in workers { worker.join().unwrap().unwrap(); }
    });
    for pool in [&intake.connections, &intake.body_pool, &intake.output_pool, &intake.mutating_grants, &intake.read_grants, &intake.listeners] {
        assert_eq!(*pool.lock().unwrap(), 0);
    }
    let snapshots: Vec<_> = metrics.iter().map(|m| m.lock().unwrap().clone()).collect();
    assert_eq!(snapshots.iter().map(|m| m.completed_submit).sum::<u64>(), packets.len() as u64);
    assert!(snapshots.iter().map(|m| m.unpaid_pressure_cancel_requests).sum::<u64>() >= 2);
    assert!(snapshots.iter().map(|m| m.unpaid_pressure_connections_closed).sum::<u64>() >= 2);
    assert!(snapshots.iter().all(|m| m.peak_connections <= MAX_CONNECTIONS));
    evidence["listener_metrics"] = json!(snapshots);
    evidence["original_pools_zero_after_join"] = json!(true);
    evidence["cpu_domain_actual_flow"] = serde_json::to_value(domain.observe_actual_flow().unwrap()).unwrap();
    if let Some(path) = std::env::var_os("TRNM_UNPAID_PRESSURE_REPORT") {
        let output = std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();
        serde_json::to_writer_pretty(output, &evidence).unwrap();
    }
    println!("UNPAID_PRESSURE_NATIVE {}", evidence);
}
