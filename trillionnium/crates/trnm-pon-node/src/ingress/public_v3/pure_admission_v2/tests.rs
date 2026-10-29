use super::*;

fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn policy() -> PublicPolicy {
    PublicPolicy::pure_pon(Duration::from_secs(2)).unwrap()
}
fn cold() -> PublicServer {
    PublicServer::new_process_cold(identity(71), policy())
        .unwrap()
        .with_pure_admission_v2()
        .unwrap()
}

#[test]
fn signed_v2_cookies_and_responses_cannot_cross_the_original_pure_profile() {
    assert_eq!(
        hex::encode(policy().id()),
        "f2ab74afd1669afaa28160005d52697f563d690ab8c8a0a1ad34d834b7b5fd3c"
    );
    assert_eq!(
        hex::encode(policy().pure_admission_v2_id()),
        "f6854cd511f62e47b5d84dcb99b812e0f9df3f6ebe270f5d482933f1ea3bbc56"
    );
    let settings = Settings::development(Some(1)).unwrap();
    let raw = PublicServer::new_process_cold(identity(71), policy()).unwrap();
    let mut v2 = cold();
    v2.secret = raw.secret;
    v2.epoch = raw.epoch;
    v2.started = raw.started;
    let body = serde_json::to_vec(&Request::Head).unwrap();
    let hello = Hello {
        op: 2,
        len: body.len(),
        caller: [3; 32],
        digest: hash(b"public-request-body-v3", &[&body]),
        client_nonce: [7; 32],
    };
    let peer = "127.0.0.1:1".parse().unwrap();
    let old_cookie = raw.cookie(&settings, hello, peer).unwrap();
    let new_cookie = v2.cookie(&settings, hello, peer).unwrap();
    assert_ne!(policy().id(), policy().pure_admission_v2_id());
    assert_ne!(
        policy().arithmetic_facts_id(),
        policy().pure_admission_v2_id()
    );
    assert_eq!(v2.resource_profile(), policy().pure_admission_v2_id());
    for (server, own, foreign, expected) in [
        (&raw, &old_cookie, &new_cookie, policy().id()),
        (
            &v2,
            &new_cookie,
            &old_cookie,
            policy().pure_admission_v2_id(),
        ),
    ] {
        server.validate(own, &settings, true).unwrap();
        assert_eq!(
            server
                .validate(foreign, &settings, true)
                .unwrap_err()
                .to_string(),
            "PUBLIC_COOKIE_CONTEXT"
        );
        for (cookie, accepted) in [(own, true), (foreign, false)] {
            verify_hex_strict(
                identity(71).public_key(),
                &cookie.server_message().unwrap(),
                &cookie.signature,
            )
            .unwrap();
            assert_eq!(
                validate_challenge_context(
                    &serde_json::to_vec(cookie).unwrap(),
                    cookie,
                    &hello,
                    &settings,
                    identity(71).public_key(),
                    policy(),
                    expected,
                )
                .is_ok(),
                accepted
            );
        }
        let frame = response(server, &settings, own, Ok(json!({"test": true}))).unwrap();
        let mut reply: Response = serde_json::from_slice(&frame[4..]).unwrap();
        validate_response_context(
            &frame[4..],
            &reply,
            &settings,
            identity(71).public_key(),
            expected,
            own.id().unwrap(),
            hello.digest,
        )
        .unwrap();
        reply.profile = foreign.profile.clone();
        reply.signature = identity(71).sign(&reply.message().unwrap()).unwrap();
        assert_eq!(
            validate_response_context(
                &serde_json::to_vec(&reply).unwrap(),
                &reply,
                &settings,
                identity(71).public_key(),
                expected,
                own.id().unwrap(),
                hello.digest,
            )
            .unwrap_err()
            .to_string(),
            "PUBLIC_RESPONSE_CONTEXT"
        );
    }
    assert!(PublicServer::new(identity(71), PublicPolicy::development())
        .unwrap()
        .with_pure_admission_v2()
        .is_err());
    assert!(cold().with_arithmetic_facts().is_err());
    assert!(cold().with_native_growth().is_err());
    assert!(cold().with_pure_admission_v2().is_err());
}

#[test]
fn same_cold_epoch_shares_facts_and_fifo_without_credit_or_intake_reset() {
    let raw = PublicServer::new_process_cold(identity(71), policy()).unwrap();
    let domain = raw.mutation_cpu_domain();
    let before = domain.observe().unwrap();
    assert_eq!(before.stored_credit_ns, 0);
    assert!(domain.observe_pure_admission().unwrap().is_none());
    let first = raw.with_pure_admission_v2().unwrap();
    let second = PublicServer::with_continuous_domain(identity(72), policy(), &domain)
        .unwrap()
        .with_pure_admission_v2()
        .unwrap();
    assert_eq!(domain.observe().unwrap(), before);
    assert_eq!(
        domain
            .observe_actual_flow()
            .unwrap()
            .unwrap()
            .initial_credit_ns,
        0
    );
    assert!(domain.shares_domain_with(&second.mutation_cpu_domain()));
    assert!(Arc::ptr_eq(
        &first.listener_intake().unwrap(),
        &second.listener_intake().unwrap()
    ));
    assert!(Arc::ptr_eq(
        first.pure_admission_v2.as_ref().unwrap(),
        second.pure_admission_v2.as_ref().unwrap()
    ));
    let observation = domain.observe_pure_admission().unwrap().unwrap();
    assert_eq!(
        (
            observation.waiting,
            observation.registered,
            observation.started,
            observation.cancelled
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(observation.fifo_capacity, 4);
    assert_eq!(observation.arithmetic_slots, 64);
    assert!(
        observation.retained_software_bytes > 0
            && observation.retained_software_bytes <= MAX_ARITHMETIC_FACT_SOFTWARE_BYTES
    );
    let independent = cold();
    assert!(!Arc::ptr_eq(
        first.pure_admission_v2.as_ref().unwrap(),
        independent.pure_admission_v2.as_ref().unwrap()
    ));
}

#[test]
fn cross_listener_fifo_forbids_overtaking_and_releases_cancelled_positions() {
    let first = cold();
    let domain = first.mutation_cpu_domain();
    let second = PublicServer::with_continuous_domain(identity(72), policy(), &domain)
        .unwrap()
        .with_pure_admission_v2()
        .unwrap();
    let before = domain.observe().unwrap();
    let mut earlier = PureAdmissionWaiter::for_server(&first).unwrap().unwrap();
    let cancelled = PureAdmissionWaiter::for_server(&second).unwrap().unwrap();
    let mut later = PureAdmissionWaiter::for_server(&second).unwrap().unwrap();
    let last = PureAdmissionWaiter::for_server(&first).unwrap().unwrap();
    assert!(
        matches!(PureAdmissionWaiter::for_server(&second), Err(error) if error.to_string() == "PUBLIC_PURE_V2_FIFO_CAPACITY")
    );
    assert_eq!(domain.observe().unwrap(), before);
    drop(cancelled);
    let newest = PureAdmissionWaiter::for_server(&second).unwrap().unwrap();
    {
        let mut budget = first.mutation_cpu.lock().unwrap();
        let refill = budget.updated + Duration::from_millis(400);
        assert_eq!(
            later
                .reserve_turn(&mut budget, refill)
                .unwrap_err()
                .to_string(),
            "PUBLIC_PURE_V2_FIFO_TURN"
        );
        // A newcomer cannot credit or consume the first cold-start reserve.
        assert_eq!(budget.credit_ns, 0);
        earlier.reserve_turn(&mut budget, refill).unwrap();
        assert_eq!(budget.in_flight, 1);
        assert_eq!(budget.credit_ns, 0);
        assert!(!later.waiting_for_turn(&budget).unwrap());
        assert_eq!(
            later
                .reserve_turn(&mut budget, refill)
                .unwrap_err()
                .to_string(),
            "PUBLIC_MUTATION_CPU_BUDGET"
        );
        assert!(budget.settle(refill, Some(0)));
        later.reserve_turn(&mut budget, refill).unwrap();
        assert!(budget.settle(refill, Some(0)));
        assert!(newest.waiting_for_turn(&budget).unwrap());
    }
    drop(last);
    drop(newest);
    let actual = domain.observe_pure_admission().unwrap().unwrap();
    assert_eq!(
        (
            actual.waiting,
            actual.registered,
            actual.started,
            actual.cancelled
        ),
        (0, 5, 2, 3)
    );
    assert_eq!(domain.observe().unwrap().in_flight, 0);
}

#[test]
fn expired_and_cancelled_fifo_waits_do_not_strand_the_following_listener() {
    let first = cold();
    let domain = first.mutation_cpu_domain();
    let second = PublicServer::with_continuous_domain(identity(72), policy(), &domain)
        .unwrap()
        .with_pure_admission_v2()
        .unwrap();
    // Keep a prior admitted waiter in front. Enough ordinary elapsed refill is
    // available for the tested call, so it really waits for its cross-listener turn.
    let head = PureAdmissionWaiter::for_server(&first).unwrap().unwrap();
    {
        let mut budget = first.mutation_cpu.lock().unwrap();
        let now = budget.updated + Duration::from_millis(400);
        budget.refill(now);
    }
    let metrics = Mutex::new(PublicMetrics::default());
    let stop = AtomicBool::new(false);
    let cancelled = AtomicBool::new(false);
    let result = PaidMutationCpuPermit::acquire_before(
        &second,
        &metrics,
        Instant::now() + Duration::from_millis(20),
        &stop,
        &cancelled,
    );
    assert!(matches!(result, Err(error) if error.to_string() == "PUBLIC_REQUEST_DEADLINE"));
    assert_eq!(domain.observe_pure_admission().unwrap().unwrap().waiting, 1);
    thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            PaidMutationCpuPermit::acquire_before(
                &second,
                &metrics,
                Instant::now() + Duration::from_secs(2),
                &stop,
                &cancelled,
            )
            .map(|_| ())
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while domain.observe_pure_admission().unwrap().unwrap().waiting != 2 {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        cancelled.store(true, Ordering::Release);
        assert_eq!(
            waiter.join().unwrap().unwrap_err().to_string(),
            "PUBLIC_REQUEST_CANCELLED"
        );
    });
    drop(head);
    let after = domain.observe_pure_admission().unwrap().unwrap();
    assert_eq!(
        (
            after.waiting,
            after.registered,
            after.started,
            after.cancelled
        ),
        (0, 3, 0, 3)
    );
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    assert_eq!(metrics.lock().unwrap().mutation_cpu_reservations, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn unknown_cpu_clock_keeps_v2_fail_closed_and_releases_its_fifo_position() {
    let server = cold();
    let domain = server.mutation_cpu_domain();
    {
        let mut budget = server.mutation_cpu.lock().unwrap();
        let now = budget.updated + Duration::from_millis(400);
        budget.refill(now);
    }
    server.fail_next_cpu_start.store(true, Ordering::Release);
    let metrics = Mutex::new(PublicMetrics::default());
    for _ in 0..2 {
        let result = PaidMutationCpuPermit::acquire_before(
            &server,
            &metrics,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
            &AtomicBool::new(false),
        );
        assert!(
            matches!(result, Err(error) if error.to_string() == "PUBLIC_MUTATION_CPU_UNAVAILABLE")
        );
        assert!(!domain.accounting_available());
        assert_eq!(domain.observe().unwrap().in_flight, 0);
        assert_eq!(domain.observe_pure_admission().unwrap().unwrap().waiting, 0);
    }
    let metrics = metrics.lock().unwrap();
    assert_eq!(metrics.mutation_cpu_reservations, 0);
    assert_eq!(metrics.mutation_cpu_refusals, 2);
    assert_eq!(metrics.mutation_cpu_clock_failures, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn cross_listener_false_trace_facts_reject_new_claims_and_valid_work_still_replays_native() {
    use trnm_crypto_primitives::pon_work;
    let directory = tempfile::tempdir().unwrap();
    let clock = crate::ingress::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let source =
        Node::open_with_authenticated_state(directory.path(), settings.clone(), 1).unwrap();
    let packet = source
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            clock - 50,
            4096,
        )
        .unwrap();
    let offset = pon_work::PROOF_BYTES - 32;
    let bad_claims: Vec<_> = (0u64..4096)
        .map(|n| pon_work::hash(b"pure-pon-v2-negative-trace", &[&n.to_le_bytes()]))
        .filter(|trace| {
            trace.as_slice() != &packet.proof[offset..]
                && pon_work::hash(b"ticket", &[&packet.header.challenge(), trace])
                    <= packet.header.target
        })
        .take(2)
        .collect();
    assert_eq!(bad_claims.len(), 2);
    let mut invalid = [packet.clone(), packet.clone()];
    for (candidate, trace) in invalid.iter_mut().zip(bad_claims) {
        candidate.proof[offset..].copy_from_slice(&trace);
    }
    let owner = super::super::tests::shared(source);
    let before = owner.lock().unwrap().read_active().unwrap();
    let first = cold();
    let domain = first.mutation_cpu_domain();
    let second = PublicServer::with_continuous_domain(identity(72), policy(), &domain)
        .unwrap()
        .with_pure_admission_v2()
        .unwrap();
    assert_eq!(domain.observe().unwrap().stored_credit_ns, 0);
    let observer = PublicRequestObserver::new(16).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    struct Stop(Arc<AtomicBool>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    thread::scope(|scope| {
        let _guard = Stop(stop.clone());
        let mut addresses = Vec::new();
        let mut workers = Vec::new();
        for server in [first, second] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            addresses.push(listener.local_addr().unwrap());
            let owner = owner.clone();
            let stop = stop.clone();
            let observer = observer.clone();
            workers.push(scope.spawn(move || {
                serve_public_protected_v3_with_request_observer(
                    listener,
                    owner,
                    Duration::from_secs(15),
                    stop,
                    server,
                    Arc::new(Mutex::new(PublicMetrics::default())),
                    observer,
                )
            }));
        }
        let (wrong_profile, wrong_metrics) = call_public_protected_v3_with_deadline(
            addresses[0],
            &Request::Head,
            &settings,
            identity(71).public_key(),
            &identity(80),
            policy(),
            Some(Instant::now() + Duration::from_secs(2)),
        );
        assert_eq!(
            wrong_profile.unwrap_err().to_string(),
            "PUBLIC_CHALLENGE_CONTEXT"
        );
        assert_eq!(wrong_metrics.solution_trials, 0);
        for (index, invalid) in invalid.iter().enumerate() {
            let (reply, metrics) = call_public_pure_pon_v2(
                addresses[index],
                &Request::Submit {
                    packet: hex::encode(invalid.encode().unwrap()),
                },
                &settings,
                identity(71 + index as u8).public_key(),
                &identity(80),
                policy(),
                Some(Instant::now() + Duration::from_secs(2)),
            );
            let reply = reply.unwrap();
            assert!(!reply.ok);
            assert_eq!(reply.value["error"], "WORK:Transcript");
            assert_eq!(metrics.solution_trials, 0);
            assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
            assert_eq!(
                domain
                    .observe_completion_work()
                    .unwrap()
                    .retained_identities,
                0
            );
        }
        // The warm shared fact is never a current-context/native authority cache.
        let mut foreign = packet.clone();
        foreign.header.network[0] ^= 1;
        let (reply, metrics) = call_public_pure_pon_v2(
            addresses[1],
            &Request::Submit {
                packet: hex::encode(foreign.encode().unwrap()),
            },
            &settings,
            identity(72).public_key(),
            &identity(80),
            policy(),
            Some(Instant::now() + Duration::from_secs(2)),
        );
        assert!(!reply.unwrap().ok);
        assert_eq!(metrics.solution_trials, 0);
        assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
        let (reply, metrics) = call_public_pure_pon_v2(
            addresses[1],
            &Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &settings,
            identity(72).public_key(),
            &identity(80),
            policy(),
            Some(Instant::now() + Duration::from_secs(2)),
        );
        assert!(reply.unwrap().ok);
        assert_eq!(metrics.solution_trials, 0);
        stop.store(true, Ordering::Release);
        let finished: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap().unwrap())
            .collect();
        assert_eq!(finished.iter().map(|m| m.work_started).sum::<u64>(), 3);
        assert_eq!(finished.iter().map(|m| m.work_failed).sum::<u64>(), 2);
        assert_eq!(finished.iter().map(|m| m.completed_submit).sum::<u64>(), 1);
        for actual in finished {
            assert_eq!(actual.mutation_cpu_clock_failures, 0);
            assert_eq!(actual.mutation_cpu_in_flight_after_shutdown, 0);
            assert_eq!(
                actual.mutation_cpu_charged_ns,
                actual.mutation_full_work_cpu_ns + actual.mutation_dispatch_excluding_work_cpu_ns
            );
        }
    });
    let snapshot = observer.snapshot();
    assert!(snapshot.coverage_complete());
    let rows: Vec<_> = snapshot
        .records
        .iter()
        .filter(|r| r.full_work_started)
        .collect();
    assert_eq!(rows.len(), 3);
    for (index, row) in rows.iter().enumerate() {
        assert!(row.full_work_thread_cpu_ns.unwrap() > 0);
        assert_eq!(row.full_work_accepted, Some(index == 2));
        let actual = row.work_arithmetic.unwrap();
        assert!(actual.completed);
        let actual = actual.arithmetic.unwrap();
        assert_eq!(actual.trace_reused, index == 1);
        assert_eq!(actual.transcript_completed, index != 1);
        assert_eq!(actual.product_completed, index == 2);
    }
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.initial_credit_ns, 0);
    assert!(flow.paid_cpu_debit_ns > 0);
    assert_eq!(flow.live_owners, 0);
    assert_eq!(domain.observe_pure_admission().unwrap().unwrap().waiting, 0);
    let mut independent =
        Node::open_with_authenticated_state(&directory.path().join("independent"), settings, 1)
            .unwrap();
    let id = independent.admit(&packet, clock).unwrap();
    independent.activate_observed(id, clock).unwrap();
    assert_eq!(
        owner.lock().unwrap().read_active().unwrap(),
        independent.read_active().unwrap()
    );
}
