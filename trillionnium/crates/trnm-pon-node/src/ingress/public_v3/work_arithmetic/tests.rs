use super::*;

fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn policy() -> PublicPolicy {
    PublicPolicy::new(8, Duration::from_secs(2)).unwrap()
}
fn server() -> PublicServer {
    PublicServer::new(identity(71), policy()).unwrap()
}

#[test]
fn arithmetic_profile_has_exact_separate_bytes_and_rejects_cross_profile_challenges() {
    let policy = policy();
    assert_eq!(
        hex::encode(policy.id()),
        "c110c3ccb1e229c3a85f4819b1e087fa819c865b50f8bd3ab78d3b8f45206cb2"
    );
    assert_eq!(
        hex::encode(policy.arithmetic_facts_id()),
        "14ada27ef062b1e510b7d7ab470e83157e58e7752b8f27a754f64dac614146e3"
    );
    let settings = Settings::development(Some(1)).unwrap();
    let raw = server();
    let mut arithmetic = server().with_arithmetic_facts().unwrap();
    // Keep every other server/context/MAC input equal, so incompatibility below
    // is specifically the signed resource profile, not a changed owner epoch.
    arithmetic.secret = raw.secret;
    arithmetic.epoch = raw.epoch;
    arithmetic.started = raw.started;
    let request = serde_json::to_vec(&Request::Head).unwrap();
    let hello = Hello {
        op: 2,
        len: request.len(),
        caller: digest(identity(80).public_key()).unwrap(),
        digest: hash(b"public-request-body-v3", &[&request]),
        client_nonce: [4; 32],
    };
    let peer = "127.0.0.1:1".parse().unwrap();
    let raw_cookie = raw.cookie(&settings, hello, peer).unwrap();
    let arithmetic_cookie = arithmetic.cookie(&settings, hello, peer).unwrap();
    for (owner, own, foreign, expected) in [
        (&raw, &raw_cookie, &arithmetic_cookie, policy.id()),
        (
            &arithmetic,
            &arithmetic_cookie,
            &raw_cookie,
            policy.arithmetic_facts_id(),
        ),
    ] {
        owner.validate(own, &settings, true).unwrap();
        assert_eq!(
            owner
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
            let bytes = serde_json::to_vec(cookie).unwrap();
            assert_eq!(
                validate_challenge_context(
                    &bytes,
                    cookie,
                    &hello,
                    &settings,
                    identity(71).public_key(),
                    policy,
                    expected,
                )
                .is_ok(),
                accepted
            );
        }
    }
    assert_eq!(raw.resource_profile(), policy.id());
    assert_eq!(arithmetic.resource_profile(), policy.arithmetic_facts_id());
}

#[test]
fn explicit_arithmetic_setup_preserves_the_exact_cpu_owner_and_cold_start_credit() {
    let raw = PublicServer::new_process_cold(identity(71), policy()).unwrap();
    let original = raw.mutation_cpu.clone();
    let before = raw.mutation_cpu_domain().observe().unwrap();
    assert_eq!(before.stored_credit_ns, 0);
    assert_eq!(raw.arithmetic_facts_software_bytes(), None);
    let arithmetic = raw.with_arithmetic_facts().unwrap();
    assert!(Arc::ptr_eq(&original, &arithmetic.mutation_cpu));
    let after = arithmetic.mutation_cpu_domain().observe().unwrap();
    assert_eq!(after.stored_credit_ns, before.stored_credit_ns);
    assert_eq!(after.in_flight, before.in_flight);
    assert_eq!(after.burst_ns, before.burst_ns);
    assert_eq!(after.refill_ns_per_second, before.refill_ns_per_second);
    assert_eq!(after.start_reserve_ns, before.start_reserve_ns);
    assert_eq!(after.worker_limit, before.worker_limit);
    assert_eq!(arithmetic.arithmetic_facts.as_ref().unwrap().capacity(), 64);
    let charge = arithmetic.arithmetic_facts_software_bytes().unwrap();
    assert!(charge > 0 && charge <= MAX_ARITHMETIC_FACT_SOFTWARE_BYTES);
    assert!(matches!(
        arithmetic.with_arithmetic_facts(),
        Err(error) if error.to_string() == "PUBLIC_ARITHMETIC_FACTS_ALREADY_ENABLED"
    ));
    let fresh = server().with_arithmetic_facts().unwrap();
    assert!(!Arc::ptr_eq(&original, &fresh.mutation_cpu));
}

#[cfg(target_os = "linux")]
#[test]
fn actual_paid_arithmetic_tcp_rejects_current_bad_products_then_activates_exact_valid_packet() {
    use trnm_crypto_primitives::pon_work::{self, CELLS};

    let directory = tempfile::tempdir().unwrap();
    let clock = crate::ingress::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let source =
        Node::open_with_authenticated_state(directory.path(), settings.clone(), 1).unwrap();
    let valid = source
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            clock - 50,
            4096,
        )
        .unwrap();
    let mut bad = valid.clone();
    let offset = 4 + 2 * CELLS * 4;
    let word = u32::from_le_bytes(bad.proof[offset..offset + 4].try_into().unwrap());
    let changed = if word == 0 { 1u32 } else { 0u32 };
    bad.proof[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
    assert_eq!(
        pon_work::verify(
            bad.header.challenge(),
            bad.header.work_task,
            bad.header.target,
            &bad.proof,
        )
        .unwrap_err(),
        pon_work::WorkError::Product
    );
    let owner = super::super::tests::shared(source);
    let before = owner.lock().unwrap().read_active().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
    let observer = PublicRequestObserver::new(8).unwrap();
    let arithmetic_server = server().with_arithmetic_facts().unwrap();
    let domain = arithmetic_server.mutation_cpu_domain();
    let (node, signal, counters, observations) = (
        owner.clone(),
        stop.clone(),
        metrics.clone(),
        observer.clone(),
    );
    let worker = thread::spawn(move || {
        serve_public_protected_v3_with_request_observer(
            listener,
            node,
            Duration::from_secs(8),
            signal,
            arithmetic_server,
            counters,
            observations,
        )
    });
    let wrong_profile = call_public_protected_v3_with_deadline(
        address,
        &Request::Head,
        &settings,
        identity(71).public_key(),
        &identity(80),
        policy(),
        Some(Instant::now() + Duration::from_secs(2)),
    );
    assert!(wrong_profile.0.is_err());
    assert_eq!(
        wrong_profile.1.failed_stage,
        Some(PublicClientStage::Challenge)
    );
    for packet in [&bad, &bad] {
        let (result, _) = call_public_protected_v3_with_arithmetic_facts(
            address,
            &Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &settings,
            identity(71).public_key(),
            &identity(80),
            policy(),
            Some(Instant::now() + Duration::from_secs(2)),
        );
        let result = result.unwrap();
        assert!(!result.ok);
        assert_eq!(result.value["error"], "WORK:Product");
        assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
        assert_eq!(
            domain
                .observe_completion_work()
                .unwrap()
                .retained_identities,
            0
        );
    }
    let (result, _) = call_public_protected_v3_with_arithmetic_facts(
        address,
        &Request::Submit {
            packet: hex::encode(valid.encode().unwrap()),
        },
        &settings,
        identity(71).public_key(),
        &identity(80),
        policy(),
        Some(Instant::now() + Duration::from_secs(2)),
    );
    assert!(result.unwrap().ok);
    stop.store(true, Ordering::Release);
    let observed = worker.join().unwrap().unwrap();
    assert_eq!(observed.work_started, 3);
    assert_eq!(observed.work_finished, 3);
    assert_eq!(observed.work_failed, 2);
    assert_eq!(observed.completed_submit, 1);
    assert_eq!(observed.mutation_cpu_reservations, 3);
    assert_eq!(observed.mutation_cpu_clock_failures, 0);
    assert_eq!(observed.mutation_cpu_in_flight_after_shutdown, 0);
    assert!(observed.mutation_full_work_cpu_ns > 0);
    assert_eq!(
        observed.mutation_cpu_charged_ns,
        observed.mutation_full_work_cpu_ns + observed.mutation_dispatch_excluding_work_cpu_ns
    );
    let completion = domain.observe_completion_work().unwrap();
    assert_eq!(completion.retained_identities, 1);
    assert_eq!(completion.live_completions, 0);
    assert_eq!(completion.repeated_identity_skips, 0);
    let snapshot = observer.snapshot();
    assert!(snapshot.coverage_complete());
    let rows: Vec<_> = snapshot
        .records
        .iter()
        .filter(|row| row.full_work_started)
        .collect();
    assert_eq!(rows.len(), 3);
    for (index, row) in rows.iter().enumerate() {
        assert!(row.full_work_thread_cpu_ns.unwrap() > 0);
        assert_eq!(row.full_work_accepted, Some(index == 2));
        let outer = row.work_arithmetic.unwrap();
        assert!(outer.completed);
        assert_eq!(outer.slots, 64);
        assert!(outer.retained_software_bytes <= MAX_ARITHMETIC_FACT_SOFTWARE_BYTES);
        let actual = outer.arithmetic.unwrap();
        assert_eq!(actual.transcript_completed, index == 0);
        assert_eq!(actual.product_completed, index == 0);
        assert_eq!(actual.trace_reused, index != 0);
        assert_eq!(actual.product_reused, index != 0);
    }
    let mut independent =
        Node::open_with_authenticated_state(&directory.path().join("independent"), settings, 1)
            .unwrap();
    let id = independent.admit(&valid, clock).unwrap();
    independent.activate_observed(id, clock).unwrap();
    assert_eq!(
        owner.lock().unwrap().read_active().unwrap(),
        independent.read_active().unwrap()
    );
}

#[test]
fn warm_arithmetic_dispatch_cannot_bypass_original_abandonment_or_current_context() {
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
    let arithmetic = server().with_arithmetic_facts().unwrap();
    let facts = arithmetic.arithmetic_facts.as_ref().unwrap();
    facts
        .verify(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .unwrap();
    let owner = Mutex::new(source);
    let before = owner.lock().unwrap().read_active().unwrap();
    for (cancelled, stop, expired, expected) in [
        (true, true, true, "PUBLIC_REQUEST_CANCELLED"),
        (false, true, false, "PUBLIC_REQUEST_DEADLINE"),
        (false, false, true, "PUBLIC_REQUEST_DEADLINE"),
    ] {
        let metrics = Mutex::new(PublicMetrics::default());
        let deadline = if expired {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(2)
        };
        let result = public_dispatch(
            &owner,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            deadline,
            &AtomicBool::new(stop),
            &AtomicBool::new(cancelled),
            &metrics,
            PublicDispatchObservation {
                observation: None,
                mutation_cpu: None,
                arithmetic_facts: Some(facts),
            },
        );
        assert_eq!(result.unwrap_err().to_string(), expected);
        assert_eq!(metrics.lock().unwrap().work_started, 0);
        assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
    }
    let mut foreign = packet;
    foreign.header.network[0] ^= 1;
    let metrics = Mutex::new(PublicMetrics::default());
    let result = public_dispatch(
        &owner,
        Request::Submit {
            packet: hex::encode(foreign.encode().unwrap()),
        },
        Instant::now() + Duration::from_secs(2),
        &AtomicBool::new(false),
        &AtomicBool::new(false),
        &metrics,
        PublicDispatchObservation {
            observation: None,
            mutation_cpu: None,
            arithmetic_facts: Some(facts),
        },
    );
    assert!(result.is_err());
    assert_eq!(metrics.lock().unwrap().work_started, 0);
    assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
}

#[test]
fn original_observer_json_has_no_arithmetic_claim_and_opt_in_unfinished_is_unknown() {
    let observer = PublicRequestObserver::new(2).unwrap();
    let raw_connection = observer.connection().unwrap();
    drop(raw_connection);
    let arithmetic_connection = observer.connection().unwrap();
    let arithmetic_task = arithmetic_connection.task();
    let facts = ArithmeticFactCache::new(64).unwrap();
    arithmetic_task.work_started();
    arithmetic_task.work_arithmetic(PublicArithmeticWorkObservation::started(&facts));
    drop(arithmetic_task);
    drop(arithmetic_connection);
    let snapshot = observer.snapshot();
    let raw = serde_json::to_value(&snapshot.records[0]).unwrap();
    assert!(raw.get("work_arithmetic").is_none());
    let unfinished = &snapshot.records[1];
    assert_eq!(unfinished.full_work_accepted, None);
    assert_eq!(unfinished.full_work_thread_cpu_ns, None);
    let arithmetic = unfinished.work_arithmetic.unwrap();
    assert!(!arithmetic.completed);
    assert!(arithmetic.arithmetic.is_none());
}
