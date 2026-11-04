use super::*;
fn server(domain: &ServiceMutationCpuDomain, key: u8) -> PublicServer {
    PublicServer::with_continuous_domain(
        DevelopmentIdentity::from_secret_hex(&hex::encode([key; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        domain,
    )
    .unwrap()
}
#[test]
fn shared_domain_cannot_mint_a_second_listener_body_budget() {
    let domain = ServiceMutationCpuDomain::standalone();
    let a = server(&domain, 71);
    let b = server(&domain, 72);
    assert!(a
        .mutation_cpu_domain()
        .shares_domain_with(&b.mutation_cpu_domain()));
    let x = a.listener_intake().unwrap();
    let y = b.listener_intake().unwrap();
    let _first = BufferPermit::acquire(
        x.body_pool.clone(),
        MAX_PAID_BODY_BYTES,
        MAX_PAID_BODY_BYTES,
    )
    .unwrap();
    let second = BufferPermit::try_acquire(y.body_pool.clone(), 1, MAX_PAID_BODY_BYTES).unwrap();
    println!("SHARED_INTAKE_BASELINE existing_cpu_domain_shared=true reserved_body_bytes={} extra_listener_byte_granted={}",MAX_PAID_BODY_BYTES,second.is_some());
    assert!(
        second.is_none(),
        "a second listener recreated the entire body pool"
    );
}
#[test]
fn listener_reconstruction_reuses_all_original_pools_and_outstanding_reservations() {
    let domain = ServiceMutationCpuDomain::standalone();
    let first = server(&domain, 71).listener_intake().unwrap();
    let held = BufferPermit::acquire(
        first.body_pool.clone(),
        MAX_PAID_BODY_BYTES,
        MAX_PAID_BODY_BYTES,
    )
    .unwrap();
    for key in 72..80 {
        let other = server(&domain, key).listener_intake().unwrap();
        assert!(Arc::ptr_eq(&first, &other));
        assert!(
            BufferPermit::try_acquire(other.body_pool.clone(), 1, MAX_PAID_BODY_BYTES)
                .unwrap()
                .is_none()
        );
    }
    drop(held);
    assert!(BufferPermit::try_acquire(
        first.body_pool.clone(),
        MAX_PAID_BODY_BYTES,
        MAX_PAID_BODY_BYTES
    )
    .unwrap()
    .is_some());
}
#[test]
fn connections_outputs_and_both_lanes_share_their_original_caps() {
    let domain = ServiceMutationCpuDomain::standalone();
    let x = server(&domain, 71).listener_intake().unwrap();
    let y = server(&domain, 72).listener_intake().unwrap();
    for (a, b, cap) in [
        (
            x.connections.clone(),
            y.connections.clone(),
            MAX_CONNECTIONS,
        ),
        (
            x.output_pool.clone(),
            y.output_pool.clone(),
            MAX_OUTPUT_BYTES,
        ),
        (
            x.mutating_grants.clone(),
            y.mutating_grants.clone(),
            MAX_MUTATING_GRANTS,
        ),
        (
            x.read_grants.clone(),
            y.read_grants.clone(),
            MAX_READ_GRANTS,
        ),
    ] {
        let permit = BufferPermit::acquire(a, cap, cap).unwrap();
        assert!(BufferPermit::try_acquire(b.clone(), 1, cap)
            .unwrap()
            .is_none());
        drop(permit);
        assert!(BufferPermit::try_acquire(b, cap, cap).unwrap().is_some());
    }
}
#[test]
fn independent_operator_domains_do_not_accidentally_share_pools() {
    let a = server(&ServiceMutationCpuDomain::standalone(), 71)
        .listener_intake()
        .unwrap();
    let b = server(&ServiceMutationCpuDomain::standalone(), 72)
        .listener_intake()
        .unwrap();
    assert!(!Arc::ptr_eq(&a, &b));
    let _permit = BufferPermit::acquire(
        a.body_pool.clone(),
        MAX_PAID_BODY_BYTES,
        MAX_PAID_BODY_BYTES,
    )
    .unwrap();
    assert!(
        BufferPermit::try_acquire(b.body_pool.clone(), 1, MAX_PAID_BODY_BYTES)
            .unwrap()
            .is_some()
    );
}
#[test]
fn mutation_cannot_spend_shared_read_body_or_control_output_reserve() {
    let domain = ServiceMutationCpuDomain::standalone();
    let x = server(&domain, 71).listener_intake().unwrap();
    let y = server(&domain, 72).listener_intake().unwrap();
    for (a, b, max, reserve) in [
        (
            x.body_pool.clone(),
            y.body_pool.clone(),
            MAX_PAID_BODY_BYTES,
            READ_BODY_RESERVE,
        ),
        (
            x.output_pool.clone(),
            y.output_pool.clone(),
            MAX_OUTPUT_BYTES,
            CONTROL_OUTPUT_RESERVE,
        ),
    ] {
        let mutation = BufferPermit::acquire(a, max - reserve, max - reserve).unwrap();
        assert!(BufferPermit::try_acquire(b.clone(), 1, max - reserve)
            .unwrap()
            .is_none());
        let read = BufferPermit::acquire(b.clone(), reserve, max).unwrap();
        assert!(BufferPermit::try_acquire(b.clone(), 1, max)
            .unwrap()
            .is_none());
        drop(mutation);
        drop(read);
        assert_eq!(*b.lock().unwrap(), 0);
    }
}
#[test]
fn actual_two_listeners_use_shared_connection_slots_and_release_on_stop() {
    let dir = tempfile::tempdir().unwrap();
    let clock = super::super::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let mut native = Node::open(dir.path(), settings.clone(), 2).unwrap();
    native
        .enable_local_mempool(crate::PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: crate::development_public(0).unwrap(),
        })
        .unwrap();
    let owner = Arc::new(Mutex::new(native));
    let domain = ServiceMutationCpuDomain::standalone();
    let first = server(&domain, 71);
    let intake = first.listener_intake().unwrap();
    // Memory-only reservation models occupied capacity; no 64-socket flood.
    let held = BufferPermit::acquire(intake.connections.clone(), MAX_CONNECTIONS, MAX_CONNECTIONS)
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    struct Stop(Arc<AtomicBool>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    thread::scope(|scope| {
        let servers: Vec<_> = [first, server(&domain, 72)]
            .into_iter()
            .enumerate()
            .map(|(i, service)| {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                let node = owner.clone();
                let stopping = stop.clone();
                let counters = Arc::new(Mutex::new(PublicMetrics::default()));
                let local = counters.clone();
                (
                    address,
                    71 + i as u8,
                    counters,
                    scope.spawn(move || {
                        serve_public_protected_v3_with_metrics(
                            listener,
                            node,
                            Duration::from_secs(10),
                            stopping,
                            service,
                            local,
                        )
                    }),
                )
            })
            .collect();
        let guard = Stop(stop.clone());
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        for (address, key, _, _) in &servers {
            let caller =
                DevelopmentIdentity::from_secret_hex(&hex::encode([*key + 10; 32])).unwrap();
            let expected = DevelopmentIdentity::from_secret_hex(&hex::encode([*key; 32])).unwrap();
            assert!(call_public_protected_v3(
                *address,
                &Request::Head,
                &settings,
                expected.public_key(),
                &caller,
                policy
            )
            .is_err());
        }
        assert_eq!(*intake.connections.lock().unwrap(), MAX_CONNECTIONS);
        for (_, _, stats, _) in &servers {
            assert!(stats.lock().unwrap().capacity_refusals >= 1);
        }
        drop(held);
        for (address, key, _, _) in &servers {
            let caller =
                DevelopmentIdentity::from_secret_hex(&hex::encode([*key + 20; 32])).unwrap();
            let expected = DevelopmentIdentity::from_secret_hex(&hex::encode([*key; 32])).unwrap();
            let result = call_public_protected_v3(
                *address,
                &Request::Head,
                &settings,
                expected.public_key(),
                &caller,
                policy,
            )
            .unwrap();
            assert!(result.ok);
            assert_eq!(result.value["height"], 0);
        }
        drop(guard);
        for (_, _, _, worker) in servers {
            worker.join().unwrap().unwrap();
        }
    });
    for pool in [
        &intake.connections,
        &intake.body_pool,
        &intake.output_pool,
        &intake.mutating_grants,
        &intake.read_grants,
    ] {
        assert_eq!(*pool.lock().unwrap(), 0);
    }
    println!("SHARED_INTAKE_SOCKET listeners=2 controlled_reservations=64 over_capacity_reads_refused=2 reads_after_release=2 final_pools_zero=true network_saturation_test=false");
}

#[test]
fn one_plain_node_must_not_accept_independent_cpu_domains_through_two_real_listeners() {
    let dir = tempfile::tempdir().unwrap();
    let clock = super::super::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    node.enable_local_mempool(crate::PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: crate::development_public(0).unwrap(),
    })
    .unwrap();
    let node = Arc::new(Mutex::new(node));
    let a = PublicServer::new(
        DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let b = PublicServer::new(
        DevelopmentIdentity::from_secret_hex(&hex::encode([72; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    assert!(!a
        .mutation_cpu_domain()
        .shares_domain_with(&b.mutation_cpu_domain()));
    let a_domain = a.mutation_cpu_domain();
    let b_domain = b.mutation_cpu_domain();
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_address = first_listener.local_addr().unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    let first_stop = stopped.clone();
    let first_node = node.clone();
    let first = std::thread::spawn(move || {
        serve_public_protected_v3(
            first_listener,
            first_node,
            Duration::from_secs(5),
            first_stop,
            a,
        )
    });
    let caller = DevelopmentIdentity::from_secret_hex(&hex::encode([80; 32])).unwrap();
    let expected = DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap();
    let mut ready = false;
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until {
        if call_public_protected_v3(
            first_address,
            &Request::Head,
            &settings,
            expected.public_key(),
            &caller,
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        )
        .is_ok_and(|reply| reply.ok)
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    assert!(
        ready,
        "first local V3 server must serve a signed Head before checking a second"
    );
    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let result = serve_public_protected_v3(
        second_listener,
        node.clone(),
        Duration::from_secs(1),
        Arc::new(AtomicBool::new(false)),
        b,
    );
    stopped.store(true, Ordering::Release);
    let first_result = first.join().unwrap();
    assert!(
        first_result.is_ok(),
        "original server remains healthy: {first_result:?}"
    );
    let (original_binding, second_binding) = {
        let owner = node.lock().unwrap();
        (
            owner.continuous_domain_matches(&a_domain),
            owner.continuous_domain_matches(&b_domain),
        )
    };
    println!(
        "NODE_DOMAIN_NEGATIVE second_result={:?} original_binding={} second_binding={}",
        result.as_ref().map(|_| "ACCEPTED"),
        original_binding,
        second_binding
    );
    let error = result.unwrap_err();
    assert!(error.is(crate::error::ErrorCode::OwnerPublicServiceCpuDomain));
    // Stop the mismatched caller; the original listener/domain above stays healthy.
    assert!(error.requires_owner_stop());
    assert_eq!(
        error.to_string(),
        "OWNER_PUBLIC_SERVICE_CPU_DOMAIN",
        "a second independent budget must never attach to the same actual Node"
    );
}

#[test]
fn pinned_normal_node_recovers_same_budget_after_listener_stop_and_key_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let clock = super::super::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let mut plain = Node::open(dir.path(), settings.clone(), 2).unwrap();
    assert!(
        plain.public_service_cpu_domain().is_err(),
        "unbound owner must not manufacture a CPU budget"
    );
    plain
        .enable_local_mempool(crate::PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: crate::development_public(0).unwrap(),
        })
        .unwrap();
    let shared = Arc::new(Mutex::new(plain));
    let first = PublicServer::new(
        DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let first_domain = first.mutation_cpu_domain();
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let node = shared.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let job = std::thread::spawn(move || {
        serve_public_protected_v3(listener, node, Duration::from_secs(4), s, first)
    });
    let until = Instant::now() + Duration::from_secs(3);
    let expected = DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap();
    let caller = DevelopmentIdentity::from_secret_hex(&hex::encode([88; 32])).unwrap();
    let mut observed = false;
    while Instant::now() < until {
        if call_public_protected_v3(
            address,
            &Request::Head,
            &settings,
            expected.public_key(),
            &caller,
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        )
        .is_ok_and(|r| r.ok)
        {
            observed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    stop.store(true, Ordering::Release);
    assert!(job.join().unwrap().is_ok());
    assert!(observed);
    let retained = shared.lock().unwrap().public_service_cpu_domain().unwrap();
    assert!(retained.shares_domain_with(&first_domain));
    let _operation = retained.begin().unwrap().finish();
    let previous = retained.observe().unwrap().stored_credit_ns;
    let second = PublicServer::with_continuous_domain(
        DevelopmentIdentity::from_secret_hex(&hex::encode([72; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        &retained,
    )
    .unwrap();
    let listen = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listen.local_addr().unwrap();
    let stop2 = Arc::new(AtomicBool::new(false));
    let s2 = stop2.clone();
    let node = shared.clone();
    let job2 = std::thread::spawn(move || {
        serve_public_protected_v3(listen, node, Duration::from_secs(4), s2, second)
    });
    let expected = DevelopmentIdentity::from_secret_hex(&hex::encode([72; 32])).unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    let mut reconnected = false;
    while Instant::now() < until {
        if call_public_protected_v3(
            addr,
            &Request::Head,
            &settings,
            expected.public_key(),
            &caller,
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        )
        .is_ok_and(|r| r.ok)
        {
            reconnected = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    stop2.store(true, Ordering::Release);
    assert!(job2.join().unwrap().is_ok());
    assert!(reconnected);
    let now = retained.observe().unwrap().stored_credit_ns;
    assert!(
        now <= previous + i128::from(super::scalar_cpu::MUTATION_CPU_REFILL_NS_PER_SECOND) * 5,
        "a key-rotated listener cannot mint a fresh budget burst"
    );
    println!("NODE_DOMAIN_REUSE ordinary_services=2 exact_same_domain=true key_rotation=true");
}

#[test]
fn one_node_cannot_spawn_a_fifth_worker_queue_service_from_the_same_domain() {
    let dir = tempfile::tempdir().unwrap();
    let clock = super::super::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    node.enable_local_mempool(crate::PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: crate::development_public(0).unwrap(),
    })
    .unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&domain).unwrap();
    let owner = Arc::new(Mutex::new(node));
    let intake = server(&domain, 71).listener_intake().unwrap();
    let held = BufferPermit::acquire(
        intake.listeners.clone(),
        MAX_LISTENERS_PER_CPU_DOMAIN,
        MAX_LISTENERS_PER_CPU_DOMAIN,
    )
    .unwrap();
    let listen = TcpListener::bind("127.0.0.1:0").unwrap();
    let result = serve_public_protected_v3(
        listen,
        owner.clone(),
        Duration::from_secs(2),
        Arc::new(AtomicBool::new(false)),
        server(&domain, 72),
    );
    let error = result.unwrap_err();
    assert!(error.is(crate::error::ErrorCode::PublicListenerDomainCapacity));
    assert!(!error.requires_owner_stop());
    assert_eq!(error.to_string(), "PUBLIC_LISTENER_DOMAIN_CAPACITY");
    assert_eq!(
        *intake.listeners.lock().unwrap(),
        MAX_LISTENERS_PER_CPU_DOMAIN
    );
    drop(held);
    assert_eq!(*intake.listeners.lock().unwrap(), 0);
    let s = Arc::new(AtomicBool::new(false));
    let stop = s.clone();
    let node = owner.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let job = std::thread::spawn(move || {
        serve_public_protected_v3(
            listener,
            node,
            Duration::from_secs(4),
            stop,
            server(&domain, 72),
        )
    });
    let caller = DevelopmentIdentity::from_secret_hex(&hex::encode([90; 32])).unwrap();
    let expected = DevelopmentIdentity::from_secret_hex(&hex::encode([72; 32])).unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    let mut allowed = false;
    while Instant::now() < until {
        if call_public_protected_v3(
            address,
            &Request::Head,
            &settings,
            expected.public_key(),
            &caller,
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        )
        .is_ok_and(|r| r.ok)
        {
            allowed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    s.store(true, Ordering::Release);
    assert!(job.join().unwrap().is_ok());
    assert!(allowed);
    assert_eq!(*intake.listeners.lock().unwrap(), 0);
    println!("NODE_DOMAIN_WORKER_CAP max_listeners={} max_workers={} max_proof_queued={} max_read_queued={} fifth_refused=true recovered=true",
        MAX_LISTENERS_PER_CPU_DOMAIN,MAX_LISTENERS_PER_CPU_DOMAIN*3,
        MAX_LISTENERS_PER_CPU_DOMAIN*2,MAX_LISTENERS_PER_CPU_DOMAIN*2);
}

#[test]
fn public_cli_process_cold_start_never_receives_an_instant_fresh_cpu_or_cookie_burst() {
    for key in 90..96 {
        let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([key; 32])).unwrap();
        let policy = PublicPolicy::new(8, Duration::from_millis(2000)).unwrap();
        let server = PublicServer::new_process_cold(identity, policy).unwrap();
        let domain = server.mutation_cpu_domain();
        let state = domain.observe().unwrap();
        assert_eq!(state.stored_credit_ns, 0);
        assert_eq!(state.in_flight, 0);
        assert!(!state.accounting_unavailable);
        let intake = server.listener_intake().unwrap();
        let clock = Instant::now();
        assert!(!intake.try_challenge(2, clock).unwrap());
        assert!(intake
            .try_challenge(2, clock + Duration::from_millis(8))
            .unwrap());
        assert!(!intake
            .try_challenge(2, clock + Duration::from_millis(8))
            .unwrap());
    }
    // Historical pre-fix constructor granted this at every new Process.
    let historical = PublicServer::new(
        DevelopmentIdentity::from_secret_hex(&hex::encode([95u8; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_millis(2000)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        historical
            .mutation_cpu_domain()
            .observe()
            .unwrap()
            .stored_credit_ns,
        i128::from(super::scalar_cpu::MUTATION_CPU_BURST_NS)
    );
    println!("PROCESS_COLD_BUDGET cold_creations=6 each_initial_cpu_ns=0 each_initial_challenges=0 old_constructor_cpu_ns=2000000000");
}

#[cfg(target_os = "linux")]
#[test]
fn public_library_external_listener_cannot_bypass_the_fixed_host_kernel_parent() {
    // A wildcard-bound socket with a finite 80ms lifetime: no guest request is
    // accepted and no service is advertised. The old library entry nonetheless
    // returned a normal successful service without any fixed kernel parent.
    let dir = tempfile::tempdir().unwrap();
    let now = super::super::now().unwrap();
    let settings = Settings::development(Some(now - 100)).unwrap();
    let mut node = Node::open(dir.path(), settings, 2).unwrap();
    node.enable_local_mempool(crate::PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: crate::development_public(0).unwrap(),
    })
    .unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let svc = server(&domain, 71);
    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    assert!(!listener.local_addr().unwrap().ip().is_loopback());
    let stopped = Arc::new(AtomicBool::new(false));
    let result =
        serve_public_protected_v3(listener, owner, Duration::from_millis(80), stopped, svc);
    println!(
        "LIBRARY_EXTERNAL_BOUNDARY original_return={:?}",
        result.as_ref().map(|_| "ACCEPTED")
    );
    let error = result.unwrap_err().to_string();
    assert!(
        error.starts_with("PUBLIC_HOST_KERNEL_"),
        "direct library V3 was able to sidestep CLI-only host admission: {error}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn all_public_v3_library_wrappers_reject_external_socket_before_binding_owner_or_workers() {
    let dir = tempfile::tempdir().unwrap();
    let now = super::super::now().unwrap();
    let settings = Settings::development(Some(now - 100)).unwrap();
    let mut node = Node::open(dir.path(), settings, 2).unwrap();
    node.enable_local_mempool(crate::PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: crate::development_public(0).unwrap(),
    })
    .unwrap();
    let owner = Arc::new(Mutex::new(node));
    let domain = ServiceMutationCpuDomain::standalone();
    let intake = server(&domain, 71).listener_intake().unwrap();
    for variant in 0..3 {
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let srv = server(&domain, 71);
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let result = match variant {
            0 => serve_public_protected_v3(
                listener,
                owner.clone(),
                Duration::from_millis(80),
                stop,
                srv,
            ),
            1 => serve_public_protected_v3_with_metrics(
                listener,
                owner.clone(),
                Duration::from_millis(80),
                stop,
                srv,
                metrics.clone(),
            ),
            _ => serve_public_protected_v3_with_request_observer(
                listener,
                owner.clone(),
                Duration::from_millis(80),
                stop,
                srv,
                metrics.clone(),
                PublicRequestObserver::new(4).unwrap(),
            ),
        };
        let error = result.unwrap_err().to_string();
        assert!(
            error.starts_with("PUBLIC_HOST_KERNEL_"),
            "wrapper {variant}: {error}"
        );
        assert!(owner.lock().unwrap().public_service_cpu_domain().is_err());
        assert_eq!(*intake.listeners.lock().unwrap(), 0);
        assert_eq!(*intake.connections.lock().unwrap(), 0);
        assert_eq!(metrics.lock().unwrap().accepted_connections, 0);
    }
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    println!("EXPORTED_V3_KERNEL_PARENT wrappers=3 rejected=3 early_owner_binding=0 worker_reservations=0 guest_requests=0");
}
