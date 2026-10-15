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
