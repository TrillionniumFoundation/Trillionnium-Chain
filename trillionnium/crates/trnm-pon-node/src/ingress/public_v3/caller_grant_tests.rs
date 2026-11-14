//! Actual authenticated caller pressure; distinct keys can still saturate the
//! original global allowance. This does not qualify anonymous-service fairness.
use super::*;

fn identity(key: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([key; 32])).unwrap()
}
fn until(predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "original reactor did not progress"
        );
        thread::sleep(Duration::from_millis(2));
    }
}
fn hello(caller: &DevelopmentIdentity, nonce: u8) -> Hello {
    Hello {
        op: 1,
        len: 1,
        caller: digest(caller.public_key()).unwrap(),
        digest: hash(b"public-request-body-v3", &[b"x"]),
        client_nonce: [nonce; 32],
    }
}

fn paid_grant(
    address: SocketAddr,
    hello: Hello,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
) -> Result<TcpStream> {
    let (mut socket, cookie, _, deadline) =
        super::tests::paid_solution_only(address, hello, caller, policy)?;
    let ready: Value = serde_json::from_slice(&client_frame(&mut socket, 256, deadline)?)?;
    ensure(
        ready["cookie_digest"] == hex::encode(cookie.id()?),
        "PUBLIC_READY",
    )?;
    Ok(socket)
}

#[test]
fn same_authenticated_caller_cannot_hold_a_third_paid_mutation_grant_across_listeners() {
    let directory = tempfile::tempdir().unwrap();
    let clock = super::super::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let source = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let packet = source
        .make(
            source.active().unwrap().0,
            vec![],
            crate::development_public(0).unwrap(),
            clock - 50,
            4096,
        )
        .unwrap();
    let packet_bytes = packet.encode().unwrap();
    let packet_id = packet.id().unwrap();
    let owner = super::tests::shared(source);
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let first = PublicServer::with_continuous_domain(identity(71), policy, &domain).unwrap();
    let intake = first.listener_intake().unwrap();
    let second = PublicServer::with_continuous_domain(identity(71), policy, &domain).unwrap();
    let listeners = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let addresses = listeners
        .each_ref()
        .map(|listener| listener.local_addr().unwrap());
    let metrics = [
        Arc::new(Mutex::new(PublicMetrics::default())),
        Arc::new(Mutex::new(PublicMetrics::default())),
    ];
    let stop = Arc::new(AtomicBool::new(false));
    struct Stop(Arc<AtomicBool>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    thread::scope(|scope| {
        let workers: Vec<_> = listeners
            .into_iter()
            .zip([first, second])
            .enumerate()
            .map(|(index, (listener, service))| {
                let (node, stopping, counters) =
                    (owner.clone(), stop.clone(), metrics[index].clone());
                scope.spawn(move || {
                    serve_public_protected_v3_with_metrics(
                        listener,
                        node,
                        Duration::from_secs(10),
                        stopping,
                        service,
                        counters,
                    )
                })
            })
            .collect();
        let guard = Stop(stop.clone());
        until(|| *intake.listeners.lock().unwrap() == 2);
        let caller = identity(80);
        let mut held = Vec::new();
        for (index, address) in addresses.iter().enumerate() {
            held.push(paid_grant(*address, hello(&caller, index as u8), &caller, policy).unwrap());
        }
        assert_eq!(*intake.mutating_grants.lock().unwrap(), 2);
        let third = paid_grant(addresses[1], hello(&caller, 2), &caller, policy);
        assert!(
            third.is_err(),
            "one authenticated caller obtained a third paid mutation grant through another listener"
        );
        assert_eq!(*intake.mutating_grants.lock().unwrap(), 2);
        assert_eq!(
            metrics
                .iter()
                .map(|m| m.lock().unwrap().caller_mutation_capacity_refusals)
                .sum::<u64>(),
            1,
            "the third refusal must be the caller cap, not unrelated socket failure"
        );
        assert_eq!(
            intake.caller_mutation_usage().unwrap(),
            BTreeMap::from([(digest(caller.public_key()).unwrap(), 2)])
        );
        // Another caller completes the real full-W1/native admission while the
        // first caller still holds both paid bodies. No verifier or CPU injection.
        let other = identity(81);
        let submitted = call_public_protected_v3(
            addresses[1],
            &Request::Submit {
                packet: hex::encode(&packet_bytes),
            },
            &settings,
            identity(71).public_key(),
            &other,
            policy,
        )
        .unwrap();
        assert!(submitted.ok, "{}", submitted.value);
        assert_eq!(submitted.value["block"], hex::encode(packet_id));
        {
            let native = owner.lock().unwrap();
            assert_eq!(native.active().unwrap().0, packet_id);
            assert_eq!(
                native.packet(packet_id).unwrap().encode().unwrap(),
                packet_bytes
            );
        }
        until(|| *intake.mutating_grants.lock().unwrap() == 2);
        held.push(paid_grant(addresses[1], hello(&other, 3), &other, policy).unwrap());
        assert_eq!(*intake.mutating_grants.lock().unwrap(), 3);
        assert!(
            call_public_protected_v3(
                addresses[0],
                &Request::Head,
                &settings,
                identity(71).public_key(),
                &caller,
                policy,
            )
            .unwrap()
            .ok
        );
        drop(held.remove(0));
        until(|| *intake.mutating_grants.lock().unwrap() == 2);
        held.push(paid_grant(addresses[0], hello(&caller, 4), &caller, policy).unwrap());
        assert_eq!(*intake.mutating_grants.lock().unwrap(), 3);
        assert_eq!(
            metrics
                .iter()
                .map(|m| m.lock().unwrap().work_started)
                .sum::<u64>(),
            1,
            "only the distinct caller's real Submit may start native W1"
        );
        drop(held);
        until(|| *intake.mutating_grants.lock().unwrap() == 0);
        drop(guard);
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
    });
    assert!(intake.caller_mutation_usage().unwrap().is_empty());
    assert_eq!(
        metrics
            .iter()
            .map(|m| m.lock().unwrap().completed_submit)
            .sum::<u64>(),
        1
    );
    assert_eq!(
        metrics
            .iter()
            .map(|m| m.lock().unwrap().work_failed)
            .sum::<u64>(),
        0
    );
    for pool in [
        &intake.connections,
        &intake.body_pool,
        &intake.output_pool,
        &intake.mutating_grants,
        &intake.read_grants,
    ] {
        assert_eq!(*pool.lock().unwrap(), 0);
    }
}

#[test]
fn unverified_caller_claims_never_allocate_grants_and_malformed_body_releases_them() {
    let directory = tempfile::tempdir().unwrap();
    let clock = super::super::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let node = super::tests::shared(Node::open(directory.path(), settings, 1).unwrap());
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let server = PublicServer::new(identity(71), policy).unwrap();
    let intake = server.listener_intake().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
    let stop = Arc::new(AtomicBool::new(false));
    struct Stop(Arc<AtomicBool>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    thread::scope(|scope| {
        let (signal, counters) = (stop.clone(), metrics.clone());
        let worker = scope.spawn(move || {
            serve_public_protected_v3_with_metrics(
                listener,
                node,
                Duration::from_secs(10),
                signal,
                server,
                counters,
            )
        });
        let guard = Stop(stop.clone());
        let caller = identity(80);
        let mut unpaid = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        client_write(&mut unpaid, &hello(&caller, 1).encode(), deadline).unwrap();
        let challenge: Cookie =
            serde_json::from_slice(&client_frame(&mut unpaid, 2048, deadline).unwrap()).unwrap();
        verify_hex_strict(
            identity(71).public_key(),
            &challenge.server_message().unwrap(),
            &challenge.signature,
        )
        .unwrap();
        assert!(intake.caller_mutation_usage().unwrap().is_empty());
        assert_eq!(*intake.mutating_grants.lock().unwrap(), 0);
        drop(unpaid);
        assert!(paid_grant(address, hello(&caller, 2), &identity(81), policy).is_err());
        until(|| metrics.lock().unwrap().signature_refusals == 1);
        assert!(intake.caller_mutation_usage().unwrap().is_empty());
        assert_eq!(metrics.lock().unwrap().caller_mutation_capacity_refusals, 0);
        let mut paid = paid_grant(address, hello(&caller, 3), &caller, policy).unwrap();
        assert_eq!(
            intake
                .caller_mutation_usage()
                .unwrap()
                .values()
                .copied()
                .sum::<usize>(),
            1
        );
        paid.write_all(b"x").unwrap();
        let refusal: Response = serde_json::from_slice(
            &client_frame(
                &mut paid,
                MAX_RESPONSE,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!refusal.ok);
        verify_hex_strict(
            identity(71).public_key(),
            &refusal.message().unwrap(),
            &refusal.signature,
        )
        .unwrap();
        drop(paid);
        until(|| intake.caller_mutation_usage().unwrap().is_empty());
        assert_eq!(metrics.lock().unwrap().work_started, 0);
        let retry = paid_grant(address, hello(&caller, 4), &caller, policy).unwrap();
        drop(retry);
        until(|| intake.caller_mutation_usage().unwrap().is_empty());
        drop(guard);
        worker.join().unwrap().unwrap();
    });
    assert_eq!(*intake.mutating_grants.lock().unwrap(), 0);
    assert_eq!(*intake.body_pool.lock().unwrap(), 0);
    assert!(intake.caller_mutation_usage().unwrap().is_empty());
}

// The following tests directly exercise the private post-authentication grant
// transition and lifetime. They make no signature or native-work claim.
fn cookie(server: &PublicServer, caller: u8, op: u8) -> Cookie {
    let mut h = hello(&identity(caller), caller);
    h.op = op;
    server
        .cookie(
            &Settings::development(Some(1)).unwrap(),
            h,
            "127.0.0.1:1".parse().unwrap(),
        )
        .unwrap()
}
fn server() -> PublicServer {
    PublicServer::new(
        identity(71),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap()
}

#[test]
fn caller_grant_lives_until_last_connection_and_task_owner_and_error_drop() {
    let server = server();
    let intake = server.listener_intake().unwrap();
    let c = cookie(&server, 80, 1);
    let (first, first_body) = try_authenticated_paid_permits(&c, &intake)
        .unwrap()
        .unwrap();
    let (second, second_body) = try_authenticated_paid_permits(&c, &intake)
        .unwrap()
        .unwrap();
    let connection = Arc::new(first);
    let task = connection.clone();
    drop(connection);
    assert_eq!(
        try_authenticated_paid_permits(&c, &intake)
            .err()
            .unwrap()
            .code(),
        Some(crate::ErrorCode::PublicCallerMutationCapacity)
    );
    assert_eq!(*intake.mutating_grants.lock().unwrap(), 2);
    // Releasing a disconnected connection alone did not refund its live task.
    drop(first_body);
    drop(task);
    assert_eq!(
        intake
            .caller_mutation_usage()
            .unwrap()
            .values()
            .copied()
            .sum::<usize>(),
        1
    );
    let failed_ready: Result<()> = (|| {
        let _original_permits = try_authenticated_paid_permits(&c, &intake)?.unwrap();
        Err("TEST_READY_ENCODING_FAILED".into())
    })();
    assert!(failed_ready.is_err());
    assert_eq!(
        intake
            .caller_mutation_usage()
            .unwrap()
            .values()
            .copied()
            .sum::<usize>(),
        1
    );
    assert_eq!(*intake.mutating_grants.lock().unwrap(), 1);
    assert_eq!(*intake.body_pool.lock().unwrap(), 3);
    drop((second_body, second));
    assert!(intake.caller_mutation_usage().unwrap().is_empty());
    assert_eq!(*intake.mutating_grants.lock().unwrap(), 0);
    assert_eq!(*intake.body_pool.lock().unwrap(), 0);
}

#[test]
fn caller_grants_keep_original_global_cap_read_reserve_and_failed_body_rollback() {
    let server = server();
    let intake = server.listener_intake().unwrap();
    let mut held = Vec::new();
    // Four distinct identities can still fill the original eight slots. This
    // explicitly preserves the Sybil/global-saturation limitation.
    for index in 0..MAX_MUTATING_GRANTS {
        let c = cookie(&server, 80 + (index / 2) as u8, 1);
        held.push(
            try_authenticated_paid_permits(&c, &intake)
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(*intake.mutating_grants.lock().unwrap(), MAX_MUTATING_GRANTS);
    assert_eq!(intake.caller_mutation_usage().unwrap().len(), 4);
    assert!(
        try_authenticated_paid_permits(&cookie(&server, 90, 1), &intake)
            .unwrap()
            .is_none()
    );
    assert_eq!(intake.caller_mutation_usage().unwrap().len(), 4);
    let read = try_authenticated_paid_permits(&cookie(&server, 80, 2), &intake)
        .unwrap()
        .unwrap();
    assert_eq!(*intake.read_grants.lock().unwrap(), 1);
    assert_eq!(intake.caller_mutation_usage().unwrap().len(), 4);
    drop((held, read));
    assert!(intake.caller_mutation_usage().unwrap().is_empty());

    let bulk = BufferPermit::acquire(
        intake.body_pool.clone(),
        MAX_PAID_BODY_BYTES - READ_BODY_RESERVE,
        MAX_PAID_BODY_BYTES - READ_BODY_RESERVE,
    )
    .unwrap();
    assert!(
        try_authenticated_paid_permits(&cookie(&server, 80, 1), &intake)
            .unwrap()
            .is_none()
    );
    assert_eq!(*intake.mutating_grants.lock().unwrap(), 0);
    assert!(intake.caller_mutation_usage().unwrap().is_empty());
    let read = try_authenticated_paid_permits(&cookie(&server, 80, 2), &intake)
        .unwrap()
        .unwrap();
    assert_eq!(*intake.read_grants.lock().unwrap(), 1);
    drop((bulk, read));
    assert_eq!(*intake.body_pool.lock().unwrap(), 0);
}

#[test]
fn caller_cap_is_shared_by_submit_pool_and_growth_costly_operations() {
    let server = server();
    let intake = server.listener_intake().unwrap();
    let growth = PublicServer::with_continuous_domain(
        identity(72),
        server.policy,
        &server.mutation_cpu_domain(),
    )
    .unwrap()
    .with_native_growth()
    .unwrap();
    assert!(Arc::ptr_eq(&intake, &growth.listener_intake().unwrap()));
    let first = try_authenticated_paid_permits(&cookie(&server, 80, 1), &intake)
        .unwrap()
        .unwrap();
    let second = try_authenticated_paid_permits(&cookie(&server, 80, 4), &intake)
        .unwrap()
        .unwrap();
    for op in [1, 4, 6, 7] {
        let profile = if op >= 6 { &growth } else { &server };
        assert_eq!(
            try_authenticated_paid_permits(&cookie(profile, 80, op), &intake)
                .err()
                .unwrap()
                .code(),
            Some(crate::ErrorCode::PublicCallerMutationCapacity)
        );
    }
    for op in [2, 3, 5, 8] {
        let profile = if op == 8 { &growth } else { &server };
        let read = try_authenticated_paid_permits(&cookie(profile, 80, op), &intake)
            .unwrap()
            .unwrap();
        assert_eq!(
            intake
                .caller_mutation_usage()
                .unwrap()
                .values()
                .copied()
                .sum::<usize>(),
            2
        );
        drop(read);
    }
    drop((first, second));
    assert!(intake.caller_mutation_usage().unwrap().is_empty());
}

#[test]
fn concurrent_caller_grants_linearize_across_the_shared_intake() {
    let server = server();
    let intake = server.listener_intake().unwrap();
    let c = cookie(&server, 80, 1);
    let barrier = Arc::new(std::sync::Barrier::new(5));
    thread::scope(|scope| {
        let (sent, received) = mpsc::channel();
        let mut releases = Vec::new();
        let mut workers = Vec::new();
        for _ in 0..4 {
            let intake = intake.clone();
            let c = c.clone();
            let barrier = barrier.clone();
            let sent = sent.clone();
            let (release, wait) = mpsc::channel::<()>();
            releases.push(release);
            workers.push(scope.spawn(move || {
                barrier.wait();
                let outcome = try_authenticated_paid_permits(&c, &intake);
                sent.send((
                    outcome.as_ref().is_ok_and(|value| value.is_some()),
                    outcome.as_ref().err().and_then(|error| error.code()),
                ))
                .unwrap();
                // Sender drop releases every worker on parent assertion panic.
                let _ = wait.recv();
                drop(outcome);
            }));
        }
        drop(sent);
        barrier.wait();
        let rows = (0..4)
            .map(|_| received.recv_timeout(Duration::from_secs(2)).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.iter().filter(|row| row.0).count(), 2);
        assert_eq!(
            rows.iter()
                .filter(|row| row.1 == Some(crate::ErrorCode::PublicCallerMutationCapacity))
                .count(),
            2
        );
        assert_eq!(*intake.mutating_grants.lock().unwrap(), 2);
        assert_eq!(*intake.body_pool.lock().unwrap(), 6);
        assert_eq!(
            intake
                .caller_mutation_usage()
                .unwrap()
                .values()
                .copied()
                .sum::<usize>(),
            2
        );
        drop(releases);
        for worker in workers {
            worker.join().unwrap();
        }
    });
    assert!(intake.caller_mutation_usage().unwrap().is_empty());
    assert_eq!(*intake.mutating_grants.lock().unwrap(), 0);
    assert_eq!(*intake.body_pool.lock().unwrap(), 0);
}

#[test]
fn resource_revision_r20_has_exact_caller_limit_and_fresh_signed_identifiers() {
    assert_eq!(intake::MAX_CALLER_MUTATION_GRANTS, 2);
    assert_eq!(MAX_MUTATING_GRANTS, 8);
    assert_eq!(MAX_READ_GRANTS, 8);
    assert_eq!(MUTATION_CPU_WORKERS, 2);
    for (bits, expected, previous) in [
        (
            8,
            "ae83a59b214d10a93bccd557b3c9b20c05742648a52414bc3a2d32ecf03469cb",
            "0f3f0e42d13eb44419c55538198d7bee00206d62c067287e0b9dada7e9d19751",
        ),
        (
            12,
            "3f88d9d9eb972e2512c39001b34f4678af5ef34c4a2362e6b69090184c1ce203",
            "648bca6f6241e5f31e2fe13f414a60cfcb9d3b030885ab3a2127ba7f425c64c6",
        ),
        (
            16,
            "59ee63889ec8f95e2bd6c45789bf7b5ff3b916cf1244a4970f8744ee49bb175b",
            "33ad551362c92985fdd794b4117898abf9ae800b2a5cd482af025014c66b4ff4",
        ),
    ] {
        let policy = PublicPolicy::new(bits, Duration::from_secs(2)).unwrap();
        assert_eq!(hex::encode(policy.id()), expected);
        assert_ne!(hex::encode(policy.id()), previous);
    }
}
