use super::*;
use trnm_crypto_primitives::pon_work::{self, rejection_cache::MAX_REJECTION_CACHE_SOFTWARE_BYTES};

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
fn ordinary_default_preserves_cpu_owner_explicit_settings_and_other_profiles() {
    let mut ordinary = PublicServer::new_process_cold(identity(71), policy()).unwrap();
    let original = ordinary.mutation_cpu.clone();
    let before = ordinary.mutation_cpu_domain().observe().unwrap();
    assert_eq!(before.stored_credit_ns, 0);
    ordinary.install_default_w1_rejection_cache().unwrap();
    assert!(Arc::ptr_eq(&original, &ordinary.mutation_cpu));
    assert_eq!(ordinary.mutation_cpu_domain().observe().unwrap(), before);
    assert_eq!(ordinary.resource_profile(), policy().id());
    let cache = ordinary.w1_rejection_cache.as_ref().unwrap();
    assert_eq!(cache.capacity(), 256);
    assert_eq!(cache.lifetime(), Duration::from_secs(30));
    assert!(cache.software_bytes() > 0);
    assert!(cache.software_bytes() <= MAX_REJECTION_CACHE_SOFTWARE_BYTES);

    let exact_lifetime = Duration::from_nanos(123_456);
    let mut explicit = server().with_w1_rejection_cache(3, exact_lifetime).unwrap();
    explicit.install_default_w1_rejection_cache().unwrap();
    assert_eq!(explicit.w1_rejection_cache.as_ref().unwrap().capacity(), 3);
    assert_eq!(
        explicit.w1_rejection_cache.as_ref().unwrap().lifetime(),
        exact_lifetime
    );
    // The existing builder accepts positive fractional-millisecond TTLs. The
    // old display field must not turn that valid exact configuration into zero.
    let configured =
        PublicRejectionWorkObservation::started(explicit.w1_rejection_cache.as_ref().unwrap());
    assert_eq!(configured.lifetime_ms, 0);
    assert_eq!(configured.lifetime_seconds, 0);
    assert_eq!(configured.lifetime_subsec_nanos, 123_456);
    assert_eq!(
        Duration::new(
            configured.lifetime_seconds,
            configured.lifetime_subsec_nanos
        ),
        exact_lifetime
    );
    let mut arithmetic = server().with_arithmetic_facts().unwrap();
    arithmetic.install_default_w1_rejection_cache().unwrap();
    assert!(arithmetic.w1_rejection_cache.is_none());
    assert_eq!(
        arithmetic.resource_profile(),
        policy().arithmetic_facts_id()
    );
    let mut growth = server().with_native_growth().unwrap();
    growth.install_default_w1_rejection_cache().unwrap();
    assert!(growth.w1_rejection_cache.is_none());
    assert_eq!(growth.resource_profile(), policy().growth_id());

    let seed = zeroize::Zeroizing::new([94; 32]);
    let spki = trnm_crypto_primitives::pq_auth::PqNativeSigningKey::public_spki_from_seed(&seed);
    let key_id = trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki(&spki).unwrap();
    let identity = PqPublicIdentity::from_owned_seed(seed, key_id).unwrap();
    let mut pq = PublicServer::new_pq_history(identity, policy()).unwrap();
    pq.install_default_w1_rejection_cache().unwrap();
    assert!(pq.w1_rejection_cache.is_none());
    assert_eq!(pq.resource_profile(), policy().pq_history_id());
}

#[cfg(target_os = "linux")]
#[test]
fn default_paid_tcp_repeated_refusal_is_charged_and_valid_packet_still_replays() {
    let directory = tempfile::tempdir().unwrap();
    let clock = crate::ingress::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let source = Node::open(directory.path(), settings.clone(), 1).unwrap();
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
    let offset = 4 + 2 * pon_work::CELLS * 4;
    let word = u32::from_le_bytes(bad.proof[offset..offset + 4].try_into().unwrap());
    bad.proof[offset..offset + 4].copy_from_slice(&u32::from(word == 0).to_le_bytes());
    let mut distinct = bad.clone();
    let offset = offset + 4;
    let word = u32::from_le_bytes(distinct.proof[offset..offset + 4].try_into().unwrap());
    distinct.proof[offset..offset + 4].copy_from_slice(&u32::from(word == 0).to_le_bytes());
    for packet in [&bad, &distinct] {
        assert_eq!(
            pon_work::verify(
                packet.header.challenge(),
                packet.header.work_task,
                packet.header.target,
                &packet.proof,
            )
            .unwrap_err(),
            pon_work::WorkError::Product
        );
    }
    let owner = super::super::tests::shared(source);
    let before = owner.lock().unwrap().read_active().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
    let observer = PublicRequestObserver::new(8).unwrap();
    // No cache builder or test-only path selection: the normal serving entry
    // must install the default after its existing startup ownership checks.
    let ordinary = server();
    let domain = ordinary.mutation_cpu_domain();
    let (node, signal, counters, capture) = (
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
            ordinary,
            counters,
            capture,
        )
    });
    for packet in [&bad, &bad, &distinct] {
        let (result, _) = call_public_protected_v3_with_deadline(
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
        let reply = result.unwrap();
        assert!(!reply.ok);
        assert_eq!(reply.value["error"], "WORK:Product");
        assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
        assert_eq!(
            domain
                .observe_completion_work()
                .unwrap()
                .retained_identities,
            0
        );
    }
    let (result, _) = call_public_protected_v3_with_deadline(
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
    let actual = worker.join().unwrap().unwrap();
    assert_eq!(actual.work_started, 4);
    assert_eq!(actual.work_finished, 4);
    assert_eq!(actual.work_failed, 3);
    assert_eq!(actual.completed_submit, 1);
    assert_eq!(actual.mutation_cpu_reservations, 4);
    assert_eq!(actual.mutation_cpu_clock_failures, 0);
    assert_eq!(actual.mutation_cpu_in_flight_after_shutdown, 0);
    assert!(actual.mutation_full_work_cpu_ns > 0);
    assert_eq!(
        actual.mutation_cpu_charged_ns,
        actual.mutation_full_work_cpu_ns + actual.mutation_dispatch_excluding_work_cpu_ns
    );
    let snapshot = observer.snapshot();
    assert!(snapshot.coverage_complete());
    let rows: Vec<_> = snapshot
        .records
        .iter()
        .filter(|row| row.full_work_started)
        .collect();
    assert_eq!(rows.len(), 4);
    for (index, row) in rows.iter().enumerate() {
        assert!(row.full_work_thread_cpu_ns.unwrap() > 0);
        assert_eq!(row.full_work_accepted, Some(index == 3));
        assert!(row.work_arithmetic.is_none());
        let outer = row.work_rejection.unwrap();
        assert!(outer.completed);
        assert_eq!(outer.slots, 256);
        assert_eq!(outer.lifetime_ms, 30_000);
        assert_eq!(outer.lifetime_seconds, 30);
        assert_eq!(outer.lifetime_subsec_nanos, 0);
        assert!(outer.retained_software_bytes <= MAX_REJECTION_CACHE_SOFTWARE_BYTES);
        let cache = outer.cache.unwrap();
        assert_eq!(cache.exact_fact_found, index == 1);
        assert_eq!(cache.cached_rejection_returned, index == 1);
        assert_eq!(cache.native_verifier_started, index != 1);
        assert_eq!(cache.native_verifier_returned, index != 1);
        assert_eq!(cache.full_replay_started, index != 1);
        assert_eq!(
            cache.publication,
            if index == 0 || index == 2 {
                "retained"
            } else {
                "none"
            }
        );
    }
    let completion = domain.observe_completion_work().unwrap();
    assert_eq!(completion.retained_identities, 1);
    assert_eq!(completion.live_completions, 0);
    let active = owner.lock().unwrap().read_active().unwrap();
    drop(owner);
    let cold = Node::open(directory.path(), settings.clone(), 1).unwrap();
    assert_eq!(cold.read_active().unwrap(), active);
    let mut independent = Node::open(&directory.path().join("independent"), settings, 1).unwrap();
    let id = independent.admit(&valid, clock).unwrap();
    independent.activate_observed(id, clock).unwrap();
    assert_eq!(independent.read_active().unwrap(), active);
}

#[test]
fn warmed_refusal_keeps_original_cancellation_context_and_cpu_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let clock = crate::ingress::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let mut bad = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            clock - 50,
            4096,
        )
        .unwrap();
    let offset = 4 + 2 * pon_work::CELLS * 4;
    let word = u32::from_le_bytes(bad.proof[offset..offset + 4].try_into().unwrap());
    bad.proof[offset..offset + 4].copy_from_slice(&u32::from(word == 0).to_le_bytes());
    let owner = Mutex::new(node);
    let before = owner.lock().unwrap().read_active().unwrap();
    let mut ordinary = server();
    ordinary.install_default_w1_rejection_cache().unwrap();
    let metrics = Mutex::new(PublicMetrics::default());
    let permit = PaidMutationCpuPermit::acquire(&ordinary, &metrics).unwrap();
    let measurement = MutationCpuMeasurement::for_permit(Some(&permit));
    let result = public_dispatch(
        &owner,
        Request::Submit {
            packet: hex::encode(bad.encode().unwrap()),
        },
        Instant::now() + Duration::from_secs(2),
        &AtomicBool::new(false),
        &AtomicBool::new(false),
        &metrics,
        PublicDispatchObservation {
            observation: None,
            mutation_cpu: Some(&measurement),
            arithmetic_facts: None,
            w1_rejection_cache: ordinary.w1_rejection_cache.as_ref(),
        },
    );
    assert_eq!(result.unwrap_err().to_string(), "WORK:Product");
    assert!(permit.finish(&measurement, &ordinary, &metrics).unwrap() > 0);
    for (cancelled, stopped, expired, expected) in [
        (true, true, true, "PUBLIC_REQUEST_CANCELLED"),
        (false, true, false, "PUBLIC_REQUEST_DEADLINE"),
        (false, false, true, "PUBLIC_REQUEST_DEADLINE"),
    ] {
        let result = public_dispatch(
            &owner,
            Request::Submit {
                packet: hex::encode(bad.encode().unwrap()),
            },
            if expired {
                Instant::now()
            } else {
                Instant::now() + Duration::from_secs(2)
            },
            &AtomicBool::new(stopped),
            &AtomicBool::new(cancelled),
            &metrics,
            PublicDispatchObservation {
                observation: None,
                mutation_cpu: None,
                arithmetic_facts: None,
                w1_rejection_cache: ordinary.w1_rejection_cache.as_ref(),
            },
        );
        assert_eq!(result.unwrap_err().to_string(), expected);
    }
    let mut foreign = bad;
    foreign.header.network[0] ^= 1;
    assert!(public_dispatch(
        &owner,
        Request::Submit {
            packet: hex::encode(foreign.encode().unwrap())
        },
        Instant::now() + Duration::from_secs(2),
        &AtomicBool::new(false),
        &AtomicBool::new(false),
        &metrics,
        PublicDispatchObservation {
            observation: None,
            mutation_cpu: None,
            arithmetic_facts: None,
            w1_rejection_cache: ordinary.w1_rejection_cache.as_ref(),
        },
    )
    .is_err());
    assert_eq!(metrics.lock().unwrap().work_started, 1);
    assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
    // A retained invalid fact cannot authorize a start from a depleted domain.
    // This is a deterministic meter fault control, not measured pressure data.
    {
        let mut budget = ordinary.mutation_cpu.lock().unwrap();
        budget.credit_ns = -i128::from(MUTATION_CPU_BURST_NS);
        budget.updated = Instant::now() + Duration::from_secs(5);
    }
    let refused = PaidMutationCpuPermit::acquire_before(
        &ordinary,
        &metrics,
        Instant::now() + Duration::from_millis(10),
        &AtomicBool::new(false),
        &AtomicBool::new(false),
    );
    assert!(matches!(refused, Err(error) if error.to_string() == "PUBLIC_MUTATION_CPU_BUDGET"));
    assert_eq!(metrics.lock().unwrap().mutation_cpu_reservations, 1);
    assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
}

#[test]
fn absent_or_unfinished_rejection_observation_never_claims_a_cache_hit() {
    let observer = PublicRequestObserver::new(2).unwrap();
    drop(observer.connection().unwrap());
    let connection = observer.connection().unwrap();
    let task = connection.task();
    let cache = RejectionCache::new(256, Duration::from_secs(30)).unwrap();
    task.work_started();
    task.work_rejection(PublicRejectionWorkObservation::started(&cache));
    drop(task);
    drop(connection);
    let snapshot = observer.snapshot();
    assert!(serde_json::to_value(&snapshot.records[0])
        .unwrap()
        .get("work_rejection")
        .is_none());
    let row = &snapshot.records[1];
    assert_eq!(row.full_work_accepted, None);
    assert_eq!(row.full_work_thread_cpu_ns, None);
    let observed = row.work_rejection.unwrap();
    assert!(!observed.completed);
    assert!(observed.cache.is_none());
}
