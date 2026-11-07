use super::*;

fn server(domain: Option<&ServiceMutationCpuDomain>, secret: u8) -> PublicServer {
    let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([secret; 32])).unwrap();
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    match domain {
        Some(domain) => PublicServer::with_continuous_domain(identity, policy, domain).unwrap(),
        None => PublicServer::new(identity, policy).unwrap(),
    }
}
fn wait_for_waiters(server: &PublicServer, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let observed = server.mutation_cpu.lock().unwrap().queued_start_count();
        if observed == count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "CPU waiter did not register: {observed}/{count}"
        );
        thread::yield_now();
    }
}

#[test]
fn actual_shared_server_starts_follow_oldest_waiter_across_listener_owners() {
    let first = server(None, 111);
    let domain = first.mutation_cpu_domain();
    let later = server(Some(&domain), 112);
    assert!(Arc::ptr_eq(&first.mutation_cpu, &later.mutation_cpu));
    let held_metrics = Mutex::new(PublicMetrics::default());
    let old_metrics = Mutex::new(PublicMetrics::default());
    let new_metrics = Mutex::new(PublicMetrics::default());
    // Two actual measured reservations occupy the original two worker slots.
    let held_one = PaidMutationCpuPermit::acquire(&first, &held_metrics).unwrap();
    let held_two = PaidMutationCpuPermit::acquire(&first, &held_metrics).unwrap();
    let (granted_tx, granted_rx) = mpsc::channel();
    let (release_old_tx, release_old_rx) = mpsc::channel();
    thread::scope(|scope| {
        let first_ref = &first;
        let old_metrics_ref = &old_metrics;
        let old_granted = granted_tx.clone();
        let old = scope.spawn(move || {
            let permit = PaidMutationCpuPermit::acquire_before(
                first_ref,
                old_metrics_ref,
                Instant::now() + Duration::from_secs(5),
                &Arc::new(AtomicBool::new(false)),
                &Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
            old_granted.send(1).unwrap();
            release_old_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            permit.finish(
                &MutationCpuMeasurement::default(),
                first_ref,
                old_metrics_ref,
            );
        });
        wait_for_waiters(&first, 1);
        let later_ref = &later;
        let new_metrics_ref = &new_metrics;
        let new = scope.spawn(move || {
            let permit = PaidMutationCpuPermit::acquire_before(
                later_ref,
                new_metrics_ref,
                Instant::now() + Duration::from_secs(5),
                &Arc::new(AtomicBool::new(false)),
                &Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
            granted_tx.send(2).unwrap();
            permit.finish(
                &MutationCpuMeasurement::default(),
                later_ref,
                new_metrics_ref,
            );
        });
        wait_for_waiters(&first, 2);
        held_one.finish(&MutationCpuMeasurement::default(), &first, &held_metrics);
        assert_eq!(granted_rx.recv_timeout(Duration::from_secs(3)).unwrap(), 1);
        assert!(granted_rx.try_recv().is_err());
        assert_eq!(domain.observe().unwrap().in_flight, 2);
        release_old_tx.send(()).unwrap();
        assert_eq!(granted_rx.recv_timeout(Duration::from_secs(3)).unwrap(), 2);
        old.join().unwrap();
        new.join().unwrap();
    });
    held_two.finish(&MutationCpuMeasurement::default(), &first, &held_metrics);
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    assert!(domain.accounting_available());
    assert_eq!(first.mutation_cpu.lock().unwrap().queued_start_count(), 0);
    assert_eq!(held_metrics.lock().unwrap().mutation_cpu_reservations, 2);
    assert_eq!(old_metrics.lock().unwrap().mutation_cpu_reservations, 1);
    assert_eq!(new_metrics.lock().unwrap().mutation_cpu_reservations, 1);
}

#[test]
fn cancelled_foreign_listener_head_cannot_hold_new_cpu_start_or_refund_it() {
    let first = server(None, 113);
    let domain = first.mutation_cpu_domain();
    let later = server(Some(&domain), 114);
    let stop = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let old = PendingCpuStart::register(
        first.mutation_cpu.clone(),
        Instant::now() + Duration::from_secs(5),
        stop,
        cancelled.clone(),
    )
    .unwrap();
    cancelled.store(true, Ordering::Release);
    let metrics = Mutex::new(PublicMetrics::default());
    let permit = PaidMutationCpuPermit::acquire_before(
        &later,
        &metrics,
        Instant::now() + Duration::from_secs(5),
        &Arc::new(AtomicBool::new(false)),
        &Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert_eq!(domain.observe().unwrap().in_flight, 1);
    drop(old);
    assert_eq!(domain.observe().unwrap().in_flight, 1);
    assert_eq!(first.mutation_cpu.lock().unwrap().queued_start_count(), 0);
    permit.finish(&MutationCpuMeasurement::default(), &later, &metrics);
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    assert_eq!(metrics.lock().unwrap().mutation_cpu_reservations, 1);
    assert!(domain.accounting_available());
}

#[test]
fn missing_actual_start_clock_closes_the_turn_without_start_or_credit_repair() {
    let server = server(None, 115);
    let metrics = Mutex::new(PublicMetrics::default());
    server.fail_next_cpu_start.store(true, Ordering::Release);
    let error = PaidMutationCpuPermit::acquire_before(
        &server,
        &metrics,
        Instant::now() + Duration::from_secs(5),
        &Arc::new(AtomicBool::new(false)),
        &Arc::new(AtomicBool::new(false)),
    )
    .err()
    .unwrap();
    assert_eq!(error.to_string(), "PUBLIC_MUTATION_CPU_UNAVAILABLE");
    let budget = server.mutation_cpu.lock().unwrap();
    assert!(budget.unavailable);
    assert_eq!(budget.in_flight, 0);
    assert_eq!(budget.queued_start_count(), 0);
    let measured = metrics.lock().unwrap();
    assert_eq!(measured.mutation_cpu_reservations, 0);
    assert_eq!(measured.mutation_cpu_refusals, 1);
    assert_eq!(measured.mutation_cpu_clock_failures, 1);
}
