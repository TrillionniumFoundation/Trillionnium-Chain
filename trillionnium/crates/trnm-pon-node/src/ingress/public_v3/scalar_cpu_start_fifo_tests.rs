//! Bounded start ordering controls, not an honest-service latency qualification.
//! Boundary arithmetic is explicit; concurrent controls use the actual original
//! permit and thread-CPU settlement paths without socket or task authority.
use super::super::{
    DevelopmentIdentity, MutationCpuMeasurement, PaidMutationCpuPermit, PublicMetrics,
    PublicPolicy, PublicServer,
};
use super::*;
use std::sync::mpsc;

fn server(domain: &ServiceMutationCpuDomain, key: u8) -> PublicServer {
    PublicServer::with_continuous_domain(
        DevelopmentIdentity::from_secret_hex(&hex::encode([key; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        domain,
    )
    .unwrap()
}

fn waiting(domain: &ServiceMutationCpuDomain) -> usize {
    domain
        .budget
        .lock()
        .unwrap()
        .start_waiters
        .iter()
        .filter(|id| **id != 0)
        .count()
}

fn wait_count(domain: &ServiceMutationCpuDomain, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while waiting(domain) != expected {
        assert!(
            Instant::now() < deadline,
            "FIFO waiters did not reach {expected}"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn occupied_start<'scope, 'env>(
    scope: &'scope thread::Scope<'scope, 'env>,
    domain: &'scope ServiceMutationCpuDomain,
) -> (
    mpsc::Sender<()>,
    thread::ScopedJoinHandle<'scope, ServiceMutationCpuSettlement>,
) {
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::channel();
    let worker = scope.spawn(move || {
        let operation = domain.begin().unwrap();
        ready_tx.send(()).unwrap();
        let released = release_rx.recv_timeout(Duration::from_secs(8));
        let receipt = operation.finish();
        assert!(released.is_ok(), "original live owner was not released");
        receipt
    });
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    (release_tx, worker)
}

#[test]
fn queued_start_claims_are_fifo_under_original_refill_and_worker_ceiling() {
    // Controlled Instant arithmetic: this is not measured service CPU or time.
    let budget = Arc::new(Mutex::new(PaidMutationCpuBudget::cold_start()));
    let mut first = MutationCpuStartWaiter::register(budget.clone()).unwrap();
    let mut second = MutationCpuStartWaiter::register(budget.clone()).unwrap();
    let mut third = MutationCpuStartWaiter::register(budget.clone()).unwrap();
    let mut account = budget.lock().unwrap();
    let start = account.updated;
    assert_eq!(account.credit_ns, 0);
    assert_eq!(account.in_flight, 0);
    assert!(first.is_head(&account));
    for pending in [&mut third, &mut second] {
        assert_eq!(
            pending
                .reserve(&mut account, start + Duration::from_millis(400))
                .unwrap_err()
                .to_string(),
            "PUBLIC_MUTATION_CPU_BUDGET"
        );
    }
    assert_eq!(account.credit_ns, i128::from(MUTATION_CPU_START_RESERVE_NS));
    assert!(account.reserve(start + Duration::from_millis(400)).is_err());
    first
        .reserve(&mut account, start + Duration::from_millis(400))
        .unwrap();
    assert_eq!((account.credit_ns, account.in_flight), (0, 1));
    assert!(second.is_head(&account));
    second
        .reserve(&mut account, start + Duration::from_millis(800))
        .unwrap();
    assert_eq!((account.credit_ns, account.in_flight), (0, 2));
    assert!(third
        .reserve(&mut account, start + Duration::from_millis(1200))
        .is_err());
    assert_eq!(account.in_flight, MUTATION_CPU_WORKERS);
    assert!(account.settle_observed(
        start + Duration::from_millis(1200),
        Some(10),
        Some(10),
        Some(0),
    ));
    third
        .reserve(&mut account, start + Duration::from_millis(1200))
        .unwrap();
    assert_eq!(account.start_waiters, [0; MUTATION_CPU_START_WAITERS]);
    let flow = account
        .flow
        .as_ref()
        .unwrap()
        .snapshot(account.credit_ns, account.in_flight, 0)
        .unwrap();
    assert_eq!(flow.initial_credit_ns, 0);
    assert_eq!(flow.credited_refill_ns, 300_000_000);
    assert_eq!(flow.booked_reservation_ns, 200_000_000);
    assert_eq!(flow.paid_cpu_debit_ns, 10);
    assert!(flow.balance_identity_verified);
    drop(account);
    // Claimed token drop cannot remove another waiter's id or settle CPU.
    drop((first, second, third));
    assert_eq!(budget.lock().unwrap().in_flight, 2);
}

#[test]
fn fixed_waiter_registry_reuses_only_metadata_slots_and_never_ticket_ids() {
    let domain = ServiceMutationCpuDomain::standalone();
    let original = domain.observe_actual_flow().unwrap().unwrap();
    let mut waiters = (0..MUTATION_CPU_START_WAITERS)
        .map(|_| MutationCpuStartWaiter::register(domain.budget.clone()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(MUTATION_CPU_START_WAITERS, 4);
    assert_eq!(waiting(&domain), MUTATION_CPU_START_WAITERS);
    assert_eq!(
        MutationCpuStartWaiter::register(domain.budget.clone())
            .err()
            .unwrap()
            .to_string(),
        "PUBLIC_MUTATION_CPU_BUDGET"
    );
    let removed = waiters.remove(1);
    let removed_id = removed.id.unwrap();
    drop(removed);
    let replacement = MutationCpuStartWaiter::register(domain.budget.clone()).unwrap();
    assert!(replacement.id.unwrap() > removed_id);
    assert!(replacement.id.unwrap() > waiters.last().unwrap().id.unwrap());
    assert!(!replacement.is_head(&domain.budget.lock().unwrap()));
    assert_eq!(domain.observe_actual_flow().unwrap().unwrap(), original);
    drop(waiters);
    assert!(replacement.is_head(&domain.budget.lock().unwrap()));
    drop(replacement);
    assert_eq!(waiting(&domain), 0);
    assert_eq!(domain.observe_actual_flow().unwrap().unwrap(), original);
    let restarted = PaidMutationCpuBudget::cold_start();
    assert_eq!(restarted.start_waiters, [0; MUTATION_CPU_START_WAITERS]);
    assert_eq!(restarted.credit_ns, 0);
}

#[test]
fn direct_begin_cannot_leapfrog_and_waiter_unwind_never_refunds_credit() {
    let domain = ServiceMutationCpuDomain::standalone();
    let first = MutationCpuStartWaiter::register(domain.budget.clone()).unwrap();
    assert_eq!(
        domain.clone().begin().err().unwrap().to_string(),
        "PUBLIC_MUTATION_CPU_BUDGET"
    );
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    let before = domain.observe_actual_flow().unwrap().unwrap();
    let result = std::panic::catch_unwind(|| {
        let _owned = first;
        panic!("controlled waiter unwind");
    });
    assert!(result.is_err());
    assert_eq!(waiting(&domain), 0);
    assert_eq!(domain.observe_actual_flow().unwrap().unwrap(), before);
    assert!(!domain.begin().unwrap().finish().accounting_unavailable);
}

#[test]
fn exhausted_waiter_sequence_fails_closed_without_reusing_an_order() {
    let domain = ServiceMutationCpuDomain::standalone();
    let first = MutationCpuStartWaiter::register(domain.budget.clone()).unwrap();
    domain.budget.lock().unwrap().next_start_waiter = u64::MAX;
    assert_eq!(
        MutationCpuStartWaiter::register(domain.budget.clone())
            .err()
            .unwrap()
            .to_string(),
        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
    );
    assert_eq!(waiting(&domain), 1);
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    drop(first);
    assert_eq!(waiting(&domain), 0);
    assert!(domain.observe().unwrap().accounting_unavailable);
    assert!(domain.begin().is_err());
}

#[test]
fn distinct_listener_handles_share_start_order_and_original_live_capacity() {
    let domain = ServiceMutationCpuDomain::standalone();
    let first = server(&domain, 81);
    let second = server(&domain, 82);
    let metrics = Mutex::new(PublicMetrics::default());
    let stop = AtomicBool::new(false);
    let cancelled = AtomicBool::new(false);
    thread::scope(|scope| {
        let (release_one, occupied_one) = occupied_start(scope, &domain);
        let (release_two, occupied_two) = occupied_start(scope, &domain);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_first, finish_first) = mpsc::channel();
        let first_tx = started_tx.clone();
        let first_server = &first;
        let first_metrics = &metrics;
        let first_stop = &stop;
        let first_cancelled = &cancelled;
        let first_worker = scope.spawn(move || {
            let permit = PaidMutationCpuPermit::acquire_before(
                first_server,
                first_metrics,
                Instant::now() + Duration::from_secs(5),
                first_stop,
                first_cancelled,
            )
            .unwrap();
            first_tx.send(1).unwrap();
            let released = finish_first.recv_timeout(Duration::from_secs(5));
            let measured = permit.finish(
                &MutationCpuMeasurement::default(),
                first_server,
                first_metrics,
            );
            assert!(released.is_ok());
            assert!(measured.is_some());
        });
        wait_count(&domain, 1);
        let second_worker = scope.spawn(|| {
            let permit = PaidMutationCpuPermit::acquire_before(
                &second,
                &metrics,
                Instant::now() + Duration::from_secs(5),
                &stop,
                &cancelled,
            )
            .unwrap();
            started_tx.send(2).unwrap();
            assert!(permit
                .finish(&MutationCpuMeasurement::default(), &second, &metrics)
                .is_some());
        });
        wait_count(&domain, 2);
        release_one.send(()).unwrap();
        assert!(!occupied_one.join().unwrap().accounting_unavailable);
        assert_eq!(started_rx.recv_timeout(Duration::from_secs(3)).unwrap(), 1);
        assert_eq!(domain.observe().unwrap().in_flight, MUTATION_CPU_WORKERS);
        assert_eq!(waiting(&domain), 1);
        release_first.send(()).unwrap();
        first_worker.join().unwrap();
        assert_eq!(started_rx.recv_timeout(Duration::from_secs(3)).unwrap(), 2);
        second_worker.join().unwrap();
        release_two.send(()).unwrap();
        assert!(!occupied_two.join().unwrap().accounting_unavailable);
    });
    assert_eq!(waiting(&domain), 0);
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    assert_eq!(metrics.lock().unwrap().mutation_cpu_reservations, 2);
    assert!(
        domain
            .observe_actual_flow()
            .unwrap()
            .unwrap()
            .balance_identity_verified
    );
}

#[test]
fn cancelled_stopped_and_expired_fronts_release_order_without_releasing_live_owners() {
    for reason in ["cancel", "stop", "deadline"] {
        let domain = ServiceMutationCpuDomain::standalone();
        let first = server(&domain, 83);
        let second = server(&domain, 84);
        let metrics = Mutex::new(PublicMetrics::default());
        let stop = AtomicBool::new(false);
        let cancelled = AtomicBool::new(false);
        thread::scope(|scope| {
            let (release_one, occupied_one) = occupied_start(scope, &domain);
            let (release_two, occupied_two) = occupied_start(scope, &domain);
            let first_worker = scope.spawn(|| {
                PaidMutationCpuPermit::acquire_before(
                    &first,
                    &metrics,
                    Instant::now()
                        + if reason == "deadline" {
                            Duration::from_millis(250)
                        } else {
                            Duration::from_secs(5)
                        },
                    &stop,
                    &cancelled,
                )
                .err()
                .unwrap()
                .to_string()
            });
            wait_count(&domain, 1);
            let second_worker = scope.spawn(|| {
                let permit = PaidMutationCpuPermit::acquire_before(
                    &second,
                    &metrics,
                    Instant::now() + Duration::from_secs(5),
                    &AtomicBool::new(false),
                    &AtomicBool::new(false),
                )
                .unwrap();
                permit.finish(&MutationCpuMeasurement::default(), &second, &metrics)
            });
            wait_count(&domain, 2);
            let expected = match reason {
                "cancel" => {
                    cancelled.store(true, Ordering::Release);
                    "PUBLIC_REQUEST_CANCELLED"
                }
                "stop" => {
                    stop.store(true, Ordering::Release);
                    "PUBLIC_REQUEST_DEADLINE"
                }
                _ => "PUBLIC_REQUEST_DEADLINE",
            };
            assert_eq!(first_worker.join().unwrap(), expected);
            assert_eq!(waiting(&domain), 1);
            assert_eq!(domain.observe().unwrap().in_flight, 2);
            assert_eq!(metrics.lock().unwrap().mutation_cpu_reservations, 0);
            release_one.send(()).unwrap();
            assert!(!occupied_one.join().unwrap().accounting_unavailable);
            assert!(second_worker.join().unwrap().is_some());
            release_two.send(()).unwrap();
            assert!(!occupied_two.join().unwrap().accounting_unavailable);
        });
        assert_eq!(waiting(&domain), 0);
        assert_eq!(domain.observe().unwrap().in_flight, 0);
        assert_eq!(metrics.lock().unwrap().mutation_cpu_reservations, 1);
        assert!(
            domain
                .observe_actual_flow()
                .unwrap()
                .unwrap()
                .balance_identity_verified
        );
    }
}

#[test]
fn start_clock_failure_removes_front_without_minting_a_permit_or_bypassing_failure() {
    let domain = ServiceMutationCpuDomain::standalone();
    let server = server(&domain, 85);
    let metrics = Mutex::new(PublicMetrics::default());
    server.fail_next_cpu_start.store(true, Ordering::Release);
    let error = PaidMutationCpuPermit::acquire_before(
        &server,
        &metrics,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
        &AtomicBool::new(false),
    )
    .err()
    .unwrap();
    assert_eq!(error.to_string(), "PUBLIC_MUTATION_CPU_UNAVAILABLE");
    assert_eq!(waiting(&domain), 0);
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    assert!(domain.observe().unwrap().accounting_unavailable);
    assert_eq!(metrics.lock().unwrap().mutation_cpu_reservations, 0);
    assert_eq!(metrics.lock().unwrap().mutation_cpu_clock_failures, 1);
    assert!(domain.begin().is_err());
}
