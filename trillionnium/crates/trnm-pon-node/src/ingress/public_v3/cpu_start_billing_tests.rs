//! Deterministic ledger controls plus short actual-thread interval checks.
//! These controls establish accounting scope, not throughput or service SLOs.
use super::*;
use crate::ingress::public_v3::{
    scalar_cpu::{
        CpuFlow, ServiceMutationCpuDomain, ServiceMutationCpuFlowObservation,
        MUTATION_CPU_BURST_NS, MUTATION_CPU_START_RESERVE_NS,
    },
    DevelopmentIdentity, MutationCpuMeasurement, PaidMutationCpuPermit, PendingCpuStart,
    PublicMetrics, PublicPolicy, PublicServer,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

pub(super) fn fresh_account(initial: i128) -> Arc<Mutex<PaidMutationCpuBudget>> {
    let mut budget = PaidMutationCpuBudget::new();
    budget.credit_ns = initial;
    budget.flow = Some(CpuFlow::new(initial));
    // Exclude real-time refill from these exact ledger identities.
    budget.updated = Instant::now() + Duration::from_secs(3600);
    Arc::new(Mutex::new(budget))
}
pub(super) fn flow(
    account: &Arc<Mutex<PaidMutationCpuBudget>>,
) -> ServiceMutationCpuFlowObservation {
    let budget = account.lock().unwrap();
    assert!(!budget.unavailable);
    budget
        .flow
        .as_ref()
        .unwrap()
        .snapshot(
            budget.credit_ns,
            budget.in_flight,
            budget.termination_reserved_ns,
        )
        .unwrap()
}
pub(super) fn consume_actual_cpu() {
    let begin = ThreadCpuStamp::start().unwrap();
    while begin.clone().finish().unwrap() < 100_000 {
        std::hint::black_box(41_u64.wrapping_mul(73));
    }
}
pub(super) fn server(account: &Arc<Mutex<PaidMutationCpuBudget>>) -> PublicServer {
    let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([119; 32])).unwrap();
    PublicServer::with_continuous_domain(
        identity,
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        &ServiceMutationCpuDomain::from_shared(account.clone()),
    )
    .unwrap()
}

#[test]
fn admission_debit_has_no_reserve_refund_or_unsettled_live_owner() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    {
        let mut budget = account.lock().unwrap();
        let now = budget.updated;
        budget.charge_admission_wait(now, 41).unwrap();
        assert_eq!(budget.in_flight, 0);
        assert_eq!(budget.credit_ns, i128::from(MUTATION_CPU_BURST_NS) - 41);
    }
    let paid = flow(&account);
    assert_eq!(
        paid.schema,
        "public-v3-local-actual-cpu-flow-admission-wait-v3"
    );
    assert_eq!(paid.admission_wait_cpu_ns, 41);
    assert_eq!(paid.paid_cpu_debit_ns, 41);
    assert_eq!(paid.booked_reservation_ns, 0);
    assert_eq!(paid.live_debited_cpu_ns, 0);
    assert_eq!(paid.settled_full_cpu_ns, 0);
    assert_eq!(paid.unsettled_known_live_cpu_ns, 0);
}

#[test]
fn wait_debt_changes_original_start_eligibility_without_extra_credit() {
    let account = fresh_account(i128::from(MUTATION_CPU_START_RESERVE_NS));
    {
        let mut budget = account.lock().unwrap();
        let now = budget.updated;
        budget.charge_admission_wait(now, 1).unwrap();
        assert_eq!(
            budget.reserve(now).unwrap_err().to_string(),
            "PUBLIC_MUTATION_CPU_BUDGET"
        );
        budget
            .charge_admission_wait(now, MUTATION_CPU_START_RESERVE_NS)
            .unwrap();
        assert_eq!(budget.credit_ns, -1);
        assert_eq!(budget.in_flight, 0);
        assert_eq!(
            budget.reserve(now).unwrap_err().to_string(),
            "PUBLIC_MUTATION_CPU_BUDGET"
        );
        assert!(!budget.unavailable);
    }
    let paid = flow(&account);
    assert_eq!(
        paid.admission_wait_cpu_ns,
        MUTATION_CPU_START_RESERVE_NS + 1
    );
    assert_eq!(paid.stored_credit_ns, -1);
    assert_eq!(paid.unsettled_known_live_cpu_ns, 0);
}

#[test]
fn wait_live_and_residual_debits_obey_the_same_exact_balance() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    {
        let mut budget = account.lock().unwrap();
        let now = budget.updated;
        budget.charge_admission_wait(now, 7).unwrap();
        budget.reserve(now).unwrap();
        budget.charge_request_live(now, 11, 11).unwrap();
        budget.charge_admission_wait(now, 13).unwrap();
        let active = budget
            .flow
            .as_ref()
            .unwrap()
            .snapshot(
                budget.credit_ns,
                budget.in_flight,
                budget.termination_reserved_ns,
            )
            .unwrap();
        assert_eq!(active.admission_wait_cpu_ns, 20);
        assert_eq!(active.paid_cpu_debit_ns, 31);
        assert_eq!(active.unsettled_known_live_cpu_ns, 11);
        assert!(budget.settle_observed(now, Some(3), Some(14), Some(11)));
    }
    let paid = flow(&account);
    assert_eq!(paid.admission_wait_cpu_ns, 20);
    assert_eq!(paid.settled_full_cpu_ns, 14);
    assert_eq!(paid.paid_cpu_debit_ns, 34);
    assert_eq!(paid.unsettled_known_live_cpu_ns, 0);
    assert_eq!(
        paid.stored_credit_ns,
        i128::from(MUTATION_CPU_BURST_NS) - 34
    );
}

#[test]
fn rolling_wait_drop_debits_only_the_new_actual_tail() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let mut waiting = AdmissionWaitCpu::new(account.clone(), ThreadCpuStamp::start()).unwrap();
    consume_actual_cpu();
    {
        let _locked = waiting.lock_and_sample().unwrap();
    }
    let first = flow(&account);
    assert!(first.admission_wait_cpu_ns >= 100_000);
    consume_actual_cpu();
    drop(waiting);
    let last = flow(&account);
    assert!(last.admission_wait_cpu_ns >= first.admission_wait_cpu_ns + 100_000);
    assert_eq!(last.paid_cpu_debit_ns, last.admission_wait_cpu_ns);
    assert_eq!(
        last.stored_credit_ns,
        i128::from(MUTATION_CPU_BURST_NS) - i128::from(last.admission_wait_cpu_ns)
    );
    assert_eq!(last.live_owners, 0);
    assert_eq!(last.unsettled_known_live_cpu_ns, 0);
}

#[test]
fn reserved_owner_receives_the_identical_last_sample_without_resampling() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let mut waiting = AdmissionWaitCpu::new(account.clone(), ThreadCpuStamp::start()).unwrap();
    consume_actual_cpu();
    let (stamp, live) = {
        let mut locked = waiting.lock_and_sample().unwrap();
        let exact = locked.stamp.as_ref().unwrap().clone();
        let (stamp, live) = locked.reserve_owner(None).unwrap();
        assert_eq!(stamp, exact);
        (stamp, live)
    };
    let admission = flow(&account).admission_wait_cpu_ns;
    drop(waiting);
    assert_eq!(flow(&account).admission_wait_cpu_ns, admission);
    consume_actual_cpu();
    live.finish_thread();
    let already = live.complete().unwrap();
    let full = stamp.finish().unwrap();
    {
        let mut budget = account.lock().unwrap();
        assert!(budget.settle_observed(
            Instant::now(),
            Some(full - already),
            Some(full),
            Some(already),
        ));
    }
    let paid = flow(&account);
    assert_eq!(paid.admission_wait_cpu_ns, admission);
    assert_eq!(paid.paid_cpu_debit_ns, admission + full);
    assert_eq!(paid.unsettled_known_live_cpu_ns, 0);
}

#[test]
fn failed_direct_begin_retries_are_charged_without_any_reservation() {
    let account = fresh_account(0);
    let domain = ServiceMutationCpuDomain::from_shared(account.clone());
    let mut prior = 0;
    for _ in 0..3 {
        assert_eq!(
            domain.begin().err().unwrap().to_string(),
            "PUBLIC_MUTATION_CPU_BUDGET"
        );
        let paid = flow(&account);
        assert!(paid.admission_wait_cpu_ns > prior);
        assert_eq!(paid.paid_cpu_debit_ns, paid.admission_wait_cpu_ns);
        assert_eq!(paid.live_owners, 0);
        assert_eq!(paid.booked_reservation_ns, 0);
        assert_eq!(paid.unsettled_known_live_cpu_ns, 0);
        assert_eq!(
            paid.stored_credit_ns,
            -i128::from(paid.admission_wait_cpu_ns)
        );
        prior = paid.admission_wait_cpu_ns;
    }
    assert!(domain.accounting_available());
}

#[test]
fn successful_public_start_settles_wait_and_paid_owner_once() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let server = server(&account);
    let metrics = Mutex::new(PublicMetrics::default());
    let permit = PaidMutationCpuPermit::acquire_before(
        &server,
        &metrics,
        Instant::now() + Duration::from_secs(1),
        &Arc::new(AtomicBool::new(false)),
        &Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let admission = flow(&account).admission_wait_cpu_ns;
    assert!(admission > 0);
    consume_actual_cpu();
    permit.finish(&MutationCpuMeasurement::default(), &server, &metrics);
    let paid = flow(&account);
    let metrics = metrics.lock().unwrap();
    assert_eq!(metrics.mutation_cpu_reservations, 1);
    assert_eq!(metrics.mutation_cpu_admission_wait_observations, 1);
    assert_eq!(metrics.mutation_cpu_admission_wait_unknown, 0);
    assert_eq!(metrics.mutation_cpu_admission_wait_ns, admission);
    assert_eq!(
        serde_json::to_value(metrics.mutation_cpu_charged_scope).unwrap(),
        "owner-and-scoped-workers-excluding-admission-wait"
    );
    assert_eq!(paid.admission_wait_cpu_ns, admission);
    assert_eq!(paid.settled_full_cpu_ns, metrics.mutation_cpu_charged_ns);
    assert_eq!(
        paid.paid_cpu_debit_ns,
        admission + metrics.mutation_cpu_charged_ns
    );
    assert_eq!(
        paid.stored_credit_ns,
        i128::from(MUTATION_CPU_BURST_NS) - i128::from(paid.paid_cpu_debit_ns)
    );
    assert_eq!(paid.live_owners, 0);
    assert_eq!(paid.unsettled_known_live_cpu_ns, 0);
}

#[test]
fn cancelled_stopped_and_expired_public_attempts_all_keep_their_wait_debit() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let server = server(&account);
    let metrics = Mutex::new(PublicMetrics::default());
    let mut prior = 0;
    for kind in ["cancel", "stop", "deadline"] {
        let stop = Arc::new(AtomicBool::new(kind == "stop"));
        let cancelled = Arc::new(AtomicBool::new(kind == "cancel"));
        let deadline = if kind == "deadline" {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(1)
        };
        assert!(PaidMutationCpuPermit::acquire_before(
            &server, &metrics, deadline, &stop, &cancelled,
        )
        .is_err());
        let paid = flow(&account);
        assert!(paid.admission_wait_cpu_ns > prior);
        assert_eq!(paid.paid_cpu_debit_ns, paid.admission_wait_cpu_ns);
        assert_eq!(paid.live_owners, 0);
        assert_eq!(paid.booked_reservation_ns, 0);
        assert_eq!(account.lock().unwrap().queued_start_count(), 0);
        prior = paid.admission_wait_cpu_ns;
    }
    let measured = metrics.lock().unwrap();
    assert_eq!(measured.mutation_cpu_reservations, 0);
    assert_eq!(measured.mutation_cpu_charged_ns, 0);
    assert_eq!(measured.mutation_cpu_admission_wait_observations, 3);
    assert_eq!(measured.mutation_cpu_admission_wait_unknown, 0);
    assert_eq!(
        measured.mutation_cpu_admission_wait_ns,
        flow(&account).admission_wait_cpu_ns
    );
}

#[test]
fn slow_nonhead_cancellation_charges_polling_and_preserves_the_foreign_turn() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let server = server(&account);
    let stop = Arc::new(AtomicBool::new(false));
    let head = PendingCpuStart::register(
        account.clone(),
        Instant::now() + Duration::from_secs(5),
        stop.clone(),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let metrics = Mutex::new(PublicMetrics::default());
    thread::scope(|scope| {
        let task = scope.spawn(|| {
            PaidMutationCpuPermit::acquire_before(
                &server,
                &metrics,
                Instant::now() + Duration::from_secs(2),
                &stop,
                &cancelled,
            )
            .err()
            .unwrap()
        });
        let end = Instant::now() + Duration::from_secs(1);
        while account.lock().unwrap().queued_start_count() != 2 {
            assert!(Instant::now() < end);
            thread::yield_now();
        }
        thread::sleep(Duration::from_millis(5));
        cancelled.store(true, Ordering::Release);
        assert!(task.join().unwrap().to_string().contains("CANCEL"));
    });
    assert_eq!(account.lock().unwrap().queued_start_count(), 1);
    drop(head);
    let paid = flow(&account);
    assert!(paid.admission_wait_cpu_ns > 0);
    assert_eq!(paid.paid_cpu_debit_ns, paid.admission_wait_cpu_ns);
    assert_eq!(paid.live_owners, 0);
    assert_eq!(paid.booked_reservation_ns, 0);
    assert_eq!(account.lock().unwrap().queued_start_count(), 0);
}

#[test]
fn unknown_or_wrong_thread_clock_fences_without_returning_any_principal() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let foreign_stamp = thread::spawn(|| ThreadCpuStamp::start().unwrap())
        .join()
        .unwrap();
    let mut waiting = AdmissionWaitCpu::new(account.clone(), Some(foreign_stamp)).unwrap();
    assert_eq!(
        waiting.lock_and_sample().err().unwrap().to_string(),
        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
    );
    {
        let budget = account.lock().unwrap();
        assert!(budget.unavailable);
        assert_eq!(budget.in_flight, 0);
        assert_eq!(budget.credit_ns, i128::from(MUTATION_CPU_BURST_NS));
    }
    drop(waiting);
    let missing = fresh_account(37);
    assert!(AdmissionWaitCpu::new(missing.clone(), None).is_err());
    let budget = missing.lock().unwrap();
    assert!(budget.unavailable);
    assert_eq!(budget.credit_ns, 37);
    assert_eq!(budget.in_flight, 0);
}

#[test]
fn panic_and_poison_cleanup_keep_known_wait_cpu_without_unpoisoning() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _waiting = AdmissionWaitCpu::new(account.clone(), ThreadCpuStamp::start()).unwrap();
        let _turn = PendingCpuStart::register(
            account.clone(),
            Instant::now() + Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        consume_actual_cpu();
        panic!("intentional admission owner unwind");
    }))
    .is_err());
    assert_eq!(account.lock().unwrap().queued_start_count(), 0);
    assert!(flow(&account).admission_wait_cpu_ns >= 100_000);
    let before = account.lock().unwrap().credit_ns;
    let waiting = AdmissionWaitCpu::new(account.clone(), ThreadCpuStamp::start()).unwrap();
    consume_actual_cpu();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _locked = account.lock().unwrap();
        panic!("intentional account poison");
    }))
    .is_err());
    drop(waiting);
    assert!(account.is_poisoned());
    let budget = account.lock().err().unwrap().into_inner();
    assert!(budget.unavailable);
    assert!(budget.credit_ns < before);
    assert_eq!(budget.in_flight, 0);
}

#[test]
fn wait_accounting_overflow_never_wraps_or_repairs_credit() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    budget.flow.as_mut().unwrap().admission_wait_cpu_ns = u64::MAX;
    let before = budget.credit_ns;
    budget.charge_admission_wait(now, 1).unwrap();
    assert_eq!(budget.credit_ns, before - 1);
    assert!(budget.flow.is_none());
    assert!(!budget.unavailable);
    budget.credit_ns = i128::MIN;
    assert_eq!(
        budget
            .charge_admission_wait(now, 1)
            .unwrap_err()
            .to_string(),
        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
    );
    assert_eq!(budget.credit_ns, i128::MIN);
    assert!(budget.unavailable);
}

#[test]
fn unknown_after_known_wait_never_erases_or_refunds_prior_debits() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let metrics = Mutex::new(PublicMetrics::default());
    let mut waiting =
        AdmissionWaitCpu::with_metrics(account.clone(), ThreadCpuStamp::start(), Some(&metrics))
            .unwrap();
    consume_actual_cpu();
    {
        let _locked = waiting.lock_and_sample().unwrap();
    }
    let before = flow(&account);
    waiting.stamp = Some(
        thread::spawn(|| ThreadCpuStamp::start().unwrap())
            .join()
            .unwrap(),
    );
    assert!(waiting.lock_and_sample().is_err());
    drop(waiting);
    let budget = account.lock().unwrap();
    assert!(budget.unavailable);
    assert_eq!(budget.credit_ns, before.stored_credit_ns);
    assert_eq!(
        budget.flow.as_ref().unwrap().admission_wait_cpu_ns,
        before.admission_wait_cpu_ns
    );
    assert_eq!(budget.in_flight, 0);
    let measured = metrics.lock().unwrap();
    assert_eq!(measured.mutation_cpu_admission_wait_observations, 1);
    assert_eq!(measured.mutation_cpu_admission_wait_unknown, 1);
    assert_eq!(
        measured.mutation_cpu_admission_wait_ns,
        before.admission_wait_cpu_ns
    );
}

#[test]
fn foreign_queue_token_cannot_move_wait_debits_or_reserve_another_account() {
    let account_a = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let account_b = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let mut foreign = PendingCpuStart::register(
        account_b.clone(),
        Instant::now() + Duration::from_secs(1),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let before_b = flow(&account_b);
    let mut waiting = AdmissionWaitCpu::new(account_a.clone(), ThreadCpuStamp::start()).unwrap();
    consume_actual_cpu();
    {
        let mut locked = waiting.lock_and_sample().unwrap();
        assert_eq!(
            locked
                .reserve_owner(Some(&mut foreign))
                .err()
                .unwrap()
                .to_string(),
            "PUBLIC_PENDING_ORDER"
        );
        assert_eq!(locked.in_flight, 0);
    }
    drop(waiting);
    assert_eq!(flow(&account_b), before_b);
    let paid_a = flow(&account_a);
    assert!(paid_a.admission_wait_cpu_ns >= 100_000);
    assert_eq!(paid_a.live_owners, 0);
    assert_eq!(paid_a.booked_reservation_ns, 0);
    drop(foreign);
}

#[test]
fn second_handoff_is_unavailable_before_booking_or_returning_any_principal() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let mut waiting = AdmissionWaitCpu::new(account.clone(), ThreadCpuStamp::start()).unwrap();
    let (stamp, live) = {
        let mut locked = waiting.lock_and_sample().unwrap();
        let (stamp, live) = locked.reserve_owner(None).unwrap();
        let before = locked.credit_ns;
        assert_eq!(
            locked.reserve_owner(None).err().unwrap().to_string(),
            "PUBLIC_MUTATION_CPU_UNAVAILABLE"
        );
        assert!(locked.unavailable);
        assert_eq!(locked.in_flight, 1);
        assert_eq!(locked.credit_ns, before);
        (stamp, live)
    };
    drop(waiting);
    live.finish_thread();
    assert!(stamp.finish().is_some());
    assert!(live.complete().is_none());
    let mut budget = account.lock().unwrap();
    assert!(budget.unavailable);
    assert_eq!(budget.in_flight, 1);
    let before = budget.credit_ns;
    // Close the one original reservation as unknown, without a principal return.
    assert!(!budget.settle_observed(Instant::now(), None, None, None));
    assert_eq!(budget.credit_ns, before);
    assert_eq!(budget.in_flight, 0);
    assert!(budget.unavailable);
}

#[test]
fn full_original_waiter_queue_still_bills_the_refused_attempt_without_a_slot() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let server = server(&account);
    let metrics = Mutex::new(PublicMetrics::default());
    let stop = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut turns = Vec::new();
    for _ in 0..crate::ingress::public_v3::MAX_MUTATING_GRANTS {
        turns.push(
            PendingCpuStart::register(account.clone(), deadline, stop.clone(), cancelled.clone())
                .unwrap(),
        );
    }
    let before_count = account.lock().unwrap().queued_start_count();
    assert!(
        PaidMutationCpuPermit::acquire_before(&server, &metrics, deadline, &stop, &cancelled,)
            .is_err()
    );
    assert_eq!(account.lock().unwrap().queued_start_count(), before_count);
    let paid = flow(&account);
    assert!(paid.admission_wait_cpu_ns > 0);
    assert_eq!(paid.paid_cpu_debit_ns, paid.admission_wait_cpu_ns);
    assert_eq!(paid.live_owners, 0);
    assert_eq!(paid.booked_reservation_ns, 0);
    let measured = metrics.lock().unwrap();
    assert_eq!(measured.mutation_cpu_admission_wait_observations, 1);
    assert_eq!(measured.mutation_cpu_admission_wait_unknown, 0);
    assert_eq!(
        measured.mutation_cpu_admission_wait_ns,
        paid.admission_wait_cpu_ns
    );
    drop(measured);
    drop(turns);
    assert_eq!(flow(&account), paid);
}

#[test]
fn missing_clock_service_projection_is_explicitly_unknown_not_a_zero_success() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let server = server(&account);
    let metrics = Mutex::new(PublicMetrics::default());
    server.fail_next_cpu_start.store(true, Ordering::Release);
    assert!(PaidMutationCpuPermit::acquire_before(
        &server,
        &metrics,
        Instant::now() + Duration::from_secs(1),
        &Arc::new(AtomicBool::new(false)),
        &Arc::new(AtomicBool::new(false)),
    )
    .is_err());
    let measured = metrics.lock().unwrap();
    assert_eq!(measured.mutation_cpu_reservations, 0);
    assert_eq!(measured.mutation_cpu_charged_ns, 0);
    assert_eq!(measured.mutation_cpu_admission_wait_observations, 1);
    assert_eq!(measured.mutation_cpu_admission_wait_unknown, 1);
    assert_eq!(measured.mutation_cpu_admission_wait_ns, 0);
    assert!(account.lock().unwrap().unavailable);
}

#[test]
fn unwind_publishes_actual_wait_to_the_same_listener_without_owner_cpu() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let metrics = Mutex::new(PublicMetrics::default());
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _waiting = AdmissionWaitCpu::with_metrics(
            account.clone(),
            ThreadCpuStamp::start(),
            Some(&metrics),
        )
        .unwrap();
        consume_actual_cpu();
        panic!("intentional listener wait unwind");
    }))
    .is_err());
    let paid = flow(&account);
    let measured = metrics.lock().unwrap();
    assert!(paid.admission_wait_cpu_ns >= 100_000);
    assert_eq!(
        measured.mutation_cpu_admission_wait_ns,
        paid.admission_wait_cpu_ns
    );
    assert_eq!(measured.mutation_cpu_admission_wait_observations, 1);
    assert_eq!(measured.mutation_cpu_admission_wait_unknown, 0);
    assert_eq!(measured.mutation_cpu_charged_ns, 0);
    assert_eq!(paid.live_owners, 0);
}
