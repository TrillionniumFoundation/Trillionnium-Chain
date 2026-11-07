//! Actual ownership and lock-order controls for overlapping start attempts.
use super::tests::{consume_actual_cpu, flow, fresh_account, server};
use super::*;
use crate::ingress::public_v3::{
    scalar_cpu::{ServiceMutationCpuDomain, MUTATION_CPU_BURST_NS},
    MutationCpuMeasurement, PaidMutationCpuPermit, PublicMetrics,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use trnm_mvcc_fee::pon_executor::ExecutionWorkerAccounting;

#[test]
fn nested_direct_begin_is_paid_by_the_original_owner_without_a_second_reserve() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let domain = ServiceMutationCpuDomain::from_shared(account.clone());
    let operation = domain.begin().unwrap();
    let before = flow(&account);
    consume_actual_cpu();
    assert_eq!(
        domain.begin().err().unwrap().to_string(),
        "PUBLIC_MUTATION_CPU_BUDGET"
    );
    let after = flow(&account);
    assert_eq!(after.admission_wait_cpu_ns, before.admission_wait_cpu_ns);
    assert_eq!(after.booked_reservation_ns, before.booked_reservation_ns);
    assert_eq!(after.live_owners, 1);
    assert_eq!(after.paid_cpu_debit_ns, before.paid_cpu_debit_ns);
    let settled = operation.finish();
    assert!(!settled.accounting_unavailable);
    let paid = flow(&account);
    assert_eq!(
        paid.paid_cpu_debit_ns,
        before.admission_wait_cpu_ns + settled.total_cpu_ns.unwrap()
    );
    assert_eq!(
        paid.stored_credit_ns,
        i128::from(MUTATION_CPU_BURST_NS) - i128::from(paid.paid_cpu_debit_ns)
    );
    assert_eq!(paid.live_owners, 0);
}

#[test]
fn nested_public_admission_has_no_second_wait_bill_or_false_clock_failure() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let server = server(&account);
    let metrics = Mutex::new(PublicMetrics::default());
    let stop = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(1);
    let permit =
        PaidMutationCpuPermit::acquire_before(&server, &metrics, deadline, &stop, &cancelled)
            .unwrap();
    let before = flow(&account);
    assert_eq!(
        PaidMutationCpuPermit::acquire_before(&server, &metrics, deadline, &stop, &cancelled,)
            .err()
            .unwrap()
            .to_string(),
        "PUBLIC_MUTATION_CPU_BUDGET"
    );
    assert_eq!(
        flow(&account).admission_wait_cpu_ns,
        before.admission_wait_cpu_ns
    );
    assert_eq!(account.lock().unwrap().in_flight, 1);
    {
        let measured = metrics.lock().unwrap();
        assert_eq!(measured.mutation_cpu_refusals, 1);
        assert_eq!(measured.mutation_cpu_clock_failures, 0);
        assert_eq!(measured.mutation_cpu_admission_wait_observations, 2);
        assert_eq!(measured.mutation_cpu_admission_wait_covered_observations, 1);
        assert_eq!(measured.mutation_cpu_admission_wait_unknown, 0);
    }
    permit.finish(&MutationCpuMeasurement::default(), &server, &metrics);
    let paid = flow(&account);
    let measured = metrics.lock().unwrap();
    assert_eq!(
        paid.paid_cpu_debit_ns,
        measured.mutation_cpu_admission_wait_ns + measured.mutation_cpu_charged_ns
    );
    assert_eq!(paid.live_owners, 0);
}

#[test]
fn scoped_worker_retry_is_charged_only_in_the_original_child_interval() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let domain = ServiceMutationCpuDomain::from_shared(account.clone());
    let operation = domain.begin().unwrap();
    let admission = flow(&account).admission_wait_cpu_ns;
    thread::scope(|scope| {
        let accounting = &operation.workers;
        let child = scope.spawn(|| {
            let interval = accounting.worker_started().unwrap();
            consume_actual_cpu();
            assert_eq!(
                domain.begin().err().unwrap().to_string(),
                "PUBLIC_MUTATION_CPU_BUDGET"
            );
            assert_eq!(flow(&account).admission_wait_cpu_ns, admission);
            drop(interval);
        });
        accounting.worker_spawn_succeeded();
        child.join().unwrap();
    });
    // Removing the worker must retain this still-live owner's scope.
    assert!(scope_covers_current_thread(&account).unwrap());
    assert_eq!(
        account
            .lock()
            .unwrap()
            .cpu_scopes
            .iter()
            .filter(|scope| scope.strong_count() != 0)
            .count(),
        1
    );
    let settled = operation.finish();
    assert!(!settled.accounting_unavailable);
    assert_eq!(settled.spawned_workers, 1);
    assert_eq!(settled.known_workers, 1);
    assert!(settled.scoped_worker_cpu_ns.unwrap() >= 100_000);
    let paid = flow(&account);
    assert_eq!(paid.admission_wait_cpu_ns, admission);
    assert_eq!(
        paid.paid_cpu_debit_ns,
        admission + settled.total_cpu_ns.unwrap()
    );
    assert_eq!(paid.unsettled_known_live_cpu_ns, 0);
}

#[test]
fn another_account_on_the_same_thread_never_inherits_the_first_account_scope() {
    let account_a = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let account_b = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let first = ServiceMutationCpuDomain::from_shared(account_a.clone())
        .begin()
        .unwrap();
    assert!(scope_covers_current_thread(&account_a).unwrap());
    assert!(!scope_covers_current_thread(&account_b).unwrap());
    let second = ServiceMutationCpuDomain::from_shared(account_b.clone())
        .begin()
        .unwrap();
    assert!(flow(&account_b).admission_wait_cpu_ns > 0);
    assert!(scope_covers_current_thread(&account_b).unwrap());
    assert!(!second.finish().accounting_unavailable);
    assert!(scope_covers_current_thread(&account_a).unwrap());
    assert!(!first.finish().accounting_unavailable);
}

#[test]
fn retained_finished_state_and_stale_cleanup_cannot_cover_or_remove_a_new_owner() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let domain = ServiceMutationCpuDomain::from_shared(account.clone());
    let first = domain.begin().unwrap();
    let stale = first.live.clone();
    let weak = Arc::downgrade(&stale.state);
    assert!(!first.finish().accounting_unavailable);
    assert!(weak.upgrade().is_some());
    {
        let state = stale.state.lock().unwrap();
        assert!(state.owner_finished && state.threads.is_empty());
    }
    assert!(!scope_covers_current_thread(&account).unwrap());
    let second = domain.begin().unwrap();
    let current = second.live.clone();
    {
        let mut budget = account.lock().unwrap();
        budget.retire_cpu_scope(&stale.state);
        assert!(budget
            .cpu_scopes
            .iter()
            .any(|scope| std::ptr::eq(scope.as_ptr(), Arc::as_ptr(&current.state))));
    }
    assert!(scope_covers_current_thread(&account).unwrap());
    assert!(!second.finish().accounting_unavailable);
    // A late worker cannot revive a closed state or obtain a new scope/allowance.
    stale.register_worker(ThreadCpuStamp::start());
    assert!(!domain.accounting_available());
}

#[test]
fn poisoned_scope_attribution_is_unknown_without_a_second_debit_or_reserve() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let domain = ServiceMutationCpuDomain::from_shared(account.clone());
    let operation = domain.begin().unwrap();
    let before = flow(&account);
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _state = operation.live.state.lock().unwrap();
        panic!("intentional request-registry poison");
    }))
    .is_err());
    let metrics = Mutex::new(PublicMetrics::default());
    assert!(AdmissionWaitCpu::with_metrics(
        account.clone(),
        ThreadCpuStamp::start(),
        Some(&metrics),
    )
    .is_err());
    let budget = account.lock().unwrap();
    assert!(budget.unavailable);
    assert_eq!(budget.in_flight, 1);
    assert_eq!(budget.credit_ns, before.stored_credit_ns);
    drop(budget);
    let measured = metrics.lock().unwrap();
    assert_eq!(measured.mutation_cpu_admission_wait_observations, 1);
    assert_eq!(measured.mutation_cpu_admission_wait_unknown, 1);
    assert_eq!(measured.mutation_cpu_admission_wait_ns, 0);
    drop(measured);
    assert!(operation.finish().accounting_unavailable);
}

#[test]
fn lookup_releases_the_global_lock_before_waiting_for_the_request_registry() {
    let account = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let domain = ServiceMutationCpuDomain::from_shared(account.clone());
    let operation = domain.begin().unwrap();
    let reached = Arc::new(AtomicBool::new(false));
    account.lock().unwrap().scope_snapshot_reached = Some(reached.clone());
    thread::scope(|scope| {
        let registry = operation.live.state.lock().unwrap();
        let child = scope.spawn(|| {
            // This other actual thread has no inherited owner.
            let operation = domain.begin().unwrap();
            operation.finish()
        });
        let end = Instant::now() + Duration::from_secs(2);
        while !reached.load(Ordering::Acquire) {
            assert!(Instant::now() < end);
            thread::yield_now();
        }
        // Child has released global and is blocked on our real registry lock.
        assert!(account.try_lock().is_ok());
        drop(registry);
        assert!(!child.join().unwrap().accounting_unavailable);
    });
    assert!(!operation.finish().accounting_unavailable);
}

#[test]
fn typed_registration_rejects_a_foreign_live_state_before_any_reservation() {
    let account_a = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let account_b = fresh_account(i128::from(MUTATION_CPU_BURST_NS));
    let before_b = flow(&account_b);
    let foreign = LiveRequestCpu::unregistered(account_b.clone(), ThreadCpuStamp::start().unwrap());
    let mut waiting = AdmissionWaitCpu::new(account_a.clone(), ThreadCpuStamp::start()).unwrap();
    {
        let locked = waiting.lock_and_sample().unwrap();
        assert_eq!(
            locked.registration_slot(&foreign).unwrap_err().to_string(),
            "PUBLIC_MUTATION_CPU_UNAVAILABLE"
        );
        assert_eq!(locked.in_flight, 0);
        assert!(locked
            .cpu_scopes
            .iter()
            .all(|scope| scope.strong_count() == 0));
    }
    drop(waiting);
    assert_eq!(flow(&account_b), before_b);
    assert_eq!(flow(&account_a).live_owners, 0);
}
