use super::*;
use std::sync::Barrier;

fn consume_real_cpu() {
    let mut value = 1u64;
    for _ in 0..100_000 {
        value = std::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
    }
    std::hint::black_box(value);
}

#[test]
fn cloned_shared_domain_preserves_two_actual_owner_start_ceiling() {
    let domain = ServiceMutationCpuDomain::standalone();
    let clone = domain.clone();
    assert!(domain.shares_domain_with(&clone));
    assert!(!domain.shares_domain_with(&ServiceMutationCpuDomain::standalone()));
    let barrier = Barrier::new(3);
    let receipts = thread::scope(|scope| {
        let a = scope.spawn(|| {
            let operation = domain.begin().unwrap();
            barrier.wait();
            barrier.wait();
            consume_real_cpu();
            operation.finish()
        });
        let b = scope.spawn(|| {
            let operation = clone.begin().unwrap();
            barrier.wait();
            barrier.wait();
            consume_real_cpu();
            operation.finish()
        });
        barrier.wait();
        assert_eq!(domain.budget.lock().unwrap().in_flight, 2);
        assert_eq!(
            domain.begin().err().unwrap().to_string(),
            "PUBLIC_MUTATION_CPU_BUDGET"
        );
        barrier.wait();
        [a.join().unwrap(), b.join().unwrap()]
    });
    for receipt in receipts {
        assert!(!receipt.accounting_unavailable);
        assert!(receipt.total_cpu_ns.unwrap() > 0);
    }
    assert_eq!(domain.budget.lock().unwrap().in_flight, 0);
}

#[test]
fn shared_operation_real_partial_owner_debit_settles_only_residual() {
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    consume_real_cpu();
    operation.checkpoint().unwrap();
    let partial = operation.live.state.lock().unwrap().charged_ns;
    assert!(partial > 0);
    consume_real_cpu();
    operation.checkpoint().unwrap();
    let receipt = operation.finish();
    assert!(!receipt.accounting_unavailable);
    assert_eq!(receipt.scoped_worker_cpu_ns, Some(0));
    assert_eq!(receipt.total_cpu_ns, receipt.owner_cpu_ns);
    assert_eq!(
        receipt.total_cpu_ns.unwrap() - receipt.live_paid_cpu_ns.unwrap(),
        receipt.residual_cpu_ns.unwrap()
    );
    assert!(receipt.live_paid_cpu_ns.unwrap() >= partial);
    assert_eq!(domain.budget.lock().unwrap().in_flight, 0);
}

#[test]
fn repeated_real_scopes_and_worker_panic_join_before_single_settlement() {
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    for panic_worker in [false, true] {
        thread::scope(|scope| {
            let accounting = &operation.workers;
            let handle = scope.spawn(move || {
                let _interval = accounting.worker_started().unwrap();
                consume_real_cpu();
                accounting.checkpoint().unwrap();
                assert!(!panic_worker, "controlled actual worker unwind");
            });
            accounting.worker_spawn_succeeded();
            assert_eq!(handle.join().is_err(), panic_worker);
        });
    }
    let receipt = operation.finish();
    assert_eq!(
        (
            receipt.spawned_workers,
            receipt.started_workers,
            receipt.finished_workers,
            receipt.known_workers
        ),
        (2, 2, 2, 2)
    );
    assert!(!receipt.accounting_unavailable);
    assert!(receipt.scoped_worker_cpu_ns.unwrap() > 0);
    assert_eq!(
        receipt.total_cpu_ns.unwrap(),
        receipt.owner_cpu_ns.unwrap() + receipt.scoped_worker_cpu_ns.unwrap()
    );
    assert_eq!(
        receipt.residual_cpu_ns.unwrap(),
        receipt.total_cpu_ns.unwrap() - receipt.live_paid_cpu_ns.unwrap()
    );
}

#[test]
fn unknown_live_clock_and_unclosed_operation_disable_all_shared_starts() {
    let domain = ServiceMutationCpuDomain::standalone();
    let clone = domain.clone();
    let operation = domain.begin().unwrap();
    operation
        .live
        .fail_next_sample
        .store(true, Ordering::Release);
    assert_eq!(
        operation.checkpoint().err().unwrap().to_string(),
        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
    );
    let receipt = operation.finish();
    assert!(receipt.accounting_unavailable);
    assert_eq!(receipt.live_paid_cpu_ns, None);
    assert_eq!(receipt.residual_cpu_ns, None);
    assert_eq!(
        clone.begin().err().unwrap().to_string(),
        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
    );
    let fresh = ServiceMutationCpuDomain::standalone();
    drop(fresh.begin().unwrap());
    assert_eq!(
        fresh.begin().err().unwrap().to_string(),
        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
    );
}

#[test]
fn actual_owner_thread_mismatch_preserves_unknown_without_zero_refund() {
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    let receipt = thread::spawn(move || operation.finish()).join().unwrap();
    assert!(receipt.accounting_unavailable);
    assert_eq!(receipt.owner_cpu_ns, None);
    assert_eq!(receipt.total_cpu_ns, None);
    assert_eq!(
        domain.begin().err().unwrap().to_string(),
        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
    );
}
