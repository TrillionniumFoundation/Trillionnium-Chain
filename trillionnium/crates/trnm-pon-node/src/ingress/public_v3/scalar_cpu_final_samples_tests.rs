//! Final measurement is not permission to continue work or return a reservation.
//! The original settlement, forced-debt and native pressure assertions remain.
use super::*;
use std::time::Duration;

#[test]
fn lost_reservation_final_debit_fences_without_refill_repair_or_refund() {
    for count in [0, MUTATION_CPU_WORKERS + 1, usize::MAX] {
        let mut budget = PaidMutationCpuBudget::new();
        let now = budget.updated;
        budget.in_flight = count;
        budget.credit_ns = 123_456;
        budget
            .record_final_live(now + Duration::from_secs(1), 17)
            .unwrap();
        assert_eq!(budget.credit_ns, 123_439);
        assert_eq!(budget.updated, now);
        assert_eq!(budget.in_flight, count);
        assert!(budget.unavailable);
        assert!(!budget.settle(now, Some(3)));
        assert_eq!(budget.credit_ns, 123_439);
        assert_eq!(budget.in_flight, count);
        assert!(budget
            .reserve(now)
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    }
}

#[test]
fn final_debit_cannot_forgive_prior_uncertainty_or_numeric_overflow() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    budget.reserve(now).unwrap();
    budget.unavailable = true;
    assert!(budget
        .record_final_live(now, 7)
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    assert!(budget.unavailable);
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    budget.credit_ns = i128::MIN;
    assert!(budget
        .record_final_live(now, 1)
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    assert_eq!(budget.credit_ns, i128::MIN);
    assert_eq!(budget.updated, now);
    assert!(budget.unavailable);
}

#[test]
fn actual_final_measurement_keeps_known_components_and_closes_new_starts() {
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    operation.checkpoint().unwrap();
    let live = operation.live.clone();
    let before = {
        let mut budget = domain.budget.lock().unwrap();
        budget.in_flight = 0;
        budget.credit_ns
    };
    let receipt = operation.finish();
    let total = receipt.total_cpu_ns.unwrap();
    let paid = receipt.live_paid_cpu_ns.unwrap();
    let residual = receipt.residual_cpu_ns.unwrap();
    assert_eq!(total, paid.checked_add(residual).unwrap());
    assert_eq!(receipt.scoped_worker_cpu_ns, Some(0));
    assert_eq!(receipt.owner_cpu_ns, Some(total));
    assert!(receipt.accounting_unavailable);
    assert!(!receipt.live_refused);
    {
        let budget = domain.budget.lock().unwrap();
        assert!(budget.unavailable);
        assert_eq!(budget.in_flight, 0);
        assert!(budget.credit_ns <= before);
    }
    assert!(!domain.accounting_available());
    assert!(domain
        .begin()
        .err()
        .unwrap()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    // A completed observation has removed the thread; it cannot resume work.
    assert!(live
        .checkpoint()
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
}

#[test]
fn continuing_checkpoint_still_requires_a_live_reservation() {
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    domain.budget.lock().unwrap().in_flight = 0;
    assert!(operation
        .checkpoint()
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    assert!(!domain.accounting_available());
    let receipt = operation.finish();
    assert!(receipt.accounting_unavailable);
    assert!(receipt.total_cpu_ns.is_some());
    assert!(receipt.residual_cpu_ns.is_none());
}
