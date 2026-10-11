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

#[test]
fn stale_refill_keeps_watermark_and_cannot_credit_the_same_interval_twice() {
    let mut budget = PaidMutationCpuBudget::new();
    let start = budget.updated;
    budget.credit_ns = 0;
    let second = std::time::Duration::from_secs(1);
    budget.refill(start + second * 2);
    let paid = i128::from(MUTATION_CPU_REFILL_NS_PER_SECOND) * 2;
    assert_eq!(budget.credit_ns, paid);
    budget.refill(start + second);
    assert_eq!(budget.updated, start + second * 2);
    assert_eq!(budget.credit_ns, paid);
    budget.refill(start + second * 2);
    assert_eq!(budget.credit_ns, paid);
    budget.refill(start + second * 3);
    assert_eq!(
        budget.credit_ns,
        i128::from(MUTATION_CPU_REFILL_NS_PER_SECOND) * 3
    );
    assert!(!budget.unavailable);
}

#[test]
fn stale_reserve_and_settle_match_the_non_decreasing_clock_trace() {
    let mut budget = PaidMutationCpuBudget::new();
    let start = budget.updated;
    let later = start + std::time::Duration::from_secs(1);
    budget.credit_ns = 0;
    budget.refill(later);
    let before = budget.credit_ns;
    budget.reserve(start).unwrap();
    assert_eq!(budget.updated, later);
    budget.settle(start, Some(75_000_000), Some(0));
    assert_eq!(budget.updated, later);
    assert_eq!(budget.credit_ns, before - 75_000_000);
    budget.refill(later);
    assert_eq!(budget.credit_ns, before - 75_000_000);
    assert_eq!(budget.in_flight, 0);
    assert!(!budget.unavailable);
}

#[test]
fn extra_settlement_cannot_return_an_unowned_reservation() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    budget.reserve(now).unwrap();
    budget.charge_live(now, 500_000_000).unwrap();
    budget.settle(now, Some(50_000_000), Some(0));
    let remaining = budget.credit_ns;
    assert_eq!(remaining, i128::from(MUTATION_CPU_BURST_NS) - 550_000_000);
    budget.settle(now, Some(0), Some(0));
    assert_eq!(budget.credit_ns, remaining);
    assert_eq!(budget.in_flight, 0);
    assert!(budget.unavailable);
    assert_eq!(
        budget.reserve(now).unwrap_err().to_string(),
        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
    );
}

#[test]
fn missing_or_impossible_reservation_preserves_credit_and_marks_unknown() {
    for in_flight in [0, MUTATION_CPU_WORKERS + 1, usize::MAX] {
        let mut budget = PaidMutationCpuBudget::new();
        let now = budget.updated;
        budget.in_flight = in_flight;
        budget.credit_ns = -123;
        budget.settle(now + std::time::Duration::from_secs(1), Some(0), Some(0));
        assert!(budget.unavailable);
        assert_eq!(budget.credit_ns, -123);
        assert_eq!(budget.updated, now);
        assert_eq!(budget.in_flight, in_flight);
    }
}

#[test]
fn two_legitimate_reservations_return_once_and_keep_live_cpu_nested() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    budget.reserve(now).unwrap();
    budget.reserve(now).unwrap();
    budget.charge_live(now, 700_000_000).unwrap();
    budget.settle(now, Some(50_000_000), Some(0));
    assert_eq!(budget.in_flight, 1);
    budget.settle(now, Some(75_000_000), Some(0));
    assert_eq!(budget.in_flight, 0);
    assert_eq!(
        budget.credit_ns,
        i128::from(MUTATION_CPU_BURST_NS) - 825_000_000
    );
    assert!(!budget.unavailable);
}

#[test]
fn finish_reports_shared_settlement_uncertainty_without_erasing_known_cpu() {
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    consume_real_cpu();
    // Inject local accounting corruption, not a remote packet or Native result.
    // The last owner sample is still known; failure occurs at reserve return.
    domain.budget.lock().unwrap().in_flight = 0;
    let receipt = operation.finish();
    assert!(receipt.owner_cpu_ns.is_some());
    assert!(receipt.total_cpu_ns.is_some());
    assert!(receipt.residual_cpu_ns.is_some());
    assert!(receipt.accounting_unavailable);
    assert!(!domain.accounting_available());
    assert_eq!(
        domain.begin().err().unwrap().to_string(),
        "PUBLIC_MUTATION_CPU_UNAVAILABLE"
    );
}

#[test]
fn observing_budget_never_refills_or_returns_an_outstanding_reserve() {
    let domain = ServiceMutationCpuDomain::standalone();
    let old_watermark = {
        let mut budget = domain.budget.lock().unwrap();
        budget.credit_ns = -123;
        budget.in_flight = 1;
        budget.updated -= std::time::Duration::from_secs(10);
        budget.updated
    };
    let first = domain.observe().unwrap();
    for _ in 0..32 {
        assert_eq!(domain.clone().observe().unwrap(), first);
    }
    assert_eq!(first.stored_credit_ns, -123);
    assert_eq!(first.in_flight, 1);
    assert_eq!(domain.budget.lock().unwrap().updated, old_watermark);
    assert!(!first.accounting_unavailable);
    domain.budget.lock().unwrap().unavailable = true;
    let unknown = domain.observe().unwrap();
    assert!(unknown.accounting_unavailable);
    assert_eq!(unknown.stored_credit_ns, -123);
    assert_eq!(unknown.in_flight, 1);
}

#[test]
fn settlement_result_distinguishes_known_debt_unknown_sample_and_unowned_return() {
    for measured in [Some(0), Some(MUTATION_CPU_BURST_NS + 1), None] {
        let mut budget = PaidMutationCpuBudget::new();
        let now = budget.updated;
        budget.reserve(now).unwrap();
        assert_eq!(budget.settle(now, measured, Some(0)), measured.is_some());
        assert_eq!(budget.in_flight, 0);
        if measured == Some(MUTATION_CPU_BURST_NS + 1) {
            assert_eq!(budget.credit_ns, -1);
            assert!(!budget.unavailable);
        }
        let credit = budget.credit_ns;
        assert!(!budget.settle(now, Some(0), Some(0)));
        assert_eq!(budget.credit_ns, credit);
        assert!(budget.unavailable);
    }
}

#[test]
fn spent_quantum_releases_only_its_own_promise_and_can_fund_the_other_worker() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    let reserve = MUTATION_CPU_START_RESERVE_NS;
    budget.credit_ns = i128::from(3 * reserve);
    budget.reserve(now).unwrap();
    budget.charge_request_live(now, reserve, reserve).unwrap();
    budget.reserve(now).unwrap();
    assert_eq!(budget.spendable_credit().unwrap(), i128::from(reserve));
    budget
        .charge_request_live(now, reserve, 2 * reserve)
        .unwrap();
    assert_eq!(budget.spendable_credit().unwrap(), 0);
    // The first request cannot consume the second request's unused quantum.
    assert!(budget
        .charge_request_live(now, 1, 2 * reserve + 1)
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuBudget));
    assert!(budget.settle(now, Some(0), Some(2 * reserve + 1)));
    assert_eq!(budget.spendable_credit().unwrap(), -1);
    // A final sample is a debit, not permission to continue in that deficit.
    assert!(budget.record_final_live(now, reserve, reserve).is_err());
    assert!(budget.settle(now, Some(0), Some(reserve)));
    assert_eq!(budget.credit_ns, -1);
    assert_eq!(budget.spent_start_reserves_ns, 0);
}

#[test]
fn refill_clips_actual_balance_without_reissuing_a_sampled_quantum() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    let reserve = MUTATION_CPU_START_RESERVE_NS;
    budget.reserve(now).unwrap();
    budget
        .charge_request_live(now, reserve / 2, reserve / 2)
        .unwrap();
    let later = now + std::time::Duration::from_secs(100);
    budget.refill(later);
    assert_eq!(
        budget.credit_ns + i128::from(reserve),
        i128::from(MUTATION_CPU_BURST_NS)
    );
    assert_eq!(
        budget.spendable_credit().unwrap(),
        i128::from(MUTATION_CPU_BURST_NS - reserve / 2)
    );
    assert!(budget.settle(now, Some(7), Some(reserve / 2)));
    assert_eq!(budget.updated, later);
    assert_eq!(budget.credit_ns, i128::from(MUTATION_CPU_BURST_NS) - 7);
    assert_eq!(budget.spent_start_reserves_ns, 0);
    let credit = budget.credit_ns;
    assert!(!budget.settle(later, Some(0), Some(reserve / 2)));
    assert_eq!(budget.credit_ns, credit);
}

#[test]
fn final_sample_consumes_remaining_promise_before_exact_residual_return() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    let reserve = MUTATION_CPU_START_RESERVE_NS;
    budget.credit_ns = i128::from(2 * reserve);
    budget.reserve(now).unwrap();
    budget
        .charge_request_live(now, reserve / 4, reserve / 4)
        .unwrap();
    budget
        .record_final_live(now, reserve, reserve + reserve / 4)
        .unwrap();
    assert_eq!(budget.spent_start_reserves_ns, reserve);
    assert!(budget.settle(now, Some(13), Some(reserve + reserve / 4)));
    assert_eq!(budget.credit_ns, i128::from(reserve - reserve / 4) - 13);
    assert_eq!(budget.spent_start_reserves_ns, 0);
    assert_eq!(budget.in_flight, 0);
}

#[test]
fn impossible_consumed_reserve_return_fences_without_refund() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    budget.reserve(now).unwrap();
    budget.charge_request_live(now, 7, 7).unwrap();
    let credit = budget.credit_ns;
    assert!(!budget.settle(now, Some(0), Some(8)));
    assert_eq!(budget.credit_ns, credit);
    assert!(budget.unavailable);
    assert!(budget
        .reserve(now)
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
}

#[test]
fn two_hundred_thousand_accounting_steps_match_independent_remaining_promise_model() {
    // Independent representation: actual remaining CPU and each active request's
    // unspent promise. It does not reuse the implementation's raw-credit/S fold.
    let mut budget = PaidMutationCpuBudget::new();
    let start = budget.updated;
    let mut last_ns = 0_u64;
    let mut now_ns = 0_u64;
    let mut balance = i128::from(MUTATION_CPU_BURST_NS);
    let mut requests = [None::<u64>; MUTATION_CPU_WORKERS];
    let reserve = MUTATION_CPU_START_RESERVE_NS;
    let mut seed = 0xd936_410e_1796_ebb1_u64;
    for step in 0..200_000 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        now_ns += (seed >> 40) % 8_000_001;
        // Retain stale/refill interleavings, including no elapsed time.
        let sampled_ns = if step % 13 == 0 {
            now_ns.saturating_sub(20_000_000)
        } else {
            now_ns
        };
        let now = start + std::time::Duration::from_nanos(sampled_ns);
        if sampled_ns >= last_ns {
            let refill = u128::from(sampled_ns - last_ns)
                * u128::from(MUTATION_CPU_REFILL_NS_PER_SECOND)
                / 1_000_000_000;
            balance = (balance + refill as i128).min(i128::from(MUTATION_CPU_BURST_NS));
            last_ns = sampled_ns;
        }
        let slot = ((seed >> 32) as usize) % MUTATION_CPU_WORKERS;
        let delta = (seed >> 8) % (2 * reserve + 1);
        match (seed % 4, requests[slot]) {
            (0, None) => {
                let unspent: u64 = requests
                    .iter()
                    .flatten()
                    .map(|cpu| reserve.saturating_sub(*cpu))
                    .sum();
                let allowed = balance - i128::from(unspent) >= i128::from(reserve);
                let result = budget.reserve(now);
                assert_eq!(result.is_ok(), allowed, "reserve step {step}");
                if allowed {
                    requests[slot] = Some(0);
                } else {
                    assert!(result
                        .unwrap_err()
                        .is(crate::ErrorCode::PublicMutationCpuBudget));
                }
            }
            (1 | 2, Some(previous)) => {
                let total = previous + delta;
                requests[slot] = Some(total);
                balance -= i128::from(delta);
                let unspent: u64 = requests
                    .iter()
                    .flatten()
                    .map(|cpu| reserve.saturating_sub(*cpu))
                    .sum();
                let result = if seed % 4 == 1 {
                    budget.charge_request_live(now, delta, total)
                } else {
                    budget.record_final_live(now, delta, total)
                };
                assert_eq!(
                    result.is_ok(),
                    balance >= i128::from(unspent),
                    "charge step {step}"
                );
                if let Err(error) = result {
                    assert!(error.is(crate::ErrorCode::PublicMutationCpuBudget));
                }
            }
            (3, Some(total)) => {
                assert!(
                    budget.settle(now, Some(delta), Some(total)),
                    "settle step {step}"
                );
                balance -= i128::from(delta);
                requests[slot] = None;
            }
            _ => budget.refill(now),
        }
        let active = requests.iter().flatten().count();
        let unspent: u64 = requests
            .iter()
            .flatten()
            .map(|cpu| reserve.saturating_sub(*cpu))
            .sum();
        assert_eq!(budget.in_flight, active, "active step {step}");
        assert_eq!(
            budget.credit_ns + (active as i128) * i128::from(reserve),
            balance,
            "balance step {step}"
        );
        assert_eq!(
            budget.spendable_credit().unwrap(),
            balance - i128::from(unspent),
            "free step {step}"
        );
        assert!(!budget.unavailable, "unknown step {step}");
    }
    for total in requests.into_iter().flatten() {
        assert!(budget.settle(
            start + std::time::Duration::from_nanos(last_ns),
            Some(0),
            Some(total)
        ));
    }
    assert_eq!(budget.in_flight, 0);
    assert_eq!(budget.spent_start_reserves_ns, 0);
    assert_eq!(budget.credit_ns, balance);
}

#[test]
fn an_incomplete_sample_join_cannot_refund_an_unclosed_consumed_reserve() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    budget.reserve(now).unwrap();
    budget.charge_request_live(now, 7, 7).unwrap();
    let credit = budget.credit_ns;
    assert!(!budget.settle(now, Some(0), Some(0)));
    assert_eq!(budget.credit_ns, credit);
    assert!(budget.unavailable);
    assert!(budget.reserve(now).is_err());
}

#[test]
fn a_consumed_reserve_without_an_active_owner_cannot_fund_new_admission() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    budget.credit_ns = 0;
    budget.spent_start_reserves_ns = MUTATION_CPU_START_RESERVE_NS;
    assert!(budget
        .reserve(now)
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    assert_eq!(budget.credit_ns, 0);
    assert_eq!(budget.in_flight, 0);
}
