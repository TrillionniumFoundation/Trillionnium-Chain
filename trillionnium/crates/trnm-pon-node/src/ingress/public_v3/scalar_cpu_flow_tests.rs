//! Arithmetic controls, not synthetic receiver CPU or service acceptance.
use super::*;
use std::time::Duration;

fn snapshot(budget: &PaidMutationCpuBudget) -> Option<ServiceMutationCpuFlowObservation> {
    (!budget.unavailable)
        .then(|| {
            budget
                .flow
                .as_ref()
                .and_then(|flow| flow.snapshot(budget.credit_ns, budget.in_flight))
        })
        .flatten()
}
#[test]
fn actual_cpu_flow_tracks_two_owned_reserves_extension_and_finish_once() {
    let mut b = PaidMutationCpuBudget::new();
    let now = b.updated;
    b.reserve(now).unwrap();
    b.reserve(now).unwrap();
    assert_eq!(snapshot(&b).unwrap().booked_reservation_ns, 200_000_000);
    b.charge_request_live(now, 120_000_000, 120_000_000)
        .unwrap();
    let live = snapshot(&b).unwrap();
    assert_eq!(live.unsettled_known_live_cpu_ns, 120_000_000);
    assert_eq!(live.booked_reservation_ns, 200_000_000);
    assert!(b.settle_observed(now, Some(5_000_000), Some(125_000_000), Some(120_000_000)));
    let first = snapshot(&b).unwrap();
    assert_eq!(first.settled_full_cpu_ns, 125_000_000);
    assert_eq!(first.paid_cpu_debit_ns, 125_000_000);
    assert_eq!(first.unsettled_known_live_cpu_ns, 0);
    assert_eq!(first.booked_reservation_ns, 100_000_000);
    b.charge_request_live(now, 30_000_000, 30_000_000).unwrap();
    assert!(b.settle_observed(now, Some(3_000_000), Some(33_000_000), Some(30_000_000)));
    let end = snapshot(&b).unwrap();
    assert_eq!(end.paid_cpu_debit_ns, 158_000_000);
    assert_eq!(end.live_debited_cpu_ns, 150_000_000);
    assert_eq!(end.settlement_residual_cpu_ns, 8_000_000);
    assert_eq!(end.settled_full_cpu_ns, 158_000_000);
    assert_eq!(end.booked_reservation_ns, 0);
    assert_eq!(end.remaining_paid_credit_ns, 1_842_000_000);
    assert_eq!(end.stored_credit_ns, end.remaining_paid_credit_ns);
}
#[test]
fn actual_cpu_flow_measures_credited_refill_and_cap_discard() {
    let mut b = PaidMutationCpuBudget::new();
    let now = b.updated;
    b.reserve(now).unwrap();
    b.charge_request_live(now, 50_000_000, 50_000_000).unwrap();
    b.refill(now + Duration::from_secs(1));
    let live = snapshot(&b).unwrap();
    assert_eq!(live.credited_refill_ns, 50_000_000);
    assert_eq!(live.discarded_refill_ns, 200_000_000);
    assert_eq!(live.remaining_paid_credit_ns, 2_000_000_000);
    assert!(b.settle_observed(
        now + Duration::from_secs(1),
        Some(0),
        Some(50_000_000),
        Some(50_000_000)
    ));
    b.refill(now + Duration::from_secs(2));
    let end = snapshot(&b).unwrap();
    assert_eq!(end.credited_refill_ns, 50_000_000);
    assert_eq!(end.discarded_refill_ns, 450_000_000);
    assert_eq!(end.settled_full_cpu_ns, 50_000_000);
    assert_eq!(end.unsettled_known_live_cpu_ns, 0);
    let before = b.updated;
    b.refill(now);
    assert_eq!(b.updated, before);
    assert_eq!(snapshot(&b).unwrap(), end);
}
#[test]
fn actual_cpu_flow_unknown_overflow_does_not_modify_original_policy() {
    let mut b = PaidMutationCpuBudget::new();
    let now = b.updated;
    b.flow.as_mut().unwrap().discarded_refill_ns = u64::MAX;
    b.refill(now + Duration::from_secs(1));
    assert!(snapshot(&b).is_none());
    assert_eq!(b.credit_ns, i128::from(MUTATION_CPU_BURST_NS));
    assert!(!b.unavailable);
    b.reserve(now + Duration::from_secs(1)).unwrap();
    assert_eq!(b.in_flight, 1);
    assert!(b.settle_observed(now + Duration::from_secs(1), Some(0), Some(0), Some(0)));
    assert!(!b.unavailable);
}
#[test]
fn actual_cpu_flow_wrong_attribution_and_balance_stay_unknown() {
    let mut b = PaidMutationCpuBudget::new();
    let now = b.updated;
    b.reserve(now).unwrap();
    b.charge_request_live(now, 60_000_000, 60_000_000).unwrap();
    assert!(b.settle_observed(now, Some(5_000_000), Some(99_000_000), Some(60_000_000)));
    assert!(snapshot(&b).is_none());
    assert_eq!(b.credit_ns, 1_935_000_000);
    assert!(!b.unavailable);
    let mut corrupt = PaidMutationCpuBudget::new();
    corrupt.credit_ns -= 1;
    assert!(snapshot(&corrupt).is_none());
    assert!(!corrupt.unavailable);
    corrupt.reserve(corrupt.updated).unwrap();
    assert!(snapshot(&corrupt).is_none());
}
#[test]
fn actual_cpu_flow_unknown_clock_and_lost_reserve_do_not_fabricate_identity() {
    let mut b = PaidMutationCpuBudget::new();
    let now = b.updated;
    b.reserve(now).unwrap();
    assert!(!b.settle_observed(now, None, None, None));
    assert!(b.unavailable);
    assert!(snapshot(&b).is_none());
    let mut lost = PaidMutationCpuBudget::new();
    let now = lost.updated;
    lost.reserve(now).unwrap();
    lost.in_flight = 0;
    assert!(snapshot(&lost).is_none());
    assert!(!lost.settle_observed(now, Some(0), Some(0), Some(0)));
    assert!(lost.unavailable);
    assert!(snapshot(&lost).is_none());
}
#[test]
fn actual_cpu_flow_optional_read_preserves_old_observation_json_and_credit() {
    let domain = ServiceMutationCpuDomain::standalone();
    let before = domain.observe().unwrap();
    let old_json = serde_json::to_value(&before).unwrap();
    assert_eq!(old_json.as_object().unwrap().len(), 8);
    let one = domain.observe_actual_flow().unwrap().unwrap();
    let two = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(one, two);
    assert_eq!(before, domain.observe().unwrap());
    assert_eq!(one.schema, "public-v3-local-actual-cpu-flow-v1");
    assert!(one.balance_identity_verified);
}

#[test]
fn freshness_separates_paid_stored_depletion_from_later_scalar_start_eligibility() {
    let mut budget = PaidMutationCpuBudget::new();
    let now = budget.updated;
    budget.reserve(now).unwrap();
    assert!(budget.settle_observed(now, Some(1_950_000_000), Some(1_950_000_000), Some(0)));
    let original = snapshot(&budget).unwrap();
    assert_eq!(original.remaining_paid_credit_ns, 50_000_000);
    let fresh = budget.credit_freshness_at(now).unwrap();
    assert!(!fresh.projected_scalar_start_eligible);
    let later = now + Duration::from_secs(1);
    let stale = budget.credit_freshness_at(later).unwrap();
    assert_eq!(stale.watermark_age_ns, 1_000_000_000);
    assert_eq!(stale.actual_flow, original);
    assert_eq!(stale.projected_credited_refill_ns, 250_000_000);
    assert_eq!(stale.projected_stored_credit_ns, 300_000_000);
    assert!(stale.projected_scalar_start_eligible);
    assert_eq!(budget.updated, now);
    assert_eq!(snapshot(&budget).unwrap(), original);
    // The original real reservation, not the observation, grants this start.
    budget.reserve(later).unwrap();
    assert_eq!(
        budget.credit_ns,
        stale.projected_stored_credit_ns - 100_000_000
    );
}

#[test]
fn freshness_matches_original_refill_with_debt_and_outstanding_reserves() {
    for owners in 0..=MUTATION_CPU_WORKERS {
        for paid in [0, 1_950_000_000, 3_000_000_000] {
            let mut budget = PaidMutationCpuBudget::new();
            let now = budget.updated;
            budget.reserve(now).unwrap();
            assert!(budget.settle_observed(now, Some(paid), Some(paid), Some(0)));
            for _ in 0..owners {
                // Use an original refill to fund actual outstanding starts;
                // the zero-owner case retains any debt until observation.
                budget.reserve(now + Duration::from_secs(20)).unwrap();
            }
            let watermark = budget.updated;
            let before = snapshot(&budget).unwrap();
            let observed_at = watermark + Duration::from_secs(1);
            let projected = budget.credit_freshness_at(observed_at).unwrap();
            assert_eq!(snapshot(&budget).unwrap(), before);
            assert_eq!(budget.updated, watermark);
            budget.refill(observed_at);
            assert_eq!(projected.projected_stored_credit_ns, budget.credit_ns);
            assert_eq!(
                projected.projected_paid_credit_ns,
                snapshot(&budget).unwrap().remaining_paid_credit_ns
            );
            assert_eq!(
                projected.projected_scalar_start_eligible,
                owners < MUTATION_CPU_WORKERS
                    && budget.credit_ns >= i128::from(MUTATION_CPU_START_RESERVE_NS)
            );
        }
    }
}

#[test]
fn freshness_unknown_clock_or_flow_never_fabricates_refill_or_changes_budget() {
    for mode in [
        "unavailable",
        "missing-flow",
        "bad-flow",
        "lost-owner",
        "future-watermark",
        "discard-counter-overflow",
    ] {
        let mut budget = PaidMutationCpuBudget::new();
        let observed_at = budget.updated;
        match mode {
            "unavailable" => budget.unavailable = true,
            "missing-flow" => budget.flow = None,
            "bad-flow" => budget.flow.as_mut().unwrap().initial_credit_ns += 1,
            "lost-owner" => budget.in_flight = MUTATION_CPU_WORKERS + 1,
            "future-watermark" => budget.updated += Duration::from_secs(1),
            "discard-counter-overflow" => {
                budget.flow.as_mut().unwrap().discarded_refill_ns = u64::MAX
            }
            _ => unreachable!(),
        };
        let before = (
            budget.credit_ns,
            budget.updated,
            budget.in_flight,
            budget.unavailable,
        );
        let original_flow = snapshot(&budget);
        let sampled_at = if mode == "discard-counter-overflow" {
            observed_at + Duration::from_secs(1)
        } else {
            observed_at
        };
        assert!(budget.credit_freshness_at(sampled_at).is_none());
        assert_eq!(snapshot(&budget), original_flow);
        assert_eq!(
            before,
            (
                budget.credit_ns,
                budget.updated,
                budget.in_flight,
                budget.unavailable
            )
        );
    }
}

#[test]
fn public_freshness_read_is_optional_and_preserves_original_schema_and_flow() {
    let domain = ServiceMutationCpuDomain::standalone();
    let before = domain.observe().unwrap();
    let flow = domain.observe_actual_flow().unwrap();
    let freshness = domain.observe_credit_freshness().unwrap().unwrap();
    assert_eq!(freshness.actual_flow, flow.clone().unwrap());
    assert_eq!(domain.observe().unwrap(), before);
    assert_eq!(domain.observe_actual_flow().unwrap(), flow);
    assert_eq!(
        serde_json::to_value(before)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        8
    );
    assert_eq!(freshness.projected_credited_refill_ns, 0);
    assert_eq!(
        freshness.projected_paid_credit_ns,
        i128::from(MUTATION_CPU_BURST_NS)
    );
}
