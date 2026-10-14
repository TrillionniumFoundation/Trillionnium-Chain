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
