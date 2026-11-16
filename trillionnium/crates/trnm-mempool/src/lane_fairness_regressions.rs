//! Scheduling regressions for shared-lane and clamped-reserve admission.

use super::*;

#[test]
fn oversized_reserve_clamp_keeps_reserve_only_fairness_cold() {
    let mut g = LaneAdmissionGate::new(2, 99);

    // Misconfigured reserve > total must clamp into reserve-only mode rather than
    // fabricating dedicated normal capacity or warm fairness state.
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert_eq!(g.critical_served_streak, 0);

    // Even if stale fairness state leaked in from recovery, reserve-only dequeue
    // order must not synthesize a normal turn from the misconfigured split.
    g.critical_served_streak = g.critical_burst_limit;
    assert_eq!(g.pop_ready(), Some(10));
    assert_eq!(g.critical_served_streak, 0);
    assert_eq!(g.pop_ready(), Some(11));
    assert_eq!(g.critical_served_streak, 0);
}

#[test]
fn critical_spillover_warms_normal_fairness_like_direct_normal_admission() {
    let mut g = LaneAdmissionGate::new(4, 2);

    // Saturate the critical reserve first.
    assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);

    // The next critical ingress spills into free normal capacity while both
    // lanes stay backlogged.
    assert_eq!(g.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);

    // Critical spillover should arm the same fairness warmup contract as a
    // direct normal admission, so the newly occupied normal lane gets the next turn.
    assert_eq!(g.pop_ready(), Some(102));
    assert_eq!(g.pop_ready(), Some(100));
}

#[test]
fn zero_reserve_shared_queue_duplicate_probes_do_not_invent_cross_domain_preemption() {
    let mut g = LaneAdmissionGate::new(3, 0);

    // Zero-reserve mode collapses both ingress classes into the shared normal lane.
    // Mixed-class retries must remain classification-only and must not synthesize
    // fairness/preemption state that perturbs shared FIFO dequeue order.
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 0, 3));

    // Cross-class duplicate probes stay Duplicate while the tx ids are queued.
    assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Duplicate);

    // The shared queue must still drain in pure FIFO order; duplicate probe noise
    // must not create synthetic critical preference or warm fairness state.
    assert_eq!(g.pop_ready(), Some(10));
    assert_eq!(g.pop_ready(), Some(20));
    assert_eq!(g.pop_ready(), Some(30));
    assert_eq!(g.queued_counts(), (0, 0, 0));
    assert_eq!(g.critical_served_streak, 0);
}

#[test]
fn zero_reserve_idle_self_heal_does_not_leak_stale_fairness_into_next_shared_batch() {
    let mut g = LaneAdmissionGate::new(3, 0);

    // Simulate restored idle state with stale fairness/bookkeeping. In zero-reserve
    // mode, the next mixed batch still shares one FIFO lane and must not inherit a
    // synthetic normal-vs-critical scheduling preference.
    g.critical_served_streak = g.critical_burst_limit;
    g.normal.seen.insert(7001);
    g.seen_global.insert(7002);

    assert_eq!(g.pop_ready(), None);
    assert_eq!(g.critical_served_streak, 0);
    assert!(g.normal.seen.is_empty());
    assert!(g.critical.seen.is_empty());
    assert!(g.seen_global.is_empty());

    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(30, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 0, 3));

    // Zero-reserve mode must stay pure shared-lane FIFO after idle self-heal.
    assert_eq!(g.pop_ready(), Some(20));
    assert_eq!(g.pop_ready(), Some(10));
    assert_eq!(g.pop_ready(), Some(30));
    assert_eq!(g.critical_served_streak, 0);
}

#[test]
fn reserve_only_duplicate_probe_noise_does_not_preempt_existing_critical_fifo() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    assert_eq!(
        gate.admit(900, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(901, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // Reserve-only mode collapses both ingress classes into the shared critical
    // queue. Cross-class duplicate probes must stay classification-only and must
    // not synthesize fairness/preemption state that perturbs shared FIFO order.
    assert_eq!(
        gate.admit(900, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    assert_eq!(gate.pop_ready(), Some(900));
    assert_eq!(gate.pop_ready(), Some(901));
    assert_eq!(gate.pop_ready(), Some(1));
}

#[test]
fn oversized_critical_reserve_clamp_reopened_slot_remains_cross_class_fresh_until_reused() {
    let mut g = LaneAdmissionGate::new(2, 5);

    // Saturate the reserve-only shared lane and confirm a fresh normal retry is
    // fail-closed rather than cached as a duplicate while no headroom exists.
    assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(
        g.admit(22, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(22, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // A single real drain reopens one shared slot even though critical backlog is
    // still active. The previously backpressured id must admit as fresh through
    // either class, then immediately dedupe across the other class.
    assert_eq!(g.pop_ready(), Some(20));
    assert_eq!(g.admit(22, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(22, IngressClass::Normal), AdmitOutcome::Duplicate);
}

#[test]
fn reserve_only_active_backlog_duplicate_probe_keeps_reopened_shared_headroom_flat() {
    let mut g = LaneAdmissionGate::new(3, 3);

    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 2, 2));

    let reopened = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(g.qos_snapshot(), reopened);

    // In reserve-only mode, duplicate probes against active backlog must stay
    // purely classificatory: they cannot consume or hide the one genuinely
    // reopened shared slot that both ingress classes may still use.
    assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(g.qos_snapshot(), reopened);
    assert_eq!(g.queued_counts(), (0, 2, 2));
    assert_eq!(g.seen_global.len(), 2);

    assert_eq!(g.admit(12, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (0, 3, 3));
    assert_eq!(g.seen_global.len(), 3);
}
