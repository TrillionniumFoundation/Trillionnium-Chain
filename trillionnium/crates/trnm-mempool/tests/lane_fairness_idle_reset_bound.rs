use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn drained_lane_resets_fairness_before_new_critical_arrival() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Build mixed backlog and consume one critical dequeue so fairness state becomes warm.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(21, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(20));

    // Drain the lane fully; any stale fairness state should die with the backlog.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(21));
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // New mixed ingress after the idle boundary should start cold: critical work
    // should preempt immediately instead of being spuriously delayed by old fairness.
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(40, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(40));
    assert_eq!(gate.pop_ready(), Some(30));
}
