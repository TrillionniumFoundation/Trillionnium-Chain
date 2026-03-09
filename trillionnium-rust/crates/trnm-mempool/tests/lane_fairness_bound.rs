use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn normal_backlog_gets_service_within_one_pop_after_arrival_under_critical_pressure() {
    let mut gate = LaneAdmissionGate::new(8, 3);

    // Establish sustained critical pressure and consume a few critical turns.
    assert_eq!(gate.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(101));

    // Normal traffic appears while critical backlog is still active.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(103, IngressClass::Critical), AdmitOutcome::Accepted);

    // Anti-starvation contract: normal gets a turn no later than the next dequeue.
    // (Immediate service is acceptable and currently expected.)
    let first = gate.pop_ready();
    let second = gate.pop_ready();
    assert!(first == Some(1) || second == Some(1));
}

#[test]
fn critical_spillover_in_normal_lane_gets_turn_within_one_pop_under_critical_pressure() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Saturate reserved critical capacity.
    assert_eq!(gate.admit(200, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(201, IngressClass::Critical), AdmitOutcome::Accepted);

    // Keep some critical backlog active while admitting one overflow critical tx
    // via normal-lane spillover.
    assert_eq!(gate.admit(202, IngressClass::Critical), AdmitOutcome::Accepted);

    // Overflowed critical tx in normal lane should not wait through a full burst.
    let first = gate.pop_ready();
    let second = gate.pop_ready();
    assert!(first == Some(202) || second == Some(202));
}

#[test]
fn drained_lane_clears_warm_fairness_before_next_critical_only_batch() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Warm fairness with dual-lane backlog and consume one normal fairness turn.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);

    // Drain the mixed batch fully; exact ordering is strategy-dependent.
    let mut drained = vec![gate.pop_ready(), gate.pop_ready(), gate.pop_ready()];
    drained.sort_unstable();
    assert_eq!(drained, vec![Some(1), Some(100), Some(101)]);

    // Fresh critical-only batch after full drain should not inherit stale warmed
    // fairness state from the prior mixed batch.
    assert_eq!(gate.admit(200, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.pop_ready(), Some(200));
}
