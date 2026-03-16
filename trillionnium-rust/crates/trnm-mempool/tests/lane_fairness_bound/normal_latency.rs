use super::*;

#[test]
fn normal_backlog_gets_service_within_one_pop_after_arrival_under_critical_pressure() {
    let mut gate = LaneAdmissionGate::new(8, 3);

    // Establish sustained critical pressure and consume a few critical turns.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(101));

    // Normal traffic appears while critical backlog is still active.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Anti-starvation contract: normal gets a turn no later than the next dequeue.
    // (Immediate service is acceptable and currently expected.)
    let first = gate.pop_ready();
    let second = gate.pop_ready();
    assert!(first == Some(1) || second == Some(1));
}

#[test]
fn mixed_batch_after_full_drain_still_grants_normal_turn_within_one_pop() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Warm fairness with dual-lane backlog and drain everything.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    let mut drained = vec![gate.pop_ready(), gate.pop_ready(), gate.pop_ready()];
    drained.sort_unstable();
    assert_eq!(drained, vec![Some(1), Some(100), Some(101)]);

    // Contract guard: after a full drain, the next mixed batch should still
    // preserve bounded normal latency under critical pressure.
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    let first = gate.pop_ready();
    let second = gate.pop_ready();
    assert!(first == Some(2) || second == Some(2));
}

#[test]
fn sustained_critical_pressure_with_normal_backlog_keeps_normal_latency_bounded() {
    let mut gate = LaneAdmissionGate::new(8, 3);

    // Build mixed backlog where normal traffic arrives while critical traffic stays active.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Contract: once fairness is warm under active critical pressure, normal backlog
    // should receive service within at most one additional dequeue.
    let p1 = gate.pop_ready();
    let p2 = gate.pop_ready();
    assert!(matches!(
        (p1, p2),
        (Some(1), _) | (_, Some(1)) | (Some(2), _) | (_, Some(2))
    ));
}
