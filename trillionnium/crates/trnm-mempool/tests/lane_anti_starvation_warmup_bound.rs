use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn newly_arrived_normal_backlog_gets_a_turn_within_one_dequeue_under_critical_pressure() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Keep critical pressure active and consume one critical dequeue to build streak.
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
    assert!(gate.pop_ready().is_some());

    // Normal backlog arrives while critical backlog is still active.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Anti-starvation contract: normal should get service within one dequeue,
    // not wait behind another full critical burst.
    assert_eq!(gate.pop_ready(), Some(1));
}
