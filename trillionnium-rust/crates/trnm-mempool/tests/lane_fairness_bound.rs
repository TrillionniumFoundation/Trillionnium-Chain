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
