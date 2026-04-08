use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn duplicate_probe_noise_does_not_cool_warm_fairness_with_dual_backlog() {
    let mut gate = LaneAdmissionGate::new(8, 3);

    // Build sustained critical pressure first, then add normal backlog so the
    // lane enters the warm anti-starvation regime under active dual backlog.
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

    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(104, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Warm fairness grants the first normal anti-starvation turn.
    assert_eq!(gate.pop_ready(), Some(1));

    // While both queues remain backlogged, duplicate probes across classes must
    // not perturb fairness bookkeeping or poison fresh classification.
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(103, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // With fairness already warm and dual backlog still active, the remaining
    // oldest normal item should still get service within one additional dequeue.
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(2)),
        "warm fairness should survive duplicate probe noise while dual backlog remains active"
    );
}
