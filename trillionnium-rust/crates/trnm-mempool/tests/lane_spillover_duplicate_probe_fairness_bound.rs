use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn duplicate_probe_against_spillovered_critical_does_not_cool_first_real_normal_turn() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Fill reserved critical capacity first.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Overflow one critical item into the normal lane while it is still empty.
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Duplicate probe noise against the spillovered item must not perturb the
    // fairness warmup state that this path is supposed to arm.
    assert_eq!(
        gate.admit(102, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    // Real normal backlog arrives while critical pressure remains active.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // The spillovered critical item at the normal-queue head may drain first, but
    // duplicate probe noise must not force the first real normal item to wait
    // behind another full critical burst.
    assert_eq!(gate.pop_ready(), Some(102));
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(1)),
        "first real normal item should still get a turn within one additional dequeue after spillover duplicate probes"
    );
}
