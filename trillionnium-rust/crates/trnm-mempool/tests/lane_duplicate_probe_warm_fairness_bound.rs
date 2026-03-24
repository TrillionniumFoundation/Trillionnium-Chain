use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn duplicate_probe_noise_does_not_cool_warm_fairness_with_active_dual_backlog() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Build critical pressure first so the first later normal arrival warms fairness
    // while critical work remains queued.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(100));

    // Normal backlog appears under active critical pressure and should arm warm fairness.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // The first anti-starvation turn should go to normal.
    assert_eq!(gate.pop_ready(), Some(1));

    // Duplicate probe noise against still-queued ids from either class must not cool
    // the already-warm fairness state while both lanes remain backlogged.
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(101, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // Warm fairness should still deliver the remaining normal item within one
    // additional dequeue instead of forcing another full critical burst.
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(2)),
        "warm fairness should survive duplicate-probe noise while dual backlog remains active"
    );
}
