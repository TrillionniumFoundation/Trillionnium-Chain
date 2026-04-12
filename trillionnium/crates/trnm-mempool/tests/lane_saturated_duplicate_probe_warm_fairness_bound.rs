use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn saturated_duplicate_probe_noise_does_not_cool_warm_fairness_with_dual_backlog() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Build critical pressure first, then admit normal backlog while critical work
    // remains queued so fairness warmup is armed under active dual backlog.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(100));

    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Warm fairness grants the first normal anti-starvation turn.
    assert_eq!(gate.pop_ready(), Some(1));

    // Refill to global capacity so subsequent duplicate probes happen while the
    // lane remains saturated with active backlog on both classes.
    assert_eq!(
        gate.admit(104, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    // Duplicate retries from either class must stay Duplicate and must not cool
    // warm fairness while both backlogs remain active.
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    // Warm fairness should still deliver the oldest remaining normal item within
    // one additional dequeue instead of forcing another full critical burst.
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(2)),
        "warm fairness should survive saturated duplicate-probe noise while dual backlog remains active"
    );
}
