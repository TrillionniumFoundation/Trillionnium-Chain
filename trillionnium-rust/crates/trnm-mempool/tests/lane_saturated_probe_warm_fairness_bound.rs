use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn saturated_fresh_probe_noise_does_not_cool_warm_fairness_with_dual_backlog() {
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

    // Refill to global capacity so subsequent fresh ingress probes are saturated.
    assert_eq!(
        gate.admit(104, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    // Saturated fresh probes from either class must remain backpressured and must
    // not cool warm fairness while both backlogs remain active.
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Warm fairness should still deliver the oldest remaining normal item within
    // one additional dequeue instead of forcing another full critical burst.
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(2)),
        "warm fairness should survive saturated fresh-probe noise while dual backlog remains active"
    );
}
