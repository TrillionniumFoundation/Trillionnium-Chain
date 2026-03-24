use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn spillover_warm_fairness_stays_live_after_first_spillover_turn_with_refill_and_probe_noise() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Fill dedicated critical reserve, then spill critical work into the normal
    // lane so the spillover path warms fairness under active dual backlog.
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

    // Build real normal backlog behind the spillovered critical item and refill
    // one more critical tx so the lane reaches global saturation.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (4, 2, 6));

    // Warm fairness may serve the spillovered critical item first because it is
    // at the normal-queue head.
    assert_eq!(gate.pop_ready(), Some(102));

    // Refill critical pressure immediately, then inject duplicate/fresh probe
    // noise while the lane is saturated again.
    assert_eq!(
        gate.admit(104, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (4, 2, 6));
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Contract guard: once spillover has warmed fairness, serving the spillovered
    // head item must not cool the anti-starvation state. Even after immediate
    // refill plus probe noise, the oldest real normal item should still get a
    // turn within one additional dequeue.
    assert_eq!(gate.pop_ready(), Some(100));
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(1)),
        "oldest real normal item should still get a turn within one additional dequeue after spillover warmup survives refill and probe noise"
    );
}
