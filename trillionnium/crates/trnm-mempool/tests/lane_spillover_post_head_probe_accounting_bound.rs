use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn spillover_head_drain_probe_noise_keeps_queue_accounting_and_next_normal_turn_stable() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Fill reserved critical capacity, then overflow one critical item into the
    // normal lane so it becomes the normal-queue head.
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

    // Add real normal backlog behind the spillovered critical item and refill
    // one more critical tx to reach full global saturation.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (4, 2, 6));

    // The spillovered critical item at the normal-queue head may drain first.
    assert_eq!(gate.pop_ready(), Some(102));
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    // Post-head-drain probe noise must not perturb queue accounting: drained ids
    // are fresh again, queued ids remain duplicates, and full-lane fresh probes
    // stay backpressured.
    assert_eq!(
        gate.admit(102, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (4, 2, 6));
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (4, 2, 6));
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (4, 2, 6));

    // After one critical dequeue, warm fairness should still give the oldest real
    // normal item a turn within one additional dequeue instead of cooling due to
    // the probe noise or the drained spillover id's reentry.
    assert_eq!(gate.pop_ready(), Some(100));
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(1)),
        "oldest real normal item should still get a turn within one additional dequeue after spillover head drain and probe noise"
    );
}
