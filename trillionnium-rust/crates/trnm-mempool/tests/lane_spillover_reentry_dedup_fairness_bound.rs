use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn spillover_head_reentry_rededupes_across_classes_without_cooling_next_real_normal_turn() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Fill reserved critical capacity, then overflow one critical item into the
    // normal lane so it becomes the normal-queue head under active dual backlog.
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
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (4, 2, 6));

    // The spillovered head may drain first from the normal lane.
    assert_eq!(gate.pop_ready(), Some(102));
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    // Re-enter the drained spillover id via the original critical class. Once it
    // is queued again, duplicate retries from either class must immediately be
    // rejected without perturbing queue accounting.
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (4, 2, 6));
    assert_eq!(
        gate.admit(102, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (4, 2, 6));

    // Warm fairness should stay live despite the reentry + duplicate noise: after
    // one more critical dequeue, the oldest real normal item should still get a
    // turn within one additional dequeue.
    assert_eq!(gate.pop_ready(), Some(100));
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(1)),
        "oldest real normal item should still get a turn within one additional dequeue after spillover head reentry and duplicate noise"
    );
}
