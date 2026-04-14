use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn reserve_only_shared_lane_duplicate_probe_does_not_poison_following_critical_refill() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode isolates all execution through the shared critical lane.
    // Normal ingress may borrow headroom, but duplicate probe noise must stay
    // classification-only and must not perturb the next critical refill.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (0, 2, 2));

    // Cross-class duplicate probes for a borrowed id must not fabricate extra
    // queue state while aggregate headroom is still open.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (0, 2, 2));

    // The remaining shared-lane slot is still usable for fresh ingress.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // Once full, a fresh critical id stays backpressured until one dequeue frees
    // shared-lane capacity, regardless of the earlier duplicate noise.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Shared-lane FIFO must remain intact across the refill boundary.
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), Some(99));
    assert_eq!(gate.pop_ready(), None);
}
