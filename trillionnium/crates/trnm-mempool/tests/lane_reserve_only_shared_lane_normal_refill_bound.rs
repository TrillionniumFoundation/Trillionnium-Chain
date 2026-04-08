use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn reserve_only_shared_lane_duplicate_probe_does_not_poison_following_normal_refill() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode collapses both execution domains into the shared critical
    // lane. Cross-class duplicate probes must therefore remain classification-only
    // and must not consume or strand shared-lane capacity needed by later normal
    // ingress.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 2, 2));

    // Probing the queued critical id from the opposite class must not fabricate
    // extra queue state while the shared lane still has open headroom.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.queued_counts(), (0, 2, 2));

    // The final shared-lane slot remains available for fresh normal ingress.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // Once full, a fresh normal id stays backpressured until one dequeue frees
    // shared-lane capacity, regardless of the earlier duplicate noise.
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);

    // Shared-lane FIFO must remain intact across the refill boundary.
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), Some(99));
    assert_eq!(gate.pop_ready(), None);
}
