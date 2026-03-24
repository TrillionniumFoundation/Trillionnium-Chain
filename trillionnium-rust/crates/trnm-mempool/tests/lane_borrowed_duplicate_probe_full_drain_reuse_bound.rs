use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_duplicate_probe_noise_does_not_poison_cross_class_reuse_after_full_drain() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity first.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // With the critical lane idle, normal ingress may borrow the final reserved
    // critical slot instead of being backpressured.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // Cross-class duplicate probe noise against the borrowed id must stay
    // Duplicate while queued and must not poison later reuse.
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // Fresh ids remain plain backpressure while the lane is saturated.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // Drain fully so idle/full-drain self-heal paths clear any stale lane-local,
    // lane-wide, and fairness bookkeeping left behind by the duplicate probes.
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // After the full drain boundary, the previously borrowed + probed id must be
    // reusable as fresh ingress through the opposite class.
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), None);
}
