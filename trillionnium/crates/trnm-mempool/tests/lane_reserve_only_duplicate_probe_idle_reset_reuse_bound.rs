use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn reserve_only_duplicate_probe_noise_and_idle_polls_do_not_poison_cross_class_reuse() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only split: all queued work lives in the critical lane while normal
    // ingress may borrow idle headroom.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // While saturated, duplicate probes for a still-queued borrowed id must stay
    // Duplicate across classes without mutating the queued contract.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(10, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // Drain completely so reserve-only idempotency state crosses the full-drain
    // self-heal boundary.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Long-lived schedulers may keep polling after a drained lane. Those idle
    // polls must stay no-op and must not preserve stale duplicate markers.
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.pop_ready(), None);

    // The previously duplicated id must be reusable as a fresh tx across classes
    // after the full-drain + idle-poll boundary.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(10, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.pop_ready(), Some(10));

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), None);
}
