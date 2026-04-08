use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn oversized_critical_reserve_full_drain_resets_for_cross_class_reuse_and_cold_fifo_progress() {
    // reserve > total must clamp into reserve-only mode without leaving behind
    // stale duplicate or fairness state after a true full drain.
    let mut gate = LaneAdmissionGate::new(3, 99);

    // Borrowed normal ingress and native critical ingress should share the clamped
    // reserve-only headroom in FIFO order.
    assert_eq!(
        gate.admit(100, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(102, IngressClass::Normal),
        AdmitOutcome::Accepted
    );

    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(101));
    assert_eq!(gate.pop_ready(), Some(102));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // After the full-drain boundary, the previously drained id must be reusable
    // across classes as fresh ingress rather than staying duplicate-poisoned.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(200, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(201, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Clamp-to-reserve-only mode should restart cold after the drain: FIFO shared
    // queue progress, no stale duplicate state, and no fairness detours.
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(200));
    assert_eq!(gate.pop_ready(), Some(201));
    assert_eq!(gate.pop_ready(), None);
}
