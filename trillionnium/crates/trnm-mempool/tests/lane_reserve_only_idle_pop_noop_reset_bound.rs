use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn repeated_empty_pop_after_reserve_only_full_drain_does_not_poison_next_batch_reuse_or_fifo() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes all live work through the critical lane while still
    // allowing normal ingress to borrow idle headroom.
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

    // Mixed-class submit order should drain FIFO in reserve-only mode.
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(101));
    assert_eq!(gate.pop_ready(), Some(102));
    assert_eq!(gate.pop_ready(), None);

    // Long-lived schedulers may keep polling an already drained reserve-only lane.
    // Those idle polls must remain a no-op and must not poison reuse or ordering.
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.pop_ready(), None);

    // The drained id must be reusable across classes after the full-drain boundary.
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

    // Reserve-only mode should still restart cold after the idle poll noise: FIFO
    // progress, no stale duplicate state, and no fairness detours.
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(200));
    assert_eq!(gate.pop_ready(), Some(201));
    assert_eq!(gate.pop_ready(), None);
}
