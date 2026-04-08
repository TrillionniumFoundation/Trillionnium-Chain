use super::*;

#[test]
fn reserve_only_borrowed_normal_ingress_preserves_cross_class_idempotency_until_drain() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // In reserve-only split, normal ingress borrows critical headroom.
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);

    // Cross-class retries for the same tx id must dedupe while queued.
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    // Once drained, the id should become admissible again.
    assert_eq!(gate.pop_ready(), Some(30));
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}

#[test]
fn reserve_only_critical_ingress_preserves_cross_class_idempotency_until_drain() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    // Critical ingress occupies reserve-only capacity directly.
    assert_eq!(
        gate.admit(50, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Same tx retried via normal class must still dedupe while queued.
    assert_eq!(
        gate.admit(50, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // After drain, cross-class retry should be fresh/admissible again.
    assert_eq!(gate.pop_ready(), Some(50));
    assert_eq!(gate.admit(50, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn reserve_only_full_drain_resets_idempotency_for_immediate_free_ingress_reuse() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    // Reserve-only split: mixed classes share the critical queue.
    assert_eq!(
        gate.admit(500, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(501, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Drain fully so no stale idempotency/fairness state survives.
    assert_eq!(gate.pop_ready(), Some(500));
    assert_eq!(gate.pop_ready(), Some(501));
    assert_eq!(gate.pop_ready(), None);

    // Same id should be immediately reusable as fresh ingress after full drain.
    assert_eq!(
        gate.admit(500, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    // And free-ingress borrowing for normal should remain live in the same cycle.
    assert_eq!(
        gate.admit(502, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
}
