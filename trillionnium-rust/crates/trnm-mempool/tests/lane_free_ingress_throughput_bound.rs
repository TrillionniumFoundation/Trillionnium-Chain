use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn reserve_only_split_keeps_normal_free_ingress_live_while_critical_headroom_exists() {
    // Degenerate split: all capacity reserved for critical lane.
    // Contract: normal ingress can still borrow free critical headroom.
    let mut gate = LaneAdmissionGate::new(3, 3);

    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    let (normal, critical, total) = gate.queued_counts();
    assert_eq!(normal, 0, "reserve-only mode should spill normal ingress");
    assert_eq!(critical, 2, "borrowed normal ingress should land in critical lane");
    assert_eq!(total, 2);
}

#[test]
fn reserve_only_split_backpressures_fresh_normal_ingress_once_borrowed_headroom_is_full() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // No free headroom remains to borrow: fresh normal ingress must backpressure,
    // not silently over-admit.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Backpressured);
}

#[test]
fn reserve_only_split_backpressured_id_is_not_poisoned_across_class_after_drain() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(21, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(22, IngressClass::Normal), AdmitOutcome::Backpressured);

    // Drain one slot and ensure the previously backpressured id remains fresh,
    // even when retried via a different ingress class.
    assert!(gate.pop_ready().is_some());
    assert_eq!(gate.admit(22, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn reserve_only_borrowed_normal_ingress_preserves_cross_class_idempotency_until_drain() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // In reserve-only split, normal ingress borrows critical headroom.
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);

    // Cross-class retries for the same tx id must dedupe while queued.
    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Duplicate);

    // Once drained, the id should become admissible again.
    assert_eq!(gate.pop_ready(), Some(30));
    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Accepted);
}
