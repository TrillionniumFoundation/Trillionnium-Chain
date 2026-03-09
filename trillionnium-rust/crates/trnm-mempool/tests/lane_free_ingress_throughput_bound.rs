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
