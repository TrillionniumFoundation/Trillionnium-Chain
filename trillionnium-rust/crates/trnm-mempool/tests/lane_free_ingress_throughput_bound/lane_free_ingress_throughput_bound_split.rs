use super::*;

#[test]
fn reserve_only_split_keeps_normal_free_ingress_live_while_critical_headroom_exists() {
    // Degenerate split: all capacity reserved for critical lane.
    // Contract: normal ingress can still borrow free critical headroom.
    let mut gate = LaneAdmissionGate::new(3, 3);

    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    let (normal, critical, total) = gate.queued_counts();
    assert_eq!(normal, 0, "reserve-only mode should spill normal ingress");
    assert_eq!(
        critical, 2,
        "borrowed normal ingress should land in critical lane"
    );
    assert_eq!(total, 2);
}

#[test]
fn reserve_only_split_backpressures_fresh_normal_ingress_once_borrowed_headroom_is_full() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // No free headroom remains to borrow: fresh normal ingress must backpressure,
    // not silently over-admit.
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
}

#[test]
fn reserve_only_mixed_ingress_keeps_fifo_progress_without_fairness_detours() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // In reserve-only split, all ingress lands on the critical queue. Mixed class
    // submit order should still drain FIFO so free-ingress throughput does not
    // regress behind fairness bookkeeping intended for dual-lane mode.
    assert_eq!(gate.admit(61, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(62, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(63, IngressClass::Normal), AdmitOutcome::Accepted);

    assert_eq!(gate.pop_ready(), Some(61));
    assert_eq!(gate.pop_ready(), Some(62));
    assert_eq!(gate.pop_ready(), Some(63));
}

#[test]
fn zero_reserve_critical_ingress_uses_free_normal_headroom_without_dedicated_critical_lane() {
    let mut gate = LaneAdmissionGate::new(1, 0);

    // With no dedicated critical reserve, critical ingress should still stay live
    // by spilling into free normal headroom.
    assert_eq!(
        gate.admit(80, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (1, 0, 1));

    // Global saturation still backpressures fresh ingress until one tx drains.
    assert_eq!(
        gate.admit(81, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.pop_ready(), Some(80));
}
