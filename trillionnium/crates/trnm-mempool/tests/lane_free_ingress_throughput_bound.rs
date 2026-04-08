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
fn reserve_only_split_backpressured_id_is_not_poisoned_across_class_after_drain() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(21, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(22, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain one slot and ensure the previously backpressured id remains fresh,
    // even when retried via a different ingress class.
    assert!(gate.pop_ready().is_some());
    assert_eq!(
        gate.admit(22, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}

#[test]
fn reserve_only_split_backpressured_id_is_not_poisoned_on_same_class_retry_after_drain() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(40, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(41, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(42, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // While saturation persists, retries for a fresh backpressured id must remain
    // backpressured (not duplicate-poisoned), even if retried via another class.
    assert_eq!(
        gate.admit(42, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // Same-class retry should remain fresh once capacity is freed.
    assert!(gate.pop_ready().is_some());
    assert_eq!(gate.admit(42, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn reserve_only_split_fresh_backpressured_id_stays_backpressured_across_retries_until_drain() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(70, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(71, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Fresh id under saturation should remain Backpressured (not Duplicate) on
    // repeated retries across classes until capacity opens.
    for class in [
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
    ] {
        assert_eq!(gate.admit(72, class), AdmitOutcome::Backpressured);
    }

    assert!(gate.pop_ready().is_some());
    assert_eq!(
        gate.admit(72, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}

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
fn reserve_only_split_repeated_retry_noise_keeps_fresh_backpressured_id_recoverable() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(90, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(91, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Saturation: fresh id must be backpressured, not duplicate-poisoned.
    assert_eq!(
        gate.admit(92, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Retry noise should not change classification while saturated.
    assert_eq!(
        gate.admit(90, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(92, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(92, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // After one drain, the previously backpressured fresh id must still recover.
    assert!(gate.pop_ready().is_some());
    assert_eq!(
        gate.admit(92, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
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

#[test]
fn zero_capacity_duplicate_probe_noise_does_not_poison_cross_class_retry_after_recovery() {
    let mut gate = LaneAdmissionGate::new(0, 0);

    // Hard-stop mode: fresh ingress is backpressured, but repeated retries for the
    // same id across classes must stay fresh/backpressured rather than becoming a
    // synthetic duplicate while capacity remains zero.
    assert_eq!(
        gate.admit(700, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(700, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(700, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Once capacity is restored in a fresh lane instance, that previously rejected
    // id must remain admissible across either class.
    let mut recovered = LaneAdmissionGate::new(1, 1);
    assert_eq!(
        recovered.admit(700, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(recovered.pop_ready(), Some(700));
    assert_eq!(
        recovered.admit(700, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
}
