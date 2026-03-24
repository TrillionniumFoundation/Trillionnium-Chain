use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn reserve_only_saturated_fresh_probe_noise_full_drain_allows_immediate_cross_class_reuse() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only split: normal ingress borrows idle critical headroom until the
    // shared critical queue is globally full.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // While saturated, fresh probes from either class must stay backpressured and
    // must not poison later reuse of the same id across the full-drain boundary.
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain completely so reserve-only fairness/idempotency bookkeeping crosses
    // the cold-reset boundary.
    while gate.pop_ready().is_some() {}
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // The previously backpressured fresh id must be immediately reusable from
    // either class after the full drain, without inheriting stale duplicate state.
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.pop_ready(), Some(999));

    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(999));
    assert_eq!(gate.queued_counts(), (0, 0, 0));
}
