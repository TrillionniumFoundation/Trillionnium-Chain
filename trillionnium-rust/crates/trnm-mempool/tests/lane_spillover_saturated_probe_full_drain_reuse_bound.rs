use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn spillover_saturated_fresh_probe_noise_full_drain_allows_immediate_cross_class_reuse() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated critical reserve first, then spill one critical tx into the
    // normal lane. This arms the spillover fairness warmup path under active
    // dual backlog.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    // While globally saturated, fresh probes from both classes must remain
    // backpressured and must not poison later reuse of the same id.
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain completely so spillover-warmed fairness bookkeeping and lane-wide /
    // lane-local idempotency caches all cross the full-drain reset boundary.
    while gate.pop_ready().is_some() {}
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // The previously backpressured fresh id must be immediately reusable from
    // either class after the full drain, without inheriting stale duplicate or
    // fairness state from the earlier saturated spillover batch.
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.pop_ready(), Some(999));

    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(999));
    assert_eq!(gate.queued_counts(), (0, 0, 0));
}
