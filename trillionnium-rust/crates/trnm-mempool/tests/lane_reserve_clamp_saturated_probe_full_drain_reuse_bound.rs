use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn oversized_critical_reserve_saturated_duplicate_probe_then_full_drain_allows_cold_cross_class_reuse(
) {
    // reserve > total clamps into reserve-only mode. Under saturation, queued ids
    // must stay Duplicate while fresh ids remain Backpressured; after a true full
    // drain, drained ids must be reusable across classes without stale poisoning.
    let mut gate = LaneAdmissionGate::new(3, 99);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // Saturated reserve-clamped path must preserve duplicate-vs-backpressure
    // semantics across ingress classes.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(11, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // Full drain should cold-reset reserve-only bookkeeping.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Previously drained ids should be reusable from either class after reset.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(13, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), Some(13));
    assert_eq!(gate.pop_ready(), None);
}
