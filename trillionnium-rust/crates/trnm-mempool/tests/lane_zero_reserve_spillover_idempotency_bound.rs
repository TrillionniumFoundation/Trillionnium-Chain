use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn zero_reserve_critical_spillover_retry_stays_fresh_until_drain_and_then_dedupes() {
    let mut gate = LaneAdmissionGate::new(2, 0);

    // Zero critical reserve: critical ingress must spill into normal headroom.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // Once globally saturated, a fresh critical id must remain backpressured
    // across cross-class retries instead of being poisoned into Duplicate.
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // After one dequeue opens headroom, the previously backpressured id should
    // admit immediately via critical spillover.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // While queued through spillover, the same id must still dedupe globally
    // across ingress classes until it drains.
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
}

#[test]
fn zero_reserve_full_drain_resets_cross_class_reuse_without_stale_duplicate_state() {
    let mut gate = LaneAdmissionGate::new(2, 0);

    // Zero-reserve mode routes all ingress through normal-lane headroom.
    assert_eq!(
        gate.admit(50, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(51, IngressClass::Normal), AdmitOutcome::Accepted);

    // Drain fully so idle-reset / full-drain self-heal paths complete.
    assert_eq!(gate.pop_ready(), Some(50));
    assert_eq!(gate.pop_ready(), Some(51));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Previously drained ids must be reusable across the opposite class after
    // the zero-reserve full-drain boundary.
    assert_eq!(gate.admit(50, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(51, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Zero-reserve spillover order should remain FIFO after reset.
    assert_eq!(gate.pop_ready(), Some(50));
    assert_eq!(gate.pop_ready(), Some(51));
    assert_eq!(gate.pop_ready(), None);
}
