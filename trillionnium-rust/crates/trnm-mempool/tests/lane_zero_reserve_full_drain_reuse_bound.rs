use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn zero_reserve_full_drain_allows_cross_class_reuse_without_stale_duplicate_state() {
    let mut gate = LaneAdmissionGate::new(2, 0);

    // With zero dedicated critical reserve, all ingress uses the normal lane.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 0, 2));

    // While queued, ids must still dedupe globally across ingress classes.
    assert_eq!(
        gate.admit(10, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    // Fresh ids stay backpressured until the lane drains.
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain completely so idle/full-drain reset paths run.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // After a true full drain, previously queued ids must be reusable through the
    // opposite class instead of staying poisoned as duplicates.
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 0, 2));

    // Zero-reserve mode should also let the previously backpressured fresh id enter
    // after capacity recovers, with normal-lane FIFO preserved.
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), None);
}
