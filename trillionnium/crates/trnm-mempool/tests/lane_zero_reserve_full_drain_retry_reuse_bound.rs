use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn zero_reserve_saturated_retry_then_full_drain_allows_cross_class_reuse_of_same_id() {
    let mut gate = LaneAdmissionGate::new(2, 0);

    // Zero-reserve mode routes both classes through normal-lane headroom.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 0, 2));

    // A fresh id retried across both classes while saturated must stay
    // backpressured instead of being poisoned into Duplicate.
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain everything so the zero-reserve idle/full-drain self-heal paths run.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // The previously backpressured id must remain fresh after the full drain and
    // admit from either class without inheriting stale duplicate state.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), None);
}
