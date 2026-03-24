use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn oversized_critical_reserve_clamps_to_total_and_preserves_reserve_only_idempotency() {
    // reserve > total must behave exactly like reserve-only mode instead of
    // over-admitting or splitting queue semantics inconsistently.
    let mut gate = LaneAdmissionGate::new(2, 99);

    // Normal ingress should still be able to borrow the clamped critical headroom.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 2, 2));

    // While saturated, queued ids must stay Duplicate across classes and fresh ids
    // must stay Backpressured.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // After one dequeue, the previously backpressured id must still be fresh.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), None);
}
