use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_last_idle_critical_slot_keeps_backpressured_critical_retry_fresh_after_full_drain() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity, then borrow the last idle critical slot.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // Fresh critical ingress is backpressured while the borrowed slot keeps the
    // lane globally full, and repeated probes must stay Backpressured rather than
    // poisoning the id into Duplicate.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain completely so the idle/full-drain self-heal path clears any stale
    // duplicate/backpressure bookkeeping associated with the saturated probes.
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // The previously backpressured critical id must remain fresh after the full
    // drain boundary, even when retried through the original critical class.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.pop_ready(), Some(99));
    assert_eq!(gate.pop_ready(), None);
}


#[test]
fn borrowed_last_idle_critical_slot_preserves_duplicate_before_guard_reopens() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity, then borrow the last idle critical slot.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // A fresh critical retry stays backpressured while the borrowed slot keeps the
    // final reserved slot guarded.
    assert_eq!(gate.admit(99, IngressClass::Critical), AdmitOutcome::Backpressured);

    // But an already queued normal id must still classify as Duplicate even though
    // the reserve guard blocks same-class headroom before any dequeue happens.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Duplicate);

    // Reopening one slot restores fresh admission for the previously backpressured id.
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn guarded_last_critical_slot_preserves_cross_class_duplicate_before_reopen() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity while leaving exactly one reserved critical
    // slot free and a live critical backlog.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // The final reserved critical slot is guarded against fresh normal spillover,
    // but an already queued critical id must still classify as Duplicate even when
    // retried through the blocked normal path.
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Duplicate);

    // A fresh normal retry remains backpressured until the reserve reopens.
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
}
