use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_last_critical_slot_recovers_to_critical_progress_after_one_dequeue() {
    let mut g = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity and borrow the last critical slot while
    // critical lane is idle to preserve free-ingress throughput.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Fresh critical ingress is backpressured until one slot drains.
    assert_eq!(
        g.admit(90, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After one dequeue, critical ingress should recover immediately.
    let drained = g.pop_ready();
    assert!(drained.is_some());
    assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);

    // Critical work should make progress before remaining normal backlog.
    assert_eq!(g.pop_ready(), Some(90));
}

#[test]
fn reserve_only_backpressured_critical_id_remains_fresh_after_one_drain() {
    let mut g = LaneAdmissionGate::new(2, 2);

    // Reserve-only split keeps normal ingress live by borrowing critical slots.
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);

    // Critical ingress is backpressured at full capacity.
    assert_eq!(
        g.admit(77, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After one dequeue, the previously backpressured id must still be fresh
    // (not poisoned as duplicate) and admit immediately.
    assert!(matches!(g.pop_ready(), Some(11) | Some(12)));
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn borrowed_last_critical_slot_keeps_fresh_critical_retry_backpressured_until_drain() {
    let mut g = LaneAdmissionGate::new(3, 1);

    // Fill normal dedicated capacity and borrow the last critical slot.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Fresh critical id under saturation must remain Backpressured across retries
    // (never poisoned into Duplicate) until capacity is released.
    assert_eq!(
        g.admit(91, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(91, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    assert!(g.pop_ready().is_some());
    assert_eq!(g.admit(91, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn borrowed_last_critical_slot_keeps_duplicate_probe_duplicate_while_guarded() {
    let mut g = LaneAdmissionGate::new(3, 1);

    // Borrow the last reserved critical slot while the critical lane is idle.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (2, 1, 3));

    // The borrowed tx is already queued in the lane, so a critical retry of the
    // same id must preserve Duplicate classification even though the class-local
    // reserve guard would backpressure a fresh critical id here.
    assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(g.queued_counts(), (2, 1, 3));
}

#[test]
fn active_critical_backlog_blocks_normal_from_borrowing_last_reserved_slot() {
    let mut g = LaneAdmissionGate::new(4, 2);

    // Fill dedicated normal capacity, then borrow only surplus critical headroom.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // One immediate critical slot must remain available while critical backlog is active.
    assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (2, 2, 4));

    // Fresh normal retries must stay backpressured and keep queue accounting flat
    // instead of borrowing the final reserved critical slot.
    assert_eq!(
        g.admit(4, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(4, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(g.queued_counts(), (2, 2, 4));
}

#[test]
fn active_critical_backlog_reopens_normal_retry_only_after_reserved_slot_is_truly_free() {
    let mut g = LaneAdmissionGate::new(5, 2);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 1, 4));

    // The last free slot is reserved for critical ingress while critical backlog is active.
    assert_eq!(
        g.admit(45, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(g.admit(45, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 2, 5));

    // One critical dequeue is not enough if another critical tx still occupies the reserve.
    assert!(matches!(g.pop_ready(), Some(90) | Some(45)));
    assert_eq!(
        g.admit(46, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Once the remaining critical backlog clears, the reopened reserve is immediately
    // borrowable again for a previously backpressured normal retry, which then dedupes.
    assert!(matches!(g.pop_ready(), Some(90) | Some(45)));
    assert_eq!(g.admit(46, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(46, IngressClass::Critical), AdmitOutcome::Duplicate);
}

#[test]
fn reserve_only_backpressured_critical_id_stays_fresh_across_cross_class_retries_until_drain() {
    let mut g = LaneAdmissionGate::new(2, 2);

    // Reserve-only split (all critical reservation) lets normal ingress borrow
    // critical headroom while critical lane is idle.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Critical ingress is fresh but backpressured at full capacity.
    assert_eq!(
        g.admit(123, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // Cross-class retry before drain must stay Backpressured (not Duplicate).
    assert_eq!(
        g.admit(123, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // After one dequeue, the same id must admit immediately from either class.
    assert!(g.pop_ready().is_some());
    assert_eq!(g.admit(123, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn reserve_only_backpressured_normal_id_stays_fresh_across_cross_class_retries_until_drain() {
    let mut g = LaneAdmissionGate::new(2, 2);

    // Reserve-only split: fill borrowed critical headroom with mixed queued work.
    assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // Fresh normal ingress under saturation must remain Backpressured even when
    // retried across classes before any dequeue occurs.
    assert_eq!(
        g.admit(124, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(124, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After one dequeue, the previously backpressured id must still admit as fresh.
    assert!(g.pop_ready().is_some());
    assert_eq!(g.admit(124, IngressClass::Critical), AdmitOutcome::Accepted);
}
