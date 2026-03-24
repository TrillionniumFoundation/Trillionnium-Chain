use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn spillover_backpressured_cross_class_retries_leave_queue_accounting_flat_until_recovery() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    for class in [
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
    ] {
        assert_eq!(gate.admit(999, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (2, 1, 3));
    }

    assert!(matches!(gate.pop_ready(), Some(1) | Some(100)));
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
}

#[test]
fn repeated_spillover_backpressure_retries_stay_flat_across_a_small_burst() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    for class in [
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
    ] {
        assert_eq!(gate.admit(999, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (2, 1, 3));
    }

    let first = gate.pop_ready();
    assert!(matches!(first, Some(1) | Some(100)));
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
}

#[test]
fn spillover_backpressure_small_burst_keeps_duplicates_and_fresh_retries_bounded() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    for class in [
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
    ] {
        assert_eq!(gate.admit(101, class), AdmitOutcome::Duplicate);
        assert_eq!(gate.admit(999, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (2, 1, 3));
    }

    let first = gate.pop_ready();
    assert!(matches!(first, Some(1) | Some(100)));
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
}

#[test]
fn spillover_backpressured_id_recovers_then_becomes_reusable_after_full_drain() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill the dedicated critical slot plus normal capacity, then force one more
    // critical tx to spill into the normal lane so the lane is globally full.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Fresh id stays Backpressured across cross-class retries while saturation holds.
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // After one dequeue opens headroom, the same id must recover as fresh.
    // Under warm fairness the first drain may be the oldest normal item; under
    // colder scheduling it may be the reserved critical item. Either way, one
    // dequeue must be enough to recover the fresh id.
    let first = gate.pop_ready();
    assert!(matches!(first, Some(1) | Some(100)));
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Once recovered into the lane, retries from the opposite class must dedupe.
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // Drain fully so idle/full-drain self-heal clears any stale duplicate state.
    let mut drained = vec![gate.pop_ready(), gate.pop_ready(), gate.pop_ready()];
    drained.sort_unstable();
    assert_eq!(drained, vec![Some(100), Some(101), Some(999)]);
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // After full drain, the old id must be reusable from either class.
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(999));
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}
