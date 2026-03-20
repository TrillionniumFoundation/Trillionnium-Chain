use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn full_drain_after_saturated_backpressure_keeps_fresh_cross_class_retry_admissible() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

    // Fresh id hits saturated global capacity and must remain non-poisoned.
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(30, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain everything so idle self-heal / full-drain reset paths run completely.
    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Extra idle polls after the full-drain reset must stay no-op and must not
    // resurrect stale backpressure metadata for the previously rejected id.
    assert_eq!(gate.pop_ready(), None);

    // Previously backpressured id must still be fresh after full drain, even when
    // retried through the opposite class.
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.pop_ready(), Some(30));
}

#[test]
fn saturated_retry_burst_keeps_queue_counts_stable_until_headroom_reopens() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(gate.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (1, 1, 2));

    for class in [
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
    ] {
        assert_eq!(gate.admit(99, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (1, 1, 2));
    }

    assert!(matches!(gate.pop_ready(), Some(1) | Some(2)));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (1, 1, 2));
}

#[test]
fn repeated_idle_polls_after_full_drain_do_not_resurrect_backpressured_retry_metadata() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Backpressured);

    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.pop_ready(), None);

    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 1, 1));
    assert_eq!(gate.pop_ready(), Some(30));
}

#[test]
fn repeated_same_id_saturated_retries_stay_backpressured_until_one_slot_reopens() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (1, 1, 2));

    for class in [
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
    ] {
        assert_eq!(gate.admit(30, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (1, 1, 2));
    }

    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Duplicate);
}
