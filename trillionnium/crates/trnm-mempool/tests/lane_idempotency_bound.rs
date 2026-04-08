use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn saturated_lane_preserves_duplicate_vs_backpressure_contract() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // At full capacity, duplicate ids must stay Duplicate while fresh ids are
    // classified as Backpressured.
    assert_eq!(
        gate.admit(10, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After one dequeue (from either lane), the previously backpressured id
    // should admit as fresh.
    let drained = gate.pop_ready();
    assert!(drained == Some(10) || drained == Some(11));
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}

#[test]
fn reserve_only_saturated_lane_keeps_borrowed_duplicate_classification() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    // Reserve-only mode: normal ingress borrows critical headroom.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Under saturation, the borrowed id must still be globally deduped across
    // classes instead of being downgraded to Backpressured.
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(3, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Once one slot drains, the previously fresh id can enter.
    assert!(matches!(gate.pop_ready(), Some(1) | Some(2)));
    assert_eq!(
        gate.admit(3, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}

#[test]
fn backpressured_id_does_not_poison_cross_class_retry_after_capacity_recovers() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // tx 12 is fresh but backpressured at lane saturation.
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    // Retrying through the other class while still saturated must remain
    // Backpressured (never Duplicate) because tx 12 was never queued.
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // After one dequeue, tx 12 should be admitted as fresh regardless of class.
    assert!(matches!(gate.pop_ready(), Some(10) | Some(11)));
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
}
