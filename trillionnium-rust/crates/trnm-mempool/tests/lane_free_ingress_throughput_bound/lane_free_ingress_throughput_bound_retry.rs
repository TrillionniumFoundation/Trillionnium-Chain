use super::*;

#[test]
fn reserve_only_split_backpressured_id_is_not_poisoned_across_class_after_drain() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(21, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(22, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain one slot and ensure the previously backpressured id remains fresh,
    // even when retried via a different ingress class.
    assert!(gate.pop_ready().is_some());
    assert_eq!(
        gate.admit(22, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}

#[test]
fn reserve_only_split_backpressured_id_is_not_poisoned_on_same_class_retry_after_drain() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(40, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(41, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(42, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // While saturation persists, retries for a fresh backpressured id must remain
    // backpressured (not duplicate-poisoned), even if retried via another class.
    assert_eq!(
        gate.admit(42, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // Same-class retry should remain fresh once capacity is freed.
    assert!(gate.pop_ready().is_some());
    assert_eq!(gate.admit(42, IngressClass::Normal), AdmitOutcome::Accepted);
}

#[test]
fn reserve_only_split_fresh_backpressured_id_stays_backpressured_across_retries_until_drain() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(70, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(71, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Fresh id under saturation should remain Backpressured (not Duplicate) on
    // repeated retries across classes until capacity opens.
    for class in [
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
    ] {
        assert_eq!(gate.admit(72, class), AdmitOutcome::Backpressured);
    }

    assert!(gate.pop_ready().is_some());
    assert_eq!(
        gate.admit(72, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}

#[test]
fn reserve_only_split_repeated_retry_noise_keeps_fresh_backpressured_id_recoverable() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    assert_eq!(gate.admit(90, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(91, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Saturation: fresh id must be backpressured, not duplicate-poisoned.
    assert_eq!(
        gate.admit(92, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Retry noise should not change classification while saturated.
    assert_eq!(
        gate.admit(90, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(92, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(92, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // After one drain, the previously backpressured fresh id must still recover.
    assert!(gate.pop_ready().is_some());
    assert_eq!(
        gate.admit(92, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}
