use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn full_drain_after_saturated_backpressure_keeps_fresh_cross_class_retry_admissible() {
    let mut gate = LaneAdmissionGate::new(2, 1);

    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

    // Fresh id hits saturated global capacity and must remain non-poisoned.
    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Backpressured);

    // Drain everything so idle self-heal / full-drain reset paths run completely.
    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert!(matches!(gate.pop_ready(), Some(10) | Some(20)));
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Previously backpressured id must still be fresh after full drain, even when
    // retried through the opposite class.
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.pop_ready(), Some(30));
}
