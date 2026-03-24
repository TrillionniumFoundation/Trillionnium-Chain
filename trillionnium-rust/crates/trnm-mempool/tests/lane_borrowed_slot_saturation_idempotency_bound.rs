use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_last_reserved_slot_keeps_duplicate_semantics_while_saturated() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity first.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // With the critical lane idle, normal ingress may temporarily borrow the last
    // reserved slot instead of being backpressured.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // Once global capacity is saturated, the borrowed tx id must still be treated
    // as a duplicate across both ingress classes rather than degrading to plain
    // backpressure.
    assert_eq!(
        gate.admit(12, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    // Fresh ids still backpressure while the lane stays full.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(100, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );

    // Drain the borrowed tx through the shared critical queue path, then the same
    // id should be admissible again as fresh ingress.
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}
