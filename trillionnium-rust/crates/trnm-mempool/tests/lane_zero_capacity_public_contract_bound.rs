use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn zero_total_capacity_keeps_fresh_retries_backpressured_without_duplicate_poisoning() {
    let mut gate = LaneAdmissionGate::new(0, 0);

    // Hard-stop mode must reject fresh ingress from either class without ever
    // poisoning the id into Duplicate, even across repeated cross-class retries.
    assert_eq!(gate.admit(7, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(7, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(7, IngressClass::Normal), AdmitOutcome::Backpressured);

    // No queue state should be created while the lane is hard-stopped.
    assert_eq!(gate.queued_counts(), (0, 0, 0));
    assert_eq!(gate.pop_ready(), None);

    // Distinct fresh ids must behave the same way.
    assert_eq!(gate.admit(8, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(8, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.queued_counts(), (0, 0, 0));
}
