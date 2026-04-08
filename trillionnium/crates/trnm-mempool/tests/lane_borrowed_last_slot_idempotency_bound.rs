use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_last_idle_critical_slot_stays_globally_idempotent_under_saturation() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity first.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // With the critical lane idle, normal ingress may borrow the last reserved
    // slot to preserve free-ingress throughput.
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Even though tx 3 was admitted via borrowed critical capacity, it must
    // still dedupe globally across ingress classes while the lane is saturated.
    assert_eq!(
        gate.admit(3, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(4, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // Once one slot drains, the previously fresh id must admit immediately.
    assert!(matches!(gate.pop_ready(), Some(1) | Some(2) | Some(3)));
    assert_eq!(
        gate.admit(4, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
}
