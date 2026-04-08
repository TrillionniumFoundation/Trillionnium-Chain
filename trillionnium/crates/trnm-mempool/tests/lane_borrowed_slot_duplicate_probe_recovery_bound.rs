use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_last_critical_slot_duplicate_probe_does_not_delay_critical_recovery_after_one_drain() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity first.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    // With the critical lane idle, normal ingress may temporarily borrow the last
    // reserved critical slot to preserve free-ingress throughput.
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Duplicate probe noise for the borrowed id must preserve duplicate semantics
    // without poisoning subsequent recovery for fresh critical ingress.
    assert_eq!(
        gate.admit(3, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // Once the borrowed slot drains, fresh critical ingress should recover
    // immediately and keep priority over remaining normal backlog.
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(99));
}
