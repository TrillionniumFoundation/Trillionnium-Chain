use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_last_critical_slot_reuse_stays_fresh_after_full_drain() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity first.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    // With the critical lane idle, normal ingress may temporarily borrow the last
    // free critical slot instead of being backpressured.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    // Borrowed normal ingress occupies the critical lane's idle reserve slot.
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // While globally full, the borrowed id must still dedupe across classes.
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    // Drain the lane completely so the idle/full-drain self-heal paths run.
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // After the full drain, the previously borrowed id must be treated as fresh
    // when it re-enters through the opposite class.
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), None);
}
