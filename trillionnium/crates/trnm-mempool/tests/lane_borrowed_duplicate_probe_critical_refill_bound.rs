use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_slot_duplicate_probe_noise_does_not_delay_next_real_critical_refill() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Fill dedicated normal capacity, then borrow the final idle critical slot.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(13, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Duplicate probe noise against the borrowed id must stay Duplicate while the
    // lane is saturated and must not poison the next real critical refill.
    assert_eq!(
        gate.admit(13, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(13, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // The borrowed slot drains first, reopening immediate critical headroom.
    assert_eq!(gate.pop_ready(), Some(13));
    assert_eq!(gate.queued_counts(), (3, 0, 3));

    // Fresh critical ingress should admit cleanly and preempt the remaining normal
    // backlog instead of being delayed by stale duplicate/fairness state.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(99));
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), None);
}
