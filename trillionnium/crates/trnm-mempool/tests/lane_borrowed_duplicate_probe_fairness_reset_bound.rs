use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_duplicate_probe_full_drain_does_not_poison_next_mixed_batch_fairness() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Fill dedicated normal capacity, then borrow the final idle critical slot.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(13, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Duplicate probe noise against the borrowed id must stay Duplicate while the
    // lane is saturated and must not leave stale fairness/idempotency state after
    // a full drain.
    assert_eq!(
        gate.admit(13, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(13, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );

    // Drain completely so the idle/full-drain self-heal path clears borrowed-lane
    // duplicate markers and any stale fairness bookkeeping.
    assert_eq!(gate.pop_ready(), Some(13));
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Fresh mixed backlog after the full drain must behave like a clean lane: the
    // normal item should still receive its bounded fairness turn instead of being
    // delayed by stale borrowed-duplicate state from the previous batch.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(201, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    let first = gate.pop_ready();
    let second = gate.pop_ready();
    let third = gate.pop_ready();

    assert!(
        first == Some(200) || first == Some(201),
        "expected one critical item to drain first, got {:?}",
        first
    );
    assert_eq!(second, Some(1));
    assert!(
        third == Some(200) || third == Some(201),
        "expected the remaining critical item after the fairness turn, got {:?}",
        third
    );
    assert_ne!(
        first, third,
        "expected the two critical dequeues to be distinct"
    );
    assert_eq!(gate.pop_ready(), None);
}
