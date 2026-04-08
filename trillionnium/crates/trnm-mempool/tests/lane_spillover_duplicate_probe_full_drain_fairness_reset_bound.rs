use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn critical_spillover_duplicate_probe_full_drain_does_not_poison_next_mixed_batch_fairness() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Fill normal dedicated capacity, then force one critical tx to spill over into
    // the remaining free normal slot once the reserved critical slot is occupied.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Cross-class duplicate noise against the spilled critical id must stay
    // duplicate while queued and must not leave stale fairness/idempotency state
    // behind after full drain.
    assert_eq!(
        gate.admit(101, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );

    // Drain everything, including the critical tx that spilled into normal.
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(1));
    let tail = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        tail.contains(&Some(2)) && tail.contains(&Some(101)),
        "full drain should include the remaining normal tx and the spilled critical tx"
    );
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Fresh mixed traffic after the full drain should start from a cold fairness
    // state: critical gets the first turn, then normal gets its bounded turn.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(201, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    assert_eq!(gate.pop_ready(), Some(200));
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(201));
    assert_eq!(gate.pop_ready(), None);
}
