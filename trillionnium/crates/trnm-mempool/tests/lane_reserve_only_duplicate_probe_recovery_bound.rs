use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn reserve_only_borrowed_duplicate_probe_does_not_delay_fresh_critical_retry_after_one_drain() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only split: normal ingress borrows idle critical headroom.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 3, 3));

    // Duplicate probe noise for the borrowed id must remain Duplicate while the
    // lane is full and must not poison recovery for a fresh critical id.
    assert_eq!(
        gate.admit(3, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After one dequeue frees reserve-only headroom, the fresh critical id should
    // admit immediately and keep FIFO progress through the shared critical queue.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(gate.pop_ready(), Some(99));
    assert_eq!(gate.pop_ready(), None);
}
