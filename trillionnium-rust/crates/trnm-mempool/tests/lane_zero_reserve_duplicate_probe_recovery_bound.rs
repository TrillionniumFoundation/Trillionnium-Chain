use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn zero_reserve_spillover_duplicate_probe_does_not_block_fresh_retry_after_one_drain() {
    let mut gate = LaneAdmissionGate::new(3, 0);

    // Zero-reserve mode routes critical ingress through normal-lane headroom.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 0, 3));

    // While saturated, a queued spillover id must stay Duplicate across classes,
    // while a fresh id remains Backpressured rather than being poisoned.
    assert_eq!(
        gate.admit(100, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After one dequeue opens headroom, the fresh id should admit immediately
    // and FIFO order for the remaining shared queue should remain intact.
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(
        gate.admit(200, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(200));
    assert_eq!(gate.pop_ready(), None);
}
