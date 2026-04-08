use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn repeated_empty_pop_after_zero_reserve_full_drain_does_not_poison_next_batch_reuse_or_priority() {
    let mut gate = LaneAdmissionGate::new(3, 0);

    // Zero-reserve mode routes both classes through normal-lane headroom.
    // Build an initial mixed batch and drain it completely so the idle/full-drain
    // self-heal path has to clear stale fairness and idempotency state.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

    let mut drained = vec![gate.pop_ready(), gate.pop_ready(), gate.pop_ready()];
    drained.sort_unstable();
    assert_eq!(drained, vec![Some(1), Some(2), Some(100)]);
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.pop_ready(), None);

    // The fully drained critical id must be immediately reusable from the
    // opposite class after repeated empty polls.
    assert_eq!(
        gate.admit(100, IngressClass::Normal),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(201, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Zero-reserve mode should restart from a cold scheduler state with FIFO
    // progress through the shared normal-lane headroom, not stale duplicate or
    // fairness poisoning from the prior batch.
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(200));
    assert_eq!(gate.pop_ready(), Some(201));
    assert_eq!(gate.pop_ready(), None);
}
