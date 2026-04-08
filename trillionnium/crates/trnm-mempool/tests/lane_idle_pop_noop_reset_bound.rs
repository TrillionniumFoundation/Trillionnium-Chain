use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn repeated_empty_pop_after_full_drain_does_not_poison_next_batch_fairness_or_reuse() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Warm fairness with an active mixed backlog first.
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);

    // Tx 2 spills into the normal lane and sits at the normal-queue head, so the
    // warmed fairness turn serves it first.
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(10));

    // Long-lived schedulers may keep polling the lane while it is empty.
    // Those idle polls must stay a no-op: no stale fairness/bookkeeping should
    // survive into the next mixed batch.
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // The drained id should be immediately reusable across classes.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(21, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Fresh post-idle mixed ingress should start cold: first critical wins, then
    // normal gets its bounded anti-starvation turn.
    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(21));
    assert_eq!(gate.pop_ready(), None);
}
