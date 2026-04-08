use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn oversized_critical_reserve_full_drain_and_idle_polls_do_not_poison_next_batch_reuse_or_fifo() {
    // reserve > total must clamp into reserve-only mode. After a true full drain,
    // repeated idle polls must stay no-op and must not preserve stale duplicate or
    // fairness bookkeeping into the next mixed batch.
    let mut gate = LaneAdmissionGate::new(2, 99);

    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (0, 2, 2));

    // Reserve-clamped mode should drain in shared FIFO order.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Long-lived schedulers may keep polling an already drained lane.
    for _ in 0..3 {
        assert_eq!(gate.pop_ready(), None);
        assert_eq!(gate.queued_counts(), (0, 0, 0));
    }

    // The previously drained id must be reusable as fresh ingress across classes,
    // and the next reserve-clamped batch should restart cold in FIFO order.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(10, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(12));
    assert_eq!(gate.pop_ready(), None);
}
