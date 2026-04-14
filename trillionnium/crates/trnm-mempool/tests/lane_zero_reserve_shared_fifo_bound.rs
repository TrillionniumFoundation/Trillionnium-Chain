use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn zero_reserve_mixed_ingress_preserves_shared_queue_fifo_order() {
    let mut gate = LaneAdmissionGate::new(4, 0);

    // With zero dedicated critical reserve, both ingress classes share the normal
    // lane headroom. Execution-domain isolation must not invent class-based
    // preemption inside that single shared queue.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (4, 0, 4));

    // In zero-reserve mode, dequeue order should stay FIFO across ingress classes
    // because all queued work is isolated to the same shared lane.
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(101));
    assert_eq!(gate.pop_ready(), None);
}
