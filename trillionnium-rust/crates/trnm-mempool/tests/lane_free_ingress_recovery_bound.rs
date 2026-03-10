use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn borrowed_last_critical_slot_recovers_to_critical_progress_after_one_dequeue() {
    let mut g = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity and borrow the last critical slot while
    // critical lane is idle to preserve free-ingress throughput.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Fresh critical ingress is backpressured until one slot drains.
    assert_eq!(
        g.admit(90, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After one dequeue, critical ingress should recover immediately.
    let drained = g.pop_ready();
    assert!(drained.is_some());
    assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);

    // Critical work should make progress before remaining normal backlog.
    assert_eq!(g.pop_ready(), Some(90));
}

#[test]
fn reserve_only_backpressured_critical_id_remains_fresh_after_one_drain() {
    let mut g = LaneAdmissionGate::new(2, 2);

    // Reserve-only split keeps normal ingress live by borrowing critical slots.
    assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);

    // Critical ingress is backpressured at full capacity.
    assert_eq!(
        g.admit(77, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // After one dequeue, the previously backpressured id must still be fresh
    // (not poisoned as duplicate) and admit immediately.
    assert!(matches!(g.pop_ready(), Some(11) | Some(12)));
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Accepted);
}

#[test]
fn borrowed_last_critical_slot_keeps_fresh_critical_retry_backpressured_until_drain() {
    let mut g = LaneAdmissionGate::new(3, 1);

    // Fill normal dedicated capacity and borrow the last critical slot.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Fresh critical id under saturation must remain Backpressured across retries
    // (never poisoned into Duplicate) until capacity is released.
    assert_eq!(
        g.admit(91, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(91, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    assert!(g.pop_ready().is_some());
    assert_eq!(g.admit(91, IngressClass::Critical), AdmitOutcome::Accepted);
}
