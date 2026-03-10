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
    assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Backpressured);

    // After one dequeue, critical ingress should recover immediately.
    let drained = g.pop_ready();
    assert!(drained.is_some());
    assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);

    // Critical work should make progress before remaining normal backlog.
    assert_eq!(g.pop_ready(), Some(90));
}
