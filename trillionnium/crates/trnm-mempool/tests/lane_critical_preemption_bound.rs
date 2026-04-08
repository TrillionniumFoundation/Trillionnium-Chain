use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn newly_arrived_critical_backlog_preempts_normal_flood_on_next_dequeue() {
    let mut gate = LaneAdmissionGate::new(8, 2);

    // Build only normal backlog first and consume one normal turn.
    for id in 1..=4 {
        assert_eq!(gate.admit(id, IngressClass::Normal), AdmitOutcome::Accepted);
    }
    assert_eq!(gate.pop_ready(), Some(1));

    // Critical traffic appears while normal backlog remains active.
    assert_eq!(
        gate.admit(900, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Public contract: high-priority ingress should preempt immediately on the
    // next dequeue instead of waiting for another fairness/burst cycle.
    assert_eq!(gate.pop_ready(), Some(900));

    // Normal backlog should continue making forward progress afterwards.
    assert_eq!(gate.pop_ready(), Some(2));
}
