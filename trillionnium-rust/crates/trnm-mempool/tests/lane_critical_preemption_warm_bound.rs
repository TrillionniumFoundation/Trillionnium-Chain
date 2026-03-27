use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn newly_arrived_critical_backlog_preempts_normal_flood_without_extra_normal_turn() {
    let mut g = LaneAdmissionGate::new(8, 2);

    // Build only normal backlog and consume one normal turn first.
    for id in 1..=4 {
        assert_eq!(g.admit(id, IngressClass::Normal), AdmitOutcome::Accepted);
    }
    assert_eq!(g.pop_ready(), Some(1));

    // Critical traffic appears while a normal flood is still active.
    assert_eq!(g.admit(900, IngressClass::Critical), AdmitOutcome::Accepted);

    // QoS bound: the first newly arrived critical item should run before any
    // additional normal dequeue so normal backlog cannot hide fresh critical work
    // behind an extra stale fairness cycle.
    assert_eq!(g.pop_ready(), Some(900));
    assert_eq!(g.pop_ready(), Some(2));
}
