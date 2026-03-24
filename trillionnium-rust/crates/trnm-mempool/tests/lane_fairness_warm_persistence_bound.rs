use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn fairness_stays_warm_after_serving_one_normal_while_dual_backlog_remains() {
    let mut gate = LaneAdmissionGate::new(8, 3);

    // Build sustained critical pressure, then introduce normal backlog so fairness warms.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(100));
    assert_eq!(gate.pop_ready(), Some(101));

    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(103, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(104, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Warm fairness grants the first normal anti-starvation turn.
    assert_eq!(gate.pop_ready(), Some(1));

    // Dual backlog remains active. Fairness should stay warm enough that the next
    // normal item is served within one additional dequeue instead of waiting through
    // another full critical burst window.
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(2)),
        "second normal item should be served within one additional dequeue once fairness is warm"
    );
}
