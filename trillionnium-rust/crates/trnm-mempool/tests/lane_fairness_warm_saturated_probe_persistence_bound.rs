use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn warmed_fairness_survives_saturated_fresh_probe_noise_after_first_normal_turn() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Build sustained critical pressure and warm fairness once normal backlog appears.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(100));

    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(102, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
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

    // Refill critical pressure while dual backlog remains active. One additional
    // critical admit is enough to saturate the lane because earlier critical work
    // already spilled into the normal queue.
    assert_eq!(
        gate.admit(105, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // While globally saturated, fresh probes must remain backpressured and must not
    // cool the already-warm fairness state.
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // The remaining real normal backlog should still get service within one more dequeue.
    let next = [gate.pop_ready(), gate.pop_ready()];
    assert!(
        next.contains(&Some(2)),
        "warm fairness should survive saturated fresh-probe noise after the first normal turn"
    );
}
