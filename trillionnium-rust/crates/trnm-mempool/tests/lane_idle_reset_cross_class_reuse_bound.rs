use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn full_drain_clears_stale_fairness_and_idempotency_before_cross_class_reuse() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Warm a non-zero critical streak with mixed backlog so idle-boundary reset
    // has real fairness state to clear.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // Drain fully across both lanes.
    let mut drained = vec![gate.pop_ready(), gate.pop_ready(), gate.pop_ready()];
    drained.sort_unstable();
    assert_eq!(drained, vec![Some(1), Some(100), Some(101)]);
    assert_eq!(gate.pop_ready(), None);

    // After a full drain, the same tx id must be fresh again even when retried
    // via the other ingress class, proving no stale idempotency survives idle.
    assert_eq!(gate.admit(100, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.pop_ready(), Some(100));

    // Fresh critical ingress after the idle boundary must also not inherit an old
    // fairness streak that would spuriously delay service.
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(200));
}
