use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[test]
fn cross_class_duplicate_probe_does_not_prewarm_fairness_before_real_normal_backlog() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Start with critical-only backlog.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Cross-class duplicate noise must stay classification-only: it must not create
    // synthetic normal backlog, mutate queued counts, or prewarm fairness.
    assert_eq!(
        gate.admit(101, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (0, 2, 2));

    // Once a real normal item arrives under active critical pressure, the normal
    // turn may warm exactly once from that real mixed backlog boundary.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (1, 2, 3));

    // The next dequeue should honor the real mixed-backlog fairness contract, not
    // any earlier duplicate probe noise.
    assert_eq!(gate.pop_ready(), Some(1));
}
