use super::*;

#[test]
fn critical_spillover_in_normal_lane_gets_turn_within_one_pop_under_critical_pressure() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Saturate reserved critical capacity.
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(201, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Keep some critical backlog active while admitting one overflow critical tx
    // via normal-lane spillover.
    assert_eq!(
        gate.admit(202, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // Overflowed critical tx in normal lane should not wait through a full burst.
    let first = gate.pop_ready();
    let second = gate.pop_ready();
    assert!(first == Some(202) || second == Some(202));
}

#[test]
fn reserve_only_borrowed_normal_does_not_preempt_already_queued_critical() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    assert_eq!(
        gate.admit(900, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(901, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    // In reserve-only mode, normal ingress borrows critical headroom.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // Anti-starvation must not invert priority here: pre-existing critical work
    // should still drain first.
    assert_eq!(gate.pop_ready(), Some(900));
    assert_eq!(gate.pop_ready(), Some(901));
    assert_eq!(gate.pop_ready(), Some(1));
}

#[test]
fn reserve_only_duplicate_probe_noise_does_not_preempt_existing_critical_fifo() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    assert_eq!(
        gate.admit(900, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(901, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

    // Reserve-only mode collapses both ingress classes into the shared critical
    // queue. Cross-class duplicate probes must stay classification-only and must
    // not synthesize fairness/preemption state that perturbs shared FIFO order.
    assert_eq!(gate.admit(900, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(1, IngressClass::Critical), AdmitOutcome::Duplicate);

    assert_eq!(gate.pop_ready(), Some(900));
    assert_eq!(gate.pop_ready(), Some(901));
    assert_eq!(gate.pop_ready(), Some(1));
}
