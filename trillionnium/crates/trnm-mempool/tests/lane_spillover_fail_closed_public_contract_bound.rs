use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn exhausted_spillover_headroom_keeps_public_qos_surface_fail_closed() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity, then borrow the final idle critical slot.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    let saturated = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // Cross-class duplicate probes against the borrowed occupant must stay purely
    // classificatory and must not reopen hidden headroom.
    assert_eq!(gate.admit(3, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    // Once both the dedicated reserve and borrowed spillover slot are occupied,
    // fresh ingress from either class must remain fail-closed.
    assert_eq!(gate.admit(50, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    assert_eq!(gate.admit(51, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.queued_counts(), (2, 1, 3));
}
