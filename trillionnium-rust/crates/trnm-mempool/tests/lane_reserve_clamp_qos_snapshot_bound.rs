use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn oversized_critical_reserve_clamps_qos_snapshot_to_reserve_only_contract() {
    // reserve > total must clamp fail-closed into reserve-only semantics instead of
    // advertising phantom normal headroom to upstream QoS/backpressure observers.
    let mut gate = LaneAdmissionGate::new(2, 99);

    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 0,
            critical_headroom: 2,
            total_headroom: 2,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // Normal ingress borrows the clamped critical reserve because no dedicated normal
    // lane exists once the reserve is saturated to total capacity.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    let saturated = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated);

    // Fresh retry noise from either class must not perturb the clamped reserve-only
    // QoS surface while the lane stays saturated.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated);
}
