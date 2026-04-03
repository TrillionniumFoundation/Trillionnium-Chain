use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_refilled_survivor_drain_reopens_shared_slot_without_duplicate_masking() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode models the launch-day sponsor/free-ingress boundary:
    // both ingress classes share one public admission surface.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);

    let saturated = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 3,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated);

    // One real drain reopens a single shared slot.
    assert_eq!(gate.pop_ready(), Some(10));
    let reopened = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened);

    // A drained id may immediately refill the reopened slot.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(), saturated);

    // Once a different survivor drains, observers should see one shared slot reopen
    // again even while duplicate probes hit both the re-filled id and the remaining
    // queued survivor across classes.
    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);

    // The reopened shared slot should still accept truly fresh work immediately.
    assert_eq!(gate.admit(40, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(), saturated);
}
