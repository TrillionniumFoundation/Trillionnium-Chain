use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_reopened_shared_slot_survives_mixed_duplicate_noise() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. Fill it, drain one occupant, and verify the reopened shared slot
    // stays visible while duplicate probes interleave same-class and cross-class
    // retries for the remaining queued ids.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    assert_eq!(gate.pop_ready(), Some(1));

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

    // Mixed same-class and cross-class duplicate probes must remain purely
    // classificatory and leave the reopened shared slot visible to both
    // sponsor-backed and free ingress.
    assert_eq!(gate.admit(2, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(3, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);

    // The reopened shared slot should still accept fresh work immediately after
    // the mixed duplicate noise, regardless of which ingress class consumes it.
    assert_eq!(gate.admit(4, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 3,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );
}
