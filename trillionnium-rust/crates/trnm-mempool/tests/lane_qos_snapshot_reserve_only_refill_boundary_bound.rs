use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_preserves_refill_visibility_across_duplicate_probe_noise() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. Duplicate probes must stay classification-only so observability keeps
    // exposing the one remaining refill slot.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    let one_slot_left = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), one_slot_left);

    // Cross-class duplicate noise must not consume the remaining shared-lane
    // headroom or perturb the advertised sponsor/free-ingress admissibility.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), one_slot_left);
    assert_eq!(gate.admit(11, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), one_slot_left);

    // The final shared slot should still admit fresh work from either ingress
    // class, after which the snapshot must close for both classes immediately.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(),
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
