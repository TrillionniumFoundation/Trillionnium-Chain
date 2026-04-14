use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_shared_lane_duplicate_probe_keeps_qos_snapshot_stable_until_real_refill() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode collapses both ingress classes into the shared critical
    // lane. Duplicate probes must remain classification-only and must not mutate
    // the QoS surface that upstream admission/backpressure logic reads.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

    let expected_with_one_shared_slot_left = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), expected_with_one_shared_slot_left);

    // Cross-class duplicate noise must not fabricate queue growth or collapse the
    // remaining shared-lane headroom in the reported snapshot.
    assert_eq!(
        gate.admit(10, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), expected_with_one_shared_slot_left);

    // Only a real refill should consume the last shared slot and close both fresh
    // ingress classes in the snapshot.
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
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
