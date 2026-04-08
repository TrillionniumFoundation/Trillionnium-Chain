use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_preserves_multi_slot_refill_visibility_across_duplicate_noise() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. After two occupants drain, observers should see two reopened shared
    // slots immediately, and duplicate cross-class probes must stay
    // classification-only until fresh work actually consumes that headroom.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);

    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));

    let reopened = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 1,
        total_queued: 1,
        normal_headroom: 0,
        critical_headroom: 2,
        total_headroom: 2,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened);

    // Surviving queued work and already-drained ids may both be probed through the
    // opposite ingress class; neither duplicate path should perturb the reopened
    // sponsor/free-ingress snapshot.
    assert_eq!(gate.admit(12, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot().total_headroom, 1);
    assert!(gate.qos_snapshot().fresh_normal_admissible);
    assert!(gate.qos_snapshot().fresh_critical_admissible);

    // One more fresh admission should consume the final reopened shared slot and
    // close the externally visible admission surface again.
    assert_eq!(gate.admit(13, IngressClass::Normal), AdmitOutcome::Accepted);
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
