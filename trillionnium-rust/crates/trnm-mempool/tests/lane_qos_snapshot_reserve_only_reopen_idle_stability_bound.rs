use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_keeps_reopened_shared_slot_visible_across_idle_polls_and_duplicate_noise() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. Fill it, then drain one item so observability reopens exactly one
    // shared slot for either sponsor-backed or free ingress.
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

    // Idle scheduler polls must not consume or hide the reopened shared slot.
    assert_eq!(gate.pop_ready(), Some(2));
    let widened = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 1,
        total_queued: 1,
        normal_headroom: 0,
        critical_headroom: 2,
        total_headroom: 2,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), widened);

    // Duplicate probes for the still-queued shared-lane id must remain purely
    // classificatory and leave the widened admission surface untouched.
    assert_eq!(gate.admit(3, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), widened);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), widened);

    // Fresh work from either ingress class should still observe the same shared
    // reserve-only headroom after the duplicate noise.
    assert_eq!(gate.admit(4, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(5, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot().total_headroom, 0);
    assert!(!gate.qos_snapshot().fresh_normal_admissible);
    assert!(!gate.qos_snapshot().fresh_critical_admissible);
}
