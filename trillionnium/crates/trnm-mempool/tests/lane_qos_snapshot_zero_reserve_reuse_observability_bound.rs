use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_reserve_qos_snapshot_reopens_cleanly_for_cross_class_reuse_after_full_drain() {
    let mut gate = LaneAdmissionGate::new(2, 0);

    // Zero-reserve mode routes both ingress classes through normal-lane headroom.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 0, 2));

    // Once the shared lane fully drains, observability must reopen immediately
    // without waiting for an extra idle poll.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.queued_counts(), (0, 0, 0));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 2,
            critical_headroom: 0,
            total_headroom: 2,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // A previously drained id must be reusable immediately via the opposite
    // ingress class, and the snapshot should account for the reused id as fresh
    // shared-lane occupancy rather than stale duplicate metadata.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 1,
            critical_queued: 0,
            total_queued: 1,
            normal_headroom: 1,
            critical_headroom: 0,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // While re-queued, duplicate probes across either ingress class must remain
    // purely classificatory and leave the reopened sponsor/free-ingress snapshot
    // untouched.
    let expected = gate.qos_snapshot();
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), expected);
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), expected);
}
