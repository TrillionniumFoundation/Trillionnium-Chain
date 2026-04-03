use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_drained_id_can_cross_class_reuse_reopened_slot_while_survivor_stays_duplicate() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode models the launch-day sponsor/free-ingress boundary: both
    // classes share the same critical-backed lane and only real drains may reopen
    // public admission headroom.
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

    // One real drain reopens exactly one shared slot for fresh sponsor/free ingress.
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

    // Duplicate probes against surviving queued ids must remain classification-only.
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);

    // The drained id may reuse the reopened shared slot even when it re-enters from
    // the opposite ingress class, and that reuse must immediately close the shared
    // surface again without refreshing surviving queued ids.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.admit(20, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated);
}
