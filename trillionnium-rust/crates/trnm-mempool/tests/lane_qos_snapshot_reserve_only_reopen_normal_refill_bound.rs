use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_closes_when_normal_consumes_reopened_shared_slot_after_duplicate_noise() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. Fill it first, then drain one occupant so observability reopens a
    // single shared slot for either sponsor-backed or free ingress.
    assert_eq!(gate.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);

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

    // Cross-class duplicate noise for still-queued ids must remain purely
    // classificatory and leave the one reopened shared slot observable.
    assert_eq!(gate.admit(2, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);

    // A fresh normal admission should be able to consume the reopened shared
    // slot directly; once it does, both ingress classes must observe the same
    // immediately closed snapshot.
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
