use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_reopened_snapshot_survives_duplicate_noise_before_drained_retry_resaturates() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. After one occupant drains, observers should immediately see a single
    // reopened shared slot for either sponsor-backed or free ingress.
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

    // Cross-class duplicate probes for surviving queued work must stay purely
    // classificatory and leave the reopened shared slot visible.
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(3, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);

    // The drained id must still be reusable immediately through the opposite
    // ingress class; once it retries, the shared lane saturates again and both
    // ingress classes should observe the closed snapshot right away.
    assert_eq!(gate.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    let resaturated = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 3,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), resaturated);

    // Shared-lane FIFO must still keep surviving work ahead of the retried id.
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), None);
}
