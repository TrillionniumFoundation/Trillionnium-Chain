use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_drained_retry_resaturates_snapshot_and_backpressures_fresh_cross_class_probe() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. After one occupant drains, the reopened shared slot may be reused by
    // the drained id through the opposite ingress class.
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

    // Once the drained id retries through the opposite ingress class, the shared
    // lane becomes saturated again and the externally visible snapshot must close.
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

    // Fresh work through the opposite ingress class must see immediate
    // backpressure instead of silently reopening sponsor/free-ingress headroom.
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), resaturated);

    // Duplicate probes for surviving queued work remain classification-only and
    // must not perturb the saturated snapshot either.
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), resaturated);
}
