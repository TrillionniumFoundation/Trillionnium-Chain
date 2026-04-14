use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_full_drain_releases_refilled_duplicate_retention_and_restores_cross_class_reuse() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode models the launch-day sponsor/free-ingress boundary:
    // both ingress classes share one public admission surface until queued work
    // actually drains out of the lane.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
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

    // One real drain reopens exactly one shared slot, and a fresh refill may
    // consume it through the opposite ingress class.
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
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.qos_snapshot(), saturated);

    // While queued, both the refilled id and older survivors remain globally
    // duplicate-classified across ingress classes.
    assert_eq!(
        gate.admit(10, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), saturated);

    // After a true full drain, duplicate retention must be released for both the
    // refilled id and the older survivor so either can re-enter as fresh work.
    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.pop_ready(), Some(30));
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.pop_ready(), None);

    let empty = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 0,
        total_queued: 0,
        normal_headroom: 0,
        critical_headroom: 3,
        total_headroom: 3,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), empty);
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
}
