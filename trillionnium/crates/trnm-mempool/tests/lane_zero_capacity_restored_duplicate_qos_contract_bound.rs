use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_backpressured_retry_keeps_public_qos_surface_frozen_until_real_drain() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    // Reserve-only mode models the launch-day sponsor/free-ingress boundary:
    // both classes share one public admission surface backed entirely by the
    // reserved lane.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    let saturated = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated);

    // Fresh retry noise for the same tx id must stay backpressured across both
    // classes and must not perturb the advertised freeze boundary.
    assert_eq!(
        gate.admit(77, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(
        gate.admit(77, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), saturated);

    // One real drain reopens exactly one shared public slot.
    assert_eq!(gate.pop_ready(), Some(1));
    let reopened = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 1,
        total_queued: 1,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened);

    // The previously backpressured id must still be fresh and may consume the
    // reopened shared slot from either class, immediately refreezing admission.
    assert_eq!(
        gate.admit(77, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(
        gate.admit(77, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), saturated);
}
