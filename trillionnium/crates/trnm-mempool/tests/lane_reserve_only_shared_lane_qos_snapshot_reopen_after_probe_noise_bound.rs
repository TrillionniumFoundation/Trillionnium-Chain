use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_shared_lane_probe_noise_keeps_qos_snapshot_flat_until_one_real_drain_reopens_both_classes(
) {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both classes through shared critical capacity.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    let saturated_snapshot = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 3,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // While the shared reserve-only lane is full, duplicate probes from either class
    // must stay Duplicate and fresh probes must stay Backpressured without perturbing
    // the operator-facing QoS snapshot.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(
        gate.admit(100, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // A single real drain should immediately reopen reserve-only shared headroom for
    // both ingress classes, rather than waiting for a full drain or idle poll.
    assert_eq!(gate.pop_ready(), Some(1));
    let reopened_snapshot = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened_snapshot);

    // The previously backpressured fresh id should now admit cleanly and become
    // globally duplicate again across classes.
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
}
