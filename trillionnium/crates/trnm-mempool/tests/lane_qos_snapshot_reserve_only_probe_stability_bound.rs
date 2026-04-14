use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_stays_stable_across_shared_lane_probe_noise() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane, so once it is full neither sponsor nor free-ingress probes should
    // perturb the externally visible admission snapshot.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    let expected = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 3,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };

    assert_eq!(gate.qos_snapshot(), expected);

    // Fresh probes from either class should stay backpressured while the shared
    // reserve-only lane is saturated, without changing observability.
    for (tx_id, class) in [
        (70_u64, IngressClass::Normal),
        (71_u64, IngressClass::Critical),
        (72_u64, IngressClass::Normal),
    ] {
        assert_eq!(gate.admit(tx_id, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.qos_snapshot(), expected);
    }

    // Duplicate probes for already queued work must likewise leave the snapshot
    // untouched across both ingress classes sharing the same lane.
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), expected);
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), expected);
}
