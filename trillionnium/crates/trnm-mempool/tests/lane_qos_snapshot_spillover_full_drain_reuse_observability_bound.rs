use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn qos_snapshot_stays_consistent_when_spillover_lane_reuses_drained_id_after_full_drain() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Fill the normal lane, then admit one critical tx into the dedicated reserve
    // and another into borrowed normal headroom.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(50, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(51, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Drain the entire batch without an intervening idle poll.
    assert_eq!(gate.pop_ready(), Some(50));
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(51));
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Observability must reopen immediately once the gate fully drains.
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 3,
            critical_headroom: 1,
            total_headroom: 4,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // A previously drained critical id must be reusable immediately via the
    // opposite ingress class, and the snapshot should account for the reused id
    // as fresh normal-lane occupancy rather than stale duplicate metadata.
    assert_eq!(gate.admit(50, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 1,
            critical_queued: 0,
            total_queued: 1,
            normal_headroom: 2,
            critical_headroom: 1,
            total_headroom: 3,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // While re-queued, duplicate probes across either ingress class must still be
    // rejected without perturbing the externally visible snapshot.
    let expected = gate.qos_snapshot();
    assert_eq!(
        gate.admit(50, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), expected);
    assert_eq!(
        gate.admit(50, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), expected);
}
