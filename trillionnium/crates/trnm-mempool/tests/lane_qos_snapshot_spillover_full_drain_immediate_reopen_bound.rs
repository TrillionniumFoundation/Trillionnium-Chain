use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn qos_snapshot_reopens_immediately_after_spillover_full_drain_without_idle_poll() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Fill normal capacity, then keep one critical tx in the dedicated reserve and
    // one spilled into borrowed normal headroom.
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
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 1,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );

    // Drain the dedicated critical occupant, then the remaining normal-lane work,
    // including the spilled critical copy.
    assert_eq!(gate.pop_ready(), Some(50));
    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.pop_ready(), Some(51));
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Full-drain itself should cold-reset the gate so observability does not need
    // an extra idle scheduler poll before re-advertising fee/sponsor headroom.
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
}
