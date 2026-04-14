use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn spillover_reopened_last_idle_reserve_admits_one_fresh_normal_borrow_then_recloses_qos() {
    let mut gate = LaneAdmissionGate::new(4, 1);

    // Fill dedicated normal capacity, then keep one critical tx in the dedicated
    // reserve and one spilled into borrowed normal headroom.
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

    // Draining the dedicated reserve occupant reopens exactly one aggregate slot
    // while the older spilled critical copy still occupies borrowed normal space.
    assert_eq!(gate.pop_ready(), Some(50));
    let reopened_snapshot = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 0,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened_snapshot);

    // Because the critical lane is idle again, fresh normal ingress may borrow the
    // last idle reserved slot exactly once to preserve throughput.
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    let reclosed_snapshot = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), reclosed_snapshot);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Once the reopened last idle reserve slot is borrowed, both classes must see
    // the lane as fail-closed again until a real drain reopens headroom.
    assert_eq!(
        gate.admit(100, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), reclosed_snapshot);
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), reclosed_snapshot);
}
