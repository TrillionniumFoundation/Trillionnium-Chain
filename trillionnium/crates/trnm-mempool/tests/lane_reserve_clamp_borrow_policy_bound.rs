use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn oversized_reserve_clamp_keeps_last_free_shared_slot_borrowable_under_active_backlog() {
    let mut gate = LaneAdmissionGate::new(2, 99);

    // reserve > total clamps into reserve-only semantics. Even once one critical
    // occupant is queued, the final truly free shared slot must remain borrowable
    // until aggregate anti-spam capacity is actually exhausted.
    assert_eq!(
        gate.admit(41, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (0, 1, 1));
    assert_eq!(gate.qos_snapshot().fresh_normal_admissible, true);
    assert_eq!(gate.qos_snapshot().fresh_critical_admissible, true);

    assert_eq!(gate.admit(42, IngressClass::Normal), AdmitOutcome::Accepted);
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
    assert_eq!(gate.queued_counts(), (0, 2, 2));
    assert_eq!(gate.qos_snapshot(), saturated);

    // Under the clamp, cross-class duplicates still dedupe globally and fresh
    // work stays fail-closed for both ingress classes once the final shared slot
    // is consumed.
    assert_eq!(
        gate.admit(42, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), saturated);
}
