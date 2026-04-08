use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn oversized_reserve_clamp_mixed_backlog_reopens_shared_slot_without_stale_duplicate_poison() {
    let mut gate = LaneAdmissionGate::new(2, 99);

    // reserve > total clamps into reserve-only semantics. Mixed-class ingress
    // shares the same critical queue, so both classes should consume the only two
    // real slots without fabricating dedicated normal headroom.
    assert_eq!(gate.admit(41, IngressClass::Critical), AdmitOutcome::Accepted);
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
    assert_eq!(gate.qos_snapshot(), saturated);

    // Cross-class duplicate noise while saturated must remain classificatory only.
    assert_eq!(gate.admit(42, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated);

    // One real drain should immediately reopen exactly one shared slot for both
    // classes under the reserve clamp.
    assert_eq!(gate.pop_ready(), Some(41));
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

    // The drained id is fresh again, and the duplicate probe against the still-
    // queued borrowed occupant must not poison or consume the reopened slot.
    assert_eq!(gate.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(41, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(), saturated);
}
