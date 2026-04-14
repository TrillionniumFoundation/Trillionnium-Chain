use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn oversized_reserve_single_slot_clamp_preserves_fail_closed_and_reopen_contract() {
    let mut gate = LaneAdmissionGate::new(1, 99);

    // reserve > total must clamp into a one-slot reserve-only lane. A borrowed
    // normal occupant should consume the only shared slot and fail-close fresh
    // admission for both classes until a real drain reopens capacity.
    assert_eq!(gate.admit(41, IngressClass::Normal), AdmitOutcome::Accepted);
    let saturated = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 1,
        total_queued: 1,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.queued_counts(), (0, 1, 1));
    assert_eq!(gate.qos_snapshot(), saturated);

    // While the only shared slot is occupied, queued ids remain globally
    // duplicate and fresh retries remain backpressured across ingress classes.
    assert_eq!(
        gate.admit(41, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.queued_counts(), (0, 1, 1));

    // One dequeue should immediately reopen the shared reserve-only slot.
    assert_eq!(gate.pop_ready(), Some(41));
    assert_eq!(gate.queued_counts(), (0, 0, 0));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // The drained id must re-enter as fresh once real headroom exists again.
    assert_eq!(
        gate.admit(41, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (0, 1, 1));
}
