use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_reserve_single_shared_slot_preserves_fail_closed_and_reopen_contract() {
    let mut gate = LaneAdmissionGate::new(1, 0);

    // With zero reserve and only one aggregate slot, both ingress classes share a
    // single normal-lane slot. Once either class claims it, QoS must fail closed
    // for both classes until a real dequeue reopens that same shared slot.
    assert_eq!(gate.admit(41, IngressClass::Critical), AdmitOutcome::Accepted);
    let saturated = LaneQosSnapshot {
        normal_queued: 1,
        critical_queued: 0,
        total_queued: 1,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.queued_counts(), (1, 0, 1));
    assert_eq!(gate.qos_snapshot(), saturated);

    // While the only shared slot is occupied, queued ids remain globally
    // duplicate across classes and fresh retries remain backpressured.
    assert_eq!(gate.admit(41, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(99, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.queued_counts(), (1, 0, 1));

    // One real dequeue should immediately reopen that single shared slot to both
    // ingress classes because zero-reserve mode has no hidden guarded capacity.
    assert_eq!(gate.pop_ready(), Some(41));
    assert_eq!(gate.queued_counts(), (0, 0, 0));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 1,
            critical_headroom: 0,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // The drained id must re-enter as fresh once real headroom exists again.
    assert_eq!(gate.admit(41, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (1, 0, 1));
}
