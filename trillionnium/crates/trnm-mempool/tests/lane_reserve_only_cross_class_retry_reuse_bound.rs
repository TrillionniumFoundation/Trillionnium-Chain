use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_fresh_normal_retry_does_not_poison_later_cross_class_critical_admission() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    // Reserve-only mode routes both classes through the shared critical queue.
    // Fill it completely so fresh retry noise is forced onto the fail-closed path.
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

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

    // A fresh normal retry must stay backpressured, but that classification must
    // not mark the tx id as seen across the shared reserve-only lane.
    assert_eq!(
        gate.admit(77, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(77, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.queued_counts(), (0, 2, 2));

    // Once one real occupant drains, the same tx id should still be fresh and be
    // able to claim the reopened slot through the opposite ingress class.
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

    assert_eq!(
        gate.admit(77, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(77, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(
        gate.admit(77, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (0, 2, 2));
}
