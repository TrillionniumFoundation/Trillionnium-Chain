use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_reopened_shared_slot_admits_prior_cross_class_fresh_retry_without_stale_duplicate_poisoning() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    // Reserve-only mode routes both classes through the shared critical lane.
    assert_eq!(gate.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    let saturated_snapshot = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // A fresh id rejected under saturation must stay fresh across class flips;
    // repeated probes must not fabricate duplicate state or perturb QoS.
    assert_eq!(gate.admit(99, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(gate.queued_counts(), (0, 2, 2));

    // One real dequeue reopens the shared reserve-only slot for both classes.
    assert_eq!(gate.pop_ready(), Some(1));
    let reopened_snapshot = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 1,
        total_queued: 1,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened_snapshot);

    // The same previously backpressured id must admit cleanly through the opposite
    // class, proving reserve-only retry noise did not poison lane-wide dedupe.
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 2, 2));
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(gate.admit(99, IngressClass::Critical), AdmitOutcome::Duplicate);
}
