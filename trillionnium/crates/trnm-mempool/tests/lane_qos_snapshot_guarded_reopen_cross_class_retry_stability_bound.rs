use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reopened_last_reserved_critical_slot_stays_guarded_across_cross_class_duplicate_and_retry_noise() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Saturate the lane with dedicated normal occupancy plus two critical txs.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);

    let saturated = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 2,
        total_queued: 5,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated);

    // Drain exactly one critical occupant so the final reserved slot reopens, but
    // remains guarded because critical backlog is still active.
    let drained = gate.pop_ready().expect("critical backlog should drain first");
    let survivor = if drained == 10 { 11 } else { 10 };
    let reopened_guarded = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened_guarded);

    // Cross-class duplicate probes for the surviving queued critical id, plus
    // retries for the already-drained id, must stay classification-only noise.
    assert_eq!(gate.admit(survivor, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened_guarded);
    assert_eq!(gate.admit(survivor, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened_guarded);

    assert_eq!(gate.admit(drained, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), reopened_guarded);
    assert_eq!(gate.admit(drained, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), reopened_guarded);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // The reopened reserved slot must still accept fresh critical ingress, and the
    // newly admitted tx must immediately reclose the public QoS surface.
    assert_eq!(gate.admit(12, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(), saturated);
    assert_eq!(gate.queued_counts(), (3, 2, 5));
}
