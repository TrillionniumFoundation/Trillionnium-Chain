use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn guarded_critical_refill_fresh_normal_probes_keep_qos_and_queue_counts_flat_until_real_critical_refill(
) {
    let mut gate = LaneAdmissionGate::new(4, 2);

    // Fill dedicated normal capacity, then borrow the final idle reserved slot.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    // Drain the borrowed normal occupant, then refill one reserved slot through
    // critical ingress. The last reserved slot is now actively owned, so fresh
    // normal ingress must stay guard-blocked while critical ingress still has
    // one spillover-reachable aggregate slot left.
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(
        gate.admit(90, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    let guarded_snapshot = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(gate.qos_snapshot(), guarded_snapshot);

    // Fresh normal probe noise must remain classification-only: it should not
    // mutate queue occupancy or reopen the guarded QoS surface.
    assert_eq!(
        gate.admit(70, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(gate.qos_snapshot(), guarded_snapshot);

    assert_eq!(
        gate.admit(71, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(gate.qos_snapshot(), guarded_snapshot);

    // A real critical refill should still be able to consume the final aggregate
    // slot immediately and reclose fresh admission for both classes.
    assert_eq!(
        gate.admit(91, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    let saturated_snapshot = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 2,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.queued_counts(), (2, 2, 4));
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
}
