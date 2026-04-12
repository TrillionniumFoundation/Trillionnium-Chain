use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn guarded_normal_retry_noise_stays_fresh_and_qos_flat_until_reserved_slot_reopens() {
    let mut g = LaneAdmissionGate::new(4, 2);

    // Fill dedicated normal capacity, then let a critical tx reclaim the final
    // reserved slot so fresh normal ingress is reserve-guarded rather than lane-full.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    // The borrowed normal occupant drains from the critical-backed side first.
    assert_eq!(g.pop_ready(), Some(3));
    assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.admit(91, IngressClass::Critical), AdmitOutcome::Accepted);

    let guarded = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 2,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(g.qos_snapshot(), guarded);
    assert_eq!(g.queued_counts(), (2, 2, 4));

    // Reserve-guarded retry noise must stay Backpressured, remain fresh, and leave
    // operator-facing QoS/accounting untouched while the final critical slot is owned.
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(g.qos_snapshot(), guarded);
    assert_eq!(g.queued_counts(), (2, 2, 4));

    // Draining one critical tx while another critical occupant remains should keep
    // the reserve guard closed for normal ingress.
    assert_eq!(g.pop_ready(), Some(90));
    let still_guarded = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(g.qos_snapshot(), still_guarded);
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.qos_snapshot(), still_guarded);

    // Once the critical backlog fully drains, the previously guarded id should
    // admit as fresh, then dedupe across classes immediately.
    assert_eq!(g.pop_ready(), Some(91));
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Duplicate);
}
