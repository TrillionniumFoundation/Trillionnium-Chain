use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn borrowed_critical_headroom_closes_to_normal_ingress_after_real_critical_refill() {
    let mut gate = LaneAdmissionGate::new(4, 2);

    // Fill the dedicated normal lane, then borrow one genuinely idle critical
    // slot to keep free ingress live before any critical backlog exists.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        }
    );

    // A real critical refill must consume that reopened headroom and immediately
    // shut the borrowed path back down for fresh normal ingress.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 2, 4));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 2,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );

    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
}
