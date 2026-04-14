use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn qos_snapshot_keeps_normal_guard_closed_until_last_active_critical_slot_truly_clears() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity, then activate both reserved critical slots.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 2, 5));

    // One critical dequeue reopens aggregate headroom, but normal must stay guard-
    // blocked while another critical tx still owns the final reserved slot.
    assert!(matches!(gate.pop_ready(), Some(10) | Some(11)));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 1,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        }
    );

    // Once the remaining critical backlog drains, the reopened final reserved slot
    // becomes borrowable again for fresh normal ingress.
    assert!(matches!(gate.pop_ready(), Some(10) | Some(11)));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 0,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 2,
            total_headroom: 2,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );
}
