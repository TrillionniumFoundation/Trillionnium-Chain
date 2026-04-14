use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn borrowed_last_idle_critical_slot_snapshot_closes_normal_headroom_until_active_critical_backlog_truly_clears(
) {
    let mut gate = LaneAdmissionGate::new(4, 2);

    // Fill dedicated normal capacity, then borrow exactly one idle critical slot.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
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

    // Once live critical backlog consumes the final reserved slot, aggregate
    // saturation must close normal admission immediately.
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
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

    // Dequeuing the borrowed normal item reopens aggregate headroom, but the last
    // reserved critical slot is still owned by active critical backlog, so fresh
    // normal ingress must remain guard-blocked.
    assert_eq!(gate.pop_ready(), Some(12));
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

    // Only after the active critical backlog really clears may normal borrow the
    // last idle reserved slot again.
    assert_eq!(gate.pop_ready(), Some(20));
    assert_eq!(gate.queued_counts(), (2, 0, 2));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 0,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 2,
            total_headroom: 2,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );
}
