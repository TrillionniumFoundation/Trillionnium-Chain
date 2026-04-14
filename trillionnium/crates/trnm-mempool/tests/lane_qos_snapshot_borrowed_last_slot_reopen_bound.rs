use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn qos_snapshot_reopens_borrowable_last_reserved_slot_after_borrowed_occupant_drains() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill the normal lane, then let normal ingress borrow the last idle reserved
    // critical slot so both public ingress classes become fully saturated.
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
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );

    // Once the borrowed reserved-slot occupant drains and the critical lane is idle
    // again, observability must immediately re-advertise the shared borrowable slot
    // instead of waiting for an extra scheduler poll.
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(gate.queued_counts(), (2, 0, 2));
    let reopened = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 0,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened);

    // Cross-class duplicate probes for the surviving normal backlog must stay
    // purely classificatory and must not perturb the reopened sponsor/free-ingress
    // headroom now that the reserved slot is borrowable again.
    assert_eq!(
        gate.admit(1, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), reopened);
}
