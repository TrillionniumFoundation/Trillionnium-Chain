use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn borrowed_normal_spillover_guards_final_reserved_slot_before_any_critical_arrives() {
    let mut gate = LaneAdmissionGate::new(4, 2);

    // Fill the dedicated normal lane, then spill one normal tx into reserved
    // headroom while the critical lane is still idle.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

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
    assert_eq!(gate.qos_snapshot(), guarded_snapshot);

    // Once spillover is already using reserved headroom, the final reserved slot
    // must stay fail-closed to fresh normal ingress even before any critical tx
    // arrives, while still remaining immediately usable by critical traffic.
    assert_eq!(gate.admit(4, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), guarded_snapshot);
    assert_eq!(gate.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 2, 4));
}
