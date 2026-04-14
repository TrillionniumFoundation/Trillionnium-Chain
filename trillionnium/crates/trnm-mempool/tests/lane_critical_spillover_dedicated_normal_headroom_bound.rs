use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn critical_spillover_requires_real_dedicated_normal_headroom_and_reopens_after_drain() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Occupy the dedicated critical slot, then consume every dedicated normal slot.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(21, IngressClass::Normal), AdmitOutcome::Accepted);
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

    // With no dedicated normal slot left, further critical traffic must stay
    // backpressured rather than fabricating extra spillover capacity.
    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
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

    // Once a real drain reopens dedicated normal headroom, the same critical tx id
    // may spill into that slot immediately and then becomes globally duplicate.
    let drained = gate.pop_ready();
    assert!(matches!(drained, Some(20) | Some(21)));
    assert_eq!(gate.queued_counts(), (1, 1, 2));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 1,
            critical_queued: 1,
            total_queued: 2,
            normal_headroom: 1,
            critical_headroom: 0,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    assert_eq!(
        gate.admit(30, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(30, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
}
