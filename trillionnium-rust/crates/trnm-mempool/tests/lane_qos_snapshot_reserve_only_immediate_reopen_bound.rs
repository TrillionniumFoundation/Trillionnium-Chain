use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_reopens_immediately_after_last_borrowed_slot_drains() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes all ingress through the shared critical lane.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (0, 3, 3));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 3,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );

    assert_eq!(gate.pop_ready(), Some(1));
    assert_eq!(gate.pop_ready(), Some(2));

    // With aggregate reserve headroom reopened, reserve-only mode should already
    // advertise fresh admissibility for both ingress classes through the shared lane.
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 1,
            total_queued: 1,
            normal_headroom: 0,
            critical_headroom: 2,
            total_headroom: 2,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // Draining the final shared slot should cold-reset the reserve-only gate
    // immediately, so observers do not need an extra idle poll to see reopened
    // sponsor/free-ingress headroom.
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(gate.queued_counts(), (0, 0, 0));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 0,
            critical_headroom: 3,
            total_headroom: 3,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );
}
