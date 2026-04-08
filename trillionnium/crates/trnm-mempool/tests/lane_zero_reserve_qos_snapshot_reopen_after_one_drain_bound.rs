use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_reserve_qos_snapshot_reopens_both_classes_after_one_shared_slot_drains() {
    let mut gate = LaneAdmissionGate::new(2, 0);

    // Zero-reserve mode routes both classes through the shared normal lane.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 0,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );

    // Once one shared slot drains, both ingress classes should immediately see
    // fresh admission headroom again because zero-reserve mode has no guarded
    // dedicated critical slot to keep closed.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 1,
            critical_queued: 0,
            total_queued: 1,
            normal_headroom: 1,
            critical_headroom: 0,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    assert_eq!(gate.admit(30, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Duplicate);
}
