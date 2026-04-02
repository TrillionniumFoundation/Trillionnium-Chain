use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_refilled_shared_slot_keeps_duplicate_retention_without_masking_reopened_headroom() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode models the launch-day sponsor/free-ingress boundary:
    // both ingress classes share one public admission surface.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    let saturated = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 3,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated);

    // One real drain should immediately reopen exactly one shared slot.
    assert_eq!(gate.pop_ready(), Some(1));
    let reopened = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened);

    // A fresh refill may consume the reopened slot through either ingress class.
    assert_eq!(gate.admit(4, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(), saturated);

    // Once the refilled id is queued, cross-class replay probes for that id must
    // stay purely duplicate-classified and keep the saturated snapshot flat.
    assert_eq!(gate.admit(4, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated);

    // After another real drain, the surviving refilled id still owns duplicate
    // retention, but its replay probe must not mask the newly reopened slot.
    assert_eq!(gate.pop_ready(), Some(2));
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(4, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);
}
