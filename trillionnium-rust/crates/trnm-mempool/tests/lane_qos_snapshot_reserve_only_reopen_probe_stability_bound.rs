use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_qos_snapshot_stays_stable_across_probe_noise_after_reopen() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode routes both ingress classes through the shared critical
    // lane. Fill it first so we can verify the first reopened slot advertises
    // stable headroom as soon as one occupant drains.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

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

    // A fresh sponsor-backed admission should consume the single reopened shared
    // slot, and once saturated again the externally visible snapshot should
    // close immediately.
    assert_eq!(gate.admit(70, IngressClass::Critical), AdmitOutcome::Accepted);
    let resaturated = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 3,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), resaturated);

    // Once resaturated, cross-class fresh probes should stay classification-only
    // and must not perturb the advertised sponsor/free-ingress headroom.
    assert_eq!(gate.admit(71, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), resaturated);
    assert_eq!(gate.admit(72, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), resaturated);

    // Duplicate probes for already queued work across the other ingress class
    // must likewise leave the snapshot unchanged.
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), resaturated);
    assert_eq!(gate.admit(70, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), resaturated);
}
