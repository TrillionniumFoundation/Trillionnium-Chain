use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_duplicate_noise_does_not_reopen_hard_stopped_qos_snapshot() {
    let mut gate = LaneAdmissionGate::new(2, 2);

    // Reserve-only mode: normal ingress borrows critical capacity because there is
    // no dedicated normal lane. Then a real critical tx consumes the final slot.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);

    let saturated_snapshot = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 2,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // Duplicate retry noise against the borrowed normal id must stay Duplicate and
    // must not perturb the operator-facing QoS surface into advertising headroom.
    assert_eq!(gate.admit(1, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // A distinct fresh id is still backpressured and also must leave the snapshot flat.
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
}
