use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn oversized_reserve_clamp_reopen_keeps_qos_snapshot_flat_across_duplicate_probe_noise_until_refill(
) {
    let mut gate = LaneAdmissionGate::new(2, 99);

    // Oversized reserve clamps into reserve-only mode, so both ingress classes share
    // the same critical-backed capacity surface.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

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

    // While saturated, the surviving queued ids must remain globally duplicate and
    // fresh probes must remain backpressured without perturbing QoS.
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // One real drain should immediately reopen the clamped shared headroom for both
    // ingress classes.
    assert_eq!(gate.pop_ready(), Some(1));
    let reopened_snapshot = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 1,
        total_queued: 1,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened_snapshot);

    // Duplicate probe noise against the surviving queued id must keep the reopened
    // QoS snapshot flat until a real refill consumes the slot again.
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened_snapshot);

    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
}
