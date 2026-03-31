use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_reserve_probe_noise_keeps_qos_snapshot_flat_until_one_real_drain_reopens_both_classes() {
    let mut gate = LaneAdmissionGate::new(2, 0);

    // Zero-reserve mode routes both ingress classes through the same shared
    // normal-lane headroom.
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

    let saturated_snapshot = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 0,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // While the shared lane is full, duplicate probes and fresh retries from
    // either class must remain classification-only and must not perturb the
    // operator-facing QoS surface.
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(gate.admit(20, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(gate.admit(30, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(gate.admit(31, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // A single real dequeue should immediately reopen one shared slot for both
    // ingress classes; zero-reserve mode has no guarded dedicated critical slot.
    assert_eq!(gate.pop_ready(), Some(10));
    let reopened_snapshot = LaneQosSnapshot {
        normal_queued: 1,
        critical_queued: 0,
        total_queued: 1,
        normal_headroom: 1,
        critical_headroom: 0,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened_snapshot);

    // A previously backpressured fresh id should now admit cleanly and become
    // globally duplicate across classes again.
    assert_eq!(gate.admit(31, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(31, IngressClass::Normal), AdmitOutcome::Duplicate);
}
