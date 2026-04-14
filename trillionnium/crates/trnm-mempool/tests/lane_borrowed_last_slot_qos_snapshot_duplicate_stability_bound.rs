use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn borrowed_last_idle_critical_slot_duplicate_and_fresh_probe_noise_keep_qos_snapshot_flat_until_drain(
) {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity, then borrow the final idle critical slot.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    let saturated_snapshot = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // The borrowed tx must stay globally duplicate across ingress classes while the
    // final reserved slot remains occupied by borrowed work.
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(
        gate.admit(3, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // Fresh probes from either class must remain backpressured and must not perturb
    // the operator-facing QoS surface while no real headroom exists.
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), saturated_snapshot);

    // Once the borrowed occupant drains, the final reserved slot becomes visible
    // again to both classes.
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 0,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );
}
