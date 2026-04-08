use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn borrowed_last_idle_critical_slot_probe_noise_keeps_qos_snapshot_flat() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity, then borrow the final idle reserved slot.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

    let borrowed_snapshot = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), borrowed_snapshot);

    // Once the last reserved slot is borrowed, duplicate probes for the borrowed id
    // and fresh critical retries must not perturb operator-facing QoS state.
    assert_eq!(gate.admit(3, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), borrowed_snapshot);

    assert_eq!(gate.admit(99, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), borrowed_snapshot);
    assert_eq!(gate.queued_counts(), (2, 1, 3));
}
