use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_total_capacity_distinct_cross_class_probe_noise_keeps_qos_snapshot_hard_stopped() {
    let mut gate = LaneAdmissionGate::new(0, 0);
    let expected = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 0,
        total_queued: 0,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };

    assert_eq!(gate.qos_snapshot(), expected);

    // Fresh distinct ids retried across both ingress classes must remain
    // backpressured in hard-stop mode without fabricating queue state or
    // perturbing the operator-facing QoS surface.
    for (tx_id, class) in [
        (101, IngressClass::Normal),
        (101, IngressClass::Critical),
        (202, IngressClass::Critical),
        (202, IngressClass::Normal),
    ] {
        assert_eq!(gate.admit(tx_id, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (0, 0, 0));
        assert_eq!(gate.qos_snapshot(), expected);
    }

    // Idle scheduler polls must stay a pure no-op even after mixed fresh probe
    // noise from multiple distinct ids.
    for _ in 0..2 {
        assert_eq!(gate.pop_ready(), None);
        assert_eq!(gate.queued_counts(), (0, 0, 0));
        assert_eq!(gate.qos_snapshot(), expected);
    }
}
