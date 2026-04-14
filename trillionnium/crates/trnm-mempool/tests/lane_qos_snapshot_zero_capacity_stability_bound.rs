use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_capacity_qos_snapshot_stays_hard_stopped_across_probe_noise_and_idle_polls() {
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

    // Fresh probes from either ingress class must stay backpressured without
    // perturbing the externally visible hard-stop snapshot.
    for (tx_id, class) in [
        (70_u64, IngressClass::Normal),
        (71_u64, IngressClass::Critical),
        (72_u64, IngressClass::Normal),
    ] {
        assert_eq!(gate.admit(tx_id, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.qos_snapshot(), expected);
    }

    // Repeated probes for the same fresh id must likewise stay backpressured and
    // leave observability unchanged instead of poisoning duplicate state.
    assert_eq!(
        gate.admit(70, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), expected);

    // Idle scheduler polls must preserve the hard-stop surface too.
    for _ in 0..2 {
        assert_eq!(gate.pop_ready(), None);
        assert_eq!(gate.qos_snapshot(), expected);
    }
}
