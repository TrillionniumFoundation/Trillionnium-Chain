use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_reserve_qos_snapshot_stays_stable_across_saturated_fresh_and_duplicate_probe_noise() {
    let mut gate = LaneAdmissionGate::new(2, 0);

    // Zero-reserve mode routes all ingress through normal capacity.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

    let expected = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 0,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };

    assert_eq!(gate.qos_snapshot(), expected);

    // While globally saturated, fresh probes from either class must stay
    // backpressured and must not perturb QoS observability.
    for (tx_id, class) in [
        (30_u64, IngressClass::Normal),
        (31_u64, IngressClass::Critical),
        (32_u64, IngressClass::Normal),
    ] {
        assert_eq!(gate.admit(tx_id, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.qos_snapshot(), expected);
    }

    // Already queued ids must remain Duplicate across classes, again without
    // changing the saturated snapshot surface exposed to operators.
    assert_eq!(
        gate.admit(10, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), expected);
    assert_eq!(
        gate.admit(20, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), expected);
}
