use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_capacity_qos_snapshot_stays_frozen_across_cross_class_probe_noise() {
    let mut gate = LaneAdmissionGate::new(0, 0);

    let hard_stop = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 0,
        total_queued: 0,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };

    assert_eq!(gate.qos_snapshot(), hard_stop);

    // Hard-stop mode must not let repeated fresh/duplicate-looking probes mutate
    // observability into advertising any headroom while total capacity remains zero.
    for class in [
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
    ] {
        assert_eq!(gate.admit(700, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.qos_snapshot(), hard_stop);
    }

    assert_eq!(gate.admit(701, IngressClass::Critical), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), hard_stop);
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.qos_snapshot(), hard_stop);
}
