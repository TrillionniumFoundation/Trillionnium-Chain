use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_capacity_cross_class_fresh_retry_noise_stays_fail_closed() {
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

    // Cross-class fresh retry bursts must remain fail-closed and must not mutate
    // queue accounting or the public QoS surface while total capacity is zero.
    for class in [
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
    ] {
        assert_eq!(gate.admit(99, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.queued_counts(), (0, 0, 0));
        assert_eq!(gate.qos_snapshot(), expected);
    }
}
