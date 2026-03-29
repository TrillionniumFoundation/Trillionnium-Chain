use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn hard_stop_idle_polls_keep_public_queue_and_qos_invariants_flat_across_fresh_retry_noise() {
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

    assert_eq!(gate.queued_counts(), (0, 0, 0));
    assert_eq!(gate.qos_snapshot(), expected);

    for _ in 0..3 {
        for class in [IngressClass::Normal, IngressClass::Critical] {
            assert_eq!(gate.admit(99, class), AdmitOutcome::Backpressured);
            assert_eq!(gate.admit(100, class), AdmitOutcome::Backpressured);
            assert_eq!(gate.queued_counts(), (0, 0, 0));
            assert_eq!(gate.qos_snapshot(), expected);
        }

        assert_eq!(gate.pop_ready(), None);
        assert_eq!(gate.queued_counts(), (0, 0, 0));
        assert_eq!(gate.qos_snapshot(), expected);
    }
}
