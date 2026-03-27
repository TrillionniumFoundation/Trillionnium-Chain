use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn guarded_last_critical_slot_keeps_qos_snapshot_stable_across_repeated_normal_retries() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    let expected = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };

    // With active critical backlog, the final reserved slot stays guarded for
    // fresh critical ingress. Repeated normal retry bursts must remain
    // backpressured without perturbing public QoS observability.
    for _ in 0..4 {
        assert_eq!(gate.qos_snapshot(), expected);
        assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
        assert_eq!(gate.qos_snapshot(), expected);
        assert_eq!(gate.queued_counts(), (3, 1, 4));
    }
}
