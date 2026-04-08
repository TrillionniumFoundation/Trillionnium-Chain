use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_total_capacity_idle_polls_do_not_change_retry_semantics_or_fabricate_queue_state() {
    let mut gate = LaneAdmissionGate::new(0, 0);

    // In hard-stop mode, fresh ingress must remain backpressured across classes.
    assert_eq!(
        gate.admit(41, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(41, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (0, 0, 0));

    // Long-lived schedulers may keep polling a stopped lane. Those idle polls must
    // stay pure no-ops: they must not fabricate queue state and must not change the
    // retry contract for either the previously seen fresh id or a new fresh id.
    for _ in 0..3 {
        assert_eq!(gate.pop_ready(), None);
        assert_eq!(gate.queued_counts(), (0, 0, 0));
    }

    assert_eq!(
        gate.admit(41, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(41, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        gate.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.queued_counts(), (0, 0, 0));
    assert_eq!(gate.pop_ready(), None);
}

#[test]
fn zero_total_capacity_qos_snapshot_stays_hard_stopped_across_fresh_retry_noise_and_idle_polls() {
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

    for class in [
        IngressClass::Normal,
        IngressClass::Critical,
        IngressClass::Normal,
        IngressClass::Critical,
    ] {
        assert_eq!(gate.admit(88, class), AdmitOutcome::Backpressured);
        assert_eq!(gate.qos_snapshot(), expected);
        assert_eq!(gate.queued_counts(), (0, 0, 0));
        assert_eq!(gate.pop_ready(), None);
        assert_eq!(gate.qos_snapshot(), expected);
    }

    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.qos_snapshot(), expected);
}
