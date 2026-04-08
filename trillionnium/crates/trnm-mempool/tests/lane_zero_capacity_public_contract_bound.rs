use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn zero_total_capacity_keeps_fresh_retries_backpressured_without_duplicate_poisoning() {
    let mut gate = LaneAdmissionGate::new(0, 0);
    let hard_stopped = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 0,
        total_queued: 0,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };

    assert_eq!(gate.qos_snapshot(), hard_stopped);

    // Hard-stop mode must reject fresh ingress from either class without ever
    // poisoning the id into Duplicate, even across repeated cross-class retries.
    assert_eq!(
        gate.admit(7, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), hard_stopped);
    assert_eq!(
        gate.admit(7, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), hard_stopped);
    assert_eq!(
        gate.admit(7, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), hard_stopped);

    // No queue state should be created while the lane is hard-stopped.
    assert_eq!(gate.queued_counts(), (0, 0, 0));
    assert_eq!(gate.pop_ready(), None);
    assert_eq!(gate.qos_snapshot(), hard_stopped);

    // Distinct fresh ids must behave the same way, and classification-only retry
    // probes must not make the public sponsor/free-ingress snapshot look open.
    assert_eq!(
        gate.admit(8, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), hard_stopped);
    assert_eq!(
        gate.admit(8, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), hard_stopped);
    assert_eq!(gate.queued_counts(), (0, 0, 0));
}
