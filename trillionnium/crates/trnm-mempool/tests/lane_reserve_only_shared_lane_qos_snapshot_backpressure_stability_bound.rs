use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn reserve_only_shared_lane_fresh_retry_noise_keeps_qos_snapshot_stable_until_real_refill() {
    let mut gate = LaneAdmissionGate::new(3, 3);

    // Reserve-only mode collapses both ingress classes into the shared critical
    // lane. Fresh retry noise must remain classification-only: repeated
    // backpressured probes must not perturb the operator-facing QoS snapshot
    // before any real dequeue/refill boundary occurs.
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(12, IngressClass::Critical),
        AdmitOutcome::Accepted
    );

    let expected_full = LaneQosSnapshot {
        normal_queued: 0,
        critical_queued: 3,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), expected_full);

    // Repeated fresh retries from either class must stay backpressured without
    // fabricating queue growth, reopening headroom, or mutating class-specific
    // admissibility in the snapshot.
    assert_eq!(
        gate.admit(90, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), expected_full);
    assert_eq!(
        gate.admit(91, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(gate.qos_snapshot(), expected_full);

    // A real dequeue is the only event that may reopen the shared-lane snapshot.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 2,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );

    // Once real headroom exists again, a previously backpressured fresh id can
    // refill cleanly and the snapshot closes only because of that refill.
    assert_eq!(gate.admit(90, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.qos_snapshot(), expected_full);
}
