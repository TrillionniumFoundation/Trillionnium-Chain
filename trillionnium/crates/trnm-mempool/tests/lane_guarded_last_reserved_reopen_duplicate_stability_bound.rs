use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn guarded_last_reserved_reopens_cleanly_after_final_critical_drain_despite_cross_class_duplicate_noise(
) {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity and leave one reserved critical slot active.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(10, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    let guarded = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), guarded);

    // Once the last live critical item drains, the guarded slot should reopen for
    // both classes. Duplicate probes against surviving normal ids must remain
    // classification-only and must not re-close the public QoS surface.
    assert_eq!(gate.pop_ready(), Some(10));
    let reopened = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 0,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 2,
        total_headroom: 2,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), reopened);

    assert_eq!(
        gate.admit(2, IngressClass::Critical),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), reopened);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), reopened);

    // Fresh critical ingress should still be able to consume reopened reserve
    // capacity immediately after the duplicate noise.
    assert_eq!(
        gate.admit(11, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (3, 1, 4));
    assert_eq!(gate.qos_snapshot(), guarded);
}
