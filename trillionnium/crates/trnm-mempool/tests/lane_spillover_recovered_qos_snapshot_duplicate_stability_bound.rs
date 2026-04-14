use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn spillover_recovered_id_duplicate_probe_keeps_qos_snapshot_stable_until_next_real_drain() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Saturate the lane by filling the dedicated critical slot and both normal
    // slots, with the second critical tx spilling into normal capacity.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );

    // A fresh id is backpressured while aggregate saturation holds.
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );

    // One dequeue reopens exactly one fresh slot. Depending on fairness state,
    // either the reserved critical item or the oldest normal item may drain first.
    let first = gate.pop_ready();
    assert!(matches!(first, Some(1) | Some(100)));

    let recovered_snapshot = LaneQosSnapshot {
        normal_queued: 1,
        critical_queued: 1,
        total_queued: 2,
        normal_headroom: 1,
        critical_headroom: 0,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), recovered_snapshot);

    // The previously backpressured id recovers as fresh.
    assert_eq!(
        gate.admit(999, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    let saturated_again_snapshot = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), saturated_again_snapshot);

    // Once recovered into the lane, duplicate probes from the opposite class must
    // stay Duplicate and must not perturb the public QoS surface.
    assert_eq!(
        gate.admit(999, IngressClass::Normal),
        AdmitOutcome::Duplicate
    );
    assert_eq!(gate.qos_snapshot(), saturated_again_snapshot);
    assert_eq!(gate.queued_counts(), (2, 1, 3));
}
